#include "rar.hpp"

#ifdef RAR_SMP
#include "threadmisc.cpp"

#ifdef _WIN_ALL
int ThreadPool::ThreadPriority=THREAD_PRIORITY_NORMAL;
#endif

ThreadPool::ThreadPool(uint MaxThreads)
{
  MaxAllowedThreads = MaxThreads;
  if (MaxAllowedThreads>MaxPoolThreads)
    MaxAllowedThreads=MaxPoolThreads;
  if (MaxAllowedThreads==0)
    MaxAllowedThreads=1;

  ThreadsCreatedCount=0;

  // If we have more threads than queue size, we'll hang on pool destroying,
  // not releasing all waiting threads.
  if (MaxAllowedThreads>ASIZE(TaskQueue))
    MaxAllowedThreads=ASIZE(TaskQueue);

  Closing=false;

  bool Success = CriticalSectionCreate(&CritSection);
#ifdef _WIN_ALL
  QueuedTasksCnt=CreateSemaphore(NULL,0,ASIZE(TaskQueue),NULL);
  NoneActive=CreateEvent(NULL,TRUE,TRUE,NULL);
  Success=Success && QueuedTasksCnt!=NULL && NoneActive!=NULL;
#elif defined(_UNIX)
  AnyActive = false;
  QueuedTasksCnt = 0;
  Success=Success && pthread_cond_init(&AnyActiveCond,NULL)==0 &&
          pthread_mutex_init(&AnyActiveMutex,NULL)==0 &&
          pthread_cond_init(&QueuedTasksCntCond,NULL)==0 &&
          pthread_mutex_init(&QueuedTasksCntMutex,NULL)==0;
#endif
  if (!Success)
  {
    ErrHandler.GeneralErrMsg(L"\nThread pool initialization failed.");
    ErrHandler.Exit(RARX_FATAL);
  }

  QueueTop = 0;
  QueueBottom = 0;
  ActiveThreads = 0;
}


ThreadPool::~ThreadPool()
{
  WaitDone();
  Closing=true;

#ifdef _WIN_ALL
  ReleaseSemaphore(QueuedTasksCnt,ASIZE(TaskQueue),NULL);
#elif defined(_UNIX)
  // Threads still can access QueuedTasksCnt for a short time after WaitDone(),
  // so lock is required. We would occassionally hang without it.
  pthread_mutex_lock(&QueuedTasksCntMutex);
  QueuedTasksCnt+=ASIZE(TaskQueue);
  pthread_mutex_unlock(&QueuedTasksCntMutex);

  pthread_cond_broadcast(&QueuedTasksCntCond);
#endif

  for(uint I=0;I<ThreadsCreatedCount;I++)
  {
#ifdef _WIN_ALL
    // Waiting until the thread terminates.
    CWaitForSingleObject(ThreadHandles[I]);
#endif
    // Close the thread handle. In Unix it results in pthread_join call,
    // which also waits for thread termination.
    ThreadClose(ThreadHandles[I]);
  }

  CriticalSectionDelete(&CritSection);
#ifdef _WIN_ALL
  CloseHandle(QueuedTasksCnt);
  CloseHandle(NoneActive);
#elif defined(_UNIX)
  pthread_cond_destroy(&AnyActiveCond);
  pthread_mutex_destroy(&AnyActiveMutex);
  pthread_cond_destroy(&QueuedTasksCntCond);
  pthread_mutex_destroy(&QueuedTasksCntMutex);
#endif
}


void ThreadPool::CreateThreads()
{
  for(uint I=0;I<MaxAllowedThreads;I++)
  {
    ThreadHandles[I] = ThreadCreate(PoolThread, this);
    ThreadsCreatedCount++;
#ifdef _WIN_ALL
    if (ThreadPool::ThreadPriority!=THREAD_PRIORITY_NORMAL)
      SetThreadPriority(ThreadHandles[I],ThreadPool::ThreadPriority);
#endif
  }
}


NATIVE_THREAD_TYPE ThreadPool::PoolThread(void *Param)
{
  ((ThreadPool*)Param)->PoolThreadLoop();
  return 0;
}


void ThreadPool::PoolThreadLoop()
{
  QueueEntry Task;
  while (GetQueuedTask(&Task))
  {
    Task.Proc(Task.Param);
    
    CriticalSectionStart(&CritSection); 
    if (--ActiveThreads == 0)
    {
#ifdef _WIN_ALL
      SetEvent(NoneActive);
#elif defined(_UNIX)
      pthread_mutex_lock(&AnyActiveMutex);
      AnyActive=false;
      pthread_cond_signal(&AnyActiveCond);
      pthread_mutex_unlock(&AnyActiveMutex);
#endif
    }
    CriticalSectionEnd(&CritSection); 
  }
}


bool ThreadPool::GetQueuedTask(QueueEntry *Task)
{
#ifdef _WIN_ALL
  CWaitForSingleObject(QueuedTasksCnt);
#elif defined(_UNIX)
  pthread_mutex_lock(&QueuedTasksCntMutex);
  while (QueuedTasksCnt==0)
    cpthread_cond_wait(&QueuedTasksCntCond,&QueuedTasksCntMutex);
  QueuedTasksCnt--;
  pthread_mutex_unlock(&QueuedTasksCntMutex);
#endif

  if (Closing)
    return false;

  CriticalSectionStart(&CritSection); 

  *Task = TaskQueue[QueueBottom];
  QueueBottom = (QueueBottom + 1) % ASIZE(TaskQueue);

  CriticalSectionEnd(&CritSection); 

  return true;
}


// Add task to queue. We assume that it is always called from main thread,
// it allows to avoid any locks here. We process collected tasks only
// when WaitDone is called.
void ThreadPool::AddTask(PTHREAD_PROC Proc,void *Data)
{
  if (ThreadsCreatedCount == 0)
    CreateThreads();
  
  // If queue is full, wait until it is empty.
  if (ActiveThreads>=ASIZE(TaskQueue))
    WaitDone();

  TaskQueue[QueueTop].Proc = Proc;
  TaskQueue[QueueTop].Param = Data;
  QueueTop = (QueueTop + 1) % ASIZE(TaskQueue);
  ActiveThreads++;
}


// Start queued tasks and wait until all threads are inactive.
// We assume that it is always called from main thread, when pool threads
// are sleeping yet.
void ThreadPool::WaitDone()
{
  if (ActiveThreads==0)
    return;
#ifdef _WIN_ALL
  ResetEvent(NoneActive);
  ReleaseSemaphore(QueuedTasksCnt,ActiveThreads,NULL);
  CWaitForSingleObject(NoneActive);
#elif defined(_UNIX)
  AnyActive=true;

  // Threads reset AnyActive before accessing QueuedTasksCnt and even
  // preceding WaitDone() call does not guarantee that some slow thread
  // is not accessing QueuedTasksCnt now. So lock is necessary.
  pthread_mutex_lock(&QueuedTasksCntMutex);
  QueuedTasksCnt+=ActiveThreads;
  pthread_mutex_unlock(&QueuedTasksCntMutex);

  pthread_cond_broadcast(&QueuedTasksCntCond);

  pthread_mutex_lock(&AnyActiveMutex);
  while (AnyActive)
    cpthread_cond_wait(&AnyActiveCond,&AnyActiveMutex);
  pthread_mutex_unlock(&AnyActiveMutex);
#endif
}
#endif // RAR_SMP
