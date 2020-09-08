#ifndef _RAR_THREADPOOL_
#define _RAR_THREADPOOL_

#ifndef RAR_SMP
const uint MaxPoolThreads=1; // For single threaded version.
#else
// We need to use the processor groups API to increase it beyond 64.
// Also be sure to check and adjust if needed per thread and total block size
// when compressing if going above 64.
const uint MaxPoolThreads=64;


#ifdef _UNIX
  #include <pthread.h>
  #include <semaphore.h>
#endif

// Undefine for debugging.
#define     USE_THREADS

#ifdef _UNIX
  #define NATIVE_THREAD_TYPE void*
  typedef void* (*NATIVE_THREAD_PTR)(void *Data);
  typedef pthread_t THREAD_HANDLE;
  typedef pthread_mutex_t CRITSECT_HANDLE;
#else
  #define NATIVE_THREAD_TYPE DWORD WINAPI
  typedef DWORD (WINAPI *NATIVE_THREAD_PTR)(void *Data);
  typedef HANDLE THREAD_HANDLE;
  typedef CRITICAL_SECTION CRITSECT_HANDLE;
#endif

typedef void (*PTHREAD_PROC)(void *Data);
#define THREAD_PROC(fn) void fn(void *Data)

uint GetNumberOfCPU();
uint GetNumberOfThreads();


class ThreadPool
{
  private:
    struct QueueEntry
    {
    	PTHREAD_PROC Proc;
      void *Param;
    };

    void CreateThreads();
    static NATIVE_THREAD_TYPE PoolThread(void *Param);
  	void PoolThreadLoop();
  	bool GetQueuedTask(QueueEntry *Task);

    // Number of threads in the pool. Must not exceed MaxPoolThreads.
    uint MaxAllowedThreads;
  	THREAD_HANDLE ThreadHandles[MaxPoolThreads];

    // Number of actually created threads.
    uint ThreadsCreatedCount;

    uint ActiveThreads;

  	QueueEntry TaskQueue[MaxPoolThreads];
  	uint QueueTop;
  	uint QueueBottom;

    bool Closing; // Set true to quit all threads.
  	
#ifdef _WIN_ALL
  	// Semaphore counting number of tasks stored in queue.
  	HANDLE QueuedTasksCnt;

    // Event signalling if no active tasks are performing now.
    HANDLE NoneActive;

#elif defined(_UNIX)
    // Semaphores seem to be slower than conditional variables in pthreads,
    // so we use the conditional variable to count tasks stored in queue.
    uint QueuedTasksCnt;
    pthread_cond_t QueuedTasksCntCond;
    pthread_mutex_t QueuedTasksCntMutex;

    bool AnyActive; // Active tasks present flag.
    pthread_cond_t AnyActiveCond;
    pthread_mutex_t AnyActiveMutex;
#endif

    // Pool critical section. We use the single section for all branches
    // to avoid deadlocks, when thread1 has section1 and wants section2
    // and thread2 has section2 and wants section1.
  	CRITSECT_HANDLE CritSection;
  public:
    ThreadPool(uint MaxThreads);
    ~ThreadPool();
    void AddTask(PTHREAD_PROC Proc,void *Data);
    void WaitDone();

#ifdef _WIN_ALL
    static int ThreadPriority;
    static void SetPriority(int Priority) {ThreadPriority=Priority;}
#endif
};

#endif // RAR_SMP

#endif // _RAR_THREADPOOL_

