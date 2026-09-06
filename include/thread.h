/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_THREAD_H
#define HC_THREAD_H

#include <signal.h>
#include <limits.h>

#if defined (_WIN)
#include <windows.h>
#else
#include <pthread.h>
#if defined(__APPLE__)
#include <dispatch/dispatch.h>
#else
#include <semaphore.h>
#endif // __APPLE__
#endif // _WIN

// The two platforms disagree on what a failed create looks like: CreateThread () answers with a NULL
// handle and pthread_create () with an errno, so a caller that wants to know has to spell the test
// twice. hc_thread_create_ok () gives both one answer. A caller that does not check it goes on to
// wait on a thread that does not exist, which on glibc is a join against a zeroed pthread_t.

#if defined (_WIN)

#define hc_thread_create(t,f,a)     t = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) &f, a, 0, NULL)
#define hc_thread_create_ok(t,f,a)  (((t) = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) &f, a, 0, NULL)) != NULL)

// WaitForSingleObject () waits on the thread, it does not release it. CreateThread () hands back a
// handle the caller owns, and the thread object and its slot in the process handle table stay alive
// until that handle is closed. So every worker we join leaks one handle. It is bounded for the pools
// that run once per session, but choose_kernel () spawns and joins a hook thread on every kernel
// launch, so a long run on a hook mode leaks steadily for as long as it runs.

#define hc_thread_wait(n,a)         do { for (int i = 0; i < n; i++) { WaitForSingleObject ((a)[i], INFINITE); CloseHandle ((a)[i]); } } while (0)
#define hc_thread_exit(t)           ExitThread (t)
#define hc_thread_detach(t)         CloseHandle (t)
#define hc_thread_self()            GetCurrentThreadId ()
#define hc_thread_join(t)           do { WaitForSingleObject (t, INFINITE); CloseHandle (t); } while (0)

#define hc_thread_mutex_init(m)     InitializeCriticalSection (&m)
#define hc_thread_mutex_lock(m)     EnterCriticalSection      (&m)
#define hc_thread_mutex_unlock(m)   LeaveCriticalSection      (&m)
#define hc_thread_mutex_delete(m)   DeleteCriticalSection     (&m)

/*
#define hc_thread_mutex_init(m)     m = CreateMutex     (NULL, FALSE, NULL)
#define hc_thread_mutex_lock(m)     WaitForSingleObject (m, INFINITE)
#define hc_thread_mutex_unlock(m)   ReleaseMutex        (m)
#define hc_thread_mutex_delete(m)   CloseHandle         (m)
*/

#define hc_thread_cond_init(c)      InitializeConditionVariable (&c)
#define hc_thread_cond_signal(c)    WakeConditionVariable       (&c)
#define hc_thread_cond_broadcast(c) WakeAllConditionVariable    (&c)
#define hc_thread_cond_wait(c,m)    SleepConditionVariableCS    (&c, &m, INFINITE)
#define hc_thread_cond_delete(c)    (void)(c)

#define hc_thread_sem_init(s)       s = CreateSemaphore (NULL, 0, INT_MAX, NULL)
#define hc_thread_sem_post(s)       ReleaseSemaphore    (s, 1, NULL)
#define hc_thread_sem_wait(s)       WaitForSingleObject (s, INFINITE)
#define hc_thread_sem_close(s)      CloseHandle         (s)

#else

#define hc_thread_create(t,f,a)     pthread_create (&t, NULL, f, a)
#define hc_thread_create_ok(t,f,a)  (pthread_create (&t, NULL, f, a) == 0)
#define hc_thread_wait(n,a)         do { for (int i = 0; i < n; i++) pthread_join ((a)[i], NULL); } while (0)
#define hc_thread_exit(t)           pthread_exit (&t)
#define hc_thread_detach(t)         pthread_detach (t)
#define hc_thread_self()            pthread_self ()
#define hc_thread_join(t)           pthread_join (t, NULL)

#define hc_thread_mutex_init(m)     pthread_mutex_init     (&m, NULL)
#define hc_thread_mutex_lock(m)     pthread_mutex_lock     (&m)
#define hc_thread_mutex_unlock(m)   pthread_mutex_unlock   (&m)
#define hc_thread_mutex_delete(m)   pthread_mutex_destroy  (&m)

#define hc_thread_cond_init(c)      pthread_cond_init      (&c, NULL)
#define hc_thread_cond_signal(c)    pthread_cond_signal    (&c)
#define hc_thread_cond_broadcast(c) pthread_cond_broadcast (&c)
#define hc_thread_cond_wait(c,m)    pthread_cond_wait      (&c, &m)
#define hc_thread_cond_delete(c)    pthread_cond_destroy   (&c)

#if defined (__APPLE__)

#define hc_thread_sem_init(s)       ((s) = dispatch_semaphore_create (0))
#define hc_thread_sem_wait(s)       dispatch_semaphore_wait ((s), DISPATCH_TIME_FOREVER)
#define hc_thread_sem_post(s)       dispatch_semaphore_signal ((s))
#define hc_thread_sem_close(s)      dispatch_release ((s))

#else

#define hc_thread_sem_init(s)       sem_init    (&s, 0, 0)
#define hc_thread_sem_post(s)       sem_post    (&s)
#define hc_thread_sem_wait(s)       sem_wait    (&s)
#define hc_thread_sem_close(s)      sem_destroy (&s)

#endif // __APPLE__

#endif

/*
#if defined (_WIN)

BOOL WINAPI sigHandler_default (DWORD sig);
BOOL WINAPI sigHandler_benchmark (DWORD sig);
void hc_signal (BOOL WINAPI (callback) (DWORD));

#else

void sigHandler_default (int sig);
void sigHandler_benchmark (int sig);
void hc_signal (void (callback) (int));

#endif
*/

int mycracked (hashcat_ctx_t *hashcat_ctx);
int myabort_runtime (hashcat_ctx_t *hashcat_ctx);
int myabort_checkpoint (hashcat_ctx_t *hashcat_ctx);
int myabort_finish (hashcat_ctx_t *hashcat_ctx);
int myabort (hashcat_ctx_t *hashcat_ctx);
int myquit (hashcat_ctx_t *hashcat_ctx);
int bypass (hashcat_ctx_t *hashcat_ctx);
int bypass_seek_step (hashcat_ctx_t *hashcat_ctx, const int direction);
u64 seek_position (const hashcat_ctx_t *hashcat_ctx);
double seek_percent (const hashcat_ctx_t *hashcat_ctx, const u64 words);
void seek_apply (hashcat_ctx_t *hashcat_ctx);
int runtime_adjust (hashcat_ctx_t *hashcat_ctx, const int seconds);
int SuspendThreads (hashcat_ctx_t *hashcat_ctx);
int ResumeThreads (hashcat_ctx_t *hashcat_ctx);
int stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx);
int finish_after_attack (hashcat_ctx_t *hashcat_ctx);

#endif // HC_THREAD_H
