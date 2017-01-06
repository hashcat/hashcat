/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _THREAD_H
#define _THREAD_H

#include <signal.h>

#if defined (_POSIX)
#include <pthread.h>
#include <semaphore.h>
#endif // _POSIX
#if defined (_WIN)
#include <windows.h>
#endif // _WIN

#if defined (_WIN)

#define hc_thread_create(t,f,a)     t = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) &f, a, 0, NULL)
#define hc_thread_wait(n,a)         for (u32 i = 0; i < n; i++) WaitForSingleObject ((a)[i], INFINITE)
#define hc_thread_exit(t)           ExitThread (t)

#define hc_thread_mutex_lock(m)     EnterCriticalSection      (&m)
#define hc_thread_mutex_unlock(m)   LeaveCriticalSection      (&m)
#define hc_thread_mutex_init(m)     InitializeCriticalSection (&m)
#define hc_thread_mutex_delete(m)   DeleteCriticalSection     (&m)

#elif defined (_POSIX)

#define hc_thread_create(t,f,a)     pthread_create (&t, NULL, f, a)
#define hc_thread_wait(n,a)         for (u32 i = 0; i < n; i++) pthread_join ((a)[i], NULL)
#define hc_thread_exit(t)           pthread_exit (&t)

#define hc_thread_mutex_lock(m)     pthread_mutex_lock     (&m)
#define hc_thread_mutex_unlock(m)   pthread_mutex_unlock   (&m)
#define hc_thread_mutex_init(m)     pthread_mutex_init     (&m, NULL)
#define hc_thread_mutex_delete(m)   pthread_mutex_destroy  (&m)

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
int myabort (hashcat_ctx_t *hashcat_ctx);
int myquit (hashcat_ctx_t *hashcat_ctx);
int bypass (hashcat_ctx_t *hashcat_ctx);
int SuspendThreads (hashcat_ctx_t *hashcat_ctx);
int ResumeThreads (hashcat_ctx_t *hashcat_ctx);
int stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx);

#endif // _THREAD_H
