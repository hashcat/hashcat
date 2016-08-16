#pragma once

/**
* types
*/

#ifdef _WIN
typedef LARGE_INTEGER     hc_timer_t;
typedef HANDLE            hc_thread_t;
typedef CRITICAL_SECTION  hc_thread_mutex_t;
#elif _POSIX
typedef struct timeval    hc_timer_t;
typedef pthread_t         hc_thread_t;
typedef pthread_mutex_t   hc_thread_mutex_t;
#endif

/**
* thread management
*/

#ifdef _WIN
inline void hc_timer_set(hc_timer_t *a) {
  QueryPerformanceCounter(a);
}
inline double hc_timer_get(hc_timer_t a) {
  hc_timer_t hr_freq;
  QueryPerformanceFrequency(&hr_freq);
  hc_timer_t hr_tmp;
  hc_timer_set(&hr_tmp);
  return (double)((double)(hr_tmp.QuadPart - a.QuadPart) / (double)(hr_freq.QuadPart / 1000));
}
#elif _POSIX
inline void hc_timer_set(hc_timer_t a) {
  gettimeofday(a, NULL);
}
inline double hc_timer_get(hc_timer_t a) {
  hc_timer_t hr_tmp;
  hc_timer_set(&hr_tmp);
  return (double)(((hr_tmp.tv_sec - (a).tv_sec) * 1000) + ((double)(hr_tmp.tv_usec - (a).tv_usec) / 1000));
}
#endif

#ifdef _WIN
#define hc_thread_create(t,f,a)     t = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) &f, a, 0, NULL)
/*inline void hc_thread_create(hc_thread_t *t, void *(*f)(void *p), hc_device_param_t *a){
  t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&f, a, 0, NULL);
}*/
inline void hc_thread_wait(uint n, HANDLE* a) {
  for (uint i = 0; i < n; i++)
    WaitForSingleObject(a[i], INFINITE);
}
#define hc_thread_exit(t)           ExitThread (t)

#define hc_thread_mutex_lock(m)     EnterCriticalSection      (&m)
#define hc_thread_mutex_unlock(m)   LeaveCriticalSection      (&m)
#define hc_thread_mutex_init(m)     InitializeCriticalSection (&m)
#define hc_thread_mutex_delete(m)   DeleteCriticalSection     (&m)

#elif _POSIX

#define hc_thread_create(t,f,a)     pthread_create (&t, NULL, f, a)
#define hc_thread_wait(n,a)         for (uint i = 0; i < n; ++i) pthread_join ((a)[i], NULL)
#define hc_thread_exit(t)           pthread_exit (&t)

#define hc_thread_mutex_lock(m)     pthread_mutex_lock     (&m)
#define hc_thread_mutex_unlock(m)   pthread_mutex_unlock   (&m)
#define hc_thread_mutex_init(m)     pthread_mutex_init     (&m, NULL)
#define hc_thread_mutex_delete(m)   pthread_mutex_destroy  (&m)
#endif

#ifdef __APPLE__
typedef struct cpu_set
{
  uint32_t count;

} cpu_set_t;

static inline void CPU_ZERO(cpu_set_t *cs) { cs->count = 0; }
static inline void CPU_SET(int num, cpu_set_t *cs) { cs->count |= (1 << num); }
static inline int  CPU_ISSET(int num, cpu_set_t *cs) { return (cs->count & (1 << num)); }
#endif
