/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What hashcat asks of the operating system, and what it sets on its own process before anything
// else looks: the environment a driver reads, the umask, the seed, how many processors and how much
// free memory the machine reports, which architecture this is, where stderr goes, and how long to
// wait on a descriptor.
//
// These are the calls that have to be written once per operating system, which is why the header
// block below is as long as it is. Keeping them together means the rest of the helpers do not carry
// that block, and neither does a plugin that links one of them.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "system.h"

#include <errno.h>
#include <inttypes.h>

#if defined (__CYGWIN__)
#include <sys/cygwin.h>
#endif

#if defined (__APPLE__)   || defined (__OpenBSD__)   || defined (__NetBSD__) || \
    defined (__FreeBSD__) || defined (__DragonFly__)
#include <sys/sysctl.h>
#if defined (__APPLE__)
#include <mach/mach.h>
#endif
#endif

#if defined (_WIN)
#include <winsock2.h>
#endif

#if defined (_POSIX)
#include <sys/utsname.h>
#if !defined (__APPLE__)   && !defined (__OpenBSD__)   && !defined (__NetBSD__) && \
    !defined (__FreeBSD__) && !defined (__DragonFly__)
#include <sys/sysinfo.h>
#endif
#endif
void setup_environment_variables (const folder_config_t *folder_config, const user_options_t *user_options)
{
  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    char *display;

    hc_asprintf (&display, "DISPLAY=%s", compute);

    putenv (display);

    hcfree (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  #if defined (DEBUG)
  if (getenv ("OCL_CODE_CACHE_ENABLE") == NULL)
    putenv ((char *) "OCL_CODE_CACHE_ENABLE=0");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");
  #endif

  if (getenv ("TMPDIR") == NULL)
  {
    char *tmpdir = NULL;

    hc_asprintf (&tmpdir, "TMPDIR=%s", folder_config->profile_dir);

    putenv (tmpdir);

    // we can't free tmpdir at this point!
  }

  // creates too much cpu load
  if (getenv ("AMD_DIRECT_DISPATCH") == NULL)
    putenv ((char *) "AMD_DIRECT_DISPATCH=0");

  if (user_options->hash_mode == 72000) // ugly but rare hack, we might move this to modules at a later stage
    if (getenv ("PYTHON_GIL") == NULL)
     putenv ((char *) "PYTHON_GIL=0");

  /*
  if (getenv ("CL_CONFIG_USE_VECTORIZER") == NULL)
    putenv ((char *) "CL_CONFIG_USE_VECTORIZER=False");
  */

  #if defined (__CYGWIN__)
  cygwin_internal (CW_SYNC_WINENV);
  #endif
}

void setup_umask (void)
{
  umask (077);
}

void setup_seeding (const bool rp_gen_seed_chgd, const u32 rp_gen_seed)
{
  if (rp_gen_seed_chgd == true)
  {
    srand (rp_gen_seed);
  }
  else
  {
    const time_t ts = time (NULL); // don't tell me that this is an insecure seed

    srand ((unsigned int) ts);
  }
}

u32 get_random_num (const u32 min, const u32 max)
{
  if (min == max) return (min);

  const u32 low = max - min;

  if (low == 0) return (0);

  #if defined (_WIN)

  return (((u32) rand () % (max - min + 1)) + min);

  #else

  return (((u32) random () % (max - min + 1)) + min);

  #endif
}

int hc_get_processor_count (void)
{
  int cnt = 0;

  #if defined (_WIN)

  SYSTEM_INFO info;

  GetSystemInfo (&info);

  cnt = (int) info.dwNumberOfProcessors;

  #else

  cnt = (int) sysconf (_SC_NPROCESSORS_ONLN);

  #endif

  return cnt;
}

int select_read_timeout (int sockfd, const int sec)
{
  struct timeval tv;

  tv.tv_sec  = sec;
  tv.tv_usec = 0;

  fd_set fds;

  FD_ZERO (&fds);

  #if defined (_WIN)
  FD_SET ((SOCKET)sockfd, &fds);
  #else
  FD_SET (sockfd, &fds);
  #endif

  return select (sockfd + 1, &fds, NULL, NULL, &tv);
}

int select_write_timeout (int sockfd, const int sec)
{
  struct timeval tv;

  tv.tv_sec  = sec;
  tv.tv_usec = 0;

  fd_set fds;

  FD_ZERO (&fds);

  #if defined (_WIN)
  FD_SET ((SOCKET)sockfd, &fds);
  #else
  FD_SET (sockfd, &fds);
  #endif

  return select (sockfd + 1, NULL, &fds, NULL, &tv);
}

#if defined (_WIN)

int select_read_timeout_console (const int sec)
{
  const HANDLE hStdIn = GetStdHandle (STD_INPUT_HANDLE);

  const DWORD rc = WaitForSingleObject (hStdIn, sec * 1000);

  if (rc == WAIT_OBJECT_0)
  {
    DWORD dwRead;

    INPUT_RECORD inRecords;

    inRecords.EventType = 0;

    PeekConsoleInput (hStdIn, &inRecords, 1, &dwRead);

    if (inRecords.EventType == 0)
    {
      // those are good ones

      return 1;
    }
    else
    {
      // but we don't want that stuff like windows focus etc. in our stream

      ReadConsoleInput (hStdIn, &inRecords, 1, &dwRead);
    }

    return select_read_timeout_console (sec);
  }
  else if (rc == WAIT_TIMEOUT)
  {
    return 0;
  }

  return -1;
}

#else

int select_read_timeout_console (const int sec)
{
  return select_read_timeout (fileno (stdin), sec);
}

#endif

int get_current_arch ()
{
  #if defined (_WIN)

  SYSTEM_INFO sysinfo;

  GetNativeSystemInfo (&sysinfo);

  switch (sysinfo.wProcessorArchitecture)
  {
    case PROCESSOR_ARCHITECTURE_AMD64: return 1;
    case PROCESSOR_ARCHITECTURE_INTEL: return 2;
    case PROCESSOR_ARCHITECTURE_ARM64: return 3;
    case PROCESSOR_ARCHITECTURE_ARM: return 4;
    default: return 0;
  }

  #else

  struct utsname uts;

  if (uname(&uts) != 0) return 0; // same as default, it doesn't matter if it fails here

  if (strstr(uts.machine, "x86_64")) return 1;
  else if (strstr(uts.machine, "i386") || strstr(uts.machine, "i686")) return 2;
  else if (strstr(uts.machine, "aarch64") || strstr(uts.machine, "arm64")) return 3;
  else if (strstr(uts.machine, "arm")) return 4;
  else return 0;

  #endif
}

#if defined (__APPLE__)

bool is_apple_silicon (void)
{
  size_t size;
  cpu_type_t cpu_type = 0;
  size = sizeof (cpu_type);
  sysctlbyname ("hw.cputype", &cpu_type, &size, NULL, 0);

  return (cpu_type == 0x100000c);
}

#endif // __APPLE__

#if defined (_WIN)
#define DEVNULL "NUL"
#else
#define DEVNULL "/dev/null"
#endif

int suppress_stderr (void)
{
  int null_fd = open (DEVNULL, O_WRONLY);

  if (null_fd < 0) return -1;

  int saved_fd = dup (fileno (stderr));

  if (saved_fd < 0)
  {
    close (null_fd);

    return -1;
  }

  dup2 (null_fd, fileno (stderr));

  close (null_fd);

  return saved_fd;
}

void restore_stderr (int saved_fd)
{
  if (saved_fd < 0) return;

  dup2 (saved_fd, fileno (stderr));

  close (saved_fd);
}

bool get_free_memory (u64 *free_mem)
{
  #if defined (_WIN)

  MEMORYSTATUSEX memStatus;

  memStatus.dwLength = sizeof (memStatus);

  if (GlobalMemoryStatusEx (&memStatus))
  {
    *free_mem = (u64) memStatus.ullAvailPhys;

    return true;
  }
  else
  {
    return false;
  }

  #elif defined (__APPLE__)

  mach_port_t host_port = mach_host_self ();

  mach_msg_type_number_t count = HOST_VM_INFO_COUNT;

  vm_statistics_data_t vm_stat;

  if (host_statistics (host_port, HOST_VM_INFO, (host_info_t) &vm_stat, &count) != KERN_SUCCESS)
  {
    return false;
  }

  int64_t page_size;

  host_page_size (host_port, (vm_size_t*) &page_size);

  *free_mem = (u64) (vm_stat.free_count + vm_stat.inactive_count) * page_size;

  return true;

  #elif defined (__OpenBSD__)

  struct uvmexp uvmexp;

  size_t size = sizeof (uvmexp);

  int mib[2] = {CTL_VM, VM_UVMEXP};

  if (sysctl (mib, 2, &uvmexp, &size, NULL, 0) == -1) return false;

  *free_mem = (uint64_t)(uvmexp.free * uvmexp.pagesize);

  return true;

  #elif defined (__FreeBSD__) || defined (__NetBSD__) || defined (__DragonFly__)

  size_t len;

  u64 pagesize = 0, free_pages = 0, cache_pages = 0, inactive_pages = 0;

  len = sizeof (pagesize);

  if (sysctlbyname ("hw.pagesize", &pagesize, &len, NULL, 0) == -1) return false;

  len = sizeof (free_pages);

  if (sysctlbyname ("vm.stats.vm.v_free_count", &free_pages, &len, NULL, 0) == -1) return false;

  #if defined (__OpenBSD__) || defined (__FreeBSD__) || defined (__DragonFly__)

  len = sizeof (cache_pages);

  if (sysctlbyname ("vm.stats.vm.v_cache_count", &cache_pages, &len, NULL, 0) == -1) return false;

  #endif // __OpenBSD__ || __FreeBSD__ || __DragonFly__

  len = sizeof (inactive_pages);

  if (sysctlbyname ("vm.stats.vm.v_inactive_count", &inactive_pages, &len, NULL, 0) == -1) return false;

  u64 total_pages = free_pages + cache_pages + inactive_pages;

  *free_mem = (u64) (total_pages * pagesize);

  return true;

  #else

  // Get MemAvailable from /proc/meminfo instead of sysinfo()

  FILE *fp = fopen ("/proc/meminfo", "r");

  if (fp == NULL)
  {
    // fallback

    struct sysinfo info;

    if (sysinfo (&info) != 0) return false;

    const unsigned long freeram = info.freeram;
    const unsigned long bufferram = info.bufferram;
    const unsigned long sharedram = info.sharedram;

    const unsigned long totamram = freeram + bufferram + sharedram;

    *free_mem = (u64) totamram * info.mem_unit;

    return true;
  }

  char line[256] = { 0 };

  u64 memAvailable_kb = 0;

  while (fgets (line, sizeof (line) - 1, fp))
  {
    if (sscanf (line, "MemAvailable: %" SCNu64 " kB", &memAvailable_kb) == 1)
    {
      fclose (fp);

      *free_mem = (memAvailable_kb * 1024);

      return true;
    }
  }

  fclose (fp);

  #endif

  return false;
}