/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "shared.h"

#if defined (__CYGWIN__)
#include <sys/cygwin.h>
#endif

static inline int get_msb32 (const u32 v)
{
  int i;

  for (i = 32; i > 0; i--) if ((v >> (i - 1)) & 1) break;

  return i;
}

static inline int get_msb64 (const u64 v)
{
  int i;

  for (i = 64; i > 0; i--) if ((v >> (i - 1)) & 1) break;

  return i;
}

bool overflow_check_u32_add (const u32 a, const u32 b)
{
  const int a_msb = get_msb32 (a);
  const int b_msb = get_msb32 (b);

  return ((a_msb < 32) && (b_msb < 32));
}

bool overflow_check_u32_mul (const u32 a, const u32 b)
{
  const int a_msb = get_msb32 (a);
  const int b_msb = get_msb32 (b);

  return ((a_msb + b_msb) < 32);
}

bool overflow_check_u64_add (const u64 a, const u64 b)
{
  const int a_msb = get_msb64 (a);
  const int b_msb = get_msb64 (b);

  return ((a_msb < 64) && (b_msb < 64));
}

bool overflow_check_u64_mul (const u64 a, const u64 b)
{
  const int a_msb = get_msb64 (a);
  const int b_msb = get_msb64 (b);

  return ((a_msb + b_msb) < 64);
}

bool is_power_of_2 (const u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 mydivc32 (const u32 dividend, const u32 divisor)
{
  u32 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

u64 mydivc64 (const u64 dividend, const u64 divisor)
{
  u64 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

char *filename_from_filepath (char *filepath)
{
  char *ptr = NULL;

  if ((ptr = strrchr (filepath, '/')) != NULL)
  {
    ptr++;
  }
  else if ((ptr = strrchr (filepath, '\\')) != NULL)
  {
    ptr++;
  }
  else
  {
    ptr = filepath;
  }

  return ptr;
}

void naive_replace (char *s, const char key_char, const char replace_char)
{
  const size_t len = strlen (s);

  for (size_t in = 0; in < len; in++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s[in] = replace_char;
    }
  }
}

void naive_escape (char *s, size_t s_max, const char key_char, const char escape_char)
{
  char s_escaped[1024] = { 0 };

  size_t s_escaped_max = sizeof (s_escaped);

  const size_t len = strlen (s);

  for (size_t in = 0, out = 0; in < len; in++, out++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s_escaped[out] = escape_char;

      out++;
    }

    if (out == s_escaped_max - 2) break;

    s_escaped[out] = c;
  }

  strncpy (s, s_escaped, s_max - 1);
}

void hc_asprintf (char **strp, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  int rc __attribute__((unused));
  rc = vasprintf (strp, fmt, args);
  va_end (args);
}

#if defined (_WIN)
#define __WINDOWS__
#endif
#include "sort_r.h"
#if defined (_WIN)
#undef __WINDOWS__
#endif

void hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  sort_r (base, nmemb, size, compar, arg);
}

void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  for (size_t l = 0, r = nmemb; r; r >>= 1)
  {
    const size_t m = r >> 1;

    const size_t c = l + m;

    const char *next = (const char *) base + (c * size);

    const int cmp = (*compar) (key, next, arg);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return ((void *) next);
  }

  return (NULL);
}

bool hc_path_is_file (const char *path)
{
  struct stat s;

  if (stat (path, &s) == -1) return false;

  if (S_ISREG (s.st_mode)) return true;

  return false;
}

bool hc_path_is_directory (const char *path)
{
  struct stat s;

  if (stat (path, &s) == -1) return false;

  if (S_ISDIR (s.st_mode)) return true;

  return false;
}

bool hc_path_is_empty (const char *path)
{
  struct stat s;

  if (stat (path, &s) == -1) return false;

  if (s.st_size == 0) return true;

  return false;
}

bool hc_path_exist (const char *path)
{
  if (access (path, F_OK) == -1) return false;

  return true;
}

bool hc_path_read (const char *path)
{
  if (access (path, R_OK) == -1) return false;

  return true;
}

bool hc_path_write (const char *path)
{
  if (access (path, W_OK) == -1) return false;

  return true;
}

bool hc_path_create (const char *path)
{
  if (hc_path_exist (path) == true) return false;

  const int fd = creat (path, S_IRUSR | S_IWUSR);

  if (fd == -1) return false;

  close (fd);

  unlink (path);

  return true;
}

bool hc_path_has_bom (const char *path)
{
  u8 buf[8] = { 0 };

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return false;

  const size_t nread = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (nread < 1) return false;

  /* signatures from https://en.wikipedia.org/wiki/Byte_order_mark#Byte_order_marks_by_encoding */

  // utf-8

  if ((buf[0] == 0xef)
   && (buf[1] == 0xbb)
   && (buf[2] == 0xbf)) return true;

  // utf-16

  if ((buf[0] == 0xfe)
   && (buf[1] == 0xff)) return true;

  if ((buf[0] == 0xff)
   && (buf[1] == 0xfe)) return true;

  // utf-32

  if ((buf[0] == 0x00)
   && (buf[1] == 0x00)
   && (buf[2] == 0xfe)
   && (buf[3] == 0xff)) return true;

  if ((buf[0] == 0xff)
   && (buf[1] == 0xfe)
   && (buf[2] == 0x00)
   && (buf[3] == 0x00)) return true;

  // utf-7

  if ((buf[0] == 0x2b)
   && (buf[1] == 0x2f)
   && (buf[2] == 0x76)
   && (buf[3] == 0x38)) return true;

  if ((buf[0] == 0x2b)
   && (buf[1] == 0x2f)
   && (buf[2] == 0x76)
   && (buf[3] == 0x39)) return true;

  if ((buf[0] == 0x2b)
   && (buf[1] == 0x2f)
   && (buf[2] == 0x76)
   && (buf[3] == 0x2b)) return true;

  if ((buf[0] == 0x2b)
   && (buf[1] == 0x2f)
   && (buf[2] == 0x76)
   && (buf[3] == 0x2f)) return true;

  if ((buf[0] == 0x2b)
   && (buf[1] == 0x2f)
   && (buf[2] == 0x76)
   && (buf[3] == 0x38)
   && (buf[4] == 0x2d)) return true;

  // utf-1

  if ((buf[0] == 0xf7)
   && (buf[1] == 0x64)
   && (buf[2] == 0x4c)) return true;

  // utf-ebcdic

  if ((buf[0] == 0xdd)
   && (buf[1] == 0x73)
   && (buf[2] == 0x66)
   && (buf[3] == 0x73)) return true;

  // scsu

  if ((buf[0] == 0x0e)
   && (buf[1] == 0xfe)
   && (buf[2] == 0xff)) return true;

  // bocu-1

  if ((buf[0] == 0xfb)
   && (buf[1] == 0xee)
   && (buf[2] == 0x28)) return true;

  // gb-18030

  if ((buf[0] == 0x84)
   && (buf[1] == 0x31)
   && (buf[2] == 0x95)
   && (buf[3] == 0x33)) return true;

  return false;
}

bool hc_string_is_digit (const char *s)
{
  if (s == NULL) return false;

  const size_t len = strlen (s);

  if (len == 0) return false;

  for (size_t i = 0; i < len; i++)
  {
    const int c = (const int) s[i];

    if (isdigit (c) == 0) return false;
  }

  return true;
}

void setup_environment_variables ()
{
  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    char *display;

    hc_asprintf (&display, "DISPLAY=%s", compute);

    putenv (display);

    free (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  if (getenv ("OCL_CODE_CACHE_ENABLE") == NULL)
    putenv ((char *) "OCL_CODE_CACHE_ENABLE=0");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");

  if (getenv ("CL_CONFIG_USE_VECTORIZER") == NULL)
    putenv ((char *) "CL_CONFIG_USE_VECTORIZER=False");

  #if defined (__CYGWIN__)
  cygwin_internal (CW_SYNC_WINENV);
  #endif
}

void setup_umask ()
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

  return (((u32) rand () % (max - min)) + min);

  #else

  return (((u32) random () % (max - min)) + min);

  #endif
}

void hc_string_trim_leading (char *s)
{
  int skip = 0;

  const int len = (int) strlen (s);

  for (int i = 0; i < len; i++)
  {
    const int c = (const int) s[i];

    if (isspace (c) == 0) break;

    skip++;
  }

  if (skip == 0) return;

  const int new_len = len - skip;

  memmove (s, s + skip, new_len);

  s[new_len] = 0;
}

void hc_string_trim_trailing (char *s)
{
  int skip = 0;

  const int len = (int) strlen (s);

  for (int i = len - 1; i >= 0; i--)
  {
    const int c = (const int) s[i];

    if (isspace (c) == 0) break;

    skip++;
  }

  if (skip == 0) return;

  const size_t new_len = len - skip;

  s[new_len] = 0;
}

size_t hc_fread (void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  return fread (ptr, size, nmemb, stream);
}

void hc_fwrite (const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  size_t rc = fwrite (ptr, size, nmemb, stream);

  if (rc == 0) rc = 0;
}

bool hc_same_files (char *file1, char *file2)
{
  if ((file1 != NULL) && (file2 != NULL))
  {
    struct stat tmpstat_file1;
    struct stat tmpstat_file2;

    int do_check = 0;

    FILE *fp;

    fp = fopen (file1, "r");

    if (fp)
    {
      if (fstat (fileno (fp), &tmpstat_file1))
      {
        fclose (fp);

        return false;
      }

      fclose (fp);

      do_check++;
    }

    fp = fopen (file2, "r");

    if (fp)
    {
      if (fstat (fileno (fp), &tmpstat_file2))
      {
        fclose (fp);

        return false;
      }

      fclose (fp);

      do_check++;
    }

    if (do_check == 2)
    {
      tmpstat_file1.st_mode     = 0;
      tmpstat_file1.st_nlink    = 0;
      tmpstat_file1.st_uid      = 0;
      tmpstat_file1.st_gid      = 0;
      tmpstat_file1.st_rdev     = 0;
      tmpstat_file1.st_atime    = 0;

      #if defined (STAT_NANOSECONDS_ACCESS_TIME)
      tmpstat_file1.STAT_NANOSECONDS_ACCESS_TIME = 0;
      #endif

      #if defined (_POSIX)
      tmpstat_file1.st_blksize  = 0;
      tmpstat_file1.st_blocks   = 0;
      #endif

      tmpstat_file2.st_mode     = 0;
      tmpstat_file2.st_nlink    = 0;
      tmpstat_file2.st_uid      = 0;
      tmpstat_file2.st_gid      = 0;
      tmpstat_file2.st_rdev     = 0;
      tmpstat_file2.st_atime    = 0;

      #if defined (STAT_NANOSECONDS_ACCESS_TIME)
      tmpstat_file2.STAT_NANOSECONDS_ACCESS_TIME = 0;
      #endif

      #if defined (_POSIX)
      tmpstat_file2.st_blksize  = 0;
      tmpstat_file2.st_blocks   = 0;
      #endif

      if (memcmp (&tmpstat_file1, &tmpstat_file2, sizeof (struct stat)) == 0)
      {
        return true;
      }
    }
  }

  return false;
}

u32 hc_strtoul (const char *nptr, char **endptr, int base)
{
  return (u32) strtoul (nptr, endptr, base);
}

u64 hc_strtoull (const char *nptr, char **endptr, int base)
{
  return (u64) strtoull (nptr, endptr, base);
}

u32 power_of_two_ceil_32 (const u32 v)
{
  u32 r = v;

  r--;

  r |= r >> 1;
  r |= r >> 2;
  r |= r >> 4;
  r |= r >> 8;
  r |= r >> 16;

  r++;

  return r;
}

u32 power_of_two_floor_32 (const u32 v)
{
  u32 r = power_of_two_ceil_32 (v);

  if (r > v)
  {
    r >>= 1;
  }

  return r;
}

u32 round_up_multiple_32 (const u32 v, const u32 m)
{
  if (m == 0) return v;

  const u32 r = v % m;

  if (r == 0) return v;

  return v + m - r;
}

u64 round_up_multiple_64 (const u64 v, const u64 m)
{
  if (m == 0) return v;

  const u64 r = v % m;

  if (r == 0) return v;

  return v + m - r;
}

// difference to original strncat is no returncode and u8* instead of char*

void hc_strncat (u8 *dst, u8 *src, const size_t n)
{
  const size_t dst_len = strlen ((char *) dst);

  u8 *src_ptr = src;
  u8 *dst_ptr = dst + dst_len;

  for (size_t i = 0; i < n && *src_ptr != 0; i++)
  {
    *dst_ptr++ = *src_ptr++;
  }

  *dst_ptr = 0;
}

int count_char (const u8 *buf, const int len, const u8 c)
{
  int r = 0;

  for (int i = 0; i < len; i++)
  {
    if (buf[i] == c) r++;
  }

  return r;
}

float get_entropy (const u8 *buf, const int len)
{
  float entropy = 0.0;

  for (int c = 0; c < 256; c++)
  {
    const int r = count_char (buf, len, (const u8) c);

    if (r == 0) continue;

    float w = (float) r / len;

    entropy += -w * log2 (w);
  }

  return entropy;
}

int select_read_timeout (int sockfd, const int sec)
{
  struct timeval tv;

  tv.tv_sec  = sec;
  tv.tv_usec = 0;

  fd_set fds;

  FD_ZERO (&fds);
  FD_SET (sockfd, &fds);

  return select (sockfd + 1, &fds, NULL, NULL, &tv);
}

int select_write_timeout (int sockfd, const int sec)
{
  struct timeval tv;

  tv.tv_sec  = sec;
  tv.tv_usec = 0;

  fd_set fds;

  FD_ZERO (&fds);
  FD_SET (sockfd, &fds);

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
