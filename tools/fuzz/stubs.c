/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * The event log is how the core reports to the outside world, and reaching the
 * real implementation means linking the whole hashcat_ctx into every fuzz
 * target. The targets do not read what is logged, so these three take its
 * place. Everything else a target calls is the real code, compiled from the
 * same source the binary is built from.
 */

#include "common.h"
#include "types.h"

#include <stdarg.h>
#include <stdint.h>

size_t event_log_info    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
size_t event_log_error   (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}

// The rule compiler reaches the file layer and the random generator behind
// generate_random_rule (). No target opens a file or generates a rule, so the
// file layer says "no file" and the generator is a constant. Everything else a
// target calls is the real code.

#include "filehandling.h"

bool hc_fopen_raw (HCFILE *fp, const char *path, const char *mode)
{
  (void) fp;
  (void) path;
  (void) mode;

  return false;
}

bool hc_fopen (HCFILE *fp, const char *path, const char *mode)
{
  (void) fp;
  (void) path;
  (void) mode;

  return false;
}

const char *hc_fopen_strerror (void)
{
  return "no file layer in a fuzz target";
}

void hc_fclose (HCFILE *fp)
{
  (void) fp;
}

int hc_feof (HCFILE *fp)
{
  (void) fp;

  return 1;
}

size_t fgetl (HCFILE *fp, char *line_buf, const size_t line_sz)
{
  (void) fp;
  (void) line_buf;
  (void) line_sz;

  return 0;
}

u32 get_random_num (const u32 min, const u32 max)
{
  (void) max;

  return min;
}

// A module that can also read a binary capture file, m22000 for instance,
// names the file layer from module_hash_binary_parse (). The target only ever
// calls module_hash_decode (), so these say the file is empty.

int hc_fseek (HCFILE *fp, off_t offset, int whence)
{
  (void) fp;
  (void) offset;
  (void) whence;

  return -1;
}

size_t hc_fread (void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) fp;

  return 0;
}

void hc_rewind (HCFILE *fp)
{
  (void) fp;
}

u64 count_lines (HCFILE *fp)
{
  (void) fp;

  return 0;
}
