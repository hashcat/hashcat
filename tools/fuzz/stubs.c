/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * The event log is how the core reports to the outside world, and reaching the
 * real implementation means linking the whole hashcat_ctx into every fuzz
 * target. The targets do not read what is logged, so the three event_log
 * functions below take its place. The file layer and the random generator are
 * stubbed further down, for the rule compiler. Everything else a target calls
 * is the real code, compiled from the same source the binary is built from.
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
// file layer says "no file" and the generator is a constant.

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

size_t superchop_with_length (char *buf, const size_t len)
{
  // The mask parser reaches this only on its charset file path, after hc_fopen () succeeds. The
  // hc_fopen () stub returns false, so this is never reached and a no op is enough.

  (void) buf;

  return len;
}

// The mask parser shares src/mpsp.c with the feed-driving code (mask_ctx_update_loop and friends),
// which the harness never calls but which the linker still has to resolve. These are the symbols
// that code reaches into the core for. A run only ever calls mask_css_parse, so none of these runs.

int backend_session_update_combinator (hashcat_ctx_t *hashcat_ctx)
{
  (void) hashcat_ctx;

  return 0;
}

int backend_session_update_mp (hashcat_ctx_t *hashcat_ctx)
{
  (void) hashcat_ctx;

  return 0;
}

int backend_session_update_mp_rl (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r)
{
  (void) hashcat_ctx;
  (void) css_cnt_l;
  (void) css_cnt_r;

  return 0;
}

const char *generic_ctx_segment_of (const hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u64 index)
{
  (void) hashcat_ctx;
  (void) role;
  (void) index;

  return NULL;
}

int generic_ctx_word_family (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u8 *anchor, const u32 min_len, const u32 max_len, const bool backward, u64 *out_index, u64 *out_words)
{
  (void) hashcat_ctx;
  (void) role;
  (void) anchor;
  (void) min_len;
  (void) max_len;
  (void) backward;
  (void) out_index;
  (void) out_words;

  return -1;
}

void logfile_append (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;
}

// A module reads its own options through these. They live with the option table in
// src/module_options.c, which a parser target does not link, and a target never sets an option, so
// none is ever given.

bool        module_option_given (const user_options_t *user_options, const char *name);
u32         module_option_u32   (const user_options_t *user_options, const char *name);
const char *module_option_str   (const user_options_t *user_options, const char *name);

bool module_option_given (const user_options_t *user_options, const char *name)
{
  (void) user_options;
  (void) name;

  return false;
}

u32 module_option_u32 (const user_options_t *user_options, const char *name)
{
  (void) user_options;
  (void) name;

  return 0;
}

const char *module_option_str (const user_options_t *user_options, const char *name)
{
  (void) user_options;
  (void) name;

  return NULL;
}
