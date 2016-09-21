/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OUTFILE_H
#define _OUTFILE_H

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

typedef enum outfile_fmt
{
  OUTFILE_FMT_HASH      = (1 << 0),
  OUTFILE_FMT_PLAIN     = (1 << 1),
  OUTFILE_FMT_HEXPLAIN  = (1 << 2),
  OUTFILE_FMT_CRACKPOS  = (1 << 3)

} outfile_fmt_t;

void outfile_init           (outfile_ctx_t *outfile_ctx, const user_options_t *user_options);
void outfile_destroy        (outfile_ctx_t *outfile_ctx);
void outfile_format_plain   (outfile_ctx_t *outfile_ctx, const unsigned char *plain_ptr, const uint plain_len);
void outfile_write_open     (outfile_ctx_t *outfile_ctx);
void outfile_write_close    (outfile_ctx_t *outfile_ctx);
void outfile_write          (outfile_ctx_t *outfile_ctx, const char *out_buf, const unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, const unsigned char *username, const uint user_len, const hashconfig_t *hashconfig);
int  outfile_and_hashfile   (outfile_ctx_t *outfile_ctx, const char *hashfile);

#endif // _OUTFILE_H
