/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _LOOPBACK_H
#define _LOOPBACK_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define LOOPBACK_FILE   "hashcat.loopback"

void loopback_init          (loopback_ctx_t *loopback_ctx, const user_options_t *user_options);
void loopback_destroy       (loopback_ctx_t *loopback_ctx);
int  loopback_write_open    (loopback_ctx_t *loopback_ctx, const induct_ctx_t *induct_ctx);
void loopback_write_close   (loopback_ctx_t *loopback_ctx);
void loopback_format_plain  (loopback_ctx_t *loopback_ctx, const u8 *plain_ptr, const unsigned int plain_len);
void loopback_write_append  (loopback_ctx_t *loopback_ctx, const u8 *plain_ptr, const unsigned int plain_len);
void loopback_write_unlink  (loopback_ctx_t *loopback_ctx);

#endif // _LOOPBACK_H
