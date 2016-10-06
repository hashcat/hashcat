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

static const char LOOPBACK_FILE[] = "hashcat.loopback";

int  loopback_init          (hashcat_ctx_t *hashcat_ctx);
void loopback_destroy       (hashcat_ctx_t *hashcat_ctx);
int  loopback_write_open    (hashcat_ctx_t *hashcat_ctx);
void loopback_write_close   (hashcat_ctx_t *hashcat_ctx);
void loopback_write_append  (hashcat_ctx_t *hashcat_ctx, const u8 *plain_ptr, const unsigned int plain_len);
void loopback_write_unlink  (hashcat_ctx_t *hashcat_ctx);

#endif // _LOOPBACK_H
