/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _POTFILE_H
#define _POTFILE_H

#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#define INCR_POT 1000

int sort_by_hash_t_salt       (const void *v1, const void *v2);
int sort_by_hash_t_salt_hccap (const void *v1, const void *v2);

int  potfile_init             (hashcat_ctx_t *hashcat_ctx);
int  potfile_read_open        (hashcat_ctx_t *hashcat_ctx);
void potfile_read_close       (hashcat_ctx_t *hashcat_ctx);
int  potfile_write_open       (hashcat_ctx_t *hashcat_ctx);
void potfile_write_close      (hashcat_ctx_t *hashcat_ctx);
void potfile_write_append     (hashcat_ctx_t *hashcat_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len);
int  potfile_remove_parse     (hashcat_ctx_t *hashcat_ctx);
void potfile_destroy          (hashcat_ctx_t *hashcat_ctx);
int  potfile_handle_show      (hashcat_ctx_t *hashcat_ctx);
int  potfile_handle_left      (hashcat_ctx_t *hashcat_ctx);

#endif // _POTFILE_H
