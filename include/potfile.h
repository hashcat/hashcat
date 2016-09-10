/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _POTFILE_H
#define _POTFILE_H

#include <stdio.h>
#include <errno.h>

#define POTFILE_DISABLE 0

#define INCR_POT 1000


typedef struct
{
  char    plain_buf[HCBUFSIZ_TINY];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct
{
  FILE *fp;

  char *filename;

  pot_t *pot;

  uint pot_cnt;
  uint pot_avail;
  uint pot_hashes_avail;

} potfile_ctx_t;

int sort_by_pot (const void *v1, const void *v2);

void potfile_init         (potfile_ctx_t *potfile_ctx, const char *profile_dir, const char *potfile_path);
int  potfile_read_open    (potfile_ctx_t *potfile_ctx);
void potfile_read_parse   (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig);
void potfile_read_close   (potfile_ctx_t *potfile_ctx);
int  potfile_write_open   (potfile_ctx_t *potfile_ctx);
void potfile_write_close  (potfile_ctx_t *potfile_ctx);
void potfile_write_append (potfile_ctx_t *potfile_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len);
void potfile_hash_alloc   (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig, const uint num);
void potfile_hash_free    (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig);
void potfile_destroy      (potfile_ctx_t *potfile_ctx);

#endif // _POTFILE_H
