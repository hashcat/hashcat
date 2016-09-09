/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _POTFILE_H
#define _POTFILE_H

#include <stdio.h>
#include <errno.h>

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

} potfile_ctx_t;

void potfile_init        (potfile_ctx_t *potfile_ctx, const char *profile_dir, const char *potfile_path);
int  potfile_read_open   (potfile_ctx_t *potfile_ctx);
void potfile_read_close  (potfile_ctx_t *potfile_ctx);
int  potfile_write_open  (potfile_ctx_t *potfile_ctx);
void potfile_write_close (potfile_ctx_t *potfile_ctx);
void potfile_destroy     (potfile_ctx_t *potfile_ctx);

#endif // _POTFILE_H
