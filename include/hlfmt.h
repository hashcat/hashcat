/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HLFMT_H
#define _HLFMT_H

#include <stdio.h>

#define HLFMTS_CNT 11

char *strhlfmt (const u32 hashfile_format);

void hlfmt_hash (u32 hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, const hashconfig_t *hashconfig, const user_options_t *user_options);
void hlfmt_user (u32 hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len, const hashconfig_t *hashconfig);

u32 hlfmt_detect (FILE *fp, u32 max_check, const hashconfig_t *hashconfig);

#endif // _HLFMT_H
