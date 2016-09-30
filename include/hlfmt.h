/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HLFMT_H
#define _HLFMT_H

#include <stdio.h>

#define HLFMTS_CNT 11

char *strhlfmt (const uint hashfile_format);

void hlfmt_hash (uint hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, const hashconfig_t *hashconfig, const user_options_t *user_options);
void hlfmt_user (uint hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len, const hashconfig_t *hashconfig);

uint hlfmt_detect (FILE *fp, uint max_check, const hashconfig_t *hashconfig);

#endif // _HLFMT_H
