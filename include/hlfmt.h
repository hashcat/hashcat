/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HLFMT_H
#define _HLFMT_H

#include <stdio.h>

#define HLFMTS_CNT 11

const char *strhlfmt (const u32 hashfile_format);

void hlfmt_hash (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, size_t line_len, char **hashbuf_pos, size_t *hashbuf_len);
void hlfmt_user (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, size_t line_len, char **userbuf_pos, size_t *userbuf_len);

u32 hlfmt_detect (hashcat_ctx_t *hashcat_ctx, FILE *fp, u32 max_check);

#endif // _HLFMT_H
