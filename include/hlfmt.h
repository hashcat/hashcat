/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _HLFMT_H
#define _HLFMT_H

#include <stdio.h>

char *strhlfmt (const uint hashfile_format);

void hlfmt_hash (uint hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len);
void hlfmt_user (uint hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len);

uint hlfmt_detect (FILE *fp, uint max_check);

#endif // _HLFMT_H
