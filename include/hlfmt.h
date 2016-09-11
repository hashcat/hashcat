/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HLFMT_H
#define _HLFMT_H

#include <stdio.h>

#define HLFMTS_CNT 11

typedef enum hlfmt_name
{
  HLFMT_HASHCAT  = 0,
  HLFMT_PWDUMP   = 1,
  HLFMT_PASSWD   = 2,
  HLFMT_SHADOW   = 3,
  HLFMT_DCC      = 4,
  HLFMT_DCC2     = 5,
  HLFMT_NETNTLM1 = 7,
  HLFMT_NETNTLM2 = 8,
  HLFMT_NSLDAP   = 9,
  HLFMT_NSLDAPS  = 10

} hlfmt_name_t;

char *strhlfmt (const uint hashfile_format);

void hlfmt_hash (uint hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, hashconfig_t *hashconfig);
void hlfmt_user (uint hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len, hashconfig_t *hashconfig);

uint hlfmt_detect (FILE *fp, uint max_check, hashconfig_t *hashconfig);

#endif // _HLFMT_H
