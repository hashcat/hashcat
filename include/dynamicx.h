/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_DYNAMICX_H
#define HC_DYNAMICX_H

#include <stdio.h>

int         dynamicx_hash_mode  (const int dynamic_num);
const char *dynamicx_expression (const int dynamic_num);

int dynamicx_tag_number (const char *line_buf, const int line_len, int *tag_len);
int dynamicx_translate  (char *line_buf, const int line_len, const char separator, int *tag_len, int *hash_len, const char **error);
int dynamicx_encode     (char *out_buf, const int tag_len, const int hash_len, const char separator, const int out_sz);

int dynamicx_first_number      (hashcat_ctx_t *hashcat_ctx);
int dynamicx_session_hash_mode (hashcat_ctx_t *hashcat_ctx);

#endif // HC_DYNAMICX_H
