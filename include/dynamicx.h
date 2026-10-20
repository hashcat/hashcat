/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_DYNAMICX_H
#define HC_DYNAMICX_H

#include <stdio.h>

// How a --dynamic-x line is laid out once it is hashcat's. Without DYNAMICX_LINE_RECIPE it is
// <hash><separator><salt>. With it, it is a mode 4000 line, <hash>*<salt>*<salt2>*<user>, carrying
// the salt and the fields its recipe reads, and the salt in hex or base64 if the recipe decodes it
// from that. The SPLIT bits say which of John's $$2 and $$U markers are taken off the end of the
// salt, which is the fields John's format declares.

#define DYNAMICX_LINE_RECIPE   (1u << 0)
#define DYNAMICX_LINE_SALT     (1u << 1)
#define DYNAMICX_LINE_SALT_HEX (1u << 2)
#define DYNAMICX_LINE_SALT_B64 (1u << 3)
#define DYNAMICX_LINE_SALT2    (1u << 4)
#define DYNAMICX_LINE_USER     (1u << 5)
#define DYNAMICX_SPLIT_SALT2   (1u << 6)
#define DYNAMICX_SPLIT_USER    (1u << 7)

int         dynamicx_hash_mode  (const int dynamic_num, const bool optimized);
const char *dynamicx_expression (const int dynamic_num);
const char *dynamicx_recipe     (const int dynamic_num);

int dynamicx_tag_number (const char *line_buf, const int line_len, int *tag_len);
int dynamicx_translate  (char *line_buf, const int line_len, const int line_size, const char separator, const u32 layout, int *tag_len, int *hash_len, char **kept_buf, u32 *kept_len, const char **error);
int dynamicx_encode     (char *out_buf, const hashinfo_t *hash_info, const int tag_len, const int hash_len, const int out_sz);

int dynamicx_first_number      (hashcat_ctx_t *hashcat_ctx);
int dynamicx_session_hash_mode (hashcat_ctx_t *hashcat_ctx);

#endif // HC_DYNAMICX_H
