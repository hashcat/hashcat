/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_BASE58_H
#define _INC_HASH_BASE58_H

DECLSPEC bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz);
DECLSPEC int b58check(const void *bin, size_t binsz);

DECLSPEC bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
DECLSPEC bool b58check_enc(char *b58c, size_t *b58c_sz, u8 ver, const void *data, size_t datasz);

DECLSPEC bool b58dec_51 (u32 *out, const char *data);
DECLSPEC bool b58dec_52 (u32 *out, const char *data);

#endif // _INC_HASH_BASE58_H