/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_CIPHER_SALSA20_H
#define INC_CIPHER_SALSA20_H

DECLSPEC void salsa20_20      (PRIVATE_AS u32 *x);
DECLSPEC void hsalsa20        (PRIVATE_AS const u32 *k, PRIVATE_AS const u32 *n, PRIVATE_AS u32 *out);
DECLSPEC void salsa20_block   (PRIVATE_AS const u32 *k, PRIVATE_AS const u32 *n, PRIVATE_AS const u32 *c, PRIVATE_AS u32 *out);
DECLSPEC void xsalsa20_stream (PRIVATE_AS u32 *out, const u32 out_len, PRIVATE_AS const u32 *n, PRIVATE_AS const u32 *k);

#endif // INC_CIPHER_SALSA20_H
