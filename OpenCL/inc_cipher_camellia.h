/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_CIPHER_CAMELLIA_H
#define INC_CIPHER_CAMELLIA_H

DECLSPEC void camellia_feistel (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *ke, PRIVATE_AS u32 *y);
DECLSPEC void camellia_fl (PRIVATE_AS u32 *x, PRIVATE_AS const u32 *ke1, PRIVATE_AS const u32 *ke2);
DECLSPEC void camellia256_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void camellia256_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void camellia256_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // INC_CIPHER_CAMELLIA_H
