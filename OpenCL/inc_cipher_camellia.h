/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_CAMELLIA_H
#define _INC_CIPHER_CAMELLIA_H

DECLSPEC void cam_feistel (const u32 *x, const u32 *k, u32 *y);
DECLSPEC void cam_fl (u32 *x, const u32 *kl, const u32 *kr);
DECLSPEC void camellia256_set_key (u32 *ks, const u32 *ukey);
DECLSPEC void camellia256_encrypt (const u32 *ks, const u32 *in, u32 *out);
DECLSPEC void camellia256_decrypt (const u32 *ks, const u32 *in, u32 *out);

#endif // _INC_CIPHER_CAMELLIA_H
