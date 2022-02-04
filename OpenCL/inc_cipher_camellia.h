/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_CAMELLIA_H
#define _INC_CIPHER_CAMELLIA_H

DECLSPEC void cam_feistel (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *k, PRIVATE_AS u32 *y);
DECLSPEC void cam_fl (PRIVATE_AS u32 *x, PRIVATE_AS const u32 *kl, PRIVATE_AS const u32 *kr);
DECLSPEC void camellia256_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void camellia256_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void camellia256_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // _INC_CIPHER_CAMELLIA_H
