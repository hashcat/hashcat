/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_TWOFISH_H
#define _INC_CIPHER_TWOFISH_H

DECLSPEC u32 mds_rem (u32 p0, u32 p1);
DECLSPEC u32 h_fun128 (PRIVATE_AS const u32 x, PRIVATE_AS const u32 *key);
DECLSPEC void twofish128_set_key (PRIVATE_AS u32 *sk, PRIVATE_AS u32 *lk, PRIVATE_AS const u32 *ukey);
DECLSPEC void twofish128_encrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void twofish128_decrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC u32 h_fun192 (const u32 x, PRIVATE_AS const u32 *key);
DECLSPEC void twofish192_set_key (PRIVATE_AS u32 *sk, PRIVATE_AS u32 *lk, PRIVATE_AS const u32 *ukey);
DECLSPEC void twofish192_encrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void twofish192_decrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC u32 h_fun256 (const u32 x, PRIVATE_AS const u32 *key);
DECLSPEC void twofish256_set_key (PRIVATE_AS u32 *sk, PRIVATE_AS u32 *lk, PRIVATE_AS const u32 *ukey);
DECLSPEC void twofish256_encrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void twofish256_decrypt (PRIVATE_AS const u32 *sk, PRIVATE_AS const u32 *lk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // _INC_CIPHER_TWOFISH_H
