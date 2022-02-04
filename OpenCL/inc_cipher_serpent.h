/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_SERPENT_H
#define _INC_CIPHER_SERPENT_H

DECLSPEC void serpent128_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void serpent128_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void serpent128_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void serpent192_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void serpent192_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void serpent192_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void serpent256_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void serpent256_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void serpent256_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // _INC_CIPHER_SERPENT_H
