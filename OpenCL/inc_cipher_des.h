/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void _des_crypt_encrypt (u32x *iv, u32x *data, u32x *Kc, u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
DECLSPEC void _des_crypt_decrypt (u32x *iv, u32x *data, u32x *Kc, u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
DECLSPEC void _des_crypt_keysetup (u32x c, u32x d, u32x *Kc, u32x *Kd, SHM_TYPE u32 (*s_skb)[64])
