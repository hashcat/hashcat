/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_AES_GCM_H
#define _INC_CIPHER_AES_GCM_H

DECLSPEC void AES_GCM_inc32 (PRIVATE_AS u32 *block);
DECLSPEC void AES_GCM_xor_block (PRIVATE_AS u32 *dst, PRIVATE_AS const u32 *src);
DECLSPEC void AES_GCM_gf_mult (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y, PRIVATE_AS u32 *z);
DECLSPEC void AES_GCM_ghash (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out);
DECLSPEC void AES_GCM_ghash_global (PRIVATE_AS const u32 *subkey, GLOBAL_AS const u32 *in, int in_len, PRIVATE_AS u32 *out);
DECLSPEC void AES_GCM_Init (PRIVATE_AS const u32 *ukey, int key_len, PRIVATE_AS u32 *key, PRIVATE_AS u32 *subkey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_Prepare_J0 (PRIVATE_AS const u32 *iv, int iv_len, PRIVATE_AS const u32 *subkey, PRIVATE_AS u32 *J0);
DECLSPEC void AES_GCM_gctr (PRIVATE_AS const u32 *key, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_GCTR (PRIVATE_AS u32 *key, PRIVATE_AS u32 *J0, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_GHASH (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *aad_buf, int aad_len, PRIVATE_AS const u32 *enc_buf, int enc_len, PRIVATE_AS u32 *out);
DECLSPEC void AES_GCM_GHASH_GLOBAL (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *aad_buf, int aad_len, GLOBAL_AS const u32 *enc_buf, int enc_len, PRIVATE_AS u32 *out);

#endif // _INC_CIPHER_AES_GCM_H
