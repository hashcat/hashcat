/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_AES_GCM_H
#define _INC_CIPHER_AES_GCM_H

DECLSPEC void AES_GCM_inc32 (u32 *block);
DECLSPEC void AES_GCM_xor_block (u32 *dst, const u32 *src);
DECLSPEC void AES_GCM_gf_mult (const u32 *x, const u32 *y, u32 *z);
DECLSPEC void AES_GCM_ghash (const u32 *subkey, const u32 *in, int in_len, u32 *out);
DECLSPEC void AES_GCM_ghash_global (const u32 *subkey, GLOBAL_AS const u32 *in, int in_len, u32 *out);
DECLSPEC void AES_GCM_Init (const u32 *ukey, int key_len, u32 *key, u32 *subkey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_Prepare_J0 (const u32 *iv, int iv_len, const u32 *subkey, u32 *J0);
DECLSPEC void AES_GCM_gctr (const u32 *key, const u32 *iv, const u32 *in, int in_len, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_GCTR (u32 *key, u32 *J0, const u32 *in, int in_len, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void AES_GCM_GHASH (const u32 *subkey, const u32 *aad_buf, int aad_len, const u32 *enc_buf, int enc_len, u32 *out);
DECLSPEC void AES_GCM_GHASH_GLOBAL (const u32 *subkey, const u32 *aad_buf, int aad_len, GLOBAL_AS const u32 *enc_buf, int enc_len, u32 *out);

#endif // _INC_CIPHER_AES_GCM_H
