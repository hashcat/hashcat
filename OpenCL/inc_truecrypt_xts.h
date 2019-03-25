/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_TRUECRYPT_XTS_H
#define _INC_TRUECRYPT_XTS_H

DECLSPEC void xts_mul2 (u32 *in, u32 *out);
DECLSPEC void aes256_decrypt_xts_first (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC void aes256_decrypt_xts_next (const u32 *in, u32 *out, u32 *T, u32 *ks, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC void serpent256_decrypt_xts_first (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *ks);
DECLSPEC void serpent256_decrypt_xts_next (const u32 *in, u32 *out, u32 *T, u32 *ks);
DECLSPEC void twofish256_decrypt_xts_first (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *sk, u32 *lk);
DECLSPEC void twofish256_decrypt_xts_next (const u32 *in, u32 *out, u32 *T, u32 *sk, u32 *lk);
DECLSPEC int verify_header_aes (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC int verify_header_serpent (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2);
DECLSPEC int verify_header_twofish (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2);
DECLSPEC int verify_header_aes_twofish (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC int verify_header_serpent_aes (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC int verify_header_twofish_serpent (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4);
DECLSPEC int verify_header_aes_twofish_serpent (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, const u32 *ukey5, const u32 *ukey6, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC int verify_header_serpent_twofish_aes (GLOBAL_AS const u32 *data_buf, const u32 signature, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, const u32 *ukey5, const u32 *ukey6, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

#endif // _INC_TRUECRYPT_XTS_H
