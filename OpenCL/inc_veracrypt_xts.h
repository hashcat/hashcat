/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_VERACRYPT_XTS_H
#define _INC_HASH_VERACRYPT_XTS_H

DECLSPEC void camellia256_decrypt_xts_first (PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *S, PRIVATE_AS u32 *T, PRIVATE_AS u32 *ks);
DECLSPEC void camellia256_decrypt_xts_next (PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *T, PRIVATE_AS u32 *ks);
DECLSPEC void kuznyechik_decrypt_xts_first (PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *S, PRIVATE_AS u32 *T, PRIVATE_AS u32 *ks);
DECLSPEC void kuznyechik_decrypt_xts_next (PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *T, PRIVATE_AS u32 *ks);
DECLSPEC int verify_header_camellia (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2);
DECLSPEC int verify_header_kuznyechik (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2);
DECLSPEC int verify_header_camellia_kuznyechik (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *ukey3, PRIVATE_AS const u32 *ukey4);
DECLSPEC int verify_header_camellia_serpent (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *ukey3, PRIVATE_AS const u32 *ukey4);
DECLSPEC int verify_header_kuznyechik_aes (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *ukey3, PRIVATE_AS const u32 *ukey4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC int verify_header_kuznyechik_twofish (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *ukey3, PRIVATE_AS const u32 *ukey4);
DECLSPEC int verify_header_kuznyechik_serpent_camellia (GLOBAL_AS const u32 *data_buf, const u32 signature, PRIVATE_AS const u32 *ukey1, PRIVATE_AS const u32 *ukey2, PRIVATE_AS const u32 *ukey3, PRIVATE_AS const u32 *ukey4, PRIVATE_AS const u32 *ukey5, PRIVATE_AS const u32 *ukey6);

#endif // _INC_HASH_VERACRYPT_XTS_H
