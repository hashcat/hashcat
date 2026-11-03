/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BESTCRYPT_H
#define INC_BESTCRYPT_H

#define BESTCRYPT_MODE_CBC 0xBC000002
#define BESTCRYPT_MODE_XTS 0xBC000004

// the PKCS#12 block size, which the key generator fixes at 64 bytes whatever the hash is

#define BESTCRYPT_V 64

// the part of a key slot the password is checked against: the first 8 blocks hold 90 bytes of key
// data and, at offset 96, the first 32 bytes of the digest of those 90 bytes

#define BESTCRYPT_BLOCK_LEN  128
#define BESTCRYPT_BODY_LEN   90
#define BESTCRYPT_DIGEST_OFF 96

// the longest password the widened buffer below holds, which module_pw_max () answers with

#define BESTCRYPT_PW_MAX 63

DECLSPEC void bestcrypt_salt_bytes (PRIVATE_AS u8 *out, GLOBAL_AS const u32 *salt_buf, const int salt_len);
DECLSPEC void bestcrypt_pwd_bytes (PRIVATE_AS u8 *out, GLOBAL_AS const u32 *pw_buf, const int pw_len);
DECLSPEC void bestcrypt_fill_be (PRIVATE_AS u32 *dst, const int dst_len, PRIVATE_AS const u8 *src, const int src_len);
DECLSPEC int bestcrypt_v2 (const int pw_len);
DECLSPEC void bestcrypt_inc512 (PRIVATE_AS u32 *a);
DECLSPEC void bestcrypt_add512 (PRIVATE_AS u32 *a, PRIVATE_AS const u32 *b);
DECLSPEC int bestcrypt_kdf_input (PRIVATE_AS u32 *w, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS const u32 *pw_buf, const int pw_len, const int v2);
DECLSPEC void bestcrypt_xts_mul2 (PRIVATE_AS u32 *t);
DECLSPEC void bestcrypt_decrypt_block (PRIVATE_AS u32 *pt, GLOBAL_AS const u32 *slot_buf, const int iv_off, const u32 mode_id, PRIVATE_AS const u32 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

#endif // INC_BESTCRYPT_H
