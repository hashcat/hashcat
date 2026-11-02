/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_CIPHER_AES_MODES_H
#define INC_CIPHER_AES_MODES_H

// AES operates on byte strings stored as little endian words, matching the password's input format.
// Keys of 16, 24 or 32 bytes select AES-128, AES-192 or AES-256. Each call creates its own key
// schedule from that key. The s_te0 to s_te4 and s_td0 to s_td4 tables come from inc_cipher_aes.cl
// and use local memory when the kernel stores them there.

DECLSPEC void aes_set_encrypt_key_swap (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *key, const u32 key_len, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3);
DECLSPEC void aes_set_decrypt_key_swap (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *key, const u32 key_len, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3);

DECLSPEC void aes_encrypt_block (PRIVATE_AS const u32 *ks, const u32 key_len, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void aes_decrypt_block (PRIVATE_AS const u32 *ks, const u32 key_len, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

// The len argument must be a multiple of 16 bytes for ECB and CBC. No padding is added or removed.

DECLSPEC void aes_ecb_encrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void aes_ecb_decrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC void aes_cbc_encrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4);
DECLSPEC void aes_cbc_decrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

DECLSPEC void aes_unwrap_rounds (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, PRIVATE_AS u32 *a, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

// RFC 3394 key unwrap takes 8 + 8n bytes in the in buffer, with n at least 1. The out buffer
// receives the key of 8n bytes. Return 8n, or 0 if the integrity check value is not
// A6A6A6A6A6A6A6A6. The aes_unwrap_iv_swap () function writes the check value itself to out[0] and
// out[1] instead, allowing the caller to compare that value.

DECLSPEC u32  aes_unwrap_swap    (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);
DECLSPEC void aes_unwrap_iv_swap (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

#endif // INC_CIPHER_AES_MODES_H
