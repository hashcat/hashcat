/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_AES_H
#define _CPU_AES_H

#define AES_KEY aes_ctx
void AES_set_encrypt_key (const u8 *key, int keysize, AES_KEY *aes_key);
void AES_set_decrypt_key (const u8 *key, int keysize, AES_KEY *aes_key);
void AES_encrypt (AES_KEY *aes_key, const u8 *input, u8 *output);
void AES_decrypt (AES_KEY *aes_key, const u8 *input, u8 *output);

void AES128_decrypt_cbc (const u32 key[4], const u32 iv[4], const u32 in[16], u32 out[16]);

#endif // _CPU_AES_H
