/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef AES_H
#define AES_H

/* AES context.  */
typedef struct aes_context
{
  uint bits;

  uint rek[60];
  uint rdk[60];

} aes_context_t;

typedef aes_context_t aes_ctx;

#define AES_KEY aes_ctx
void AES_set_encrypt_key (unsigned char *key, int keysize, AES_KEY *aes_key);
void AES_set_decrypt_key (unsigned char *key, int keysize, AES_KEY *aes_key);
void AES_encrypt (AES_KEY *aes_key, char *input, char *output);
void AES_decrypt (AES_KEY *aes_key, char *input, char *output);

#endif
