/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PKCS1_COMMON_H
#define _INC_PKCS1_COMMON_H

#define HC_PKCS1_SALT_LENGTH 8
#define HC_PKCS1_MD_LENGTH   16

#define HC_PKCS1_MAX_BLOCK_SIZE  16
#define HC_PKCS1_MAX_KEY_LENGTH  32
#define HC_PKCS1_MAX_DATA_LENGTH 12288

typedef struct pkcs1
{
  void *chosen_cipher;
  u32 salt_iv[HC_PKCS1_MAX_BLOCK_SIZE / 4];

  u32 data[HC_PKCS1_MAX_DATA_LENGTH / 4];
  size_t data_len;
} pkcs1_t;

#ifdef REAL_SHM
#define PSEUDO_SHM_TYPE LOCAL_AS
#else
#define PSEUDO_SHM_TYPE
#endif

DECLSPEC void generate_key (u32 *salt_buf, u32 *pw, size_t pw_len, u32 *key);
DECLSPEC void generate_key_vector (u32 *salt_buf, u32x *pw, size_t pw_len, u32x *key);
DECLSPEC void prep_buffers (u32 *salt_buf, u32 *salt_iv, u32 *first_block, PSEUDO_SHM_TYPE u32 *data, GLOBAL_AS const pkcs1_t *esalt);

#endif // _INC_PKCS1_COMMON_H
