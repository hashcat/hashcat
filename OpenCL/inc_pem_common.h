/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PEM_COMMON_H
#define _INC_PEM_COMMON_H

#define HC_PEM_SALT_LENGTH 8
#define HC_PEM_MD_LENGTH   16

#define HC_PEM_MAX_BLOCK_SIZE  16
#define HC_PEM_MAX_KEY_LENGTH  32
#define HC_PEM_MAX_DATA_LENGTH 12288

typedef struct pem
{
  void *chosen_cipher;
  u32 salt_iv[HC_PEM_MAX_BLOCK_SIZE / 4];

  u32 data[HC_PEM_MAX_DATA_LENGTH / 4];
  size_t data_len;
} pem_t;

#ifdef REAL_SHM
#define PSEUDO_SHM_TYPE LOCAL_AS
#else
#define PSEUDO_SHM_TYPE
#endif

DECLSPEC void generate_key (u32 *salt_buf, u32 *pw, size_t pw_len, u32 *key);
DECLSPEC void generate_key_vector (u32 *salt_buf, u32x *pw, size_t pw_len, u32x *key);
DECLSPEC void prep_buffers (u32 *salt_buf, u32 *salt_iv, u32 *first_block, PSEUDO_SHM_TYPE u32 *data, GLOBAL_AS const pem_t *esalt);

#endif // _INC_PEM_COMMON_H
