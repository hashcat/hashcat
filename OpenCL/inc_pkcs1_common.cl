/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_types.h"
#include "inc_vendor.h"
#include "inc_pkcs1_common.h"

#ifdef KERNEL_STATIC
#include "inc_hash_md5.cl"
#endif

DECLSPEC void generate_key (u32 *salt_buf, u32 *pw, size_t pw_len, u32 *key)
{
  #ifdef DEBUG
  printf("salt_buf:");
  for (u32 i = 0; i < 16; i++) printf(" 0x%08x", salt_buf[i]);
  printf("\n");
  printf("pw:");
  for (u32 i = 0; i < 16; i++) printf(" 0x%08x", pw[i]);
  printf("\n");
  printf("pw_len: %lu\n", pw_len);
  #endif

  u32 md_buf[16] = { 0 };
  md5_ctx_t md_ctx;

  md5_init (&md_ctx);
  md5_update (&md_ctx, pw, pw_len);
  md5_update (&md_ctx, salt_buf, HC_PKCS1_SALT_LENGTH);
  md5_final (&md_ctx);

  key[0] = md_ctx.h[0];

  #if KEY_LENGTH > 4
  key[1] = md_ctx.h[1];
  #endif

  #if KEY_LENGTH > 8
  key[2] = md_ctx.h[2];
  #endif

  #if KEY_LENGTH > 12
  key[3] = md_ctx.h[3];
  #endif

  #if KEY_LENGTH > 16

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < HC_PKCS1_MD_LENGTH / 4; i++)
  {
    md_buf[i] = md_ctx.h[i];
  }

  md5_init (&md_ctx);
  md5_update (&md_ctx, md_buf, HC_PKCS1_MD_LENGTH);
  md5_update (&md_ctx, pw, pw_len);
  md5_update (&md_ctx, salt_buf, HC_PKCS1_SALT_LENGTH);
  md5_final (&md_ctx);

  key[4] = md_ctx.h[0];
  #endif // KEY_LENGTH > 16

  #if KEY_LENGTH > 20
  key[5] = md_ctx.h[1];
  #endif

  #if KEY_LENGTH > 24
  key[6] = md_ctx.h[2];
  #endif

  #if KEY_LENGTH > 28
  key[7] = md_ctx.h[3];
  #endif

  #if KEY_LENGTH > 32
  #error Only supports up to KEY_LENGTH == 32 at present.  Extend generate_key!
  #endif

  #ifdef DEBUG
  printf("key:");
  for (u32 i = 0; i < KEY_LENGTH / 4; i++) printf(" 0x%08x", key[i]);
  printf("\n");
  #endif   // DEBUG
}

DECLSPEC void generate_key_vector (u32 *salt_buf, u32x *pw, size_t pw_len, u32x *key)
{
  #ifdef DEBUG
  printf("salt_buf:");
  for (u32 i = 0; i < 16; i++) printf(" 0x%08x", salt_buf[i]);
  printf("\n");
  for (u32 v = 0; v < VECT_SIZE; v++)
  {
    printf("pw[%u]:", v);
    for (u32 i = 0; i < 16; i++) printf(" 0x%08x", VECTOR_ELEMENT(pw[i], v));
    printf("\n");
  }
  printf("pw_len: %lu\n", pw_len);
  #endif

  u32x md_buf[16] = { 0 };
  md5_ctx_vector_t md_ctx;

  md5_init_vector (&md_ctx);
  md5_update_vector (&md_ctx, pw, pw_len);
  md5_update_vector_from_scalar (&md_ctx, salt_buf, HC_PKCS1_SALT_LENGTH);
  md5_final_vector (&md_ctx);

  key[0] = md_ctx.h[0];

  #if KEY_LENGTH > 4
  key[1] = md_ctx.h[1];
  #endif

  #if KEY_LENGTH > 8
  key[2] = md_ctx.h[2];
  #endif

  #if KEY_LENGTH > 12
  key[3] = md_ctx.h[3];
  #endif

  #if KEY_LENGTH > 16

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < HC_PKCS1_MD_LENGTH / 4; i++)
  {
    md_buf[i] = md_ctx.h[i];
  }

  md5_init_vector (&md_ctx);
  md5_update_vector (&md_ctx, md_buf, HC_PKCS1_MD_LENGTH);
  md5_update_vector (&md_ctx, pw, pw_len);
  md5_update_vector_from_scalar (&md_ctx, salt_buf, HC_PKCS1_SALT_LENGTH);
  md5_final_vector (&md_ctx);

  key[4] = md_ctx.h[0];
  #endif // KEY_LENGTH > 16

  #if KEY_LENGTH > 20
  key[5] = md_ctx.h[1];
  #endif

  #if KEY_LENGTH > 24
  key[6] = md_ctx.h[2];
  #endif

  #if KEY_LENGTH > 28
  key[7] = md_ctx.h[3];
  #endif

  #if KEY_LENGTH > 32
  #error Only supports up to KEY_LENGTH == 32 at present.  Extend generate_key!
  #endif

  #ifdef DEBUG
  for (u32 v = 0; v < VECT_SIZE; v++)
  {
    printf("key[%u]:", v);
    for (u32 i = 0; i < KEY_LENGTH / 4; i++) printf(" 0x%08x", VECTOR_ELEMENT(key[i], v));
    printf("\n");
  }
  #endif   // DEBUG
}

DECLSPEC void prep_buffers(u32 *salt_buf, u32 *salt_iv, u32 *first_block, PSEUDO_SHM_TYPE u32 *data, GLOBAL_AS const pkcs1_t *esalt)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < HC_PKCS1_SALT_LENGTH / 4; i++)
  {
    salt_buf[i] = esalt->salt_iv[i];
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < BLOCK_SIZE / 4; i++)
  {
    salt_iv[i] = esalt->salt_iv[i];
    first_block[i] = data[i];
  }
}
