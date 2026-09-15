/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define BLAKE2B_OUTBYTES 64
#define ARGON2_BLOCK_SIZE  1024
#define ARGON2_PREHASH_SEED_LENGTH 72
#define ARGON2_PREHASH_DIGEST_LENGTH 64

typedef struct argon2id
{
  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;
  
  u32 digest_len;

} argon2id_t;

typedef struct argon2id_tmp
{
  u32 first_block[16][256];
  u32 second_block[16][256];

  u32 final_block[256];

} argon2id_tmp_t;

DECLSPEC void compress(const u32 inlen, const u32 *in, const u32 outlen , u32 *block)
{
  blake2b_ctx_t   ctx;
  blake2b_init   (&ctx);
  blake2b_update (&ctx, in, inlen);
  blake2b_final  (&ctx);

  block [0] = l32_from_64_S (ctx.h[0]);
  block [1] = h32_from_64_S (ctx.h[0]);
  block [2] = l32_from_64_S (ctx.h[1]);
  block [3] = h32_from_64_S (ctx.h[1]);
  block [4] = l32_from_64_S (ctx.h[2]);
  block [5] = h32_from_64_S (ctx.h[2]);
  block [6] = l32_from_64_S (ctx.h[3]);
  block [7] = h32_from_64_S (ctx.h[3]);

  u32 blakeBuffer [32] = {0};

  int iterations =  ((outlen - 64) / 32 );
  for (int iter = 0, off = 8; iter < iterations; iter++, off += 8){
    for (int i = 0, idx = 0; i < 16; i += 2, idx += 1) {
      blakeBuffer [i + 0] = l32_from_64_S (ctx.h[idx]);
      blakeBuffer [i + 1] = h32_from_64_S (ctx.h[idx]);
    }

    blake2b_init   (&ctx);
    blake2b_update (&ctx, blakeBuffer, BLAKE2B_OUTBYTES);
    blake2b_final  (&ctx);

    block [off + 0] = l32_from_64_S (ctx.h[0]);
    block [off + 1] = h32_from_64_S (ctx.h[0]);
    block [off + 2] = l32_from_64_S (ctx.h[1]);
    block [off + 3] = h32_from_64_S (ctx.h[1]);
    block [off + 4] = l32_from_64_S (ctx.h[2]);
    block [off + 5] = h32_from_64_S (ctx.h[2]);
    block [off + 6] = l32_from_64_S (ctx.h[3]);
    block [off + 7] = h32_from_64_S (ctx.h[3]);
  }

  block [240 + 8] = l32_from_64_S (ctx.h[4]);
  block [240 + 9] = h32_from_64_S (ctx.h[4]);
  block [240 +10] = l32_from_64_S (ctx.h[5]);
  block [240 +11] = h32_from_64_S (ctx.h[5]);
  block [240 +12] = l32_from_64_S (ctx.h[6]);
  block [240 +13] = h32_from_64_S (ctx.h[6]);
  block [240 +14] = l32_from_64_S (ctx.h[7]);
  block [240 +15] = h32_from_64_S (ctx.h[7]);
}

KERNEL_FQ void m71000_init (_KERN_ATTR_TMPS_ESALT (argon2id_tmp_t, argon2id_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 fixed_input [32] = {0};
  fixed_input[0] =  esalt_bufs[DIGESTS_OFFSET_HOST].parallelism;
  fixed_input[1] =  32; // output lenght size in bytes
  fixed_input[2] =  esalt_bufs[DIGESTS_OFFSET_HOST].memory_usage_in_kib;
  fixed_input[3] =  esalt_bufs[DIGESTS_OFFSET_HOST].iterations;
  fixed_input[4] =  0x13; // Version 0x10 or 0x13
  fixed_input[5] =  2; // ID

  u32 password_len [32] = {0};
  password_len[0] =  pws[gid].pw_len;

  u32 salt_len [32] = {0};
  salt_len[0] =  salt_bufs[SALT_POS_HOST].salt_len;

  blake2b_ctx_t   ctx;
  blake2b_init   (&ctx);
  blake2b_update (&ctx, fixed_input, 24);

  blake2b_update (&ctx, password_len, 4);
  blake2b_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

  blake2b_update (&ctx, salt_len, 4);
  blake2b_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  u32 secret_ad [32] = {0};
  blake2b_update (&ctx, secret_ad, 4);
  blake2b_update (&ctx, secret_ad, 4);
  blake2b_final  (&ctx);

  u32 blockhash[32] = {0};
  blockhash [0] = ARGON2_BLOCK_SIZE;
  for (int i = 1, idx = 0; i < 17; i += 2, idx += 1)
  {
    blockhash [i + 0] = l32_from_64_S (ctx.h[idx]);
    blockhash [i + 1] = h32_from_64_S (ctx.h[idx]);
  }

  u32 parallelism = esalt_bufs[DIGESTS_OFFSET_HOST].parallelism;
  u32 block [256] = {0};

  for (int l = 0; l < parallelism; l++)
  {
    blockhash[68 / 4] = 0;
    blockhash[72 / 4] = l;

    compress(ARGON2_PREHASH_SEED_LENGTH + 4 , blockhash, ARGON2_BLOCK_SIZE, block);

    for(int idx = 0 ; idx < 256; idx++)
    {
      tmps[gid].first_block[l][idx] = block[idx];
    }

    blockhash[68 / 4] = 1;
    compress(ARGON2_PREHASH_SEED_LENGTH + 4 , blockhash, ARGON2_BLOCK_SIZE, block);

    for(int idx = 0 ; idx < 256; idx++)
    {
      tmps[gid].second_block[l][idx] = block[idx];
    }
  }
}

KERNEL_FQ void m71000_loop (_KERN_ATTR_TMPS_ESALT (argon2id_tmp_t, argon2id_t))
{
  // Empty because the bridge is used for the memory intensive part
}

KERNEL_FQ void m71000_comp ( _KERN_ATTR_TMPS_ESALT (argon2id_tmp_t, argon2id_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 final_block [256] = {0};

  for(int idx = 0 ; idx < 256; idx++)
  {
    final_block[idx] = tmps[gid].final_block[idx];
  }

  u32 output_len [32] = {0};
  output_len [0] = 32;

  blake2b_ctx_t   ctx;
  blake2b_init   (&ctx);
  ctx.h[0] ^= 64 ^ 32; // or using hexadecimal 0x40 ^ 0x20;
  blake2b_update (&ctx, output_len, 4);
  blake2b_update (&ctx, final_block, ARGON2_BLOCK_SIZE);
  blake2b_final  (&ctx);

  const u32 r0 = l32_from_64_S (ctx.h[0]);
  const u32 r1 = h32_from_64_S (ctx.h[0]);
  const u32 r2 = l32_from_64_S (ctx.h[1]);
  const u32 r3 = h32_from_64_S (ctx.h[1]);

  #define il_pos 0

  #include COMPARE_M
}