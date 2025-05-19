/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SHA512_DIGEST_LENGTH 64

typedef struct shiro1_sha512_tmp
{
  u64 dgst[8];
  u64 out[8];  // Final output hash
} shiro1_sha512_tmp_t;

KERNEL_FQ void m12150_init (KERN_ATTR_TMPS (shiro1_sha512_tmp_t))
{
  const u32 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
  
  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_final (&ctx);

  for (int i = 0; i < 8; i++) {
    tmps[gid].dgst[i] = ctx.h[i];
    tmps[gid].out[i] = ctx.h[i];
  }
}

KERNEL_FQ void m12150_loop(KERN_ATTR_TMPS (shiro1_sha512_tmp_t)) {
  const u32 gid = get_global_id(0);

  if (gid >= GID_CNT) return;

  sha512_ctx_t sha512_ctx;

  // Temporary buffer to hold the digest in u32 format
  u32 digest_u32[16];

  // Convert u64 digest to u32 format manually
  digest_u32[0] = h32_from_64_S(tmps[gid].dgst[0]);
  digest_u32[1] = l32_from_64_S(tmps[gid].dgst[0]);
  digest_u32[2] = h32_from_64_S(tmps[gid].dgst[1]);
  digest_u32[3] = l32_from_64_S(tmps[gid].dgst[1]);
  digest_u32[4] = h32_from_64_S(tmps[gid].dgst[2]);
  digest_u32[5] = l32_from_64_S(tmps[gid].dgst[2]);
  digest_u32[6] = h32_from_64_S(tmps[gid].dgst[3]);
  digest_u32[7] = l32_from_64_S(tmps[gid].dgst[3]);
  digest_u32[8] = h32_from_64_S(tmps[gid].dgst[4]);
  digest_u32[9] = l32_from_64_S(tmps[gid].dgst[4]);
  digest_u32[10] = h32_from_64_S(tmps[gid].dgst[5]);
  digest_u32[11] = l32_from_64_S(tmps[gid].dgst[5]);
  digest_u32[12] = h32_from_64_S(tmps[gid].dgst[6]);
  digest_u32[13] = l32_from_64_S(tmps[gid].dgst[6]);
  digest_u32[14] = h32_from_64_S(tmps[gid].dgst[7]);
  digest_u32[15] = l32_from_64_S(tmps[gid].dgst[7]);

  for (u32 i = 0; i < LOOP_CNT; i++) {
    sha512_init (&sha512_ctx);
    sha512_update (&sha512_ctx, digest_u32, SHA512_DIGEST_LENGTH);
    sha512_final (&sha512_ctx);

    for (int j = 0; j < 8; j++) {      
      tmps[gid].dgst[j] = sha512_ctx.h[j];
    }

    // Update the digest_u32 array for the next iteration
    digest_u32[0] = h32_from_64_S(tmps[gid].dgst[0]);
    digest_u32[1] = l32_from_64_S(tmps[gid].dgst[0]);
    digest_u32[2] = h32_from_64_S(tmps[gid].dgst[1]);
    digest_u32[3] = l32_from_64_S(tmps[gid].dgst[1]);
    digest_u32[4] = h32_from_64_S(tmps[gid].dgst[2]);
    digest_u32[5] = l32_from_64_S(tmps[gid].dgst[2]);
    digest_u32[6] = h32_from_64_S(tmps[gid].dgst[3]);
    digest_u32[7] = l32_from_64_S(tmps[gid].dgst[3]);
    digest_u32[8] = h32_from_64_S(tmps[gid].dgst[4]);
    digest_u32[9] = l32_from_64_S(tmps[gid].dgst[4]);
    digest_u32[10] = h32_from_64_S(tmps[gid].dgst[5]);
    digest_u32[11] = l32_from_64_S(tmps[gid].dgst[5]);
    digest_u32[12] = h32_from_64_S(tmps[gid].dgst[6]);
    digest_u32[13] = l32_from_64_S(tmps[gid].dgst[6]);
    digest_u32[14] = h32_from_64_S(tmps[gid].dgst[7]);
    digest_u32[15] = l32_from_64_S(tmps[gid].dgst[7]);
  }

  // Store the final digest in the tmps buffer
  for (int i = 0; i < 8; i++) {
    tmps[gid].out[i] = sha512_ctx.h[i];
  }
}

KERNEL_FQ void m12150_comp (KERN_ATTR_TMPS (shiro1_sha512_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  const u64 a = tmps[gid].out[0];
  const u64 b = tmps[gid].out[1];

  const u32 r0 = l32_from_64_S (a);
  const u32 r1 = h32_from_64_S (a);
  const u32 r2 = l32_from_64_S (b);
  const u32 r3 = h32_from_64_S (b);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
