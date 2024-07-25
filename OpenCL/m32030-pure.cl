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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct netiq_sspr_sha256_tmp
{
  u32 dgst[8];

} netiq_sspr_sha256_tmp_t;

KERNEL_FQ void m32030_init (KERN_ATTR_TMPS (netiq_sspr_sha256_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
  tmps[gid].dgst[5] = ctx.h[5];
  tmps[gid].dgst[6] = ctx.h[6];
  tmps[gid].dgst[7] = ctx.h[7];
}

KERNEL_FQ void m32030_loop (KERN_ATTR_TMPS (netiq_sspr_sha256_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x h[8];

      h[0] = SHA256M_A;
      h[1] = SHA256M_B;
      h[2] = SHA256M_C;
      h[3] = SHA256M_D;
      h[4] = SHA256M_E;
      h[5] = SHA256M_F;
      h[6] = SHA256M_G;
      h[7] = SHA256M_H;

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 32 * 8;

      sha256_transform_vector (w0, w1, w2, w3, h);

      dgst[0] = h[0];
      dgst[1] = h[1];
      dgst[2] = h[2];
      dgst[3] = h[3];
      dgst[4] = h[4];
      dgst[5] = h[5];
      dgst[6] = h[6];
      dgst[7] = h[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);
  }
}

KERNEL_FQ void m32030_comp (KERN_ATTR_TMPS (netiq_sspr_sha256_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].dgst[DGST_R0];
  const u32 r1 = tmps[gid].dgst[DGST_R1];
  const u32 r2 = tmps[gid].dgst[DGST_R2];
  const u32 r3 = tmps[gid].dgst[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
