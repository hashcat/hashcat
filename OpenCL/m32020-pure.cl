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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct netiq_sspr_sha1_tmp
{
  u32 dgst[5];

} netiq_sspr_sha1_tmp_t;

KERNEL_FQ void m32020_init (KERN_ATTR_TMPS (netiq_sspr_sha1_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha1_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
}

KERNEL_FQ void m32020_loop (KERN_ATTR_TMPS (netiq_sspr_sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  for (u32 i = 0; i < 5; i += 5)
  {
    u32x dgst[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x h[5];

      h[0] = SHA1M_A;
      h[1] = SHA1M_B;
      h[2] = SHA1M_C;
      h[3] = SHA1M_D;
      h[4] = SHA1M_E;

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 20 * 8;

      sha1_transform_vector (w0, w1, w2, w3, h);

      dgst[0] = h[0];
      dgst[1] = h[1];
      dgst[2] = h[2];
      dgst[3] = h[3];
      dgst[4] = h[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
  }
}

KERNEL_FQ void m32020_comp (KERN_ATTR_TMPS (netiq_sspr_sha1_tmp_t))
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
