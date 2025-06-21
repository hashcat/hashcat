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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct netiq_sspr_md5_tmp
{
  u32 dgst[4];

} netiq_sspr_md5_tmp_t;

KERNEL_FQ KERNEL_FA void m32000_init (KERN_ATTR_TMPS (netiq_sspr_md5_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

  md5_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
}

KERNEL_FQ KERNEL_FA void m32000_loop (KERN_ATTR_TMPS (netiq_sspr_md5_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  for (u32 i = 0; i < 4; i += 4)
  {
    u32x dgst[4];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x h[4];

      h[0] = MD5M_A;
      h[1] = MD5M_B;
      h[2] = MD5M_C;
      h[3] = MD5M_D;

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = 0x00000080;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 16 * 8;
      w3[3] = 0;

      md5_transform_vector (w0, w1, w2, w3, h);

      dgst[0] = h[0];
      dgst[1] = h[1];
      dgst[2] = h[2];
      dgst[3] = h[3];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
  }
}

KERNEL_FQ KERNEL_FA void m32000_comp (KERN_ATTR_TMPS (netiq_sspr_md5_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].dgst[0];
  const u32 r1 = tmps[gid].dgst[1];
  const u32 r2 = tmps[gid].dgst[2];
  const u32 r3 = tmps[gid].dgst[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
