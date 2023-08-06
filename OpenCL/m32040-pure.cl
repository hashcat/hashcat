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

typedef struct netiq_sspr_sha512_tmp
{
  u64 dgst[8];

} netiq_sspr_sha512_tmp_t;

KERNEL_FQ void m32040_init (KERN_ATTR_TMPS (netiq_sspr_sha512_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
  tmps[gid].dgst[5] = ctx.h[5];
  tmps[gid].dgst[6] = ctx.h[6];
  tmps[gid].dgst[7] = ctx.h[7];
}

KERNEL_FQ void m32040_loop (KERN_ATTR_TMPS (netiq_sspr_sha512_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  for (u32 i = 0; i < 8; i += 8)
  {
    u64x dgst[8];

    dgst[0] = pack64v (tmps, dgst, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u64x h[8];

      h[0] = SHA512M_A;
      h[1] = SHA512M_B;
      h[2] = SHA512M_C;
      h[3] = SHA512M_D;
      h[4] = SHA512M_E;
      h[5] = SHA512M_F;
      h[6] = SHA512M_G;
      h[7] = SHA512M_H;

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];
      u32x w4[4];
      u32x w5[4];
      u32x w6[4];
      u32x w7[4];

      w0[0] = h32_from_64 (dgst[0]);
      w0[1] = l32_from_64 (dgst[0]);
      w0[2] = h32_from_64 (dgst[1]);
      w0[3] = l32_from_64 (dgst[1]);
      w1[0] = h32_from_64 (dgst[2]);
      w1[1] = l32_from_64 (dgst[2]);
      w1[2] = h32_from_64 (dgst[3]);
      w1[3] = l32_from_64 (dgst[3]);
      w2[0] = h32_from_64 (dgst[4]);
      w2[1] = l32_from_64 (dgst[4]);
      w2[2] = h32_from_64 (dgst[5]);
      w2[3] = l32_from_64 (dgst[5]);
      w3[0] = h32_from_64 (dgst[6]);
      w3[1] = l32_from_64 (dgst[6]);
      w3[2] = h32_from_64 (dgst[7]);
      w3[3] = l32_from_64 (dgst[7]);
      w4[0] = 0x80000000;
      w4[1] = 0;
      w4[2] = 0;
      w4[3] = 0;
      w5[0] = 0;
      w5[1] = 0;
      w5[2] = 0;
      w5[3] = 0;
      w6[0] = 0;
      w6[1] = 0;
      w6[2] = 0;
      w6[3] = 0;
      w7[0] = 0;
      w7[1] = 0;
      w7[2] = 0;
      w7[3] = 64 * 8;

      sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, h);

      dgst[0] = h[0];
      dgst[1] = h[1];
      dgst[2] = h[2];
      dgst[3] = h[3];
      dgst[4] = h[4];
      dgst[5] = h[5];
      dgst[6] = h[6];
      dgst[7] = h[7];
    }

    unpack64v (tmps, dgst, gid, i + 0, dgst[0]);
    unpack64v (tmps, dgst, gid, i + 1, dgst[1]);
    unpack64v (tmps, dgst, gid, i + 2, dgst[2]);
    unpack64v (tmps, dgst, gid, i + 3, dgst[3]);
    unpack64v (tmps, dgst, gid, i + 4, dgst[4]);
    unpack64v (tmps, dgst, gid, i + 5, dgst[5]);
    unpack64v (tmps, dgst, gid, i + 6, dgst[6]);
    unpack64v (tmps, dgst, gid, i + 7, dgst[7]);
  }
}

KERNEL_FQ void m32040_comp (KERN_ATTR_TMPS (netiq_sspr_sha512_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  const u64 a = tmps[gid].dgst[7];
  const u64 b = tmps[gid].dgst[3];

  const u32 r0 = l32_from_64_S (a);
  const u32 r1 = h32_from_64_S (a);
  const u32 r2 = l32_from_64_S (b);
  const u32 r3 = h32_from_64_S (b);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
