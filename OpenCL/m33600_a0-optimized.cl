
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
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd320.cl)
#endif

DECLSPEC void ripemd320_transform_transport_vector (PRIVATE_AS const u32x *w, PRIVATE_AS u32x *dgst)
{
  ripemd320_transform_vector (w + 0, w + 4, w + 8, w + 12, dgst);
}

KERNEL_FQ KERNEL_FA void m33600_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = out_len * 8;
    w[15] = 0;

    /**
     * RipeMD320
     */

    u32x dgst[10];

    dgst[0] = RIPEMD320M_A;
    dgst[1] = RIPEMD320M_B;
    dgst[2] = RIPEMD320M_C;
    dgst[3] = RIPEMD320M_D;
    dgst[4] = RIPEMD320M_E;
    dgst[5] = RIPEMD320M_F;
    dgst[6] = RIPEMD320M_G;
    dgst[7] = RIPEMD320M_H;
    dgst[8] = RIPEMD320M_I;
    dgst[9] = RIPEMD320M_L;

    ripemd320_transform_transport_vector (w, dgst);

    COMPARE_M_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33600_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m33600_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m33600_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = out_len * 8;
    w[15] = 0;

    /**
     * RipeMD320
     */

    u32x dgst[10];

    dgst[0] = RIPEMD320M_A;
    dgst[1] = RIPEMD320M_B;
    dgst[2] = RIPEMD320M_C;
    dgst[3] = RIPEMD320M_D;
    dgst[4] = RIPEMD320M_E;
    dgst[5] = RIPEMD320M_F;
    dgst[6] = RIPEMD320M_G;
    dgst[7] = RIPEMD320M_H;
    dgst[8] = RIPEMD320M_I;
    dgst[9] = RIPEMD320M_L;

    ripemd320_transform_transport_vector (w, dgst);

    COMPARE_S_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33600_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m33600_s16 (KERN_ATTR_RULES ())
{
}
