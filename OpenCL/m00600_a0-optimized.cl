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
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#endif

KERNEL_FQ void m00600_m04 (KERN_ATTR_RULES ())
{
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

    u64x m[16];

    m[ 0] = hl32_to_64 (w0[1], w0[0]);
    m[ 1] = hl32_to_64 (w0[3], w0[2]);
    m[ 2] = hl32_to_64 (w1[1], w1[0]);
    m[ 3] = hl32_to_64 (w1[3], w1[2]);
    m[ 4] = hl32_to_64 (w2[1], w2[0]);
    m[ 5] = hl32_to_64 (w2[3], w2[2]);
    m[ 6] = hl32_to_64 (w3[1], w3[0]);
    m[ 7] = hl32_to_64 (w3[3], w3[2]);
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;

    u64x h[8];

    h[0] = BLAKE2B_IV_00 ^ 0x01010040;
    h[1] = BLAKE2B_IV_01;
    h[2] = BLAKE2B_IV_02;
    h[3] = BLAKE2B_IV_03;
    h[4] = BLAKE2B_IV_04;
    h[5] = BLAKE2B_IV_05;
    h[6] = BLAKE2B_IV_06;
    h[7] = BLAKE2B_IV_07;

    blake2b_transform_vector (h, m, out_len, BLAKE2B_FINAL);

    const u32x r0 = h32_from_64 (h[0]);
    const u32x r1 = l32_from_64 (h[0]);
    const u32x r2 = h32_from_64 (h[1]);
    const u32x r3 = l32_from_64 (h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m00600_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00600_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00600_s04 (KERN_ATTR_RULES ())
{
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

    u64x m[16];

    m[ 0] = hl32_to_64 (w0[1], w0[0]);
    m[ 1] = hl32_to_64 (w0[3], w0[2]);
    m[ 2] = hl32_to_64 (w1[1], w1[0]);
    m[ 3] = hl32_to_64 (w1[3], w1[2]);
    m[ 4] = hl32_to_64 (w2[1], w2[0]);
    m[ 5] = hl32_to_64 (w2[3], w2[2]);
    m[ 6] = hl32_to_64 (w3[1], w3[0]);
    m[ 7] = hl32_to_64 (w3[3], w3[2]);
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;

    u64x h[8];

    h[0] = BLAKE2B_IV_00 ^ 0x01010040;
    h[1] = BLAKE2B_IV_01;
    h[2] = BLAKE2B_IV_02;
    h[3] = BLAKE2B_IV_03;
    h[4] = BLAKE2B_IV_04;
    h[5] = BLAKE2B_IV_05;
    h[6] = BLAKE2B_IV_06;
    h[7] = BLAKE2B_IV_07;

    blake2b_transform_vector (h, m, out_len, BLAKE2B_FINAL);

    const u32x r0 = h32_from_64 (h[0]);
    const u32x r1 = l32_from_64 (h[0]);
    const u32x r2 = h32_from_64 (h[1]);
    const u32x r3 = l32_from_64 (h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m00600_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00600_s16 (KERN_ATTR_RULES ())
{
}
