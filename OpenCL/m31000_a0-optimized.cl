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
#include M2S(INCLUDE_PATH/inc_hash_blake2s.cl)
#endif

KERNEL_FQ void m31000_m04 (KERN_ATTR_RULES ())
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

    u32x m[16];

    m[ 0] = w0[0];
    m[ 1] = w0[1];
    m[ 2] = w0[2];
    m[ 3] = w0[3];
    m[ 4] = w1[0];
    m[ 5] = w1[1];
    m[ 6] = w1[2];
    m[ 7] = w1[3];
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;

    u32x h[8];

    h[0] = BLAKE2S_IV_00 ^ 0x01010020;
    h[1] = BLAKE2S_IV_01;
    h[2] = BLAKE2S_IV_02;
    h[3] = BLAKE2S_IV_03;
    h[4] = BLAKE2S_IV_04;
    h[5] = BLAKE2S_IV_05;
    h[6] = BLAKE2S_IV_06;
    h[7] = BLAKE2S_IV_07;

    blake2s_transform_vector (h, m, out_len, BLAKE2S_FINAL);

    const u32x r0 = h[DGST_R0];
    const u32x r1 = h[DGST_R1];
    const u32x r2 = h[DGST_R2];
    const u32x r3 = h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31000_s04 (KERN_ATTR_RULES ())
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

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x m[16];

    m[ 0] = w0[0];
    m[ 1] = w0[1];
    m[ 2] = w0[2];
    m[ 3] = w0[3];
    m[ 4] = w1[0];
    m[ 5] = w1[1];
    m[ 6] = w1[2];
    m[ 7] = w1[3];
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;

    u32x h[8];

    h[0] = BLAKE2S_IV_00 ^ 0x01010020;
    h[1] = BLAKE2S_IV_01;
    h[2] = BLAKE2S_IV_02;
    h[3] = BLAKE2S_IV_03;
    h[4] = BLAKE2S_IV_04;
    h[5] = BLAKE2S_IV_05;
    h[6] = BLAKE2S_IV_06;
    h[7] = BLAKE2S_IV_07;

    blake2s_transform_vector (h, m, out_len, BLAKE2S_FINAL);

    const u32x r0 = h[DGST_R0];
    const u32x r1 = h[DGST_R1];
    const u32x r2 = h[DGST_R2];
    const u32x r3 = h[DGST_R3];
    
    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31000_s16 (KERN_ATTR_RULES ())
{
}
