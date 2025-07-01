/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible to simd
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

DECLSPEC u64 siphash_rot32_S (const u64 a)
{
  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = in.v32.b;
  out.v32.b = in.v32.a;

  return out.v64;
}

DECLSPEC u64x siphash_rot32 (const u64x a)
{
  u64x r;

  #if VECT_SIZE == 1
  r = siphash_rot32_S (a);
  #endif

  #if VECT_SIZE >= 2
  r.s0 = siphash_rot32_S (a.s0);
  r.s1 = siphash_rot32_S (a.s1);
  #endif

  #if VECT_SIZE >= 4
  r.s2 = siphash_rot32_S (a.s2);
  r.s3 = siphash_rot32_S (a.s3);
  #endif

  #if VECT_SIZE >= 8
  r.s4 = siphash_rot32_S (a.s4);
  r.s5 = siphash_rot32_S (a.s5);
  r.s6 = siphash_rot32_S (a.s6);
  r.s7 = siphash_rot32_S (a.s7);
  #endif

  #if VECT_SIZE >= 16
  r.s8 = siphash_rot32_S (a.s8);
  r.s9 = siphash_rot32_S (a.s9);
  r.sa = siphash_rot32_S (a.sa);
  r.sb = siphash_rot32_S (a.sb);
  r.sc = siphash_rot32_S (a.sc);
  r.sd = siphash_rot32_S (a.sd);
  r.se = siphash_rot32_S (a.se);
  r.sf = siphash_rot32_S (a.sf);
  #endif

  return r;
}

#define SIPROUND(v0,v1,v2,v3)   \
  (v0) += (v1);                 \
  (v1)  = hc_rotl64 ((v1), 13); \
  (v1) ^= (v0);                 \
  (v0)  = siphash_rot32 ((v0)); \
  (v2) += (v3);                 \
  (v3)  = hc_rotl64 ((v3), 16); \
  (v3) ^= (v2);                 \
  (v0) += (v3);                 \
  (v3)  = hc_rotl64 ((v3), 21); \
  (v3) ^= (v0);                 \
  (v2) += (v1);                 \
  (v1)  = hc_rotl64 ((v1), 17); \
  (v1) ^= (v2);                 \
  (v2)  = siphash_rot32 ((v2))

KERNEL_FQ KERNEL_FA void m10100_m04 (KERN_ATTR_RULES ())
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

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u64x v0p = SIPHASHM_0;
  u64x v1p = SIPHASHM_1;
  u64x v2p = SIPHASHM_2;
  u64x v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);

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

    /**
     * siphash
     */

    switch (out_len / 8)
    {
      case 0: w0[1] |= out_len << 24; break;
      case 1: w0[3] |= out_len << 24; break;
      case 2: w1[1] |= out_len << 24; break;
      case 3: w1[3] |= out_len << 24; break;
    }

    u64x v0 = v0p;
    u64x v1 = v1p;
    u64x v2 = v2p;
    u64x v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= out_len && i < 16; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w0[j + 1], w0[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    for (       j = 0; i <= out_len && i < 32; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w1[j + 1], w1[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64x v = v0 ^ v1 ^ v2 ^ v3;

    const u32x a = l32_from_64 (v);
    const u32x b = h32_from_64 (v);

    const u32x z = 0;

    COMPARE_M_SIMD (a, b, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m10100_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m10100_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m10100_s04 (KERN_ATTR_RULES ())
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

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u64x v0p = SIPHASHM_0;
  u64x v1p = SIPHASHM_1;
  u64x v2p = SIPHASHM_2;
  u64x v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
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

    /**
     * siphash
     */

    switch (out_len / 8)
    {
      case 0: w0[1] |= out_len << 24; break;
      case 1: w0[3] |= out_len << 24; break;
      case 2: w1[1] |= out_len << 24; break;
      case 3: w1[3] |= out_len << 24; break;
    }

    u64x v0 = v0p;
    u64x v1 = v1p;
    u64x v2 = v2p;
    u64x v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= out_len && i < 16; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w0[j + 1], w0[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    for (       j = 0; i <= out_len && i < 32; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w1[j + 1], w1[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64x v = v0 ^ v1 ^ v2 ^ v3;

    const u32x a = l32_from_64 (v);
    const u32x b = h32_from_64 (v);

    const u32x z = 0;

    COMPARE_S_SIMD (a, b, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m10100_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m10100_s16 (KERN_ATTR_RULES ())
{
}
