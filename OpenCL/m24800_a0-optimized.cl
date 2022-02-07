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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

DECLSPEC void hmac_sha1_pad (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform_vector (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_sha1_run (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
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
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m24800_m04 (KERN_ATTR_RULES ())
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

    const u32x out_len2 = out_len * 2;

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);

    make_utf16beN (w1, w2, w3);
    make_utf16beN (w0, w0, w1);

    u32x x0_t[4];
    u32x x1_t[4];
    u32x x2_t[4];
    u32x x3_t[4];

    x0_t[0] = w0[0];
    x0_t[1] = w0[1];
    x0_t[2] = w0[2];
    x0_t[3] = w0[3];
    x1_t[0] = w1[0];
    x1_t[1] = w1[1];
    x1_t[2] = w1[2];
    x1_t[3] = w1[3];
    x2_t[0] = w2[0];
    x2_t[1] = w2[1];
    x2_t[2] = w2[2];
    x2_t[3] = w2[3];
    x3_t[0] = w3[0];
    x3_t[1] = w3[1];
    x3_t[2] = w3[2];
    x3_t[3] = w3[3];

    u32x ipad[5];
    u32x opad[5];

    hmac_sha1_pad (x0_t, x1_t, x2_t, x3_t, ipad, opad);

    x0_t[0] = w0[0];
    x0_t[1] = w0[1];
    x0_t[2] = w0[2];
    x0_t[3] = w0[3];
    x1_t[0] = w1[0];
    x1_t[1] = w1[1];
    x1_t[2] = w1[2];
    x1_t[3] = w1[3];
    x2_t[0] = w2[0];
    x2_t[1] = w2[1];
    x2_t[2] = w2[2];
    x2_t[3] = w2[3];
    x3_t[0] = w3[0];
    x3_t[1] = w3[1];
    x3_t[2] = w3[2];
    x3_t[3] = w3[3];

    append_0x80_4x4_VV (x0_t, x1_t, x2_t, x3_t, out_len2 ^ 3);

    x3_t[2] = 0;
    x3_t[3] = (64 + out_len2) * 8;

    u32x digest[5];

    hmac_sha1_run (x0_t, x1_t, x2_t, x3_t, ipad, opad, digest);

    COMPARE_M_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ void m24800_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m24800_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m24800_s04 (KERN_ATTR_RULES ())
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

    const u32x out_len2 = out_len * 2;

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);

    make_utf16beN (w1, w2, w3);
    make_utf16beN (w0, w0, w1);

    u32x x0_t[4];
    u32x x1_t[4];
    u32x x2_t[4];
    u32x x3_t[4];

    x0_t[0] = w0[0];
    x0_t[1] = w0[1];
    x0_t[2] = w0[2];
    x0_t[3] = w0[3];
    x1_t[0] = w1[0];
    x1_t[1] = w1[1];
    x1_t[2] = w1[2];
    x1_t[3] = w1[3];
    x2_t[0] = w2[0];
    x2_t[1] = w2[1];
    x2_t[2] = w2[2];
    x2_t[3] = w2[3];
    x3_t[0] = w3[0];
    x3_t[1] = w3[1];
    x3_t[2] = w3[2];
    x3_t[3] = w3[3];

    u32x ipad[5];
    u32x opad[5];

    hmac_sha1_pad (x0_t, x1_t, x2_t, x3_t, ipad, opad);

    x0_t[0] = w0[0];
    x0_t[1] = w0[1];
    x0_t[2] = w0[2];
    x0_t[3] = w0[3];
    x1_t[0] = w1[0];
    x1_t[1] = w1[1];
    x1_t[2] = w1[2];
    x1_t[3] = w1[3];
    x2_t[0] = w2[0];
    x2_t[1] = w2[1];
    x2_t[2] = w2[2];
    x2_t[3] = w2[3];
    x3_t[0] = w3[0];
    x3_t[1] = w3[1];
    x3_t[2] = w3[2];
    x3_t[3] = w3[3];

    append_0x80_4x4_VV (x0_t, x1_t, x2_t, x3_t, out_len2 ^ 3);

    x3_t[2] = 0;
    x3_t[3] = (64 + out_len2) * 8;

    u32x digest[5];

    hmac_sha1_run (x0_t, x1_t, x2_t, x3_t, ipad, opad, digest);

    COMPARE_S_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ void m24800_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m24800_s16 (KERN_ATTR_RULES ())
{
}
