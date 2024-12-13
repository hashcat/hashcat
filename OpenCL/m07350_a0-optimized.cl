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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define DIGEST_SIZE_BYTES 16
#define BLOCK_SIZE_BYTES 64

DECLSPEC void hmac_md5_pad (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad)
{
  w0[0] ^= 0x36363636;
  w0[1] ^= 0x36363636;
  w0[2] ^= 0x36363636;
  w0[3] ^= 0x36363636;
  w1[0] ^= 0x36363636;
  w1[1] ^= 0x36363636;
  w1[2] ^= 0x36363636;
  w1[3] ^= 0x36363636;

  w2[0] = 0x36363636;
  w2[1] = 0x36363636;
  w2[2] = 0x36363636;
  w2[3] = 0x36363636;
  w3[0] = 0x36363636;
  w3[1] = 0x36363636;
  w3[2] = 0x36363636;
  w3[3] = 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, ipad);

  // 0x36 ^ 0x5c = 0x6a

  w0[0] ^= 0x6a6a6a6a;
  w0[1] ^= 0x6a6a6a6a;
  w0[2] ^= 0x6a6a6a6a;
  w0[3] ^= 0x6a6a6a6a;
  w1[0] ^= 0x6a6a6a6a;
  w1[1] ^= 0x6a6a6a6a;
  w1[2] ^= 0x6a6a6a6a;
  w1[3] ^= 0x6a6a6a6a;

  w2[0] = 0x5c5c5c5c;
  w2[1] = 0x5c5c5c5c;
  w2[2] = 0x5c5c5c5c;
  w2[3] = 0x5c5c5c5c;
  w3[0] = 0x5c5c5c5c;
  w3[1] = 0x5c5c5c5c;
  w3[2] = 0x5c5c5c5c;
  w3[3] = 0x5c5c5c5c;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, opad);
}

KERNEL_FQ void m07350_m04 (KERN_ATTR_RULES ())
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
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];
  u32 salt_buf4[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf2[3] = salt_bufs[SALT_POS_HOST].salt_buf[11];
  salt_buf3[0] = salt_bufs[SALT_POS_HOST].salt_buf[12];
  salt_buf3[1] = salt_bufs[SALT_POS_HOST].salt_buf[13];
  salt_buf3[2] = salt_bufs[SALT_POS_HOST].salt_buf[14];
  salt_buf3[3] = salt_bufs[SALT_POS_HOST].salt_buf[15];

  salt_buf4[0] = salt_bufs[SALT_POS_HOST].salt_buf[16];
  salt_buf4[1] = salt_bufs[SALT_POS_HOST].salt_buf[17];
  salt_buf4[2] = salt_bufs[SALT_POS_HOST].salt_buf[18];
  salt_buf4[3] = salt_bufs[SALT_POS_HOST].salt_buf[19];

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = salt_buf2[0];
    w2[1] = salt_buf2[1];
    w2[2] = salt_buf2[2];
    w2[3] = salt_buf2[3];
    w3[0] = salt_buf3[0];
    w3[1] = salt_buf3[1];
    w3[2] = salt_buf3[2];
    w3[3] = salt_buf3[3];

    md5_transform_vector(w0, w1, w2, w3, ipad);

    w0[0] = salt_buf4[0];
    w0[1] = salt_buf4[1];
    w0[2] = salt_buf4[2];
    w0[3] = salt_buf4[3];
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = (64 + salt_len) * 8;
    w3[3] = 0;

    md5_transform_vector(w0, w1, w2, w3, ipad);

    w0[0] = ipad[0];
    w0[1] = ipad[1];
    w0[2] = ipad[2];
    w0[3] = ipad[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = (64 + 16) * 8;
    w3[3] = 0;

    md5_transform_vector (w0, w1, w2, w3, opad);

    COMPARE_M_SIMD (opad[0], opad[3], opad[2], opad[1]);
  }
}

KERNEL_FQ void m07350_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07350_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07350_s04 (KERN_ATTR_RULES ())
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
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];
  u32 salt_buf4[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf2[3] = salt_bufs[SALT_POS_HOST].salt_buf[11];
  salt_buf3[0] = salt_bufs[SALT_POS_HOST].salt_buf[12];
  salt_buf3[1] = salt_bufs[SALT_POS_HOST].salt_buf[13];
  salt_buf3[2] = salt_bufs[SALT_POS_HOST].salt_buf[14];
  salt_buf3[3] = salt_bufs[SALT_POS_HOST].salt_buf[15];

  salt_buf4[0] = salt_bufs[SALT_POS_HOST].salt_buf[16];
  salt_buf4[1] = salt_bufs[SALT_POS_HOST].salt_buf[17];
  salt_buf4[2] = salt_bufs[SALT_POS_HOST].salt_buf[18];
  salt_buf4[3] = salt_bufs[SALT_POS_HOST].salt_buf[19];

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

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

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = salt_buf2[0];
    w2[1] = salt_buf2[1];
    w2[2] = salt_buf2[2];
    w2[3] = salt_buf2[3];
    w3[0] = salt_buf3[0];
    w3[1] = salt_buf3[1];
    w3[2] = salt_buf3[2];
    w3[3] = salt_buf3[3];

    md5_transform_vector(w0, w1, w2, w3, ipad);

    w0[0] = salt_buf4[0];
    w0[1] = salt_buf4[1];
    w0[2] = salt_buf4[2];
    w0[3] = salt_buf4[3];
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = (BLOCK_SIZE_BYTES + salt_len) * 8;
    w3[3] = 0;

    md5_transform_vector(w0, w1, w2, w3, ipad);

    w0[0] = ipad[0];
    w0[1] = ipad[1];
    w0[2] = ipad[2];
    w0[3] = ipad[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = (BLOCK_SIZE_BYTES + DIGEST_SIZE_BYTES) * 8;
    w3[3] = 0;

    md5_transform_vector (w0, w1, w2, w3, opad);

    COMPARE_S_SIMD (opad[0], opad[3], opad[2], opad[1]);
  }
}

KERNEL_FQ void m07350_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07350_s16 (KERN_ATTR_RULES ())
{
}
