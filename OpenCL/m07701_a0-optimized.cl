/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define GETCHAR(a,p)   ((PRIVATE_AS u8 *)(a))[(p)]
#define PUTCHAR(a,p,c) ((PRIVATE_AS u8 *)(a))[(p)] = (u8) (c)

#define SETSHIFTEDINT(a,n,v)                  \
{                                             \
  const u32 s = ((n) & 3) * 8;                \
  const u64 x = (u64) (v) << s;               \
  (a)[((n)/4)+0] &= ~(0xff << ((n & 3) * 8)); \
  (a)[((n)/4)+0] |= x;                        \
  (a)[((n)/4)+1]  = x >> 32;                  \
}

CONSTANT_VK u32a sapb_trans_tbl[256] =
{
  // first value hack for 0 byte as part of an optimization
  0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x3f, 0x40, 0x41, 0x50, 0x43, 0x44, 0x45, 0x4b, 0x47, 0x48, 0x4d, 0x4e, 0x54, 0x51, 0x53, 0x46,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x56, 0x55, 0x5c, 0x49, 0x5d, 0x4a,
  0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x58, 0x5b, 0x59, 0xff, 0x52,
  0x4c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x57, 0x5e, 0x5a, 0x4f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

CONSTANT_VK u32a bcodeArray[48] =
{
  0x14, 0x77, 0xf3, 0xd4, 0xbb, 0x71, 0x23, 0xd0, 0x03, 0xff, 0x47, 0x93, 0x55, 0xaa, 0x66, 0x91,
  0xf2, 0x88, 0x6b, 0x99, 0xbf, 0xcb, 0x32, 0x1a, 0x19, 0xd9, 0xa7, 0x82, 0x22, 0x49, 0xa2, 0x51,
  0xe2, 0xb7, 0x33, 0x71, 0x8b, 0x9f, 0x5d, 0x01, 0x44, 0x70, 0xae, 0x11, 0xef, 0x28, 0xf0, 0x0d
};

DECLSPEC u32 sapb_trans (const u32 in)
{
  u32 out = 0;

  out |= (sapb_trans_tbl[(in >>  0) & 0xff]) <<  0;
  out |= (sapb_trans_tbl[(in >>  8) & 0xff]) <<  8;
  out |= (sapb_trans_tbl[(in >> 16) & 0xff]) << 16;
  out |= (sapb_trans_tbl[(in >> 24) & 0xff]) << 24;

  return out;
}

DECLSPEC u32 walld0rf_magic (PRIVATE_AS const u32 *w0, const u32 pw_len, PRIVATE_AS const u32 *salt_buf0, const u32 salt_len, const u32 a, const u32 b, const u32 c, const u32 d, PRIVATE_AS u32 *t)
{
  t[ 0] = 0;
  t[ 1] = 0;
  t[ 2] = 0;
  t[ 3] = 0;
  t[ 4] = 0;
  t[ 5] = 0;
  t[ 6] = 0;
  t[ 7] = 0;
  t[ 8] = 0;
  t[ 9] = 0;
  t[10] = 0;
  t[11] = 0;
  t[12] = 0;
  t[13] = 0;
  t[14] = 0;
  t[15] = 0;

  u32 sum20 = ((a >> 24) & 3)
            + ((a >> 16) & 3)
            + ((a >>  8) & 3)
            + ((a >>  0) & 3)
            + ((b >>  8) & 3);

  sum20 |= 0x20;

  const u32 w[2] = { w0[0], w0[1] };

  const u32 s[3] = { salt_buf0[0], salt_buf0[1], salt_buf0[2] };

  u32 saved_key[4] = { a, b, c, d };

  u32 i1 = 0;
  u32 i2 = 0;
  u32 i3 = 0;

  while (i2 < sum20)
  {
    if (i1 < pw_len)
    {
      if (GETCHAR (saved_key, 15 - i1) & 1)
      {
        PUTCHAR (t, i2, bcodeArray[48 - 1 - i1]);

        i2++;

        if (i2 == sum20) break;
      }

      PUTCHAR (t, i2, GETCHAR (w, i1));

      i2++;

      if (i2 == sum20) break;

      i1++;
    }

    if (i3 < salt_len)
    {
      PUTCHAR (t, i2, GETCHAR (s, i3));

      i2++;

      if (i2 == sum20) break;

      i3++;
    }

    PUTCHAR (t, i2, bcodeArray[i2 - i1 - i3]);

    i2++;
    i2++;
  }

  return sum20;
}

KERNEL_FQ KERNEL_FA void m07701_m04 (KERN_ATTR_RULES ())
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

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf0[3] = 0;

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  salt_buf0[0] = sapb_trans (salt_buf0[0]);
  salt_buf0[1] = sapb_trans (salt_buf0[1]);
  salt_buf0[2] = sapb_trans (salt_buf0[2]);

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

    if (out_len > 8) continue; // otherwise it overflows in waldorf function

    /**
     * SAP
     */

    w0[0] = sapb_trans (w0[0]);
    w0[1] = sapb_trans (w0[1]);

    /**
     * append salt
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf0[0];
    s0[1] = salt_buf0[1];
    s0[2] = salt_buf0[2];
    s0[3] = 0;
    s1[0] = 0;
    s1[1] = 0;
    s1[2] = 0;
    s1[3] = 0;
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_le (s0, s1, s2, s3, out_len);

    const u32 pw_salt_len = out_len + salt_len;

    u32 t[16];

    t[ 0] = s0[0] | w0[0];
    t[ 1] = s0[1] | w0[1];
    t[ 2] = s0[2];
    t[ 3] = s0[3];
    t[ 4] = s1[0];
    t[ 5] = 0;
    t[ 6] = 0;
    t[ 7] = 0;
    t[ 8] = 0;
    t[ 9] = 0;
    t[10] = 0;
    t[11] = 0;
    t[12] = 0;
    t[13] = 0;
    t[14] = pw_salt_len * 8;
    t[15] = 0;

    append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, pw_salt_len);

    /**
     * md5
     */

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

    const u32 sum20 = walld0rf_magic (w0, pw_len, salt_buf0, salt_len, digest[0], digest[1], digest[2], digest[3], t);

    append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, sum20);

    t[14] = sum20 * 8;
    t[15] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

    const u32 r0 = digest[0] ^ digest[2];
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m07701_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m07701_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m07701_s04 (KERN_ATTR_RULES ())
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

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf0[3] = 0;

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  salt_buf0[0] = sapb_trans (salt_buf0[0]);
  salt_buf0[1] = sapb_trans (salt_buf0[1]);
  salt_buf0[2] = sapb_trans (salt_buf0[2]);

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

    if (out_len > 8) continue; // otherwise it overflows in waldorf function

    /**
     * SAP
     */

    w0[0] = sapb_trans (w0[0]);
    w0[1] = sapb_trans (w0[1]);

    /**
     * append salt
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf0[0];
    s0[1] = salt_buf0[1];
    s0[2] = salt_buf0[2];
    s0[3] = 0;
    s1[0] = 0;
    s1[1] = 0;
    s1[2] = 0;
    s1[3] = 0;
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_le (s0, s1, s2, s3, out_len);

    const u32 pw_salt_len = out_len + salt_len;

    u32 t[16];

    t[ 0] = s0[0] | w0[0];
    t[ 1] = s0[1] | w0[1];
    t[ 2] = s0[2];
    t[ 3] = s0[3];
    t[ 4] = s1[0];
    t[ 5] = 0;
    t[ 6] = 0;
    t[ 7] = 0;
    t[ 8] = 0;
    t[ 9] = 0;
    t[10] = 0;
    t[11] = 0;
    t[12] = 0;
    t[13] = 0;
    t[14] = pw_salt_len * 8;
    t[15] = 0;

    append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, pw_salt_len);

    /**
     * md5
     */

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

    const u32 sum20 = walld0rf_magic (w0, pw_len, salt_buf0, salt_len, digest[0], digest[1], digest[2], digest[3], t);

    append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, sum20);

    t[14] = sum20 * 8;
    t[15] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

    const u32 r0 = digest[0] ^ digest[2];
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m07701_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m07701_s16 (KERN_ATTR_RULES ())
{
}
