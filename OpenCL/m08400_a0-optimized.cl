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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

KERNEL_FQ KERNEL_FA void m08400_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  salt_buf0[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  salt_buf0[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  salt_buf0[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]);
  salt_buf0[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 3]);
  salt_buf1[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 4]);
  salt_buf1[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 5]);
  salt_buf1[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 6]);
  salt_buf1[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 7]);
  salt_buf2[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 8]);
  salt_buf2[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 9]);
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

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

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * SHA1
     */

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = 0;
    w3[3] = out_len * 8;

    u32x digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    u32x a;
    u32x b;
    u32x c;
    u32x d;
    u32x e;

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

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
    w2[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    w0[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 80 * 8;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

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
    w2[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    w0[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 80 * 8;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    COMPARE_M_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ KERNEL_FA void m08400_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m08400_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m08400_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  salt_buf0[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  salt_buf0[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  salt_buf0[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]);
  salt_buf0[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 3]);
  salt_buf1[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 4]);
  salt_buf1[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 5]);
  salt_buf1[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 6]);
  salt_buf1[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 7]);
  salt_buf2[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 8]);
  salt_buf2[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 9]);
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

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

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * SHA1
     */

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = 0;
    w3[3] = out_len * 8;

    u32x digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    u32x a;
    u32x b;
    u32x c;
    u32x d;
    u32x e;

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

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
    w2[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    w0[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 80 * 8;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

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
    w2[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    w0[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
          | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
          | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 80 * 8;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    COMPARE_S_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ KERNEL_FA void m08400_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m08400_s16 (KERN_ATTR_RULES ())
{
}
