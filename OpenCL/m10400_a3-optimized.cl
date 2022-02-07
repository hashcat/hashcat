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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

DECLSPEC void m10400m (LOCAL_AS u32 *S, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (pdf_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * constant
   */

  const u32 padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[0];
  o_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[1];
  o_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[2];
  o_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[3];
  o_buf[4] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[4];
  o_buf[5] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[5];
  o_buf[6] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[6];
  o_buf[7] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[7];

  u32 P = esalt_bufs[DIGESTS_OFFSET_HOST].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[0];
  id_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[1];
  id_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[2];
  id_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[3];

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = padding[0];
  p0[1] = padding[1];
  p0[2] = padding[2];
  p0[3] = padding[3];
  p1[0] = padding[4];
  p1[1] = padding[5];
  p1[2] = padding[6];
  p1[3] = padding[7];
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  switch_buffer_by_offset_le (p0, p1, p2, p3, pw_len);

  w0[0] |= p0[0];
  w0[1] |= p0[1];
  w0[2] |= p0[2];
  w0[3] |= p0[3];
  w1[0] |= p1[0];
  w1[1] |= p1[1];
  w1[2] |= p1[2];
  w1[3] |= p1[3];
  w2[0] |= p2[0];
  w2[1] |= p2[1];
  w2[2] |= p2[2];
  w2[3] |= p2[3];
  w3[0] |= p3[0];
  w3[1] |= p3[1];
  w3[2] |= p3[2];
  w3[3] |= p3[3];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    w0[0] = w0l | w0r;

    /**
     * pdf
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] = w0[0];
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = o_buf[0];
    w2_t[1] = o_buf[1];
    w2_t[2] = o_buf[2];
    w2_t[3] = o_buf[3];
    w3_t[0] = o_buf[4];
    w3_t[1] = o_buf[5];
    w3_t[2] = o_buf[6];
    w3_t[3] = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    digest[1] = digest[1] & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    rc4_init_40 (S, digest, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, padding, out, lid);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

DECLSPEC void m10400s (LOCAL_AS u32 *S, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (pdf_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * constant
   */

  const u32 padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[0];
  o_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[1];
  o_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[2];
  o_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[3];
  o_buf[4] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[4];
  o_buf[5] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[5];
  o_buf[6] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[6];
  o_buf[7] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[7];

  u32 P = esalt_bufs[DIGESTS_OFFSET_HOST].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[0];
  id_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[1];
  id_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[2];
  id_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[3];

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = padding[0];
  p0[1] = padding[1];
  p0[2] = padding[2];
  p0[3] = padding[3];
  p1[0] = padding[4];
  p1[1] = padding[5];
  p1[2] = padding[6];
  p1[3] = padding[7];
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  switch_buffer_by_offset_le (p0, p1, p2, p3, pw_len);

  w0[0] |= p0[0];
  w0[1] |= p0[1];
  w0[2] |= p0[2];
  w0[3] |= p0[3];
  w1[0] |= p1[0];
  w1[1] |= p1[1];
  w1[2] |= p1[2];
  w1[3] |= p1[3];
  w2[0] |= p2[0];
  w2[1] |= p2[1];
  w2[2] |= p2[2];
  w2[3] |= p2[3];
  w3[0] |= p3[0];
  w3[1] |= p3[1];
  w3[2] |= p3[2];
  w3[3] |= p3[3];

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    w0[0] = w0l | w0r;

    /**
     * pdf
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] = w0[0];
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = o_buf[0];
    w2_t[1] = o_buf[1];
    w2_t[2] = o_buf[2];
    w2_t[3] = o_buf[3];
    w3_t[0] = o_buf[4];
    w3_t[1] = o_buf[5];
    w3_t[2] = o_buf[6];
    w3_t[3] = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    digest[1] = digest[1] & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    rc4_init_40 (S, digest, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, padding, out, lid);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400m (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m08 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400m (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m16 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400m (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_s04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400s (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_s08 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400s (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m10400_s16 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m10400s (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
