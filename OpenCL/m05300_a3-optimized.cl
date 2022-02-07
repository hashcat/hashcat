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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len[6];

} ikepsk_t;

DECLSPEC void hmac_md5_pad (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad)
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

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, ipad);

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

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_md5_run (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
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

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);
}

DECLSPEC void m05300m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (ikepsk_t), LOCAL_AS u32 *s_msg_buf, LOCAL_AS u32 *s_nr_buf)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  const u32 nr_len  = esalt_bufs[DIGESTS_OFFSET_HOST].nr_len;
  const u32 msg_len = esalt_bufs[DIGESTS_OFFSET_HOST].msg_len[5];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    w0_t[0] = s_nr_buf[ 0];
    w0_t[1] = s_nr_buf[ 1];
    w0_t[2] = s_nr_buf[ 2];
    w0_t[3] = s_nr_buf[ 3];
    w1_t[0] = s_nr_buf[ 4];
    w1_t[1] = s_nr_buf[ 5];
    w1_t[2] = s_nr_buf[ 6];
    w1_t[3] = s_nr_buf[ 7];
    w2_t[0] = s_nr_buf[ 8];
    w2_t[1] = s_nr_buf[ 9];
    w2_t[2] = s_nr_buf[10];
    w2_t[3] = s_nr_buf[11];
    w3_t[0] = s_nr_buf[12];
    w3_t[1] = s_nr_buf[13];
    w3_t[2] = (64 + nr_len) * 8;
    w3_t[3] = 0;

    u32x digest[4];

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_msg_buf[off +  0];
      w0_t[1] = s_msg_buf[off +  1];
      w0_t[2] = s_msg_buf[off +  2];
      w0_t[3] = s_msg_buf[off +  3];
      w1_t[0] = s_msg_buf[off +  4];
      w1_t[1] = s_msg_buf[off +  5];
      w1_t[2] = s_msg_buf[off +  6];
      w1_t[3] = s_msg_buf[off +  7];
      w2_t[0] = s_msg_buf[off +  8];
      w2_t[1] = s_msg_buf[off +  9];
      w2_t[2] = s_msg_buf[off + 10];
      w2_t[3] = s_msg_buf[off + 11];
      w3_t[0] = s_msg_buf[off + 12];
      w3_t[1] = s_msg_buf[off + 13];
      w3_t[2] = s_msg_buf[off + 14];
      w3_t[3] = s_msg_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_msg_buf[off +  0];
    w0_t[1] = s_msg_buf[off +  1];
    w0_t[2] = s_msg_buf[off +  2];
    w0_t[3] = s_msg_buf[off +  3];
    w1_t[0] = s_msg_buf[off +  4];
    w1_t[1] = s_msg_buf[off +  5];
    w1_t[2] = s_msg_buf[off +  6];
    w1_t[3] = s_msg_buf[off +  7];
    w2_t[0] = s_msg_buf[off +  8];
    w2_t[1] = s_msg_buf[off +  9];
    w2_t[2] = s_msg_buf[off + 10];
    w2_t[3] = s_msg_buf[off + 11];
    w3_t[0] = s_msg_buf[off + 12];
    w3_t[1] = s_msg_buf[off + 13];
    w3_t[2] = (64 + msg_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_M_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

DECLSPEC void m05300s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (ikepsk_t), LOCAL_AS u32 *s_msg_buf, LOCAL_AS u32 *s_nr_buf)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  const u32 nr_len  = esalt_bufs[DIGESTS_OFFSET_HOST].nr_len;
  const u32 msg_len = esalt_bufs[DIGESTS_OFFSET_HOST].msg_len[5];

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

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    w0_t[0] = s_nr_buf[ 0];
    w0_t[1] = s_nr_buf[ 1];
    w0_t[2] = s_nr_buf[ 2];
    w0_t[3] = s_nr_buf[ 3];
    w1_t[0] = s_nr_buf[ 4];
    w1_t[1] = s_nr_buf[ 5];
    w1_t[2] = s_nr_buf[ 6];
    w1_t[3] = s_nr_buf[ 7];
    w2_t[0] = s_nr_buf[ 8];
    w2_t[1] = s_nr_buf[ 9];
    w2_t[2] = s_nr_buf[10];
    w2_t[3] = s_nr_buf[11];
    w3_t[0] = s_nr_buf[12];
    w3_t[1] = s_nr_buf[13];
    w3_t[2] = (64 + nr_len) * 8;
    w3_t[3] = 0;

    u32x digest[4];

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_msg_buf[off +  0];
      w0_t[1] = s_msg_buf[off +  1];
      w0_t[2] = s_msg_buf[off +  2];
      w0_t[3] = s_msg_buf[off +  3];
      w1_t[0] = s_msg_buf[off +  4];
      w1_t[1] = s_msg_buf[off +  5];
      w1_t[2] = s_msg_buf[off +  6];
      w1_t[3] = s_msg_buf[off +  7];
      w2_t[0] = s_msg_buf[off +  8];
      w2_t[1] = s_msg_buf[off +  9];
      w2_t[2] = s_msg_buf[off + 10];
      w2_t[3] = s_msg_buf[off + 11];
      w3_t[0] = s_msg_buf[off + 12];
      w3_t[1] = s_msg_buf[off + 13];
      w3_t[2] = s_msg_buf[off + 14];
      w3_t[3] = s_msg_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_msg_buf[off +  0];
    w0_t[1] = s_msg_buf[off +  1];
    w0_t[2] = s_msg_buf[off +  2];
    w0_t[3] = s_msg_buf[off +  3];
    w1_t[0] = s_msg_buf[off +  4];
    w1_t[1] = s_msg_buf[off +  5];
    w1_t[2] = s_msg_buf[off +  6];
    w1_t[3] = s_msg_buf[off +  7];
    w2_t[0] = s_msg_buf[off +  8];
    w2_t[1] = s_msg_buf[off +  9];
    w2_t[2] = s_msg_buf[off + 10];
    w2_t[3] = s_msg_buf[off + 11];
    w3_t[0] = s_msg_buf[off + 12];
    w3_t[1] = s_msg_buf[off + 13];
    w3_t[2] = (64 + msg_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_S_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

KERNEL_FQ void m05300_m04 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}

KERNEL_FQ void m05300_m08 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}

KERNEL_FQ void m05300_m16 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}

KERNEL_FQ void m05300_s04 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}

KERNEL_FQ void m05300_s08 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}

KERNEL_FQ void m05300_s16 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf[i];
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m05300s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_msg_buf, s_nr_buf);
}
