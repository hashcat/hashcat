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
#include M2S(INCLUDE_PATH/inc_hash_gost94.cl)
#endif

DECLSPEC void m06900m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), LOCAL_AS u32 (*s_tables)[256])
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0lr;
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    if (pw_len > 0)
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_M_SIMD (state[0], state[1], state[2], state[3]);
  }
}

DECLSPEC void m06900s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), LOCAL_AS u32 (*s_tables)[256])
{
  /**
   * modifiers are taken from args
   */

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

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0lr;
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    if (pw_len > 0)
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_S_SIMD (state[0], state[1], state[2], state[3]);
  }
}

KERNEL_FQ KERNEL_FA void m06900_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  m06900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}

KERNEL_FQ KERNEL_FA void m06900_m08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  m06900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}

KERNEL_FQ KERNEL_FA void m06900_m16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  u32 w2[4]; // no change here, because m06900m() doesn't support > 32, but we need a _m16 kernel because hashcat will call _m16 if pw_len >= 32

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

  m06900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}

KERNEL_FQ KERNEL_FA void m06900_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  m06900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}

KERNEL_FQ KERNEL_FA void m06900_s08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  m06900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}

KERNEL_FQ KERNEL_FA void m06900_s16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * modifier
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

  u32 w2[4]; // no change here, because m06900s() doesn't support > 32, but we need a _s16 kernel because hashcat will call _s16 if pw_len >= 32

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

  m06900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_tables);
}
