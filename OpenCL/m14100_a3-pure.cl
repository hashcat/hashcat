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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

DECLSPEC void m14100m (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * Precompute fixed key scheduler
   */

  const u32x c = (w[2]);
  const u32x d = (w[3]);

  u32x Kc[16];
  u32x Kd[16];

  _des_crypt_keysetup_vect (c, d, Kc, Kd, s_skb);

  const u32x e = (w[4]);
  const u32x f = (w[5]);

  u32x Ke[16];
  u32x Kf[16];

  _des_crypt_keysetup_vect (e, f, Ke, Kf, s_skb);

  /**
   * loop
   */

  u32 w0l = w[0];

  u32 w1 = w[1];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0 = w0l | w0r;

    /* First Pass */

    const u32x a = (w0);
    const u32x b = (w1);

    u32x Ka[16];
    u32x Kb[16];

    _des_crypt_keysetup_vect (a, b, Ka, Kb, s_skb);

    u32x data[2];

    data[0] = salt_buf0[0];
    data[1] = salt_buf0[1];

    u32x p1[2];

    _des_crypt_encrypt_noipfp_vect (p1, data, Ka, Kb, s_SPtrans);

    /* Second Pass */

    u32x p2[2];

    _des_crypt_decrypt_noipfp_vect (p2, p1, Kc, Kd, s_SPtrans);

    /* Third Pass */

    u32x iv[2];

    _des_crypt_encrypt_noipfp_vect (iv, p2, Ke, Kf, s_SPtrans);

    u32x z = 0;

    COMPARE_M_SIMD (iv[0], iv[1], z, z);
  }
}

DECLSPEC void m14100s (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * Precompute fixed key scheduler
   */

  u32x iv[2];

  iv[0] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0];
  iv[1] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1];

  const u32x e = (w[4]);
  const u32x f = (w[5]);

  u32x Ke[16];
  u32x Kf[16];

  _des_crypt_keysetup_vect (e, f, Ke, Kf, s_skb);

  u32x p2[2];

  _des_crypt_decrypt_noipfp_vect (p2, iv, Ke, Kf, s_SPtrans);

  const u32x c = (w[2]);
  const u32x d = (w[3]);

  u32x Kc[16];
  u32x Kd[16];

  _des_crypt_keysetup_vect (c, d, Kc, Kd, s_skb);

  u32x p1[2];

  _des_crypt_encrypt_noipfp_vect (p1, p2, Kc, Kd, s_SPtrans);

  /**
   * digest
   */

  #if VECT_SIZE == 1
  const u32 search[4] =
  {
    p1[0],
    p1[1],
    0,
    0
  };
  #else
  const u32 search[4] =
  {
    p1[0].s0,
    p1[1].s0,
    0,
    0
  };
  #endif

  /**
   * loop
   */

  u32 w0l = w[0];

  u32 w1 = w[1];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0 = w0l | w0r;

    /* First Pass */

    const u32x a = (w0);
    const u32x b = (w1);

    u32x Ka[16];
    u32x Kb[16];

    _des_crypt_keysetup_vect (a, b, Ka, Kb, s_skb);

    u32x data[2];

    data[0] = salt_buf0[0];
    data[1] = salt_buf0[1];

    u32x p1[2];

    _des_crypt_encrypt_noipfp_vect (p1, data, Ka, Kb, s_SPtrans);

    /* Second Pass was precomputed */

    /* Third Pass was precomputed */

    u32x z = 0;

    COMPARE_S_SIMD (p1[0], p1[1], z, z);
  }
}

KERNEL_FQ KERNEL_FA void m14100_mxx (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m14100m (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m14100_sxx (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m14100s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
