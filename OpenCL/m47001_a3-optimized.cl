/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

DECLSPEC void m47001m (SHM_TYPE u32a *s_te0, SHM_TYPE u32a *s_te1, SHM_TYPE u32a *s_te2, SHM_TYPE u32a *s_te3, SHM_TYPE u32a *s_te4, PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * Salt prep
   */

  u32 rnd[4];

  rnd[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  rnd[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  rnd[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  rnd[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  // S-ENC is the SCBK encrypting 0x01 0x82 and the first 6 bytes of RND.A

  u32 senc_pt[4];

  senc_pt[0] = 0x8201 | (rnd[0] << 16);
  senc_pt[1] = (rnd[0] >> 16) | (rnd[1] << 16);
  senc_pt[2] = 0;
  senc_pt[3] = 0;

  // the SCBK is the MK encrypting cUID . ~cUID

  u32 scbk_pt[4];

  scbk_pt[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  scbk_pt[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  scbk_pt[2] = ~scbk_pt[0];
  scbk_pt[3] = ~scbk_pt[1];

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32 ukey[4];

    ukey[0] = w0;
    ukey[1] = w[1];
    ukey[2] = w[2];
    ukey[3] = w[3];

    #define KEYLEN 44

    u32 ks[KEYLEN];

    aes128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    u32 scbk[4];

    aes128_encrypt (ks, scbk_pt, scbk, s_te0, s_te1, s_te2, s_te3, s_te4);

    aes128_set_encrypt_key (ks, scbk, s_te0, s_te1, s_te2, s_te3);

    u32 senc[4];

    aes128_encrypt (ks, senc_pt, senc, s_te0, s_te1, s_te2, s_te3, s_te4);

    aes128_set_encrypt_key (ks, senc, s_te0, s_te1, s_te2, s_te3);

    u32 ct[4];

    aes128_encrypt (ks, rnd, ct, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = ct[0];
    const u32 r1 = ct[1];
    const u32 r2 = ct[2];
    const u32 r3 = ct[3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

DECLSPEC void m47001s (SHM_TYPE u32a *s_te0, SHM_TYPE u32a *s_te1, SHM_TYPE u32a *s_te2, SHM_TYPE u32a *s_te3, SHM_TYPE u32a *s_te4, PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * Salt prep
   */

  u32 rnd[4];

  rnd[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  rnd[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  rnd[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  rnd[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  // S-ENC is the SCBK encrypting 0x01 0x82 and the first 6 bytes of RND.A

  u32 senc_pt[4];

  senc_pt[0] = 0x8201 | (rnd[0] << 16);
  senc_pt[1] = (rnd[0] >> 16) | (rnd[1] << 16);
  senc_pt[2] = 0;
  senc_pt[3] = 0;

  // the SCBK is the MK encrypting cUID . ~cUID

  u32 scbk_pt[4];

  scbk_pt[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  scbk_pt[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  scbk_pt[2] = ~scbk_pt[0];
  scbk_pt[3] = ~scbk_pt[1];

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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32 ukey[4];

    ukey[0] = w0;
    ukey[1] = w[1];
    ukey[2] = w[2];
    ukey[3] = w[3];

    #define KEYLEN 44

    u32 ks[KEYLEN];

    aes128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    u32 scbk[4];

    aes128_encrypt (ks, scbk_pt, scbk, s_te0, s_te1, s_te2, s_te3, s_te4);

    aes128_set_encrypt_key (ks, scbk, s_te0, s_te1, s_te2, s_te3);

    u32 senc[4];

    aes128_encrypt (ks, senc_pt, senc, s_te0, s_te1, s_te2, s_te3, s_te4);

    aes128_set_encrypt_key (ks, senc, s_te0, s_te1, s_te2, s_te3);

    u32 ct[4];

    aes128_encrypt (ks, rnd, ct, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = ct[0];
    const u32 r1 = ct[1];
    const u32 r2 = ct[2];
    const u32 r3 = ct[3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m47001_m04 (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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
  w[ 4] = 0;
  w[ 5] = 0;
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m47001m (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m47001_m08 (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m47001m (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m47001_m16 (KERN_ATTR_VECTOR ())
{
}

KERNEL_FQ KERNEL_FA void m47001_s04 (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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
  w[ 4] = 0;
  w[ 5] = 0;
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m47001s (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m47001_s08 (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m47001s (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m47001_s16 (KERN_ATTR_VECTOR ())
{
}
