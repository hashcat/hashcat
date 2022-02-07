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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct mozilla_3des
{
  u32 ct_buf[4];

} mozilla_3des_t;

KERNEL_FQ void m26000_mxx (KERN_ATTR_ESALT (mozilla_3des_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 gs_buf[5];

  gs_buf[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  gs_buf[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  gs_buf[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]);
  gs_buf[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 3]);
  gs_buf[4] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 4]);

  u32 es_buf[5];

  es_buf[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 8]);
  es_buf[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 9]);
  es_buf[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[10]);
  es_buf[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[11]);
  es_buf[4] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[12]);

  u32 ct_buf0[2];

  ct_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[0];
  ct_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[1];

  u32 ct_buf1[2];

  ct_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[2];
  ct_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = combs_buf[il_pos].i[idx];
    }

    switch_buffer_by_offset_1x64_le_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    // my $hp = sha1 ($global_salt_bin . $word);

    sha1_ctx_t ctx0;

    sha1_init (&ctx0);

    ctx0.w0[0] = gs_buf[0];
    ctx0.w0[1] = gs_buf[1];
    ctx0.w0[2] = gs_buf[2];
    ctx0.w0[3] = gs_buf[3];
    ctx0.w1[0] = gs_buf[4];

    ctx0.len = 20;

    sha1_update_swap (&ctx0, c, pw_len + comb_len);

    sha1_final (&ctx0);

    u32 hp[5];

    hp[0] = ctx0.h[0];
    hp[1] = ctx0.h[1];
    hp[2] = ctx0.h[2];
    hp[3] = ctx0.h[3];
    hp[4] = ctx0.h[4];

    // my $chp = sha1 ($hp . $entry_salt_bin);

    sha1_init (&ctx0);

    ctx0.w0[0] = hp[0];
    ctx0.w0[1] = hp[1];
    ctx0.w0[2] = hp[2];
    ctx0.w0[3] = hp[3];
    ctx0.w1[0] = hp[4];
    ctx0.w1[1] = es_buf[0];
    ctx0.w1[2] = es_buf[1];
    ctx0.w1[3] = es_buf[2];
    ctx0.w2[0] = es_buf[3];
    ctx0.w2[1] = es_buf[4];

    ctx0.len = 40;

    sha1_final (&ctx0);

    u32 chp[5];

    chp[0] = ctx0.h[0];
    chp[1] = ctx0.h[1];
    chp[2] = ctx0.h[2];
    chp[3] = ctx0.h[3];
    chp[4] = ctx0.h[4];

    // my $k1 = hmac ($pes . $entry_salt_bin, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = chp[0];
    w0[1] = chp[1];
    w0[2] = chp[2];
    w0[3] = chp[3];
    w1[0] = chp[4];
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
    w3[3] = 0;

    sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

    sha1_hmac_ctx_t ctx1a = ctx1;

    w0[0] = es_buf[0];
    w0[1] = es_buf[1];
    w0[2] = es_buf[2];
    w0[3] = es_buf[3];
    w1[0] = es_buf[4];
    w1[1] = es_buf[0];
    w1[2] = es_buf[1];
    w1[3] = es_buf[2];
    w2[0] = es_buf[3];
    w2[1] = es_buf[4];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1a, w0, w1, w2, w3, 40);

    sha1_hmac_final (&ctx1a);

    u32 k1[5];

    k1[0] = ctx1a.opad.h[0];
    k1[1] = ctx1a.opad.h[1];
    k1[2] = ctx1a.opad.h[2];
    k1[3] = ctx1a.opad.h[3];
    k1[4] = ctx1a.opad.h[4];

    // my $tk = hmac ($pes, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1b = ctx1;

    w0[0] = es_buf[0];
    w0[1] = es_buf[1];
    w0[2] = es_buf[2];
    w0[3] = es_buf[3];
    w1[0] = es_buf[4];
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
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1b, w0, w1, w2, w3, 20);

    sha1_hmac_final (&ctx1b);

    u32 tk[5];

    tk[0] = ctx1b.opad.h[0];
    tk[1] = ctx1b.opad.h[1];
    tk[2] = ctx1b.opad.h[2];
    tk[3] = ctx1b.opad.h[3];
    tk[4] = ctx1b.opad.h[4];

    // my $k2 = hmac ($tk . $entry_salt_bin, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1c = ctx1;

    w0[0] = tk[0];
    w0[1] = tk[1];
    w0[2] = tk[2];
    w0[3] = tk[3];
    w1[0] = tk[4];
    w1[1] = es_buf[0];
    w1[2] = es_buf[1];
    w1[3] = es_buf[2];
    w2[0] = es_buf[3];
    w2[1] = es_buf[4];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1c, w0, w1, w2, w3, 40);

    sha1_hmac_final (&ctx1c);

    u32 k2[5];

    k2[0] = ctx1c.opad.h[0];
    k2[1] = ctx1c.opad.h[1];
    k2[2] = ctx1c.opad.h[2];
    k2[3] = ctx1c.opad.h[3];
    k2[4] = ctx1c.opad.h[4];

    // 3DES

    u32 ukey[6];

    ukey[0] = hc_swap32_S (k1[0]);
    ukey[1] = hc_swap32_S (k1[1]);
    ukey[2] = hc_swap32_S (k1[2]);
    ukey[3] = hc_swap32_S (k1[3]);
    ukey[4] = hc_swap32_S (k1[4]);
    ukey[5] = hc_swap32_S (k2[0]);

    u32 iv[2];

    iv[0] = hc_swap32_S (k2[3]);
    iv[1] = hc_swap32_S (k2[4]);

    u32 K0[16];
    u32 K1[16];
    u32 K2[16];
    u32 K3[16];
    u32 K4[16];
    u32 K5[16];

    _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);
    _des_crypt_keysetup (ukey[2], ukey[3], K2, K3, s_skb);
    _des_crypt_keysetup (ukey[4], ukey[5], K4, K5, s_skb);

    u32 ct[2];
    u32 pt[2];

    u32 t1[2];
    u32 t2[2];

    ct[0] = ct_buf0[0];
    ct[1] = ct_buf0[1];

    _des_crypt_decrypt (t1, ct, K4, K5, s_SPtrans);
    _des_crypt_encrypt (t2, t1, K2, K3, s_SPtrans);
    _des_crypt_decrypt (pt, t2, K0, K1, s_SPtrans);

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];

    // password

    if (pt[0] != 0x73736170) continue;
    if (pt[1] != 0x64726f77) continue;

    iv[0] = ct_buf0[0];
    iv[1] = ct_buf0[1];

    ct[0] = ct_buf1[0];
    ct[1] = ct_buf1[1];

    _des_crypt_decrypt (t1, ct, K4, K5, s_SPtrans);
    _des_crypt_encrypt (t2, t1, K2, K3, s_SPtrans);
    _des_crypt_decrypt (pt, t2, K0, K1, s_SPtrans);

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];

    // -check\x02\x02

    if (pt[0] != 0x6568632d) continue;
    if (pt[1] != 0x02026b63) continue;

    const u32 r0 = ct_buf0[0];
    const u32 r1 = ct_buf0[1];
    const u32 r2 = ct_buf1[0];
    const u32 r3 = ct_buf1[1];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m26000_sxx (KERN_ATTR_ESALT (mozilla_3des_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 gs_buf[5];

  gs_buf[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  gs_buf[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  gs_buf[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]);
  gs_buf[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 3]);
  gs_buf[4] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 4]);

  u32 es_buf[5];

  es_buf[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 8]);
  es_buf[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 9]);
  es_buf[2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[10]);
  es_buf[3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[11]);
  es_buf[4] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[12]);

  u32 ct_buf0[2];

  ct_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[0];
  ct_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[1];

  u32 ct_buf1[2];

  ct_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[2];
  ct_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = combs_buf[il_pos].i[idx];
    }

    switch_buffer_by_offset_1x64_le_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    // my $hp = sha1 ($global_salt_bin . $word);

    sha1_ctx_t ctx0;

    sha1_init (&ctx0);

    ctx0.w0[0] = gs_buf[0];
    ctx0.w0[1] = gs_buf[1];
    ctx0.w0[2] = gs_buf[2];
    ctx0.w0[3] = gs_buf[3];
    ctx0.w1[0] = gs_buf[4];

    ctx0.len = 20;

    sha1_update_swap (&ctx0, c, pw_len + comb_len);

    sha1_final (&ctx0);

    u32 hp[5];

    hp[0] = ctx0.h[0];
    hp[1] = ctx0.h[1];
    hp[2] = ctx0.h[2];
    hp[3] = ctx0.h[3];
    hp[4] = ctx0.h[4];

    // my $chp = sha1 ($hp . $entry_salt_bin);

    sha1_init (&ctx0);

    ctx0.w0[0] = hp[0];
    ctx0.w0[1] = hp[1];
    ctx0.w0[2] = hp[2];
    ctx0.w0[3] = hp[3];
    ctx0.w1[0] = hp[4];
    ctx0.w1[1] = es_buf[0];
    ctx0.w1[2] = es_buf[1];
    ctx0.w1[3] = es_buf[2];
    ctx0.w2[0] = es_buf[3];
    ctx0.w2[1] = es_buf[4];

    ctx0.len = 40;

    sha1_final (&ctx0);

    u32 chp[5];

    chp[0] = ctx0.h[0];
    chp[1] = ctx0.h[1];
    chp[2] = ctx0.h[2];
    chp[3] = ctx0.h[3];
    chp[4] = ctx0.h[4];

    // my $k1 = hmac ($pes . $entry_salt_bin, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = chp[0];
    w0[1] = chp[1];
    w0[2] = chp[2];
    w0[3] = chp[3];
    w1[0] = chp[4];
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
    w3[3] = 0;

    sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

    sha1_hmac_ctx_t ctx1a = ctx1;

    w0[0] = es_buf[0];
    w0[1] = es_buf[1];
    w0[2] = es_buf[2];
    w0[3] = es_buf[3];
    w1[0] = es_buf[4];
    w1[1] = es_buf[0];
    w1[2] = es_buf[1];
    w1[3] = es_buf[2];
    w2[0] = es_buf[3];
    w2[1] = es_buf[4];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1a, w0, w1, w2, w3, 40);

    sha1_hmac_final (&ctx1a);

    u32 k1[5];

    k1[0] = ctx1a.opad.h[0];
    k1[1] = ctx1a.opad.h[1];
    k1[2] = ctx1a.opad.h[2];
    k1[3] = ctx1a.opad.h[3];
    k1[4] = ctx1a.opad.h[4];

    // my $tk = hmac ($pes, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1b = ctx1;

    w0[0] = es_buf[0];
    w0[1] = es_buf[1];
    w0[2] = es_buf[2];
    w0[3] = es_buf[3];
    w1[0] = es_buf[4];
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
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1b, w0, w1, w2, w3, 20);

    sha1_hmac_final (&ctx1b);

    u32 tk[5];

    tk[0] = ctx1b.opad.h[0];
    tk[1] = ctx1b.opad.h[1];
    tk[2] = ctx1b.opad.h[2];
    tk[3] = ctx1b.opad.h[3];
    tk[4] = ctx1b.opad.h[4];

    // my $k2 = hmac ($tk . $entry_salt_bin, $chp, \&sha1, 64);

    sha1_hmac_ctx_t ctx1c = ctx1;

    w0[0] = tk[0];
    w0[1] = tk[1];
    w0[2] = tk[2];
    w0[3] = tk[3];
    w1[0] = tk[4];
    w1[1] = es_buf[0];
    w1[2] = es_buf[1];
    w1[3] = es_buf[2];
    w2[0] = es_buf[3];
    w2[1] = es_buf[4];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx1c, w0, w1, w2, w3, 40);

    sha1_hmac_final (&ctx1c);

    u32 k2[5];

    k2[0] = ctx1c.opad.h[0];
    k2[1] = ctx1c.opad.h[1];
    k2[2] = ctx1c.opad.h[2];
    k2[3] = ctx1c.opad.h[3];
    k2[4] = ctx1c.opad.h[4];

    // 3DES

    u32 ukey[6];

    ukey[0] = hc_swap32_S (k1[0]);
    ukey[1] = hc_swap32_S (k1[1]);
    ukey[2] = hc_swap32_S (k1[2]);
    ukey[3] = hc_swap32_S (k1[3]);
    ukey[4] = hc_swap32_S (k1[4]);
    ukey[5] = hc_swap32_S (k2[0]);

    u32 iv[2];

    iv[0] = hc_swap32_S (k2[3]);
    iv[1] = hc_swap32_S (k2[4]);

    u32 K0[16];
    u32 K1[16];
    u32 K2[16];
    u32 K3[16];
    u32 K4[16];
    u32 K5[16];

    _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);
    _des_crypt_keysetup (ukey[2], ukey[3], K2, K3, s_skb);
    _des_crypt_keysetup (ukey[4], ukey[5], K4, K5, s_skb);

    u32 ct[2];
    u32 pt[2];

    u32 t1[2];
    u32 t2[2];

    ct[0] = ct_buf0[0];
    ct[1] = ct_buf0[1];

    _des_crypt_decrypt (t1, ct, K4, K5, s_SPtrans);
    _des_crypt_encrypt (t2, t1, K2, K3, s_SPtrans);
    _des_crypt_decrypt (pt, t2, K0, K1, s_SPtrans);

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];

    // password

    if (pt[0] != 0x73736170) continue;
    if (pt[1] != 0x64726f77) continue;

    iv[0] = ct_buf0[0];
    iv[1] = ct_buf0[1];

    ct[0] = ct_buf1[0];
    ct[1] = ct_buf1[1];

    _des_crypt_decrypt (t1, ct, K4, K5, s_SPtrans);
    _des_crypt_encrypt (t2, t1, K2, K3, s_SPtrans);
    _des_crypt_decrypt (pt, t2, K0, K1, s_SPtrans);

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];

    // -check\x02\x02

    if (pt[0] != 0x6568632d) continue;
    if (pt[1] != 0x02026b63) continue;

    const u32 r0 = ct_buf0[0];
    const u32 r1 = ct_buf0[1];
    const u32 r2 = ct_buf1[0];
    const u32 r3 = ct_buf1[1];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
