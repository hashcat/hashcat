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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct pem
{
  u32 data_buf[16384];
  int data_len;

  int cipher;

} pem_t;

KERNEL_FQ void m22911_mxx (KERN_ATTR_ESALT (pem_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base
   */

  u32 s[2];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  u32 first_data[2];

  first_data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  first_data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  const int last_pad_pos = data_len - 1;

  const int last_pad_elem = last_pad_pos / 4;

  u32 iv[2];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];

  u32 enc[2];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    u32 t[16];

    t[ 0] = s[0];
    t[ 1] = s[1];
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

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    u32 ukey[6];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    md5_init (&ctx);

    ctx.w0[0] = ukey[0];
    ctx.w0[1] = ukey[1];
    ctx.w0[2] = ukey[2];
    ctx.w0[3] = ukey[3];

    ctx.len = 16;

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];

    // DES

    u32 K0[16];
    u32 K1[16];
    u32 K2[16];
    u32 K3[16];
    u32 K4[16];
    u32 K5[16];

    _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);
    _des_crypt_keysetup (ukey[2], ukey[3], K2, K3, s_skb);
    _des_crypt_keysetup (ukey[4], ukey[5], K4, K5, s_skb);

    u32 dec[2];

    // first check the padding

    u32 p1[2];
    u32 p2[2];

    _des_crypt_decrypt (p1,  enc, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];

    const int paddingv = pkcs_padding_bs8 (dec, 8);

    if (paddingv == -1) continue;

    // second check (naive code) ASN.1 structure

    _des_crypt_decrypt (p1,  first_data, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= s[0];
    dec[1] ^= s[1];

    const int real_len = (data_len - 8) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) continue;

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m22911_sxx (KERN_ATTR_ESALT (pem_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base
   */

  u32 s[2];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  u32 first_data[2];

  first_data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  first_data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  const int last_pad_pos = data_len - 1;

  const int last_pad_elem = last_pad_pos / 4;

  u32 iv[2];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];

  u32 enc[2];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    u32 t[16];

    t[ 0] = s[0];
    t[ 1] = s[1];
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

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    u32 ukey[6];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    md5_init (&ctx);

    ctx.w0[0] = ukey[0];
    ctx.w0[1] = ukey[1];
    ctx.w0[2] = ukey[2];
    ctx.w0[3] = ukey[3];

    ctx.len = 16;

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];

    // DES

    u32 K0[16];
    u32 K1[16];
    u32 K2[16];
    u32 K3[16];
    u32 K4[16];
    u32 K5[16];

    _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);
    _des_crypt_keysetup (ukey[2], ukey[3], K2, K3, s_skb);
    _des_crypt_keysetup (ukey[4], ukey[5], K4, K5, s_skb);

    u32 dec[2];

    // first check the padding

    u32 p1[2];
    u32 p2[2];

    _des_crypt_decrypt (p1,  enc, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];

    const int paddingv = pkcs_padding_bs8 (dec, 8);

    if (paddingv == -1) continue;

    // second check (naive code) ASN.1 structure

    _des_crypt_decrypt (p1,  first_data, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= s[0];
    dec[1] ^= s[1];

    const int real_len = (data_len - 8) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) continue;

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
