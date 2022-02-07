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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct pem
{
  u32 data_buf[16384];
  int data_len;

  int cipher;

} pem_t;

KERNEL_FQ void m22941_mxx (KERN_ATTR_RULES_ESALT (pem_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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

  COPY_PW (pws[gid]);

  u32 s[4];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  u32 first_data[4];

  first_data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  first_data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
  first_data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
  first_data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  const int last_pad_pos = data_len - 1;

  const int last_pad_elem = last_pad_pos / 4;

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 7];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 6];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 5];
  iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 4];

  u32 enc[4];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];
  enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
  enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update (&ctx, tmp.i, tmp.pw_len);

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

    md5_update (&ctx, tmp.i, tmp.pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];

    // AES

    ukey[0] = hc_swap32_S (ukey[0]);
    ukey[1] = hc_swap32_S (ukey[1]);
    ukey[2] = hc_swap32_S (ukey[2]);
    ukey[3] = hc_swap32_S (ukey[3]);
    ukey[4] = hc_swap32_S (ukey[4]);
    ukey[5] = hc_swap32_S (ukey[5]);

    u32 ks[52];

    AES192_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 dec[4];

    // first check the padding

    aes192_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) continue;

    // second check (naive code) ASN.1 structure

    aes192_decrypt (ks, first_data, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= s[0];
    dec[1] ^= s[1];
    dec[2] ^= s[2];
    dec[3] ^= s[3];

    const int real_len = (data_len - 16) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) continue;

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m22941_sxx (KERN_ATTR_RULES_ESALT (pem_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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

  COPY_PW (pws[gid]);

  u32 s[4];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  u32 first_data[4];

  first_data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  first_data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
  first_data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
  first_data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  const int last_pad_pos = data_len - 1;

  const int last_pad_elem = last_pad_pos / 4;

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 7];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 6];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 5];
  iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 4];

  u32 enc[4];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];
  enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
  enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update (&ctx, tmp.i, tmp.pw_len);

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

    md5_update (&ctx, tmp.i, tmp.pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];

    // AES

    ukey[0] = hc_swap32_S (ukey[0]);
    ukey[1] = hc_swap32_S (ukey[1]);
    ukey[2] = hc_swap32_S (ukey[2]);
    ukey[3] = hc_swap32_S (ukey[3]);
    ukey[4] = hc_swap32_S (ukey[4]);
    ukey[5] = hc_swap32_S (ukey[5]);

    u32 ks[52];

    AES192_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 dec[4];

    // first check the padding

    aes192_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) continue;

    // second check (naive code) ASN.1 structure

    aes192_decrypt (ks, first_data, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= s[0];
    dec[1] ^= s[1];
    dec[2] ^= s[2];
    dec[3] ^= s[3];

    const int real_len = (data_len - 16) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) continue;

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
