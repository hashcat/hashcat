/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
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

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (pem_t)

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_td0[256];             \
  LOCAL_VK u32 s_td1[256];             \
  LOCAL_VK u32 s_td2[256];             \
  LOCAL_VK u32 s_td3[256];             \
  LOCAL_VK u32 s_td4[256];             \
  LOCAL_VK u32 s_te0[256];             \
  LOCAL_VK u32 s_te1[256];             \
  LOCAL_VK u32 s_te2[256];             \
  LOCAL_VK u32 s_te3[256];             \
  LOCAL_VK u32 s_te4[256];             \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_td0[i] = td0[i];                 \
    s_td1[i] = td1[i];                 \
    s_td2[i] = td2[i];                 \
    s_td3[i] = td3[i];                 \
    s_td4[i] = td4[i];                 \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_te4[i] = te4[i];                 \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_td0 = s_td0;            \
  (hc)->s_td1 = s_td1;            \
  (hc)->s_td2 = s_td2;            \
  (hc)->s_td3 = s_td3;            \
  (hc)->s_td4 = s_td4;            \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_te4 = s_te4;
#endif

typedef struct pcfg_hash_ctx
{
  u32 search[4];
  u32 s[4];
  u32 first_data[4];
  int data_len;
  u32 iv[4];
  u32 enc[4];
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0;
  LOCAL_AS u32 *s_td1;
  LOCAL_AS u32 *s_td2;
  LOCAL_AS u32 *s_td3;
  LOCAL_AS u32 *s_td4;
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_te4;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const pem_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  int last_pad_pos;
  int last_pad_elem;

  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->s[0] = salt_bufs[salt_pos].salt_buf[0];
  hc->s[1] = salt_bufs[salt_pos].salt_buf[1];
  hc->s[2] = salt_bufs[salt_pos].salt_buf[2];
  hc->s[3] = salt_bufs[salt_pos].salt_buf[3];

  hc->first_data[0] = esalt_bufs[digest_pos].data_buf[0];
  hc->first_data[1] = esalt_bufs[digest_pos].data_buf[1];
  hc->first_data[2] = esalt_bufs[digest_pos].data_buf[2];
  hc->first_data[3] = esalt_bufs[digest_pos].data_buf[3];

  hc->data_len = esalt_bufs[digest_pos].data_len;

  last_pad_pos = hc->data_len - 1;

  last_pad_elem = last_pad_pos / 4;

  hc->iv[0] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 7];
  hc->iv[1] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 6];
  hc->iv[2] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 5];
  hc->iv[3] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 4];

  hc->enc[0] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 3];
  hc->enc[1] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 2];
  hc->enc[2] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 1];
  hc->enc[3] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 0];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0 = hc->s_td0;
  LOCAL_AS u32 *s_td1 = hc->s_td1;
  LOCAL_AS u32 *s_td2 = hc->s_td2;
  LOCAL_AS u32 *s_td3 = hc->s_td3;
  LOCAL_AS u32 *s_td4 = hc->s_td4;
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_te4 = hc->s_te4;
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

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update (&ctx, w, len);

  u32 t[16];

  t[ 0] = hc->s[0];
  t[ 1] = hc->s[1];
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

  u32 ukey[4];

  ukey[0] = ctx.h[0];
  ukey[1] = ctx.h[1];
  ukey[2] = ctx.h[2];
  ukey[3] = ctx.h[3];

  ukey[0] = hc_swap32_S (ukey[0]);
  ukey[1] = hc_swap32_S (ukey[1]);
  ukey[2] = hc_swap32_S (ukey[2]);
  ukey[3] = hc_swap32_S (ukey[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 dec[4];

  aes128_decrypt (ks, hc->enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= hc->iv[0];
  dec[1] ^= hc->iv[1];
  dec[2] ^= hc->iv[2];
  dec[3] ^= hc->iv[3];

  const int paddingv = pkcs_padding_bs16 (dec, 16);

  if (paddingv == -1) return false;

  aes128_decrypt (ks, hc->first_data, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= hc->s[0];
  dec[1] ^= hc->s[1];
  dec[2] ^= hc->s[2];
  dec[3] ^= hc->s[3];

  const int real_len = (hc->data_len - 16) + paddingv;

  const int asn1_ok = asn1_detect (dec, real_len);

  if (asn1_ok == 0) return false;

  const int asn1_tag_ok = asn1_check_int_tag (dec, real_len);

  if (asn1_tag_ok == 0) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0 = hc->s_td0;
  LOCAL_AS u32 *s_td1 = hc->s_td1;
  LOCAL_AS u32 *s_td2 = hc->s_td2;
  LOCAL_AS u32 *s_td3 = hc->s_td3;
  LOCAL_AS u32 *s_td4 = hc->s_td4;
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_te4 = hc->s_te4;
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

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, w, len);

  u32 t[16];

  t[ 0] = hc->s[0];
  t[ 1] = hc->s[1];
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

  u32 ukey[4];

  ukey[0] = ctx.h[0];
  ukey[1] = ctx.h[1];
  ukey[2] = ctx.h[2];
  ukey[3] = ctx.h[3];

  ukey[0] = hc_swap32_S (ukey[0]);
  ukey[1] = hc_swap32_S (ukey[1]);
  ukey[2] = hc_swap32_S (ukey[2]);
  ukey[3] = hc_swap32_S (ukey[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 dec[4];

  aes128_decrypt (ks, hc->enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= hc->iv[0];
  dec[1] ^= hc->iv[1];
  dec[2] ^= hc->iv[2];
  dec[3] ^= hc->iv[3];

  const int paddingv = pkcs_padding_bs16 (dec, 16);

  if (paddingv == -1) return false;

  aes128_decrypt (ks, hc->first_data, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= hc->s[0];
  dec[1] ^= hc->s[1];
  dec[2] ^= hc->s[2];
  dec[3] ^= hc->s[3];

  const int real_len = (hc->data_len - 16) + paddingv;

  const int asn1_ok = asn1_detect (dec, real_len);

  if (asn1_ok == 0) return false;

  const int asn1_tag_ok = asn1_check_int_tag (dec, real_len);

  if (asn1_tag_ok == 0) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

#define PCFG_KERNEL_MXX m22931_mxx
#define PCFG_KERNEL_SXX m22931_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
