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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
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
  LOCAL_VK u32 s_SPtrans[8][64];       \
  LOCAL_VK u32 s_skb[8][64];           \
  for (u32 i = lid; i < 64; i += lsz)  \
  {                                    \
    s_SPtrans[0][i] = c_SPtrans[0][i]; \
    s_SPtrans[1][i] = c_SPtrans[1][i]; \
    s_SPtrans[2][i] = c_SPtrans[2][i]; \
    s_SPtrans[3][i] = c_SPtrans[3][i]; \
    s_SPtrans[4][i] = c_SPtrans[4][i]; \
    s_SPtrans[5][i] = c_SPtrans[5][i]; \
    s_SPtrans[6][i] = c_SPtrans[6][i]; \
    s_SPtrans[7][i] = c_SPtrans[7][i]; \
    s_skb[0][i] = c_skb[0][i];         \
    s_skb[1][i] = c_skb[1][i];         \
    s_skb[2][i] = c_skb[2][i];         \
    s_skb[3][i] = c_skb[3][i];         \
    s_skb[4][i] = c_skb[4][i];         \
    s_skb[5][i] = c_skb[5][i];         \
    s_skb[6][i] = c_skb[6][i];         \
    s_skb[7][i] = c_skb[7][i];         \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_SPtrans = s_SPtrans;    \
  (hc)->s_skb = s_skb;
#endif

typedef struct pcfg_hash_ctx
{
  u32 search[4];
  u32 s[2];
  u32 first_data[2];
  int data_len;
  u32 iv[2];
  u32 enc[2];
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
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

  hc->first_data[0] = esalt_bufs[digest_pos].data_buf[0];
  hc->first_data[1] = esalt_bufs[digest_pos].data_buf[1];

  hc->data_len = esalt_bufs[digest_pos].data_len;

  last_pad_pos = hc->data_len - 1;

  last_pad_elem = last_pad_pos / 4;

  hc->iv[0] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 3];
  hc->iv[1] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 2];

  hc->enc[0] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 1];
  hc->enc[1] = esalt_bufs[digest_pos].data_buf[last_pad_elem - 0];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
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

  u32 ukey[2];

  ukey[0] = ctx.h[0];
  ukey[1] = ctx.h[1];

  u32 K0[16];
  u32 K1[16];

  _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);

  u32 dec[2];

  _des_crypt_decrypt (dec, hc->enc, K0, K1, s_SPtrans);

  dec[0] ^= hc->iv[0];
  dec[1] ^= hc->iv[1];

  const int paddingv = pkcs_padding_bs8 (dec, 8);

  if (paddingv == -1) return false;

  _des_crypt_decrypt (dec, hc->first_data, K0, K1, s_SPtrans);

  dec[0] ^= hc->s[0];
  dec[1] ^= hc->s[1];

  const int real_len = (hc->data_len - 8) + paddingv;

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
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
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

  u32 ukey[2];

  ukey[0] = ctx.h[0];
  ukey[1] = ctx.h[1];

  u32 K0[16];
  u32 K1[16];

  _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);

  u32 dec[2];

  _des_crypt_decrypt (dec, hc->enc, K0, K1, s_SPtrans);

  dec[0] ^= hc->iv[0];
  dec[1] ^= hc->iv[1];

  const int paddingv = pkcs_padding_bs8 (dec, 8);

  if (paddingv == -1) return false;

  _des_crypt_decrypt (dec, hc->first_data, K0, K1, s_SPtrans);

  dec[0] ^= hc->s[0];
  dec[1] ^= hc->s[1];

  const int real_len = (hc->data_len - 8) + paddingv;

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

#define PCFG_KERNEL_MXX m22921_mxx
#define PCFG_KERNEL_SXX m22921_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
