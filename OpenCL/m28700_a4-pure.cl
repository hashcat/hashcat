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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

typedef struct aws4_sig_v4
{
  u32 date[3];
  u32 date_len;

  u32 longdate[4];
  u32 longdate_len;

  u32 region[4];
  u32 region_len;

  u32 service[4];
  u32 service_len;

  u32 canonical[8];
  u32 canonical_len;

  u32 stringtosign[64];
  u32 stringtosign_len;

} aws4_sig_v4_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (aws4_sig_v4_t)

typedef struct pcfg_hash_ctx
{
  u32 date_len;
  u32 date_buf[64];
  u32 region_len;
  u32 region_buf[64];
  u32 service_len;
  u32 service_buf[64];
  u32 stringtosign_len;
  u32 stringtosign_buf[64];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const aws4_sig_v4_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->date_len = esalt_bufs[digest_pos].date_len;

  for (u32 i = 0; i < 64; i++) hc->date_buf[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->date_len; i += 4, idx += 1)
  {
    hc->date_buf[idx] = hc_swap32_S (esalt_bufs[digest_pos].date[idx]);
  }

  hc->region_len = esalt_bufs[digest_pos].region_len;

  for (u32 i = 0; i < 64; i++) hc->region_buf[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->region_len; i += 4, idx += 1)
  {
    hc->region_buf[idx] = hc_swap32_S (esalt_bufs[digest_pos].region[idx]);
  }

  hc->service_len = esalt_bufs[digest_pos].service_len;

  for (u32 i = 0; i < 64; i++) hc->service_buf[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->service_len; i += 4, idx += 1)
  {
    hc->service_buf[idx] = hc_swap32_S (esalt_bufs[digest_pos].service[idx]);
  }

  hc->stringtosign_len = esalt_bufs[digest_pos].stringtosign_len;

  for (u32 i = 0; i < 64; i++) hc->stringtosign_buf[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->stringtosign_len; i += 4, idx += 1)
  {
    hc->stringtosign_buf[idx] = hc_swap32_S (esalt_bufs[digest_pos].stringtosign[idx]);
  }
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  u32 wx[64] = { 0 };

  wx[0] = 0x41575334;

  for (u32 i = 4, idx = 1; i < len + 4; i += 4, idx += 1)
  {
    wx[idx] = hc_swap32_S (w[idx - 1]);
  }

  sha256_hmac_ctx_t ctx_kdate;

  sha256_hmac_init (&ctx_kdate, wx, len + 4);

  sha256_hmac_update (&ctx_kdate, hc->date_buf, hc->date_len);

  sha256_hmac_final (&ctx_kdate);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx_kdate.opad.h[0];
  w0[1] = ctx_kdate.opad.h[1];
  w0[2] = ctx_kdate.opad.h[2];
  w0[3] = ctx_kdate.opad.h[3];
  w1[0] = ctx_kdate.opad.h[4];
  w1[1] = ctx_kdate.opad.h[5];
  w1[2] = ctx_kdate.opad.h[6];
  w1[3] = ctx_kdate.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_kregion;

  sha256_hmac_init_64 (&ctx_kregion, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_kregion, hc->region_buf, hc->region_len);

  sha256_hmac_final (&ctx_kregion);

  w0[0] = ctx_kregion.opad.h[0];
  w0[1] = ctx_kregion.opad.h[1];
  w0[2] = ctx_kregion.opad.h[2];
  w0[3] = ctx_kregion.opad.h[3];
  w1[0] = ctx_kregion.opad.h[4];
  w1[1] = ctx_kregion.opad.h[5];
  w1[2] = ctx_kregion.opad.h[6];
  w1[3] = ctx_kregion.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_kservice;

  sha256_hmac_init_64 (&ctx_kservice, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_kservice, hc->service_buf, hc->service_len);

  sha256_hmac_final (&ctx_kservice);

  w0[0] = ctx_kservice.opad.h[0];
  w0[1] = ctx_kservice.opad.h[1];
  w0[2] = ctx_kservice.opad.h[2];
  w0[3] = ctx_kservice.opad.h[3];
  w1[0] = ctx_kservice.opad.h[4];
  w1[1] = ctx_kservice.opad.h[5];
  w1[2] = ctx_kservice.opad.h[6];
  w1[3] = ctx_kservice.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_signingkey;

  sha256_hmac_init_64 (&ctx_signingkey, w0, w1, w2, w3);

  w0[0] = 0x61777334;
  w0[1] = 0x5f726571;
  w0[2] = 0x75657374;
  w0[3] = 0;
  w1[0] = 0;
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

  sha256_hmac_update_64 (&ctx_signingkey, w0, w1, w2, w3, 12);

  sha256_hmac_final (&ctx_signingkey);

  w0[0] = ctx_signingkey.opad.h[0];
  w0[1] = ctx_signingkey.opad.h[1];
  w0[2] = ctx_signingkey.opad.h[2];
  w0[3] = ctx_signingkey.opad.h[3];
  w1[0] = ctx_signingkey.opad.h[4];
  w1[1] = ctx_signingkey.opad.h[5];
  w1[2] = ctx_signingkey.opad.h[6];
  w1[3] = ctx_signingkey.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_signature;

  sha256_hmac_init_64 (&ctx_signature, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_signature, hc->stringtosign_buf, hc->stringtosign_len);

  sha256_hmac_final (&ctx_signature);

  dgst[0] = ctx_signature.opad.h[DGST_R0];
  dgst[1] = ctx_signature.opad.h[DGST_R1];
  dgst[2] = ctx_signature.opad.h[DGST_R2];
  dgst[3] = ctx_signature.opad.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  u32 wx[64] = { 0 };

  wx[0] = 0x41575334;

  for (u32 i = 4, idx = 1; i < len + 4; i += 4, idx += 1)
  {
    wx[idx] = hc_swap32_S (w[idx - 1]);
  }

  sha256_hmac_ctx_t ctx_kdate;

  sha256_hmac_init (&ctx_kdate, wx, len + 4);

  sha256_hmac_update (&ctx_kdate, hc->date_buf, hc->date_len);

  sha256_hmac_final (&ctx_kdate);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx_kdate.opad.h[0];
  w0[1] = ctx_kdate.opad.h[1];
  w0[2] = ctx_kdate.opad.h[2];
  w0[3] = ctx_kdate.opad.h[3];
  w1[0] = ctx_kdate.opad.h[4];
  w1[1] = ctx_kdate.opad.h[5];
  w1[2] = ctx_kdate.opad.h[6];
  w1[3] = ctx_kdate.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_kregion;

  sha256_hmac_init_64 (&ctx_kregion, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_kregion, hc->region_buf, hc->region_len);

  sha256_hmac_final (&ctx_kregion);

  w0[0] = ctx_kregion.opad.h[0];
  w0[1] = ctx_kregion.opad.h[1];
  w0[2] = ctx_kregion.opad.h[2];
  w0[3] = ctx_kregion.opad.h[3];
  w1[0] = ctx_kregion.opad.h[4];
  w1[1] = ctx_kregion.opad.h[5];
  w1[2] = ctx_kregion.opad.h[6];
  w1[3] = ctx_kregion.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_kservice;

  sha256_hmac_init_64 (&ctx_kservice, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_kservice, hc->service_buf, hc->service_len);

  sha256_hmac_final (&ctx_kservice);

  w0[0] = ctx_kservice.opad.h[0];
  w0[1] = ctx_kservice.opad.h[1];
  w0[2] = ctx_kservice.opad.h[2];
  w0[3] = ctx_kservice.opad.h[3];
  w1[0] = ctx_kservice.opad.h[4];
  w1[1] = ctx_kservice.opad.h[5];
  w1[2] = ctx_kservice.opad.h[6];
  w1[3] = ctx_kservice.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_signingkey;

  sha256_hmac_init_64 (&ctx_signingkey, w0, w1, w2, w3);

  w0[0] = 0x61777334;
  w0[1] = 0x5f726571;
  w0[2] = 0x75657374;
  w0[3] = 0;
  w1[0] = 0;
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

  sha256_hmac_update_64 (&ctx_signingkey, w0, w1, w2, w3, 12);

  sha256_hmac_final (&ctx_signingkey);

  w0[0] = ctx_signingkey.opad.h[0];
  w0[1] = ctx_signingkey.opad.h[1];
  w0[2] = ctx_signingkey.opad.h[2];
  w0[3] = ctx_signingkey.opad.h[3];
  w1[0] = ctx_signingkey.opad.h[4];
  w1[1] = ctx_signingkey.opad.h[5];
  w1[2] = ctx_signingkey.opad.h[6];
  w1[3] = ctx_signingkey.opad.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_ctx_t ctx_signature;

  sha256_hmac_init_64 (&ctx_signature, w0, w1, w2, w3);

  sha256_hmac_update (&ctx_signature, hc->stringtosign_buf, hc->stringtosign_len);

  sha256_hmac_final (&ctx_signature);

  dgst[0] = ctx_signature.opad.h[DGST_R0];
  dgst[1] = ctx_signature.opad.h[DGST_R1];
  dgst[2] = ctx_signature.opad.h[DGST_R2];
  dgst[3] = ctx_signature.opad.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m28700_mxx
#define PCFG_KERNEL_SXX m28700_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
