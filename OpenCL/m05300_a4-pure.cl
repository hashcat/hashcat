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
#endif

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len[6];

} ikepsk_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (ikepsk_t)

typedef struct pcfg_hash_ctx
{
  GLOBAL_AS const ikepsk_t *esalt_bufs;
  u32 digest_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const ikepsk_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_hmac_ctx_t ctx0;

  md5_hmac_init (&ctx0, w, len);

  md5_hmac_update_global (&ctx0, hc->esalt_bufs[hc->digest_pos].nr_buf, hc->esalt_bufs[hc->digest_pos].nr_len);

  md5_hmac_final (&ctx0);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx0.opad.h[0];
  w0[1] = ctx0.opad.h[1];
  w0[2] = ctx0.opad.h[2];
  w0[3] = ctx0.opad.h[3];
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

  md5_hmac_ctx_t ctx;

  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  md5_hmac_update_global (&ctx, hc->esalt_bufs[hc->digest_pos].msg_buf, hc->esalt_bufs[hc->digest_pos].msg_len[5]);

  md5_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[DGST_R0];
  dgst[1] = ctx.opad.h[DGST_R1];
  dgst[2] = ctx.opad.h[DGST_R2];
  dgst[3] = ctx.opad.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_hmac_ctx_t ctx0;

  md5_hmac_init_global (&ctx0, w, len);

  md5_hmac_update_global (&ctx0, hc->esalt_bufs[hc->digest_pos].nr_buf, hc->esalt_bufs[hc->digest_pos].nr_len);

  md5_hmac_final (&ctx0);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx0.opad.h[0];
  w0[1] = ctx0.opad.h[1];
  w0[2] = ctx0.opad.h[2];
  w0[3] = ctx0.opad.h[3];
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

  md5_hmac_ctx_t ctx;

  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  md5_hmac_update_global (&ctx, hc->esalt_bufs[hc->digest_pos].msg_buf, hc->esalt_bufs[hc->digest_pos].msg_len[5]);

  md5_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[DGST_R0];
  dgst[1] = ctx.opad.h[DGST_R1];
  dgst[2] = ctx.opad.h[DGST_R2];
  dgst[3] = ctx.opad.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m05300_mxx
#define PCFG_KERNEL_SXX m05300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
