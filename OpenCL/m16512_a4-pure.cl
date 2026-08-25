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
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

  u32 signature_len;

} jwt_t;

#define PCFG_HASH_BLKWORDS  32

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (jwt_t)

typedef struct pcfg_hash_ctx
{
  GLOBAL_AS const jwt_t *esalt_bufs;
  u32 digest_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const jwt_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha384_hmac_ctx_t ctx;

  sha384_hmac_init_swap (&ctx, w, len);

  sha384_hmac_update_global_swap (&ctx, hc->esalt_bufs[hc->digest_pos].salt_buf, hc->esalt_bufs[hc->digest_pos].salt_len);

  sha384_hmac_final (&ctx);

  dgst[0] = l32_from_64 (ctx.opad.h[0]);
  dgst[1] = h32_from_64 (ctx.opad.h[0]);
  dgst[2] = l32_from_64 (ctx.opad.h[1]);
  dgst[3] = h32_from_64 (ctx.opad.h[1]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha384_hmac_ctx_t ctx;

  sha384_hmac_init_global_swap (&ctx, w, len);

  sha384_hmac_update_global_swap (&ctx, hc->esalt_bufs[hc->digest_pos].salt_buf, hc->esalt_bufs[hc->digest_pos].salt_len);

  sha384_hmac_final (&ctx);

  dgst[0] = l32_from_64 (ctx.opad.h[0]);
  dgst[1] = h32_from_64 (ctx.opad.h[0]);
  dgst[2] = l32_from_64 (ctx.opad.h[1]);
  dgst[3] = h32_from_64 (ctx.opad.h[1]);

  return true;
}

#define PCFG_KERNEL_MXX m16512_mxx
#define PCFG_KERNEL_SXX m16512_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
