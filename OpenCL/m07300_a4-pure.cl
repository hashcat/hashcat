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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

typedef struct rakp
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (rakp_t)

typedef struct pcfg_hash_ctx
{
  GLOBAL_AS const u32 *salt_buf;

  u32 salt_len;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const rakp_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt_buf = esalt_bufs[digest_pos].salt_buf;
  hc->salt_len = esalt_bufs[digest_pos].salt_len;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_swap (&ctx, w, len);

  sha1_hmac_update_global (&ctx, hc->salt_buf, hc->salt_len);

  sha1_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[DGST_R0];
  dgst[1] = ctx.opad.h[DGST_R1];
  dgst[2] = ctx.opad.h[DGST_R2];
  dgst[3] = ctx.opad.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_global_swap (&ctx, w, len);

  sha1_hmac_update_global (&ctx, hc->salt_buf, hc->salt_len);

  sha1_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[DGST_R0];
  dgst[1] = ctx.opad.h[DGST_R1];
  dgst[2] = ctx.opad.h[DGST_R2];
  dgst[3] = ctx.opad.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m07300_mxx
#define PCFG_KERNEL_SXX m07300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
