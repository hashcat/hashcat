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

typedef struct pcfg_hash_ctx
{
  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_swap (&ctx, w, len);

  sha1_final (&ctx);

  ctx.h[4] = 0;

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global_swap (&ctx, w, len);

  sha1_final (&ctx);

  ctx.h[4] = 0;

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m13300_mxx
#define PCFG_KERNEL_SXX m13300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
