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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define PCFG_HASH_BLKWORDS  32

typedef struct pcfg_hash_ctx
{
  u32 z[32];
  sha512_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  for (u32 i = 0; i < 32; i++) hc->z[i] = 0;

  sha512_init (&hc->ctx0);

  sha512_update_global (&hc->ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha512_ctx_t ctx = hc->ctx0;

  sha512_update_swap (&ctx, w, len);

  sha512_update (&ctx, hc->z, 1);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha512_ctx_t ctx = hc->ctx0;

  sha512_update_global_swap (&ctx, w, len);

  sha512_update (&ctx, hc->z, 1);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

#define PCFG_KERNEL_MXX m22200_mxx
#define PCFG_KERNEL_SXX m22200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
