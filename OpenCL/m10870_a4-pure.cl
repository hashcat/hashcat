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

#define PCFG_HASH_BLKWORDS  32

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
  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_utf16le_swap (&ctx, w, len);

  sha384_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[3]);
  dgst[1] = h32_from_64_S (ctx.h[3]);
  dgst[2] = l32_from_64_S (ctx.h[2]);
  dgst[3] = h32_from_64_S (ctx.h[2]);

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_global_utf16le_swap (&ctx, w, len);

  sha384_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[3]);
  dgst[1] = h32_from_64_S (ctx.h[3]);
  dgst[2] = l32_from_64_S (ctx.h[2]);
  dgst[3] = h32_from_64_S (ctx.h[2]);

  return true;
}

#define PCFG_KERNEL_MXX m10870_mxx
#define PCFG_KERNEL_SXX m10870_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
