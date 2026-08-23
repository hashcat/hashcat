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
  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  u32 final[32] = { 0 };

  final[ 0] = h32_from_64_S (ctx0.h[0]);
  final[ 1] = l32_from_64_S (ctx0.h[0]);
  final[ 2] = h32_from_64_S (ctx0.h[1]);
  final[ 3] = l32_from_64_S (ctx0.h[1]);
  final[ 4] = h32_from_64_S (ctx0.h[2]);
  final[ 5] = l32_from_64_S (ctx0.h[2]);
  final[ 6] = h32_from_64_S (ctx0.h[3]);
  final[ 7] = l32_from_64_S (ctx0.h[3]);
  final[ 8] = h32_from_64_S (ctx0.h[4]);
  final[ 9] = l32_from_64_S (ctx0.h[4]);
  final[10] = h32_from_64_S (ctx0.h[5]);
  final[11] = l32_from_64_S (ctx0.h[5]);
  final[12] = h32_from_64_S (ctx0.h[6]);
  final[13] = l32_from_64_S (ctx0.h[6]);
  final[14] = h32_from_64_S (ctx0.h[7]);
  final[15] = l32_from_64_S (ctx0.h[7]);

  sha512_update (&ctx, final, 64);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  u32 final[32] = { 0 };

  final[ 0] = h32_from_64_S (ctx0.h[0]);
  final[ 1] = l32_from_64_S (ctx0.h[0]);
  final[ 2] = h32_from_64_S (ctx0.h[1]);
  final[ 3] = l32_from_64_S (ctx0.h[1]);
  final[ 4] = h32_from_64_S (ctx0.h[2]);
  final[ 5] = l32_from_64_S (ctx0.h[2]);
  final[ 6] = h32_from_64_S (ctx0.h[3]);
  final[ 7] = l32_from_64_S (ctx0.h[3]);
  final[ 8] = h32_from_64_S (ctx0.h[4]);
  final[ 9] = l32_from_64_S (ctx0.h[4]);
  final[10] = h32_from_64_S (ctx0.h[5]);
  final[11] = l32_from_64_S (ctx0.h[5]);
  final[12] = h32_from_64_S (ctx0.h[6]);
  final[13] = l32_from_64_S (ctx0.h[6]);
  final[14] = h32_from_64_S (ctx0.h[7]);
  final[15] = l32_from_64_S (ctx0.h[7]);

  sha512_update (&ctx, final, 64);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

#define PCFG_KERNEL_MXX m21000_mxx
#define PCFG_KERNEL_SXX m21000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
