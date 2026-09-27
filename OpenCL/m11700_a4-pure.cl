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
#include M2S(INCLUDE_PATH/inc_hash_streebog256.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL               \
  LOCAL_VK u64a s_sbob_sl64[8][256];        \
  for (u32 i = lid; i < 256; i += lsz)      \
  {                                         \
    s_sbob_sl64[0][i] = sbob256_sl64[0][i]; \
    s_sbob_sl64[1][i] = sbob256_sl64[1][i]; \
    s_sbob_sl64[2][i] = sbob256_sl64[2][i]; \
    s_sbob_sl64[3][i] = sbob256_sl64[3][i]; \
    s_sbob_sl64[4][i] = sbob256_sl64[4][i]; \
    s_sbob_sl64[5][i] = sbob256_sl64[5][i]; \
    s_sbob_sl64[6][i] = sbob256_sl64[6][i]; \
    s_sbob_sl64[7][i] = sbob256_sl64[7][i]; \
  }                                         \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->s_sbob_sl64 = s_sbob_sl64;
#endif

typedef struct pcfg_hash_ctx
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256] = hc->s_sbob_sl64;
  #else
  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;
  #endif

  streebog256_ctx_t ctx;

  streebog256_init (&ctx, s_sbob_sl64);

  streebog256_update_swap (&ctx, w, len);

  streebog256_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[0]);
  dgst[1] = h32_from_64_S (ctx.h[0]);
  dgst[2] = l32_from_64_S (ctx.h[1]);
  dgst[3] = h32_from_64_S (ctx.h[1]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256] = hc->s_sbob_sl64;
  #else
  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;
  #endif

  streebog256_ctx_t ctx;

  streebog256_init (&ctx, s_sbob_sl64);

  streebog256_update_global_swap (&ctx, w, len);

  streebog256_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[0]);
  dgst[1] = h32_from_64_S (ctx.h[0]);
  dgst[2] = l32_from_64_S (ctx.h[1]);
  dgst[3] = h32_from_64_S (ctx.h[1]);

  return true;
}

#define PCFG_KERNEL_MXX m11700_mxx
#define PCFG_KERNEL_SXX m11700_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
