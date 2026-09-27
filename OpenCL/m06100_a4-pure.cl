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
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u64 s_MT0[256];             \
  LOCAL_VK u64 s_MT1[256];             \
  LOCAL_VK u64 s_MT2[256];             \
  LOCAL_VK u64 s_MT3[256];             \
  LOCAL_VK u64 s_MT4[256];             \
  LOCAL_VK u64 s_MT5[256];             \
  LOCAL_VK u64 s_MT6[256];             \
  LOCAL_VK u64 s_MT7[256];             \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_MT0[i] = MT0[i];                 \
    s_MT1[i] = MT1[i];                 \
    s_MT2[i] = MT2[i];                 \
    s_MT3[i] = MT3[i];                 \
    s_MT4[i] = MT4[i];                 \
    s_MT5[i] = MT5[i];                 \
    s_MT6[i] = MT6[i];                 \
    s_MT7[i] = MT7[i];                 \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_MT0 = s_MT0;            \
  (hc)->s_MT1 = s_MT1;            \
  (hc)->s_MT2 = s_MT2;            \
  (hc)->s_MT3 = s_MT3;            \
  (hc)->s_MT4 = s_MT4;            \
  (hc)->s_MT5 = s_MT5;            \
  (hc)->s_MT6 = s_MT6;            \
  (hc)->s_MT7 = s_MT7;
#endif

typedef struct pcfg_hash_ctx
{
  #ifdef REAL_SHM
  LOCAL_AS u64 *s_MT0;
  LOCAL_AS u64 *s_MT1;
  LOCAL_AS u64 *s_MT2;
  LOCAL_AS u64 *s_MT3;
  LOCAL_AS u64 *s_MT4;
  LOCAL_AS u64 *s_MT5;
  LOCAL_AS u64 *s_MT6;
  LOCAL_AS u64 *s_MT7;
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
  LOCAL_AS u64 *s_MT0 = hc->s_MT0;
  LOCAL_AS u64 *s_MT1 = hc->s_MT1;
  LOCAL_AS u64 *s_MT2 = hc->s_MT2;
  LOCAL_AS u64 *s_MT3 = hc->s_MT3;
  LOCAL_AS u64 *s_MT4 = hc->s_MT4;
  LOCAL_AS u64 *s_MT5 = hc->s_MT5;
  LOCAL_AS u64 *s_MT6 = hc->s_MT6;
  LOCAL_AS u64 *s_MT7 = hc->s_MT7;
  #else
  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;
  #endif

  whirlpool_ctx_t ctx;

  whirlpool_init (&ctx, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_swap (&ctx, w, len);

  whirlpool_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64 *s_MT0 = hc->s_MT0;
  LOCAL_AS u64 *s_MT1 = hc->s_MT1;
  LOCAL_AS u64 *s_MT2 = hc->s_MT2;
  LOCAL_AS u64 *s_MT3 = hc->s_MT3;
  LOCAL_AS u64 *s_MT4 = hc->s_MT4;
  LOCAL_AS u64 *s_MT5 = hc->s_MT5;
  LOCAL_AS u64 *s_MT6 = hc->s_MT6;
  LOCAL_AS u64 *s_MT7 = hc->s_MT7;
  #else
  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;
  #endif

  whirlpool_ctx_t ctx;

  whirlpool_init (&ctx, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_global_swap (&ctx, w, len);

  whirlpool_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m06100_mxx
#define PCFG_KERNEL_SXX m06100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
