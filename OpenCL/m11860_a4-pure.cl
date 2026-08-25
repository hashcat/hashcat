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
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL               \
  LOCAL_VK u64a s_sbob_sl64[8][256];        \
  for (u32 i = lid; i < 256; i += lsz)      \
  {                                         \
    s_sbob_sl64[0][i] = sbob512_sl64[0][i]; \
    s_sbob_sl64[1][i] = sbob512_sl64[1][i]; \
    s_sbob_sl64[2][i] = sbob512_sl64[2][i]; \
    s_sbob_sl64[3][i] = sbob512_sl64[3][i]; \
    s_sbob_sl64[4][i] = sbob512_sl64[4][i]; \
    s_sbob_sl64[5][i] = sbob512_sl64[5][i]; \
    s_sbob_sl64[6][i] = sbob512_sl64[6][i]; \
    s_sbob_sl64[7][i] = sbob512_sl64[7][i]; \
  }                                         \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->s_sbob_sl64 = s_sbob_sl64;
#endif

typedef struct pcfg_hash_ctx
{
  streebog512_hmac_ctx_t ctx0;
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256] = hc->s_sbob_sl64;
  #else
  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;
  #endif

  u32 salt_len;
  u32 s[64];

  salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) s[i] = 0;

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  streebog512_hmac_init (&hc->ctx0, s, salt_len, s_sbob_sl64);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256] = hc->s_sbob_sl64;
  #else
  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;
  #endif

  streebog512_hmac_ctx_t ctx = hc->ctx0;

  streebog512_hmac_update_swap (&ctx, w, len);

  streebog512_hmac_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.opad.h[0]);
  dgst[1] = h32_from_64_S (ctx.opad.h[0]);
  dgst[2] = l32_from_64_S (ctx.opad.h[1]);
  dgst[3] = h32_from_64_S (ctx.opad.h[1]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64a (*s_sbob_sl64)[256] = hc->s_sbob_sl64;
  #else
  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;
  #endif

  streebog512_hmac_ctx_t ctx = hc->ctx0;

  streebog512_hmac_update_global_swap (&ctx, w, len);

  streebog512_hmac_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.opad.h[0]);
  dgst[1] = h32_from_64_S (ctx.opad.h[0]);
  dgst[2] = l32_from_64_S (ctx.opad.h[1]);
  dgst[3] = h32_from_64_S (ctx.opad.h[1]);

  return true;
}

#define PCFG_KERNEL_MXX m11860_mxx
#define PCFG_KERNEL_SXX m11860_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
