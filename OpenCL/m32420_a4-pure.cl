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
  u32 salt_len;
  u32 s[64];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  w0[0] = h32_from_64_S (ctx0.h[0]);
  w0[1] = l32_from_64_S (ctx0.h[0]);
  w0[2] = h32_from_64_S (ctx0.h[1]);
  w0[3] = l32_from_64_S (ctx0.h[1]);
  w1[0] = h32_from_64_S (ctx0.h[2]);
  w1[1] = l32_from_64_S (ctx0.h[2]);
  w1[2] = h32_from_64_S (ctx0.h[3]);
  w1[3] = l32_from_64_S (ctx0.h[3]);
  w2[0] = h32_from_64_S (ctx0.h[4]);
  w2[1] = l32_from_64_S (ctx0.h[4]);
  w2[2] = h32_from_64_S (ctx0.h[5]);
  w2[3] = l32_from_64_S (ctx0.h[5]);
  w3[0] = h32_from_64_S (ctx0.h[6]);
  w3[1] = l32_from_64_S (ctx0.h[6]);
  w3[2] = h32_from_64_S (ctx0.h[7]);
  w3[3] = l32_from_64_S (ctx0.h[7]);
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);

  sha512_update (&ctx, hc->s, hc->salt_len);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  w0[0] = h32_from_64_S (ctx0.h[0]);
  w0[1] = l32_from_64_S (ctx0.h[0]);
  w0[2] = h32_from_64_S (ctx0.h[1]);
  w0[3] = l32_from_64_S (ctx0.h[1]);
  w1[0] = h32_from_64_S (ctx0.h[2]);
  w1[1] = l32_from_64_S (ctx0.h[2]);
  w1[2] = h32_from_64_S (ctx0.h[3]);
  w1[3] = l32_from_64_S (ctx0.h[3]);
  w2[0] = h32_from_64_S (ctx0.h[4]);
  w2[1] = l32_from_64_S (ctx0.h[4]);
  w2[2] = h32_from_64_S (ctx0.h[5]);
  w2[3] = l32_from_64_S (ctx0.h[5]);
  w3[0] = h32_from_64_S (ctx0.h[6]);
  w3[1] = l32_from_64_S (ctx0.h[6]);
  w3[2] = h32_from_64_S (ctx0.h[7]);
  w3[3] = l32_from_64_S (ctx0.h[7]);
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);

  sha512_update (&ctx, hc->s, hc->salt_len);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

#define PCFG_KERNEL_MXX m32420_mxx
#define PCFG_KERNEL_SXX m32420_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
