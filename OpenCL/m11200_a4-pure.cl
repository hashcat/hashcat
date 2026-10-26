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
  sha1_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  sha1_init (&hc->ctx0);

  sha1_update_global_swap (&hc->ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx2;

  sha1_init (&ctx2);

  sha1_update_swap (&ctx2, w, len);

  sha1_final (&ctx2);

  u32 a = ctx2.h[0];
  u32 b = ctx2.h[1];
  u32 c = ctx2.h[2];
  u32 d = ctx2.h[3];
  u32 e = ctx2.h[4];

  const u32 a_sav = a;
  const u32 b_sav = b;
  const u32 c_sav = c;
  const u32 d_sav = d;
  const u32 e_sav = e;

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  ctx1.w0[0] = a;
  ctx1.w0[1] = b;
  ctx1.w0[2] = c;
  ctx1.w0[3] = d;
  ctx1.w1[0] = e;

  ctx1.len = 20;

  sha1_final (&ctx1);

  a = ctx1.h[0];
  b = ctx1.h[1];
  c = ctx1.h[2];
  d = ctx1.h[3];
  e = ctx1.h[4];

  sha1_ctx_t ctx = hc->ctx0;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = a;
  w0[1] = b;
  w0[2] = c;
  w0[3] = d;
  w1[0] = e;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20);

  sha1_final (&ctx);

  ctx.h[0] ^= a_sav;
  ctx.h[1] ^= b_sav;
  ctx.h[2] ^= c_sav;
  ctx.h[3] ^= d_sav;
  ctx.h[4] ^= e_sav;

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx2;

  sha1_init (&ctx2);

  sha1_update_global_swap (&ctx2, w, len);

  sha1_final (&ctx2);

  u32 a = ctx2.h[0];
  u32 b = ctx2.h[1];
  u32 c = ctx2.h[2];
  u32 d = ctx2.h[3];
  u32 e = ctx2.h[4];

  const u32 a_sav = a;
  const u32 b_sav = b;
  const u32 c_sav = c;
  const u32 d_sav = d;
  const u32 e_sav = e;

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  ctx1.w0[0] = a;
  ctx1.w0[1] = b;
  ctx1.w0[2] = c;
  ctx1.w0[3] = d;
  ctx1.w1[0] = e;

  ctx1.len = 20;

  sha1_final (&ctx1);

  a = ctx1.h[0];
  b = ctx1.h[1];
  c = ctx1.h[2];
  d = ctx1.h[3];
  e = ctx1.h[4];

  sha1_ctx_t ctx = hc->ctx0;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = a;
  w0[1] = b;
  w0[2] = c;
  w0[3] = d;
  w1[0] = e;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20);

  sha1_final (&ctx);

  ctx.h[0] ^= a_sav;
  ctx.h[1] ^= b_sav;
  ctx.h[2] ^= c_sav;
  ctx.h[3] ^= d_sav;
  ctx.h[4] ^= e_sav;

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m11200_mxx
#define PCFG_KERNEL_SXX m11200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
