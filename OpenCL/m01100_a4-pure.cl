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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_len;
  u32 s[64];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_utf16le (&ctx0, w, len);

  md4_final (&ctx0);

  md4_ctx_t ctx;

  md4_init (&ctx);

  ctx.w0[0] = ctx0.h[0];
  ctx.w0[1] = ctx0.h[1];
  ctx.w0[2] = ctx0.h[2];
  ctx.w0[3] = ctx0.h[3];

  ctx.len = 16;

  md4_update_utf16le (&ctx, hc->s, hc->salt_len);

  md4_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global_utf16le (&ctx0, w, len);

  md4_final (&ctx0);

  md4_ctx_t ctx;

  md4_init (&ctx);

  ctx.w0[0] = ctx0.h[0];
  ctx.w0[1] = ctx0.h[1];
  ctx.w0[2] = ctx0.h[2];
  ctx.w0[3] = ctx0.h[3];

  ctx.len = 16;

  md4_update_utf16le (&ctx, hc->s, hc->salt_len);

  md4_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m01100_mxx
#define PCFG_KERNEL_SXX m01100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
