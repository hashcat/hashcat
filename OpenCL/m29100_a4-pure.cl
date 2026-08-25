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
  u32 salt_len;
  u32 s[32];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 32; i++) hc->s[i] = 0;

  for (u32 id = 0; id < 32; id++)
  {
    hc->s[id] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[id]);
  }
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_hmac_ctx_t ctx;
  sha1_hmac_init_swap (&ctx, w, len);

  ctx.ipad.w0[0] = 0x636f6f6b;
  ctx.ipad.w0[1] = 0x69652d73;
  ctx.ipad.w0[2] = 0x65737369;
  ctx.ipad.w0[3] = 0x6f6e0000;
  ctx.ipad.w1[0] = 0;
  ctx.ipad.w1[1] = 0;
  ctx.ipad.w1[2] = 0;
  ctx.ipad.w1[3] = 0;
  ctx.ipad.w2[0] = 0;
  ctx.ipad.w2[1] = 0;
  ctx.ipad.w2[2] = 0;
  ctx.ipad.w2[3] = 0;
  ctx.ipad.w3[0] = 0;
  ctx.ipad.w3[1] = 0;
  ctx.ipad.w3[2] = 0;
  ctx.ipad.w3[3] = 0;

  ctx.ipad.len += 14;

  sha1_hmac_final (&ctx);

  u32 intermediate[16] = { 0 };

  intermediate[0] = ctx.opad.h[0];
  intermediate[1] = ctx.opad.h[1];
  intermediate[2] = ctx.opad.h[2];
  intermediate[3] = ctx.opad.h[3];
  intermediate[4] = ctx.opad.h[4];

  sha1_hmac_init (&ctx, intermediate, 20);
  sha1_hmac_update (&ctx, hc->s, hc->salt_len);
  sha1_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[0];
  dgst[1] = ctx.opad.h[1];
  dgst[2] = ctx.opad.h[2];
  dgst[3] = ctx.opad.h[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_hmac_ctx_t ctx;
  sha1_hmac_init_global_swap (&ctx, w, len);

  ctx.ipad.w0[0] = 0x636f6f6b;
  ctx.ipad.w0[1] = 0x69652d73;
  ctx.ipad.w0[2] = 0x65737369;
  ctx.ipad.w0[3] = 0x6f6e0000;
  ctx.ipad.w1[0] = 0;
  ctx.ipad.w1[1] = 0;
  ctx.ipad.w1[2] = 0;
  ctx.ipad.w1[3] = 0;
  ctx.ipad.w2[0] = 0;
  ctx.ipad.w2[1] = 0;
  ctx.ipad.w2[2] = 0;
  ctx.ipad.w2[3] = 0;
  ctx.ipad.w3[0] = 0;
  ctx.ipad.w3[1] = 0;
  ctx.ipad.w3[2] = 0;
  ctx.ipad.w3[3] = 0;

  ctx.ipad.len += 14;

  sha1_hmac_final (&ctx);

  u32 intermediate[16] = { 0 };

  intermediate[0] = ctx.opad.h[0];
  intermediate[1] = ctx.opad.h[1];
  intermediate[2] = ctx.opad.h[2];
  intermediate[3] = ctx.opad.h[3];
  intermediate[4] = ctx.opad.h[4];

  sha1_hmac_init (&ctx, intermediate, 20);
  sha1_hmac_update (&ctx, hc->s, hc->salt_len);
  sha1_hmac_final (&ctx);

  dgst[0] = ctx.opad.h[0];
  dgst[1] = ctx.opad.h[1];
  dgst[2] = ctx.opad.h[2];
  dgst[3] = ctx.opad.h[3];

  return true;
}

#define PCFG_KERNEL_MXX m29100_mxx
#define PCFG_KERNEL_SXX m29100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
