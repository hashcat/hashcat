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

typedef struct sha1_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} sha1_double_salt_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (sha1_double_salt_t)

typedef struct pcfg_hash_ctx
{
  sha1_ctx_t ctx0;
  sha1_ctx_t ctx2;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const sha1_double_salt_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  u32 colon[16];

  colon[0] = 0x3a000000;
  colon[1] = 0;
  colon[2] = 0;
  colon[3] = 0;
  colon[4] = 0;
  colon[5] = 0;
  colon[6] = 0;
  colon[7] = 0;
  colon[8] = 0;
  colon[9] = 0;
  colon[10] = 0;
  colon[11] = 0;
  colon[12] = 0;
  colon[13] = 0;
  colon[14] = 0;
  colon[15] = 0;

  sha1_init (&hc->ctx0);

  sha1_update_global_swap (&hc->ctx0, esalt_bufs[salt_pos].salt1_buf, esalt_bufs[salt_pos].salt1_len);

  sha1_init (&hc->ctx2);

  sha1_update_global_utf16le_swap (&hc->ctx2, esalt_bufs[salt_pos].salt2_buf, esalt_bufs[salt_pos].salt2_len);

  sha1_update(&hc->ctx2, colon, 1);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx1 = hc->ctx2;

  sha1_update_utf16le_swap (&ctx1, w, len);

  sha1_final (&ctx1);

  sha1_ctx_t ctx = hc->ctx0;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx1.h[0];
  w0[1] = ctx1.h[1];
  w0[2] = ctx1.h[2];
  w0[3] = ctx1.h[3];
  w1[0] = ctx1.h[4];
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

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx1 = hc->ctx2;

  sha1_update_global_utf16le_swap (&ctx1, w, len);

  sha1_final (&ctx1);

  sha1_ctx_t ctx = hc->ctx0;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx1.h[0];
  w0[1] = ctx1.h[1];
  w0[2] = ctx1.h[2];
  w0[3] = ctx1.h[3];
  w1[0] = ctx1.h[4];
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

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m29000_mxx
#define PCFG_KERNEL_SXX m29000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
