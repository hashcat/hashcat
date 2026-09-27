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
  sha1_ctx_t ctx = hc->ctx0;

  sha1_update_swap (&ctx, w, len);

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = hc_swap32_S (FORTIGATE_A);
  p0[1] = hc_swap32_S (FORTIGATE_B);
  p0[2] = hc_swap32_S (FORTIGATE_C);
  p0[3] = hc_swap32_S (FORTIGATE_D);
  p1[0] = hc_swap32_S (FORTIGATE_E);
  p1[1] = hc_swap32_S (FORTIGATE_F);
  p1[2] = 0;
  p1[3] = 0;
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  sha1_update_64 (&ctx, p0, p1, p2, p3, 24);

  sha1_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx = hc->ctx0;

  sha1_update_global_swap (&ctx, w, len);

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = hc_swap32_S (FORTIGATE_A);
  p0[1] = hc_swap32_S (FORTIGATE_B);
  p0[2] = hc_swap32_S (FORTIGATE_C);
  p0[3] = hc_swap32_S (FORTIGATE_D);
  p1[0] = hc_swap32_S (FORTIGATE_E);
  p1[1] = hc_swap32_S (FORTIGATE_F);
  p1[2] = 0;
  p1[3] = 0;
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  sha1_update_64 (&ctx, p0, p1, p2, p3, 24);

  sha1_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m07000_mxx
#define PCFG_KERNEL_SXX m07000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
