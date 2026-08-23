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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_iter;
  sha256_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_iter = salt_bufs[salt_pos].salt_iter;

  sha256_init (&hc->ctx0);

  sha256_update_global (&hc->ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha256_ctx_t ctx = hc->ctx0;

  sha256_update_swap (&ctx, w, len);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  u32 wt0[4];
  u32 wt1[4];
  u32 wt2[4];
  u32 wt3[4];

  for (u32 i = 0; i < hc->salt_iter; i++)
  {
    wt0[0] = digest[0];
    wt0[1] = digest[1];
    wt0[2] = digest[2];
    wt0[3] = digest[3];
    wt1[0] = digest[4];
    wt1[1] = digest[5];
    wt1[2] = digest[6];
    wt1[3] = digest[7];
    wt2[0] = 0x80000000;
    wt2[1] = 0;
    wt2[2] = 0;
    wt2[3] = 0;
    wt3[0] = 0;
    wt3[1] = 0;
    wt3[2] = 0;
    wt3[3] = 32 * 8;

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (wt0, wt1, wt2, wt3, digest);
  }

  dgst[0] = digest[DGST_R0];
  dgst[1] = digest[DGST_R1];
  dgst[2] = digest[DGST_R2];
  dgst[3] = digest[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha256_ctx_t ctx = hc->ctx0;

  sha256_update_global_swap (&ctx, w, len);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  u32 wt0[4];
  u32 wt1[4];
  u32 wt2[4];
  u32 wt3[4];

  for (u32 i = 0; i < hc->salt_iter; i++)
  {
    wt0[0] = digest[0];
    wt0[1] = digest[1];
    wt0[2] = digest[2];
    wt0[3] = digest[3];
    wt1[0] = digest[4];
    wt1[1] = digest[5];
    wt1[2] = digest[6];
    wt1[3] = digest[7];
    wt2[0] = 0x80000000;
    wt2[1] = 0;
    wt2[2] = 0;
    wt2[3] = 0;
    wt3[0] = 0;
    wt3[1] = 0;
    wt3[2] = 0;
    wt3[3] = 32 * 8;

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (wt0, wt1, wt2, wt3, digest);
  }

  dgst[0] = digest[DGST_R0];
  dgst[1] = digest[DGST_R1];
  dgst[2] = digest[DGST_R2];
  dgst[3] = digest[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m05720_mxx
#define PCFG_KERNEL_SXX m05720_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
