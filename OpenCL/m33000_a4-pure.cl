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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

typedef struct md5_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} md5_double_salt_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (md5_double_salt_t)

typedef struct pcfg_hash_ctx
{
  int salt2_len;
  u32 s2[64];
  md5_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const md5_double_salt_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt2_len = esalt_bufs[digest_pos].salt2_len;

  for (u32 i = 0; i < 64; i++) hc->s2[i] = 0;

  for (int i = 0, idx = 0; i < hc->salt2_len; i += 4, idx += 1)
  {
    hc->s2[idx] = esalt_bufs[digest_pos].salt2_buf[idx];
  }

  md5_init (&hc->ctx0);

  md5_update_global (&hc->ctx0, esalt_bufs[digest_pos].salt1_buf, esalt_bufs[digest_pos].salt1_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx = hc->ctx0;

  md5_update (&ctx, w, len);

  md5_update (&ctx, hc->s2, hc->salt2_len);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx = hc->ctx0;

  md5_update_global (&ctx, w, len);

  md5_update (&ctx, hc->s2, hc->salt2_len);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m33000_mxx
#define PCFG_KERNEL_SXX m33000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
