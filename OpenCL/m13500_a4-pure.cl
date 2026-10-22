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

typedef struct pstoken
{
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (pstoken_t)

typedef struct pcfg_hash_ctx
{
  sha1_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const pstoken_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  u32 pc_offset;

  pc_offset = esalt_bufs[digest_pos].pc_offset;

  hc->ctx0.h[0] = esalt_bufs[digest_pos].pc_digest[0];
  hc->ctx0.h[1] = esalt_bufs[digest_pos].pc_digest[1];
  hc->ctx0.h[2] = esalt_bufs[digest_pos].pc_digest[2];
  hc->ctx0.h[3] = esalt_bufs[digest_pos].pc_digest[3];
  hc->ctx0.h[4] = esalt_bufs[digest_pos].pc_digest[4];

  hc->ctx0.w0[0] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  0]);
  hc->ctx0.w0[1] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  1]);
  hc->ctx0.w0[2] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  2]);
  hc->ctx0.w0[3] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  3]);

  hc->ctx0.w1[0] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  4]);
  hc->ctx0.w1[1] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  5]);
  hc->ctx0.w1[2] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  6]);
  hc->ctx0.w1[3] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  7]);

  hc->ctx0.w2[0] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  8]);
  hc->ctx0.w2[1] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset +  9]);
  hc->ctx0.w2[2] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 10]);
  hc->ctx0.w2[3] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 11]);

  hc->ctx0.w3[0] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 12]);
  hc->ctx0.w3[1] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 13]);
  hc->ctx0.w3[2] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 14]);
  hc->ctx0.w3[3] = hc_swap32_S (esalt_bufs[digest_pos].salt_buf[pc_offset + 15]);

  hc->ctx0.len = esalt_bufs[digest_pos].salt_len;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx = hc->ctx0;

  sha1_update_utf16le_swap (&ctx, w, len);

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

  sha1_update_global_utf16le_swap (&ctx, w, len);

  sha1_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m13500_mxx
#define PCFG_KERNEL_SXX m13500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
