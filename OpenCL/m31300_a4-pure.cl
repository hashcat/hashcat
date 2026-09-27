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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_buf[12];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u32 salt_len;

  salt_len = 48;

  hc->salt_buf[ 0] = salt_bufs[salt_pos].salt_buf[ 0];
  hc->salt_buf[ 1] = salt_bufs[salt_pos].salt_buf[ 1];
  hc->salt_buf[ 2] = salt_bufs[salt_pos].salt_buf[ 2];
  hc->salt_buf[ 3] = salt_bufs[salt_pos].salt_buf[ 3];
  hc->salt_buf[ 4] = salt_bufs[salt_pos].salt_buf[ 4];
  hc->salt_buf[ 5] = salt_bufs[salt_pos].salt_buf[ 5];
  hc->salt_buf[ 6] = salt_bufs[salt_pos].salt_buf[ 6];
  hc->salt_buf[ 7] = salt_bufs[salt_pos].salt_buf[ 7];
  hc->salt_buf[ 8] = salt_bufs[salt_pos].salt_buf[ 8];
  hc->salt_buf[ 9] = salt_bufs[salt_pos].salt_buf[ 9];
  hc->salt_buf[10] = salt_bufs[salt_pos].salt_buf[10];
  hc->salt_buf[11] = salt_bufs[salt_pos].salt_buf[11];
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx0.h[0];
  w0[1] = ctx0.h[1];
  w0[2] = ctx0.h[2];
  w0[3] = ctx0.h[3];
  w1[0] = hc->salt_buf[ 0];
  w1[1] = hc->salt_buf[ 1];
  w1[2] = hc->salt_buf[ 2];
  w1[3] = hc->salt_buf[ 3];
  w2[0] = hc->salt_buf[ 4];
  w2[1] = hc->salt_buf[ 5];
  w2[2] = hc->salt_buf[ 6];
  w2[3] = hc->salt_buf[ 7];
  w3[0] = hc->salt_buf[ 8];
  w3[1] = hc->salt_buf[ 9];
  w3[2] = hc->salt_buf[10];
  w3[3] = hc->salt_buf[11];

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_transform (w0, w1, w2, w3, ctx.h);

  ctx.len = 64;

  md5_final (&ctx);

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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx0.h[0];
  w0[1] = ctx0.h[1];
  w0[2] = ctx0.h[2];
  w0[3] = ctx0.h[3];
  w1[0] = hc->salt_buf[ 0];
  w1[1] = hc->salt_buf[ 1];
  w1[2] = hc->salt_buf[ 2];
  w1[3] = hc->salt_buf[ 3];
  w2[0] = hc->salt_buf[ 4];
  w2[1] = hc->salt_buf[ 5];
  w2[2] = hc->salt_buf[ 6];
  w2[3] = hc->salt_buf[ 7];
  w3[0] = hc->salt_buf[ 8];
  w3[1] = hc->salt_buf[ 9];
  w3[2] = hc->salt_buf[10];
  w3[3] = hc->salt_buf[11];

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_transform (w0, w1, w2, w3, ctx.h);

  ctx.len = 64;

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m31300_mxx
#define PCFG_KERNEL_SXX m31300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
