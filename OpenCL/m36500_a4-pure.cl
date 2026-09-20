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

  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t c0;

  md4_init (&c0);

  md4_update_utf16le (&c0, w, len);

  md4_final (&c0);

  u32 t[16] = { 0 };
  t[0] = (c0.h[0] & 0x000000ff) <<  0 | (c0.h[0] & 0x0000ff00) <<  8;
  t[1] = (c0.h[0] & 0x00ff0000) >> 16 | (c0.h[0] & 0xff000000) >>  8;
  t[2] = (c0.h[1] & 0x000000ff) <<  0 | (c0.h[1] & 0x0000ff00) <<  8;
  t[3] = (c0.h[1] & 0x00ff0000) >> 16 | (c0.h[1] & 0xff000000) >>  8;
  t[4] = (c0.h[2] & 0x000000ff) <<  0 | (c0.h[2] & 0x0000ff00) <<  8;
  t[5] = (c0.h[2] & 0x00ff0000) >> 16 | (c0.h[2] & 0xff000000) >>  8;
  t[6] = (c0.h[3] & 0x000000ff) <<  0 | (c0.h[3] & 0x0000ff00) <<  8;
  t[7] = (c0.h[3] & 0x00ff0000) >> 16 | (c0.h[3] & 0xff000000) >>  8;

  md4_ctx_t c1;

  md4_init   (&c1);
  md4_update (&c1, t, 32);
  md4_final  (&c1);

  dgst[0] = c1.h[DGST_R0];
  dgst[1] = c1.h[DGST_R1];
  dgst[2] = c1.h[DGST_R2];
  dgst[3] = c1.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t c0;

  md4_init (&c0);

  md4_update_global_utf16le (&c0, w, len);

  md4_final (&c0);

  u32 t[16] = { 0 };
  t[0] = (c0.h[0] & 0x000000ff) <<  0 | (c0.h[0] & 0x0000ff00) <<  8;
  t[1] = (c0.h[0] & 0x00ff0000) >> 16 | (c0.h[0] & 0xff000000) >>  8;
  t[2] = (c0.h[1] & 0x000000ff) <<  0 | (c0.h[1] & 0x0000ff00) <<  8;
  t[3] = (c0.h[1] & 0x00ff0000) >> 16 | (c0.h[1] & 0xff000000) >>  8;
  t[4] = (c0.h[2] & 0x000000ff) <<  0 | (c0.h[2] & 0x0000ff00) <<  8;
  t[5] = (c0.h[2] & 0x00ff0000) >> 16 | (c0.h[2] & 0xff000000) >>  8;
  t[6] = (c0.h[3] & 0x000000ff) <<  0 | (c0.h[3] & 0x0000ff00) <<  8;
  t[7] = (c0.h[3] & 0x00ff0000) >> 16 | (c0.h[3] & 0xff000000) >>  8;

  md4_ctx_t c1;

  md4_init   (&c1);
  md4_update (&c1, t, 32);
  md4_final  (&c1);

  dgst[0] = c1.h[DGST_R0];
  dgst[1] = c1.h[DGST_R1];
  dgst[2] = c1.h[DGST_R2];
  dgst[3] = c1.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m36500_mxx
#define PCFG_KERNEL_SXX m36500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
