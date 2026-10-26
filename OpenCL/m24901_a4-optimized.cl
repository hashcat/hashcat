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

DECLSPEC bool pcfg_md5_besder (PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = in[i];

  pcfg_put_byte (t, len, 0x80);

  u32 w0[4] = { t[0], t[1], t[2], t[3] };
  u32 w1[4] = { t[4], t[5], t[6], t[7] };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, len * 8, 0 };

  u32 h[4];

  h[0] = MD5M_A;
  h[1] = MD5M_B;
  h[2] = MD5M_C;
  h[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, h);

  const u32 a0 = ((((h[0] >>  0) & 0xff) + ((h[0] >>  8) & 0xff)) & 0xff) % 62;
  const u32 a1 = ((((h[0] >> 16) & 0xff) + ((h[0] >> 24) & 0xff)) & 0xff) % 62;
  const u32 b0 = ((((h[1] >>  0) & 0xff) + ((h[1] >>  8) & 0xff)) & 0xff) % 62;
  const u32 b1 = ((((h[1] >> 16) & 0xff) + ((h[1] >> 24) & 0xff)) & 0xff) % 62;
  const u32 c0 = ((((h[2] >>  0) & 0xff) + ((h[2] >>  8) & 0xff)) & 0xff) % 62;
  const u32 c1 = ((((h[2] >> 16) & 0xff) + ((h[2] >> 24) & 0xff)) & 0xff) % 62;
  const u32 d0 = ((((h[3] >>  0) & 0xff) + ((h[3] >>  8) & 0xff)) & 0xff) % 62;
  const u32 d1 = ((((h[3] >> 16) & 0xff) + ((h[3] >> 24) & 0xff)) & 0xff) % 62;

  dgst[0] = (a0 <<  0) | (a1 <<  8);
  dgst[1] = (b0 <<  0) | (b1 <<  8);
  dgst[2] = (c0 <<  0) | (c1 <<  8);
  dgst[3] = (d0 <<  0) | (d1 <<  8);

  return true;
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  return pcfg_md5_besder (w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_md5_besder (t, len, dgst);
}

#define PCFG_KERNEL_MXX m24901_mxx
#define PCFG_KERNEL_SXX m24901_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
