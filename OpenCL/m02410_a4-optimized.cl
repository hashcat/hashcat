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

#define PCFG_ASA_MAX 48

typedef struct pcfg_hash_ctx
{
  u32 salt_buf0;
  u32 salt_len;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_buf0 = salt_bufs[salt_pos].salt_buf[0];
  hc->salt_len  = salt_bufs[salt_pos].salt_len;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC void pcfg_md5_asa (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst, PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  const u32 salt_len = hc->salt_len;

  u32 b[16];

  for (u32 i = 0; i < 16; i++) b[i] = 0;

  for (u32 i = 0, idx = 0; i < len; i += 4, idx += 1) b[idx] = w[idx];

  for (u32 i = 0; i < salt_len; i++) pcfg_put_byte (b, len + i, (hc->salt_buf0 >> (i * 8)) & 0xff);

  const u32 out_salt_len = len + salt_len;

  const u32 pad_len = (out_salt_len <= 16) ? 16 : ((out_salt_len <= 32) ? 32 : 48);

  b[pad_len / 4] = 0x80;
  b[14]          = pad_len * 8;

  u32 w0[4] = { b[ 0], b[ 1], b[ 2], b[ 3] };
  u32 w1[4] = { b[ 4], b[ 5], b[ 6], b[ 7] };
  u32 w2[4] = { b[ 8], b[ 9], b[10], b[11] };
  u32 w3[4] = { b[12], b[13], b[14], b[15] };

  u32 h[4];

  h[0] = MD5M_A;
  h[1] = MD5M_B;
  h[2] = MD5M_C;
  h[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, h);

  h[0] -= MD5M_A;
  h[1] -= MD5M_B;
  h[2] -= MD5M_C;
  h[3] -= MD5M_D;

  dgst[0] = h[0] & 0x00ffffff;
  dgst[1] = h[3] & 0x00ffffff;
  dgst[2] = h[2] & 0x00ffffff;
  dgst[3] = h[1] & 0x00ffffff;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if ((len + hc->salt_len) > PCFG_ASA_MAX) return false;

  pcfg_md5_asa (w, len, dgst, hc);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if ((len + hc->salt_len) > PCFG_ASA_MAX) return false;

  u32 t[12];

  for (u32 i = 0; i < 12; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  pcfg_md5_asa (t, len, dgst, hc);

  return true;
}

#define PCFG_KERNEL_MXX m02410_mxx
#define PCFG_KERNEL_SXX m02410_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
