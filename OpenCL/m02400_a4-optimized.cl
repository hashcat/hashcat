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

DECLSPEC void pcfg_md5_pix (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = w[0];
  w0[1] = w[1];
  w0[2] = w[2];
  w0[3] = w[3];

  if (len <= 16)
  {
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 16 * 8;
    w3[3] = 0;
  }
  else if (len <= 32)
  {
    w1[0] = w[4];
    w1[1] = w[5];
    w1[2] = w[6];
    w1[3] = w[7];
    w2[0] = 0x80;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 32 * 8;
    w3[3] = 0;
  }
  else
  {
    w1[0] = w[4];
    w1[1] = w[5];
    w1[2] = w[6];
    w1[3] = w[7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = 0x80;
    w3[1] = 0;
    w3[2] = 48 * 8;
    w3[3] = 0;
  }

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

  // in the order the rules kernel compares in, which is COMPARE_M_SIMD (a, d, c, b)

  dgst[0] = h[0] & 0x00ffffff;
  dgst[1] = h[3] & 0x00ffffff;
  dgst[2] = h[2] & 0x00ffffff;
  dgst[3] = h[1] & 0x00ffffff;
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 48) return false;

  pcfg_md5_pix (w, len, dgst);

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 48) return false;

  u32 t[12];

  for (u32 i = 0; i < 12; i++) t[i] = 0;

  for (u32 i = 0; i < len; i++) pcfg_put_byte (t, i, pcfg_base_byte (w, i));

  pcfg_md5_pix (t, len, dgst);

  return true;
}

#define PCFG_KERNEL_MXX m02400_mxx
#define PCFG_KERNEL_SXX m02400_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
