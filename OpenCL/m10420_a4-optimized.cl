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

CONSTANT_VK u32a padding[8] =
{
  0x5e4ebf28,
  0x418a754e,
  0x564e0064,
  0x0801faff,
  0xb6002e2e,
  0x803e68d0,
  0xfea90c2f,
  0x7a695364
};

typedef struct pdf
{
  int V;
  int R;
  int P;

  int enc_md;

  u32 id_buf[8];
  u32 u_buf[32];
  u32 o_buf[32];

  int id_len;
  int o_len;
  int u_len;

  u32 rc4key[2];
  u32 rc4data[2];

  int P_minus;

} pdf_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (pdf_t)

typedef struct pcfg_hash_ctx
{
  u32 o_buf[8];
  u32 id_buf[4];
  u32 P;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const pdf_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  for (u32 i = 0; i < 8; i++) hc->o_buf[i] = esalt_bufs[digest_pos].o_buf[i];

  for (u32 i = 0; i < 4; i++) hc->id_buf[i] = esalt_bufs[digest_pos].id_buf[i];

  hc->P = esalt_bufs[digest_pos].P;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_pdf_collider (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = padding[0];
  p0[1] = padding[1];
  p0[2] = padding[2];
  p0[3] = padding[3];
  p1[0] = padding[4];
  p1[1] = padding[5];
  p1[2] = padding[6];
  p1[3] = padding[7];
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  switch_buffer_by_offset_le_S (p0, p1, p2, p3, len);

  u32 t[16];

  t[ 0] = w[0] | p0[0];
  t[ 1] = w[1] | p0[1];
  t[ 2] = w[2] | p0[2];
  t[ 3] = w[3] | p0[3];
  t[ 4] = w[4] | p1[0];
  t[ 5] = w[5] | p1[1];
  t[ 6] = w[6] | p1[2];
  t[ 7] = w[7] | p1[3];
  t[ 8] = hc->o_buf[0];
  t[ 9] = hc->o_buf[1];
  t[10] = hc->o_buf[2];
  t[11] = hc->o_buf[3];
  t[12] = hc->o_buf[4];
  t[13] = hc->o_buf[5];
  t[14] = hc->o_buf[6];
  t[15] = hc->o_buf[7];

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

  t[ 0] = hc->P;
  t[ 1] = hc->id_buf[0];
  t[ 2] = hc->id_buf[1];
  t[ 3] = hc->id_buf[2];
  t[ 4] = hc->id_buf[3];
  t[ 5] = 0x80;
  t[ 6] = 0;
  t[ 7] = 0;
  t[ 8] = 0;
  t[ 9] = 0;
  t[10] = 0;
  t[11] = 0;
  t[12] = 0;
  t[13] = 0;
  t[14] = 84 * 8;
  t[15] = 0;

  md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

  dgst[0] = digest[0];
  dgst[1] = digest[1] & 0xff;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  return pcfg_pdf_collider (hc, w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_pdf_collider (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m10420_mxx
#define PCFG_KERNEL_SXX m10420_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
