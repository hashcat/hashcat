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
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

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

#define PCFG_KERN_ATTR KERN_ATTR_PCFG_ESALT (pdf_t)

#define PCFG_HASH_SHARED_DECL \
  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->S = S;                    \
  (hc)->lid = lid;

typedef struct pcfg_hash_ctx
{
  u32 o_buf[8];
  u32 id_buf[4];

  u32 P;

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const pdf_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  for (u32 i = 0; i < 8; i++) hc->o_buf[i] = esalt_bufs[digest_pos].o_buf[i];

  for (u32 i = 0; i < 4; i++) hc->id_buf[i] = esalt_bufs[digest_pos].id_buf[i];

  hc->P = (u32) esalt_bufs[digest_pos].P;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_pdf_rev2 (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  const u32 padding[8] =
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

  u32 p[8];

  for (u32 i = 0; i < 8; i++) p[i] = w[i];

  for (u32 i = len; i < 32; i++) pcfg_put_byte (p, i, pcfg_get_byte (padding, i - len));

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = p[0];
  w0[1] = p[1];
  w0[2] = p[2];
  w0[3] = p[3];
  w1[0] = p[4];
  w1[1] = p[5];
  w1[2] = p[6];
  w1[3] = p[7];
  w2[0] = hc->o_buf[0];
  w2[1] = hc->o_buf[1];
  w2[2] = hc->o_buf[2];
  w2[3] = hc->o_buf[3];
  w3[0] = hc->o_buf[4];
  w3[1] = hc->o_buf[5];
  w3[2] = hc->o_buf[6];
  w3[3] = hc->o_buf[7];

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, digest);

  w0[0] = hc->P;
  w0[1] = hc->id_buf[0];
  w0[2] = hc->id_buf[1];
  w0[3] = hc->id_buf[2];
  w1[0] = hc->id_buf[3];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 84 * 8;
  w3[3] = 0;

  md5_transform (w0, w1, w2, w3, digest);

  // now the RC4 part, forty bits of the digest against the pad string

  digest[1] = digest[1] & 0xff;
  digest[2] = 0;
  digest[3] = 0;

  rc4_init_40 (hc->S, digest, hc->lid);

  u32 out[4];

  rc4_next_16 (hc->S, 0, 0, padding, out, hc->lid);

  dgst[0] = out[0];
  dgst[1] = out[1];
  dgst[2] = out[2];
  dgst[3] = out[3];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  return pcfg_pdf_rev2 (hc, w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = w[i];

  return pcfg_pdf_rev2 (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m10400_mxx
#define PCFG_KERNEL_SXX m10400_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
