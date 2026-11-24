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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define KEYLEN 44

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_te0[256];             \
  LOCAL_VK u32 s_te1[256];             \
  LOCAL_VK u32 s_te2[256];             \
  LOCAL_VK u32 s_te3[256];             \
  LOCAL_VK u32 s_te4[256];             \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_te4[i] = te4[i];                 \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_te4 = s_te4;
#endif

typedef struct pcfg_hash_ctx
{
  u32 rnd[4];
  u32 senc_pt[4];
  u32 scbk_pt[4];

  #ifdef REAL_SHM
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_te4;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->rnd[0] = salt_bufs[salt_pos].salt_buf[0];
  hc->rnd[1] = salt_bufs[salt_pos].salt_buf[1];
  hc->rnd[2] = salt_bufs[salt_pos].salt_buf[2];
  hc->rnd[3] = salt_bufs[salt_pos].salt_buf[3];

  // S-ENC is the SCBK encrypting 0x01 0x82 and the first 6 bytes of RND.A

  hc->senc_pt[0] = 0x8201 | (hc->rnd[0] << 16);
  hc->senc_pt[1] = (hc->rnd[0] >> 16) | (hc->rnd[1] << 16);
  hc->senc_pt[2] = 0;
  hc->senc_pt[3] = 0;

  // the SCBK is the MK encrypting cUID . ~cUID

  hc->scbk_pt[0] = salt_bufs[salt_pos].salt_buf[4];
  hc->scbk_pt[1] = salt_bufs[salt_pos].salt_buf[5];
  hc->scbk_pt[2] = ~hc->scbk_pt[0];
  hc->scbk_pt[3] = ~hc->scbk_pt[1];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_osdp (PRIVATE_AS const u32 *ukey, PRIVATE_AS u32 *dgst, PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_te4 = hc->s_te4;
  #else
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;
  #endif

  u32 ks[KEYLEN];

  aes128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 scbk[4];

  aes128_encrypt (ks, hc->scbk_pt, scbk, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes128_set_encrypt_key (ks, scbk, s_te0, s_te1, s_te2, s_te3);

  u32 senc[4];

  aes128_encrypt (ks, hc->senc_pt, senc, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes128_set_encrypt_key (ks, senc, s_te0, s_te1, s_te2, s_te3);

  u32 ct[4];

  aes128_encrypt (ks, hc->rnd, ct, s_te0, s_te1, s_te2, s_te3, s_te4);

  dgst[0] = ct[0];
  dgst[1] = ct[1];
  dgst[2] = ct[2];
  dgst[3] = ct[3];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 16) return false;

  return pcfg_osdp (w, dgst, hc);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 16) return false;

  u32 ukey[4];

  ukey[0] = w[0];
  ukey[1] = w[1];
  ukey[2] = w[2];
  ukey[3] = w[3];

  return pcfg_osdp (ukey, dgst, hc);
}

#define PCFG_KERNEL_MXX m47001_mxx
#define PCFG_KERNEL_SXX m47001_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
