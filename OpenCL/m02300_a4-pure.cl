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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_openssl_enc.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_td0[256];             \
  LOCAL_VK u32 s_td1[256];             \
  LOCAL_VK u32 s_td2[256];             \
  LOCAL_VK u32 s_td3[256];             \
  LOCAL_VK u32 s_td4[256];             \
  LOCAL_VK u32 s_te0[256];             \
  LOCAL_VK u32 s_te1[256];             \
  LOCAL_VK u32 s_te2[256];             \
  LOCAL_VK u32 s_te3[256];             \
  LOCAL_VK u32 s_te4[256];             \
  LOCAL_VK u32 s_inv0[256];            \
  LOCAL_VK u32 s_inv1[256];            \
  LOCAL_VK u32 s_inv2[256];            \
  LOCAL_VK u32 s_inv3[256];            \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_td0[i] = td0[i];                 \
    s_td1[i] = td1[i];                 \
    s_td2[i] = td2[i];                 \
    s_td3[i] = td3[i];                 \
    s_td4[i] = td4[i];                 \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_te4[i] = te4[i];                 \
    s_inv0[i] = td_inv0[i];            \
    s_inv1[i] = td_inv1[i];            \
    s_inv2[i] = td_inv2[i];            \
    s_inv3[i] = td_inv3[i];            \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_td0 = s_td0;            \
  (hc)->s_td1 = s_td1;            \
  (hc)->s_td2 = s_td2;            \
  (hc)->s_td3 = s_td3;            \
  (hc)->s_td4 = s_td4;            \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_te4 = s_te4;            \
  (hc)->s_inv0 = s_inv0;          \
  (hc)->s_inv1 = s_inv1;          \
  (hc)->s_inv2 = s_inv2;          \
  (hc)->s_inv3 = s_inv3;
#endif

#define PCFG_KERN_ATTR KERN_ATTR_PCFG_ESALT (openssl_enc_t)

typedef struct pcfg_hash_ctx
{
  GLOBAL_AS const openssl_enc_t *esalt;

  u32 search[4];

  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0;
  LOCAL_AS u32 *s_td1;
  LOCAL_AS u32 *s_td2;
  LOCAL_AS u32 *s_td3;
  LOCAL_AS u32 *s_td4;
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_te4;
  LOCAL_AS u32 *s_inv0;
  LOCAL_AS u32 *s_inv1;
  LOCAL_AS u32 *s_inv2;
  LOCAL_AS u32 *s_inv3;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const openssl_enc_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->esalt = &esalt_bufs[digest_pos];

  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0 = hc->s_td0;
  LOCAL_AS u32 *s_td1 = hc->s_td1;
  LOCAL_AS u32 *s_td2 = hc->s_td2;
  LOCAL_AS u32 *s_td3 = hc->s_td3;
  LOCAL_AS u32 *s_td4 = hc->s_td4;
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_te4 = hc->s_te4;
  LOCAL_AS u32 *s_inv0 = hc->s_inv0;
  LOCAL_AS u32 *s_inv1 = hc->s_inv1;
  LOCAL_AS u32 *s_inv2 = hc->s_inv2;
  LOCAL_AS u32 *s_inv3 = hc->s_inv3;
  #else
  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;
  CONSTANT_AS u32a *s_inv0 = td_inv0;
  CONSTANT_AS u32a *s_inv1 = td_inv1;
  CONSTANT_AS u32a *s_inv2 = td_inv2;
  CONSTANT_AS u32a *s_inv3 = td_inv3;
  #endif

  const bool ok = openssl_enc_check (w, len, hc->esalt, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, s_inv0, s_inv1, s_inv2, s_inv3);

  if (ok == false) return false;

  // the check above is the whole verification, so the digest handed back is the one searched for

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m02300_mxx
#define PCFG_KERNEL_SXX m02300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
