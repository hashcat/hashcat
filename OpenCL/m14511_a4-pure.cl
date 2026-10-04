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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (cryptoapi_t)

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
  u32 aes_key_len;
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_te4;
  #endif
  GLOBAL_AS const salt_t *salt_bufs;
  u32 salt_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const cryptoapi_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt_bufs = salt_bufs;
  hc->salt_pos  = salt_pos;

  hc->aes_key_len = esalt_bufs[digest_pos].key_size;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
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

  u32 wx[64] = { 0 };

  u32 w_len = len;

  for (u32 i = 0; i < PCFG_DEV_WORDS; i++) wx[i] = w[i];

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_swap (&ctx0, w, len);

  sha1_final (&ctx0);

  const u32 k0 = ctx0.h[0];
  const u32 k1 = ctx0.h[1];
  const u32 k2 = ctx0.h[2];
  const u32 k3 = ctx0.h[3];

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->aes_key_len > 128)
  {
    k4 = ctx0.h[4];

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    ctx.w0[0] = 0x41000000;

    ctx.len = 1;

    sha1_update_swap (&ctx, wx, w_len);

    sha1_final (&ctx);

    k5 = ctx.h[0];

    if (hc->aes_key_len > 192)
    {
      k6 = ctx.h[1];
      k7 = ctx.h[2];
    }
  }

  u32 ukey[8] = { 0 };

  ukey[0] = k0;
  ukey[1] = k1;
  ukey[2] = k2;
  ukey[3] = k3;

  if (hc->aes_key_len > 128)
  {
    ukey[4] = k4;
    ukey[5] = k5;

    if (hc->aes_key_len > 192)
    {
      ukey[6] = k6;
      ukey[7] = k7;
    }
  }

  const u32 iv[4] = {
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[0]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[1]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[2]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[3])
  };

  u32 CT[4] = { 0 };

  u32 ks[60] = { 0 };

  if (hc->aes_key_len == 128)
  {
    AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else if (hc->aes_key_len == 192)
  {
    AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else
  {
    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  dgst[0] = CT[0];
  dgst[1] = CT[1];
  dgst[2] = CT[2];
  dgst[3] = CT[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
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

  u32 wx[64] = { 0 };

  u32 w_len = len;

  for (u32 i = 0; i < 64; i++) wx[i] = w[i];

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, w, len);

  sha1_final (&ctx0);

  const u32 k0 = ctx0.h[0];
  const u32 k1 = ctx0.h[1];
  const u32 k2 = ctx0.h[2];
  const u32 k3 = ctx0.h[3];

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->aes_key_len > 128)
  {
    k4 = ctx0.h[4];

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    ctx.w0[0] = 0x41000000;

    ctx.len = 1;

    sha1_update_swap (&ctx, wx, w_len);

    sha1_final (&ctx);

    k5 = ctx.h[0];

    if (hc->aes_key_len > 192)
    {
      k6 = ctx.h[1];
      k7 = ctx.h[2];
    }
  }

  u32 ukey[8] = { 0 };

  ukey[0] = k0;
  ukey[1] = k1;
  ukey[2] = k2;
  ukey[3] = k3;

  if (hc->aes_key_len > 128)
  {
    ukey[4] = k4;
    ukey[5] = k5;

    if (hc->aes_key_len > 192)
    {
      ukey[6] = k6;
      ukey[7] = k7;
    }
  }

  const u32 iv[4] = {
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[0]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[1]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[2]),
    hc_swap32_S(hc->salt_bufs[hc->salt_pos].salt_buf[3])
  };

  u32 CT[4] = { 0 };

  u32 ks[60] = { 0 };

  if (hc->aes_key_len == 128)
  {
    AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else if (hc->aes_key_len == 192)
  {
    AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else
  {
    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  dgst[0] = CT[0];
  dgst[1] = CT[1];
  dgst[2] = CT[2];
  dgst[3] = CT[3];

  return true;
}

#define PCFG_KERNEL_MXX m14511_mxx
#define PCFG_KERNEL_SXX m14511_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
