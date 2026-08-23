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
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
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
  LOCAL_VK u64 s_MT0[256];             \
  LOCAL_VK u64 s_MT1[256];             \
  LOCAL_VK u64 s_MT2[256];             \
  LOCAL_VK u64 s_MT3[256];             \
  LOCAL_VK u64 s_MT4[256];             \
  LOCAL_VK u64 s_MT5[256];             \
  LOCAL_VK u64 s_MT6[256];             \
  LOCAL_VK u64 s_MT7[256];             \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_te4[i] = te4[i];                 \
    s_MT0[i] = MT0[i];                 \
    s_MT1[i] = MT1[i];                 \
    s_MT2[i] = MT2[i];                 \
    s_MT3[i] = MT3[i];                 \
    s_MT4[i] = MT4[i];                 \
    s_MT5[i] = MT5[i];                 \
    s_MT6[i] = MT6[i];                 \
    s_MT7[i] = MT7[i];                 \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_te4 = s_te4;            \
  (hc)->s_MT0 = s_MT0;            \
  (hc)->s_MT1 = s_MT1;            \
  (hc)->s_MT2 = s_MT2;            \
  (hc)->s_MT3 = s_MT3;            \
  (hc)->s_MT4 = s_MT4;            \
  (hc)->s_MT5 = s_MT5;            \
  (hc)->s_MT6 = s_MT6;            \
  (hc)->s_MT7 = s_MT7;
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
  LOCAL_AS u64 *s_MT0;
  LOCAL_AS u64 *s_MT1;
  LOCAL_AS u64 *s_MT2;
  LOCAL_AS u64 *s_MT3;
  LOCAL_AS u64 *s_MT4;
  LOCAL_AS u64 *s_MT5;
  LOCAL_AS u64 *s_MT6;
  LOCAL_AS u64 *s_MT7;
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
  LOCAL_AS u64 *s_MT0 = hc->s_MT0;
  LOCAL_AS u64 *s_MT1 = hc->s_MT1;
  LOCAL_AS u64 *s_MT2 = hc->s_MT2;
  LOCAL_AS u64 *s_MT3 = hc->s_MT3;
  LOCAL_AS u64 *s_MT4 = hc->s_MT4;
  LOCAL_AS u64 *s_MT5 = hc->s_MT5;
  LOCAL_AS u64 *s_MT6 = hc->s_MT6;
  LOCAL_AS u64 *s_MT7 = hc->s_MT7;
  #else
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;
  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;
  #endif

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_swap (&ctx0, w, len);

  whirlpool_final (&ctx0);

  const u32 k0 = ctx0.h[0];
  const u32 k1 = ctx0.h[1];
  const u32 k2 = ctx0.h[2];
  const u32 k3 = ctx0.h[3];

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->aes_key_len > 128)
  {
    k4 = ctx0.h[4];
    k5 = ctx0.h[5];

    if (hc->aes_key_len > 192)
    {
      k6 = ctx0.h[6];
      k7 = ctx0.h[7];
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
  LOCAL_AS u64 *s_MT0 = hc->s_MT0;
  LOCAL_AS u64 *s_MT1 = hc->s_MT1;
  LOCAL_AS u64 *s_MT2 = hc->s_MT2;
  LOCAL_AS u64 *s_MT3 = hc->s_MT3;
  LOCAL_AS u64 *s_MT4 = hc->s_MT4;
  LOCAL_AS u64 *s_MT5 = hc->s_MT5;
  LOCAL_AS u64 *s_MT6 = hc->s_MT6;
  LOCAL_AS u64 *s_MT7 = hc->s_MT7;
  #else
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;
  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;
  #endif

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_global_swap (&ctx0, w, len);

  whirlpool_final (&ctx0);

  const u32 k0 = ctx0.h[0];
  const u32 k1 = ctx0.h[1];
  const u32 k2 = ctx0.h[2];
  const u32 k3 = ctx0.h[3];

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->aes_key_len > 128)
  {
    k4 = ctx0.h[4];
    k5 = ctx0.h[5];

    if (hc->aes_key_len > 192)
    {
      k6 = ctx0.h[6];
      k7 = ctx0.h[7];
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

#define PCFG_KERNEL_MXX m14551_mxx
#define PCFG_KERNEL_SXX m14551_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
