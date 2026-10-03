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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

#define PCFG_HASH_BLKWORDS  32

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (cryptoapi_t)

typedef struct pcfg_hash_ctx
{
  u32 serpent_key_len;
  GLOBAL_AS const salt_t *salt_bufs;
  u32 salt_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const cryptoapi_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt_bufs = salt_bufs;
  hc->salt_pos  = salt_pos;

  hc->serpent_key_len = esalt_bufs[digest_pos].key_size;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  const u32 k0 = h32_from_64_S (ctx0.h[0]);
  const u32 k1 = l32_from_64_S (ctx0.h[0]);
  const u32 k2 = h32_from_64_S (ctx0.h[1]);
  const u32 k3 = l32_from_64_S (ctx0.h[1]);

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->serpent_key_len > 128)
  {
    k4 = h32_from_64_S (ctx0.h[2]);
    k5 = l32_from_64_S (ctx0.h[2]);

    if (hc->serpent_key_len > 192)
    {
      k6 = h32_from_64_S (ctx0.h[3]);
      k7 = l32_from_64_S (ctx0.h[3]);
    }
  }

  u32 ukey[8] = { 0 };

  ukey[0] = hc_swap32_S (k0);
  ukey[1] = hc_swap32_S (k1);
  ukey[2] = hc_swap32_S (k2);
  ukey[3] = hc_swap32_S (k3);

  if (hc->serpent_key_len > 128)
  {
    ukey[4] = hc_swap32_S (k4);
    ukey[5] = hc_swap32_S (k5);

    if (hc->serpent_key_len > 192)
    {
      ukey[6] = hc_swap32_S (k6);
      ukey[7] = hc_swap32_S (k7);
    }
  }

  const u32 iv[4] = {
    hc->salt_bufs[hc->salt_pos].salt_buf[0],
    hc->salt_bufs[hc->salt_pos].salt_buf[1],
    hc->salt_bufs[hc->salt_pos].salt_buf[2],
    hc->salt_bufs[hc->salt_pos].salt_buf[3]
  };

  u32 CT[4] = { 0 };

  u32 ks[140] = { 0 };

  if (hc->serpent_key_len == 128)
  {
    serpent128_set_key (ks, ukey);

    serpent128_encrypt (ks, iv, CT);
  }
  else if (hc->serpent_key_len == 192)
  {
    serpent192_set_key (ks, ukey);

    serpent192_encrypt (ks, iv, CT);
  }
  else
  {
    serpent256_set_key (ks, ukey);

    serpent256_encrypt (ks, iv, CT);
  }

  dgst[0] = hc_swap32_S (CT[0]);
  dgst[1] = hc_swap32_S (CT[1]);
  dgst[2] = hc_swap32_S (CT[2]);
  dgst[3] = hc_swap32_S (CT[3]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  const u32 k0 = h32_from_64_S (ctx0.h[0]);
  const u32 k1 = l32_from_64_S (ctx0.h[0]);
  const u32 k2 = h32_from_64_S (ctx0.h[1]);
  const u32 k3 = l32_from_64_S (ctx0.h[1]);

  u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

  if (hc->serpent_key_len > 128)
  {
    k4 = h32_from_64_S (ctx0.h[2]);
    k5 = l32_from_64_S (ctx0.h[2]);

    if (hc->serpent_key_len > 192)
    {
      k6 = h32_from_64_S (ctx0.h[3]);
      k7 = l32_from_64_S (ctx0.h[3]);
    }
  }

  u32 ukey[8] = { 0 };

  ukey[0] = hc_swap32_S (k0);
  ukey[1] = hc_swap32_S (k1);
  ukey[2] = hc_swap32_S (k2);
  ukey[3] = hc_swap32_S (k3);

  if (hc->serpent_key_len > 128)
  {
    ukey[4] = hc_swap32_S (k4);
    ukey[5] = hc_swap32_S (k5);

    if (hc->serpent_key_len > 192)
    {
      ukey[6] = hc_swap32_S (k6);
      ukey[7] = hc_swap32_S (k7);
    }
  }

  const u32 iv[4] = {
    hc->salt_bufs[hc->salt_pos].salt_buf[0],
    hc->salt_bufs[hc->salt_pos].salt_buf[1],
    hc->salt_bufs[hc->salt_pos].salt_buf[2],
    hc->salt_bufs[hc->salt_pos].salt_buf[3]
  };

  u32 CT[4] = { 0 };

  u32 ks[140] = { 0 };

  if (hc->serpent_key_len == 128)
  {
    serpent128_set_key (ks, ukey);

    serpent128_encrypt (ks, iv, CT);
  }
  else if (hc->serpent_key_len == 192)
  {
    serpent192_set_key (ks, ukey);

    serpent192_encrypt (ks, iv, CT);
  }
  else
  {
    serpent256_set_key (ks, ukey);

    serpent256_encrypt (ks, iv, CT);
  }

  dgst[0] = hc_swap32_S (CT[0]);
  dgst[1] = hc_swap32_S (CT[1]);
  dgst[2] = hc_swap32_S (CT[2]);
  dgst[3] = hc_swap32_S (CT[3]);

  return true;
}

#define PCFG_KERNEL_MXX m14532_mxx
#define PCFG_KERNEL_SXX m14532_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
