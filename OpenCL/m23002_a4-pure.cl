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

typedef struct securezip
{
  u32 data[36];
  u32 file[16];
  u32 iv[4];
  u32 iv_len;

} securezip_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (securezip_t)

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
  (hc)->s_inv0 = s_inv0;          \
  (hc)->s_inv1 = s_inv1;          \
  (hc)->s_inv2 = s_inv2;          \
  (hc)->s_inv3 = s_inv3;
#endif

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  u32 iv[4];
  u32 data[4];

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
  LOCAL_AS u32 *s_inv0;
  LOCAL_AS u32 *s_inv1;
  LOCAL_AS u32 *s_inv2;
  LOCAL_AS u32 *s_inv3;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const securezip_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->iv[0] = esalt_bufs[digest_pos].data[28];
  hc->iv[1] = esalt_bufs[digest_pos].data[29];
  hc->iv[2] = esalt_bufs[digest_pos].data[30];
  hc->iv[3] = esalt_bufs[digest_pos].data[31];

  hc->data[0] = esalt_bufs[digest_pos].data[32];
  hc->data[1] = esalt_bufs[digest_pos].data[33];
  hc->data[2] = esalt_bufs[digest_pos].data[34];
  hc->data[3] = esalt_bufs[digest_pos].data[35];
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
  CONSTANT_AS u32a *s_inv0 = td_inv0;
  CONSTANT_AS u32a *s_inv1 = td_inv1;
  CONSTANT_AS u32a *s_inv2 = td_inv2;
  CONSTANT_AS u32a *s_inv3 = td_inv3;
  #endif

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_swap (&ctx, w, len);

  sha1_final (&ctx);

  u32 t0[4];

  t0[0] = 0x36363636 ^ ctx.h[0];
  t0[1] = 0x36363636 ^ ctx.h[1];
  t0[2] = 0x36363636 ^ ctx.h[2];
  t0[3] = 0x36363636 ^ ctx.h[3];

  u32 t1[4];

  t1[0] = 0x36363636 ^ ctx.h[4];
  t1[1] = 0x36363636;
  t1[2] = 0x36363636;
  t1[3] = 0x36363636;

  u32 t2[4];

  t2[0] = 0x36363636;
  t2[1] = 0x36363636;
  t2[2] = 0x36363636;
  t2[3] = 0x36363636;

  u32 t3[4];

  t3[0] = 0x36363636;
  t3[1] = 0x36363636;
  t3[2] = 0x36363636;
  t3[3] = 0x36363636;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (t0, t1, t2, t3, digest);

  t0[0] = 0x80000000;
  t0[1] = 0;
  t0[2] = 0;
  t0[3] = 0;

  t1[0] = 0;
  t1[1] = 0;
  t1[2] = 0;
  t1[3] = 0;

  t2[0] = 0;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;

  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = 64 * 8;

  sha1_transform (t0, t1, t2, t3, digest);

  u32 key[6]; // 5 + 1 = 6 (20 bytes + 4 bytes = 24 bytes for the key)

  key[0] = digest[0];
  key[1] = digest[1];
  key[2] = digest[2];
  key[3] = digest[3];
  key[4] = digest[4];

  t0[0] = 0x5c5c5c5c ^ ctx.h[0];
  t0[1] = 0x5c5c5c5c ^ ctx.h[1];
  t0[2] = 0x5c5c5c5c ^ ctx.h[2];
  t0[3] = 0x5c5c5c5c ^ ctx.h[3];

  t1[0] = 0x5c5c5c5c ^ ctx.h[4];
  t1[1] = 0x5c5c5c5c;
  t1[2] = 0x5c5c5c5c;
  t1[3] = 0x5c5c5c5c;

  t2[0] = 0x5c5c5c5c;
  t2[1] = 0x5c5c5c5c;
  t2[2] = 0x5c5c5c5c;
  t2[3] = 0x5c5c5c5c;

  t3[0] = 0x5c5c5c5c;
  t3[1] = 0x5c5c5c5c;
  t3[2] = 0x5c5c5c5c;
  t3[3] = 0x5c5c5c5c;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (t0, t1, t2, t3, digest);

  t0[0] = 0x80000000;
  t0[1] = 0;
  t0[2] = 0;
  t0[3] = 0;

  t1[0] = 0;
  t1[1] = 0;
  t1[2] = 0;
  t1[3] = 0;

  t2[0] = 0;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;

  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = 64 * 8;

  sha1_transform (t0, t1, t2, t3, digest);

  key[5] = digest[0];

  u32 ks[52];

  AES192_set_decrypt_key_inv (ks, key, s_te0, s_te1, s_te2, s_te3, s_inv0, s_inv1, s_inv2, s_inv3);

  u32 out[4];

  aes192_decrypt (ks, hc->data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= hc->iv[0];
  out[1] ^= hc->iv[1];
  out[2] ^= hc->iv[2];
  out[3] ^= hc->iv[3];

  if (out[0] != 0x10101010) return false;
  if (out[1] != 0x10101010) return false;
  if (out[2] != 0x10101010) return false;
  if (out[3] != 0x10101010) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64];

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m23002_mxx
#define PCFG_KERNEL_SXX m23002_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
