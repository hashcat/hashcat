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
  u32 iv[4];
  u32 ct[4];
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

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_bufs = salt_bufs;
  hc->salt_pos  = salt_pos;

  hc->iv[0] = salt_bufs[salt_pos].salt_buf[0];
  hc->iv[1] = salt_bufs[salt_pos].salt_buf[1];
  hc->iv[2] = salt_bufs[salt_pos].salt_buf[2];
  hc->iv[3] = salt_bufs[salt_pos].salt_buf[3];

  hc->ct[0] = salt_bufs[salt_pos].salt_buf[4];
  hc->ct[1] = salt_bufs[salt_pos].salt_buf[5];
  hc->ct[2] = salt_bufs[salt_pos].salt_buf[6];
  hc->ct[3] = salt_bufs[salt_pos].salt_buf[7];
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

  u32 ukey[8];

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_swap (&sha1_hmac_ctx, w, len);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc->iv[0];
  w0[1] = hc->iv[1];
  w0[2] = hc->iv[2];
  w0[3] = hc->iv[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 16);

  sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx2);

  ukey[0] = sha1_hmac_ctx2.opad.h[0];
  ukey[1] = sha1_hmac_ctx2.opad.h[1];
  ukey[2] = sha1_hmac_ctx2.opad.h[2];
  ukey[3] = sha1_hmac_ctx2.opad.h[3];
  ukey[4] = sha1_hmac_ctx2.opad.h[4];

  sha1_hmac_ctx_t sha1_hmac_ctx3 = sha1_hmac_ctx;

  w0[0] = 2;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx3, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx3);

  ukey[5] = sha1_hmac_ctx3.opad.h[0];
  ukey[6] = sha1_hmac_ctx3.opad.h[1];
  ukey[7] = sha1_hmac_ctx3.opad.h[2];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 out[4];

  AES256_encrypt (ks, hc->iv, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 pt[4];

  pt[0] = hc->ct[0] ^ out[0];
  pt[1] = hc->ct[1] ^ out[1];
  pt[2] = hc->ct[2] ^ out[2];
  pt[3] = hc->ct[3] ^ out[3];

  if (is_valid_printable_32_incl_common_control (pt[0]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[1]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[2]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[3]) == 0) return false;

  int i;

  for (i = 8; i < 16; i += 4)
  {
    AES256_encrypt (ks, out, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    pt[0] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 0] ^ out[0];
    pt[1] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 1] ^ out[1];
    pt[2] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 2] ^ out[2];
    pt[3] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 3] ^ out[3];

    if (is_valid_printable_32_incl_common_control (pt[0]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[1]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[2]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[3]) == 0) break;
  }

  if (i < 16) return false;

  dgst[0] = hc->ct[0];
  dgst[1] = hc->ct[1];
  dgst[2] = hc->ct[2];
  dgst[3] = hc->ct[3];

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

  u32 ukey[8];

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, w, len);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc->iv[0];
  w0[1] = hc->iv[1];
  w0[2] = hc->iv[2];
  w0[3] = hc->iv[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 16);

  sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx2);

  ukey[0] = sha1_hmac_ctx2.opad.h[0];
  ukey[1] = sha1_hmac_ctx2.opad.h[1];
  ukey[2] = sha1_hmac_ctx2.opad.h[2];
  ukey[3] = sha1_hmac_ctx2.opad.h[3];
  ukey[4] = sha1_hmac_ctx2.opad.h[4];

  sha1_hmac_ctx_t sha1_hmac_ctx3 = sha1_hmac_ctx;

  w0[0] = 2;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx3, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx3);

  ukey[5] = sha1_hmac_ctx3.opad.h[0];
  ukey[6] = sha1_hmac_ctx3.opad.h[1];
  ukey[7] = sha1_hmac_ctx3.opad.h[2];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 out[4];

  AES256_encrypt (ks, hc->iv, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 pt[4];

  pt[0] = hc->ct[0] ^ out[0];
  pt[1] = hc->ct[1] ^ out[1];
  pt[2] = hc->ct[2] ^ out[2];
  pt[3] = hc->ct[3] ^ out[3];

  if (is_valid_printable_32_incl_common_control (pt[0]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[1]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[2]) == 0) return false;
  if (is_valid_printable_32_incl_common_control (pt[3]) == 0) return false;

  int i;

  for (i = 8; i < 16; i += 4)
  {
    AES256_encrypt (ks, out, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    pt[0] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 0] ^ out[0];
    pt[1] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 1] ^ out[1];
    pt[2] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 2] ^ out[2];
    pt[3] = hc->salt_bufs[hc->salt_pos].salt_buf[i + 3] ^ out[3];

    if (is_valid_printable_32_incl_common_control (pt[0]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[1]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[2]) == 0) break;
    if (is_valid_printable_32_incl_common_control (pt[3]) == 0) break;
  }

  if (i < 16) return false;

  dgst[0] = hc->ct[0];
  dgst[1] = hc->ct[1];
  dgst[2] = hc->ct[2];
  dgst[3] = hc->ct[3];

  return true;
}

#define PCFG_KERNEL_MXX m34700_mxx
#define PCFG_KERNEL_SXX m34700_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
