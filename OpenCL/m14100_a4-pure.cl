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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_SPtrans[8][64];       \
  LOCAL_VK u32 s_skb[8][64];           \
  for (u32 i = lid; i < 64; i += lsz)  \
  {                                    \
    s_SPtrans[0][i] = c_SPtrans[0][i]; \
    s_SPtrans[1][i] = c_SPtrans[1][i]; \
    s_SPtrans[2][i] = c_SPtrans[2][i]; \
    s_SPtrans[3][i] = c_SPtrans[3][i]; \
    s_SPtrans[4][i] = c_SPtrans[4][i]; \
    s_SPtrans[5][i] = c_SPtrans[5][i]; \
    s_SPtrans[6][i] = c_SPtrans[6][i]; \
    s_SPtrans[7][i] = c_SPtrans[7][i]; \
    s_skb[0][i] = c_skb[0][i];         \
    s_skb[1][i] = c_skb[1][i];         \
    s_skb[2][i] = c_skb[2][i];         \
    s_skb[3][i] = c_skb[3][i];         \
    s_skb[4][i] = c_skb[4][i];         \
    s_skb[5][i] = c_skb[5][i];         \
    s_skb[6][i] = c_skb[6][i];         \
    s_skb[7][i] = c_skb[7][i];         \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_SPtrans = s_SPtrans;    \
  (hc)->s_skb = s_skb;
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_buf0[2];
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf1[2] = 0;
  pw_buf1[3] = 0;

  hc->salt_buf0[0] = salt_bufs[salt_pos].salt_buf_pc[0];
  hc->salt_buf0[1] = salt_bufs[salt_pos].salt_buf_pc[1];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = w[0];
  w0[1] = w[1];
  w0[2] = w[2];
  w0[3] = w[3];
  w1[0] = w[4];
  w1[1] = w[5];
  w1[2] = w[6];
  w1[3] = w[7];

  const u32 a = w0[0];
  const u32 b = w0[1];

  u32 Ka[16];
  u32 Kb[16];

  _des_crypt_keysetup (a, b, Ka, Kb, s_skb);

  u32 data[2];

  data[0] = hc->salt_buf0[0];
  data[1] = hc->salt_buf0[1];

  u32 p1[2];

  _des_crypt_encrypt_noipfp (p1, data, Ka, Kb, s_SPtrans);

  const u32 c = w0[2];
  const u32 d = w0[3];

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

  u32 p2[2];

  _des_crypt_decrypt_noipfp (p2, p1, Kc, Kd, s_SPtrans);

  const u32 e = w1[0];
  const u32 f = w1[1];

  u32 Ke[16];
  u32 Kf[16];

  _des_crypt_keysetup (e, f, Ke, Kf, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_noipfp (iv, p2, Ke, Kf, s_SPtrans);

  dgst[0] = iv[0];
  dgst[1] = iv[1];
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = w[0];
  w0[1] = w[1];
  w0[2] = w[2];
  w0[3] = w[3];
  w1[0] = w[4];
  w1[1] = w[5];
  w1[2] = w[6];
  w1[3] = w[7];

  const u32 a = w0[0];
  const u32 b = w0[1];

  u32 Ka[16];
  u32 Kb[16];

  _des_crypt_keysetup (a, b, Ka, Kb, s_skb);

  u32 data[2];

  data[0] = hc->salt_buf0[0];
  data[1] = hc->salt_buf0[1];

  u32 p1[2];

  _des_crypt_encrypt_noipfp (p1, data, Ka, Kb, s_SPtrans);

  const u32 c = w0[2];
  const u32 d = w0[3];

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

  u32 p2[2];

  _des_crypt_decrypt_noipfp (p2, p1, Kc, Kd, s_SPtrans);

  const u32 e = w1[0];
  const u32 f = w1[1];

  u32 Ke[16];
  u32 Kf[16];

  _des_crypt_keysetup (e, f, Ke, Kf, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_noipfp (iv, p2, Ke, Kf, s_SPtrans);

  dgst[0] = iv[0];
  dgst[1] = iv[1];
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m14100_mxx
#define PCFG_KERNEL_SXX m14100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
