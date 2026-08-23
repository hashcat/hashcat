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
#define PCFG_HASH_SHARED_DECL               \
  LOCAL_VK u32 s_SPtrans[8][64];            \
  LOCAL_VK u32 s_skb[8][64];                \
  for (u32 i = lid; i < 64; i += lsz)       \
  {                                         \
    s_SPtrans[0][i] = c_SPtrans_opti[0][i]; \
    s_SPtrans[1][i] = c_SPtrans_opti[1][i]; \
    s_SPtrans[2][i] = c_SPtrans_opti[2][i]; \
    s_SPtrans[3][i] = c_SPtrans_opti[3][i]; \
    s_SPtrans[4][i] = c_SPtrans_opti[4][i]; \
    s_SPtrans[5][i] = c_SPtrans_opti[5][i]; \
    s_SPtrans[6][i] = c_SPtrans_opti[6][i]; \
    s_SPtrans[7][i] = c_SPtrans_opti[7][i]; \
    s_skb[0][i] = c_skb[0][i];              \
    s_skb[1][i] = c_skb[1][i];              \
    s_skb[2][i] = c_skb[2][i];              \
    s_skb[3][i] = c_skb[3][i];              \
    s_skb[4][i] = c_skb[4][i];              \
    s_skb[5][i] = c_skb[5][i];              \
    s_skb[6][i] = c_skb[6][i];              \
    s_skb[7][i] = c_skb[7][i];              \
  }                                         \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_SPtrans = s_SPtrans;    \
  (hc)->s_skb = s_skb;
#endif

typedef struct pcfg_hash_ctx
{
  u32 mask;
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->mask = salt_bufs[salt_pos].salt_buf[0];
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
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  u32 data[2];

  data[0] = (w[0] << 1) & 0xfefefefe;
  data[1] = (w[1] << 1) & 0xfefefefe;

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_opti (data[0], data[1], Kc, Kd, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_mask (iv, hc->mask, Kc, Kd, s_SPtrans);

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
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  u32 data[2];

  data[0] = (w[0] << 1) & 0xfefefefe;
  data[1] = (w[1] << 1) & 0xfefefefe;

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_opti (data[0], data[1], Kc, Kd, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_mask (iv, hc->mask, Kc, Kd, s_SPtrans);

  dgst[0] = iv[0];
  dgst[1] = iv[1];
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m01500_mxx
#define PCFG_KERNEL_SXX m01500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
