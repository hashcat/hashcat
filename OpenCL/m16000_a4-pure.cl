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

CONSTANT_VK u32a c_tripcode_salt[128] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
  0x12, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
  0x2b, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL                \
  LOCAL_VK u32 s_SPtrans[8][64];             \
  LOCAL_VK u32 s_skb[8][64];                 \
  LOCAL_VK u32 s_tripcode_salt[128];         \
  for (u32 i = lid; i < 64; i += lsz)        \
  {                                          \
    s_SPtrans[0][i] = c_SPtrans_opti[0][i];  \
    s_SPtrans[1][i] = c_SPtrans_opti[1][i];  \
    s_SPtrans[2][i] = c_SPtrans_opti[2][i];  \
    s_SPtrans[3][i] = c_SPtrans_opti[3][i];  \
    s_SPtrans[4][i] = c_SPtrans_opti[4][i];  \
    s_SPtrans[5][i] = c_SPtrans_opti[5][i];  \
    s_SPtrans[6][i] = c_SPtrans_opti[6][i];  \
    s_SPtrans[7][i] = c_SPtrans_opti[7][i];  \
    s_skb[0][i] = c_skb[0][i];               \
    s_skb[1][i] = c_skb[1][i];               \
    s_skb[2][i] = c_skb[2][i];               \
    s_skb[3][i] = c_skb[3][i];               \
    s_skb[4][i] = c_skb[4][i];               \
    s_skb[5][i] = c_skb[5][i];               \
    s_skb[6][i] = c_skb[6][i];               \
    s_skb[7][i] = c_skb[7][i];               \
  }                                          \
  for (u32 i = lid; i < 128; i += lsz)       \
  {                                          \
    s_tripcode_salt[i] = c_tripcode_salt[i]; \
  }                                          \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc)          \
  (hc)->s_SPtrans = s_SPtrans;             \
  (hc)->s_skb = s_skb;                     \
  (hc)->s_tripcode_salt = s_tripcode_salt;
#endif

typedef struct pcfg_hash_ctx
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  LOCAL_AS u32 *s_tripcode_salt;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  LOCAL_AS u32 *s_tripcode_salt = hc->s_tripcode_salt;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  CONSTANT_AS u32a (*s_tripcode_salt) = c_tripcode_salt;
  #endif

  u32 mask = 0;

  mask |= s_tripcode_salt[(w[0] >>  8) & 0x7f] << 0;
  mask |= s_tripcode_salt[(w[0] >> 16) & 0x7f] << 6;

  u32 data[2];

  data[0] = (w[0] << 1) & 0xfefefefe;
  data[1] = (w[1] << 1) & 0xfefefefe;

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_opti (data[0], data[1], Kc, Kd, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_mask (iv, mask, Kc, Kd, s_SPtrans);

  iv[0] &= 0xff7f7f7f;
  iv[1] &= 0xff7f7f7f;

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
  LOCAL_AS u32 *s_tripcode_salt = hc->s_tripcode_salt;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  CONSTANT_AS u32a (*s_tripcode_salt) = c_tripcode_salt;
  #endif

  u32 mask = 0;

  mask |= s_tripcode_salt[(w[0] >>  8) & 0x7f] << 0;
  mask |= s_tripcode_salt[(w[0] >> 16) & 0x7f] << 6;

  u32 data[2];

  data[0] = (w[0] << 1) & 0xfefefefe;
  data[1] = (w[1] << 1) & 0xfefefefe;

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_opti (data[0], data[1], Kc, Kd, s_skb);

  u32 iv[2];

  _des_crypt_encrypt_mask (iv, mask, Kc, Kd, s_SPtrans);

  iv[0] &= 0xff7f7f7f;
  iv[1] &= 0xff7f7f7f;

  dgst[0] = iv[0];
  dgst[1] = iv[1];
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m16000_mxx
#define PCFG_KERNEL_SXX m16000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
