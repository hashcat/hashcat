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
  u32 salt_buf[8];
  u32 salt_len;

  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  for (u32 i = 0; i < 8; i++) hc->salt_buf[i] = salt_bufs[salt_pos].salt_buf[i];

  hc->salt_len = salt_bufs[salt_pos].salt_len;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_oracle_h (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  const u32 salt_len = hc->salt_len;

  u32 dst[16];

  for (u32 i = 0; i <  8; i++) dst[i] = hc->salt_buf[i];
  for (u32 i = 8; i < 16; i++) dst[i] = 0;

  for (u32 i = 0; i < len; i++) pcfg_put_byte (dst, salt_len + i, pcfg_get_byte (w, i));

  const u32 salt_word_len = (salt_len + len) * 2;

  /**
   * precompute key1 since key is static: 0x0123456789abcdefUL
   * plus LEFT_ROTATE by 2
   */

  u32 Kc[16];

  Kc[ 0] = 0x64649040;
  Kc[ 1] = 0x14909858;
  Kc[ 2] = 0xc4b44888;
  Kc[ 3] = 0x9094e438;
  Kc[ 4] = 0xd8a004f0;
  Kc[ 5] = 0xa8f02810;
  Kc[ 6] = 0xc84048d8;
  Kc[ 7] = 0x68d804a8;
  Kc[ 8] = 0x0490e40c;
  Kc[ 9] = 0xac183024;
  Kc[10] = 0x24c07c10;
  Kc[11] = 0x8c88c038;
  Kc[12] = 0xc048c824;
  Kc[13] = 0x4c0470a8;
  Kc[14] = 0x584020b4;
  Kc[15] = 0x00742c4c;

  u32 Kd[16];

  Kd[ 0] = 0xa42ce40c;
  Kd[ 1] = 0x64689858;
  Kd[ 2] = 0x484050b8;
  Kd[ 3] = 0xe8184814;
  Kd[ 4] = 0x405cc070;
  Kd[ 5] = 0xa010784c;
  Kd[ 6] = 0x6074a800;
  Kd[ 7] = 0x80701c1c;
  Kd[ 8] = 0x9cd49430;
  Kd[ 9] = 0x4c8ce078;
  Kd[10] = 0x5c18c088;
  Kd[11] = 0x28a8a4c8;
  Kd[12] = 0x3c180838;
  Kd[13] = 0xb0b86c20;
  Kd[14] = 0xac84a094;
  Kd[15] = 0x4ce0c0c4;

  /**
   * key1 (generate key)
   */

  u32 iv[2];

  iv[0] = 0;
  iv[1] = 0;

  for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
  {
    u32 data[2];

    data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
    data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

    data[0] ^= iv[0];
    data[1] ^= iv[1];

    _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
  }

  /**
   * key2 (generate hash)
   */

  _des_crypt_keysetup (iv[0], iv[1], Kc, Kd, s_skb);

  iv[0] = 0;
  iv[1] = 0;

  for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
  {
    u32 data[2];

    data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
    data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

    data[0] ^= iv[0];
    data[1] ^= iv[1];

    _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
  }

  dgst[0] = iv[0];
  dgst[1] = iv[1];
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  if ((hc->salt_len + len) > 64) return false;

  return pcfg_oracle_h (hc, w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  if ((hc->salt_len + len) > 64) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_oracle_h (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m03100_mxx
#define PCFG_KERNEL_SXX m03100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
