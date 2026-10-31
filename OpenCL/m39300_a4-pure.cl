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
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
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

typedef struct krb5pa_1
{
  u32 user[32];
  u32 realm[32];

  u32 salt_buf[32];
  u32 salt_len;

  u32 enc_timestamp[32];
  u32 enc_timestamp_len;

} krb5pa_1_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (krb5pa_1_t)

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  GLOBAL_AS const krb5pa_1_t *esalt_bufs;

  u32 digest_pos;
  u32 salt_len;

  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC bool krb5_des_crc_pa_timestamp_check (PRIVATE_AS const u32 *key_in, PRIVATE_AS const u32 *enc_timestamp, const u32 enc_timestamp_len, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  u32 key[2];
  key[0] = key_in[0];
  key[1] = key_in[1];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  u32 iv[2];
  iv[0] = key[0];
  iv[1] = key[1];

  u32 stored_crc = 0;
  u32 plain[32];
  u32 wpos = 0;

  for (u32 off = 0; off < enc_timestamp_len; off += 8)
  {
    u32 c[2];
    u32 p[2];

    c[0] = enc_timestamp[(off / 4) + 0];
    c[1] = enc_timestamp[(off / 4) + 1];

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= iv[0];
    p[1] ^= iv[1];

    iv[0] = c[0];
    iv[1] = c[1];

    if (off == 8)
    {
      stored_crc = p[0];
      p[0] = 0;

      if ((p[1] & 0x000000ff) != 0x00000030) return false;
    }

    if (wpos < 32)
    {
      plain[wpos + 0] = p[0];
      plain[wpos + 1] = p[1];
    }

    wpos += 2;
  }

  const u32 crc_len = (wpos < 32) ? wpos * 4 : 128;

  const u32 computed_crc = ~crc32 (plain, crc_len, ~0);

  if (computed_crc != stored_crc) return false;

  return true;
}

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const krb5pa_1_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
  hc->salt_len   = esalt_bufs[digest_pos].salt_len;
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

  u32 t[64];

  krb5_des_build_buf (w, len, hc->esalt_bufs[hc->digest_pos].salt_buf, hc->salt_len, t);

  u32 key[2];

  krb5_des_string_to_key (t, len + hc->salt_len, key, s_SPtrans, s_skb);

  u32 ts[32];

  for (u32 i = 0; i < (hc->esalt_bufs[hc->digest_pos].enc_timestamp_len + 3) / 4; i++)
  {
    ts[i] = hc->esalt_bufs[hc->digest_pos].enc_timestamp[i];
  }

  if (krb5_des_crc_pa_timestamp_check (key, ts, hc->esalt_bufs[hc->digest_pos].enc_timestamp_len, s_SPtrans, s_skb) == false) return false;

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

  const bool ok = pcfg_hash (hc, t, len, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m39300_mxx
#define PCFG_KERNEL_SXX m39300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
