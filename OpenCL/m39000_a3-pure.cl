/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des_bs.cl)
#endif

typedef struct krb5pa_3
{
  u32 user[128];
  u32 realm[128];

  u32 kdc_salt[32];
  u32 kdc_salt_len;

  u32 enc_timestamp[32];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_3_t;

DECLSPEC bool krb5_des_pa_timestamp_check (PRIVATE_AS const u32 *key, GLOBAL_AS const u32 *enc_timestamp, const u32 enc_timestamp_len, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  // The timestamp opens the fourth block, and CBC needs only the block in front of it to decrypt
  // that one. So it is tested on its own before the three ahead of it are decrypted for the MD5.

  if (enc_timestamp_len >= 32)
  {
    u32 c[2];
    u32 p[2];

    c[0] = enc_timestamp[6];
    c[1] = enc_timestamp[7];

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= enc_timestamp[4];

    if ((p[0] & 0x000000ff) != 0x00000030) return false;
  }

  md5_ctx_t ctx;

  md5_init (&ctx);

  u32 iv[2];
  u32 mac[4];
  u32 w[16];

  u32 pos = 0;
  bool ts_seen = false;

  iv[0] = 0;
  iv[1] = 0;

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
      mac[0] = p[0];
      mac[1] = p[1];
      p[0] = 0;
      p[1] = 0;
    }
    else if (off == 16)
    {
      mac[2] = p[0];
      mac[3] = p[1];
      p[0] = 0;
      p[1] = 0;
    }

    if (off == 24 && !ts_seen)
    {
      if ((p[0] & 0x000000ff) != 0x00000030) return false;

      ts_seen = true;
    }

    w[pos + 0] = p[0];
    w[pos + 1] = p[1];

    pos += 2;

    if (pos == 16)
    {
      md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, 64);
      pos = 0;
    }
  }

  if (pos != 0)
  {
    for (u32 i = pos; i < 16; i++) w[i] = 0;

    md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, pos * 4);
  }

  md5_final (&ctx);

  if (mac[0] != ctx.h[0]) return false;
  if (mac[1] != ctx.h[1]) return false;
  if (mac[2] != ctx.h[2]) return false;
  if (mac[3] != ctx.h[3]) return false;

  return true;
}

#define KRB5_DES_BS_KERNEL_TM  m39000_tm
#define KRB5_DES_BS_KERNEL_MXX m39000_mxx
#define KRB5_DES_BS_KERNEL_SXX m39000_sxx

// The candidate is tested on the block the timestamp opens, the fourth one, which CBC chains with
// the third. A timestamp too short to have that block gets the full check for every candidate.

#define KRB5_DES_BS_PREPARE                                                                               \
  GLOBAL_AS const krb5pa_3_t *esalt = &((GLOBAL_AS const krb5pa_3_t *) esalt_bufs)[DIGESTS_OFFSET_HOST];  \
                                                                                                          \
  GLOBAL_AS const u32 *salt_buf = esalt->kdc_salt;                                                        \
                                                                                                          \
  const u32 salt_len = esalt->kdc_salt_len;                                                               \
                                                                                                          \
  const u32 iv0 = esalt->enc_timestamp[4];                                                                \
  const u32 iv1 = esalt->enc_timestamp[5];                                                                \
  const u32 ct0 = esalt->enc_timestamp[6];                                                                \
  const u32 ct1 = esalt->enc_timestamp[7];                                                                \
                                                                                                          \
  const u32 untested = (esalt->enc_timestamp_len < 32) ? 0xffffffff : 0;

#define KRB5_DES_BS_CIPHER

// the 0x30 of the SEQUENCE the timestamp is

#define KRB5_DES_BS_HITS(B) (KRB5_DES_BS_EQ8 (B, 0, 0x30) | untested)

#define KRB5_DES_BS_VERIFY                                                                                              \
  if (krb5_des_pa_timestamp_check (key, esalt->enc_timestamp, esalt->enc_timestamp_len, s_SPtrans, s_skb) == true)      \
  {                                                                                                                     \
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)                                                        \
    {                                                                                                                   \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);  \
    }                                                                                                                   \
  }

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_krb5_des_bs_kernel.cl)
#endif
