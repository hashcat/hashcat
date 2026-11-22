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
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des_bs.cl)
#endif

typedef struct krb5pa_1
{
  u32 user[128];
  u32 realm[128];

  u32 kdc_salt[32];
  u32 kdc_salt_len;

  u32 enc_timestamp[32];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_1_t;

DECLSPEC bool krb5_des_crc_pa_timestamp_check (PRIVATE_AS const u32 *key_in, GLOBAL_AS const u32 *enc_timestamp, const u32 enc_timestamp_len, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  u32 key[2];
  key[0] = key_in[0];
  key[1] = key_in[1];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  // The timestamp opens in the second half of the second block, and CBC needs only the first
  // block to decrypt that one. So it is tested on its own before anything else is decrypted.

  if (enc_timestamp_len >= 16)
  {
    u32 c[2];
    u32 p[2];

    c[0] = enc_timestamp[2];
    c[1] = enc_timestamp[3];

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[1] ^= enc_timestamp[1];

    if ((p[1] & 0x000000ff) != 0x00000030) return false;
  }

  // DES-CBC decrypt with IV=key (etype 1)

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

  if (((plain[4] >> 16) & 0x0000ffff) != 0x00003032) return false;

  u32 d;

  d = plain[5];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;

  d = plain[6];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;

  d = plain[7];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;


  d = plain[5];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;

  d = plain[6];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;

  d = plain[7];
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false; d >>= 8;
  if (((d & 0xff) < 0x30) || ((d & 0xff) > 0x39)) return false;

  return true;
}


#define KRB5_DES_BS_KERNEL_TM  m39300_tm
#define KRB5_DES_BS_KERNEL_MXX m39300_mxx
#define KRB5_DES_BS_KERNEL_SXX m39300_sxx

// The candidate is tested on the second block, which CBC chains with the first. The timestamp
// opens its second half, behind the four bytes of the CRC. A timestamp too short to have that block
// gets the full check for every candidate.

#define KRB5_DES_BS_PREPARE                                                                               \
  GLOBAL_AS const krb5pa_1_t *esalt = &((GLOBAL_AS const krb5pa_1_t *) esalt_bufs)[DIGESTS_OFFSET_HOST];  \
                                                                                                          \
  GLOBAL_AS const u32 *salt_buf = esalt->kdc_salt;                                                        \
                                                                                                          \
  const u32 salt_len = esalt->kdc_salt_len;                                                               \
                                                                                                          \
  const u32 iv0 = esalt->enc_timestamp[0];                                                                \
  const u32 iv1 = esalt->enc_timestamp[1];                                                                \
  const u32 ct0 = esalt->enc_timestamp[2];                                                                \
  const u32 ct1 = esalt->enc_timestamp[3];                                                                \
                                                                                                          \
  const u32 untested = (esalt->enc_timestamp_len < 16) ? 0xffffffff : 0;

#define KRB5_DES_BS_CIPHER

// the 0x30 of the SEQUENCE the timestamp is

#define KRB5_DES_BS_HITS(B) (KRB5_DES_BS_EQ8 (B, 4, 0x30) | untested)

#define KRB5_DES_BS_VERIFY                                                                                              \
  if (krb5_des_crc_pa_timestamp_check (key, esalt->enc_timestamp, esalt->enc_timestamp_len, s_SPtrans, s_skb) == true)  \
  {                                                                                                                     \
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)                                                        \
    {                                                                                                                   \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);  \
    }                                                                                                                   \
  }

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_krb5_des_bs_kernel.cl)
#endif
