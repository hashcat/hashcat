/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_encpart_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des_bs.cl)
#endif

typedef struct krb5asrep_3
{
  u32 user[128];
  u32 realm[128];
  u32 format;

  u32 kdc_salt[32];
  u32 kdc_salt_len;

  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5asrep_3_t;

#define KRB5_DES_BS_KERNEL_TM  m38600_tm
#define KRB5_DES_BS_KERNEL_MXX m38600_mxx
#define KRB5_DES_BS_KERNEL_SXX m38600_sxx

// The candidate is tested on the block the ASN.1 header of the reply is in, the second one of
// edata2, which CBC chains with the first.

#define KRB5_DES_BS_PREPARE                                                                                     \
  GLOBAL_AS const krb5asrep_3_t *esalt = &((GLOBAL_AS const krb5asrep_3_t *) esalt_bufs)[DIGESTS_OFFSET_HOST];  \
                                                                                                                \
  GLOBAL_AS const u32 *salt_buf = esalt->kdc_salt;                                                              \
                                                                                                                \
  const u32 salt_len = esalt->kdc_salt_len;                                                                     \
                                                                                                                \
  const u32 iv0 = esalt->edata2[0];                                                                             \
  const u32 iv1 = esalt->edata2[1];                                                                             \
  const u32 ct0 = esalt->edata2[2];                                                                             \
  const u32 ct1 = esalt->edata2[3];

#define KRB5_DES_BS_CIPHER

// A reply opens with 0x79 or 0x7a, a length on one, two or three bytes, and the 0x30 of a SEQUENCE
// right behind it, see krb5_des_encpart_asn1 ().

#define KRB5_DES_BS_HITS(B)                                                      \
  ( (~(B)[0] & (B)[1] & (B)[2] & (B)[3] & (B)[4] & ~(B)[5] & ((B)[6] ^ (B)[7]))  \
  & ( (~(B)[8] & KRB5_DES_BS_EQ8 (B, 2, 0x30))                                   \
    | (KRB5_DES_BS_EQ8 (B, 1, 0x81) & KRB5_DES_BS_EQ8 (B, 3, 0x30))              \
    | (KRB5_DES_BS_EQ8 (B, 1, 0x82) & KRB5_DES_BS_EQ8 (B, 4, 0x30))))

#define KRB5_DES_BS_VERIFY                                                                                              \
  if (krb5_des_encpart_check (key, esalt->checksum, esalt->edata2, esalt->edata2_len, true, s_SPtrans, s_skb) == true)  \
  {                                                                                                                     \
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)                                                        \
    {                                                                                                                   \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);  \
    }                                                                                                                   \
  }

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_krb5_des_bs_kernel.cl)
#endif
