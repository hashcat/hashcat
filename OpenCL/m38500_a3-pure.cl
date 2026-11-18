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

typedef struct krb5tgs_3
{
  u32 raw_token[512];

  u32 user[128];
  u32 realm[128];

  u32 kdc_salt[32];
  u32 kdc_salt_len;

  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

  u32 format;

} krb5tgs_3_t;

#define KRB5_DES_BS_KERNEL_TM  m38500_tm
#define KRB5_DES_BS_KERNEL_MXX m38500_mxx
#define KRB5_DES_BS_KERNEL_SXX m38500_sxx

// The candidate is tested on the block the ASN.1 header of the ticket is in, the second one of
// edata2, which CBC chains with the first.

#define KRB5_DES_BS_PREPARE                                                                                 \
  GLOBAL_AS const krb5tgs_3_t *esalt = &((GLOBAL_AS const krb5tgs_3_t *) esalt_bufs)[DIGESTS_OFFSET_HOST];  \
                                                                                                            \
  GLOBAL_AS const u32 *salt_buf = esalt->kdc_salt;                                                          \
                                                                                                            \
  const u32 salt_len = esalt->kdc_salt_len;                                                                 \
                                                                                                            \
  const u32 iv0 = esalt->edata2[0];                                                                         \
  const u32 iv1 = esalt->edata2[1];                                                                         \
  const u32 ct0 = esalt->edata2[2];                                                                         \
  const u32 ct1 = esalt->edata2[3];

#define KRB5_DES_BS_CIPHER

// A ticket opens with 0x63 and a length behind 0x81 or 0x82, see krb5_des_encpart_asn1 (). The six
// bits those two have in common are tested with the 0x63.

#define KRB5_DES_BS_HITS(B) (KRB5_DES_BS_EQ8 (B, 0, 0x63) & (B)[8] & ~((B)[9] | (B)[10] | (B)[11] | (B)[12] | (B)[13]))

#define KRB5_DES_BS_VERIFY                                                                                                \
  if (krb5_des_encpart_check (key, esalt->checksum, esalt->edata2, esalt->edata2_len, false, s_SPtrans, s_skb) == true)   \
  {                                                                                                                       \
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)                                                          \
    {                                                                                                                     \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);    \
    }                                                                                                                     \
  }

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_krb5_des_bs_kernel.cl)
#endif
