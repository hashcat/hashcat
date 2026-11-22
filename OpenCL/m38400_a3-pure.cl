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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des_bs.cl)
#endif

#define KRB5_DES_BS_KERNEL_TM  m38400_tm
#define KRB5_DES_BS_KERNEL_MXX m38400_mxx
#define KRB5_DES_BS_KERNEL_SXX m38400_sxx

// This mode has no cipher to test a candidate on: the key is the digest. So the slices compare the
// 56 bits DES uses of it, and the full check compares all of it the way the other kernels do.

#define KRB5_DES_BS_PREPARE_M                                         \
  GLOBAL_AS const u32 *salt_buf = salt_bufs[SALT_POS_HOST].salt_buf;  \
                                                                      \
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

#define KRB5_DES_BS_PREPARE_S                                         \
  GLOBAL_AS const u32 *salt_buf = salt_bufs[SALT_POS_HOST].salt_buf;  \
                                                                      \
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;             \
                                                                      \
  const u32 search[4] =                                               \
  {                                                                   \
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],             \
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],             \
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],             \
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]              \
  };

#define KRB5_DES_BS_TEST_M(B,need)                                                           \
  for (u32 d = 0; d < DIGESTS_CNT; d++)                                                      \
  {                                                                                          \
    const u32 d0 = digests_buf[DIGESTS_OFFSET_HOST + d].digest_buf[DGST_R0];                 \
    const u32 d1 = digests_buf[DIGESTS_OFFSET_HOST + d].digest_buf[DGST_R1];                 \
                                                                                             \
    need |= KRB5_DES_BS_EQ_KEY (B, d0, d1);                                                  \
  }

#define KRB5_DES_BS_TEST_S(B,need) need |= KRB5_DES_BS_EQ_KEY (B, search[0], search[1]);

#define KRB5_DES_BS_VERIFY_M                \
  {                                         \
    const u32 z = 0;                        \
                                            \
    COMPARE_M_SIMD (key[0], key[1], z, z);  \
  }

#define KRB5_DES_BS_VERIFY_S                \
  {                                         \
    const u32 z = 0;                        \
                                            \
    COMPARE_S_SIMD (key[0], key[1], z, z);  \
  }

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_krb5_des_bs_kernel.cl)
#endif
