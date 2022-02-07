/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

KERNEL_FQ void m09710_m04 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * esalt
   */

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * md5
     */

    w0[0]  = w0[0];
    w0[1]  = w0[1] & 0xff;
    w0[2]  = 0x8000;
    w0[3]  = 0;
    w1[0]  = 0;
    w1[1]  = 0;
    w1[2]  = 0;
    w1[3]  = 0;
    w2[0]  = 0;
    w2[1]  = 0;
    w2[2]  = 0;
    w2[3]  = 0;
    w3[0]  = 0;
    w3[1]  = 0;
    w3[2]  = 9 * 8;
    w3[3]  = 0;

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    // now the RC4 part

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 16 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    rc4_next_16 (S, 16, j, digest, out, lid);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void m09710_m08 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09710_m16 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09710_s04 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * esalt
   */

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * md5
     */

    w0[0]  = w0[0];
    w0[1]  = w0[1] & 0xff;
    w0[2]  = 0x8000;
    w0[3]  = 0;
    w1[0]  = 0;
    w1[1]  = 0;
    w1[2]  = 0;
    w1[3]  = 0;
    w2[0]  = 0;
    w2[1]  = 0;
    w2[2]  = 0;
    w2[3]  = 0;
    w3[0]  = 0;
    w3[1]  = 0;
    w3[2]  = 9 * 8;
    w3[3]  = 0;

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    // now the RC4 part

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 16 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    rc4_next_16 (S, 16, j, digest, out, lid);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void m09710_s08 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09710_s16 (KERN_ATTR_RULES_ESALT (oldoffice01_t))
{
}
