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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

#define MIN_NULL_BYTES 10

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 secondBlockData[8];
  u32 secondBlockLen;
  u32 rc4key[2];

} oldoffice34_t;

KERNEL_FQ void m09800_m04 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
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
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  /**
   * esalt
   */

  const u32 version = esalt_bufs[DIGESTS_OFFSET_HOST].version;

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

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha1
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_salt_len = (out_len * 2) + 16;

    w3[3] = pw_salt_len * 8;
    w3[2] = 0;
    w3[1] = hc_swap32 (w2[1]);
    w3[0] = hc_swap32 (w2[0]);
    w2[3] = hc_swap32 (w1[3]);
    w2[2] = hc_swap32 (w1[2]);
    w2[1] = hc_swap32 (w1[1]);
    w2[0] = hc_swap32 (w1[0]);
    w1[3] = hc_swap32 (w0[3]);
    w1[2] = hc_swap32 (w0[2]);
    w1[1] = hc_swap32 (w0[1]);
    w1[0] = hc_swap32 (w0[0]);
    w0[3] = salt_buf[3];
    w0[2] = salt_buf[2];
    w0[1] = salt_buf[1];
    w0[0] = salt_buf[0];

    u32 pass_hash[5];

    pass_hash[0] = SHA1M_A;
    pass_hash[1] = SHA1M_B;
    pass_hash[2] = SHA1M_C;
    pass_hash[3] = SHA1M_D;
    pass_hash[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, pass_hash);

    w0[0] = pass_hash[0];
    w0[1] = pass_hash[1];
    w0[2] = pass_hash[2];
    w0[3] = pass_hash[3];
    w1[0] = pass_hash[4];
    w1[1] = 0;
    w1[2] = 0x80000000;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    if (version == 3)
    {
      digest[1] &= 0xff;
      digest[2]  = 0;
      digest[3]  = 0;
    }

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = hc_swap32 (out[0]);
    w0[1] = hc_swap32 (out[1]);
    w0[2] = hc_swap32 (out[2]);
    w0[3] = hc_swap32 (out[3]);
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (S, 16, j, digest, out, lid);

    // initial compare

    int digest_pos = find_hash (out, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);

    if (digest_pos == -1) continue;

    if (esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockLen != 0)
    {
      w0[0] = pass_hash[0];
      w0[1] = pass_hash[1];
      w0[2] = pass_hash[2];
      w0[3] = pass_hash[3];
      w1[0] = pass_hash[4];
      w1[1] = 0x01000000;
      w1[2] = 0x80000000;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (20 + 4) * 8;

      digest[0] = SHA1M_A;
      digest[1] = SHA1M_B;
      digest[2] = SHA1M_C;
      digest[3] = SHA1M_D;
      digest[4] = SHA1M_E;

      sha1_transform (w0, w1, w2, w3, digest);

      digest[0] = hc_swap32_S (digest[0]);
      digest[1] = hc_swap32_S (digest[1]);
      digest[2] = 0;
      digest[3] = 0;

      digest[1] &= 0xff; // only 40-bit key

      // second block decrypt:

      rc4_init_128 (S, digest, lid);

      u32 secondBlockData[4];

      secondBlockData[0] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[0];
      secondBlockData[1] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[1];
      secondBlockData[2] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[2];
      secondBlockData[3] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[3];

      j = rc4_next_16 (S, 0, 0, secondBlockData, out, lid);

      int null_bytes = 0;

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      secondBlockData[0] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[4];
      secondBlockData[1] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[5];
      secondBlockData[2] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[6];
      secondBlockData[3] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[7];

      rc4_next_16 (S, 16, j, secondBlockData, out, lid);

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      if (null_bytes < MIN_NULL_BYTES) continue;
    }

    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;

    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ void m09800_m08 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_m16 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_s04 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
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
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  /**
   * esalt
   */

  const u32 version = esalt_bufs[DIGESTS_OFFSET_HOST].version;

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

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha1
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_salt_len = (out_len * 2) + 16;

    w3[3] = pw_salt_len * 8;
    w3[2] = 0;
    w3[1] = hc_swap32 (w2[1]);
    w3[0] = hc_swap32 (w2[0]);
    w2[3] = hc_swap32 (w1[3]);
    w2[2] = hc_swap32 (w1[2]);
    w2[1] = hc_swap32 (w1[1]);
    w2[0] = hc_swap32 (w1[0]);
    w1[3] = hc_swap32 (w0[3]);
    w1[2] = hc_swap32 (w0[2]);
    w1[1] = hc_swap32 (w0[1]);
    w1[0] = hc_swap32 (w0[0]);
    w0[3] = salt_buf[3];
    w0[2] = salt_buf[2];
    w0[1] = salt_buf[1];
    w0[0] = salt_buf[0];

    u32 pass_hash[5];

    pass_hash[0] = SHA1M_A;
    pass_hash[1] = SHA1M_B;
    pass_hash[2] = SHA1M_C;
    pass_hash[3] = SHA1M_D;
    pass_hash[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, pass_hash);

    w0[0] = pass_hash[0];
    w0[1] = pass_hash[1];
    w0[2] = pass_hash[2];
    w0[3] = pass_hash[3];
    w1[0] = pass_hash[4];
    w1[1] = 0;
    w1[2] = 0x80000000;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    if (version == 3)
    {
      digest[1] &= 0xff;
      digest[2]  = 0;
      digest[3]  = 0;
    }

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = hc_swap32 (out[0]);
    w0[1] = hc_swap32 (out[1]);
    w0[2] = hc_swap32 (out[2]);
    w0[3] = hc_swap32 (out[3]);
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (S, 16, j, digest, out, lid);

    // initial compare

    if (out[0] != search[0]) continue;
    if (out[1] != search[1]) continue;
    if (out[2] != search[2]) continue;
    if (out[3] != search[3]) continue;

    if (esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockLen != 0)
    {
      w0[0] = pass_hash[0];
      w0[1] = pass_hash[1];
      w0[2] = pass_hash[2];
      w0[3] = pass_hash[3];
      w1[0] = pass_hash[4];
      w1[1] = 0x01000000;
      w1[2] = 0x80000000;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (20 + 4) * 8;

      digest[0] = SHA1M_A;
      digest[1] = SHA1M_B;
      digest[2] = SHA1M_C;
      digest[3] = SHA1M_D;
      digest[4] = SHA1M_E;

      sha1_transform (w0, w1, w2, w3, digest);

      digest[0] = hc_swap32_S (digest[0]);
      digest[1] = hc_swap32_S (digest[1]);
      digest[2] = 0;
      digest[3] = 0;

      digest[1] &= 0xff; // only 40-bit key

      // second block decrypt:

      rc4_init_128 (S, digest, lid);

      u32 secondBlockData[4];

      secondBlockData[0] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[0];
      secondBlockData[1] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[1];
      secondBlockData[2] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[2];
      secondBlockData[3] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[3];

      j = rc4_next_16 (S, 0, 0, secondBlockData, out, lid);

      int null_bytes = 0;

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      secondBlockData[0] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[4];
      secondBlockData[1] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[5];
      secondBlockData[2] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[6];
      secondBlockData[3] = esalt_bufs[DIGESTS_OFFSET_HOST].secondBlockData[7];

      rc4_next_16 (S, 16, j, secondBlockData, out, lid);

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      if (null_bytes < MIN_NULL_BYTES) continue;
    }

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ void m09800_s08 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_s16 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}
