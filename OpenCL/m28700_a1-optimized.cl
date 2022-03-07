/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

typedef struct aws4_sig_v4
{
  u32 date[3];
  u32 date_len;

  u32 longdate[4];
  u32 longdate_len;

  u32 region[4];
  u32 region_len;

  u32 service[4];
  u32 service_len;

  u32 canonical[8];
  u32 canonical_len;

  u32 stringtosign[64];
  u32 stringtosign_len;

} aws4_sig_v4_t;

DECLSPEC void hmac_sha256_pad (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA256M_A;
  ipad[1] = SHA256M_B;
  ipad[2] = SHA256M_C;
  ipad[3] = SHA256M_D;
  ipad[4] = SHA256M_E;
  ipad[5] = SHA256M_F;
  ipad[6] = SHA256M_G;
  ipad[7] = SHA256M_H;

  sha256_transform_vector (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA256M_A;
  opad[1] = SHA256M_B;
  opad[2] = SHA256M_C;
  opad[3] = SHA256M_D;
  opad[4] = SHA256M_E;
  opad[5] = SHA256M_F;
  opad[6] = SHA256M_G;
  opad[7] = SHA256M_H;

  sha256_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_sha256_run (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m28700_m04 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4] = { 0 };
  u32 pw_buf1[4] = { 0 };

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * date
   */

  u32x date_buf0[4] = { 0 };

  date_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 0]);
  date_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 1]);
  date_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 2]);
  date_buf0[3] = 0;

  const u32 date_len = esalt_bufs[DIGESTS_OFFSET_HOST].date_len;

  /**
   * region
   */

  u32x region_buf0[4] = { 0 };

  region_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 0]);
  region_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 1]);
  region_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 2]);
  region_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 3]);

  const u32 region_len = esalt_bufs[DIGESTS_OFFSET_HOST].region_len;

  /**
   * service
   */

  u32x service_buf0[4] = { 0 };

  service_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 0]);
  service_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 1]);
  service_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 2]);
  service_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 3]);

  const u32 service_len = esalt_bufs[DIGESTS_OFFSET_HOST].service_len;

  /**
   * stringtosign
   */

  u32x stringtosign_buf[64] = { 0 };

  const u32 stringtosign_len = esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign_len;

  for (u32 i = 0, idx = 0; i < stringtosign_len; i += 4, idx += 1)
  {
    stringtosign_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = wordl0[0] | wordr0[0];
    w0_t[1] = wordl0[1] | wordr0[1];
    w0_t[2] = wordl0[2] | wordr0[2];
    w0_t[3] = wordl0[3] | wordr0[3];
    w1_t[0] = wordl1[0] | wordr1[0];
    w1_t[1] = wordl1[1] | wordr1[1];
    w1_t[2] = wordl1[2] | wordr1[2];
    w1_t[3] = wordl1[3] | wordr1[3];
    w2_t[0] = wordl2[0] | wordr2[0];
    w2_t[1] = wordl2[1] | wordr2[1];
    w2_t[2] = wordl2[2] | wordr2[2];
    w2_t[3] = wordl2[3] | wordr2[3];
    w3_t[0] = wordl3[0] | wordr3[0];
    w3_t[1] = wordl3[1] | wordr3[1];
    w3_t[2] = wordl3[2] | wordr3[2];
    w3_t[3] = wordl3[3] | wordr3[3];

    u32x ipad[8];
    u32x opad[8];

    u32x digest[8];

    // kdate

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = 0x41575334;
    w0[1] = hc_swap32 (w0_t[0]);
    w0[2] = hc_swap32 (w0_t[1]);
    w0[3] = hc_swap32 (w0_t[2]);
    w1[0] = hc_swap32 (w0_t[3]);
    w1[1] = hc_swap32 (w1_t[0]);
    w1[2] = hc_swap32 (w1_t[1]);
    w1[3] = hc_swap32 (w1_t[2]);
    w2[0] = hc_swap32 (w1_t[3]);
    w2[1] = hc_swap32 (w2_t[0]);
    w2[2] = hc_swap32 (w2_t[1]);
    w2[3] = hc_swap32 (w2_t[2]);
    w3[0] = hc_swap32 (w2_t[3]);
    w3[1] = hc_swap32 (w3_t[0]);
    w3[2] = hc_swap32 (w3_t[1]);
    w3[3] = hc_swap32 (w3_t[2]);

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = date_buf0[0];
    w0[1] = date_buf0[1];
    w0[2] = date_buf0[2];
    w0[3] = date_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + date_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // kregion

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = region_buf0[0];
    w0[1] = region_buf0[1];
    w0[2] = region_buf0[2];
    w0[3] = region_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + region_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // kservice

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = service_buf0[0];
    w0[1] = service_buf0[1];
    w0[2] = service_buf0[2];
    w0[3] = service_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + service_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // signingkey

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = 0x61777334;
    w0[1] = 0x5f726571;
    w0[2] = 0x75657374;
    w0[3] = 0x80000000;
    w1[0] = 0;
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
    w3[3] = (64 + 12) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // signature

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_vector_t ctx_signature;

    sha256_hmac_init_vector_64 (&ctx_signature, w0, w1, w2, w3);

    sha256_hmac_update_vector (&ctx_signature, stringtosign_buf, stringtosign_len);

    sha256_hmac_final_vector (&ctx_signature);

    const u32x r0 = ctx_signature.opad.h[DGST_R0];
    const u32x r1 = ctx_signature.opad.h[DGST_R1];
    const u32x r2 = ctx_signature.opad.h[DGST_R2];
    const u32x r3 = ctx_signature.opad.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28700_m08 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
}

KERNEL_FQ void m28700_m16 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
}

KERNEL_FQ void m28700_s04 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * date
   */

  u32x date_buf0[4] = { 0 };

  date_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 0]);
  date_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 1]);
  date_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[ 2]);
  date_buf0[3] = 0;

  const u32 date_len = esalt_bufs[DIGESTS_OFFSET_HOST].date_len;

  /**
   * region
   */

  u32x region_buf0[4] = { 0 };

  region_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 0]);
  region_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 1]);
  region_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 2]);
  region_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[ 3]);

  const u32 region_len = esalt_bufs[DIGESTS_OFFSET_HOST].region_len;

  /**
   * service
   */

  u32x service_buf0[4] = { 0 };

  service_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 0]);
  service_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 1]);
  service_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 2]);
  service_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[ 3]);

  const u32 service_len = esalt_bufs[DIGESTS_OFFSET_HOST].service_len;

  /**
   * stringtosign
   */

  u32x stringtosign_buf[64] = { 0 };

  const u32 stringtosign_len = esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign_len;

  for (u32 i = 0, idx = 0; i < stringtosign_len; i += 4, idx += 1)
  {
    stringtosign_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign[idx]);
  }

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
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = wordl0[0] | wordr0[0];
    w0_t[1] = wordl0[1] | wordr0[1];
    w0_t[2] = wordl0[2] | wordr0[2];
    w0_t[3] = wordl0[3] | wordr0[3];
    w1_t[0] = wordl1[0] | wordr1[0];
    w1_t[1] = wordl1[1] | wordr1[1];
    w1_t[2] = wordl1[2] | wordr1[2];
    w1_t[3] = wordl1[3] | wordr1[3];
    w2_t[0] = wordl2[0] | wordr2[0];
    w2_t[1] = wordl2[1] | wordr2[1];
    w2_t[2] = wordl2[2] | wordr2[2];
    w2_t[3] = wordl2[3] | wordr2[3];
    w3_t[0] = wordl3[0] | wordr3[0];
    w3_t[1] = wordl3[1] | wordr3[1];
    w3_t[2] = wordl3[2] | wordr3[2];
    w3_t[3] = wordl3[3] | wordr3[3];

    u32x ipad[8];
    u32x opad[8];

    u32x digest[8];

    // kdate

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = 0x41575334;
    w0[1] = hc_swap32 (w0_t[0]);
    w0[2] = hc_swap32 (w0_t[1]);
    w0[3] = hc_swap32 (w0_t[2]);
    w1[0] = hc_swap32 (w0_t[3]);
    w1[1] = hc_swap32 (w1_t[0]);
    w1[2] = hc_swap32 (w1_t[1]);
    w1[3] = hc_swap32 (w1_t[2]);
    w2[0] = hc_swap32 (w1_t[3]);
    w2[1] = hc_swap32 (w2_t[0]);
    w2[2] = hc_swap32 (w2_t[1]);
    w2[3] = hc_swap32 (w2_t[2]);
    w3[0] = hc_swap32 (w2_t[3]);
    w3[1] = hc_swap32 (w3_t[0]);
    w3[2] = hc_swap32 (w3_t[1]);
    w3[3] = hc_swap32 (w3_t[2]);

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = date_buf0[0];
    w0[1] = date_buf0[1];
    w0[2] = date_buf0[2];
    w0[3] = date_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + date_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // kregion

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = region_buf0[0];
    w0[1] = region_buf0[1];
    w0[2] = region_buf0[2];
    w0[3] = region_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + region_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // kservice

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = service_buf0[0];
    w0[1] = service_buf0[1];
    w0[2] = service_buf0[2];
    w0[3] = service_buf0[3];
    w1[0] = 0;
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
    w3[3] = (64 + service_len) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // signingkey

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = 0x61777334;
    w0[1] = 0x5f726571;
    w0[2] = 0x75657374;
    w0[3] = 0x80000000;
    w1[0] = 0;
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
    w3[3] = (64 + 12) * 8;

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    // signature

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_vector_t ctx_signature;

    sha256_hmac_init_vector_64 (&ctx_signature, w0, w1, w2, w3);

    sha256_hmac_update_vector (&ctx_signature, stringtosign_buf, stringtosign_len);

    sha256_hmac_final_vector (&ctx_signature);

    const u32x r0 = ctx_signature.opad.h[DGST_R0];
    const u32x r1 = ctx_signature.opad.h[DGST_R1];
    const u32x r2 = ctx_signature.opad.h[DGST_R2];
    const u32x r3 = ctx_signature.opad.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28700_s08 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
}

KERNEL_FQ void m28700_s16 (KERN_ATTR_ESALT (aws4_sig_v4_t))
{
}
