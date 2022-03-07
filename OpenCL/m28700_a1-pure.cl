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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
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

KERNEL_FQ void m28700_mxx (KERN_ATTR_RULES_ESALT (aws4_sig_v4_t))
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = hc_swap32_S (pws[gid].i[idx]);
  }

  const u32 date_len = esalt_bufs[DIGESTS_OFFSET_HOST].date_len;

  u32 date_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < date_len; i += 4, idx += 1)
  {
    date_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[idx]);
  }

  const u32 region_len = esalt_bufs[DIGESTS_OFFSET_HOST].region_len;

  u32 region_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < region_len; i += 4, idx += 1)
  {
    region_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[idx]);
  }

  const u32 service_len = esalt_bufs[DIGESTS_OFFSET_HOST].service_len;

  u32 service_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < service_len; i += 4, idx += 1)
  {
    service_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[idx]);
  }

  const u32 stringtosign_len = esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign_len;

  u32 stringtosign_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < stringtosign_len; i += 4, idx += 1)
  {
    stringtosign_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = hc_swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    u32 w_t[64];

    w_t[0] = 0x41575334;

    for (u32 i = 1; i < 64; i++)
    {
      w_t[i] = c[i - 1];
    }

    // kdate

    sha256_hmac_ctx_t ctx_kdate;

    sha256_hmac_init (&ctx_kdate, w_t, pw_len + comb_len + 4);

    sha256_hmac_update (&ctx_kdate, date_buf, date_len);

    sha256_hmac_final (&ctx_kdate);

    // kregion

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx_kdate.opad.h[0];
    w0[1] = ctx_kdate.opad.h[1];
    w0[2] = ctx_kdate.opad.h[2];
    w0[3] = ctx_kdate.opad.h[3];
    w1[0] = ctx_kdate.opad.h[4];
    w1[1] = ctx_kdate.opad.h[5];
    w1[2] = ctx_kdate.opad.h[6];
    w1[3] = ctx_kdate.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_kregion;

    sha256_hmac_init_64 (&ctx_kregion, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_kregion, region_buf, region_len);

    sha256_hmac_final (&ctx_kregion);

    // kservice

    w0[0] = ctx_kregion.opad.h[0];
    w0[1] = ctx_kregion.opad.h[1];
    w0[2] = ctx_kregion.opad.h[2];
    w0[3] = ctx_kregion.opad.h[3];
    w1[0] = ctx_kregion.opad.h[4];
    w1[1] = ctx_kregion.opad.h[5];
    w1[2] = ctx_kregion.opad.h[6];
    w1[3] = ctx_kregion.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_kservice;

    sha256_hmac_init_64 (&ctx_kservice, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_kservice, service_buf, service_len);

    sha256_hmac_final (&ctx_kservice);

    // signingkey

    w0[0] = ctx_kservice.opad.h[0];
    w0[1] = ctx_kservice.opad.h[1];
    w0[2] = ctx_kservice.opad.h[2];
    w0[3] = ctx_kservice.opad.h[3];
    w1[0] = ctx_kservice.opad.h[4];
    w1[1] = ctx_kservice.opad.h[5];
    w1[2] = ctx_kservice.opad.h[6];
    w1[3] = ctx_kservice.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_signingkey;

    sha256_hmac_init_64 (&ctx_signingkey, w0, w1, w2, w3);

    // aws4_request

    w0[0] = 0x61777334;
    w0[1] = 0x5f726571;
    w0[2] = 0x75657374;
    w0[3] = 0;
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
    w3[3] = 0;

    sha256_hmac_update_64 (&ctx_signingkey, w0, w1, w2, w3, 12);

    sha256_hmac_final (&ctx_signingkey);

    // signature

    w0[0] = ctx_signingkey.opad.h[0];
    w0[1] = ctx_signingkey.opad.h[1];
    w0[2] = ctx_signingkey.opad.h[2];
    w0[3] = ctx_signingkey.opad.h[3];
    w1[0] = ctx_signingkey.opad.h[4];
    w1[1] = ctx_signingkey.opad.h[5];
    w1[2] = ctx_signingkey.opad.h[6];
    w1[3] = ctx_signingkey.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_signature;

    sha256_hmac_init_64 (&ctx_signature, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_signature, stringtosign_buf, stringtosign_len);

    sha256_hmac_final (&ctx_signature);

    const u32 r0 = ctx_signature.opad.h[DGST_R0];
    const u32 r1 = ctx_signature.opad.h[DGST_R1];
    const u32 r2 = ctx_signature.opad.h[DGST_R2];
    const u32 r3 = ctx_signature.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28700_sxx (KERN_ATTR_RULES_ESALT (aws4_sig_v4_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = hc_swap32_S (pws[gid].i[idx]);
  }

  const u32 date_len = esalt_bufs[DIGESTS_OFFSET_HOST].date_len;

  u32 date_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < date_len; i += 4, idx += 1)
  {
    date_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].date[idx]);
  }

  const u32 region_len = esalt_bufs[DIGESTS_OFFSET_HOST].region_len;

  u32 region_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < region_len; i += 4, idx += 1)
  {
    region_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].region[idx]);
  }

  const u32 service_len = esalt_bufs[DIGESTS_OFFSET_HOST].service_len;

  u32 service_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < service_len; i += 4, idx += 1)
  {
    service_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].service[idx]);
  }

  const u32 stringtosign_len = esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign_len;

  u32 stringtosign_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < stringtosign_len; i += 4, idx += 1)
  {
    stringtosign_buf[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].stringtosign[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = hc_swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    u32 w_t[64];

    w_t[0] = 0x41575334;

    for (u32 i = 1; i < 64; i++)
    {
      w_t[i] = c[i - 1];
    }

    // kdate

    sha256_hmac_ctx_t ctx_kdate;

    sha256_hmac_init (&ctx_kdate, w_t, pw_len + comb_len + 4);

    sha256_hmac_update (&ctx_kdate, date_buf, date_len);

    sha256_hmac_final (&ctx_kdate);

    // kregion

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx_kdate.opad.h[0];
    w0[1] = ctx_kdate.opad.h[1];
    w0[2] = ctx_kdate.opad.h[2];
    w0[3] = ctx_kdate.opad.h[3];
    w1[0] = ctx_kdate.opad.h[4];
    w1[1] = ctx_kdate.opad.h[5];
    w1[2] = ctx_kdate.opad.h[6];
    w1[3] = ctx_kdate.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_kregion;

    sha256_hmac_init_64 (&ctx_kregion, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_kregion, region_buf, region_len);

    sha256_hmac_final (&ctx_kregion);

    // kservice

    w0[0] = ctx_kregion.opad.h[0];
    w0[1] = ctx_kregion.opad.h[1];
    w0[2] = ctx_kregion.opad.h[2];
    w0[3] = ctx_kregion.opad.h[3];
    w1[0] = ctx_kregion.opad.h[4];
    w1[1] = ctx_kregion.opad.h[5];
    w1[2] = ctx_kregion.opad.h[6];
    w1[3] = ctx_kregion.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_kservice;

    sha256_hmac_init_64 (&ctx_kservice, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_kservice, service_buf, service_len);

    sha256_hmac_final (&ctx_kservice);

    // signingkey

    w0[0] = ctx_kservice.opad.h[0];
    w0[1] = ctx_kservice.opad.h[1];
    w0[2] = ctx_kservice.opad.h[2];
    w0[3] = ctx_kservice.opad.h[3];
    w1[0] = ctx_kservice.opad.h[4];
    w1[1] = ctx_kservice.opad.h[5];
    w1[2] = ctx_kservice.opad.h[6];
    w1[3] = ctx_kservice.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_signingkey;

    sha256_hmac_init_64 (&ctx_signingkey, w0, w1, w2, w3);

    // aws4_request

    w0[0] = 0x61777334;
    w0[1] = 0x5f726571;
    w0[2] = 0x75657374;
    w0[3] = 0;
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
    w3[3] = 0;

    sha256_hmac_update_64 (&ctx_signingkey, w0, w1, w2, w3, 12);

    sha256_hmac_final (&ctx_signingkey);

    // signature

    w0[0] = ctx_signingkey.opad.h[0];
    w0[1] = ctx_signingkey.opad.h[1];
    w0[2] = ctx_signingkey.opad.h[2];
    w0[3] = ctx_signingkey.opad.h[3];
    w1[0] = ctx_signingkey.opad.h[4];
    w1[1] = ctx_signingkey.opad.h[5];
    w1[2] = ctx_signingkey.opad.h[6];
    w1[3] = ctx_signingkey.opad.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_ctx_t ctx_signature;

    sha256_hmac_init_64 (&ctx_signature, w0, w1, w2, w3);

    sha256_hmac_update (&ctx_signature, stringtosign_buf, stringtosign_len);

    sha256_hmac_final (&ctx_signature);

    const u32 r0 = ctx_signature.opad.h[DGST_R0];
    const u32 r1 = ctx_signature.opad.h[DGST_R1];
    const u32 r2 = ctx_signature.opad.h[DGST_R2];
    const u32 r3 = ctx_signature.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
