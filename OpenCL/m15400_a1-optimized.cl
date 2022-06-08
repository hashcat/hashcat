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
#endif

typedef struct chacha20
{
  u32 iv[2];
  u32 plain[2];
  u32 position[2];
  u32 offset;

} chacha20_t;

#define CHACHA_CONST_00 0x61707865
#define CHACHA_CONST_01 0x3320646e
#define CHACHA_CONST_02 0x79622d32
#define CHACHA_CONST_03 0x6b206574

#define QR(a, b, c, d)                  \
  do {                                  \
    x[a] = x[a] + x[b];                 \
    x[d] = hc_rotl32 (x[d] ^ x[a], 16); \
    x[c] = x[c] + x[ d];                \
    x[b] = hc_rotl32 (x[b] ^ x[c], 12); \
    x[a] = x[a] + x[ b];                \
    x[d] = hc_rotl32 (x[d] ^ x[a], 8);  \
    x[c] = x[c] + x[ d];                \
    x[b] = hc_rotl32 (x[b] ^ x[c], 7);  \
  } while (0);

DECLSPEC void chacha20_transform (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32 *position, const u32 offset, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *plain, PRIVATE_AS u32x *digest)
{
  /**
   * Key expansion
   */

  u32x ctx[16];

  ctx[ 0] = CHACHA_CONST_00;
  ctx[ 1] = CHACHA_CONST_01;
  ctx[ 2] = CHACHA_CONST_02;
  ctx[ 3] = CHACHA_CONST_03;
  ctx[ 4] = w0[0];
  ctx[ 5] = w0[1];
  ctx[ 6] = w0[2];
  ctx[ 7] = w0[3];
  ctx[ 8] = w1[0];
  ctx[ 9] = w1[1];
  ctx[10] = w1[2];
  ctx[11] = w1[3];
  ctx[12] = position[0];
  ctx[13] = position[1];
  ctx[14] = iv[1];
  ctx[15] = iv[0];

  /**
   * Generate 64 byte keystream
   */

  u32x x[32];

  x[ 0] = ctx[ 0];
  x[ 1] = ctx[ 1];
  x[ 2] = ctx[ 2];
  x[ 3] = ctx[ 3];
  x[ 4] = ctx[ 4];
  x[ 5] = ctx[ 5];
  x[ 6] = ctx[ 6];
  x[ 7] = ctx[ 7];
  x[ 8] = ctx[ 8];
  x[ 9] = ctx[ 9];
  x[10] = ctx[10];
  x[11] = ctx[11];
  x[12] = ctx[12];
  x[13] = ctx[13];
  x[14] = ctx[14];
  x[15] = ctx[15];

  #pragma unroll
  for (u8 i = 0; i < 10; i++)
  {
    /* Column round */
    QR (0, 4, 8,  12);
    QR (1, 5, 9,  13);
    QR (2, 6, 10, 14);
    QR (3, 7, 11, 15);

    /* Diagonal round */
    QR (0, 5, 10, 15);
    QR (1, 6, 11, 12);
    QR (2, 7, 8,  13);
    QR (3, 4, 9,  14);
  }

  x[ 0] += ctx[ 0];
  x[ 1] += ctx[ 1];
  x[ 2] += ctx[ 2];
  x[ 3] += ctx[ 3];
  x[ 4] += ctx[ 4];
  x[ 5] += ctx[ 5];
  x[ 6] += ctx[ 6];
  x[ 7] += ctx[ 7];
  x[ 8] += ctx[ 8];
  x[ 9] += ctx[ 9];
  x[10] += ctx[10];
  x[11] += ctx[11];
  x[12] += ctx[12];
  x[13] += ctx[13];
  x[14] += ctx[14];
  x[15] += ctx[15];

  if (offset > 56)
  {
    /**
     * Generate a second 64 byte keystream
     */

    ctx[12] += 1;

    #if VECT_SIZE == 1
    if (ctx[12] == 0) ctx[13] += 1;
    #endif

    #if VECT_SIZE >= 2
    if (ctx[12].s0 == 0) ctx[13].s0 += 1;
    if (ctx[12].s1 == 0) ctx[13].s1 += 1;
    #endif

    #if VECT_SIZE >= 4
    if (ctx[12].s2 == 0) ctx[13].s2 += 1;
    if (ctx[12].s3 == 0) ctx[13].s3 += 1;
    #endif

    #if VECT_SIZE >= 8
    if (ctx[12].s4 == 0) ctx[13].s4 += 1;
    if (ctx[12].s5 == 0) ctx[13].s5 += 1;
    if (ctx[12].s6 == 0) ctx[13].s6 += 1;
    if (ctx[12].s7 == 0) ctx[13].s7 += 1;
    #endif

    #if VECT_SIZE >= 16
    if (ctx[12].s8 == 0) ctx[13].s8 += 1;
    if (ctx[12].s9 == 0) ctx[13].s9 += 1;
    if (ctx[12].sa == 0) ctx[13].sa += 1;
    if (ctx[12].sb == 0) ctx[13].sb += 1;
    if (ctx[12].sc == 0) ctx[13].sc += 1;
    if (ctx[12].sd == 0) ctx[13].sd += 1;
    if (ctx[12].se == 0) ctx[13].se += 1;
    if (ctx[12].sf == 0) ctx[13].sf += 1;
    #endif

    x[16] = ctx[ 0];
    x[17] = ctx[ 1];
    x[18] = ctx[ 2];
    x[19] = ctx[ 3];
    x[20] = ctx[ 4];
    x[21] = ctx[ 5];
    x[22] = ctx[ 6];
    x[23] = ctx[ 7];
    x[24] = ctx[ 8];
    x[25] = ctx[ 9];
    x[26] = ctx[10];
    x[27] = ctx[11];
    x[28] = ctx[12];
    x[29] = ctx[13];
    x[30] = ctx[14];
    x[31] = ctx[15];

    #pragma unroll
    for (u8 i = 0; i < 10; i++)
    {
      /* Column round */
      QR (16, 20, 24, 28);
      QR (17, 21, 25, 29);
      QR (18, 22, 26, 30);
      QR (19, 23, 27, 31);

      /* Diagonal round */
      QR (16, 21, 26, 31);
      QR (17, 22, 27, 28);
      QR (18, 23, 24, 29);
      QR (19, 20, 25, 30);
    }

    x[16] += ctx[ 0];
    x[17] += ctx[ 1];
    x[18] += ctx[ 2];
    x[19] += ctx[ 3];
    x[20] += ctx[ 4];
    x[21] += ctx[ 5];
    x[22] += ctx[ 6];
    x[23] += ctx[ 7];
    x[24] += ctx[ 8];
    x[25] += ctx[ 9];
    x[26] += ctx[10];
    x[27] += ctx[11];
    x[28] += ctx[12];
    x[29] += ctx[13];
    x[30] += ctx[14];
    x[31] += ctx[15];
  }

  /**
   * Encrypt plaintext with keystream
   */

  const u32 index  = offset / 4;
  const u32 remain = offset % 4;

  digest[0] = plain[1];
  digest[1] = plain[0];

  if (remain > 0)
  {
    digest[1] ^= x[index + 0] >> ( 0 + remain * 8);
    digest[1] ^= x[index + 1] << (32 - remain * 8);

    digest[0] ^= x[index + 1] >> ( 0 + remain * 8);
    digest[0] ^= x[index + 2] << (32 - remain * 8);
  }
  else
  {
    digest[1] ^= x[index + 0];
    digest[0] ^= x[index + 1];
  }
}

KERNEL_FQ void m15400_m04 (KERN_ATTR_ESALT (chacha20_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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
   * Salt prep
   */

  u32 iv[2]       = { 0 };
  u32 plain[2]    = { 0 };
  u32 position[2] = { 0 };
  u32 offset      = 0;

  position[0] = esalt_bufs[DIGESTS_OFFSET_HOST].position[0];
  position[1] = esalt_bufs[DIGESTS_OFFSET_HOST].position[1];

  offset = esalt_bufs[DIGESTS_OFFSET_HOST].offset;

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];

  plain[0] = esalt_bufs[DIGESTS_OFFSET_HOST].plain[0];
  plain[1] = esalt_bufs[DIGESTS_OFFSET_HOST].plain[1];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x out_len = pw_l_len + pw_r_len;

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

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32x digest[4] = { 0 };

    chacha20_transform (w0, w1, position, offset, iv, plain, digest);

    const u32x r0 = digest[0];
    const u32x r1 = digest[1];
    const u32x r2 = digest[2];
    const u32x r3 = digest[3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m15400_m08 (KERN_ATTR_ESALT (chacha20_t))
{
}

KERNEL_FQ void m15400_m16 (KERN_ATTR_ESALT (chacha20_t))
{
}

KERNEL_FQ void m15400_s04 (KERN_ATTR_ESALT (chacha20_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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
   * Salt prep
   */

  u32 iv[2]       = { 0 };
  u32 plain[2]    = { 0 };
  u32 position[2] = { 0 };
  u32 offset      = 0;

  position[0] = esalt_bufs[DIGESTS_OFFSET_HOST].position[0];
  position[1] = esalt_bufs[DIGESTS_OFFSET_HOST].position[1];

  offset = esalt_bufs[DIGESTS_OFFSET_HOST].offset;

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];

  plain[0] = esalt_bufs[DIGESTS_OFFSET_HOST].plain[0];
  plain[1] = esalt_bufs[DIGESTS_OFFSET_HOST].plain[1];

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

    const u32x out_len = pw_l_len + pw_r_len;

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

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32x digest[4] = { 0 };

    chacha20_transform (w0, w1, position, offset, iv, plain, digest);

    const u32x r0 = digest[0];
    const u32x r1 = digest[1];
    const u32x r2 = digest[2];
    const u32x r3 = digest[3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m15400_s08 (KERN_ATTR_ESALT (chacha20_t))
{
}

KERNEL_FQ void m15400_s16 (KERN_ATTR_ESALT (chacha20_t))
{
}
