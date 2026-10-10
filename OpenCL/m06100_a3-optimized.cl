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
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#endif

// Single-table + zero-key specialized Whirlpool transform for mode 6100.
//
// Two combined optimizations vs the generic whirlpool_transform_vector():
//   1) Zero-key: the incoming chaining value for a single-block raw hash is the
//      all-zero IV, so the round-key schedule is a compile-time constant. We bake
//      the 10 round keys in as immediates and drop the entire key-schedule half.
//   2) Single table: Whirlpool's 8 lookup tables satisfy MTk[x] = ROTR64(MT0[x],
//      8k), so we keep only MT0 in shared memory (2 KB instead of 16 KB) and derive
//      the other 7 lookups by rotation. This frees shared memory for higher
//      occupancy on this latency-bound kernel; the rotates use the idle ALU.
//
// Only s_MT0 is used; the other pointers are ignored. Round keys were verified
// against the Whirlpool empty-string test vector.

#define WTF1(l,v0,v1,v2,v3,v4,v5,v6,v7)                   \
{                                                         \
  (l) =            BOX64 (s_MT0, v8h_from_v64 (v0))       \
      ^ hc_rotr64 (BOX64 (s_MT0, v8g_from_v64 (v1)),  8)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8f_from_v64 (v2)), 16)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8e_from_v64 (v3)), 24)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8d_from_v64 (v4)), 32)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8c_from_v64 (v5)), 40)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8b_from_v64 (v6)), 48)  \
      ^ hc_rotr64 (BOX64 (s_MT0, v8a_from_v64 (v7)), 56); \
}

#define WTROUND(k0,k1,k2,k3,k4,k5,k6,k7)      \
{                                             \
  u64x L0, L1, L2, L3, L4, L5, L6, L7;        \
  WTF1 (L0, S0, S7, S6, S5, S4, S3, S2, S1);  \
  WTF1 (L1, S1, S0, S7, S6, S5, S4, S3, S2);  \
  WTF1 (L2, S2, S1, S0, S7, S6, S5, S4, S3);  \
  WTF1 (L3, S3, S2, S1, S0, S7, S6, S5, S4);  \
  WTF1 (L4, S4, S3, S2, S1, S0, S7, S6, S5);  \
  WTF1 (L5, S5, S4, S3, S2, S1, S0, S7, S6);  \
  WTF1 (L6, S6, S5, S4, S3, S2, S1, S0, S7);  \
  WTF1 (L7, S7, S6, S5, S4, S3, S2, S1, S0);  \
  S0 = L0 ^ (k0);                             \
  S1 = L1 ^ (k1);                             \
  S2 = L2 ^ (k2);                             \
  S3 = L3 ^ (k3);                             \
  S4 = L4 ^ (k4);                             \
  S5 = L5 ^ (k5);                             \
  S6 = L6 ^ (k6);                             \
  S7 = L7 ^ (k7);                             \
}

DECLSPEC void whirlpool_transform_transport_vector (PRIVATE_AS const u32x *w, PRIVATE_AS u32x *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
{
  const u64x W0 = hl32_to_64 (w[ 0], w[ 1]);
  const u64x W1 = hl32_to_64 (w[ 2], w[ 3]);
  const u64x W2 = hl32_to_64 (w[ 4], w[ 5]);
  const u64x W3 = hl32_to_64 (w[ 6], w[ 7]);
  const u64x W4 = hl32_to_64 (w[ 8], w[ 9]);
  const u64x W5 = hl32_to_64 (w[10], w[11]);
  const u64x W6 = hl32_to_64 (w[12], w[13]);
  const u64x W7 = hl32_to_64 (w[14], w[15]);

  // digest / key is the all-zero IV, so S = 0 ^ W = W

  u64x S0 = W0;
  u64x S1 = W1;
  u64x S2 = W2;
  u64x S3 = W3;
  u64x S4 = W4;
  u64x S5 = W5;
  u64x S6 = W6;
  u64x S7 = W7;

  WTROUND (0x300beec0af902967UL, 0x2828282828282828UL, 0x2828282828282828UL, 0x2828282828282828UL, 0x2828282828282828UL, 0x2828282828282828UL, 0x2828282828282828UL, 0x2828282828282828UL);
  WTROUND (0x3bab89f8ead1ae24UL, 0x4445456645e9cbafUL, 0x70fea4a4c5a4b289UL, 0xc5faa9e1e1cce1a0UL, 0x48acc05cfcfcb8fcUL, 0x8ff70e26908f8f69UL, 0x96791407d7857979UL, 0xf8a8f868b8c878f8UL);
  WTROUND (0xd319bfdb30467058UL, 0x295b23d1afcf37dbUL, 0x012c8ac28b95ac98UL, 0x81639eb1c0b206a7UL, 0x445e607ab0b209dbUL, 0x735b2ccfbc8cbc71UL, 0xdc670924efedddd3UL, 0x7b8d3bf0d73b7d19UL);
  WTROUND (0x38beaac1de116586UL, 0x687cf3d04a87337fUL, 0xf337fadb98adf057UL, 0xc5e24258ee358dbcUL, 0x1109f0e8996e247eUL, 0x01c5d6ed10b03401UL, 0xfbc952f17b28ecd3UL, 0x3256dc0cc7f12740UL);
  WTROUND (0xaf25a520949bcf14UL, 0xc13626a9e3c4534dUL, 0xe60f7d867740f9e1UL, 0x915de6bbe26a0629UL, 0x965a54cc4cfe5e8dUL, 0xbee931cb62323aa6UL, 0xb17b591896846a47UL, 0xd4f0c9362759af31UL);
  WTROUND (0xe2f9b5c025370bb0UL, 0x392bcba2168494a5UL, 0x608af8cefa348c14UL, 0x7aa53764418c9219UL, 0xb3f346a1fa833f89UL, 0x97493f487802cf7cUL, 0xdcade8ba1e008f23UL, 0x92774f49edb0323dUL);
  WTROUND (0x75416382774dff2fUL, 0xfffa38d055034600UL, 0xbf7d02493e98f361UL, 0xf4a860c29ae5ce0bUL, 0xc8df5a44ee5d9d27UL, 0x23f45a55047500a4UL, 0xb016101202f9e28cUL, 0xac30cd296833331dUL);
  WTROUND (0x036bf1826884ad89UL, 0x9940c662d8467163UL, 0x4c433e174b19c210UL, 0xe29ccfd34cff86c5UL, 0x21ff11a042df2653UL, 0x1b8e00cb6ce44b13UL, 0xa6123bf7a347b7ceUL, 0xd918900e3b2833caUL);
  WTROUND (0xd01c677a0a9a2cf9UL, 0x2a942f534a63b6b2UL, 0x88422246feaca8b4UL, 0x474a5cc73d583559UL, 0x74a6925da55c6fa1UL, 0x7717e68cc4735c39UL, 0x082a3b0b53ec1ac6UL, 0x2af658eb814de762UL);
  WTROUND (0x489548b601eebc3aUL, 0xa50d6bc66bed8e81UL, 0xe0ce3dcf88265a75UL, 0xc28c4adbc0f69ce9UL, 0x54b79cd57f718513UL, 0x43414b8a977d0b7bUL, 0x631935bbdbf6157aUL, 0x6a7a4ef637018227UL);

  const u64x D0 = S0 ^ W0;
  const u64x D1 = S1 ^ W1;
  const u64x D2 = S2 ^ W2;
  const u64x D3 = S3 ^ W3;
  const u64x D4 = S4 ^ W4;
  const u64x D5 = S5 ^ W5;
  const u64x D6 = S6 ^ W6;
  const u64x D7 = S7 ^ W7;

  digest[ 0] = h32_from_64 (D0);
  digest[ 1] = l32_from_64 (D0);
  digest[ 2] = h32_from_64 (D1);
  digest[ 3] = l32_from_64 (D1);
  digest[ 4] = h32_from_64 (D2);
  digest[ 5] = l32_from_64 (D2);
  digest[ 6] = h32_from_64 (D3);
  digest[ 7] = l32_from_64 (D3);
  digest[ 8] = h32_from_64 (D4);
  digest[ 9] = l32_from_64 (D4);
  digest[10] = h32_from_64 (D5);
  digest[11] = l32_from_64 (D5);
  digest[12] = h32_from_64 (D6);
  digest[13] = l32_from_64 (D6);
  digest[14] = h32_from_64 (D7);
  digest[15] = l32_from_64 (D7);
}

DECLSPEC void m06100m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w[16];

    w[ 0] = w0lr;
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = pw_len * 8;

    /**
     * Whirlool
     */

    u32x dgst[16];

    dgst[ 0] = 0;
    dgst[ 1] = 0;
    dgst[ 2] = 0;
    dgst[ 3] = 0;
    dgst[ 4] = 0;
    dgst[ 5] = 0;
    dgst[ 6] = 0;
    dgst[ 7] = 0;
    dgst[ 8] = 0;
    dgst[ 9] = 0;
    dgst[10] = 0;
    dgst[11] = 0;
    dgst[12] = 0;
    dgst[13] = 0;
    dgst[14] = 0;
    dgst[15] = 0;

    whirlpool_transform_transport_vector (w, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

    COMPARE_M_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

DECLSPEC void m06100s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
{
  /**
   * modifiers are taken from args
   */

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w[16];

    w[ 0] = w0lr;
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = pw_len * 8;

    /**
     * Whirlool
     */

    u32x dgst[16];

    dgst[ 0] = 0;
    dgst[ 1] = 0;
    dgst[ 2] = 0;
    dgst[ 3] = 0;
    dgst[ 4] = 0;
    dgst[ 5] = 0;
    dgst[ 6] = 0;
    dgst[ 7] = 0;
    dgst[ 8] = 0;
    dgst[ 9] = 0;
    dgst[10] = 0;
    dgst[11] = 0;
    dgst[12] = 0;
    dgst[13] = 0;
    dgst[14] = 0;
    dgst[15] = 0;

    whirlpool_transform_transport_vector (w, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

    COMPARE_S_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ KERNEL_FA void m06100_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  // Only MT0 is stored in shared memory (2 KB instead of 16 KB); the other 7
  // tables are derived on the fly via MTk[x] == ROTR64 (MT0[x], 8k).
  LOCAL_VK u64 s_MT0[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
  }

  SYNC_THREADS ();

  SHM_TYPE u64 *s_MT1 = s_MT0;
  SHM_TYPE u64 *s_MT2 = s_MT0;
  SHM_TYPE u64 *s_MT3 = s_MT0;
  SHM_TYPE u64 *s_MT4 = s_MT0;
  SHM_TYPE u64 *s_MT5 = s_MT0;
  SHM_TYPE u64 *s_MT6 = s_MT0;
  SHM_TYPE u64 *s_MT7 = s_MT0;

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = s_MT0;
  CONSTANT_AS u64a *s_MT2 = s_MT0;
  CONSTANT_AS u64a *s_MT3 = s_MT0;
  CONSTANT_AS u64a *s_MT4 = s_MT0;
  CONSTANT_AS u64a *s_MT5 = s_MT0;
  CONSTANT_AS u64a *s_MT6 = s_MT0;
  CONSTANT_AS u64a *s_MT7 = s_MT0;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m06100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ KERNEL_FA void m06100_m08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  // Only MT0 is stored in shared memory (2 KB instead of 16 KB); the other 7
  // tables are derived on the fly via MTk[x] == ROTR64 (MT0[x], 8k).
  LOCAL_VK u64 s_MT0[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
  }

  SYNC_THREADS ();

  SHM_TYPE u64 *s_MT1 = s_MT0;
  SHM_TYPE u64 *s_MT2 = s_MT0;
  SHM_TYPE u64 *s_MT3 = s_MT0;
  SHM_TYPE u64 *s_MT4 = s_MT0;
  SHM_TYPE u64 *s_MT5 = s_MT0;
  SHM_TYPE u64 *s_MT6 = s_MT0;
  SHM_TYPE u64 *s_MT7 = s_MT0;

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = s_MT0;
  CONSTANT_AS u64a *s_MT2 = s_MT0;
  CONSTANT_AS u64a *s_MT3 = s_MT0;
  CONSTANT_AS u64a *s_MT4 = s_MT0;
  CONSTANT_AS u64a *s_MT5 = s_MT0;
  CONSTANT_AS u64a *s_MT6 = s_MT0;
  CONSTANT_AS u64a *s_MT7 = s_MT0;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m06100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ KERNEL_FA void m06100_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m06100_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  // Only MT0 is stored in shared memory (2 KB instead of 16 KB); the other 7
  // tables are derived on the fly via MTk[x] == ROTR64 (MT0[x], 8k).
  LOCAL_VK u64 s_MT0[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
  }

  SYNC_THREADS ();

  SHM_TYPE u64 *s_MT1 = s_MT0;
  SHM_TYPE u64 *s_MT2 = s_MT0;
  SHM_TYPE u64 *s_MT3 = s_MT0;
  SHM_TYPE u64 *s_MT4 = s_MT0;
  SHM_TYPE u64 *s_MT5 = s_MT0;
  SHM_TYPE u64 *s_MT6 = s_MT0;
  SHM_TYPE u64 *s_MT7 = s_MT0;

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = s_MT0;
  CONSTANT_AS u64a *s_MT2 = s_MT0;
  CONSTANT_AS u64a *s_MT3 = s_MT0;
  CONSTANT_AS u64a *s_MT4 = s_MT0;
  CONSTANT_AS u64a *s_MT5 = s_MT0;
  CONSTANT_AS u64a *s_MT6 = s_MT0;
  CONSTANT_AS u64a *s_MT7 = s_MT0;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m06100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ KERNEL_FA void m06100_s08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  // Only MT0 is stored in shared memory (2 KB instead of 16 KB); the other 7
  // tables are derived on the fly via MTk[x] == ROTR64 (MT0[x], 8k).
  LOCAL_VK u64 s_MT0[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
  }

  SYNC_THREADS ();

  SHM_TYPE u64 *s_MT1 = s_MT0;
  SHM_TYPE u64 *s_MT2 = s_MT0;
  SHM_TYPE u64 *s_MT3 = s_MT0;
  SHM_TYPE u64 *s_MT4 = s_MT0;
  SHM_TYPE u64 *s_MT5 = s_MT0;
  SHM_TYPE u64 *s_MT6 = s_MT0;
  SHM_TYPE u64 *s_MT7 = s_MT0;

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = s_MT0;
  CONSTANT_AS u64a *s_MT2 = s_MT0;
  CONSTANT_AS u64a *s_MT3 = s_MT0;
  CONSTANT_AS u64a *s_MT4 = s_MT0;
  CONSTANT_AS u64a *s_MT5 = s_MT0;
  CONSTANT_AS u64a *s_MT6 = s_MT0;
  CONSTANT_AS u64a *s_MT7 = s_MT0;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m06100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ KERNEL_FA void m06100_s16 (KERN_ATTR_BASIC ())
{
}
