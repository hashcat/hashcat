/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"


inline u64 hl8_to_32(const u8 a, const u8 b, const u8 c, const u8 d)
{
  return as_uint((uchar4) (a, b, c, d));
}

__constant u64a blake2b_IV[8] =
{
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

__constant u8a blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define BLAKE2B_G(r,i,a,b,c,d)                \
  do {                                        \
    a = a + b + m[blake2b_sigma[r][2*i+0]];   \
    d = rotr64(d ^ a, 32);                    \
    c = c + d;                                \
    b = rotr64(b ^ c, 24);                    \
    a = a + b + m[blake2b_sigma[r][2*i+1]];   \
    d = rotr64(d ^ a, 16);                    \
    c = c + d;                                \
    b = rotr64(b ^ c, 63);                    \
  } while(0)

#define BLAKE2B_ROUND(r)                    \
  do {                                      \
    BLAKE2B_G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    BLAKE2B_G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    BLAKE2B_G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    BLAKE2B_G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    BLAKE2B_G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    BLAKE2B_G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    BLAKE2B_G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    BLAKE2B_G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
} while(0)

void blake2b_transform(const u32x pw[16], const u32x out_len, const u64 p_salt[2], const u64 p_key[16], const u8 key_length, const u8 digest_length, u64x digest[8])
{
  /*
   * Blake2b Init Param
   */

  u8  p_digest_length = digest_length;
  u8  p_key_length    = key_length;
  u8  p_fanout        = 1;
  u8  p_depth         = 1;
  u32 p_leaf_length   = 0;
  u32 p_node_offset   = 0;
  u32 p_xof_length    = 0;
  u8  p_node_depth    = 0;
  u8  p_inner_length  = 0;
  u8  p_reserved[14];
  u8  p_personnel[BLAKE2B_PERSONALBYTES];

  /*
   * Blake2b Init State
   */

  u64x s_h[8];
  u64x s_t[2];
  u64x s_f[2];
  u32x s_buflen;
  u32x s_outlen;
  u8x  s_last_node;

  s_h[0] = blake2b_IV[0] ^ hl8_to_32(p_digest_length, p_key_length, p_fanout, p_depth);
  s_h[1] = blake2b_IV[1];
  s_h[2] = blake2b_IV[2];
  s_h[3] = blake2b_IV[3];
  s_h[4] = blake2b_IV[4] ^ p_salt[0];
  s_h[5] = blake2b_IV[5] ^ p_salt[1];
  s_h[6] = blake2b_IV[6];
  s_h[7] = blake2b_IV[7];
  s_t[0] = hl32_to_64(0, out_len);
  s_t[1] =  0;
  s_f[0] = -1;
  s_f[1] =  0;
  s_outlen = 0;
  s_last_node = 0;

  /*
   * Compress
   */

  u64x v[16];
  u64x m[16];

  m[0] = swap64(hl32_to_64(pw[ 1], pw[ 0]));
  m[1] = swap64(hl32_to_64(pw[ 3], pw[ 2]));
  m[2] = swap64(hl32_to_64(pw[ 5], pw[ 4]));
  m[3] = swap64(hl32_to_64(pw[ 7], pw[ 6]));
  m[4] = swap64(hl32_to_64(pw[ 9], pw[ 8]));
  m[5] = swap64(hl32_to_64(pw[11], pw[10]));
  m[6] = swap64(hl32_to_64(pw[13], pw[12]));
  m[7] = swap64(hl32_to_64(pw[15], pw[14]));
  m[8] = 0;
  m[9] = 0;
  m[10] = 0;
  m[11] = 0;
  m[12] = 0;
  m[13] = 0;
  m[14] = 0;
  m[15] = 0;

  v[ 0] = s_h[0];
  v[ 1] = s_h[1];
  v[ 2] = s_h[2];
  v[ 3] = s_h[3];
  v[ 4] = s_h[4];
  v[ 5] = s_h[5];
  v[ 6] = s_h[6];
  v[ 7] = s_h[7];
  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = blake2b_IV[4] ^ s_t[0];
  v[13] = blake2b_IV[5] ^ s_t[1];
  v[14] = blake2b_IV[6] ^ s_f[0];
  v[15] = blake2b_IV[7] ^ s_f[1];

  BLAKE2B_ROUND( 0);
  BLAKE2B_ROUND( 1);
  BLAKE2B_ROUND( 2);
  BLAKE2B_ROUND( 3);
  BLAKE2B_ROUND( 4);
  BLAKE2B_ROUND( 5);
  BLAKE2B_ROUND( 6);
  BLAKE2B_ROUND( 7);
  BLAKE2B_ROUND( 8);
  BLAKE2B_ROUND( 9);
  BLAKE2B_ROUND(10);
  BLAKE2B_ROUND(11);

  for (int i = 0; i < 8; ++i) {
    s_h[i] = s_h[i] ^ v[i] ^ v[i + 8];
    digest[i] = s_h[i];
  }
}

__kernel void m00600_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{ 
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

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

  const u32 pw_len = pws[gid].pw_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE) {

    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect(pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x pw[16];

    pw[ 1] = swap32(w0[0]);
    pw[ 0] = swap32(w0[1]);
    pw[ 3] = swap32(w0[2]);
    pw[ 2] = swap32(w0[3]);
    pw[ 5] = swap32(w1[0]);
    pw[ 4] = swap32(w1[1]);
    pw[ 7] = swap32(w1[2]);
    pw[ 6] = swap32(w1[3]);
    pw[ 9] = swap32(w2[0]);
    pw[ 8] = swap32(w2[1]);
    pw[11] = swap32(w2[2]);
    pw[10] = swap32(w2[3]);
    pw[13] = swap32(w3[0]);
    pw[12] = swap32(w3[1]);
    pw[15] = swap32(w3[2]);
    pw[14] = swap32(w3[3]);

    u64x digest[8];

    digest[0] = 0;
    digest[1] = 0;
    digest[2] = 0;
    digest[3] = 0;
    digest[4] = 0;
    digest[5] = 0;
    digest[6] = 0;
    digest[7] = 0;

    u64 p_salt[2] = { 0, 0 };
    u64 p_key[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    blake2b_transform(pw, out_len, p_salt, p_key, 0, BLAKE2B_OUTBYTES, digest);

    const u32x r0 = h32_from_64(digest[0]);
    const u32x r1 = l32_from_64(digest[0]);
    const u32x r2 = h32_from_64(digest[1]);
    const u32x r3 = l32_from_64(digest[1]);

    COMPARE_M_SIMD(r0, r1, r2, r3);
  } 
}

__kernel void m00600_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m00600_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m00600_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{ 
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };
 
  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE) {

    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };
    
    const u32x out_len = apply_rules_vect(pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x pw[16];

    pw[ 1] = swap32(w0[0]);
    pw[ 0] = swap32(w0[1]);
    pw[ 3] = swap32(w0[2]);
    pw[ 2] = swap32(w0[3]);
    pw[ 5] = swap32(w1[0]);
    pw[ 4] = swap32(w1[1]);
    pw[ 7] = swap32(w1[2]);
    pw[ 6] = swap32(w1[3]);
    pw[ 9] = swap32(w2[0]);
    pw[ 8] = swap32(w2[1]);
    pw[11] = swap32(w2[2]);
    pw[10] = swap32(w2[3]);
    pw[13] = swap32(w3[0]);
    pw[12] = swap32(w3[1]);
    pw[15] = swap32(w3[2]);
    pw[14] = swap32(w3[3]);

    u64x digest[8];

    digest[0] = 0;
    digest[1] = 0;
    digest[2] = 0;
    digest[3] = 0;
    digest[4] = 0;
    digest[5] = 0;
    digest[6] = 0;
    digest[7] = 0;

    u64 p_salt[2] = { 0, 0 };
    u64 p_key[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    blake2b_transform(pw, out_len, p_salt, p_key, 0, BLAKE2B_OUTBYTES, digest);

    const u32x r0 = h32_from_64(digest[0]);
    const u32x r1 = l32_from_64(digest[0]);
    const u32x r2 = h32_from_64(digest[1]);
    const u32x r3 = l32_from_64(digest[1]);

    COMPARE_S_SIMD(r0, r1, r2, r3);
  }  
}

__kernel void m00600_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m00600_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
