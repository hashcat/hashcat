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
#include "inc_simd.cl"

u64 rotr64_w(const u64x w, const u32 c)
{
  return (w >> c) | (w << (64 - c));
}

u64 load64(const void *src)
{
  const u8 *p = ( const u8 * )src;
  return ((u64)(p[0]) <<  0) |
         ((u64)(p[1]) <<  8) |
         ((u64)(p[2]) << 16) |
         ((u64)(p[3]) << 24) |
         ((u64)(p[4]) << 32) |
         ((u64)(p[5]) << 40) |
         ((u64)(p[6]) << 48) |
         ((u64)(p[7]) << 56) ;
}

u64 load64_reverse(const void *src)
{
  const u8 *p = ( const u8 * )src;
  return ((u64)(p[7]) <<  0) |
         ((u64)(p[6]) <<  8) |
         ((u64)(p[5]) << 16) |
         ((u64)(p[4]) << 24) |
         ((u64)(p[3]) << 32) |
         ((u64)(p[2]) << 40) |
         ((u64)(p[1]) << 48) |
         ((u64)(p[0]) << 56) ;
}

typedef struct
{
  u8  digest_length;                    /*  1 */
  u8  key_length;                       /*  2 */
  u8  fanout;                           /*  3 */
  u8  depth;                            /*  4 */
  u32 leaf_length;                      /*  8 */
  u32 node_offset;                      /* 12 */
  u32 xof_length;                       /* 16 */
  u8  node_depth;                       /* 17 */
  u8  inner_length;                     /* 18 */
  u8  reserved[14];                     /* 32 */
  u8  salt[BLAKE2B_SALTBYTES];          /* 48 */
  u8  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
} blake2b_param;

typedef struct
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u8  buf[BLAKE2B_BLOCKBYTES];
  u32 buflen;
  u32 outlen;
  u8  last_node;
} blake2b_state;

__constant u64a blake2b_IV[8] =
{
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

__constant u8 blake2b_sigma[12][16] =
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
    d = rotr64_w(d ^ a, 32);                  \
    c = c + d;                                \
    b = rotr64_w(b ^ c, 24);                  \
    a = a + b + m[blake2b_sigma[r][2*i+1]];   \
    d = rotr64_w(d ^ a, 16);                  \
    c = c + d;                                \
    b = rotr64_w(b ^ c, 63);                  \
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

void blake2b_compress (const u32x pw[16], const u64 pw_len, u64x digest[8])
{

  /*
   * Blake2b Init Param
   */

  u32 i;
  blake2b_param P[1];

  P->digest_length = BLAKE2B_OUTBYTES;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  P->leaf_length = 0;
  P->node_offset = 0;
  P->xof_length = 0;
  P->node_depth = 0;
  P->inner_length = 0;

  for (i = 0; i < 14; i++) 
    P->reserved[i] = 0;
  for (i = 0; i < BLAKE2B_SALTBYTES; i++) 
    P->salt[i] = 0;
  for (i = 0; i < BLAKE2B_PERSONALBYTES; i++) 
    P->personal[i] = 0;

  /*
   * Blake2b Init State
   */

  blake2b_state S[1];

  for (i = 0; i < 8; ++i) 
    S->h[i] = blake2b_IV[i];

  S->t[0] =  pw_len;
  S->t[1] =  0;
  S->f[0] = -1;
  S->f[1] =  0;
  S->buflen = 0;
  S->outlen = 0;
  S->last_node = 0;

  const u8 *p = (const u8 *)(P);

  /* IV XOR ParamBlock */
  for (i = 0; i < 8; ++i)
    S->h[i] ^= load64(p + sizeof(S->h[i]) * i);

  S->outlen = P->digest_length;

  /*
   * Compress
   */

  u64 v[16];
  u64 m[16];

  p = (const u8 *)pw;

  for (i = 0; i < 8; ++i)
    m[i] = load64_reverse(p + sizeof(m[i]) * i);

  m[8] = 0;
  m[9] = 0;
  m[10] = 0;
  m[11] = 0;
  m[12] = 0;
  m[13] = 0;
  m[14] = 0;
  m[15] = 0;

  for (i = 0; i < 8; ++i)
    v[i] = S->h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = blake2b_IV[4] ^ S->t[0];
  v[13] = blake2b_IV[5] ^ S->t[1];
  v[14] = blake2b_IV[6] ^ S->f[0];
  v[15] = blake2b_IV[7] ^ S->f[1];

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

  for (i = 0; i < 8; ++i) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    digest[i] = load64_reverse(&(S->h[i]));
  }
}

void m00600s (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const u32x *words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

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

  u32 w0l = pws[gid].i[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE) {

    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0 = w0l | w0r;
    u32x pw[16];

    pw[ 1] = w0;
    pw[ 0] = pws[gid].i[ 1];
    pw[ 3] = pws[gid].i[ 2];
    pw[ 2] = pws[gid].i[ 3];
    pw[ 5] = pws[gid].i[ 4];
    pw[ 4] = pws[gid].i[ 5];
    pw[ 7] = pws[gid].i[ 6];
    pw[ 6] = pws[gid].i[ 7];
    pw[ 9] = pws[gid].i[ 8];
    pw[ 8] = pws[gid].i[ 9];
    pw[11] = pws[gid].i[10];
    pw[10] = pws[gid].i[11];
    pw[13] = pws[gid].i[12];
    pw[12] = pws[gid].i[13];
    pw[15] = pws[gid].i[14];
    pw[15] = pws[gid].i[15];

    u32 pw_len = pws[gid].pw_len;

    u64x digest[8];

    digest[0] = 0;
    digest[1] = 0;
    digest[2] = 0;
    digest[3] = 0;
    digest[4] = 0;
    digest[5] = 0;
    digest[6] = 0;
    digest[7] = 0;

    blake2b_compress(pw, pw_len, digest);

    const u32x r0 = h32_from_64(digest[0]);
    const u32x r1 = l32_from_64(digest[0]);
    const u32x r2 = h32_from_64(digest[1]);
    const u32x r3 = l32_from_64(digest[1]);

    COMPARE_S_SIMD(r0, r1, r2, r3);
  }
}

__kernel void m00600_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{

}

__kernel void m00600_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m00600_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}


__kernel void m00600_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const u32x *words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{ 
 
  m00600s(pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);  
}

__kernel void m00600_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m00600_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
