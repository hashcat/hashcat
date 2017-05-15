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

#define CHACHA_CONST_00 0x61707865
#define CHACHA_CONST_01 0x3320646e
#define CHACHA_CONST_02 0x79622d32
#define CHACHA_CONST_03 0x6b206574

#define QR(a, b, c, d)                \
  do {                                \
    x[a] = x[a] + x[b];               \
    x[d] = rotl32(x[d] ^ x[a], 16);   \
    x[c] = x[c] + x[d];               \
    x[b] = rotl32(x[b] ^ x[c], 12);   \
    x[a] = x[a] + x[b];               \
    x[d] = rotl32(x[d] ^ x[a], 8);    \
    x[c] = x[c] + x[d];               \
    x[b] = rotl32(x[b] ^ x[c], 7);    \
  } while (0);

void chacha20_transform (const u32x w0[4], const u32x w1[4], const u32 position[2], const u32 offset, const u32 iv[2], const u32 plain[4], u32x digest[4])
{
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

  u32x x[16];

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

  for (u8 i = 0; i < 10; ++i) 
  {
    /* Column round */
    QR(0, 4, 8,  12);
    QR(1, 5, 9,  13);
    QR(2, 6, 10, 14);
    QR(3, 7, 11, 15);

    /* Diagonal round */
    QR(0, 5, 10, 15);
    QR(1, 6, 11, 12);
    QR(2, 7, 8,  13);
    QR(3, 4, 9,  14);
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


  u32 index  = offset / 4;
  u32 remain = offset % 4;

  //printf("index: %d, offset: %d, remain: %d\n", index, offset, remain);

  digest[0] = plain[1];
  digest[1] = plain[0];

  if (remain > 0)
  {
    u32x tmp[3];
    tmp[0] = x[index + 0];
    tmp[1] = x[index + 1];
    tmp[2] = x[index + 2];

    digest[1] ^= tmp[0] >> (remain * 8);
    digest[1] ^= tmp[1] << (32 - remain * 8);

    digest[0] ^= tmp[1] >> (remain * 8);
    digest[0] ^= tmp[2] << (32 - remain * 8); 
  }
  else
  {
    digest[1] ^= x[index + 0];
    digest[0] ^= x[index + 1];    
  }

  //printf("digest[0]: %08x, x[0]: %08x, digest[1]: %08x, x[1]: %08x\n", digest[0], x[0], digest[1], x[1]); 
}  

__kernel void m15400_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * Salt prep       
   */

  u32 iv[2]    = { 0 };
  u32 plain[2] = { 0 };
  u32 position[2] = { 0 };
  u32 offset = 0;

  position[0] = esalt_bufs->position[0];
  position[1] = esalt_bufs->position[1];

  offset = esalt_bufs->offset;

  iv[0] = esalt_bufs->iv[0];
  iv[1] = esalt_bufs->iv[1];

  plain[0] = esalt_bufs->plain[0];
  plain[1] = esalt_bufs->plain[1];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect(pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x digest[4] = { 0 };

    chacha20_transform (w0, w1, position, offset, iv, plain, digest);

    const u32x r0 = digest[0];
    const u32x r1 = digest[1];
    const u32x r2 = digest[2];
    const u32x r3 = digest[3];

    COMPARE_M_SIMD(r0, r1, r2, r3);
  } 
}

__kernel void m15400_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15400_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15400_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * Salt prep
   */

  u32 iv[2]    = { 0 };
  u32 plain[2] = { 0 };
  u32 position[2] = { 0 };
  u32 offset = 0;

  position[0] = esalt_bufs->position[0];
  position[1] = esalt_bufs->position[1];

  offset = esalt_bufs->offset;

  iv[0] = esalt_bufs->iv[0];
  iv[1] = esalt_bufs->iv[1];

  plain[0] = esalt_bufs->plain[0];
  plain[1] = esalt_bufs->plain[1];
  
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

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };
    
    const u32x out_len = apply_rules_vect(pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x digest[4] = { 0 };

    chacha20_transform (w0, w1, position, offset, iv, plain, digest);

    const u32x r0 = digest[0];
    const u32x r1 = digest[1];
    const u32x r2 = digest[2];
    const u32x r3 = digest[3];

    // printf("r0: %08x, search[0]: %08x, r1: %08x, search[1]: %08x, r2: %08x, search[2]: %08x, r3: %08x, search[3]: %08x\n", r0, search[0], r1, search[1], r2, search[2], r3, search[3]);

    COMPARE_S_SIMD(r0, r1, r2, r3);
  }  
}

__kernel void m15400_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15400_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const chacha20_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
