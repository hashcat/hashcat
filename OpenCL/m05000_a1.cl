/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _KECCAK_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 2
#define DGST_R1 3
#define DGST_R2 4
#define DGST_R3 5

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

__constant u64 keccakf_rndc[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#define Theta1(s) (st[0 + s] ^ st[5 + s] ^ st[10 + s] ^ st[15 + s] ^ st[20 + s])

#define Theta2(s)               \
{                               \
  st[ 0 + s] ^= t;              \
  st[ 5 + s] ^= t;              \
  st[10 + s] ^= t;              \
  st[15 + s] ^= t;              \
  st[20 + s] ^= t;              \
}

#define Rho_Pi(s)               \
{                               \
  u32 j = keccakf_piln[s];     \
  u32 k = keccakf_rotc[s];     \
  bc0 = st[j];                  \
  st[j] = rotl64 (t, k);        \
  t = bc0;                      \
}

#define Chi(s)                  \
{                               \
  bc0 = st[0 + s];              \
  bc1 = st[1 + s];              \
  bc2 = st[2 + s];              \
  bc3 = st[3 + s];              \
  bc4 = st[4 + s];              \
  st[0 + s] ^= ~bc1 & bc2;      \
  st[1 + s] ^= ~bc2 & bc3;      \
  st[2 + s] ^= ~bc3 & bc4;      \
  st[3 + s] ^= ~bc4 & bc0;      \
  st[4 + s] ^= ~bc0 & bc1;      \
}

__kernel void m05000_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * const
   */

  const u8 keccakf_rotc[24] =
  {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
  };

  const u8 keccakf_piln[24] =
  {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
  };

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    append_0x01_2x4 (wordl0, wordl1, pw_l_len);

    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * 0x80 keccak, very special
   */

  const u32 mdlen = salt_bufs[salt_pos].keccak_mdlen;

  const u32 rsiz = 200 - (2 * mdlen);

  const u32 add80w = (rsiz - 1) / 8;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      append_0x01_2x4 (wordr0, wordr1, pw_r_len);

      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    u32 w1[4];

    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32 w2[4];

    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];

    u32 w3[4];

    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = pw_len * 8;
    w3[3] = 0;

    u64 st[25];

    st[ 0] = (u64) (w0[0]) | (u64) (w0[1]) << 32;
    st[ 1] = (u64) (w0[2]) | (u64) (w0[3]) << 32;
    st[ 2] = (u64) (w1[0]) | (u64) (w1[1]) << 32;
    st[ 3] = (u64) (w1[2]) | (u64) (w1[3]) << 32;
    st[ 4] = 0;
    st[ 5] = 0;
    st[ 6] = 0;
    st[ 7] = 0;
    st[ 8] = 0;
    st[ 9] = 0;
    st[10] = 0;
    st[11] = 0;
    st[12] = 0;
    st[13] = 0;
    st[14] = 0;
    st[15] = 0;
    st[16] = 0;
    st[17] = 0;
    st[18] = 0;
    st[19] = 0;
    st[20] = 0;
    st[21] = 0;
    st[22] = 0;
    st[23] = 0;
    st[24] = 0;

    st[add80w] |= 0x8000000000000000;

    int round;

    for (round = 0; round < KECCAK_ROUNDS; round++)
    {
      // Theta

      u64 bc0 = Theta1 (0);
      u64 bc1 = Theta1 (1);
      u64 bc2 = Theta1 (2);
      u64 bc3 = Theta1 (3);
      u64 bc4 = Theta1 (4);

      u64 t;

      t = bc4 ^ rotl64 (bc1, 1); Theta2 (0);
      t = bc0 ^ rotl64 (bc2, 1); Theta2 (1);
      t = bc1 ^ rotl64 (bc3, 1); Theta2 (2);
      t = bc2 ^ rotl64 (bc4, 1); Theta2 (3);
      t = bc3 ^ rotl64 (bc0, 1); Theta2 (4);

      // Rho Pi

      t = st[1];

      Rho_Pi (0);
      Rho_Pi (1);
      Rho_Pi (2);
      Rho_Pi (3);
      Rho_Pi (4);
      Rho_Pi (5);
      Rho_Pi (6);
      Rho_Pi (7);
      Rho_Pi (8);
      Rho_Pi (9);
      Rho_Pi (10);
      Rho_Pi (11);
      Rho_Pi (12);
      Rho_Pi (13);
      Rho_Pi (14);
      Rho_Pi (15);
      Rho_Pi (16);
      Rho_Pi (17);
      Rho_Pi (18);
      Rho_Pi (19);
      Rho_Pi (20);
      Rho_Pi (21);
      Rho_Pi (22);
      Rho_Pi (23);

      //  Chi

      Chi (0);
      Chi (5);
      Chi (10);
      Chi (15);
      Chi (20);

      //  Iota

      st[0] ^= keccakf_rndc[round];
    }

    const u32 r0 = l32_from_64 (st[1]);
    const u32 r1 = h32_from_64 (st[1]);
    const u32 r2 = l32_from_64 (st[2]);
    const u32 r3 = h32_from_64 (st[2]);

    #include COMPARE_M
  }
}

__kernel void m05000_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05000_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05000_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * const
   */

  const u8 keccakf_rotc[24] =
  {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
  };

  const u8 keccakf_piln[24] =
  {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
  };

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    append_0x01_2x4 (wordl0, wordl1, pw_l_len);

    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

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
   * 0x80 keccak, very special
   */

  const u32 mdlen = salt_bufs[salt_pos].keccak_mdlen;

  const u32 rsiz = 200 - (2 * mdlen);

  const u32 add80w = (rsiz - 1) / 8;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      append_0x01_2x4 (wordr0, wordr1, pw_r_len);

      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    u32 w1[4];

    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32 w2[4];

    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];

    u32 w3[4];

    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = pw_len * 8;
    w3[3] = 0;

    u64 st[25];

    st[ 0] = (u64) (w0[0]) | (u64) (w0[1]) << 32;
    st[ 1] = (u64) (w0[2]) | (u64) (w0[3]) << 32;
    st[ 2] = (u64) (w1[0]) | (u64) (w1[1]) << 32;
    st[ 3] = (u64) (w1[2]) | (u64) (w1[3]) << 32;
    st[ 4] = 0;
    st[ 5] = 0;
    st[ 6] = 0;
    st[ 7] = 0;
    st[ 8] = 0;
    st[ 9] = 0;
    st[10] = 0;
    st[11] = 0;
    st[12] = 0;
    st[13] = 0;
    st[14] = 0;
    st[15] = 0;
    st[16] = 0;
    st[17] = 0;
    st[18] = 0;
    st[19] = 0;
    st[20] = 0;
    st[21] = 0;
    st[22] = 0;
    st[23] = 0;
    st[24] = 0;

    st[add80w] |= 0x8000000000000000;

    int round;

    for (round = 0; round < KECCAK_ROUNDS; round++)
    {
      // Theta

      u64 bc0 = Theta1 (0);
      u64 bc1 = Theta1 (1);
      u64 bc2 = Theta1 (2);
      u64 bc3 = Theta1 (3);
      u64 bc4 = Theta1 (4);

      u64 t;

      t = bc4 ^ rotl64 (bc1, 1); Theta2 (0);
      t = bc0 ^ rotl64 (bc2, 1); Theta2 (1);
      t = bc1 ^ rotl64 (bc3, 1); Theta2 (2);
      t = bc2 ^ rotl64 (bc4, 1); Theta2 (3);
      t = bc3 ^ rotl64 (bc0, 1); Theta2 (4);

      // Rho Pi

      t = st[1];

      Rho_Pi (0);
      Rho_Pi (1);
      Rho_Pi (2);
      Rho_Pi (3);
      Rho_Pi (4);
      Rho_Pi (5);
      Rho_Pi (6);
      Rho_Pi (7);
      Rho_Pi (8);
      Rho_Pi (9);
      Rho_Pi (10);
      Rho_Pi (11);
      Rho_Pi (12);
      Rho_Pi (13);
      Rho_Pi (14);
      Rho_Pi (15);
      Rho_Pi (16);
      Rho_Pi (17);
      Rho_Pi (18);
      Rho_Pi (19);
      Rho_Pi (20);
      Rho_Pi (21);
      Rho_Pi (22);
      Rho_Pi (23);

      //  Chi

      Chi (0);
      Chi (5);
      Chi (10);
      Chi (15);
      Chi (20);

      //  Iota

      st[0] ^= keccakf_rndc[round];
    }

    const u32 r0 = l32_from_64 (st[1]);
    const u32 r1 = h32_from_64 (st[1]);
    const u32 r2 = l32_from_64 (st[2]);
    const u32 r3 = h32_from_64 (st[2]);

    #include COMPARE_S
  }
}

__kernel void m05000_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05000_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
