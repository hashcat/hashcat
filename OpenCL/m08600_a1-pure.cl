/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible
//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

__constant u32a lotus_magic_table[256] =
{
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

#if   VECT_SIZE == 1
#define BOX1(S,i) (S)[(i)]
#elif VECT_SIZE == 2
#define BOX1(S,i) (u32x) ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define BOX1(S,i) (u32x) ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define BOX1(S,i) (u32x) ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define BOX1(S,i) (u32x) ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

DECLSPEC void lotus_mix (u32 *in, __local u32 *s_lotus_magic_table)
{
  u32 p = 0;

  for (int i = 0; i < 18; i++)
  {
    u32 s = 48;

    for (int j = 0; j < 12; j++)
    {
      u32 tmp_in = in[j];
      u32 tmp_out = 0;

      p = (p + s--) & 0xff; p = ((tmp_in >>  0) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p <<  0;
      p = (p + s--) & 0xff; p = ((tmp_in >>  8) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p <<  8;
      p = (p + s--) & 0xff; p = ((tmp_in >> 16) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p << 16;
      p = (p + s--) & 0xff; p = ((tmp_in >> 24) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p << 24;

      in[j] = tmp_out;
    }
  }
}

DECLSPEC void lotus_transform_password (const u32 *in, u32x *out, __local u32 *s_lotus_magic_table)
{
  u32 t = out[3] >> 24;

  u32 c;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 4; i++)
  {
    t ^= (in[i] >>  0) & 0xff; c = BOX1 (s_lotus_magic_table, t); out[i] ^= c <<  0; t = ((out[i] >>  0) & 0xff);
    t ^= (in[i] >>  8) & 0xff; c = BOX1 (s_lotus_magic_table, t); out[i] ^= c <<  8; t = ((out[i] >>  8) & 0xff);
    t ^= (in[i] >> 16) & 0xff; c = BOX1 (s_lotus_magic_table, t); out[i] ^= c << 16; t = ((out[i] >> 16) & 0xff);
    t ^= (in[i] >> 24) & 0xff; c = BOX1 (s_lotus_magic_table, t); out[i] ^= c << 24; t = ((out[i] >> 24) & 0xff);
  }
}

DECLSPEC void pad (u32 *w, const u32 len)
{
  const u32 val = 16 - len;

  const u32 mask1 = val << 24;

  const u32 mask2 = val << 16
                  | val << 24;

  const u32 mask3 = val <<  8
                  | val << 16
                  | val << 24;

  const u32 mask4 = val <<  0
                  | val <<  8
                  | val << 16
                  | val << 24;

  switch (len)
  {
    case  0:  w[0]  = mask4;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  1:  w[0] |= mask3;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  2:  w[0] |= mask2;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  3:  w[0] |= mask1;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  4:  w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  5:  w[1] |= mask3;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  6:  w[1] |= mask2;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  7:  w[1] |= mask1;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  8:  w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  9:  w[2] |= mask3;
              w[3]  = mask4;
              break;
    case 10:  w[2] |= mask2;
              w[3]  = mask4;
              break;
    case 11:  w[2] |= mask1;
              w[3]  = mask4;
              break;
    case 12:  w[3]  = mask4;
              break;
    case 13:  w[3] |= mask3;
              break;
    case 14:  w[3] |= mask2;
              break;
    case 15:  w[3] |= mask1;
              break;
  }
}

DECLSPEC void mdtransform_norecalc (u32 *state, const u32x *block, __local u32 *s_lotus_magic_table)
{
  u32 x[12];

  x[ 0] = state[0];
  x[ 1] = state[1];
  x[ 2] = state[2];
  x[ 3] = state[3];
  x[ 4] = block[0];
  x[ 5] = block[1];
  x[ 6] = block[2];
  x[ 7] = block[3];
  x[ 8] = state[0] ^ block[0];
  x[ 9] = state[1] ^ block[1];
  x[10] = state[2] ^ block[2];
  x[11] = state[3] ^ block[3];

  lotus_mix (x, s_lotus_magic_table);

  state[0] = x[0];
  state[1] = x[1];
  state[2] = x[2];
  state[3] = x[3];
}

DECLSPEC void mdtransform (u32 *state, u32x *checksum, const u32x *block, __local u32 *s_lotus_magic_table)
{
  mdtransform_norecalc (state, block, s_lotus_magic_table);

  lotus_transform_password (block, checksum, s_lotus_magic_table);
}

DECLSPEC void domino_big_md (const u32 *saved_key, const u32 size, u32x *state, __local u32 *s_lotus_magic_table)
{
  u32 checksum[4];

  checksum[0] = 0;
  checksum[1] = 0;
  checksum[2] = 0;
  checksum[3] = 0;

  mdtransform (state, checksum, saved_key, s_lotus_magic_table);

  mdtransform_norecalc (state, checksum, s_lotus_magic_table);
}

__kernel void m08600_mxx (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

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
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    /**
     * domino
     */

    u32 state[4];

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    /**
     * padding
     */

    pad (w0, pw_len);

    domino_big_md (w0, pw_len, state, s_lotus_magic_table);

    COMPARE_M_SIMD (state[0], state[1], state[2], state[3]);
  }
}

__kernel void m08600_sxx (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

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
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    /**
     * domino
     */

    u32 state[4];

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    /**
     * padding
     */

    pad (w0, pw_len);

    domino_big_md (w0, pw_len, state, s_lotus_magic_table);

    COMPARE_S_SIMD (state[0], state[1], state[2], state[3]);
  }
}
