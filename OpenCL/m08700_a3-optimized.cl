/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#endif

CONSTANT_VK u32a lotus_magic_table[256] =
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

#define BOX(S,i) (S)[(i)]

#if   VECT_SIZE == 1
#define uint_to_hex_upper8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_upper8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_upper8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_upper8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_upper8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

#if   VECT_SIZE == 1
#define BOX1(S,i) (S)[(i)]
#elif VECT_SIZE == 2
#define BOX1(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define BOX1(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define BOX1(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define BOX1(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

DECLSPEC void lotus_mix (u32x *in, LOCAL_AS u32 *s_lotus_magic_table)
{
  u32x p = 0;

  for (int i = 0; i < 18; i++)
  {
    u32 s = 48;

    for (int j = 0; j < 12; j++)
    {
      u32x tmp_in = in[j];
      u32x tmp_out = 0;

      p = (p + s--) & 0xff; p = ((tmp_in >>  0) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p <<  0;
      p = (p + s--) & 0xff; p = ((tmp_in >>  8) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p <<  8;
      p = (p + s--) & 0xff; p = ((tmp_in >> 16) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p << 16;
      p = (p + s--) & 0xff; p = ((tmp_in >> 24) & 0xff) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= p << 24;

      in[j] = tmp_out;
    }
  }
}

DECLSPEC void lotus_transform_password (u32x *in, u32x *out, LOCAL_AS u32 *s_lotus_magic_table)
{
  u32x t = out[3] >> 24;

  u32x c;

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

DECLSPEC void mdtransform_norecalc (u32x *state, u32x *block, LOCAL_AS u32 *s_lotus_magic_table)
{
  u32x x[12];

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

DECLSPEC void mdtransform (u32x *state, u32x *checksum, u32x *block, LOCAL_AS u32 *s_lotus_magic_table)
{
  mdtransform_norecalc (state, block, s_lotus_magic_table);

  lotus_transform_password (block, checksum, s_lotus_magic_table);
}

DECLSPEC void domino_big_md (const u32x *saved_key, const u32 size, u32x *state, LOCAL_AS u32 *s_lotus_magic_table)
{
  u32x checksum[4];

  checksum[0] = 0;
  checksum[1] = 0;
  checksum[2] = 0;
  checksum[3] = 0;

  u32x block[4];

  block[0] = 0;
  block[1] = 0;
  block[2] = 0;
  block[3] = 0;

  u32 curpos;
  u32 idx;

  for (curpos = 0, idx = 0; curpos + 16 < size; curpos += 16, idx += 4)
  {
    block[0] = saved_key[idx + 0];
    block[1] = saved_key[idx + 1];
    block[2] = saved_key[idx + 2];
    block[3] = saved_key[idx + 3];

    mdtransform (state, checksum, block, s_lotus_magic_table);
  }

  block[0] = saved_key[idx + 0];
  block[1] = saved_key[idx + 1];
  block[2] = saved_key[idx + 2];
  block[3] = saved_key[idx + 3];

  mdtransform (state, checksum, block, s_lotus_magic_table);

  mdtransform_norecalc (state, checksum, s_lotus_magic_table);
}

DECLSPEC void m08700m (LOCAL_AS u32 *s_lotus_magic_table, LOCAL_AS u32 *l_bin2asc, u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * base
   */

  if (pw_len < 16)
  {
    pad (&w[ 0], pw_len & 0xf);
  }
  else if (pw_len < 32)
  {
    pad (&w[ 4], pw_len & 0xf);
  }
  else if (pw_len < 48)
  {
    pad (&w[ 8], pw_len & 0xf);
  }
  else if (pw_len < 64)
  {
    pad (&w[12], pw_len & 0xf);
  }

  /**
   * salt
   */

  const u32 salt0 = salt_bufs[salt_pos].salt_buf[0];
  const u32 salt1 = (salt_bufs[salt_pos].salt_buf[1] & 0xff) | '(' << 8;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    /**
     * domino
     */

    u32x w_tmp[16];

    w_tmp[ 0] = w0;
    w_tmp[ 1] = w[ 1];
    w_tmp[ 2] = w[ 2];
    w_tmp[ 3] = w[ 3];
    w_tmp[ 4] = w[ 4];
    w_tmp[ 5] = w[ 5];
    w_tmp[ 6] = w[ 6];
    w_tmp[ 7] = w[ 7];
    w_tmp[ 8] = w[ 8];
    w_tmp[ 9] = w[ 9];
    w_tmp[10] = w[10];
    w_tmp[11] = w[11];
    w_tmp[12] = w[12];
    w_tmp[13] = w[13];
    w_tmp[14] = w[14];
    w_tmp[15] = w[15];

    u32x state[4];

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    domino_big_md (w_tmp, pw_len, state, s_lotus_magic_table);

    const u32x w0_t = uint_to_hex_upper8 ((state[0] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[0] >>  8) & 255) << 16;
    const u32x w1_t = uint_to_hex_upper8 ((state[0] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[0] >> 24) & 255) << 16;
    const u32x w2_t = uint_to_hex_upper8 ((state[1] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[1] >>  8) & 255) << 16;
    const u32x w3_t = uint_to_hex_upper8 ((state[1] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[1] >> 24) & 255) << 16;
    const u32x w4_t = uint_to_hex_upper8 ((state[2] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[2] >>  8) & 255) << 16;
    const u32x w5_t = uint_to_hex_upper8 ((state[2] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[2] >> 24) & 255) << 16;
    const u32x w6_t = uint_to_hex_upper8 ((state[3] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[3] >>  8) & 255) << 16;
    //const u32x w7_t = uint_to_hex_upper8 ((state[3] >> 16) & 255) <<  0
    //                | uint_to_hex_upper8 ((state[3] >> 24) & 255) << 16;

    const u32x pade = 0x0e0e0e0e;

    w_tmp[ 0] = salt0;
    w_tmp[ 1] = salt1      | w0_t << 16;
    w_tmp[ 2] = w0_t >> 16 | w1_t << 16;
    w_tmp[ 3] = w1_t >> 16 | w2_t << 16;
    w_tmp[ 4] = w2_t >> 16 | w3_t << 16;
    w_tmp[ 5] = w3_t >> 16 | w4_t << 16;
    w_tmp[ 6] = w4_t >> 16 | w5_t << 16;
    w_tmp[ 7] = w5_t >> 16 | w6_t << 16;
    w_tmp[ 8] = w6_t >> 16 | pade << 16; // | w7_t <<  8;
    w_tmp[ 9] = pade;
    w_tmp[10] = pade;
    w_tmp[11] = pade;
    w_tmp[12] = 0;
    w_tmp[13] = 0;
    w_tmp[14] = 0;
    w_tmp[15] = 0;

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    domino_big_md (w_tmp, 34, state, s_lotus_magic_table);

    u32x a = state[0] & 0xffffffff;
    u32x b = state[1] & 0xffffffff;
    u32x c = state[2] & 0x000000ff;
    u32x d = state[3] & 0x00000000;

    COMPARE_M_SIMD (a, b, c, d);
  }
}

DECLSPEC void m08700s (LOCAL_AS u32 *s_lotus_magic_table, LOCAL_AS u32 *l_bin2asc, u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * base
   */

  if (pw_len < 16)
  {
    pad (&w[ 0], pw_len & 0xf);
  }
  else if (pw_len < 32)
  {
    pad (&w[ 4], pw_len & 0xf);
  }
  else if (pw_len < 48)
  {
    pad (&w[ 8], pw_len & 0xf);
  }
  else if (pw_len < 64)
  {
    pad (&w[12], pw_len & 0xf);
  }

  /**
   * salt
   */

  const u32 salt0 = salt_bufs[salt_pos].salt_buf[0];
  const u32 salt1 = (salt_bufs[salt_pos].salt_buf[1] & 0xff) | '(' << 8;

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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    /**
     * domino
     */

    u32x w_tmp[16];

    w_tmp[ 0] = w0;
    w_tmp[ 1] = w[ 1];
    w_tmp[ 2] = w[ 2];
    w_tmp[ 3] = w[ 3];
    w_tmp[ 4] = w[ 4];
    w_tmp[ 5] = w[ 5];
    w_tmp[ 6] = w[ 6];
    w_tmp[ 7] = w[ 7];
    w_tmp[ 8] = w[ 8];
    w_tmp[ 9] = w[ 9];
    w_tmp[10] = w[10];
    w_tmp[11] = w[11];
    w_tmp[12] = w[12];
    w_tmp[13] = w[13];
    w_tmp[14] = w[14];
    w_tmp[15] = w[15];

    u32x state[4];

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    domino_big_md (w_tmp, pw_len, state, s_lotus_magic_table);

    const u32x w0_t = uint_to_hex_upper8 ((state[0] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[0] >>  8) & 255) << 16;
    const u32x w1_t = uint_to_hex_upper8 ((state[0] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[0] >> 24) & 255) << 16;
    const u32x w2_t = uint_to_hex_upper8 ((state[1] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[1] >>  8) & 255) << 16;
    const u32x w3_t = uint_to_hex_upper8 ((state[1] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[1] >> 24) & 255) << 16;
    const u32x w4_t = uint_to_hex_upper8 ((state[2] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[2] >>  8) & 255) << 16;
    const u32x w5_t = uint_to_hex_upper8 ((state[2] >> 16) & 255) <<  0
                    | uint_to_hex_upper8 ((state[2] >> 24) & 255) << 16;
    const u32x w6_t = uint_to_hex_upper8 ((state[3] >>  0) & 255) <<  0
                    | uint_to_hex_upper8 ((state[3] >>  8) & 255) << 16;
    //const u32x w7_t = uint_to_hex_upper8 ((state[3] >> 16) & 255) <<  0
    //                | uint_to_hex_upper8 ((state[3] >> 24) & 255) << 16;

    const u32x pade = 0x0e0e0e0e;

    w_tmp[ 0] = salt0;
    w_tmp[ 1] = salt1      | w0_t << 16;
    w_tmp[ 2] = w0_t >> 16 | w1_t << 16;
    w_tmp[ 3] = w1_t >> 16 | w2_t << 16;
    w_tmp[ 4] = w2_t >> 16 | w3_t << 16;
    w_tmp[ 5] = w3_t >> 16 | w4_t << 16;
    w_tmp[ 6] = w4_t >> 16 | w5_t << 16;
    w_tmp[ 7] = w5_t >> 16 | w6_t << 16;
    w_tmp[ 8] = w6_t >> 16 | pade << 16; // | w7_t <<  8;
    w_tmp[ 9] = pade;
    w_tmp[10] = pade;
    w_tmp[11] = pade;
    w_tmp[12] = 0;
    w_tmp[13] = 0;
    w_tmp[14] = 0;
    w_tmp[15] = 0;

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    domino_big_md (w_tmp, 34, state, s_lotus_magic_table);

    u32x a = state[0] & 0xffffffff;
    u32x b = state[1] & 0xffffffff;
    u32x c = state[2] & 0x000000ff;
    u32x d = state[3] & 0x00000000;

    COMPARE_S_SIMD (a, b, c, d);
  }
}

KERNEL_FQ void m08700_m04 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m08700_m08 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m08700_m16 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m08700_s04 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m08700_s08 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m08700_s16 (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 s_lotus_magic_table[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
