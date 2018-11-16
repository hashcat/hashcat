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
#include "inc_hash_sha1.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

// breaks if used with u8a on AMDGPU-PRO
__constant u8a lotus64_table[64] =
{
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
  'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
  'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
  'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
  'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z', '+', '/',
};

// break if used with u8 on NVidia driver 378.x
__constant u8a lotus_magic_table[256] =
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

#define uint_to_hex_upper8(i) l_bin2asc[(i)]

#define BOX1(S,i) (S)[(i)]

DECLSPEC void lotus_mix (u32 *in, const __local u8 *s_lotus_magic_table)
{
  u8 p = 0;

  for (int i = 0; i < 18; i++)
  {
    u8 s = 48;

    for (int j = 0; j < 12; j++)
    {
      u32 tmp_in  = in[j];
      u32 tmp_out = 0;

      p = (p + s--); p = (u8) (tmp_in >>  0) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= (u32) p <<  0;
      p = (p + s--); p = (u8) (tmp_in >>  8) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= (u32) p <<  8;
      p = (p + s--); p = (u8) (tmp_in >> 16) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= (u32) p << 16;
      p = (p + s--); p = (u8) (tmp_in >> 24) ^ BOX1 (s_lotus_magic_table, p); tmp_out |= (u32) p << 24;

      in[j] = tmp_out;
    }
  }
}

DECLSPEC void lotus_transform_password (const u32 *in, u32 *out, const __local u8 *s_lotus_magic_table)
{
  u8 t = (u8) (out[3] >> 24);

  u8 c;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 4; i++)
  {
    t ^= (u8) (in[i] >>  0); c = BOX1 (s_lotus_magic_table, t); out[i] ^= (u32) c <<  0; t = (u8) (out[i] >>  0);
    t ^= (u8) (in[i] >>  8); c = BOX1 (s_lotus_magic_table, t); out[i] ^= (u32) c <<  8; t = (u8) (out[i] >>  8);
    t ^= (u8) (in[i] >> 16); c = BOX1 (s_lotus_magic_table, t); out[i] ^= (u32) c << 16; t = (u8) (out[i] >> 16);
    t ^= (u8) (in[i] >> 24); c = BOX1 (s_lotus_magic_table, t); out[i] ^= (u32) c << 24; t = (u8) (out[i] >> 24);
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

DECLSPEC void mdtransform_norecalc (u32 *state, const u32 *block, const __local u8 *s_lotus_magic_table)
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

DECLSPEC void mdtransform (u32 *state, u32 *checksum, const u32 *block, const __local u8 *s_lotus_magic_table)
{
  mdtransform_norecalc (state, block, s_lotus_magic_table);

  lotus_transform_password (block, checksum, s_lotus_magic_table);
}

DECLSPEC void domino_big_md (const u32 *saved_key, const u32 size, u32 *state, const __local u8 *s_lotus_magic_table)
{
  u32 checksum[4];

  checksum[0] = 0;
  checksum[1] = 0;
  checksum[2] = 0;
  checksum[3] = 0;

  u32 block[4];

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

DECLSPEC void base64_encode (u8 *base64_hash, const u32 len, const u8 *base64_plain)
{
  u8 *out_ptr = (u8 *) base64_hash;
  u8 *in_ptr  = (u8 *) base64_plain;

  u32 i;

  for (i = 0; i < len; i += 3)
  {
    const u8 out_val0 = lotus64_table [                            ((in_ptr[0] >> 2) & 0x3f)];
    const u8 out_val1 = lotus64_table [((in_ptr[0] << 4) & 0x30) | ((in_ptr[1] >> 4) & 0x0f)];
    const u8 out_val2 = lotus64_table [((in_ptr[1] << 2) & 0x3c) | ((in_ptr[2] >> 6) & 0x03)];
    const u8 out_val3 = lotus64_table [                            ((in_ptr[2] >> 0) & 0x3f)];

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;

    in_ptr  += 3;
    out_ptr += 4;
  }
}

DECLSPEC void lotus6_base64_encode (u8 *base64_hash, const u32 salt0, const u32 salt1, const u32 a, const u32 b, const u32 c)
{
  const uchar4 salt0c = as_uchar4 (salt0);
  const uchar4 salt1c = as_uchar4 (salt1);

  const uchar4 ac = as_uchar4 (a);
  const uchar4 bc = as_uchar4 (b);
  const uchar4 cc = as_uchar4 (c);

  u8 tmp[24]; // size 22 (=pw_len) is needed but base64 needs size divisible by 4

  /*
   * Copy $salt.$digest to a tmp buffer
   */

  u8 base64_plain[16];

  base64_plain[ 0] = salt0c.s0;
  base64_plain[ 1] = salt0c.s1;
  base64_plain[ 2] = salt0c.s2;
  base64_plain[ 3] = salt0c.s3;
  base64_plain[ 3] -= -4; // dont ask!
  base64_plain[ 4] = salt1c.s0;
  base64_plain[ 5] = ac.s0;
  base64_plain[ 6] = ac.s1;
  base64_plain[ 7] = ac.s2;
  base64_plain[ 8] = ac.s3;
  base64_plain[ 9] = bc.s0;
  base64_plain[10] = bc.s1;
  base64_plain[11] = bc.s2;
  base64_plain[12] = bc.s3;
  base64_plain[13] = cc.s0;
  base64_plain[14] = cc.s1;
  base64_plain[15] = cc.s2;

  /*
   * base64 encode the $salt.$digest string
   */

  base64_encode (tmp + 2, 14, base64_plain);

  base64_hash[ 0] = '(';
  base64_hash[ 1] = 'G';
  base64_hash[ 2] = tmp[ 2];
  base64_hash[ 3] = tmp[ 3];
  base64_hash[ 4] = tmp[ 4];
  base64_hash[ 5] = tmp[ 5];
  base64_hash[ 6] = tmp[ 6];
  base64_hash[ 7] = tmp[ 7];
  base64_hash[ 8] = tmp[ 8];
  base64_hash[ 9] = tmp[ 9];
  base64_hash[10] = tmp[10];
  base64_hash[11] = tmp[11];
  base64_hash[12] = tmp[12];
  base64_hash[13] = tmp[13];
  base64_hash[14] = tmp[14];
  base64_hash[15] = tmp[15];
  base64_hash[16] = tmp[16];
  base64_hash[17] = tmp[17];
  base64_hash[18] = tmp[18];
  base64_hash[19] = tmp[19];
  base64_hash[20] = tmp[20];
  base64_hash[21] = ')';
}

DECLSPEC void hmac_sha1_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

__kernel void m09100_init (KERN_ATTR_TMPS (lotus8_tmp_t))
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

  __local u8 s_lotus_magic_table[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_lotus_magic_table[i] = lotus_magic_table[i];
  }

  __local u32 l_bin2asc[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

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

  /**
   * pad
   */

  u32 pw_len = pws[gid].pw_len;

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

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];

  const u32 salt0 = salt_buf0[0];
  const u32 salt1 = (salt_buf0[1] & 0xff) | ('(' << 8);

  /**
   * Lotus 6 hash - SEC_pwddigest_V2
   */

  u32 w_tmp[16];

  w_tmp[ 0] = w[ 0];
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

  u32 state[4];

  state[0] = 0;
  state[1] = 0;
  state[2] = 0;
  state[3] = 0;

  domino_big_md (w_tmp, pw_len, state, s_lotus_magic_table);

  const u32 w0_t = uint_to_hex_upper8 ((state[0] >>  0) & 255) <<  0
                 | uint_to_hex_upper8 ((state[0] >>  8) & 255) << 16;
  const u32 w1_t = uint_to_hex_upper8 ((state[0] >> 16) & 255) <<  0
                 | uint_to_hex_upper8 ((state[0] >> 24) & 255) << 16;
  const u32 w2_t = uint_to_hex_upper8 ((state[1] >>  0) & 255) <<  0
                 | uint_to_hex_upper8 ((state[1] >>  8) & 255) << 16;
  const u32 w3_t = uint_to_hex_upper8 ((state[1] >> 16) & 255) <<  0
                 | uint_to_hex_upper8 ((state[1] >> 24) & 255) << 16;
  const u32 w4_t = uint_to_hex_upper8 ((state[2] >>  0) & 255) <<  0
                 | uint_to_hex_upper8 ((state[2] >>  8) & 255) << 16;
  const u32 w5_t = uint_to_hex_upper8 ((state[2] >> 16) & 255) <<  0
                 | uint_to_hex_upper8 ((state[2] >> 24) & 255) << 16;
  const u32 w6_t = uint_to_hex_upper8 ((state[3] >>  0) & 255) <<  0
                 | uint_to_hex_upper8 ((state[3] >>  8) & 255) << 16;

  const u32 pade = 0x0e0e0e0e;

  w_tmp[ 0] = salt0;
  w_tmp[ 1] = salt1      | w0_t << 16;
  w_tmp[ 2] = w0_t >> 16 | w1_t << 16;
  w_tmp[ 3] = w1_t >> 16 | w2_t << 16;
  w_tmp[ 4] = w2_t >> 16 | w3_t << 16;
  w_tmp[ 5] = w3_t >> 16 | w4_t << 16;
  w_tmp[ 6] = w4_t >> 16 | w5_t << 16;
  w_tmp[ 7] = w5_t >> 16 | w6_t << 16;
  w_tmp[ 8] = w6_t >> 16 | pade << 16;
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

  u32 a = state[0];
  u32 b = state[1];
  u32 c = state[2];

  /**
   * Base64 encode
   */

  pw_len = 22;

  u8 base64_hash[22];

  lotus6_base64_encode (base64_hash, salt_buf0[0], salt_buf0[1], a, b, c);

  /**
   * PBKDF2 - HMACSHA1 - 1st iteration
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = (base64_hash[ 0] << 24) | (base64_hash[ 1] << 16) | (base64_hash[ 2] << 8) | base64_hash[ 3];
  w0[1] = (base64_hash[ 4] << 24) | (base64_hash[ 5] << 16) | (base64_hash[ 6] << 8) | base64_hash[ 7];
  w0[2] = (base64_hash[ 8] << 24) | (base64_hash[ 9] << 16) | (base64_hash[10] << 8) | base64_hash[11];
  w0[3] = (base64_hash[12] << 24) | (base64_hash[13] << 16) | (base64_hash[14] << 8) | base64_hash[15];
  w1[0] = (base64_hash[16] << 24) | (base64_hash[17] << 16) | (base64_hash[18] << 8) | base64_hash[19];
  w1[1] = (base64_hash[20] << 24) | (base64_hash[21] << 16);
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

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_64 (&sha1_hmac_ctx, w0, w1, w2, w3);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  for (u32 i = 0, j = 1; i < 2; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    w0[0] = j;
    w0[1] = 0;
    w0[2] = 0;
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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

__kernel void m09100_loop (KERN_ATTR_TMPS (lotus8_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  for (u32 i = 0; i < 2; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

__kernel void m09100_comp (KERN_ATTR_TMPS (lotus8_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].out[DGST_R0];
  const u32 r1 = tmps[gid].out[DGST_R1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #include COMPARE_M
}
