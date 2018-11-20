/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//not compatible
//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"

DECLSPEC void sha256_transform_transport_vector (const u32x *w, u32x *digest)
{
  sha256_transform_vector (w + 0, w + 4, w + 8, w + 12, digest);
}

DECLSPEC void memcat64c_be (u32x *block, const u32 offset, u32x *carry)
{
  const u32 mod = offset & 3;
  const u32 div = offset / 4;

  u32x tmp00;
  u32x tmp01;
  u32x tmp02;
  u32x tmp03;
  u32x tmp04;
  u32x tmp05;
  u32x tmp06;
  u32x tmp07;
  u32x tmp08;
  u32x tmp09;
  u32x tmp10;
  u32x tmp11;
  u32x tmp12;
  u32x tmp13;
  u32x tmp14;
  u32x tmp15;
  u32x tmp16;

  #if defined IS_AMD || defined IS_GENERIC
  tmp00 = hc_bytealign (        0, carry[ 0], offset);
  tmp01 = hc_bytealign (carry[ 0], carry[ 1], offset);
  tmp02 = hc_bytealign (carry[ 1], carry[ 2], offset);
  tmp03 = hc_bytealign (carry[ 2], carry[ 3], offset);
  tmp04 = hc_bytealign (carry[ 3], carry[ 4], offset);
  tmp05 = hc_bytealign (carry[ 4], carry[ 5], offset);
  tmp06 = hc_bytealign (carry[ 5], carry[ 6], offset);
  tmp07 = hc_bytealign (carry[ 6], carry[ 7], offset);
  tmp08 = hc_bytealign (carry[ 7], carry[ 8], offset);
  tmp09 = hc_bytealign (carry[ 8], carry[ 9], offset);
  tmp10 = hc_bytealign (carry[ 9], carry[10], offset);
  tmp11 = hc_bytealign (carry[10], carry[11], offset);
  tmp12 = hc_bytealign (carry[11], carry[12], offset);
  tmp13 = hc_bytealign (carry[12], carry[13], offset);
  tmp14 = hc_bytealign (carry[13], carry[14], offset);
  tmp15 = hc_bytealign (carry[14], carry[15], offset);
  tmp16 = hc_bytealign (carry[15],         0, offset);
  #endif

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;

  tmp00 = hc_byte_perm (carry[ 0],         0, selector);
  tmp01 = hc_byte_perm (carry[ 1], carry[ 0], selector);
  tmp02 = hc_byte_perm (carry[ 2], carry[ 1], selector);
  tmp03 = hc_byte_perm (carry[ 3], carry[ 2], selector);
  tmp04 = hc_byte_perm (carry[ 4], carry[ 3], selector);
  tmp05 = hc_byte_perm (carry[ 5], carry[ 4], selector);
  tmp06 = hc_byte_perm (carry[ 6], carry[ 5], selector);
  tmp07 = hc_byte_perm (carry[ 7], carry[ 6], selector);
  tmp08 = hc_byte_perm (carry[ 8], carry[ 7], selector);
  tmp09 = hc_byte_perm (carry[ 9], carry[ 8], selector);
  tmp10 = hc_byte_perm (carry[10], carry[ 9], selector);
  tmp11 = hc_byte_perm (carry[11], carry[10], selector);
  tmp12 = hc_byte_perm (carry[12], carry[11], selector);
  tmp13 = hc_byte_perm (carry[13], carry[12], selector);
  tmp14 = hc_byte_perm (carry[14], carry[13], selector);
  tmp15 = hc_byte_perm (carry[15], carry[14], selector);
  tmp16 = hc_byte_perm (        0, carry[15], selector);
  #endif

  carry[ 0] = 0;
  carry[ 1] = 0;
  carry[ 2] = 0;
  carry[ 3] = 0;
  carry[ 4] = 0;
  carry[ 5] = 0;
  carry[ 6] = 0;
  carry[ 7] = 0;
  carry[ 8] = 0;
  carry[ 9] = 0;
  carry[10] = 0;
  carry[11] = 0;
  carry[12] = 0;
  carry[13] = 0;
  carry[14] = 0;
  carry[15] = 0;

  switch (div)
  {
    case  0:  block[ 0] |= tmp00;
              block[ 1]  = tmp01;
              block[ 2]  = tmp02;
              block[ 3]  = tmp03;
              block[ 4]  = tmp04;
              block[ 5]  = tmp05;
              block[ 6]  = tmp06;
              block[ 7]  = tmp07;
              block[ 8]  = tmp08;
              block[ 9]  = tmp09;
              block[10]  = tmp10;
              block[11]  = tmp11;
              block[12]  = tmp12;
              block[13]  = tmp13;
              block[14]  = tmp14;
              block[15]  = tmp15;
              carry[ 0]  = tmp16;
              break;
    case  1:  block[ 1] |= tmp00;
              block[ 2]  = tmp01;
              block[ 3]  = tmp02;
              block[ 4]  = tmp03;
              block[ 5]  = tmp04;
              block[ 6]  = tmp05;
              block[ 7]  = tmp06;
              block[ 8]  = tmp07;
              block[ 9]  = tmp08;
              block[10]  = tmp09;
              block[11]  = tmp10;
              block[12]  = tmp11;
              block[13]  = tmp12;
              block[14]  = tmp13;
              block[15]  = tmp14;
              carry[ 0]  = tmp15;
              carry[ 1]  = tmp16;
              break;
    case  2:  block[ 2] |= tmp00;
              block[ 3]  = tmp01;
              block[ 4]  = tmp02;
              block[ 5]  = tmp03;
              block[ 6]  = tmp04;
              block[ 7]  = tmp05;
              block[ 8]  = tmp06;
              block[ 9]  = tmp07;
              block[10]  = tmp08;
              block[11]  = tmp09;
              block[12]  = tmp10;
              block[13]  = tmp11;
              block[14]  = tmp12;
              block[15]  = tmp13;
              carry[ 0]  = tmp14;
              carry[ 1]  = tmp15;
              carry[ 2]  = tmp16;
              break;
    case  3:  block[ 3] |= tmp00;
              block[ 4]  = tmp01;
              block[ 5]  = tmp02;
              block[ 6]  = tmp03;
              block[ 7]  = tmp04;
              block[ 8]  = tmp05;
              block[ 9]  = tmp06;
              block[10]  = tmp07;
              block[11]  = tmp08;
              block[12]  = tmp09;
              block[13]  = tmp10;
              block[14]  = tmp11;
              block[15]  = tmp12;
              carry[ 0]  = tmp13;
              carry[ 1]  = tmp14;
              carry[ 2]  = tmp15;
              carry[ 3]  = tmp16;
              break;
    case  4:  block[ 4] |= tmp00;
              block[ 5]  = tmp01;
              block[ 6]  = tmp02;
              block[ 7]  = tmp03;
              block[ 8]  = tmp04;
              block[ 9]  = tmp05;
              block[10]  = tmp06;
              block[11]  = tmp07;
              block[12]  = tmp08;
              block[13]  = tmp09;
              block[14]  = tmp10;
              block[15]  = tmp11;
              carry[ 0]  = tmp12;
              carry[ 1]  = tmp13;
              carry[ 2]  = tmp14;
              carry[ 3]  = tmp15;
              carry[ 4]  = tmp16;
              break;
    case  5:  block[ 5] |= tmp00;
              block[ 6]  = tmp01;
              block[ 7]  = tmp02;
              block[ 8]  = tmp03;
              block[ 9]  = tmp04;
              block[10]  = tmp05;
              block[11]  = tmp06;
              block[12]  = tmp07;
              block[13]  = tmp08;
              block[14]  = tmp09;
              block[15]  = tmp10;
              carry[ 0]  = tmp11;
              carry[ 1]  = tmp12;
              carry[ 2]  = tmp13;
              carry[ 3]  = tmp14;
              carry[ 4]  = tmp15;
              carry[ 5]  = tmp16;
              break;
    case  6:  block[ 6] |= tmp00;
              block[ 7]  = tmp01;
              block[ 8]  = tmp02;
              block[ 9]  = tmp03;
              block[10]  = tmp04;
              block[11]  = tmp05;
              block[12]  = tmp06;
              block[13]  = tmp07;
              block[14]  = tmp08;
              block[15]  = tmp09;
              carry[ 0]  = tmp10;
              carry[ 1]  = tmp11;
              carry[ 2]  = tmp12;
              carry[ 3]  = tmp13;
              carry[ 4]  = tmp14;
              carry[ 5]  = tmp15;
              carry[ 6]  = tmp16;
              break;
    case  7:  block[ 7] |= tmp00;
              block[ 8]  = tmp01;
              block[ 9]  = tmp02;
              block[10]  = tmp03;
              block[11]  = tmp04;
              block[12]  = tmp05;
              block[13]  = tmp06;
              block[14]  = tmp07;
              block[15]  = tmp08;
              carry[ 0]  = tmp09;
              carry[ 1]  = tmp10;
              carry[ 2]  = tmp11;
              carry[ 3]  = tmp12;
              carry[ 4]  = tmp13;
              carry[ 5]  = tmp14;
              carry[ 6]  = tmp15;
              carry[ 7]  = tmp16;
              break;
    case  8:  block[ 8] |= tmp00;
              block[ 9]  = tmp01;
              block[10]  = tmp02;
              block[11]  = tmp03;
              block[12]  = tmp04;
              block[13]  = tmp05;
              block[14]  = tmp06;
              block[15]  = tmp07;
              carry[ 0]  = tmp08;
              carry[ 1]  = tmp09;
              carry[ 2]  = tmp10;
              carry[ 3]  = tmp11;
              carry[ 4]  = tmp12;
              carry[ 5]  = tmp13;
              carry[ 6]  = tmp14;
              carry[ 7]  = tmp15;
              carry[ 8]  = tmp16;
              break;
    case  9:  block[ 9] |= tmp00;
              block[10]  = tmp01;
              block[11]  = tmp02;
              block[12]  = tmp03;
              block[13]  = tmp04;
              block[14]  = tmp05;
              block[15]  = tmp06;
              carry[ 0]  = tmp07;
              carry[ 1]  = tmp08;
              carry[ 2]  = tmp09;
              carry[ 3]  = tmp10;
              carry[ 4]  = tmp11;
              carry[ 5]  = tmp12;
              carry[ 6]  = tmp13;
              carry[ 7]  = tmp14;
              carry[ 8]  = tmp15;
              carry[ 9]  = tmp16;
              break;
    case 10:  block[10] |= tmp00;
              block[11]  = tmp01;
              block[12]  = tmp02;
              block[13]  = tmp03;
              block[14]  = tmp04;
              block[15]  = tmp05;
              carry[ 0]  = tmp06;
              carry[ 1]  = tmp07;
              carry[ 2]  = tmp08;
              carry[ 3]  = tmp09;
              carry[ 4]  = tmp10;
              carry[ 5]  = tmp11;
              carry[ 6]  = tmp12;
              carry[ 7]  = tmp13;
              carry[ 8]  = tmp14;
              carry[ 9]  = tmp15;
              carry[10]  = tmp16;
              break;
    case 11:  block[11] |= tmp00;
              block[12]  = tmp01;
              block[13]  = tmp02;
              block[14]  = tmp03;
              block[15]  = tmp04;
              carry[ 0]  = tmp05;
              carry[ 1]  = tmp06;
              carry[ 2]  = tmp07;
              carry[ 3]  = tmp08;
              carry[ 4]  = tmp09;
              carry[ 5]  = tmp10;
              carry[ 6]  = tmp11;
              carry[ 7]  = tmp12;
              carry[ 8]  = tmp13;
              carry[ 9]  = tmp14;
              carry[10]  = tmp15;
              carry[11]  = tmp16;
              break;
    case 12:  block[12] |= tmp00;
              block[13]  = tmp01;
              block[14]  = tmp02;
              block[15]  = tmp03;
              carry[ 0]  = tmp04;
              carry[ 1]  = tmp05;
              carry[ 2]  = tmp06;
              carry[ 3]  = tmp07;
              carry[ 4]  = tmp08;
              carry[ 5]  = tmp09;
              carry[ 6]  = tmp10;
              carry[ 7]  = tmp11;
              carry[ 8]  = tmp12;
              carry[ 9]  = tmp13;
              carry[10]  = tmp14;
              carry[11]  = tmp15;
              carry[12]  = tmp16;
              break;
    case 13:  block[13] |= tmp00;
              block[14]  = tmp01;
              block[15]  = tmp02;
              carry[ 0]  = tmp03;
              carry[ 1]  = tmp04;
              carry[ 2]  = tmp05;
              carry[ 3]  = tmp06;
              carry[ 4]  = tmp07;
              carry[ 5]  = tmp08;
              carry[ 6]  = tmp09;
              carry[ 7]  = tmp10;
              carry[ 8]  = tmp11;
              carry[ 9]  = tmp12;
              carry[10]  = tmp13;
              carry[11]  = tmp14;
              carry[12]  = tmp15;
              carry[13]  = tmp16;
              break;
    case 14:  block[14] |= tmp00;
              block[15]  = tmp01;
              carry[ 0]  = tmp02;
              carry[ 1]  = tmp03;
              carry[ 2]  = tmp04;
              carry[ 3]  = tmp05;
              carry[ 4]  = tmp06;
              carry[ 5]  = tmp07;
              carry[ 6]  = tmp08;
              carry[ 7]  = tmp09;
              carry[ 8]  = tmp10;
              carry[ 9]  = tmp11;
              carry[10]  = tmp12;
              carry[11]  = tmp13;
              carry[12]  = tmp14;
              carry[13]  = tmp15;
              carry[14]  = tmp16;
              break;
    case 15:  block[15] |= tmp00;
              carry[ 0]  = tmp01;
              carry[ 1]  = tmp02;
              carry[ 2]  = tmp03;
              carry[ 3]  = tmp04;
              carry[ 4]  = tmp05;
              carry[ 5]  = tmp06;
              carry[ 6]  = tmp07;
              carry[ 7]  = tmp08;
              carry[ 8]  = tmp09;
              carry[ 9]  = tmp10;
              carry[10]  = tmp11;
              carry[11]  = tmp12;
              carry[12]  = tmp13;
              carry[13]  = tmp14;
              carry[14]  = tmp15;
              carry[15]  = tmp16;
              break;
  }
}

__kernel void m13800_m04 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (MAYBE_VOLATILE u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[digests_offset].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    const u32x out_len2 = out_len * 2;

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    u32x w[16];

    w[ 0] = swap32 (w0[0]);
    w[ 1] = swap32 (w0[1]);
    w[ 2] = swap32 (w0[2]);
    w[ 3] = swap32 (w0[3]);
    w[ 4] = swap32 (w1[0]);
    w[ 5] = swap32 (w1[1]);
    w[ 6] = swap32 (w1[2]);
    w[ 7] = swap32 (w1[3]);
    w[ 8] = swap32 (w2[0]);
    w[ 9] = swap32 (w2[1]);
    w[10] = swap32 (w2[2]);
    w[11] = swap32 (w2[3]);
    w[12] = swap32 (w3[0]);
    w[13] = swap32 (w3[1]);
    w[14] = swap32 (w3[2]);
    w[15] = swap32 (w3[3]);

    u32x carry[16];

    carry[ 0] = s_esalt[ 0];
    carry[ 1] = s_esalt[ 1];
    carry[ 2] = s_esalt[ 2];
    carry[ 3] = s_esalt[ 3];
    carry[ 4] = s_esalt[ 4];
    carry[ 5] = s_esalt[ 5];
    carry[ 6] = s_esalt[ 6];
    carry[ 7] = s_esalt[ 7];
    carry[ 8] = s_esalt[ 8];
    carry[ 9] = s_esalt[ 9];
    carry[10] = s_esalt[10];
    carry[11] = s_esalt[11];
    carry[12] = s_esalt[12];
    carry[13] = s_esalt[13];
    carry[14] = s_esalt[14];
    carry[15] = s_esalt[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w, out_len2, carry);

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform_transport_vector (w, digest);

    w[ 0] = carry[ 0];
    w[ 1] = carry[ 1];
    w[ 2] = carry[ 2];
    w[ 3] = carry[ 3];
    w[ 4] = carry[ 4];
    w[ 5] = carry[ 5];
    w[ 6] = carry[ 6];
    w[ 7] = carry[ 7];
    w[ 8] = carry[ 8];
    w[ 9] = carry[ 9];
    w[10] = carry[10];
    w[11] = carry[11];
    w[12] = carry[12];
    w[13] = carry[13];
    w[14] = carry[14];
    w[15] = carry[15];

    carry[ 0] = s_esalt[16];
    carry[ 1] = s_esalt[17];
    carry[ 2] = s_esalt[18];
    carry[ 3] = s_esalt[19];
    carry[ 4] = s_esalt[20];
    carry[ 5] = s_esalt[21];
    carry[ 6] = s_esalt[22];
    carry[ 7] = s_esalt[23];
    carry[ 8] = s_esalt[24];
    carry[ 9] = s_esalt[25];
    carry[10] = s_esalt[26];
    carry[11] = s_esalt[27];
    carry[12] = s_esalt[28];
    carry[13] = s_esalt[29];
    carry[14] = s_esalt[30];
    carry[15] = s_esalt[31];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w, out_len2, carry);

    sha256_transform_transport_vector (w, digest);

    w[ 0] = carry[ 0];
    w[ 1] = carry[ 1];
    w[ 2] = carry[ 2];
    w[ 3] = carry[ 3];
    w[ 4] = carry[ 4];
    w[ 5] = carry[ 5];
    w[ 6] = carry[ 6];
    w[ 7] = carry[ 7];
    w[ 8] = carry[ 8];
    w[ 9] = carry[ 9];
    w[10] = carry[10];
    w[11] = carry[11];
    w[12] = carry[12];
    w[13] = carry[13];
    w[14] = carry[14];
    w[15] = carry[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    append_0x80_4x4 (w + 0, w + 4, w + 8, w + 12, out_len2 ^ 3);

    w[14] = 0;
    w[15] = (out_len2 + 128) * 8;

    sha256_transform_transport_vector (w, digest);

    const u32x d = digest[DGST_R0];
    const u32x h = digest[DGST_R1];
    const u32x c = digest[DGST_R2];
    const u32x g = digest[DGST_R3];

    COMPARE_M_SIMD (d, h, c, g);
  }
}

__kernel void m13800_m08 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
}

__kernel void m13800_m16 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
}

__kernel void m13800_s04 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (MAYBE_VOLATILE u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[digests_offset].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

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

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    const u32x out_len2 = out_len * 2;

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    u32x w[16];

    w[ 0] = swap32 (w0[0]);
    w[ 1] = swap32 (w0[1]);
    w[ 2] = swap32 (w0[2]);
    w[ 3] = swap32 (w0[3]);
    w[ 4] = swap32 (w1[0]);
    w[ 5] = swap32 (w1[1]);
    w[ 6] = swap32 (w1[2]);
    w[ 7] = swap32 (w1[3]);
    w[ 8] = swap32 (w2[0]);
    w[ 9] = swap32 (w2[1]);
    w[10] = swap32 (w2[2]);
    w[11] = swap32 (w2[3]);
    w[12] = swap32 (w3[0]);
    w[13] = swap32 (w3[1]);
    w[14] = swap32 (w3[2]);
    w[15] = swap32 (w3[3]);

    u32x carry[16];

    carry[ 0] = s_esalt[ 0];
    carry[ 1] = s_esalt[ 1];
    carry[ 2] = s_esalt[ 2];
    carry[ 3] = s_esalt[ 3];
    carry[ 4] = s_esalt[ 4];
    carry[ 5] = s_esalt[ 5];
    carry[ 6] = s_esalt[ 6];
    carry[ 7] = s_esalt[ 7];
    carry[ 8] = s_esalt[ 8];
    carry[ 9] = s_esalt[ 9];
    carry[10] = s_esalt[10];
    carry[11] = s_esalt[11];
    carry[12] = s_esalt[12];
    carry[13] = s_esalt[13];
    carry[14] = s_esalt[14];
    carry[15] = s_esalt[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w, out_len2, carry);

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform_transport_vector (w, digest);

    w[ 0] = carry[ 0];
    w[ 1] = carry[ 1];
    w[ 2] = carry[ 2];
    w[ 3] = carry[ 3];
    w[ 4] = carry[ 4];
    w[ 5] = carry[ 5];
    w[ 6] = carry[ 6];
    w[ 7] = carry[ 7];
    w[ 8] = carry[ 8];
    w[ 9] = carry[ 9];
    w[10] = carry[10];
    w[11] = carry[11];
    w[12] = carry[12];
    w[13] = carry[13];
    w[14] = carry[14];
    w[15] = carry[15];

    carry[ 0] = s_esalt[16];
    carry[ 1] = s_esalt[17];
    carry[ 2] = s_esalt[18];
    carry[ 3] = s_esalt[19];
    carry[ 4] = s_esalt[20];
    carry[ 5] = s_esalt[21];
    carry[ 6] = s_esalt[22];
    carry[ 7] = s_esalt[23];
    carry[ 8] = s_esalt[24];
    carry[ 9] = s_esalt[25];
    carry[10] = s_esalt[26];
    carry[11] = s_esalt[27];
    carry[12] = s_esalt[28];
    carry[13] = s_esalt[29];
    carry[14] = s_esalt[30];
    carry[15] = s_esalt[31];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w, out_len2, carry);

    sha256_transform_transport_vector (w, digest);

    w[ 0] = carry[ 0];
    w[ 1] = carry[ 1];
    w[ 2] = carry[ 2];
    w[ 3] = carry[ 3];
    w[ 4] = carry[ 4];
    w[ 5] = carry[ 5];
    w[ 6] = carry[ 6];
    w[ 7] = carry[ 7];
    w[ 8] = carry[ 8];
    w[ 9] = carry[ 9];
    w[10] = carry[10];
    w[11] = carry[11];
    w[12] = carry[12];
    w[13] = carry[13];
    w[14] = carry[14];
    w[15] = carry[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    append_0x80_4x4 (w + 0, w + 4, w + 8, w + 12, out_len2 ^ 3);

    w[14] = 0;
    w[15] = (out_len2 + 128) * 8;

    sha256_transform_transport_vector (w, digest);

    const u32x d = digest[DGST_R0];
    const u32x h = digest[DGST_R1];
    const u32x c = digest[DGST_R2];
    const u32x g = digest[DGST_R3];

    COMPARE_S_SIMD (d, h, c, g);
  }
}

__kernel void m13800_s08 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
}

__kernel void m13800_s16 (KERN_ATTR_RULES_ESALT (win8phone_t))
{
}
