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

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

__kernel void m04400_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
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
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

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

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * sha1
     */

    u32x w0_t = swap32 (w0[0]);
    u32x w1_t = swap32 (w0[1]);
    u32x w2_t = swap32 (w0[2]);
    u32x w3_t = swap32 (w0[3]);
    u32x w4_t = swap32 (w1[0]);
    u32x w5_t = swap32 (w1[1]);
    u32x w6_t = swap32 (w1[2]);
    u32x w7_t = swap32 (w1[3]);
    u32x w8_t = swap32 (w2[0]);
    u32x w9_t = swap32 (w2[1]);
    u32x wa_t = swap32 (w2[2]);
    u32x wb_t = swap32 (w2[3]);
    u32x wc_t = swap32 (w3[0]);
    u32x wd_t = swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_len * 8;

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

    a += SHA1M_A;
    b += SHA1M_B;
    c += SHA1M_C;
    d += SHA1M_D;
    e += SHA1M_E;

    /**
     * md5
     */

    w0_t = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    w1_t = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    w2_t = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    w3_t = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    w4_t = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    w5_t = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    w6_t = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    w7_t = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    w8_t = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    w9_t = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    wa_t = 0x80;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 40 * 8;
    wf_t = 0;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

__kernel void m04400_m08 (KERN_ATTR_BASIC ())
{
}

__kernel void m04400_m16 (KERN_ATTR_BASIC ())
{
}

__kernel void m04400_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
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
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

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

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * sha1
     */

    u32x w0_t = swap32 (w0[0]);
    u32x w1_t = swap32 (w0[1]);
    u32x w2_t = swap32 (w0[2]);
    u32x w3_t = swap32 (w0[3]);
    u32x w4_t = swap32 (w1[0]);
    u32x w5_t = swap32 (w1[1]);
    u32x w6_t = swap32 (w1[2]);
    u32x w7_t = swap32 (w1[3]);
    u32x w8_t = swap32 (w2[0]);
    u32x w9_t = swap32 (w2[1]);
    u32x wa_t = swap32 (w2[2]);
    u32x wb_t = swap32 (w2[3]);
    u32x wc_t = swap32 (w3[0]);
    u32x wd_t = swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_len * 8;

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

    a += SHA1M_A;
    b += SHA1M_B;
    c += SHA1M_C;
    d += SHA1M_D;
    e += SHA1M_E;

    /**
     * md5
     */

    w0_t = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    w1_t = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    w2_t = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    w3_t = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    w4_t = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    w5_t = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    w6_t = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    w7_t = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    w8_t = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    w9_t = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    wa_t = 0x80;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 40 * 8;
    wf_t = 0;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m04400_s08 (KERN_ATTR_BASIC ())
{
}

__kernel void m04400_s16 (KERN_ATTR_BASIC ())
{
}
