/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"

__constant u32a padding[8] =
{
  0x5e4ebf28,
  0x418a754e,
  0x564e0064,
  0x0801faff,
  0xb6002e2e,
  0x803e68d0,
  0xfea90c2f,
  0x7a695364
};

typedef struct
{
  u8 S[256];

  u32 wtf_its_faster;

} RC4_KEY;

DECLSPEC void swap (__local RC4_KEY *rc4_key, const u8 i, const u8 j)
{
  u8 tmp;

  tmp           = rc4_key->S[i];
  rc4_key->S[i] = rc4_key->S[j];
  rc4_key->S[j] = tmp;
}

DECLSPEC void rc4_init_16 (__local RC4_KEY *rc4_key, const u32 *data)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  __local u32 *ptr = (__local u32 *) rc4_key->S;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 64; i++)
  {
    ptr[i] = v; v += a;
  }

  const u32 d0 = data[0] >>  0;
  const u32 d1 = data[0] >>  8;
  const u32 d2 = data[0] >> 16;
  const u32 d3 = data[0] >> 24;
  const u32 d4 = data[1] >>  0;

  u32 j = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 255; i += 5)
  {
    j += rc4_key->S[i + 0] + d0; swap (rc4_key, i + 0, j);
    j += rc4_key->S[i + 1] + d1; swap (rc4_key, i + 1, j);
    j += rc4_key->S[i + 2] + d2; swap (rc4_key, i + 2, j);
    j += rc4_key->S[i + 3] + d3; swap (rc4_key, i + 3, j);
    j += rc4_key->S[i + 4] + d4; swap (rc4_key, i + 4, j);
  }

  j += rc4_key->S[255] + d0; swap (rc4_key, 255, j);
}

DECLSPEC u8 rc4_next_16 (__local RC4_KEY *rc4_key, u8 i, u8 j, __constant u32 *in, u32 *out)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u8 idx;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  0;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  8;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 16;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 24;

    out[k] = in[k] ^ xor4;
  }

  return j;
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_m04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  __local RC4_KEY rc4_keys[64];

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[digests_offset].o_buf[0];
  o_buf[1] = esalt_bufs[digests_offset].o_buf[1];
  o_buf[2] = esalt_bufs[digests_offset].o_buf[2];
  o_buf[3] = esalt_bufs[digests_offset].o_buf[3];
  o_buf[4] = esalt_bufs[digests_offset].o_buf[4];
  o_buf[5] = esalt_bufs[digests_offset].o_buf[5];
  o_buf[6] = esalt_bufs[digests_offset].o_buf[6];
  o_buf[7] = esalt_bufs[digests_offset].o_buf[7];

  u32 P = esalt_bufs[digests_offset].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[digests_offset].id_buf[0];
  id_buf[1] = esalt_bufs[digests_offset].id_buf[1];
  id_buf[2] = esalt_bufs[digests_offset].id_buf[2];
  id_buf[3] = esalt_bufs[digests_offset].id_buf[3];

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = 0;
    w0[3] = 0;

    /**
     * pdf
     */

    rc4_init_16 (rc4_key, w0);

    u32 out[4];

    rc4_next_16 (rc4_key, 0, 0, padding, out);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_m08 (KERN_ATTR_ESALT (pdf_t))
{
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_m16 (KERN_ATTR_ESALT (pdf_t))
{
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_s04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  __local RC4_KEY rc4_keys[64];

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[digests_offset].o_buf[0];
  o_buf[1] = esalt_bufs[digests_offset].o_buf[1];
  o_buf[2] = esalt_bufs[digests_offset].o_buf[2];
  o_buf[3] = esalt_bufs[digests_offset].o_buf[3];
  o_buf[4] = esalt_bufs[digests_offset].o_buf[4];
  o_buf[5] = esalt_bufs[digests_offset].o_buf[5];
  o_buf[6] = esalt_bufs[digests_offset].o_buf[6];
  o_buf[7] = esalt_bufs[digests_offset].o_buf[7];

  u32 P = esalt_bufs[digests_offset].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[digests_offset].id_buf[0];
  id_buf[1] = esalt_bufs[digests_offset].id_buf[1];
  id_buf[2] = esalt_bufs[digests_offset].id_buf[2];
  id_buf[3] = esalt_bufs[digests_offset].id_buf[3];

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = 0;
    w0[3] = 0;

    /**
     * pdf
     */

    rc4_init_16 (rc4_key, w0);

    u32 out[4];

    rc4_next_16 (rc4_key, 0, 0, padding, out);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_s08 (KERN_ATTR_ESALT (pdf_t))
{
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m10410_s16 (KERN_ATTR_ESALT (pdf_t))
{
}
