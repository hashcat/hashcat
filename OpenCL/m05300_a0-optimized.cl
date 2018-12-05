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
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"

DECLSPEC void hmac_md5_pad (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_md5_run (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);
}

__kernel void m05300_m04 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  __local u32 s_nr_buf[16];

  for (MAYBE_VOLATILE u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[digests_offset].nr_buf[i];
  }

  __local u32 s_msg_buf[128];

  for (MAYBE_VOLATILE u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[digests_offset].msg_buf[i];
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u32 nr_len  = esalt_bufs[digests_offset].nr_len;
  const u32 msg_len = esalt_bufs[digests_offset].msg_len[5];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = s_nr_buf[ 0];
    w0[1] = s_nr_buf[ 1];
    w0[2] = s_nr_buf[ 2];
    w0[3] = s_nr_buf[ 3];
    w1[0] = s_nr_buf[ 4];
    w1[1] = s_nr_buf[ 5];
    w1[2] = s_nr_buf[ 6];
    w1[3] = s_nr_buf[ 7];
    w2[0] = s_nr_buf[ 8];
    w2[1] = s_nr_buf[ 9];
    w2[2] = s_nr_buf[10];
    w2[3] = s_nr_buf[11];
    w3[0] = s_nr_buf[12];
    w3[1] = s_nr_buf[13];
    w3[2] = (64 + nr_len) * 8;
    w3[3] = 0;

    u32x digest[4];

    hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
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

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0[0] = s_msg_buf[off +  0];
      w0[1] = s_msg_buf[off +  1];
      w0[2] = s_msg_buf[off +  2];
      w0[3] = s_msg_buf[off +  3];
      w1[0] = s_msg_buf[off +  4];
      w1[1] = s_msg_buf[off +  5];
      w1[2] = s_msg_buf[off +  6];
      w1[3] = s_msg_buf[off +  7];
      w2[0] = s_msg_buf[off +  8];
      w2[1] = s_msg_buf[off +  9];
      w2[2] = s_msg_buf[off + 10];
      w2[3] = s_msg_buf[off + 11];
      w3[0] = s_msg_buf[off + 12];
      w3[1] = s_msg_buf[off + 13];
      w3[2] = s_msg_buf[off + 14];
      w3[3] = s_msg_buf[off + 15];

      md5_transform_vector (w0, w1, w2, w3, ipad);
    }

    w0[0] = s_msg_buf[off +  0];
    w0[1] = s_msg_buf[off +  1];
    w0[2] = s_msg_buf[off +  2];
    w0[3] = s_msg_buf[off +  3];
    w1[0] = s_msg_buf[off +  4];
    w1[1] = s_msg_buf[off +  5];
    w1[2] = s_msg_buf[off +  6];
    w1[3] = s_msg_buf[off +  7];
    w2[0] = s_msg_buf[off +  8];
    w2[1] = s_msg_buf[off +  9];
    w2[2] = s_msg_buf[off + 10];
    w2[3] = s_msg_buf[off + 11];
    w3[0] = s_msg_buf[off + 12];
    w3[1] = s_msg_buf[off + 13];
    w3[2] = (64 + msg_len) * 8;
    w3[3] = 0;

    hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

    COMPARE_M_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

__kernel void m05300_m08 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
}

__kernel void m05300_m16 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
}

__kernel void m05300_s04 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  __local u32 s_nr_buf[16];

  for (MAYBE_VOLATILE u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = esalt_bufs[digests_offset].nr_buf[i];
  }

  __local u32 s_msg_buf[128];

  for (MAYBE_VOLATILE u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = esalt_bufs[digests_offset].msg_buf[i];
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u32 nr_len  = esalt_bufs[digests_offset].nr_len;
  const u32 msg_len = esalt_bufs[digests_offset].msg_len[5];

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

    apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pads
     */

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = s_nr_buf[ 0];
    w0[1] = s_nr_buf[ 1];
    w0[2] = s_nr_buf[ 2];
    w0[3] = s_nr_buf[ 3];
    w1[0] = s_nr_buf[ 4];
    w1[1] = s_nr_buf[ 5];
    w1[2] = s_nr_buf[ 6];
    w1[3] = s_nr_buf[ 7];
    w2[0] = s_nr_buf[ 8];
    w2[1] = s_nr_buf[ 9];
    w2[2] = s_nr_buf[10];
    w2[3] = s_nr_buf[11];
    w3[0] = s_nr_buf[12];
    w3[1] = s_nr_buf[13];
    w3[2] = (64 + nr_len) * 8;
    w3[3] = 0;

    u32x digest[4];

    hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
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

    hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0[0] = s_msg_buf[off +  0];
      w0[1] = s_msg_buf[off +  1];
      w0[2] = s_msg_buf[off +  2];
      w0[3] = s_msg_buf[off +  3];
      w1[0] = s_msg_buf[off +  4];
      w1[1] = s_msg_buf[off +  5];
      w1[2] = s_msg_buf[off +  6];
      w1[3] = s_msg_buf[off +  7];
      w2[0] = s_msg_buf[off +  8];
      w2[1] = s_msg_buf[off +  9];
      w2[2] = s_msg_buf[off + 10];
      w2[3] = s_msg_buf[off + 11];
      w3[0] = s_msg_buf[off + 12];
      w3[1] = s_msg_buf[off + 13];
      w3[2] = s_msg_buf[off + 14];
      w3[3] = s_msg_buf[off + 15];

      md5_transform_vector (w0, w1, w2, w3, ipad);
    }

    w0[0] = s_msg_buf[off +  0];
    w0[1] = s_msg_buf[off +  1];
    w0[2] = s_msg_buf[off +  2];
    w0[3] = s_msg_buf[off +  3];
    w1[0] = s_msg_buf[off +  4];
    w1[1] = s_msg_buf[off +  5];
    w1[2] = s_msg_buf[off +  6];
    w1[3] = s_msg_buf[off +  7];
    w2[0] = s_msg_buf[off +  8];
    w2[1] = s_msg_buf[off +  9];
    w2[2] = s_msg_buf[off + 10];
    w2[3] = s_msg_buf[off + 11];
    w3[0] = s_msg_buf[off + 12];
    w3[1] = s_msg_buf[off + 13];
    w3[2] = (64 + msg_len) * 8;
    w3[3] = 0;

    hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

    COMPARE_S_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

__kernel void m05300_s08 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
}

__kernel void m05300_s16 (KERN_ATTR_RULES_ESALT (ikepsk_t))
{
}
