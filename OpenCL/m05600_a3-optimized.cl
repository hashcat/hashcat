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
#include "inc_hash_md4.cl"
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

DECLSPEC void m05600m (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (netntlm_t), __local u32 *s_userdomain_buf, __local u32 *s_chall_buf)
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * prepare
   */

  const u32 userdomain_len = esalt_bufs[digests_offset].user_len
                           + esalt_bufs[digests_offset].domain_len;

  const u32 chall_len = esalt_bufs[digests_offset].srvchall_len
                      + esalt_bufs[digests_offset].clichall_len;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * pads
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_M_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

DECLSPEC void m05600s (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (netntlm_t), __local u32 *s_userdomain_buf, __local u32 *s_chall_buf)
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * prepare
   */

  const u32 userdomain_len = esalt_bufs[digests_offset].user_len
                           + esalt_bufs[digests_offset].domain_len;

  const u32 chall_len = esalt_bufs[digests_offset].srvchall_len
                      + esalt_bufs[digests_offset].clichall_len;

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * pads
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_S_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

__kernel void m05600_m04 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}

__kernel void m05600_m08 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}

__kernel void m05600_m16 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}

__kernel void m05600_s04 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}

__kernel void m05600_s08 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}

__kernel void m05600_s16 (KERN_ATTR_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[digests_offset].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[digests_offset].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max, s_userdomain_buf, s_chall_buf);
}
