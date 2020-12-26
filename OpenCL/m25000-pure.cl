/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#define SNMPV3_OPT1

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"
#endif

#define SNMPV3_SALT_MAX 375
#define SNMPV3_ENGINEID_MAX 32
#define SNMPV3_MSG_AUTH_PARAMS_MAX 12

typedef struct hmac_md5sha1_tmp
{
  u32  dgst_md5[4];
  u32  dgst_sha1[5];

  u32  out_md5[3];
  u32  out_sha1[3];

} hmac_md5sha1_tmp_t;

typedef struct snmpv3_multi
{
  u32 salt_buf_md5[SNMPV3_SALT_MAX];
  u32 salt_buf_sha1[SNMPV3_SALT_MAX];
  u32 salt_len;

  u8 engineID_buf[SNMPV3_ENGINEID_MAX];
  u32 engineID_len;

} snmpv3_multi_t;

KERNEL_FQ void m25000_init (KERN_ATTR_TMPS_ESALT (hmac_md5sha1_tmp_t, snmpv3_multi_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const global u8 *pw_buf = (global u8 *) pws[gid].i;

  const u32 pw_len = pws[gid].pw_len;

  const global u8 *engineID_buf = esalt_bufs[DIGESTS_OFFSET].engineID_buf;

  u32 engineID_len = esalt_bufs[DIGESTS_OFFSET].engineID_len;

  /**
   * authkey
   */

  u32 idx = 0;

  u8 tmp_buf[72] = { 0 };

   md5_ctx_t  md5_ctx;
  sha1_ctx_t sha1_ctx;

   md5_init  (&md5_ctx);
  sha1_init (&sha1_ctx);

  for (int j = 0; j < 16384; j++)
  {
    for (int i = 0; i < 64; i++)
    {
      tmp_buf[i] = pw_buf[idx++];

      if (idx >= pw_len) idx = 0;
    }

     md5_update      (&md5_ctx , (u32 *)tmp_buf, 64);
    sha1_update_swap (&sha1_ctx, (u32 *)tmp_buf, 64);
  }

   md5_final (&md5_ctx);
  sha1_final (&sha1_ctx);

  const u32 h_md5[4] = {
    hc_swap32_S (md5_ctx.h[0]),
    hc_swap32_S (md5_ctx.h[1]),
    hc_swap32_S (md5_ctx.h[2]),
    hc_swap32_S (md5_ctx.h[3])
  };

  const u32 h_sha1[5] = {
    hc_swap32_S (sha1_ctx.h[0]),
    hc_swap32_S (sha1_ctx.h[1]),
    hc_swap32_S (sha1_ctx.h[2]),
    hc_swap32_S (sha1_ctx.h[3]),
    hc_swap32_S (sha1_ctx.h[4])
  };

  u8  md5_buf[72] = { 0 };
  u8 sha1_buf[72] = { 0 };

  #ifdef SNMPV3_OPT1

  sha1_buf[ 0] = as_uchar4 (h_sha1[0]).x;
  sha1_buf[ 1] = as_uchar4 (h_sha1[0]).y;
  sha1_buf[ 2] = as_uchar4 (h_sha1[0]).z;
  sha1_buf[ 3] = as_uchar4 (h_sha1[0]).w;

   md5_buf[ 3] = as_uchar4 (h_md5[ 0]).x;
   md5_buf[ 2] = as_uchar4 (h_md5[ 0]).y;
   md5_buf[ 1] = as_uchar4 (h_md5[ 0]).z;
   md5_buf[ 0] = as_uchar4 (h_md5[ 0]).w;

  sha1_buf[ 4] = as_uchar4 (h_sha1[1]).x;
  sha1_buf[ 5] = as_uchar4 (h_sha1[1]).y;
  sha1_buf[ 6] = as_uchar4 (h_sha1[1]).z;
  sha1_buf[ 7] = as_uchar4 (h_sha1[1]).w;

   md5_buf[ 7] = as_uchar4 (h_md5[ 1]).x;
   md5_buf[ 6] = as_uchar4 (h_md5[ 1]).y;
   md5_buf[ 5] = as_uchar4 (h_md5[ 1]).z;
   md5_buf[ 4] = as_uchar4 (h_md5[ 1]).w;

  sha1_buf[ 8] = as_uchar4 (h_sha1[2]).x;
  sha1_buf[ 9] = as_uchar4 (h_sha1[2]).y;
  sha1_buf[10] = as_uchar4 (h_sha1[2]).z;
  sha1_buf[11] = as_uchar4 (h_sha1[2]).w;

   md5_buf[11] = as_uchar4 (h_md5[ 2]).x;
   md5_buf[10] = as_uchar4 (h_md5[ 2]).y;
   md5_buf[ 9] = as_uchar4 (h_md5[ 2]).z;
   md5_buf[ 8] = as_uchar4 (h_md5[ 2]).w;

  sha1_buf[12] = as_uchar4 (h_sha1[3]).x;
  sha1_buf[13] = as_uchar4 (h_sha1[3]).y;
  sha1_buf[14] = as_uchar4 (h_sha1[3]).z;
  sha1_buf[15] = as_uchar4 (h_sha1[3]).w;

   md5_buf[15] = as_uchar4 (h_md5[ 3]).x;
   md5_buf[14] = as_uchar4 (h_md5[ 3]).y;
   md5_buf[13] = as_uchar4 (h_md5[ 3]).z;
   md5_buf[12] = as_uchar4 (h_md5[ 3]).w;

  sha1_buf[16] = as_uchar4 (h_sha1[4]).x;
  sha1_buf[17] = as_uchar4 (h_sha1[4]).y;
  sha1_buf[18] = as_uchar4 (h_sha1[4]).z;
  sha1_buf[19] = as_uchar4 (h_sha1[4]).w;

  #else // ! SNMPV3_OPT1

  sha1_buf[ 0] =  h_sha1[0] & 0xff;
  sha1_buf[ 1] = (h_sha1[0] >> 8) & 0xff;
  sha1_buf[ 2] = (h_sha1[0] >> 16) & 0xff;
  sha1_buf[ 3] = (h_sha1[0] >> 24) & 0xff;

   md5_buf[ 3] =  h_md5[ 0] & 0xff;
   md5_buf[ 2] = (h_md5[ 0] >> 8) & 0xff;
   md5_buf[ 1] = (h_md5[ 0] >> 16) & 0xff;
   md5_buf[ 0] = (h_md5[ 0] >> 24) & 0xff;

  sha1_buf[ 4] =  h_sha1[1] & 0xff;
  sha1_buf[ 5] = (h_sha1[1] >> 8) & 0xff;
  sha1_buf[ 6] = (h_sha1[1] >> 16) & 0xff;
  sha1_buf[ 7] = (h_sha1[1] >> 24) & 0xff;

   md5_buf[ 7] =  h_md5[ 1] & 0xff;
   md5_buf[ 6] = (h_md5[ 1] >> 8) & 0xff;
   md5_buf[ 5] = (h_md5[ 1] >> 16) & 0xff;
   md5_buf[ 4] = (h_md5[ 1] >> 24) & 0xff;

  sha1_buf[ 8] =  h_sha1[2] & 0xff;
  sha1_buf[ 9] = (h_sha1[2] >> 8) & 0xff;
  sha1_buf[10] = (h_sha1[2] >> 16) & 0xff;
  sha1_buf[11] = (h_sha1[2] >> 24) & 0xff;

   md5_buf[11] =  h_md5[ 2] & 0xff;
   md5_buf[10] = (h_md5[ 2] >> 8) & 0xff;
   md5_buf[ 9] = (h_md5[ 2] >> 16) & 0xff;
   md5_buf[ 8] = (h_md5[ 2] >> 24) & 0xff;

  sha1_buf[12] =  h_sha1[3] & 0xff;
  sha1_buf[13] = (h_sha1[3] >> 8) & 0xff;
  sha1_buf[14] = (h_sha1[3] >> 16) & 0xff;
  sha1_buf[15] = (h_sha1[3] >> 24) & 0xff;

   md5_buf[15] =  h_md5[ 3] & 0xff;
   md5_buf[14] = (h_md5[ 3] >> 8) & 0xff;
   md5_buf[13] = (h_md5[ 3] >> 16) & 0xff;
   md5_buf[12] = (h_md5[ 3] >> 24) & 0xff;

  sha1_buf[16] =  h_sha1[4] & 0xff;
  sha1_buf[17] = (h_sha1[4] >> 8) & 0xff;
  sha1_buf[18] = (h_sha1[4] >> 16) & 0xff;
  sha1_buf[19] = (h_sha1[4] >> 24) & 0xff;

  #endif // SNMPV3_OPT1

  u32 j;
  u32 i = 20, o = 16;

  for (j = 0; j < engineID_len; j++)
  {
    sha1_buf[i++] = engineID_buf[j];
     md5_buf[o++] = engineID_buf[j];
  }

  for (j = 0; j < 16; j++)
  {
    sha1_buf[i++] = sha1_buf[j];
     md5_buf[o++] =  md5_buf[j];
  }

  for (j = 16; j < 20; j++)
  {
    sha1_buf[i++] = sha1_buf[j];
  }

   md5_init (&md5_ctx);
  sha1_init (&sha1_ctx);

   md5_update      (&md5_ctx,  md5_buf,  o);
  sha1_update_swap (&sha1_ctx, sha1_buf, i);

   md5_final (& md5_ctx);
  sha1_final (&sha1_ctx);

  unpackv (tmps, dgst_sha1, gid, 0, sha1_ctx.h[0]);
  unpackv (tmps, dgst_sha1, gid, 1, sha1_ctx.h[1]);
  unpackv (tmps, dgst_sha1, gid, 2, sha1_ctx.h[2]);
  unpackv (tmps, dgst_sha1, gid, 3, sha1_ctx.h[3]);
  unpackv (tmps, dgst_sha1, gid, 4, sha1_ctx.h[4]);

  unpackv (tmps, dgst_md5,  gid, 0, md5_ctx.h[0]);
  unpackv (tmps, dgst_md5,  gid, 1, md5_ctx.h[1]);
  unpackv (tmps, dgst_md5,  gid, 2, md5_ctx.h[2]);
  unpackv (tmps, dgst_md5,  gid, 3, md5_ctx.h[3]);
}

KERNEL_FQ void m25000_loop (KERN_ATTR_TMPS_ESALT (hmac_md5sha1_tmp_t, snmpv3_multi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x  md5_key[16] = { 0 };
  u32x sha1_key[16] = { 0 };

   md5_key[0] = packv (tmps, dgst_md5,  gid, 0);
   md5_key[1] = packv (tmps, dgst_md5,  gid, 1);
   md5_key[2] = packv (tmps, dgst_md5,  gid, 2);
   md5_key[3] = packv (tmps, dgst_md5,  gid, 3);

  sha1_key[0] = packv (tmps, dgst_sha1, gid, 0);
  sha1_key[1] = packv (tmps, dgst_sha1, gid, 1);
  sha1_key[2] = packv (tmps, dgst_sha1, gid, 2);
  sha1_key[3] = packv (tmps, dgst_sha1, gid, 3);
  sha1_key[4] = packv (tmps, dgst_sha1, gid, 4);

  u32x  s_md5[375] = { 0 };
  u32x s_sha1[375] = { 0 };

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET].salt_len;

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
     s_md5[idx] = esalt_bufs[DIGESTS_OFFSET].salt_buf_md5[idx];
    s_sha1[idx] = esalt_bufs[DIGESTS_OFFSET].salt_buf_sha1[idx];
  }

   md5_hmac_ctx_vector_t md5_ctx;
  sha1_hmac_ctx_vector_t sha1_ctx;

   md5_hmac_init_vector (&md5_ctx,  md5_key,  16);
  sha1_hmac_init_vector (&sha1_ctx, sha1_key, 20);

   md5_hmac_update_vector (&md5_ctx,  s_md5,  salt_len);
  sha1_hmac_update_vector (&sha1_ctx, s_sha1, salt_len);

   md5_hmac_final_vector (&md5_ctx);
  sha1_hmac_final_vector (&sha1_ctx);

  unpackv (tmps, out_md5,  gid, 0, md5_ctx.opad.h[DGST_R0]);
  unpackv (tmps, out_md5,  gid, 1, md5_ctx.opad.h[DGST_R1]);
  unpackv (tmps, out_md5,  gid, 2, md5_ctx.opad.h[DGST_R2]);

  unpackv (tmps, out_sha1, gid, 0, sha1_ctx.opad.h[DGST_R0]);
  unpackv (tmps, out_sha1, gid, 1, sha1_ctx.opad.h[DGST_R1]);
  unpackv (tmps, out_sha1, gid, 2, sha1_ctx.opad.h[DGST_R2]);
}

KERNEL_FQ void m25000_comp (KERN_ATTR_TMPS_ESALT (hmac_md5sha1_tmp_t, snmpv3_multi_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 s0_r0 = hc_swap32_S (tmps[gid].out_md5[DGST_R0]);
  const u32 s0_r1 = hc_swap32_S (tmps[gid].out_md5[DGST_R1]);
  const u32 s0_r2 = hc_swap32_S (tmps[gid].out_md5[DGST_R2]);
  const u32 s0_r3 = 0;

  const u32 s1_r0 = tmps[gid].out_sha1[DGST_R0];
  const u32 s1_r1 = tmps[gid].out_sha1[DGST_R1];
  const u32 s1_r2 = tmps[gid].out_sha1[DGST_R2];
  const u32 s1_r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC

  u32 digest_tp_s0[4];

  digest_tp_s0[0] = s0_r0;
  digest_tp_s0[1] = s0_r1;
  digest_tp_s0[2] = s0_r2;
  digest_tp_s0[3] = s0_r3;

  u32 digest_tp_s1[4];

  digest_tp_s1[0] = s1_r0;
  digest_tp_s1[1] = s1_r1;
  digest_tp_s1[2] = s1_r2;
  digest_tp_s1[3] = s1_r3;

  if (check (digest_tp_s0,
             bitmaps_buf_s1_a,
             bitmaps_buf_s1_b,
             bitmaps_buf_s1_c,
             bitmaps_buf_s1_d,
             bitmaps_buf_s2_a,
             bitmaps_buf_s2_b,
             bitmaps_buf_s2_c,
             bitmaps_buf_s2_d,
             bitmap_mask,
             bitmap_shift1,
             bitmap_shift2))
  {
    int digest_pos = find_hash (digest_tp_s0, digests_cnt, &digests_buf[DIGESTS_OFFSET]);

    if (digest_pos != -1)
    {
      const u32 final_hash_pos = DIGESTS_OFFSET + digest_pos;

      if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS, digests_cnt, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }

  if (check (digest_tp_s1,
             bitmaps_buf_s1_a,
             bitmaps_buf_s1_b,
             bitmaps_buf_s1_c,
             bitmaps_buf_s1_d,
             bitmaps_buf_s2_a,
             bitmaps_buf_s2_b,
             bitmaps_buf_s2_c,
             bitmaps_buf_s2_d,
             bitmap_mask,
             bitmap_shift1,
             bitmap_shift2))
  {
    int digest_pos = find_hash (digest_tp_s1, digests_cnt, &digests_buf[DIGESTS_OFFSET]);

    if (digest_pos != -1)
    {
      const u32 final_hash_pos = DIGESTS_OFFSET + digest_pos;

      if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS, digests_cnt, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }
  #endif
}
