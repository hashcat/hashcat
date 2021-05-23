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
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define SNMPV3_SALT_MAX 375
#define SNMPV3_ENGINEID_MAX 32
#define SNMPV3_MSG_AUTH_PARAMS_MAX 12

typedef struct hmac_md5_tmp
{
  u32  dgst[4];
  u32  out[3];

} hmac_md5_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_SALT_MAX];
  u32 salt_len;

  u8  engineID_buf[SNMPV3_ENGINEID_MAX];
  u32 engineID_len;

} snmpv3_t;

KERNEL_FQ void m25100_init (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
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

  md5_ctx_t ctx;

  md5_init (&ctx);

  for (int j = 0; j < 16384; j++)
  {
    for (int i = 0; i < 64; i++)
    {
      tmp_buf[i] = pw_buf[idx++];

      if (idx >= pw_len) idx = 0;
    }

    md5_update (&ctx, (u32 *)tmp_buf, 64);
  }

  md5_final (&ctx);

  const u32 h[4] = {
    hc_swap32_S (ctx.h[0]),
    hc_swap32_S (ctx.h[1]),
    hc_swap32_S (ctx.h[2]),
    hc_swap32_S (ctx.h[3])
  };

  u8 buf[72] = { 0 };

  #ifdef SNMPV3_OPT1

  buf[ 0] = as_uchar4 (h[0]).w;
  buf[ 1] = as_uchar4 (h[0]).z;
  buf[ 2] = as_uchar4 (h[0]).y;
  buf[ 3] = as_uchar4 (h[0]).x;

  buf[ 4] = as_uchar4 (h[1]).w;
  buf[ 5] = as_uchar4 (h[1]).z;
  buf[ 6] = as_uchar4 (h[1]).y;
  buf[ 7] = as_uchar4 (h[1]).x;

  buf[ 8] = as_uchar4 (h[2]).w;
  buf[ 9] = as_uchar4 (h[2]).z;
  buf[10] = as_uchar4 (h[2]).y;
  buf[11] = as_uchar4 (h[2]).x;

  buf[12] = as_uchar4 (h[3]).w;
  buf[13] = as_uchar4 (h[3]).z;
  buf[14] = as_uchar4 (h[3]).y;
  buf[15] = as_uchar4 (h[3]).x;

  #else // ! SNMPV3_OPT1

  buf[ 0] = (h[0] >> 24) & 0xff;
  buf[ 1] = (h[0] >> 16) & 0xff;
  buf[ 2] = (h[0] >> 8) & 0xff;
  buf[ 3] =  h[0] & 0xff;

  buf[ 4] = (h[1] >> 24) & 0xff;
  buf[ 5] = (h[1] >> 16) & 0xff;
  buf[ 6] = (h[1] >> 8) & 0xff;
  buf[ 7] =  h[1] & 0xff;

  buf[ 8] = (h[2] >> 24) & 0xff;
  buf[ 9] = (h[2] >> 16) & 0xff;
  buf[10] = (h[2] >> 8) & 0xff;
  buf[11] =  h[2] & 0xff;

  buf[12] = (h[3] >> 24) & 0xff;
  buf[13] = (h[3] >> 16) & 0xff;
  buf[14] = (h[3] >> 8) & 0xff;
  buf[15] =  h[3] & 0xff;

  #endif // SNMPV3_OPT1

  u32 j;
  u32 i = 16;

  for (j = 0; j < engineID_len; j++)
  {
    buf[i++] = engineID_buf[j];
  }

  for (j = 0; j < 16; j++)
  {
    buf[i++] = buf[j];
  }

  md5_init (&ctx);

  md5_update (&ctx, buf, i);

  md5_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
}

KERNEL_FQ void m25100_loop (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x key[16] = { 0 };

  key[0] = packv (tmps, dgst, gid, 0);
  key[1] = packv (tmps, dgst, gid, 1);
  key[2] = packv (tmps, dgst, gid, 2);
  key[3] = packv (tmps, dgst, gid, 3);

  u32x s[375] = { 0 };

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET].salt_len;

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = esalt_bufs[DIGESTS_OFFSET].salt_buf[idx];
  }

  md5_hmac_ctx_vector_t ctx;

  md5_hmac_init_vector (&ctx, key, 16);

  md5_hmac_update_vector (&ctx, s, salt_len);

  md5_hmac_final_vector (&ctx);

  unpackv (tmps, out, gid, 0, ctx.opad.h[DGST_R0]);
  unpackv (tmps, out, gid, 1, ctx.opad.h[DGST_R1]);
  unpackv (tmps, out, gid, 2, ctx.opad.h[DGST_R2]);
}

KERNEL_FQ void m25100_comp (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 r0 = hc_swap32_S (tmps[gid].out[DGST_R0]);
  const u32 r1 = hc_swap32_S (tmps[gid].out[DGST_R1]);
  const u32 r2 = hc_swap32_S (tmps[gid].out[DGST_R2]);
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
