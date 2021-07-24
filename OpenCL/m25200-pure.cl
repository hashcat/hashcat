/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define SNMPV3_ENGINEID_MAX 32
#define SNMPV3_SALT_MAX 752

typedef struct hmac_sha1_tmp
{
  u32 idx;
  sha1_ctx_t ctx;

} hmac_sha1_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_SALT_MAX];
  u32 salt_len;

  u8  engineID_buf[SNMPV3_ENGINEID_MAX];
  u32 engineID_len;

  u8 packet_number[8+1];

} snmpv3_t;

KERNEL_FQ void m25200_init (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const GLOBAL_AS u8 *pw_buf = (GLOBAL_AS u8 *) pws[gid].i;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * authkey
   */

  u32 idx = 0;

  u32 buf[16] = { 0 };

  u8 *tmp_buf = (u8 *) buf;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  for (int i = 0; i < 64; i++)
  {
    tmp_buf[i] = pw_buf[idx++];

    if (idx >= pw_len) idx = 0;
  }

  sha1_update_swap (&ctx, buf, 64);

  tmps[gid].idx = idx;
  tmps[gid].ctx = ctx;
}

KERNEL_FQ void m25200_loop (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const GLOBAL_AS u8 *pw_buf = (GLOBAL_AS u8 *) pws[gid].i;

  const u32 pw_len = pws[gid].pw_len;

  u32 idx = tmps[gid].idx;

  u32 buf[16] = { 0 };

  u8 *tmp_buf = (u8 *) buf;

  sha1_ctx_t ctx = tmps[gid].ctx;

  for (u32 j = 0; j < loop_cnt; j++)
  {
    for (int i = 0; i < 64; i++)
    {
      tmp_buf[i] = pw_buf[idx++];

      if (idx >= pw_len) idx = 0;
    }

    sha1_update_swap (&ctx, buf, 64);
  }

  tmps[gid].idx = idx;
  tmps[gid].ctx = ctx;
}

KERNEL_FQ void m25200_comp (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const GLOBAL_AS u8 *engineID_buf = esalt_bufs[DIGESTS_OFFSET].engineID_buf;

  u32 engineID_len = esalt_bufs[DIGESTS_OFFSET].engineID_len;

  sha1_ctx_t ctx = tmps[gid].ctx;

  sha1_final (&ctx);

  const u32 h[5] = {
    hc_swap32_S (ctx.h[0]),
    hc_swap32_S (ctx.h[1]),
    hc_swap32_S (ctx.h[2]),
    hc_swap32_S (ctx.h[3]),
    hc_swap32_S (ctx.h[4])
  };

  u32 tmp_buf[32] = { 0 };

  tmp_buf[0] = h[0];
  tmp_buf[1] = h[1];
  tmp_buf[2] = h[2];
  tmp_buf[3] = h[3];
  tmp_buf[4] = h[4];

  u8 *buf = (u8 *) (tmp_buf);

  u32 i = 20;
  u32 j;

  for (j = 0; j < engineID_len; j++)
  {
    buf[i++] = engineID_buf[j];
  }

  for (j = 0; j < 20; j++)
  {
    buf[i++] = buf[j];
  }

  sha1_init (&ctx);

  sha1_update_swap (&ctx, tmp_buf, i);

  sha1_final (&ctx);

  u32 key[16] = { 0 };

  key[0] = ctx.h[0];
  key[1] = ctx.h[1];
  key[2] = ctx.h[2];
  key[3] = ctx.h[3];
  key[4] = ctx.h[4];

  sha1_hmac_ctx_t hmac_ctx;

  sha1_hmac_init (&hmac_ctx, key, 20);

  sha1_hmac_update_global (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET].salt_buf, esalt_bufs[DIGESTS_OFFSET].salt_len);

  sha1_hmac_final (&hmac_ctx);

  const u32 r0 = hmac_ctx.opad.h[DGST_R0];
  const u32 r1 = hmac_ctx.opad.h[DGST_R1];
  const u32 r2 = hmac_ctx.opad.h[DGST_R2];
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
