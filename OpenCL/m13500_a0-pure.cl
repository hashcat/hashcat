/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"

__kernel void m13500_mxx (KERN_ATTR_RULES_ESALT (pstoken_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * salt
   */

  const u32 pc_offset = esalt_bufs[digests_offset].pc_offset;

  sha1_ctx_t ctx0;

  ctx0.h[0] = esalt_bufs[digests_offset].pc_digest[0];
  ctx0.h[1] = esalt_bufs[digests_offset].pc_digest[1];
  ctx0.h[2] = esalt_bufs[digests_offset].pc_digest[2];
  ctx0.h[3] = esalt_bufs[digests_offset].pc_digest[3];
  ctx0.h[4] = esalt_bufs[digests_offset].pc_digest[4];

  ctx0.w0[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  0]);
  ctx0.w0[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  1]);
  ctx0.w0[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  2]);
  ctx0.w0[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  3]);
  ctx0.w1[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  4]);
  ctx0.w1[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  5]);
  ctx0.w1[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  6]);
  ctx0.w1[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  7]);
  ctx0.w2[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  8]);
  ctx0.w2[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  9]);
  ctx0.w2[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 10]);
  ctx0.w2[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 11]);
  ctx0.w3[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 12]);
  ctx0.w3[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 13]);
  ctx0.w3[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 14]);
  ctx0.w3[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 15]);

  ctx0.len = esalt_bufs[digests_offset].salt_len;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx = ctx0;

    sha1_update_utf16le_swap (&ctx, tmp.i, tmp.pw_len);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m13500_sxx (KERN_ATTR_RULES_ESALT (pstoken_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

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
   * salt
   */

  const u32 pc_offset = esalt_bufs[digests_offset].pc_offset;

  sha1_ctx_t ctx0;

  ctx0.h[0] = esalt_bufs[digests_offset].pc_digest[0];
  ctx0.h[1] = esalt_bufs[digests_offset].pc_digest[1];
  ctx0.h[2] = esalt_bufs[digests_offset].pc_digest[2];
  ctx0.h[3] = esalt_bufs[digests_offset].pc_digest[3];
  ctx0.h[4] = esalt_bufs[digests_offset].pc_digest[4];

  ctx0.w0[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  0]);
  ctx0.w0[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  1]);
  ctx0.w0[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  2]);
  ctx0.w0[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  3]);
  ctx0.w1[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  4]);
  ctx0.w1[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  5]);
  ctx0.w1[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  6]);
  ctx0.w1[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  7]);
  ctx0.w2[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  8]);
  ctx0.w2[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset +  9]);
  ctx0.w2[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 10]);
  ctx0.w2[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 11]);
  ctx0.w3[0] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 12]);
  ctx0.w3[1] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 13]);
  ctx0.w3[2] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 14]);
  ctx0.w3[3] = swap32_S (esalt_bufs[digests_offset].salt_buf[pc_offset + 15]);

  ctx0.len = esalt_bufs[digests_offset].salt_len;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx = ctx0;

    sha1_update_utf16le_swap (&ctx, tmp.i, tmp.pw_len);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
