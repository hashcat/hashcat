/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__kernel void m01470_init (KERN_ATTR_TMPS (sha256_ctx_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update (&ctx0, w, pw_len);

  sha256_final (&ctx0);

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, ctx0.h, pw_len);

  sha256_update (&ctx, s, salt_len);

  sha256_final (&ctx);

  tmps[gid].sha256_ctx = ctx;
}

__kernel void m01470_loop (KERN_ATTR_TMPS (sha256_ctx_t))
{
}

__kernel void m01470_comp (KERN_ATTR_TMPS (sha256_ctx_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id  (0);

  if (gid >= gid_max) return;

  sha256_ctx_t sha256_ctx = tmps[gid].sha256_ctx;

  const u32 r0 = sha256_ctx.h[0];
  const u32 r1 = sha256_ctx.h[1];
  const u32 r2 = sha256_ctx.h[2];
  const u32 r3 = sha256_ctx.h[3];

  #define il_pos 0

  #include COMPARE_M
}
