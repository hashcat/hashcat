/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_hash_constants.h"
#include "inc_vendor.cl"
#include "inc_types.cl"

__kernel void amp (__global pw_t *pws, __global pw_t *pws_amp, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __constant const bf_t *bfs_buf, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 w0r = bfs_buf[0].i;

  pws_amp[gid].i[0] |= w0r;
}
