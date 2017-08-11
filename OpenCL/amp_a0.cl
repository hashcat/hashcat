/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_hash_constants.h"
#include "inc_vendor.cl"
#include "inc_types.cl"
#include "inc_rp.h"
#include "inc_rp.cl"

__kernel void amp (__global pw_t *pws, __global pw_t *pws_amp, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  if (rules_buf[0].cmds[0] == RULE_OP_MANGLE_NOOP && rules_buf[0].cmds[1] == 0) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_lenv = ceil ((float) pw_len / 4);

  u32 w[64] = { 0 };

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * do work
   */

  u32 out_buf[64] = { 0 };

  const u32 out_len = apply_rules (rules_buf[0].cmds, w, pw_len, out_buf);

  /**
   * out
   */

  const u32 out_lenv = ceil ((float) out_len / 4);

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    pws_amp[gid].i[idx] = out_buf[idx];
  }

  for (int idx = pw_lenv; idx < 64; idx++)
  {
    pws_amp[gid].i[idx] = 0;
  }

  pws_amp[gid].pw_len = out_len;
}
