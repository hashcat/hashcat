/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_types.cl"
#include "inc_common.cl"

__kernel void amp (__global pw_t * restrict pws, __global pw_t * restrict pws_amp, __global const kernel_rule_t * restrict rules_buf, __global const pw_t * restrict combs_buf, __global const bf_t * restrict bfs_buf, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw = pws_amp[gid];

  pw_t comb = combs_buf[0];

  const u32 pw_len = pw.pw_len;

  const u32 comb_len = comb.pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
  {
    switch_buffer_by_offset_1x64_le_S (comb.i, pw_len);
  }

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset_1x64_le_S (pw.i, comb_len);
  }

  #pragma unroll
  for (int i = 0; i < 64; i++)
  {
    pw.i[i] |= comb.i[i];
  }

  pw.pw_len = pw_len + comb_len;

  pws[gid] = pw;
}
