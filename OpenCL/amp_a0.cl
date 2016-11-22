/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_hash_constants.h"
#include "inc_vendor.cl"
#include "inc_types.cl"

#include "inc_rp.h"
#include "inc_rp.cl"

__kernel void amp (__global pw_t *pws, __global pw_t *pws_amp, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 pw_len = pws[gid].pw_len;

  if (rules_buf[0].cmds[0] == RULE_OP_MANGLE_NOOP && rules_buf[0].cmds[1] == 0)
  {
    pws_amp[gid].i[ 0] = pws[gid].i[ 0];
    pws_amp[gid].i[ 1] = pws[gid].i[ 1];
    pws_amp[gid].i[ 2] = pws[gid].i[ 2];
    pws_amp[gid].i[ 3] = pws[gid].i[ 3];
    pws_amp[gid].i[ 4] = pws[gid].i[ 4];
    pws_amp[gid].i[ 5] = pws[gid].i[ 5];
    pws_amp[gid].i[ 6] = pws[gid].i[ 6];
    pws_amp[gid].i[ 7] = pws[gid].i[ 7];
    pws_amp[gid].i[ 8] = pws[gid].i[ 8];
    pws_amp[gid].i[ 9] = pws[gid].i[ 9];
    pws_amp[gid].i[10] = pws[gid].i[10];
    pws_amp[gid].i[11] = pws[gid].i[11];
    pws_amp[gid].i[12] = pws[gid].i[12];
    pws_amp[gid].i[13] = pws[gid].i[13];
    pws_amp[gid].i[14] = pws[gid].i[14];
    pws_amp[gid].i[15] = pws[gid].i[15];

    pws_amp[gid].pw_len = pws[gid].pw_len;

    return;
  }

  u32 w0[4];
  u32 w1[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  const u32 out_len = apply_rules (rules_buf[0].cmds, w0, w1, pw_len);

  pws_amp[gid].i[0] = w0[0];
  pws_amp[gid].i[1] = w0[1];
  pws_amp[gid].i[2] = w0[2];
  pws_amp[gid].i[3] = w0[3];
  pws_amp[gid].i[4] = w1[0];
  pws_amp[gid].i[5] = w1[1];
  pws_amp[gid].i[6] = w1[2];
  pws_amp[gid].i[7] = w1[3];

  pws_amp[gid].pw_len = out_len;
}
