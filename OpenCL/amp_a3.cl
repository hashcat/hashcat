/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#endif

KERNEL_FQ void amp (GLOBAL_AS pw_t *pws, GLOBAL_AS pw_t *pws_amp, GLOBAL_AS const kernel_rule_t *rules_buf, GLOBAL_AS const pw_t *combs_buf, CONSTANT_AS bf_t *bfs_buf, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 w0r = bfs_buf[0].i;

  pws[gid].i[0] |= w0r;
}
