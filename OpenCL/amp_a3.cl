/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#endif

KERNEL_FQ void amp (GLOBAL_AS pw_t * restrict pws, GLOBAL_AS pw_t * restrict pws_amp, GLOBAL_AS const kernel_rule_t * restrict rules_buf, GLOBAL_AS const pw_t * restrict combs_buf, CONSTANT_AS const bf_t * restrict bfs_buf, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 w0r = bfs_buf[0].i;

  pws[gid].i[0] |= w0r;
}
