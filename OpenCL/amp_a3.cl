/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_amp.h)
#endif

KERNEL_FQ void amp (KERN_ATTR_AMP)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 w0r = bfs_buf[0].i;

  pws[gid].i[0] |= w0r;
}
