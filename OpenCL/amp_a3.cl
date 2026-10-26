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

KERNEL_FQ KERNEL_FA void amp (KERN_ATTR_AMP)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // one amplifier item over all base words: the host has already copied them into pws

  if (pws_cnt == gid_max)
  {
    pws[gid].i[0] |= bfs_buf[0].i;

    return;
  }

  const u32 pw_pos = (u32) gid % pws_cnt;
  const u32 il_pos = (u32) gid / pws_cnt;

  pw_t pw = pws_amp[pw_pos];

  pw.i[0] |= bfs_buf[il_pos].i;

  pws[gid] = pw;
}
