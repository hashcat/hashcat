/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_amp.h)
#endif

KERNEL_FQ void amp (KERN_ATTR_AMP)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  if (rules_buf[0].cmds[0] == RULE_OP_MANGLE_NOOP && rules_buf[0].cmds[1] == 0) return;

  pw_t pw = pws_amp[gid];

  pw.pw_len = apply_rules (rules_buf[0].cmds, pw.i, pw.pw_len);

  pws[gid] = pw;
}
