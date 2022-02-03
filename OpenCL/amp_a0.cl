/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define XSTR(x) #x
#define STR(x) XSTR(x)

#ifdef KERNEL_STATIC
#include STR(INCLUDE_PATH/inc_vendor.h)
#include STR(INCLUDE_PATH/inc_types.h)
#include STR(INCLUDE_PATH/inc_platform.cl)
#include STR(INCLUDE_PATH/inc_common.cl)
#include STR(INCLUDE_PATH/inc_rp.h)
#include STR(INCLUDE_PATH/inc_rp.cl)
#endif

KERNEL_FQ void amp (GLOBAL_AS pw_t *pws, GLOBAL_AS pw_t *pws_amp, CONSTANT_AS const kernel_rule_t *rules_buf, GLOBAL_AS const pw_t *combs_buf, GLOBAL_AS const bf_t *bfs_buf, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  if (rules_buf[0].cmds[0] == RULE_OP_MANGLE_NOOP && rules_buf[0].cmds[1] == 0) return;

  pw_t pw = pws_amp[gid];

  pw.pw_len = apply_rules (rules_buf[0].cmds, pw.i, pw.pw_len);

  pws[gid] = pw;
}
