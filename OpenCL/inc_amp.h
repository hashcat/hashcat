/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_AMP_H
#define INC_AMP_H

// pws_cnt is the base words in pws_amp. A launch can hold several amplifier items over all of them, so
// gid_max is pws_cnt times the item count, and work item gid takes word gid % pws_cnt under item
// gid / pws_cnt.

#if defined IS_METAL

#define KERN_ATTR_AMP                          \
  GLOBAL_AS         pw_t          *pws,        \
  GLOBAL_AS         pw_t          *pws_amp,    \
  CONSTANT_AS const kernel_rule_t *rules_buf,  \
  GLOBAL_AS   const pw_t          *combs_buf,  \
  GLOBAL_AS   const bf_t          *bfs_buf,    \
  CONSTANT_AS const u32           &combs_mode, \
  CONSTANT_AS const u64           &gid_max,    \
  CONSTANT_AS const u32           &pws_cnt,    \
                    uint3          hc_gid [[ thread_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_AMP                          \
  GLOBAL_AS         pw_t          *pws,        \
  GLOBAL_AS         pw_t          *pws_amp,    \
  CONSTANT_AS const kernel_rule_t *rules_buf,  \
  GLOBAL_AS   const pw_t          *combs_buf,  \
  GLOBAL_AS   const bf_t          *bfs_buf,    \
              const u32            combs_mode, \
              const u64            gid_max,    \
              const u32            pws_cnt

#endif // IS_METAL

#endif // INC_AMP_H
