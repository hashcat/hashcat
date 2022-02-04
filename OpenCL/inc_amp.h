/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_AMP_H
#define _INC_AMP_H

#if defined IS_METAL

#define KERN_ATTR_AMP                          \
  GLOBAL_AS         pw_t          *pws,        \
  GLOBAL_AS         pw_t          *pws_amp,    \
  CONSTANT_AS const kernel_rule_t *rules_buf,  \
  GLOBAL_AS   const pw_t          *combs_buf,  \
  GLOBAL_AS   const bf_t          *bfs_buf,    \
  CONSTANT_AS const u32           &combs_mode, \
  CONSTANT_AS const u64           &gid_max,    \
                    uint           hc_gid [[ thread_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_AMP                          \
  GLOBAL_AS         pw_t          *pws,        \
  GLOBAL_AS         pw_t          *pws_amp,    \
  CONSTANT_AS const kernel_rule_t *rules_buf,  \
  GLOBAL_AS   const pw_t          *combs_buf,  \
  GLOBAL_AS   const bf_t          *bfs_buf,    \
              const u32            combs_mode, \
              const u64            gid_max

#endif // IS_METAL

#endif // _INC_AMP_H
