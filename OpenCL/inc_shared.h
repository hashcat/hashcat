/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_SHARED_H
#define _INC_SHARED_H

#ifdef IS_METAL

#define KERN_ATTR_GPU_DECOMPRESS        \
  GLOBAL_AS         pw_idx_t *pws_idx,  \
  GLOBAL_AS         u32      *pws_comp, \
  GLOBAL_AS         pw_t     *pws_buf,  \
  CONSTANT_AS const u64      &gid_max,  \
                    uint      hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_GPU_MEMSET            \
  GLOBAL_AS         uint4    *buf,      \
  CONSTANT_AS const u32      &value,    \
  CONSTANT_AS const u64      &gid_max,  \
                    uint      hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_GPU_BZERO             \
  GLOBAL_AS         uint4    *buf,      \
  CONSTANT_AS const u64      &gid_max,  \
                    uint      hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_GPU_ATINIT            \
  GLOBAL_AS         pw_t     *buf,      \
  CONSTANT_AS const u64      &gid_max,  \
                    uint      hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_GPU_UTF8_TO_UTF16     \
  GLOBAL_AS         pw_t     *pws_buf,  \
  CONSTANT_AS const u64      &gid_max,  \
                    uint      hc_gid [[ thread_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_GPU_DECOMPRESS        \
  GLOBAL_AS         pw_idx_t *pws_idx,  \
  GLOBAL_AS         u32      *pws_comp, \
  GLOBAL_AS         pw_t     *pws_buf,  \
              const u64       gid_max

#define KERN_ATTR_GPU_MEMSET            \
  GLOBAL_AS         uint4    *buf,      \
              const u32       value,    \
              const u64       gid_max

#define KERN_ATTR_GPU_BZERO             \
  GLOBAL_AS         uint4    *buf,      \
              const u64       gid_max

#define KERN_ATTR_GPU_ATINIT            \
  GLOBAL_AS         pw_t     *buf,      \
              const u64       gid_max

#define KERN_ATTR_GPU_UTF8_TO_UTF16     \
  GLOBAL_AS         pw_t     *pws_buf,  \
              const u64       gid_max

#endif // IS_METAL

#endif // _INC_SHARED_H
