/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 h[64];

} argon2_reference_tmp_t;

KERNEL_FQ KERNEL_FA void m70000_init (KERN_ATTR_TMPS (argon2_reference_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  for (u32 idx = 0; idx < 64; idx++)
  {
    tmps[gid].pw_buf[idx] = pws[gid].i[idx];
  }

  tmps[gid].pw_len = pw_len;
}

KERNEL_FQ KERNEL_FA void m70000_loop (KERN_ATTR_TMPS (argon2_reference_tmp_t))
{
}

KERNEL_FQ KERNEL_FA void m70000_comp (KERN_ATTR_TMPS (argon2_reference_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].h[0];
  const u32 r1 = tmps[gid].h[1];
  const u32 r2 = tmps[gid].h[2];
  const u32 r3 = tmps[gid].h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
