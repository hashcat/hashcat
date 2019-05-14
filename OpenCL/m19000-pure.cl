/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct qnx_md5_tmp
{
  md5_ctx_t md5_ctx;

} qnx_md5_tmp_t;

KERNEL_FQ void m19000_init (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update_global (&md5_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  md5_update_global (&md5_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].md5_ctx = md5_ctx;
}

KERNEL_FQ void m19000_loop (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  md5_ctx_t md5_ctx = tmps[gid].md5_ctx;

  for (u32 i = 0; i < loop_cnt; i++)
  {
    md5_update_global (&md5_ctx, pws[gid].i, pws[gid].pw_len);
  }

  tmps[gid].md5_ctx = md5_ctx;
}

KERNEL_FQ void m19000_comp (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  md5_ctx_t md5_ctx = tmps[gid].md5_ctx;

  md5_final (&md5_ctx);

  const u32 r0 = md5_ctx.h[0];
  const u32 r1 = md5_ctx.h[1];
  const u32 r2 = md5_ctx.h[2];
  const u32 r3 = md5_ctx.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
