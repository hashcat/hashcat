/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_buf[64];
  u32 out_len;

} generic_io_tmp_t;

KERNEL_FQ void HC_ATTR_SEQ m72000_init (KERN_ATTR_TMPS (generic_io_tmp_t))
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

KERNEL_FQ void HC_ATTR_SEQ m72000_loop (KERN_ATTR_TMPS (generic_io_tmp_t))
{
}

KERNEL_FQ void HC_ATTR_SEQ m72000_comp (KERN_ATTR_TMPS (generic_io_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global (&ctx0, tmps[gid].out_buf, tmps[gid].out_len);

  md4_final (&ctx0);

  const u32 r0 = ctx0.h[0];
  const u32 r1 = ctx0.h[1];
  const u32 r2 = ctx0.h[2];
  const u32 r3 = ctx0.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
