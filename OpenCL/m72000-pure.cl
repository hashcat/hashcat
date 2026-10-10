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

// The bridge hands the crate a full record with room for 32 outputs, but only the MD4 of each output
// is ever compared, so the bridge hashes them on the host and only the digests come back here. Sync
// with src/modules/module_74000.c and src/bridges/bridge_rust_generic_hash.c.

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_cnt;
  u32 out_dgst[32][4];

} generic_io_dgst_tmp_t;

KERNEL_FQ KERNEL_FA void m72000_init (KERN_ATTR_TMPS (generic_io_dgst_tmp_t))
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

KERNEL_FQ KERNEL_FA void m72000_loop (KERN_ATTR_TMPS (generic_io_dgst_tmp_t))
{
}

KERNEL_FQ KERNEL_FA void m72000_comp (KERN_ATTR_TMPS (generic_io_dgst_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 out_cnt = tmps[gid].out_cnt;

  for (u32 i = 0; i < out_cnt; i++)
  {
    const u32 r0 = tmps[gid].out_dgst[i][0];
    const u32 r1 = tmps[gid].out_dgst[i][1];
    const u32 r2 = tmps[gid].out_dgst[i][2];
    const u32 r3 = tmps[gid].out_dgst[i][3];

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
