/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct qnx_md5_tmp
{
  md5_ctx_t md5_ctx;

} qnx_md5_tmp_t;

KERNEL_FQ KERNEL_FA void m19000_init (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, s, salt_len);

  md5_update (&md5_ctx, w, pw_len);

  tmps[gid].md5_ctx = md5_ctx;
}

KERNEL_FQ KERNEL_FA void m19000_loop (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  md5_ctx_t md5_ctx = tmps[gid].md5_ctx;

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    md5_update (&md5_ctx, w, pw_len);
  }

  tmps[gid].md5_ctx = md5_ctx;
}

KERNEL_FQ KERNEL_FA void m19000_comp (KERN_ATTR_TMPS (qnx_md5_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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
