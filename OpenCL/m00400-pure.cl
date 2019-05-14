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

typedef struct phpass_tmp
{
  u32 digest_buf[4];

} phpass_tmp_t;

KERNEL_FQ void m00400_init (KERN_ATTR_TMPS (phpass_tmp_t))
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

  md5_final (&md5_ctx);

  u32 digest[4];

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m00400_loop (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  /**
   * loop
   */

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_ctx.w0[0] = digest[0];
  md5_ctx.w0[1] = digest[1];
  md5_ctx.w0[2] = digest[2];
  md5_ctx.w0[3] = digest[3];

  md5_ctx.len = 16;

  md5_update (&md5_ctx, w, pw_len);

  md5_final (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  if ((16 + pw_len + 1) >= 56)
  {
    for (u32 i = 1; i < loop_cnt; i++)
    {
      md5_init (&md5_ctx);

      md5_ctx.w0[0] = digest[0];
      md5_ctx.w0[1] = digest[1];
      md5_ctx.w0[2] = digest[2];
      md5_ctx.w0[3] = digest[3];

      md5_ctx.len = 16;

      md5_update (&md5_ctx, w, pw_len);

      md5_final (&md5_ctx);

      digest[0] = md5_ctx.h[0];
      digest[1] = md5_ctx.h[1];
      digest[2] = md5_ctx.h[2];
      digest[3] = md5_ctx.h[3];
    }
  }
  else
  {
    for (u32 i = 1; i < loop_cnt; i++)
    {
      md5_ctx.w0[0] = digest[0];
      md5_ctx.w0[1] = digest[1];
      md5_ctx.w0[2] = digest[2];
      md5_ctx.w0[3] = digest[3];

      digest[0] = MD5M_A;
      digest[1] = MD5M_B;
      digest[2] = MD5M_C;
      digest[3] = MD5M_D;

      md5_transform (md5_ctx.w0, md5_ctx.w1, md5_ctx.w2, md5_ctx.w3, digest);
    }
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m00400_comp (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
