/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct saph_sha256_tmp
{
  u32 digest_buf[8];

} saph_sha256_tmp_t;

KERNEL_FQ KERNEL_FA void m63100_init (KERN_ATTR_TMPS (saph_sha256_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha256_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha256_final (&ctx);

  tmps[gid].digest_buf[0] = ctx.h[0];
  tmps[gid].digest_buf[1] = ctx.h[1];
  tmps[gid].digest_buf[2] = ctx.h[2];
  tmps[gid].digest_buf[3] = ctx.h[3];
  tmps[gid].digest_buf[4] = ctx.h[4];
  tmps[gid].digest_buf[5] = ctx.h[5];
  tmps[gid].digest_buf[6] = ctx.h[6];
  tmps[gid].digest_buf[7] = ctx.h[7];
}

KERNEL_FQ KERNEL_FA void m63100_loop (KERN_ATTR_TMPS (saph_sha256_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * init
   */

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  /**
   * load
   */

  u32 digest[8];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];
  digest[4] = tmps[gid].digest_buf[4];
  digest[5] = tmps[gid].digest_buf[5];
  digest[6] = tmps[gid].digest_buf[6];
  digest[7] = tmps[gid].digest_buf[7];

  /**
   * loop
   */

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_ctx_t ctx_inner = ctx;

    sha256_update_64 (&ctx_inner, w0, w1, w2, w3, 32);

    sha256_final (&ctx_inner);

    digest[0] = ctx_inner.h[0];
    digest[1] = ctx_inner.h[1];
    digest[2] = ctx_inner.h[2];
    digest[3] = ctx_inner.h[3];
    digest[4] = ctx_inner.h[4];
    digest[5] = ctx_inner.h[5];
    digest[6] = ctx_inner.h[6];
    digest[7] = ctx_inner.h[7];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
  tmps[gid].digest_buf[4] = digest[4];
  tmps[gid].digest_buf[5] = digest[5];
  tmps[gid].digest_buf[6] = digest[6];
  tmps[gid].digest_buf[7] = digest[7];
}

KERNEL_FQ KERNEL_FA void m63100_comp (KERN_ATTR_TMPS (saph_sha256_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[0];
  const u32 r1 = tmps[gid].digest_buf[1];
  const u32 r2 = tmps[gid].digest_buf[2];
  const u32 r3 = tmps[gid].digest_buf[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
