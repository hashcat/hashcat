/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct saph_sha384_tmp
{
  u64 digest_buf[8];

} saph_sha384_tmp_t;

KERNEL_FQ KERNEL_FA void m63200_init (KERN_ATTR_TMPS (saph_sha384_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha384_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha384_final (&ctx);

  tmps[gid].digest_buf[0] = ctx.h[0];
  tmps[gid].digest_buf[1] = ctx.h[1];
  tmps[gid].digest_buf[2] = ctx.h[2];
  tmps[gid].digest_buf[3] = ctx.h[3];
  tmps[gid].digest_buf[4] = ctx.h[4];
  tmps[gid].digest_buf[5] = ctx.h[5];
  tmps[gid].digest_buf[6] = 0;
  tmps[gid].digest_buf[7] = 0;
}

KERNEL_FQ KERNEL_FA void m63200_loop (KERN_ATTR_TMPS (saph_sha384_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * init
   */

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  /**
   * load
   */

  u64 digest[6];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];
  digest[4] = tmps[gid].digest_buf[4];
  digest[5] = tmps[gid].digest_buf[5];

  /**
   * loop
   */

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    w0[0] = h32_from_64_S (digest[0]);
    w0[1] = l32_from_64_S (digest[0]);
    w0[2] = h32_from_64_S (digest[1]);
    w0[3] = l32_from_64_S (digest[1]);
    w1[0] = h32_from_64_S (digest[2]);
    w1[1] = l32_from_64_S (digest[2]);
    w1[2] = h32_from_64_S (digest[3]);
    w1[3] = l32_from_64_S (digest[3]);
    w2[0] = h32_from_64_S (digest[4]);
    w2[1] = l32_from_64_S (digest[4]);
    w2[2] = h32_from_64_S (digest[5]);
    w2[3] = l32_from_64_S (digest[5]);
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha384_ctx_t ctx_inner = ctx;

    sha384_update_128 (&ctx_inner, w0, w1, w2, w3, w4, w5, w6, w7, 48);

    sha384_final (&ctx_inner);

    digest[0] = ctx_inner.h[0];
    digest[1] = ctx_inner.h[1];
    digest[2] = ctx_inner.h[2];
    digest[3] = ctx_inner.h[3];
    digest[4] = ctx_inner.h[4];
    digest[5] = ctx_inner.h[5];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
  tmps[gid].digest_buf[4] = digest[4];
  tmps[gid].digest_buf[5] = digest[5];
}

KERNEL_FQ KERNEL_FA void m63200_comp (KERN_ATTR_TMPS (saph_sha384_tmp_t))
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

  const u32 r0 = l32_from_64_S (tmps[gid].digest_buf[0]);
  const u32 r1 = h32_from_64_S (tmps[gid].digest_buf[0]);
  const u32 r2 = l32_from_64_S (tmps[gid].digest_buf[1]);
  const u32 r3 = h32_from_64_S (tmps[gid].digest_buf[1]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
