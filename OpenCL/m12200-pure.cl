/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct ecryptfs_tmp
{
  u64  out[8];

} ecryptfs_tmp_t;

KERNEL_FQ void m12200_init (KERN_ATTR_TMPS (ecryptfs_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_final (&ctx);

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
  tmps[gid].out[5] = ctx.h[5];
  tmps[gid].out[6] = ctx.h[6];
  tmps[gid].out[7] = ctx.h[7];
}

KERNEL_FQ void m12200_loop (KERN_ATTR_TMPS (ecryptfs_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x t0 = pack64v (tmps, out, gid, 0);
  u64x t1 = pack64v (tmps, out, gid, 1);
  u64x t2 = pack64v (tmps, out, gid, 2);
  u64x t3 = pack64v (tmps, out, gid, 3);
  u64x t4 = pack64v (tmps, out, gid, 4);
  u64x t5 = pack64v (tmps, out, gid, 5);
  u64x t6 = pack64v (tmps, out, gid, 6);
  u64x t7 = pack64v (tmps, out, gid, 7);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  w0[0] = 0;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0x80000000;
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
  w7[3] = 64 * 8;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = h32_from_64 (t0);
    w0[1] = l32_from_64 (t0);
    w0[2] = h32_from_64 (t1);
    w0[3] = l32_from_64 (t1);
    w1[0] = h32_from_64 (t2);
    w1[1] = l32_from_64 (t2);
    w1[2] = h32_from_64 (t3);
    w1[3] = l32_from_64 (t3);
    w2[0] = h32_from_64 (t4);
    w2[1] = l32_from_64 (t4);
    w2[2] = h32_from_64 (t5);
    w2[3] = l32_from_64 (t5);
    w3[0] = h32_from_64 (t6);
    w3[1] = l32_from_64 (t6);
    w3[2] = h32_from_64 (t7);
    w3[3] = l32_from_64 (t7);

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
    t6 = digest[6];
    t7 = digest[7];
  }

  unpack64v (tmps, out, gid, 0, t0);
  unpack64v (tmps, out, gid, 1, t1);
  unpack64v (tmps, out, gid, 2, t2);
  unpack64v (tmps, out, gid, 3, t3);
  unpack64v (tmps, out, gid, 4, t4);
  unpack64v (tmps, out, gid, 5, t5);
  unpack64v (tmps, out, gid, 6, t6);
  unpack64v (tmps, out, gid, 7, t7);
}

KERNEL_FQ void m12200_comp (KERN_ATTR_TMPS (ecryptfs_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  const u64 a = tmps[gid].out[0];

  const u32 r0 = h32_from_64_S (a);
  const u32 r1 = l32_from_64_S (a);
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
