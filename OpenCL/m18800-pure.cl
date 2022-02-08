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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bsp_tmp
{
  u32 hash[8];

} bsp_tmp_t;

KERNEL_FQ void m18800_init (KERN_ATTR_TMPS (bsp_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&ctx);

  tmps[gid].hash[0] = ctx.h[0];
  tmps[gid].hash[1] = ctx.h[1];
  tmps[gid].hash[2] = ctx.h[2];
  tmps[gid].hash[3] = ctx.h[3];
  tmps[gid].hash[4] = ctx.h[4];
  tmps[gid].hash[5] = ctx.h[5];
  tmps[gid].hash[6] = ctx.h[6];
  tmps[gid].hash[7] = ctx.h[7];
}

KERNEL_FQ void m18800_loop (KERN_ATTR_TMPS (bsp_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x digest[8];

  digest[0] = packv (tmps, hash, gid, 0);
  digest[1] = packv (tmps, hash, gid, 1);
  digest[2] = packv (tmps, hash, gid, 2);
  digest[3] = packv (tmps, hash, gid, 3);
  digest[4] = packv (tmps, hash, gid, 4);
  digest[5] = packv (tmps, hash, gid, 5);
  digest[6] = packv (tmps, hash, gid, 6);
  digest[7] = packv (tmps, hash, gid, 7);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 32 * 8;

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform_vector (w0, w1, w2, w3, digest);
  }

  unpackv (tmps, hash, gid, 0, digest[0]);
  unpackv (tmps, hash, gid, 1, digest[1]);
  unpackv (tmps, hash, gid, 2, digest[2]);
  unpackv (tmps, hash, gid, 3, digest[3]);
  unpackv (tmps, hash, gid, 4, digest[4]);
  unpackv (tmps, hash, gid, 5, digest[5]);
  unpackv (tmps, hash, gid, 6, digest[6]);
  unpackv (tmps, hash, gid, 7, digest[7]);
}

KERNEL_FQ void m18800_comp (KERN_ATTR_TMPS (bsp_tmp_t))
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

  const u32 r0 = tmps[gid].hash[DGST_R0];
  const u32 r1 = tmps[gid].hash[DGST_R1];
  const u32 r2 = tmps[gid].hash[DGST_R2];
  const u32 r3 = tmps[gid].hash[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
