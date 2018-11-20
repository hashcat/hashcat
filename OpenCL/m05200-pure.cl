/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__kernel void m05200_init (KERN_ATTR_TMPS (pwsafe3_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha256_update_global_swap (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

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

__kernel void m05200_loop (KERN_ATTR_TMPS (pwsafe3_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x digest[8];

  digest[0] = packv (tmps, digest_buf, gid, 0);
  digest[1] = packv (tmps, digest_buf, gid, 1);
  digest[2] = packv (tmps, digest_buf, gid, 2);
  digest[3] = packv (tmps, digest_buf, gid, 3);
  digest[4] = packv (tmps, digest_buf, gid, 4);
  digest[5] = packv (tmps, digest_buf, gid, 5);
  digest[6] = packv (tmps, digest_buf, gid, 6);
  digest[7] = packv (tmps, digest_buf, gid, 7);

  /**
   * init
   */

  for (u32 i = 0; i < loop_cnt; i++)
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

  unpackv (tmps, digest_buf, gid, 0, digest[0]);
  unpackv (tmps, digest_buf, gid, 1, digest[1]);
  unpackv (tmps, digest_buf, gid, 2, digest[2]);
  unpackv (tmps, digest_buf, gid, 3, digest[3]);
  unpackv (tmps, digest_buf, gid, 4, digest[4]);
  unpackv (tmps, digest_buf, gid, 5, digest[5]);
  unpackv (tmps, digest_buf, gid, 6, digest[6]);
  unpackv (tmps, digest_buf, gid, 7, digest[7]);
}

__kernel void m05200_comp (KERN_ATTR_TMPS (pwsafe3_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
