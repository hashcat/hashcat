/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct omt_sha256_tmp
{
  u32 digest_buf[8];

} omt_sha256_tmp_t;

KERNEL_FQ void m20600_init (KERN_ATTR_TMPS (omt_sha256_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);

  sha256_update_global_swap (&sha256_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha256_update_global_swap (&sha256_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&sha256_ctx);

  tmps[gid].digest_buf[0] = sha256_ctx.h[0];
  tmps[gid].digest_buf[1] = sha256_ctx.h[1];
  tmps[gid].digest_buf[2] = sha256_ctx.h[2];
  tmps[gid].digest_buf[3] = sha256_ctx.h[3];
  tmps[gid].digest_buf[4] = sha256_ctx.h[4];
  tmps[gid].digest_buf[5] = sha256_ctx.h[5];
  tmps[gid].digest_buf[6] = sha256_ctx.h[6];
  tmps[gid].digest_buf[7] = sha256_ctx.h[7];
}

KERNEL_FQ void m20600_loop (KERN_ATTR_TMPS (omt_sha256_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  /**
   * init
   */

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
   * loop
   */

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 32 * 8;

  for (u32 i = 0; i < loop_cnt; i++)
  {
    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];

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

KERNEL_FQ void m20600_comp (KERN_ATTR_TMPS (omt_sha256_tmp_t))
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

  const u32 r0 = hc_swap32_S (tmps[gid].digest_buf[DGST_R0]);
  const u32 r1 = hc_swap32_S (tmps[gid].digest_buf[DGST_R1]);
  const u32 r2 = hc_swap32_S (tmps[gid].digest_buf[DGST_R2]);
  const u32 r3 = hc_swap32_S (tmps[gid].digest_buf[DGST_R3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
