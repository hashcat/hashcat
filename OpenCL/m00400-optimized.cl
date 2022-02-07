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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

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

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = 0;
  w2[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  /**
   * init
   */

  u32 block_len = 8 + pw_len;

  u32 block0[4];

  block0[0] = salt_buf[0];
  block0[1] = salt_buf[1];
  block0[2] = w0[0];
  block0[3] = w0[1];

  u32 block1[4];

  block1[0] = w0[2];
  block1[1] = w0[3];
  block1[2] = w1[0];
  block1[3] = w1[1];

  u32 block2[4];

  block2[0] = w1[2];
  block2[1] = w1[3];
  block2[2] = w2[0];
  block2[3] = w2[1];

  u32 block3[4];

  block3[0] = 0;
  block3[1] = 0;
  block3[2] = block_len * 8;
  block3[3] = 0;

  append_0x80_4x4_S (block0, block1, block2, block3, block_len);

  /**
   * init
   */

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (block0, block1, block2, block3, digest);

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

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];

  w0[0] = packv (pws, i, gid, 0);
  w0[1] = packv (pws, i, gid, 1);
  w0[2] = packv (pws, i, gid, 2);
  w0[3] = packv (pws, i, gid, 3);
  w1[0] = packv (pws, i, gid, 4);
  w1[1] = packv (pws, i, gid, 5);
  w1[2] = packv (pws, i, gid, 6);
  w1[3] = packv (pws, i, gid, 7);
  w2[0] = packv (pws, i, gid, 8);
  w2[1] = packv (pws, i, gid, 9);
  w2[2] = 0;
  w2[3] = 0;

  u32x pw_len = packvf (pws, pw_len, gid);

  u32x digest[4];

  digest[0] = packv (tmps, digest_buf, gid, 0);
  digest[1] = packv (tmps, digest_buf, gid, 1);
  digest[2] = packv (tmps, digest_buf, gid, 2);
  digest[3] = packv (tmps, digest_buf, gid, 3);

  /**
   * loop
   */

  u32x block_len = (16 + pw_len);

  u32x block0[4];
  u32x block1[4];
  u32x block2[4];
  u32x block3[4];

  block0[0] = 0;
  block0[1] = 0;
  block0[2] = 0;
  block0[3] = 0;
  block1[0] = w0[0];
  block1[1] = w0[1];
  block1[2] = w0[2];
  block1[3] = w0[3];
  block2[0] = w1[0];
  block2[1] = w1[1];
  block2[2] = w1[2];
  block2[3] = w1[3];
  block3[0] = w2[0];
  block3[1] = w2[1];
  block3[2] = block_len * 8;
  block3[3] = 0;

  append_0x80_4x4_VV (block0, block1, block2, block3, block_len);

  /**
   * init
   */

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    block0[0] = digest[0];
    block0[1] = digest[1];
    block0[2] = digest[2];
    block0[3] = digest[3];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform_vector (block0, block1, block2, block3, digest);
  }

  unpackv (tmps, digest_buf, gid, 0, digest[0]);
  unpackv (tmps, digest_buf, gid, 1, digest[1]);
  unpackv (tmps, digest_buf, gid, 2, digest[2]);
  unpackv (tmps, digest_buf, gid, 3, digest[3]);
}

KERNEL_FQ void m00400_comp (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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
