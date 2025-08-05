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

KERNEL_FQ KERNEL_FA void m30000_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    u32x _w0[4];
    u32x _w1[4];
    u32x _w2[4];
    u32x _w3[4];

    _w0[0] = w[0];
    _w0[1] = w[1];
    _w0[2] = w[2];
    _w0[3] = w[3];
    _w1[0] = w[4];
    _w1[1] = w[5];
    _w1[2] = w[6];
    _w1[3] = w[7];
    _w2[0] = w[8];
    _w2[1] = w[9];
    _w2[2] = w[10];
    _w2[3] = w[11];
    _w3[0] = w[12];
    _w3[1] = w[13];
    _w3[2] = w[14];
    _w3[3] = w[15];

    sha256_update_vector_64 (&ctx, _w0, _w1, _w2, _w3, pw_len);

    sha256_final_vector (&ctx);

    // Second SHA256 round
    sha256_ctx_vector_t ctx2;
    sha256_init_vector (&ctx2);

    _w0[0] = ctx.h[0];
    _w0[1] = ctx.h[1];
    _w0[2] = ctx.h[2];
    _w0[3] = ctx.h[3];
    _w1[0] = ctx.h[4];
    _w1[1] = ctx.h[5];
    _w1[2] = ctx.h[6];
    _w1[3] = ctx.h[7];
    _w2[0] = 0;
    _w2[1] = 0;
    _w2[2] = 0;
    _w2[3] = 0;
    _w3[0] = 0;
    _w3[1] = 0;
    _w3[2] = 0;
    _w3[3] = 0;

    sha256_update_vector_64 (&ctx2, _w0, _w1, _w2, _w3, 32);

    sha256_final_vector (&ctx2);

    const u32x r0 = ctx2.h[DGST_R0];
    const u32x r1 = ctx2.h[DGST_R1];
    const u32x r2 = ctx2.h[DGST_R2];
    const u32x r3 = ctx2.h[DGST_R3];

    // Custom comparison with target threshold from salt
    // The salt contains the target threshold in little-endian format
    u32x target[8];
    target[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    target[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
    target[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
    target[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
    target[4] = salt_bufs[SALT_POS_HOST].salt_buf[4];
    target[5] = salt_bufs[SALT_POS_HOST].salt_buf[5];
    target[6] = salt_bufs[SALT_POS_HOST].salt_buf[6];
    target[7] = salt_bufs[SALT_POS_HOST].salt_buf[7];

    // Check if hash is less than target
    u32x cmp0 = (ctx2.h[0] < target[0]);
    u32x cmp1 = (ctx2.h[0] == target[0]) & (ctx2.h[1] < target[1]);
    u32x cmp2 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] < target[2]);
    u32x cmp3 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] == target[2]) & (ctx2.h[3] < target[3]);
    u32x cmp4 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] == target[2]) & (ctx2.h[3] == target[3]) & (ctx2.h[4] < target[4]);
    u32x cmp5 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] == target[2]) & (ctx2.h[3] == target[3]) & (ctx2.h[4] == target[4]) & (ctx2.h[5] < target[5]);
    u32x cmp6 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] == target[2]) & (ctx2.h[3] == target[3]) & (ctx2.h[4] == target[4]) & (ctx2.h[5] == target[5]) & (ctx2.h[6] < target[6]);
    u32x cmp7 = (ctx2.h[0] == target[0]) & (ctx2.h[1] == target[1]) & (ctx2.h[2] == target[2]) & (ctx2.h[3] == target[3]) & (ctx2.h[4] == target[4]) & (ctx2.h[5] == target[5]) & (ctx2.h[6] == target[6]) & (ctx2.h[7] < target[7]);

    u32x match = cmp0 | cmp1 | cmp2 | cmp3 | cmp4 | cmp5 | cmp6 | cmp7;

    if (any (match))
    {
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m30000_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    u32x _w0[4];
    u32x _w1[4];
    u32x _w2[4];
    u32x _w3[4];

    _w0[0] = w[0];
    _w0[1] = w[1];
    _w0[2] = w[2];
    _w0[3] = w[3];
    _w1[0] = w[4];
    _w1[1] = w[5];
    _w1[2] = w[6];
    _w1[3] = w[7];
    _w2[0] = w[8];
    _w2[1] = w[9];
    _w2[2] = w[10];
    _w2[3] = w[11];
    _w3[0] = w[12];
    _w3[1] = w[13];
    _w3[2] = w[14];
    _w3[3] = w[15];

    sha256_update_vector_64 (&ctx, _w0, _w1, _w2, _w3, pw_len);

    sha256_final_vector (&ctx);

    // Second SHA256 round
    sha256_ctx_vector_t ctx2;
    sha256_init_vector (&ctx2);

    _w0[0] = ctx.h[0];
    _w0[1] = ctx.h[1];
    _w0[2] = ctx.h[2];
    _w0[3] = ctx.h[3];
    _w1[0] = ctx.h[4];
    _w1[1] = ctx.h[5];
    _w1[2] = ctx.h[6];
    _w1[3] = ctx.h[7];
    _w2[0] = 0;
    _w2[1] = 0;
    _w2[2] = 0;
    _w2[3] = 0;
    _w3[0] = 0;
    _w3[1] = 0;
    _w3[2] = 0;
    _w3[3] = 0;

    sha256_update_vector_64 (&ctx2, _w0, _w1, _w2, _w3, 32);

    sha256_final_vector (&ctx2);

    const u32x r0 = ctx2.h[DGST_R0];
    const u32x r1 = ctx2.h[DGST_R1];
    const u32x r2 = ctx2.h[DGST_R2];
    const u32x r3 = ctx2.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}