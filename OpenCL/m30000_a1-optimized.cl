/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

KERNEL_FQ KERNEL_FA void m30000_m04 (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];
    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

    w0[0] |= combs_buf[il_pos].i[0];
    w0[1] |= combs_buf[il_pos].i[1];
    w0[2] |= combs_buf[il_pos].i[2];
    w0[3] |= combs_buf[il_pos].i[3];
    w1[0] |= combs_buf[il_pos].i[4];
    w1[1] |= combs_buf[il_pos].i[5];
    w1[2] |= combs_buf[il_pos].i[6];
    w1[3] |= combs_buf[il_pos].i[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);
    sha256_update_64 (&ctx, w0, w1, w2, w3, pw_len);
    sha256_final (&ctx);

    // Second SHA256 round
    sha256_ctx_t ctx2;
    sha256_init (&ctx2);

    w0[0] = ctx.h[0];
    w0[1] = ctx.h[1];
    w0[2] = ctx.h[2];
    w0[3] = ctx.h[3];
    w1[0] = ctx.h[4];
    w1[1] = ctx.h[5];
    w1[2] = ctx.h[6];
    w1[3] = ctx.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_update_64 (&ctx2, w0, w1, w2, w3, 32);
    sha256_final (&ctx2);

    // Check if hash is less than target (stored in salt)
    bool match = false;
    for (int i = 7; i >= 0; i--)
    {
      const u32 h = ctx2.h[i];
      const u32 t = salt_bufs[SALT_POS_HOST].salt_buf[i];
      
      if (h < t) { match = true; break; }
      if (h > t) { break; }
    }

    if (match)
    {
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m30000_s04 (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];
    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

    w0[0] |= combs_buf[il_pos].i[0];
    w0[1] |= combs_buf[il_pos].i[1];
    w0[2] |= combs_buf[il_pos].i[2];
    w0[3] |= combs_buf[il_pos].i[3];
    w1[0] |= combs_buf[il_pos].i[4];
    w1[1] |= combs_buf[il_pos].i[5];
    w1[2] |= combs_buf[il_pos].i[6];
    w1[3] |= combs_buf[il_pos].i[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);
    sha256_update_64 (&ctx, w0, w1, w2, w3, pw_len);
    sha256_final (&ctx);

    // Second SHA256 round
    sha256_ctx_t ctx2;
    sha256_init (&ctx2);

    w0[0] = ctx.h[0];
    w0[1] = ctx.h[1];
    w0[2] = ctx.h[2];
    w0[3] = ctx.h[3];
    w1[0] = ctx.h[4];
    w1[1] = ctx.h[5];
    w1[2] = ctx.h[6];
    w1[3] = ctx.h[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_update_64 (&ctx2, w0, w1, w2, w3, 32);
    sha256_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m30000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m30000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m30000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m30000_s16 (KERN_ATTR_RULES ())
{
}