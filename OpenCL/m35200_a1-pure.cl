/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

KERNEL_FQ KERNEL_FA void m35200_mxx (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_utf16be_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf_pc, salt_bufs[SALT_POS_HOST].salt_len_pc);

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    sha1_update_global_utf16be_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx;

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      ctx = ctx0;

      sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }
    else
    {
      ctx = ctx0;

      sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      sha1_update_global_utf16be_swap (&ctx, pws[gid].i, pws[gid].pw_len);
    }

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m35200_sxx (KERN_ATTR_BASIC ())
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_utf16be_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf_pc, salt_bufs[SALT_POS_HOST].salt_len_pc);

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    sha1_update_global_utf16be_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx;

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      ctx = ctx0;

      sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }
    else
    {
      ctx = ctx0;

      sha1_update_global_utf16be_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      sha1_update_global_utf16be_swap (&ctx, pws[gid].i, pws[gid].pw_len);
    }

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
