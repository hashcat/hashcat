/**
 * Author......: Net-Doge
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

#define NIB2HEX(n) (((n) < 10) ? ((n) + 0x30) : ((n) + 0x57))

#define U32_TO_HEX_UTF16LE(val, out)                               \
{                                                                  \
  const u32 b0 = ((val) >>  0) & 0xff;                             \
  const u32 b1 = ((val) >>  8) & 0xff;                             \
  const u32 b2 = ((val) >> 16) & 0xff;                             \
  const u32 b3 = ((val) >> 24) & 0xff;                             \
  (out)[0] = NIB2HEX (b0 >> 4) | (NIB2HEX (b0 & 0xf) << 16);     \
  (out)[1] = NIB2HEX (b1 >> 4) | (NIB2HEX (b1 & 0xf) << 16);     \
  (out)[2] = NIB2HEX (b2 >> 4) | (NIB2HEX (b2 & 0xf) << 16);     \
  (out)[3] = NIB2HEX (b3 >> 4) | (NIB2HEX (b3 & 0xf) << 16);     \
}

KERNEL_FQ KERNEL_FA void m01001_mxx (KERN_ATTR_RULES ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, tmp.i, tmp.pw_len);

    md4_final (&ctx1);

    u32 w[16];

    U32_TO_HEX_UTF16LE (ctx1.h[0], w +  0);
    U32_TO_HEX_UTF16LE (ctx1.h[1], w +  4);
    U32_TO_HEX_UTF16LE (ctx1.h[2], w +  8);
    U32_TO_HEX_UTF16LE (ctx1.h[3], w + 12);

    md4_ctx_t ctx2;

    md4_init (&ctx2);

    md4_update (&ctx2, w, 64);

    md4_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m01001_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, tmp.i, tmp.pw_len);

    md4_final (&ctx1);

    u32 w[16];

    U32_TO_HEX_UTF16LE (ctx1.h[0], w +  0);
    U32_TO_HEX_UTF16LE (ctx1.h[1], w +  4);
    U32_TO_HEX_UTF16LE (ctx1.h[2], w +  8);
    U32_TO_HEX_UTF16LE (ctx1.h[3], w + 12);

    md4_ctx_t ctx2;

    md4_init (&ctx2);

    md4_update (&ctx2, w, 64);

    md4_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
