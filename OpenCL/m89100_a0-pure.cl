/**
 * License.....: MIT
 */

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

KERNEL_FQ void m89100_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;
    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t c0;
    md4_init (&c0); md4_update_utf16le (&c0, tmp.i, tmp.pw_len); md4_final (&c0);

    u32 w[16] = { 0 };
    w[0]=c0.h[0]; w[1]=c0.h[1]; w[2]=c0.h[2]; w[3]=c0.h[3];

    md4_ctx_t c1;
    md4_init (&c1); md4_update_utf16le (&c1, w, 16); md4_final (&c1);   // outer NTLM

    const u32 r0=c1.h[DGST_R0], r1=c1.h[DGST_R1], r2=c1.h[DGST_R2], r3=c1.h[DGST_R3];
    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m89100_sxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;
    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t c0;
    md4_init (&c0); md4_update_utf16le (&c0, tmp.i, tmp.pw_len); md4_final (&c0);

    u32 w[16] = { 0 };
    w[DGST_R0] = (c0.h[0] & 0x000000ff) <<  0 | (c0.h[0] & 0x0000ff00) <<  8;
    w[DGST_R1] = (c0.h[0] & 0x00ff0000) >> 16 | (c0.h[0] & 0xff000000) >>  8;
    w[DGST_R2] = (c0.h[1] & 0x000000ff) <<  0 | (c0.h[1] & 0x0000ff00) <<  8;
    w[DGST_R3] = (c0.h[1] & 0x00ff0000) >> 16 | (c0.h[1] & 0xff000000) >>  8;
    w[DGST_R4] = (c0.h[2] & 0x000000ff) <<  0 | (c0.h[2] & 0x0000ff00) <<  8;
    w[DGST_R5] = (c0.h[2] & 0x00ff0000) >> 16 | (c0.h[2] & 0xff000000) >>  8;
    w[DGST_R6] = (c0.h[3] & 0x000000ff) <<  0 | (c0.h[3] & 0x0000ff00) <<  8;
    w[DGST_R7] = (c0.h[3] & 0x00ff0000) >> 16 | (c0.h[3] & 0xff000000) >>  8;

    md4_ctx_t c1;
    md4_init (&c1); md4_update (&c1, w, 32); md4_final (&c1);


    const u32 r0=c1.h[DGST_R0], r1=c1.h[DGST_R1], r2=c1.h[DGST_R2], r3=c1.h[DGST_R3];
    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
