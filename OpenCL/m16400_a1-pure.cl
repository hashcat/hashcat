/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"
#endif

DECLSPEC void cram_md5_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  u32 w0_t = w0[0] ^ 0x5c5c5c5c;
  u32 w1_t = w0[1] ^ 0x5c5c5c5c;
  u32 w2_t = w0[2] ^ 0x5c5c5c5c;
  u32 w3_t = w0[3] ^ 0x5c5c5c5c;
  u32 w4_t = w1[0] ^ 0x5c5c5c5c;
  u32 w5_t = w1[1] ^ 0x5c5c5c5c;
  u32 w6_t = w1[2] ^ 0x5c5c5c5c;
  u32 w7_t = w1[3] ^ 0x5c5c5c5c;
  u32 w8_t = w2[0] ^ 0x5c5c5c5c;
  u32 w9_t = w2[1] ^ 0x5c5c5c5c;
  u32 wa_t = w2[2] ^ 0x5c5c5c5c;
  u32 wb_t = w2[3] ^ 0x5c5c5c5c;
  u32 wc_t = w3[0] ^ 0x5c5c5c5c;
  u32 wd_t = w3[1] ^ 0x5c5c5c5c;
  u32 we_t = w3[2] ^ 0x5c5c5c5c;
  u32 wf_t = w3[3] ^ 0x5c5c5c5c;

  MD5_STEP_S (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP_S (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  u32 t;

  MD5_STEP_S (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP_S (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

DECLSPEC void cram_md5_update_64 (md5_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  #ifdef IS_AMD
  MAYBE_VOLATILE const int pos = ctx->len & 63;
  #else
  MAYBE_VOLATILE const int pos = ctx->len & 63;
  #endif

  ctx->len += len;

  switch_buffer_by_offset_le_S (w0, w1, w2, w3, pos);

  ctx->w0[0] |= w0[0];
  ctx->w0[1] |= w0[1];
  ctx->w0[2] |= w0[2];
  ctx->w0[3] |= w0[3];
  ctx->w1[0] |= w1[0];
  ctx->w1[1] |= w1[1];
  ctx->w1[2] |= w1[2];
  ctx->w1[3] |= w1[3];
  ctx->w2[0] |= w2[0];
  ctx->w2[1] |= w2[1];
  ctx->w2[2] |= w2[2];
  ctx->w2[3] |= w2[3];
  ctx->w3[0] |= w3[0];
  ctx->w3[1] |= w3[1];
  ctx->w3[2] |= w3[2];
  ctx->w3[3] |= w3[3];
}

DECLSPEC void cram_md5_update_global (md5_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = w[0];
  w0[1] = w[1];
  w0[2] = w[2];
  w0[3] = w[3];
  w1[0] = w[4];
  w1[1] = w[5];
  w1[2] = w[6];
  w1[3] = w[7];
  w2[0] = w[8];
  w2[1] = w[9];
  w2[2] = w[10];
  w2[3] = w[11];
  w3[0] = w[12];
  w3[1] = w[13];
  w3[2] = w[14];
  w3[3] = w[15];

  cram_md5_update_64 (ctx, w0, w1, w2, w3, len);
}

DECLSPEC void cram_md5_final (md5_ctx_t *ctx)
{
  cram_md5_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

KERNEL_FQ void m16400_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  cram_md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    cram_md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    cram_md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m16400_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  cram_md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    cram_md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    cram_md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
