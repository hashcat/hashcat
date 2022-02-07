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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

DECLSPEC const u32 replace_dot_by_len (PRIVATE_AS pw_t *out, GLOBAL_AS const pw_t *in, const u32 old_len)
{
  // first make out a copy of in:

  out->pw_len = in->pw_len;

  for (int i = 0; i < 64; i++)
  {
    out->i[i] = in->i[i];
  }

  // replace "." with the length:

  u32 cur_len = old_len;

  for (int pos = out->pw_len - 1; pos >= 0; pos--)
  {
    const u32 div = pos  / 4;
    const u32 mod = pos  & 3;
    const u32 sht = mod << 3;

    if (((out->i[div] >> sht) & 0xff) == 0x2e) // '.'
    {
      out->i[div] += (cur_len - 0x2e) << sht;

      cur_len = 0;

      continue;
    }

    cur_len++;
  }

  return cur_len;
}

KERNEL_FQ void m08300_mxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    const u32 pw_len = pws[gid].pw_len + combs_buf[il_pos].pw_len;

    // replace "." with the length:

    if (pw_len > 0)
    {
      pw_t combs;

      const u32 first_len_combs = replace_dot_by_len (&combs, &combs_buf[il_pos], 0);

      pw_t pw;

      const u32 first_len_pw = replace_dot_by_len (&pw, &pws[gid], first_len_combs);

      ctx1.w0[0] = (first_len_pw & 0xff) << 24;

      ctx1.len = 1;

      sha1_update_swap (&ctx1, pw.i,    pw.pw_len);
      sha1_update_swap (&ctx1, combs.i, combs.pw_len);
    }

    sha1_update (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update (&ctx1, s, salt_len);

    sha1_final (&ctx1);

    u32 digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_t ctx;

      sha1_init (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update (&ctx, s, salt_len);

      sha1_final (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32 r0 = digest[DGST_R0];
    const u32 r1 = digest[DGST_R1];
    const u32 r2 = digest[DGST_R2];
    const u32 r3 = digest[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m08300_sxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    const u32 pw_len = pws[gid].pw_len + combs_buf[il_pos].pw_len;

    // replace "." with the length:

    if (pw_len > 0)
    {
      pw_t combs;

      const u32 first_len_combs = replace_dot_by_len (&combs, &combs_buf[il_pos], 0);

      pw_t pw;

      const u32 first_len_pw = replace_dot_by_len (&pw, &pws[gid], first_len_combs);

      ctx1.w0[0] = (first_len_pw & 0xff) << 24;

      ctx1.len = 1;

      sha1_update_swap (&ctx1, pw.i,    pw.pw_len);
      sha1_update_swap (&ctx1, combs.i, combs.pw_len);
    }

    sha1_update (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update (&ctx1, s, salt_len);

    sha1_final (&ctx1);

    u32 digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_t ctx;

      sha1_init (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update (&ctx, s, salt_len);

      sha1_final (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32 r0 = digest[DGST_R0];
    const u32 r1 = digest[DGST_R1];
    const u32 r2 = digest[DGST_R2];
    const u32 r3 = digest[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
