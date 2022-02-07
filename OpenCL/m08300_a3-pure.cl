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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define REPLACE_DOT_BY_LEN(n)                  \
  if (((tmp[div].s##n >> sht) & 0xff) == 0x2e) \
  {                                            \
    tmp[div].s##n += (len.s##n - 0x2e) << sht; \
    len.s##n = 0;                              \
  }                                            \
  else                                         \
  {                                            \
    len.s##n++;                                \
  }

KERNEL_FQ void m08300_mxx (KERN_ATTR_VECTOR ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32x s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32 (salt_bufs[SALT_POS_HOST].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    // replace "." with the length:

    u32x tmp[64] = { 0 };

    for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
    {
      tmp[idx] = w[idx];
    }

    u32x len = 0;

    for (int pos = pw_len - 1; pos >= 0; pos--)
    {
      const u32 div = pos / 4;
      const u32 mod = pos & 3;
      const u32 sht = (3 - mod) << 3;

      #if VECT_SIZE == 1
        if (((tmp[div] >> sht) & 0xff) == 0x2e) // '.'
        {
          tmp[div] += (len - 0x2e) << sht;

          len = 0;
        }
        else
        {
          len++;
        }
      #endif
      #if VECT_SIZE >= 2
        REPLACE_DOT_BY_LEN (0)
        REPLACE_DOT_BY_LEN (1)
      #endif
      #if VECT_SIZE >= 4
        REPLACE_DOT_BY_LEN (2)
        REPLACE_DOT_BY_LEN (3)
      #endif
      #if VECT_SIZE >= 8
        REPLACE_DOT_BY_LEN (4)
        REPLACE_DOT_BY_LEN (5)
        REPLACE_DOT_BY_LEN (6)
        REPLACE_DOT_BY_LEN (7)
      #endif
      #if VECT_SIZE >= 16
        REPLACE_DOT_BY_LEN (8)
        REPLACE_DOT_BY_LEN (9)
        REPLACE_DOT_BY_LEN (a)
        REPLACE_DOT_BY_LEN (b)
        REPLACE_DOT_BY_LEN (c)
        REPLACE_DOT_BY_LEN (d)
        REPLACE_DOT_BY_LEN (e)
        REPLACE_DOT_BY_LEN (f)
      #endif
    }

    ctx1.w0[0] = (len & 0xff) << 24;

    ctx1.len = 1;

    sha1_update_vector (&ctx1, tmp, pw_len);

    sha1_update_vector (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update_vector (&ctx1, s, salt_len);

    sha1_final_vector (&ctx1);

    u32x digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_vector_t ctx;

      sha1_init_vector (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update_vector (&ctx, s, salt_len);

      sha1_final_vector (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32x r0 = digest[DGST_R0];
    const u32x r1 = digest[DGST_R1];
    const u32x r2 = digest[DGST_R2];
    const u32x r3 = digest[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m08300_sxx (KERN_ATTR_VECTOR ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32x s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32 (salt_bufs[SALT_POS_HOST].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    // replace "." with the length:

    u32x tmp[64];

    for (int i = 0; i < 64; i++)
    {
      tmp[i] = w[i];
    }

    u32x len = 0;

    for (int pos = pw_len - 1; pos >= 0; pos--)
    {
      const u32 div = pos / 4;
      const u32 mod = pos & 3;
      const u32 sht = (3 - mod) << 3;

      #if VECT_SIZE == 1
        if (((tmp[div] >> sht) & 0xff) == 0x2e) // '.'
        {
          tmp[div] += (len - 0x2e) << sht;

          len = 0;
        }
        else
        {
          len++;
        }
      #endif
      #if VECT_SIZE >= 2
        REPLACE_DOT_BY_LEN (0)
        REPLACE_DOT_BY_LEN (1)
      #endif
      #if VECT_SIZE >= 4
        REPLACE_DOT_BY_LEN (2)
        REPLACE_DOT_BY_LEN (3)
      #endif
      #if VECT_SIZE >= 8
        REPLACE_DOT_BY_LEN (4)
        REPLACE_DOT_BY_LEN (5)
        REPLACE_DOT_BY_LEN (6)
        REPLACE_DOT_BY_LEN (7)
      #endif
      #if VECT_SIZE >= 16
        REPLACE_DOT_BY_LEN (8)
        REPLACE_DOT_BY_LEN (9)
        REPLACE_DOT_BY_LEN (a)
        REPLACE_DOT_BY_LEN (b)
        REPLACE_DOT_BY_LEN (c)
        REPLACE_DOT_BY_LEN (d)
        REPLACE_DOT_BY_LEN (e)
        REPLACE_DOT_BY_LEN (f)
      #endif
    }

    ctx1.w0[0] = (len & 0xff) << 24;

    ctx1.len = 1;

    sha1_update_vector (&ctx1, tmp, pw_len);

    sha1_update_vector (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update_vector (&ctx1, s, salt_len);

    sha1_final_vector (&ctx1);

    u32x digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_vector_t ctx;

      sha1_init_vector (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update_vector (&ctx, s, salt_len);

      sha1_final_vector (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32x r0 = digest[DGST_R0];
    const u32x r1 = digest[DGST_R1];
    const u32x r2 = digest[DGST_R2];
    const u32x r3 = digest[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
