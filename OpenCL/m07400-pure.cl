/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_sha256.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct sha256crypt_tmp
{
  // pure version

  u32 alt_result[8];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha256crypt_tmp_t;

KERNEL_FQ void m07400_init (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = hc_swap32_S (w[idx]);
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (s[idx]);
  }

  /**
   * prepare
   */

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, w, pw_len);

  sha256_update (&ctx, s, salt_len);

  sha256_update (&ctx, w, pw_len);

  sha256_final (&ctx);

  u32 final[16] = { 0 };

  final[0] = ctx.h[0];
  final[1] = ctx.h[1];
  final[2] = ctx.h[2];
  final[3] = ctx.h[3];
  final[4] = ctx.h[4];
  final[5] = ctx.h[5];
  final[6] = ctx.h[6];
  final[7] = ctx.h[7];

  // alt_result

  sha256_init (&ctx);

  sha256_update (&ctx, w, pw_len);

  sha256_update (&ctx, s, salt_len);

  int pl;

  for (pl = pw_len; pl > 32; pl -= 32)
  {
    sha256_update (&ctx, final, 32);
  }

  u32 t_final[16] = { 0 };

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++) t_final[i] = final[i];

  truncate_block_16x4_be_S (t_final + 0, t_final + 4, t_final + 8, t_final + 12, pl);

  sha256_update (&ctx, t_final, pl);

  for (int cnt = pw_len; cnt > 0; cnt >>= 1)
  {
    if ((cnt & 1) != 0)
    {
      sha256_update (&ctx, final, 32);
    }
    else
    {
      sha256_update (&ctx, w, pw_len);
    }
  }

  sha256_final (&ctx);

  tmps[gid].alt_result[0] = ctx.h[0];
  tmps[gid].alt_result[1] = ctx.h[1];
  tmps[gid].alt_result[2] = ctx.h[2];
  tmps[gid].alt_result[3] = ctx.h[3];
  tmps[gid].alt_result[4] = ctx.h[4];
  tmps[gid].alt_result[5] = ctx.h[5];
  tmps[gid].alt_result[6] = ctx.h[6];
  tmps[gid].alt_result[7] = ctx.h[7];

  // p_bytes

  sha256_init (&ctx);

  for (u32 j = 0; j < pw_len; j++)
  {
    sha256_update (&ctx, w, pw_len);
  }

  sha256_final (&ctx);

  final[ 0] = ctx.h[0];
  final[ 1] = ctx.h[1];
  final[ 2] = ctx.h[2];
  final[ 3] = ctx.h[3];
  final[ 4] = ctx.h[4];
  final[ 5] = ctx.h[5];
  final[ 6] = ctx.h[6];
  final[ 7] = ctx.h[7];
  final[ 8] = 0;
  final[ 9] = 0;
  final[10] = 0;
  final[11] = 0;
  final[12] = 0;
  final[13] = 0;
  final[14] = 0;
  final[15] = 0;

  u32 p_final[64] = { 0 };

  int idx;

  for (pl = pw_len, idx = 0; pl > 32; pl -= 32, idx += 8)
  {
    p_final[idx + 0] = final[0];
    p_final[idx + 1] = final[1];
    p_final[idx + 2] = final[2];
    p_final[idx + 3] = final[3];
    p_final[idx + 4] = final[4];
    p_final[idx + 5] = final[5];
    p_final[idx + 6] = final[6];
    p_final[idx + 7] = final[7];
  }

  truncate_block_16x4_be_S (final + 0, final + 4, final + 8, final + 12, pl);

  p_final[idx + 0] = final[0];
  p_final[idx + 1] = final[1];
  p_final[idx + 2] = final[2];
  p_final[idx + 3] = final[3];
  p_final[idx + 4] = final[4];
  p_final[idx + 5] = final[5];
  p_final[idx + 6] = final[6];
  p_final[idx + 7] = final[7];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 64; i++) tmps[gid].p_bytes[i] = p_final[i];

  // s_bytes

  sha256_init (&ctx);

  for (u32 j = 0; j < 16 + (tmps[gid].alt_result[0] >> 24); j++)
  {
    sha256_update (&ctx, s, salt_len);
  }

  sha256_final (&ctx);

  final[ 0] = ctx.h[0];
  final[ 1] = ctx.h[1];
  final[ 2] = ctx.h[2];
  final[ 3] = ctx.h[3];
  final[ 4] = ctx.h[4];
  final[ 5] = ctx.h[5];
  final[ 6] = ctx.h[6];
  final[ 7] = ctx.h[7];
  final[ 8] = 0;
  final[ 9] = 0;
  final[10] = 0;
  final[11] = 0;
  final[12] = 0;
  final[13] = 0;
  final[14] = 0;
  final[15] = 0;

  u32 s_final[64] = { 0 };

  for (pl = salt_len, idx = 0; pl > 32; pl -= 32, idx += 8)
  {
    s_final[idx + 0] = final[0];
    s_final[idx + 1] = final[1];
    s_final[idx + 2] = final[2];
    s_final[idx + 3] = final[3];
    s_final[idx + 4] = final[4];
    s_final[idx + 5] = final[5];
    s_final[idx + 6] = final[6];
    s_final[idx + 7] = final[7];
  }

  truncate_block_16x4_be_S (final + 0, final + 4, final + 8, final + 12, pl);

  s_final[idx + 0] = final[0];
  s_final[idx + 1] = final[1];
  s_final[idx + 2] = final[2];
  s_final[idx + 3] = final[3];
  s_final[idx + 4] = final[4];
  s_final[idx + 5] = final[5];
  s_final[idx + 6] = final[6];
  s_final[idx + 7] = final[7];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 64; i++) tmps[gid].s_bytes[i] = s_final[i];
}

KERNEL_FQ void m07400_loop (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 pw_len = pws[gid].pw_len;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 alt_result[16] = { 0 };

  alt_result[0] = tmps[gid].alt_result[0];
  alt_result[1] = tmps[gid].alt_result[1];
  alt_result[2] = tmps[gid].alt_result[2];
  alt_result[3] = tmps[gid].alt_result[3];
  alt_result[4] = tmps[gid].alt_result[4];
  alt_result[5] = tmps[gid].alt_result[5];
  alt_result[6] = tmps[gid].alt_result[6];
  alt_result[7] = tmps[gid].alt_result[7];

  /* Repeatedly run the collected hash value through sha256 to burn
     CPU cycles.  */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    if (j & 1)
    {
      sha256_update_global (&ctx, tmps[gid].p_bytes, pw_len);
    }
    else
    {
      sha256_update (&ctx, alt_result, 32);
    }

    if (j % 3)
    {
      sha256_update_global (&ctx, tmps[gid].s_bytes, salt_len);
    }

    if (j % 7)
    {
      sha256_update_global (&ctx, tmps[gid].p_bytes, pw_len);
    }

    if (j & 1)
    {
      sha256_update (&ctx, alt_result, 32);
    }
    else
    {
      sha256_update_global (&ctx, tmps[gid].p_bytes, pw_len);
    }

    sha256_final (&ctx);

    alt_result[0] = ctx.h[0];
    alt_result[1] = ctx.h[1];
    alt_result[2] = ctx.h[2];
    alt_result[3] = ctx.h[3];
    alt_result[4] = ctx.h[4];
    alt_result[5] = ctx.h[5];
    alt_result[6] = ctx.h[6];
    alt_result[7] = ctx.h[7];
  }

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];
}

KERNEL_FQ void m07400_comp (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 r0 = hc_swap32_S (tmps[gid].alt_result[0]);
  const u32 r1 = hc_swap32_S (tmps[gid].alt_result[1]);
  const u32 r2 = hc_swap32_S (tmps[gid].alt_result[2]);
  const u32 r3 = hc_swap32_S (tmps[gid].alt_result[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
