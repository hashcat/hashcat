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
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct qnx_sha512_tmp
{
  sha512_ctx_t sha512_ctx;

  u32 sav; // to trigger sha512 bug

} qnx_sha512_tmp_t;

DECLSPEC u32 sha512_update_128_qnxbug (sha512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len, u32 sav)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  ctx->len += len;

  if ((pos + len) < 128)
  {
    switch_buffer_by_offset_8x4_be_S (w0, w1, w2, w3, w4, w5, w6, w7, pos);

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
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };
    u32 c4[4] = { 0 };
    u32 c5[4] = { 0 };
    u32 c6[4] = { 0 };
    u32 c7[4] = { 0 };

    switch_buffer_by_offset_8x4_carry_be_S (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

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
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];

    sav = ctx->w7[1];

    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
    ctx->w4[0] = c4[0];
    ctx->w4[1] = c4[1];
    ctx->w4[2] = c4[2];
    ctx->w4[3] = c4[3];
    ctx->w5[0] = c5[0];
    ctx->w5[1] = c5[1];
    ctx->w5[2] = c5[2];
    ctx->w5[3] = c5[3];
    ctx->w6[0] = c6[0];
    ctx->w6[1] = c6[1];
    ctx->w6[2] = c6[2];
    ctx->w6[3] = c6[3];
    ctx->w7[0] = c7[0];
    ctx->w7[1] = c7[1];
    ctx->w7[2] = c7[2];
    ctx->w7[3] = c7[3];
  }

  return sav;
}

DECLSPEC u32 sha512_update_global_swap_qnxbug (sha512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, u32 sav)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);
    w4[0] = hc_swap32_S (w4[0]);
    w4[1] = hc_swap32_S (w4[1]);
    w4[2] = hc_swap32_S (w4[2]);
    w4[3] = hc_swap32_S (w4[3]);
    w5[0] = hc_swap32_S (w5[0]);
    w5[1] = hc_swap32_S (w5[1]);
    w5[2] = hc_swap32_S (w5[2]);
    w5[3] = hc_swap32_S (w5[3]);
    w6[0] = hc_swap32_S (w6[0]);
    w6[1] = hc_swap32_S (w6[1]);
    w6[2] = hc_swap32_S (w6[2]);
    w6[3] = hc_swap32_S (w6[3]);
    w7[0] = hc_swap32_S (w7[0]);
    w7[1] = hc_swap32_S (w7[1]);
    w7[2] = hc_swap32_S (w7[2]);
    w7[3] = hc_swap32_S (w7[3]);

    sav = sha512_update_128_qnxbug (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128, sav);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sav = sha512_update_128_qnxbug (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1, sav);

  return sav;
}

DECLSPEC void sha512_final_qnxbug (sha512_ctx_t *ctx, u32 sav)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  append_0x80_8x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sav = ctx->w7[1];

    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
    ctx->w4[0] = 0;
    ctx->w4[1] = 0;
    ctx->w4[2] = 0;
    ctx->w4[3] = 0;
    ctx->w5[0] = 0;
    ctx->w5[1] = 0;
    ctx->w5[2] = 0;
    ctx->w5[3] = 0;
    ctx->w6[0] = 0;
    ctx->w6[1] = 0;
    ctx->w6[2] = 0;
    ctx->w6[3] = 0;
    ctx->w7[0] = 0;
    ctx->w7[1] = 0;
    ctx->w7[2] = 0;
    ctx->w7[3] = 0;
  }

  ctx->w7[1] = sav;
  ctx->w7[2] = 0;
  ctx->w7[3] = ctx->len * 8;

  sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

KERNEL_FQ void m19200_init (KERN_ATTR_TMPS (qnx_sha512_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  sha512_ctx_t sha512_ctx;

  sha512_init (&sha512_ctx);

  sha512_update_global_swap (&sha512_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha512_update_global_swap (&sha512_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].sha512_ctx = sha512_ctx;
  tmps[gid].sav = 0;
}

KERNEL_FQ void m19200_loop (KERN_ATTR_TMPS (qnx_sha512_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t sha512_ctx = tmps[gid].sha512_ctx;
  u32 sav = tmps[gid].sav;

  for (u32 i = 0; i < loop_cnt; i++)
  {
    sav = sha512_update_global_swap_qnxbug (&sha512_ctx, pws[gid].i, pws[gid].pw_len, sav);
  }

  tmps[gid].sha512_ctx = sha512_ctx;
  tmps[gid].sav = sav;
}

KERNEL_FQ void m19200_comp (KERN_ATTR_TMPS (qnx_sha512_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t sha512_ctx = tmps[gid].sha512_ctx;

  sha512_final (&sha512_ctx);

  const u32 r0 = l32_from_64_S (hc_swap64_S (sha512_ctx.h[0]));
  const u32 r1 = h32_from_64_S (hc_swap64_S (sha512_ctx.h[0]));
  const u32 r2 = l32_from_64_S (hc_swap64_S (sha512_ctx.h[1]));
  const u32 r3 = h32_from_64_S (hc_swap64_S (sha512_ctx.h[1]));

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif

  // we should also handle the buggy qnx sha512 implementation
  // see https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/sha2.c#L578-L595

  sha512_ctx_t sha512_ctx2 = tmps[gid].sha512_ctx;
  u32 sav = tmps[gid].sav;

  if (sha512_ctx2.len >= 116)
  {
    sha512_final_qnxbug (&sha512_ctx2, sav);

    const u32 r0 = l32_from_64_S (hc_swap64_S (sha512_ctx2.h[0]));
    const u32 r1 = h32_from_64_S (hc_swap64_S (sha512_ctx2.h[0]));
    const u32 r2 = l32_from_64_S (hc_swap64_S (sha512_ctx2.h[1]));
    const u32 r3 = h32_from_64_S (hc_swap64_S (sha512_ctx2.h[1]));

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
