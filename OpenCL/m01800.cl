/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA512_

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

// Buggy drivers...

#ifdef IS_AMD
#define STATE_DECL volatile
//#define STATE_DECL
#else
#define STATE_DECL
#endif

#define PUTCHAR64_BE(a,p,c) ((u8 *)(a))[(p) ^ 7] = (u8) (c)
#define GETCHAR64_BE(a,p)   ((u8 *)(a))[(p) ^ 7]

typedef struct
{
  u64 state[8];
  u64 buf[16];
  int len;

} sha512_ctx_t;

__constant u64 k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

void sha512_transform (const u64 w[16], u64 digest[8])
{
  u64 w0_t = w[ 0];
  u64 w1_t = w[ 1];
  u64 w2_t = w[ 2];
  u64 w3_t = w[ 3];
  u64 w4_t = w[ 4];
  u64 w5_t = w[ 5];
  u64 w6_t = w[ 6];
  u64 w7_t = w[ 7];
  u64 w8_t = w[ 8];
  u64 w9_t = w[ 9];
  u64 wa_t = w[10];
  u64 wb_t = w[11];
  u64 wc_t = w[12];
  u64 wd_t = w[13];
  u64 we_t = w[14];
  u64 wf_t = w[15];

  STATE_DECL u64 a = digest[0];
  STATE_DECL u64 b = digest[1];
  STATE_DECL u64 c = digest[2];
  STATE_DECL u64 d = digest[3];
  STATE_DECL u64 e = digest[4];
  STATE_DECL u64 f = digest[5];
  STATE_DECL u64 g = digest[6];
  STATE_DECL u64 h = digest[7];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

void sha512_init (sha512_ctx_t *sha512_ctx)
{
  sha512_ctx->state[0] = SHA512M_A;
  sha512_ctx->state[1] = SHA512M_B;
  sha512_ctx->state[2] = SHA512M_C;
  sha512_ctx->state[3] = SHA512M_D;
  sha512_ctx->state[4] = SHA512M_E;
  sha512_ctx->state[5] = SHA512M_F;
  sha512_ctx->state[6] = SHA512M_G;
  sha512_ctx->state[7] = SHA512M_H;

  sha512_ctx->len = 0;
}

void sha512_update (sha512_ctx_t *sha512_ctx, const u64 *buf, int len)
{
  int pos = sha512_ctx->len & 0x7f;

  sha512_ctx->len += len;

  if ((pos + len) < 128)
  {
    for (int i = 0; i < len; i++)
    {
      PUTCHAR64_BE (sha512_ctx->buf, pos++, GETCHAR64_BE (buf, i));
    }

    return;
  }

  int cnt = 128 - pos;

  for (int i = 0; i < cnt; i++)
  {
    PUTCHAR64_BE (sha512_ctx->buf, pos++, GETCHAR64_BE (buf, i));
  }

  sha512_transform (sha512_ctx->buf, sha512_ctx->state);

  len -= cnt;

  for (int i = 0; i < len; i++)
  {
    PUTCHAR64_BE (sha512_ctx->buf, i, GETCHAR64_BE (buf, cnt + i));
  }
}

void sha512_final (sha512_ctx_t *sha512_ctx)
{
  int pos = sha512_ctx->len & 0x7f;

  for (int i = pos; i < 128; i++)
  {
    PUTCHAR64_BE (sha512_ctx->buf, i, 0);
  }

  PUTCHAR64_BE (sha512_ctx->buf, pos, 0x80);

  if (pos >= 112)
  {
    sha512_transform (sha512_ctx->buf, sha512_ctx->state);

    sha512_ctx->buf[ 0] = 0;
    sha512_ctx->buf[ 1] = 0;
    sha512_ctx->buf[ 2] = 0;
    sha512_ctx->buf[ 3] = 0;
    sha512_ctx->buf[ 4] = 0;
    sha512_ctx->buf[ 5] = 0;
    sha512_ctx->buf[ 6] = 0;
    sha512_ctx->buf[ 7] = 0;
    sha512_ctx->buf[ 8] = 0;
    sha512_ctx->buf[ 9] = 0;
    sha512_ctx->buf[10] = 0;
    sha512_ctx->buf[11] = 0;
    sha512_ctx->buf[12] = 0;
    sha512_ctx->buf[13] = 0;
    sha512_ctx->buf[14] = 0;
    sha512_ctx->buf[15] = 0;
  }

  sha512_ctx->buf[15] = sha512_ctx->len * 8;

  sha512_transform (sha512_ctx->buf, sha512_ctx->state);
}

__kernel void m01800_init (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha512crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * buffers
   */

  u64 pw[2];

  pw[0] = swap64 (hl32_to_64 (w0[1], w0[0]));
  pw[1] = swap64 (hl32_to_64 (w0[3], w0[2]));

  u64 salt[2];

  salt[0] = swap64 (hl32_to_64 (salt_buf[1], salt_buf[0]));
  salt[1] = swap64 (hl32_to_64 (salt_buf[3], salt_buf[2]));

  /**
   * begin
   */

  sha512_ctx_t sha512_ctx;

  sha512_init (&sha512_ctx);

  sha512_update (&sha512_ctx, pw, pw_len);
  sha512_update (&sha512_ctx, salt, salt_len);
  sha512_update (&sha512_ctx, pw, pw_len);

  sha512_final (&sha512_ctx);

  u64 tmp[8];

  tmp[0] = sha512_ctx.state[0];
  tmp[1] = sha512_ctx.state[1];
  tmp[2] = sha512_ctx.state[2];
  tmp[3] = sha512_ctx.state[3];
  tmp[4] = sha512_ctx.state[4];
  tmp[5] = sha512_ctx.state[5];
  tmp[6] = sha512_ctx.state[6];
  tmp[7] = sha512_ctx.state[7];

  sha512_init (&sha512_ctx);

  sha512_update (&sha512_ctx, pw, pw_len);
  sha512_update (&sha512_ctx, salt, salt_len);
  sha512_update (&sha512_ctx, tmp, pw_len);

  for (u32 j = pw_len; j; j >>= 1)
  {
    if (j & 1)
    {
      sha512_update (&sha512_ctx, tmp, 64);
    }
    else
    {
      sha512_update (&sha512_ctx, pw, pw_len);
    }
  }

  sha512_final (&sha512_ctx);

  tmps[gid].l_alt_result[0] = sha512_ctx.state[0];
  tmps[gid].l_alt_result[1] = sha512_ctx.state[1];
  tmps[gid].l_alt_result[2] = sha512_ctx.state[2];
  tmps[gid].l_alt_result[3] = sha512_ctx.state[3];
  tmps[gid].l_alt_result[4] = sha512_ctx.state[4];
  tmps[gid].l_alt_result[5] = sha512_ctx.state[5];
  tmps[gid].l_alt_result[6] = sha512_ctx.state[6];
  tmps[gid].l_alt_result[7] = sha512_ctx.state[7];

  // p_bytes

  sha512_init (&sha512_ctx);

  for (u32 j = 0; j < pw_len; j++)
  {
    sha512_update (&sha512_ctx, pw, pw_len);
  }

  sha512_final (&sha512_ctx);

  tmps[gid].l_p_bytes[0] = sha512_ctx.state[0];
  tmps[gid].l_p_bytes[1] = sha512_ctx.state[1];

  // s_bytes

  sha512_init (&sha512_ctx);

  for (u32 j = 0; j < 16 + ((tmps[gid].l_alt_result[0] >> 56) & 0xff); j++)
  {
    sha512_update (&sha512_ctx, salt, salt_len);
  }

  sha512_final (&sha512_ctx);

  tmps[gid].l_s_bytes[0] = sha512_ctx.state[0];
  tmps[gid].l_s_bytes[1] = sha512_ctx.state[1];
}

__kernel void m01800_loop (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha512crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u64 l_p_bytes0[2];

  l_p_bytes0[0] = tmps[gid].l_p_bytes[0];
  l_p_bytes0[1] = tmps[gid].l_p_bytes[1];

  const u32 pw_len = pws[gid].pw_len;

  u64 l_s_bytes0[2];

  l_s_bytes0[0] = tmps[gid].l_s_bytes[0];
  l_s_bytes0[1] = tmps[gid].l_s_bytes[1];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 wpc_len[8];

  wpc_len[0] = 64     +        0 +      0 + pw_len;
  wpc_len[1] = pw_len +        0 +      0 + 64;
  wpc_len[2] = 64     + salt_len +      0 + pw_len;
  wpc_len[3] = pw_len + salt_len +      0 + 64;
  wpc_len[4] = 64     +        0 + pw_len + pw_len;
  wpc_len[5] = pw_len +        0 + pw_len + 64;
  wpc_len[6] = 64     + salt_len + pw_len + pw_len;
  wpc_len[7] = pw_len + salt_len + pw_len + 64;

  u64 wpc[8][16] = { { 0 } };

  for (u32 i = 0; i < 8; i++)
  {
    u32 block_len = 0;

    if (i & 1)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
      }
    }
    else
    {
      block_len += 64;
    }

    if (i & 2)
    {
      for (u32 j = 0; j < salt_len; j++)
      {
        PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_s_bytes0, j));
      }
    }

    if (i & 4)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
      }
    }

    if (i & 1)
    {
      block_len += 64;
    }
    else
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
      }
    }

    PUTCHAR64_BE (wpc[i], block_len, 0x80);

    wpc[i][15] = block_len * 8;
  }

  /**
   * base
   */

  u64 l_alt_result[8];

  l_alt_result[0] = tmps[gid].l_alt_result[0];
  l_alt_result[1] = tmps[gid].l_alt_result[1];
  l_alt_result[2] = tmps[gid].l_alt_result[2];
  l_alt_result[3] = tmps[gid].l_alt_result[3];
  l_alt_result[4] = tmps[gid].l_alt_result[4];
  l_alt_result[5] = tmps[gid].l_alt_result[5];
  l_alt_result[6] = tmps[gid].l_alt_result[6];
  l_alt_result[7] = tmps[gid].l_alt_result[7];


  /* Repeatedly run the collected hash value through SHA512 to burn
     CPU cycles.  */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 2 : 0;
    const u32 j7 = (j % 7) ? 4 : 0;

    const u32 pc = j1 + j3 + j7;

    u64 block[16];

    block[ 0] = wpc[pc][ 0];
    block[ 1] = wpc[pc][ 1];
    block[ 2] = wpc[pc][ 2];
    block[ 3] = wpc[pc][ 3];
    block[ 4] = wpc[pc][ 4];
    block[ 5] = wpc[pc][ 5];
    block[ 6] = wpc[pc][ 6];
    block[ 7] = wpc[pc][ 7];
    block[ 8] = wpc[pc][ 8];
    block[ 9] = wpc[pc][ 9];
    block[10] = wpc[pc][10];
    block[11] = wpc[pc][11];
    block[12] = wpc[pc][12];
    block[13] = wpc[pc][13];
    block[14] = wpc[pc][14];
    block[15] = wpc[pc][15];

    if (j1)
    {
      const u32 block_len = wpc_len[pc];

      #ifdef _unroll
      #pragma unroll
      #endif
      for (u32 k = 0, p = block_len - 64; k < 64; k++, p++)
      {
        PUTCHAR64_BE (block, p, GETCHAR64_BE (l_alt_result, k));
      }
    }
    else
    {
      block[0] = l_alt_result[0];
      block[1] = l_alt_result[1];
      block[2] = l_alt_result[2];
      block[3] = l_alt_result[3];
      block[4] = l_alt_result[4];
      block[5] = l_alt_result[5];
      block[6] = l_alt_result[6];
      block[7] = l_alt_result[7];
    }

    l_alt_result[0] = SHA512M_A;
    l_alt_result[1] = SHA512M_B;
    l_alt_result[2] = SHA512M_C;
    l_alt_result[3] = SHA512M_D;
    l_alt_result[4] = SHA512M_E;
    l_alt_result[5] = SHA512M_F;
    l_alt_result[6] = SHA512M_G;
    l_alt_result[7] = SHA512M_H;

    sha512_transform (block, l_alt_result);
  }

  tmps[gid].l_alt_result[0] = l_alt_result[0];
  tmps[gid].l_alt_result[1] = l_alt_result[1];
  tmps[gid].l_alt_result[2] = l_alt_result[2];
  tmps[gid].l_alt_result[3] = l_alt_result[3];
  tmps[gid].l_alt_result[4] = l_alt_result[4];
  tmps[gid].l_alt_result[5] = l_alt_result[5];
  tmps[gid].l_alt_result[6] = l_alt_result[6];
  tmps[gid].l_alt_result[7] = l_alt_result[7];
}

__kernel void m01800_comp (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha512crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  const u64 a = swap64 (tmps[gid].l_alt_result[0]);
  const u64 b = swap64 (tmps[gid].l_alt_result[1]);

  const u32 r0 = l32_from_64 (a);
  const u32 r1 = h32_from_64 (a);
  const u32 r2 = l32_from_64 (b);
  const u32 r3 = h32_from_64 (b);

  #define il_pos 0

  #include COMPARE_M
}
