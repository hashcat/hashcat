/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_sha512.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define PUTCHAR64_BE(a,p,c) ((u8 *)(a))[(p) ^ 7] = (u8) (c)
#define GETCHAR64_BE(a,p)   ((u8 *)(a))[(p) ^ 7]

typedef struct
{
  u64 state[8];
  u64 buf[16];
  int len;

} orig_sha512_ctx_t;

DECLSPEC void sha512_transform_transport (const u64 *w, u64 *digest)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  t0[0] = h32_from_64_S (w[ 0]);
  t0[1] = l32_from_64_S (w[ 0]);
  t0[2] = h32_from_64_S (w[ 1]);
  t0[3] = l32_from_64_S (w[ 1]);
  t1[0] = h32_from_64_S (w[ 2]);
  t1[1] = l32_from_64_S (w[ 2]);
  t1[2] = h32_from_64_S (w[ 3]);
  t1[3] = l32_from_64_S (w[ 3]);
  t2[0] = h32_from_64_S (w[ 4]);
  t2[1] = l32_from_64_S (w[ 4]);
  t2[2] = h32_from_64_S (w[ 5]);
  t2[3] = l32_from_64_S (w[ 5]);
  t3[0] = h32_from_64_S (w[ 6]);
  t3[1] = l32_from_64_S (w[ 6]);
  t3[2] = h32_from_64_S (w[ 7]);
  t3[3] = l32_from_64_S (w[ 7]);
  t4[0] = h32_from_64_S (w[ 8]);
  t4[1] = l32_from_64_S (w[ 8]);
  t4[2] = h32_from_64_S (w[ 9]);
  t4[3] = l32_from_64_S (w[ 9]);
  t5[0] = h32_from_64_S (w[10]);
  t5[1] = l32_from_64_S (w[10]);
  t5[2] = h32_from_64_S (w[11]);
  t5[3] = l32_from_64_S (w[11]);
  t6[0] = h32_from_64_S (w[12]);
  t6[1] = l32_from_64_S (w[12]);
  t6[2] = h32_from_64_S (w[13]);
  t6[3] = l32_from_64_S (w[13]);
  t7[0] = h32_from_64_S (w[14]);
  t7[1] = l32_from_64_S (w[14]);
  t7[2] = h32_from_64_S (w[15]);
  t7[3] = l32_from_64_S (w[15]);

  sha512_transform (t0, t1, t2, t3, t4, t5, t6, t7, digest);
}

DECLSPEC void orig_sha512_init (orig_sha512_ctx_t *sha512_ctx)
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

DECLSPEC void orig_sha512_update (orig_sha512_ctx_t *sha512_ctx, const u64 *buf, int len)
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

  sha512_transform_transport (sha512_ctx->buf, sha512_ctx->state);

  len -= cnt;

  for (int i = 0; i < len; i++)
  {
    PUTCHAR64_BE (sha512_ctx->buf, i, GETCHAR64_BE (buf, cnt + i));
  }
}

DECLSPEC void orig_sha512_final (orig_sha512_ctx_t *sha512_ctx)
{
  int pos = sha512_ctx->len & 0x7f;

  for (int i = pos; i < 128; i++)
  {
    PUTCHAR64_BE (sha512_ctx->buf, i, 0);
  }

  PUTCHAR64_BE (sha512_ctx->buf, pos, 0x80);

  if (pos >= 112)
  {
    sha512_transform_transport (sha512_ctx->buf, sha512_ctx->state);

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

  sha512_transform_transport (sha512_ctx->buf, sha512_ctx->state);
}

__kernel void m01800_init (KERN_ATTR_TMPS (sha512crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len & 63;

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

  pw[0] = swap64_S (hl32_to_64 (w0[1], w0[0]));
  pw[1] = swap64_S (hl32_to_64 (w0[3], w0[2]));

  u64 salt[2];

  salt[0] = swap64_S (hl32_to_64 (salt_buf[1], salt_buf[0]));
  salt[1] = swap64_S (hl32_to_64 (salt_buf[3], salt_buf[2]));

  /**
   * begin
   */

  orig_sha512_ctx_t sha512_ctx;

  orig_sha512_init (&sha512_ctx);

  orig_sha512_update (&sha512_ctx, pw, pw_len);
  orig_sha512_update (&sha512_ctx, salt, salt_len);
  orig_sha512_update (&sha512_ctx, pw, pw_len);

  orig_sha512_final (&sha512_ctx);

  u64 tmp[8];

  tmp[0] = sha512_ctx.state[0];
  tmp[1] = sha512_ctx.state[1];
  tmp[2] = sha512_ctx.state[2];
  tmp[3] = sha512_ctx.state[3];
  tmp[4] = sha512_ctx.state[4];
  tmp[5] = sha512_ctx.state[5];
  tmp[6] = sha512_ctx.state[6];
  tmp[7] = sha512_ctx.state[7];

  orig_sha512_init (&sha512_ctx);

  orig_sha512_update (&sha512_ctx, pw, pw_len);
  orig_sha512_update (&sha512_ctx, salt, salt_len);
  orig_sha512_update (&sha512_ctx, tmp, pw_len);

  for (u32 j = pw_len; j; j >>= 1)
  {
    if (j & 1)
    {
      orig_sha512_update (&sha512_ctx, tmp, 64);
    }
    else
    {
      orig_sha512_update (&sha512_ctx, pw, pw_len);
    }
  }

  orig_sha512_final (&sha512_ctx);

  tmps[gid].l_alt_result[0] = sha512_ctx.state[0];
  tmps[gid].l_alt_result[1] = sha512_ctx.state[1];
  tmps[gid].l_alt_result[2] = sha512_ctx.state[2];
  tmps[gid].l_alt_result[3] = sha512_ctx.state[3];
  tmps[gid].l_alt_result[4] = sha512_ctx.state[4];
  tmps[gid].l_alt_result[5] = sha512_ctx.state[5];
  tmps[gid].l_alt_result[6] = sha512_ctx.state[6];
  tmps[gid].l_alt_result[7] = sha512_ctx.state[7];

  // p_bytes

  orig_sha512_init (&sha512_ctx);

  for (u32 j = 0; j < pw_len; j++)
  {
    orig_sha512_update (&sha512_ctx, pw, pw_len);
  }

  orig_sha512_final (&sha512_ctx);

  tmps[gid].l_p_bytes[0] = sha512_ctx.state[0];
  tmps[gid].l_p_bytes[1] = sha512_ctx.state[1];

  // s_bytes

  orig_sha512_init (&sha512_ctx);

  for (u32 j = 0; j < 16 + ((tmps[gid].l_alt_result[0] >> 56) & 0xff); j++)
  {
    orig_sha512_update (&sha512_ctx, salt, salt_len);
  }

  orig_sha512_final (&sha512_ctx);

  tmps[gid].l_s_bytes[0] = sha512_ctx.state[0];
  tmps[gid].l_s_bytes[1] = sha512_ctx.state[1];
}

__kernel void m01800_loop (KERN_ATTR_TMPS (sha512crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u64 l_p_bytes0[2];

  l_p_bytes0[0] = tmps[gid].l_p_bytes[0];
  l_p_bytes0[1] = tmps[gid].l_p_bytes[1];

  const u32 pw_len = pws[gid].pw_len & 63;

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

    sha512_transform_transport (block, l_alt_result);
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

__kernel void m01800_comp (KERN_ATTR_TMPS (sha512crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u64 a = swap64_S (tmps[gid].l_alt_result[0]);
  const u64 b = swap64_S (tmps[gid].l_alt_result[1]);

  const u32 r0 = l32_from_64_S (a);
  const u32 r1 = h32_from_64_S (a);
  const u32 r2 = l32_from_64_S (b);
  const u32 r3 = h32_from_64_S (b);

  #define il_pos 0

  #include COMPARE_M
}
