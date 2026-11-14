/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_auth_poly1305.h"

DECLSPEC void poly1305_init (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *key)
{
  const u32 k0 = key[0];
  const u32 k1 = key[1];
  const u32 k2 = key[2];
  const u32 k3 = key[3];

  ctx->r[0] = (k0) & 0x3ffffff;
  ctx->r[1] = ((k0 >> 26) | (k1 << 6)) & 0x3ffff03;
  ctx->r[2] = ((k1 >> 20) | (k2 << 12)) & 0x3ffc0ff;
  ctx->r[3] = ((k2 >> 14) | (k3 << 18)) & 0x3f03fff;
  ctx->r[4] = (k3 >> 8) & 0x00fffff;

  ctx->h[0] = 0;
  ctx->h[1] = 0;
  ctx->h[2] = 0;
  ctx->h[3] = 0;
  ctx->h[4] = 0;

  ctx->pad[0] = key[4];
  ctx->pad[1] = key[5];
  ctx->pad[2] = key[6];
  ctx->pad[3] = key[7];

  ctx->buffer_left = 0;
}

DECLSPEC void poly1305_blocks (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *m, const u32 blocks)
{
  const u32 hibit = 0x01000000;
  u32 r0, r1, r2, r3, r4;
  u32 s1, s2, s3, s4;
  u32 h0, h1, h2, h3, h4;
  u64 d0, d1, d2, d3, d4;
  u32 c;

  r0 = ctx->r[0];
  r1 = ctx->r[1];
  r2 = ctx->r[2];
  r3 = ctx->r[3];
  r4 = ctx->r[4];

  s1 = r1 * 5;
  s2 = r2 * 5;
  s3 = r3 * 5;
  s4 = r4 * 5;

  h0 = ctx->h[0];
  h1 = ctx->h[1];
  h2 = ctx->h[2];
  h3 = ctx->h[3];
  h4 = ctx->h[4];

  for (u32 i = 0; i < blocks; i++)
  {
    const u32 m0 = m[0];
    const u32 m1 = m[1];
    const u32 m2 = m[2];
    const u32 m3 = m[3];

    h0 += (m0) & 0x3ffffff;
    h1 += ((m0 >> 26) | (m1 << 6)) & 0x3ffffff;
    h2 += ((m1 >> 20) | (m2 << 12)) & 0x3ffffff;
    h3 += ((m2 >> 14) | (m3 << 18)) & 0x3ffffff;
    h4 += (m3 >> 8) | hibit;

    d0 = ((u64)h0 * r0) + ((u64)h1 * s4) + ((u64)h2 * s3) + ((u64)h3 * s2) + ((u64)h4 * s1);
    d1 = ((u64)h0 * r1) + ((u64)h1 * r0) + ((u64)h2 * s4) + ((u64)h3 * s3) + ((u64)h4 * s2);
    d2 = ((u64)h0 * r2) + ((u64)h1 * r1) + ((u64)h2 * r0) + ((u64)h3 * s4) + ((u64)h4 * s3);
    d3 = ((u64)h0 * r3) + ((u64)h1 * r2) + ((u64)h2 * r1) + ((u64)h3 * r0) + ((u64)h4 * s4);
    d4 = ((u64)h0 * r4) + ((u64)h1 * r3) + ((u64)h2 * r2) + ((u64)h3 * r1) + ((u64)h4 * r0);

    c = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff;
    d1 += c;   c = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff;
    d2 += c;   c = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff;
    d3 += c;   c = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff;
    d4 += c;   c = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff;
    h0 += c * 5; c = (h0 >> 26); h0 = h0 & 0x3ffffff;
    h1 += c;

    m += 4;
  }

  ctx->h[0] = h0;
  ctx->h[1] = h1;
  ctx->h[2] = h2;
  ctx->h[3] = h3;
  ctx->h[4] = h4;
}

DECLSPEC void poly1305_update_global (PRIVATE_AS poly1305_ctx_t *ctx, GLOBAL_AS const u32 *m, const u32 bytes)
{
  u32 i = 0;

  // Handle remaining buffer
  if (ctx->buffer_left > 0)
  {
    while (ctx->buffer_left < 16 && i < bytes)
    {
      GLOBAL_AS const u8 *m_byte = (GLOBAL_AS const u8 *)m;
      ((u8*)ctx->buffer)[ctx->buffer_left++] = m_byte[i++];
    }

    if (ctx->buffer_left == 16)
    {
      poly1305_blocks(ctx, ctx->buffer, 1);
      ctx->buffer_left = 0;
    }
  }

  GLOBAL_AS const u8 *m_byte = (GLOBAL_AS const u8 *)m;

  while (i + 16 <= bytes)
  {
    u32 block[4];
    block[0] = ((u32)m_byte[i+0]) | ((u32)m_byte[i+1] << 8) | ((u32)m_byte[i+2] << 16) | ((u32)m_byte[i+3] << 24);
    block[1] = ((u32)m_byte[i+4]) | ((u32)m_byte[i+5] << 8) | ((u32)m_byte[i+6] << 16) | ((u32)m_byte[i+7] << 24);
    block[2] = ((u32)m_byte[i+8]) | ((u32)m_byte[i+9] << 8) | ((u32)m_byte[i+10] << 16) | ((u32)m_byte[i+11] << 24);
    block[3] = ((u32)m_byte[i+12]) | ((u32)m_byte[i+13] << 8) | ((u32)m_byte[i+14] << 16) | ((u32)m_byte[i+15] << 24);

    poly1305_blocks(ctx, block, 1);
    i += 16;
  }

  while (i < bytes)
  {
    ((u8*)ctx->buffer)[ctx->buffer_left++] = m_byte[i++];
  }
}

DECLSPEC void poly1305_update_private (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *m, const u32 bytes)
{
  u32 i = 0;
  PRIVATE_AS const u8 *m_byte = (PRIVATE_AS const u8 *)m;

  if (ctx->buffer_left > 0)
  {
    while (ctx->buffer_left < 16 && i < bytes)
    {
      ((u8*)ctx->buffer)[ctx->buffer_left++] = m_byte[i++];
    }
    if (ctx->buffer_left == 16)
    {
      poly1305_blocks(ctx, ctx->buffer, 1);
      ctx->buffer_left = 0;
    }
  }

  while (i + 16 <= bytes)
  {
    u32 block[4];
    block[0] = ((u32)m_byte[i+0]) | ((u32)m_byte[i+1] << 8) | ((u32)m_byte[i+2] << 16) | ((u32)m_byte[i+3] << 24);
    block[1] = ((u32)m_byte[i+4]) | ((u32)m_byte[i+5] << 8) | ((u32)m_byte[i+6] << 16) | ((u32)m_byte[i+7] << 24);
    block[2] = ((u32)m_byte[i+8]) | ((u32)m_byte[i+9] << 8) | ((u32)m_byte[i+10] << 16) | ((u32)m_byte[i+11] << 24);
    block[3] = ((u32)m_byte[i+12]) | ((u32)m_byte[i+13] << 8) | ((u32)m_byte[i+14] << 16) | ((u32)m_byte[i+15] << 24);

    poly1305_blocks(ctx, block, 1);
    i += 16;
  }

  while (i < bytes)
  {
    ((u8*)ctx->buffer)[ctx->buffer_left++] = m_byte[i++];
  }
}

DECLSPEC void poly1305_update_pad (PRIVATE_AS poly1305_ctx_t *ctx, const u32 bytes)
{
  if (bytes % 16 != 0)
  {
    u32 pad_len = 16 - (bytes % 16);
    u32 zeros[4] = {0};
    poly1305_update_private(ctx, zeros, pad_len);
  }
}

DECLSPEC void poly1305_final (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS u32 *mac)
{
  u32 h0, h1, h2, h3, h4, c;
  u32 g0, g1, g2, g3, g4;
  u64 f;
  u32 mask;

  // Process remaining buffer
  if (ctx->buffer_left > 0)
  {
    PRIVATE_AS const u8 *msg = (PRIVATE_AS const u8 *)ctx->buffer;
    u32 hibit = (ctx->buffer_left == 16) ? 0x01000000 : 0;

    // Pad the message
    ((u8*)ctx->buffer)[ctx->buffer_left] = 1;
    ctx->buffer_left++;
    while (ctx->buffer_left < 16)
    {
      ((u8*)ctx->buffer)[ctx->buffer_left++] = 0;
    }

    msg = (PRIVATE_AS const u8 *)ctx->buffer;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    // Add final block
    h0 += (((u32)msg[ 0]) | ((u32)msg[ 1] << 8) | ((u32)msg[ 2] << 16) | ((u32)msg[ 3] << 24)) & 0x3ffffff;
    h1 += (((u32)msg[ 3] >> 2) | ((u32)msg[ 4] << 6) | ((u32)msg[ 5] << 14) | ((u32)msg[ 6] << 22)) & 0x3ffffff;
    h2 += (((u32)msg[ 6] >> 4) | ((u32)msg[ 7] << 4) | ((u32)msg[ 8] << 12) | ((u32)msg[ 9] << 20)) & 0x3ffffff;
    h3 += (((u32)msg[ 9] >> 6) | ((u32)msg[10] << 2) | ((u32)msg[11] << 10) | ((u32)msg[12] << 18)) & 0x3ffffff;
    h4 += (((u32)msg[12] >> 8) | ((u32)msg[13]) | ((u32)msg[14] << 8) | ((u32)msg[15] << 16)) | hibit;

    // h *= r
    u64 d0 = ((u64)h0 * ctx->r[0]) + ((u64)h1 * ctx->r[4]*5) + ((u64)h2 * ctx->r[3]*5) + ((u64)h3 * ctx->r[2]*5) + ((u64)h4 * ctx->r[1]*5);
    u64 d1 = ((u64)h0 * ctx->r[1]) + ((u64)h1 * ctx->r[0]) + ((u64)h2 * ctx->r[4]*5) + ((u64)h3 * ctx->r[3]*5) + ((u64)h4 * ctx->r[2]*5);
    u64 d2 = ((u64)h0 * ctx->r[2]) + ((u64)h1 * ctx->r[1]) + ((u64)h2 * ctx->r[0]) + ((u64)h3 * ctx->r[4]*5) + ((u64)h4 * ctx->r[3]*5);
    u64 d3 = ((u64)h0 * ctx->r[3]) + ((u64)h1 * ctx->r[2]) + ((u64)h2 * ctx->r[1]) + ((u64)h3 * ctx->r[0]) + ((u64)h4 * ctx->r[4]*5);
    u64 d4 = ((u64)h0 * ctx->r[4]) + ((u64)h1 * ctx->r[3]) + ((u64)h2 * ctx->r[2]) + ((u64)h3 * ctx->r[1]) + ((u64)h4 * ctx->r[0]);

    c = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff;
    d1 += c;   c = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff;
    d2 += c;   c = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff;
    d3 += c;   c = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff;
    d4 += c;   c = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff;
    h0 += c * 5; c = (h0 >> 26); h0 = h0 & 0x3ffffff;
    h1 += c;

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
  }

  // Fully carry h
  h0 = ctx->h[0];
  h1 = ctx->h[1];
  h2 = ctx->h[2];
  h3 = ctx->h[3];
  h4 = ctx->h[4];

  c = h1 >> 26; h1 = h1 & 0x3ffffff;
  h2 += c;     c = h2 >> 26; h2 = h2 & 0x3ffffff;
  h3 += c;     c = h3 >> 26; h3 = h3 & 0x3ffffff;
  h4 += c;     c = h4 >> 26; h4 = h4 & 0x3ffffff;
  h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
  h1 += c;

  // Compute h + -p
  g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
  g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  g4 = h4 + c - (1 << 26);

  // Select h if h < p, or g if h >= p
  mask = (g4 >> 31) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  // h = h % (2^128) - convert back from 26-bit limbs to 32-bit words
  h0 = ((h0) | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

  // mac = (h + pad) % (2^128)
  f = (u64)h0 + ctx->pad[0]; h0 = (u32)f;
  f = (u64)h1 + ctx->pad[1] + (f >> 32); h1 = (u32)f;
  f = (u64)h2 + ctx->pad[2] + (f >> 32); h2 = (u32)f;
  f = (u64)h3 + ctx->pad[3] + (f >> 32); h3 = (u32)f;

  mac[0] = h0;
  mac[1] = h1;
  mac[2] = h2;
  mac[3] = h3;
}
