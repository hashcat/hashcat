/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct eternl
{
    u32 salt_buf[64]; // Match pbkdf2_sha512_t format - only first 8 u32 used (32 bytes)
    u32 nonce[3]; // 12 bytes
    u32 tag[4];   // 16 bytes
    u32 encrypted[42]; // 165 bytes
} eternl_t;

typedef struct pbkdf2_sha512_tmp
{
    u64 ipad[8];
    u64 opad[8];
    u64 dgst[16];
    u64 out[16];
} pbkdf2_sha512_tmp_t;

// ChaCha20 Block Function (Scalar)
DECLSPEC void chacha20_block (PRIVATE_AS u32 *state, PRIVATE_AS u32 *out)
{
  u32 x[16];
  for (int i = 0; i < 16; i++) x[i] = state[i];

  for (int i = 0; i < 10; i++)
  {
    // Quarter round 1
    x[0] += x[4]; x[12] = hc_rotl32(x[12] ^ x[0], 16);
    x[8] += x[12]; x[4] = hc_rotl32(x[4] ^ x[8], 12);
    x[0] += x[4]; x[12] = hc_rotl32(x[12] ^ x[0], 8);
    x[8] += x[12]; x[4] = hc_rotl32(x[4] ^ x[8], 7);

    // Quarter round 2
    x[1] += x[5]; x[13] = hc_rotl32(x[13] ^ x[1], 16);
    x[9] += x[13]; x[5] = hc_rotl32(x[5] ^ x[9], 12);
    x[1] += x[5]; x[13] = hc_rotl32(x[13] ^ x[1], 8);
    x[9] += x[13]; x[5] = hc_rotl32(x[5] ^ x[9], 7);

    // Quarter round 3
    x[2] += x[6]; x[14] = hc_rotl32(x[14] ^ x[2], 16);
    x[10] += x[14]; x[6] = hc_rotl32(x[6] ^ x[10], 12);
    x[2] += x[6]; x[14] = hc_rotl32(x[14] ^ x[2], 8);
    x[10] += x[14]; x[6] = hc_rotl32(x[6] ^ x[10], 7);

    // Quarter round 4
    x[3] += x[7]; x[15] = hc_rotl32(x[15] ^ x[3], 16);
    x[11] += x[15]; x[7] = hc_rotl32(x[7] ^ x[11], 12);
    x[3] += x[7]; x[15] = hc_rotl32(x[15] ^ x[3], 8);
    x[11] += x[15]; x[7] = hc_rotl32(x[7] ^ x[11], 7);

    // Diagonal round 1
    x[0] += x[5]; x[15] = hc_rotl32(x[15] ^ x[0], 16);
    x[10] += x[15]; x[5] = hc_rotl32(x[5] ^ x[10], 12);
    x[0] += x[5]; x[15] = hc_rotl32(x[15] ^ x[0], 8);
    x[10] += x[15]; x[5] = hc_rotl32(x[5] ^ x[10], 7);

    // Diagonal round 2
    x[1] += x[6]; x[12] = hc_rotl32(x[12] ^ x[1], 16);
    x[11] += x[12]; x[6] = hc_rotl32(x[6] ^ x[11], 12);
    x[1] += x[6]; x[12] = hc_rotl32(x[12] ^ x[1], 8);
    x[11] += x[12]; x[6] = hc_rotl32(x[6] ^ x[11], 7);

    // Diagonal round 3
    x[2] += x[7]; x[13] = hc_rotl32(x[13] ^ x[2], 16);
    x[8] += x[13]; x[7] = hc_rotl32(x[7] ^ x[8], 12);
    x[2] += x[7]; x[13] = hc_rotl32(x[13] ^ x[2], 8);
    x[8] += x[13]; x[7] = hc_rotl32(x[7] ^ x[8], 7);

    // Diagonal round 4
    x[3] += x[4]; x[14] = hc_rotl32(x[14] ^ x[3], 16);
    x[9] += x[14]; x[4] = hc_rotl32(x[4] ^ x[9], 12);
    x[3] += x[4]; x[14] = hc_rotl32(x[14] ^ x[3], 8);
    x[9] += x[14]; x[4] = hc_rotl32(x[4] ^ x[9], 7);
  }

  for (int i = 0; i < 16; i++) out[i] = x[i] + state[i];
}

// Poly1305 Implementation
// Poly1305 using 26-bit limbs (stored in 32-bit values)
// Based on poly1305-donna for correctness
typedef struct poly1305_ctx
{
  u32 r[5];  // 26-bit limbs for r
  u32 h[5];  // 26-bit limbs for accumulator
  u32 pad[4]; // 32-bit padding values
  u32 buffer[4];
  u32 buffer_left;
} poly1305_ctx_t;

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
    const u8 *m_byte = (const u8 *)m;

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

DECLSPEC void poly1305_final (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS u8 *mac)
{
  u32 h0, h1, h2, h3, h4, c;
  u32 g0, g1, g2, g3, g4;
  u64 f;
  u32 mask;

  // Process remaining buffer
  if (ctx->buffer_left > 0)
  {
    const u8 *msg = (const u8 *)ctx->buffer;
    u32 hibit = (ctx->buffer_left == 16) ? 0x01000000 : 0;
    
    // Pad the message
    ((u8*)ctx->buffer)[ctx->buffer_left] = 1;
    ctx->buffer_left++;
    while (ctx->buffer_left < 16)
    {
      ((u8*)ctx->buffer)[ctx->buffer_left++] = 0;
    }
    
    msg = (const u8 *)ctx->buffer;
    
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

  ((u32*)mac)[0] = h0;
  ((u32*)mac)[1] = h1;
  ((u32*)mac)[2] = h2;
  ((u32*)mac)[3] = h3;
}

DECLSPEC void poly1305_key_gen (PRIVATE_AS u32 *key, PRIVATE_AS u32 *nonce, PRIVATE_AS u32 *poly_key)
{
    u32 state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    state[4] = key[0];
    state[5] = key[1];
    state[6] = key[2];
    state[7] = key[3];
    state[8] = key[4];
    state[9] = key[5];
    state[10] = key[6];
    state[11] = key[7];

    state[12] = 0; // Counter
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    u32 out[16];
    chacha20_block(state, out);

    poly_key[0] = out[0];
    poly_key[1] = out[1];
    poly_key[2] = out[2];
    poly_key[3] = out[3];
    poly_key[4] = out[4];
    poly_key[5] = out[5];
    poly_key[6] = out[6];
    poly_key[7] = out[7];
}

CONSTANT_VK u32 block_idx_be[1] = { 0x01000000 };

KERNEL_FQ KERNEL_FA void m01852_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, eternl_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha512_hmac_ctx.opad.h[7];

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // For Eternl we only need block 1 (first 64 bytes of PBKDF2 output)
  // Copy context after salt update, then add block index
  sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;
  
  // Append block index as u32 array like m07100
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];
  
  w0[0] = 1;  // Block index 1
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;
  
  sha512_hmac_update_128 (&sha512_hmac_ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&sha512_hmac_ctx2);

  tmps[gid].dgst[0] = sha512_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha512_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha512_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha512_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha512_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha512_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha512_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha512_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ KERNEL_FA void m01852_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, eternl_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u64 ipad[8];
  u64 opad[8];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];
  ipad[5] = tmps[gid].ipad[5];
  ipad[6] = tmps[gid].ipad[6];
  ipad[7] = tmps[gid].ipad[7];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];
  opad[5] = tmps[gid].opad[5];
  opad[6] = tmps[gid].opad[6];
  opad[7] = tmps[gid].opad[7];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    w0[0] = h32_from_64_S (tmps[gid].dgst[0]);
    w0[1] = l32_from_64_S (tmps[gid].dgst[0]);
    w0[2] = h32_from_64_S (tmps[gid].dgst[1]);
    w0[3] = l32_from_64_S (tmps[gid].dgst[1]);
    w1[0] = h32_from_64_S (tmps[gid].dgst[2]);
    w1[1] = l32_from_64_S (tmps[gid].dgst[2]);
    w1[2] = h32_from_64_S (tmps[gid].dgst[3]);
    w1[3] = l32_from_64_S (tmps[gid].dgst[3]);
    w2[0] = h32_from_64_S (tmps[gid].dgst[4]);
    w2[1] = l32_from_64_S (tmps[gid].dgst[4]);
    w2[2] = h32_from_64_S (tmps[gid].dgst[5]);
    w2[3] = l32_from_64_S (tmps[gid].dgst[5]);
    w3[0] = h32_from_64_S (tmps[gid].dgst[6]);
    w3[1] = l32_from_64_S (tmps[gid].dgst[6]);
    w3[2] = h32_from_64_S (tmps[gid].dgst[7]);
    w3[3] = l32_from_64_S (tmps[gid].dgst[7]);
    w4[0] = 0x80000000;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = (128 + 64) * 8;

    u64 dgst[8];
    
    dgst[0] = ipad[0];
    dgst[1] = ipad[1];
    dgst[2] = ipad[2];
    dgst[3] = ipad[3];
    dgst[4] = ipad[4];
    dgst[5] = ipad[5];
    dgst[6] = ipad[6];
    dgst[7] = ipad[7];

    sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, dgst);

    w0[0] = h32_from_64_S (dgst[0]);
    w0[1] = l32_from_64_S (dgst[0]);
    w0[2] = h32_from_64_S (dgst[1]);
    w0[3] = l32_from_64_S (dgst[1]);
    w1[0] = h32_from_64_S (dgst[2]);
    w1[1] = l32_from_64_S (dgst[2]);
    w1[2] = h32_from_64_S (dgst[3]);
    w1[3] = l32_from_64_S (dgst[3]);
    w2[0] = h32_from_64_S (dgst[4]);
    w2[1] = l32_from_64_S (dgst[4]);
    w2[2] = h32_from_64_S (dgst[5]);
    w2[3] = l32_from_64_S (dgst[5]);
    w3[0] = h32_from_64_S (dgst[6]);
    w3[1] = l32_from_64_S (dgst[6]);
    w3[2] = h32_from_64_S (dgst[7]);
    w3[3] = l32_from_64_S (dgst[7]);

    dgst[0] = opad[0];
    dgst[1] = opad[1];
    dgst[2] = opad[2];
    dgst[3] = opad[3];
    dgst[4] = opad[4];
    dgst[5] = opad[5];
    dgst[6] = opad[6];
    dgst[7] = opad[7];

    sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, dgst);

    tmps[gid].dgst[0] = dgst[0];
    tmps[gid].dgst[1] = dgst[1];
    tmps[gid].dgst[2] = dgst[2];
    tmps[gid].dgst[3] = dgst[3];
    tmps[gid].dgst[4] = dgst[4];
    tmps[gid].dgst[5] = dgst[5];
    tmps[gid].dgst[6] = dgst[6];
    tmps[gid].dgst[7] = dgst[7];

    tmps[gid].out[0] ^= tmps[gid].dgst[0];
    tmps[gid].out[1] ^= tmps[gid].dgst[1];
    tmps[gid].out[2] ^= tmps[gid].dgst[2];
    tmps[gid].out[3] ^= tmps[gid].dgst[3];
    tmps[gid].out[4] ^= tmps[gid].dgst[4];
    tmps[gid].out[5] ^= tmps[gid].dgst[5];
    tmps[gid].out[6] ^= tmps[gid].dgst[6];
    tmps[gid].out[7] ^= tmps[gid].dgst[7];
  }
}

KERNEL_FQ void m01852_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, eternl_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 encrypted_len = 165;

  // Convert PBKDF2 output to ChaCha20 key
  // PBKDF2-SHA512 stores output as big-endian u64 values
  // ChaCha20 expects little-endian u32 values
  // We need to byteswap the extracted u32 values
  u32 key[8];
  key[0] = hc_swap32_S(h32_from_64_S(tmps[gid].out[0]));
  key[1] = hc_swap32_S(l32_from_64_S(tmps[gid].out[0]));
  key[2] = hc_swap32_S(h32_from_64_S(tmps[gid].out[1]));
  key[3] = hc_swap32_S(l32_from_64_S(tmps[gid].out[1]));
  key[4] = hc_swap32_S(h32_from_64_S(tmps[gid].out[2]));
  key[5] = hc_swap32_S(l32_from_64_S(tmps[gid].out[2]));
  key[6] = hc_swap32_S(h32_from_64_S(tmps[gid].out[3]));
  key[7] = hc_swap32_S(l32_from_64_S(tmps[gid].out[3]));

  // ChaCha20Poly1305 decryption
  u32 nonce[3];
  nonce[0] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[0];
  nonce[1] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[1];
  nonce[2] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[2];

  // Get poly1305 key
  u32 poly1305_key[8];
  poly1305_key_gen(key, nonce, poly1305_key);

  // Decrypt and verify
  u8 mac_buffer[16];
  poly1305_ctx_t poly1305_ctx;
  poly1305_init(&poly1305_ctx, poly1305_key);

  // AAD (none)

  // Ciphertext
  poly1305_update_global(&poly1305_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].encrypted, encrypted_len);
  poly1305_update_pad(&poly1305_ctx, encrypted_len);

  // Lengths (as per RFC 8439 Section 2.8)
  // aad_len (64-bit LE) || ciphertext_len (64-bit LE)
  u32 lens[4];
  lens[0] = 0;  // AAD length low 32 bits
  lens[1] = 0;  // AAD length high 32 bits  
  lens[2] = encrypted_len;  // Ciphertext length low 32 bits
  lens[3] = 0;  // Ciphertext length high 32 bits
  poly1305_update_private(&poly1305_ctx, lens, 16);

  poly1305_final(&poly1305_ctx, mac_buffer);

  // Extract MAC as u32 values for comparison
  const u32 r0 = ((u32*)mac_buffer)[0];
  const u32 r1 = ((u32*)mac_buffer)[1];
  const u32 r2 = ((u32*)mac_buffer)[2];
  const u32 r3 = ((u32*)mac_buffer)[3];

  // Load expected digest for comparison
  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_S
  #endif
}
