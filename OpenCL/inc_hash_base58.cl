/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

/**
 * Based on bitcoin/libbase58 implementation
 * by Luke Dashjr
 * adapted by b0lek to run on GPUs as part of hashcat
 */

#include "inc_vendor.h"
#include "inc_common.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_hash_sha256.h"
#include "inc_hash_base58.h"

// (sizeof (u32) * 8):

#define B58_BITS 32

// ((((u64) 1) << B58_BITS) - 1):

#define B58_MASK 0xffffffff

CONSTANT_VK u8 B58_DIGITS_ORDERED[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

CONSTANT_VK u32 B58_DIGITS_MAP[256] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

DECLSPEC bool is_valid_base58 (PRIVATE_AS const u32 *data, PRIVATE_AS const u32 offset, PRIVATE_AS const u32 len)
{
  for (u32 i = offset; i < len; i++)
  {
    const u32 div   = (i / 4);
    const u32 shift = (i % 4) * 8;

    const u32 b = (data[div] >> shift) & 0xff;

    const u32 c = B58_DIGITS_MAP[b];

    // Invalid base58 digit

    if (c == (u32) -1) return false;
  }

  return true;
}

DECLSPEC bool b58dec (PRIVATE_AS u8 *bin, PRIVATE_AS u32 *binszp, PRIVATE_AS const u8 *b58, PRIVATE_AS const u32 b58sz)
{
  u32 binsz = *binszp;

  const u8 *b58u = (u8*) b58;
  u8 *binu       = (u8*) bin;

  u32 outisz = (binsz + sizeof (u32) - 1) / sizeof (u32);

  u32 outi[200];

  u8 bytesleft = binsz % sizeof (u32);

  u32 zero_mask = bytesleft ? (B58_MASK << (bytesleft * 8)) : 0;

  unsigned zerocount = 0;

  for (u32 i = 0; i < outisz; i++)
  {
    outi[i] = 0;
  }

  // Leading zeros, just count

  u32 i = 0;

  for (; i < b58sz && b58u[i] == '1'; i++)
  {
    ++zerocount;
  }

  for (; i < b58sz; i++)
  {
    u32 c = B58_DIGITS_MAP[b58u[i]];

    // Invalid base58 digit

    if (c == (u32) -1) return false;

    for (u32 j = outisz; j--; )
    {
      u64 t = ((u64) outi[j]) * 58 + c;

      c = t >> B58_BITS;

      outi[j] = t & B58_MASK;
    }

    // Output number too big (carry to the next int32)

    if (c != 0) return false;

    // Output number too big (last int32 filled too far)

    if (outi[0] & zero_mask) return false;
  }

  u32 j = 0;

  if (bytesleft)
  {
    for (u32 i = bytesleft; i > 0; i--)
    {
      *(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
    }

    j++;
  }

  for (; j < outisz; j++)
  {
    for (u32 i = sizeof (*outi); i > 0; i--)
    {
      *(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
    }
  }

  // Count canonical base58 byte count

  binu = (u8*) bin;

  for (u32 i = 0; i < binsz; i++)
  {
    if (binu[i]) break;

    --*binszp;
  }

  *binszp += zerocount;

  return true;
}

// special function to handle only input of 51 characters
// attention: we use BE (big endian) here as output

DECLSPEC bool b58dec_51 (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *data)
{
  // data length must be 51 and must be checked before calling the function

  for (u32 i = 0; i < 51; i++)
  {
    const u32 div   = (i / 4);
    const u32 shift = (i % 4) * 8;

    const u32 b = (data[div] >> shift) & 0xff;

    u32 c = B58_DIGITS_MAP[b];

    // checked with is_valid_base58 ():
    // if (c == (u32) -1) return false;

    // test speed with (manual or automatic) #pragma unroll

    for (u32 j = 0; j < 10; j++)
    {
      const u32 pos = 9 - j;

      const u64 t = ((u64) out[pos]) * 58 + c;

      c = t >> 32; // upper u32

      out[pos] = t; // lower u32 (& 0xffffffff)
    }
  }


  // fix byte alignment:
  // #pragma unroll

  for (u32 i = 0; i < 10; i++) // offset of: 3 bytes
  {
    out[i] = (out[i + 0] << 24) | (out[i + 1] >> 8);
  }

  return true;
}

// special function to handle only input of 52 characters
// attention: we use BE (big endian) here as output

DECLSPEC bool b58dec_52 (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *data)
{
  // data length must be 52 and must be checked before calling the function

  for (u32 i = 0; i < 52; i++)
  {
    const u32 div   = (i / 4);
    const u32 shift = (i % 4) * 8;

    const u32 b = (data[div] >> shift) & 0xff;

    u32 c = B58_DIGITS_MAP[b];

    // checked with is_valid_base58 ():
    // if (c == (u32) -1) return false;

    // test speed with (manual or automatic) #pragma unroll

    for (u32 j = 0; j < 10; j++)
    {
      const u32 pos = 9 - j;

      const u64 t = ((u64) out[pos]) * 58 + c;

      c = t >> 32; // upper u32

      out[pos] = t; // lower u32 (& 0xffffffff)
    }
  }


  // fix byte alignment:
  // #pragma unroll

  for (u32 i = 0; i < 10; i++) // offset of: 2 bytes
  {
    out[i] = (out[i + 0] << 16) | (out[i + 1] >> 16);
  }

  return true;
}

// maximum 256 bytes as input, mininum 4 bytes (checksum)

DECLSPEC bool b58check (PRIVATE_AS const u8 *bin, PRIVATE_AS const u32 binsz)
{
  u32 data[64] = { 0 }; // 64 * 4 = 256 bytes (should be enough)

  u8 *datac = (u8*) data;
  u8 *binc  = (u8*) bin;

  if (binsz <   4) return false;
  if (binsz > 256) return false;

  for (u32 i = 0; i < binsz - 4; i++)
  {
    datac[i] = binc[i];
  }

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, data, binsz-4);
  sha256_final       (&ctx);

  for (u32 i = 0; i < 8; i++) // 32 / 4
  {
    data[i] = ctx.h[i];
  }

  for (u32 i = 8; i < 16; i++) // clear bytes: needed for sha256_update ()
  {
    data[i] = 0;
  }

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 32);
  sha256_final  (&ctx);

  ctx.h[0] = hc_swap32_S (ctx.h[0]);

  u8 * ph4 = (u8*) ctx.h;
  u8 * sum = (u8*) (binc + (binsz - 4)); // offset: binsz - 4, last 4 bytes

  if (ph4[0] != sum[0]) return false;
  if (ph4[1] != sum[1]) return false;
  if (ph4[2] != sum[2]) return false;
  if (ph4[3] != sum[3]) return false;

  return true;
}

// ATTENTION: this function expects a 64 byte data buffer, containing the checksum after the data

DECLSPEC bool b58check64 (PRIVATE_AS const u32 *bin, PRIVATE_AS const u32 binsz)
{
  if (binsz < 4) return false;
  // if (binsz > 63) return false;

  u32 data[16] = { 0 };

  for (u32 i = 0; i < 15; i++) data[i] = bin[i];

  const u32 div = binsz / 4;
  const u32 mod = binsz % 4;

  data[div] = 0;

  switch (mod)
  {
    case 0:
      data[div - 1] &= 0x00000000;
      break;
    case 1:
      data[div - 1] &= 0x000000ff;
      break;
    case 2:
      data[div - 1] &= 0x0000ffff;
      break;
    case 3:
      data[div - 1] &= 0x00ffffff;
      break;
  }

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, data, binsz - 4);
  sha256_final       (&ctx);

  data[ 0] = ctx.h[0];
  data[ 1] = ctx.h[1];
  data[ 2] = ctx.h[2];
  data[ 3] = ctx.h[3];
  data[ 4] = ctx.h[4];
  data[ 5] = ctx.h[5];
  data[ 6] = ctx.h[6];
  data[ 7] = ctx.h[7];

  data[ 8] = 0;
  data[ 9] = 0;
  data[10] = 0;
  data[11] = 0;
  data[12] = 0;
  data[13] = 0;
  data[14] = 0;
  data[15] = 0;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 32);
  sha256_final  (&ctx);

  const u32 ph4 = hc_swap32_S (ctx.h[0]);

  u32 checksum = 0;

  switch (mod)
  {
    case 0:
      checksum =                    (bin[div - 1] >>  0);
      break;
    case 1:
      checksum = (bin[div] << 24) | (bin[div - 1] >>  8);
      break;
    case 2:
      checksum = (bin[div] << 16) | (bin[div - 1] >> 16);
      break;
    case 3:
      checksum = (bin[div] <<  8) | (bin[div - 1] >> 24);
      break;
  }

  return (ph4 == checksum);
}

// optimized for 21 + 4 input bytes in buffer "bin"

DECLSPEC bool b58check_25 (PRIVATE_AS const u32 *bin)
{
  u32 data[16] = { 0 };

  // for (u32 i = 0; i < 6; i++) data[i] = bin[i];

  data[0] = bin[0];
  data[1] = bin[1];
  data[2] = bin[2];
  data[3] = bin[3];
  data[4] = bin[4];
  data[5] = bin[5];

  data[5] &= 0x000000ff;

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, data, 21);
  sha256_final       (&ctx);

  data[ 0] = ctx.h[0];
  data[ 1] = ctx.h[1];
  data[ 2] = ctx.h[2];
  data[ 3] = ctx.h[3];
  data[ 4] = ctx.h[4];
  data[ 5] = ctx.h[5];
  data[ 6] = ctx.h[6];
  data[ 7] = ctx.h[7];

  data[ 8] = 0;
  data[ 9] = 0;
  data[10] = 0;
  data[11] = 0;
  data[12] = 0;
  data[13] = 0;
  data[14] = 0;
  data[15] = 0;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 32);
  sha256_final  (&ctx);

  const u32 ph4 = hc_swap32_S (ctx.h[0]);

  const u32 checksum = (bin[6] << 24) | (bin[5] >> 8);

  return (ph4 == checksum);
}

// optimized for 33 + 4 input bytes in buffer "bin"
// attention: we use BE (big endian) here as input

DECLSPEC bool b58check_37 (PRIVATE_AS const u32 *bin)
{
  u32 data[16] = { 0 };

  // for (u32 i = 0; i < 9; i++) data[i] = bin[i];

  data[0] = bin[0];
  data[1] = bin[1];
  data[2] = bin[2];
  data[3] = bin[3];
  data[4] = bin[4];
  data[5] = bin[5];
  data[6] = bin[6];
  data[7] = bin[7];
  data[8] = bin[8];

  data[8] &= 0xff000000;

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 33);
  sha256_final  (&ctx);

  data[ 0] = ctx.h[0];
  data[ 1] = ctx.h[1];
  data[ 2] = ctx.h[2];
  data[ 3] = ctx.h[3];
  data[ 4] = ctx.h[4];
  data[ 5] = ctx.h[5];
  data[ 6] = ctx.h[6];
  data[ 7] = ctx.h[7];

  data[ 8] = 0;
  data[ 9] = 0;
  data[10] = 0;
  data[11] = 0;
  data[12] = 0;
  data[13] = 0;
  data[14] = 0;
  data[15] = 0;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 32);
  sha256_final  (&ctx);

  const u32 ph4 = ctx.h[0];

  const u32 checksum = (bin[8] << 8) | (bin[9] >> 24);

  return (ph4 == checksum);
}

// optimized for 34 + 4 input bytes in buffer "bin"
// attention: we use BE (big endian) here as input

DECLSPEC bool b58check_38 (PRIVATE_AS const u32 *bin)
{
  u32 data[16] = { 0 };

  // for (u32 i = 0; i < 9; i++) data[i] = bin[i];

  data[0] = bin[0];
  data[1] = bin[1];
  data[2] = bin[2];
  data[3] = bin[3];
  data[4] = bin[4];
  data[5] = bin[5];
  data[6] = bin[6];
  data[7] = bin[7];
  data[8] = bin[8];

  data[8] &= 0xffff0000;

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 34);
  sha256_final  (&ctx);

  data[ 0] = ctx.h[0];
  data[ 1] = ctx.h[1];
  data[ 2] = ctx.h[2];
  data[ 3] = ctx.h[3];
  data[ 4] = ctx.h[4];
  data[ 5] = ctx.h[5];
  data[ 6] = ctx.h[6];
  data[ 7] = ctx.h[7];

  data[ 8] = 0;
  data[ 9] = 0;
  data[10] = 0;
  data[11] = 0;
  data[12] = 0;
  data[13] = 0;
  data[14] = 0;
  data[15] = 0;

  sha256_init   (&ctx);
  sha256_update (&ctx, data, 32);
  sha256_final  (&ctx);

  const u32 ph4 = ctx.h[0];

  const u32 checksum = (bin[8] << 16) | (bin[9] >> 16);

  return (ph4 == checksum);
}

DECLSPEC bool b58enc (PRIVATE_AS u8 *b58, PRIVATE_AS u32 *b58sz, PRIVATE_AS const u8 *data, PRIVATE_AS const u32 binsz)
{
  const u8 *bin = (u8 *) data;
  int carry;
  u32 j      = 0;
  u32 zcount = 0;

  while (zcount < binsz && !bin[zcount]) ++zcount;

  u32 size = (binsz - zcount) * 138 / 100 + 1;

  u8 buf[200] = { 0 };

  u32 i    = zcount;
  u32 high = size - 1;

  for (; i < binsz; i++, high = j)
  {
    for (carry = bin[i], j = size - 1; (j > high) || carry; j--)
    {
      carry += 256 * buf[j];

      buf[j] = carry % 58;

      carry /= 58;

      if (! j) break;
    }
  }

  j = 0;

  for (; j < (size && !buf[j]); j++) {}

  if (*b58sz <= zcount + size - j)
  {
    *b58sz = zcount + size - j + 1;

    return false;
  }

  for (u32 i = 0; i < zcount; i++)
  {
    b58[i] = '1';
  }

  for (i = zcount; j < size; i++, j++)
  {
    b58[i] = B58_DIGITS_ORDERED[buf[j]];
  }

  b58[i] = '\0';

  *b58sz = i + 1;

  return true;
}

DECLSPEC bool b58check_enc (PRIVATE_AS u8 *b58c, PRIVATE_AS u32 *b58c_sz, PRIVATE_AS const u8 ver, PRIVATE_AS const u8 *data, PRIVATE_AS const u32 datasz)
{
  u8   buf[128] = { 0 };

  u32 *buf32 = (u32*) buf;
  u8  *data8 = (u8 *) data;

  u8  *hash  = &buf[1 + datasz];

  buf[0] = ver;

  for (u32 i = 0; i < datasz; i++)
  {
    buf[i + 1] = data8[i];
  }

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, buf32, datasz + 1);
  sha256_final       (&ctx);

  u32 data1[128] = { 0 };

  for (u32 i = 0; i < 0x20; i++)
  {
    ((u8*) data1)[i] = ((u8*) ctx.h)[i];
  }

  sha256_init   (&ctx);
  sha256_update (&ctx, data1, 0x20);
  sha256_final  (&ctx);

  ctx.h[0] = hc_swap32_S (ctx.h[0]);

  for (u32 i = 0; i < 4; i++)
  {
    ((u8 *) hash)[i] = ((u8 *) ctx.h)[i];
  }

  return b58enc (b58c, b58c_sz, buf, 1 + datasz + 4);
}
