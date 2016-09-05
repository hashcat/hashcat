/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "bitops.h"

u32 is_power_of_2 (const u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 rotl32 (const u32 a, const u32 n)
{
  return ((a << n) | (a >> (32 - n)));
}

u32 rotr32 (const u32 a, const u32 n)
{
  return ((a >> n) | (a << (32 - n)));
}

u64 rotl64 (const u64 a, const u64 n)
{
  return ((a << n) | (a >> (64 - n)));
}

u64 rotr64 (const u64 a, const u64 n)
{
  return ((a >> n) | (a << (64 - n)));
}

u32 byte_swap_32 (const u32 n)
{
  return (n & 0xff000000) >> 24
       | (n & 0x00ff0000) >>  8
       | (n & 0x0000ff00) <<  8
       | (n & 0x000000ff) << 24;
}

u64 byte_swap_64 (const u64 n)
{
  return (n & 0xff00000000000000ULL) >> 56
       | (n & 0x00ff000000000000ULL) >> 40
       | (n & 0x0000ff0000000000ULL) >> 24
       | (n & 0x000000ff00000000ULL) >>  8
       | (n & 0x00000000ff000000ULL) <<  8
       | (n & 0x0000000000ff0000ULL) << 24
       | (n & 0x000000000000ff00ULL) << 40
       | (n & 0x00000000000000ffULL) << 56;
}
