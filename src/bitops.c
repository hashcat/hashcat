/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"

u32 rotl32 (const u32 a, const int n)
{
  #if defined (_MSC_VER)
  return _rotl (a, n);
  #else
  return ((a << n) | (a >> (32 - n)));
  #endif
}

u32 rotr32 (const u32 a, const int n)
{
  #if defined (_MSC_VER)
  return _rotr (a, n);
  #else
  return ((a >> n) | (a << (32 - n)));
  #endif
}

u64 rotl64 (const u64 a, const int n)
{
  #if defined (_MSC_VER)
  return _rotl64 (a, n);
  #else
  return ((a << n) | (a >> (64 - n)));
  #endif
}

u64 rotr64 (const u64 a, const int n)
{
  #if defined (_MSC_VER)
  return _rotr64 (a, n);
  #else
  return ((a >> n) | (a << (64 - n)));
  #endif
}

u16 byte_swap_16 (const u16 n)
{
  return (u16) ((n >> 8) | (n << 8));
}

u32 byte_swap_32 (const u32 n)
{
  #if defined (_MSC_VER)
  return _byteswap_ulong (n);
  #elif defined (__clang__) || defined (__GNUC__)
  return __builtin_bswap32 (n);
  #else
  return (n & 0xff000000) >> 24
       | (n & 0x00ff0000) >>  8
       | (n & 0x0000ff00) <<  8
       | (n & 0x000000ff) << 24;
  #endif
}

u64 byte_swap_64 (const u64 n)
{
  #if defined (_MSC_VER)
  return _byteswap_uint64 (n);
  #elif defined (__clang__) || defined (__GNUC__)
  return __builtin_bswap64 (n);
  #else
  return (n & 0xff00000000000000ULL) >> 56
       | (n & 0x00ff000000000000ULL) >> 40
       | (n & 0x0000ff0000000000ULL) >> 24
       | (n & 0x000000ff00000000ULL) >>  8
       | (n & 0x00000000ff000000ULL) <<  8
       | (n & 0x0000000000ff0000ULL) << 24
       | (n & 0x000000000000ff00ULL) << 40
       | (n & 0x00000000000000ffULL) << 56;
  #endif
}
