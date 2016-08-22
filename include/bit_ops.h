#pragma once
#include "common.h"
/**
* basic bit handling
*/
u32 is_power_of_2(u32 v);
inline u32 is_power_of_2(u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 rotl32(const u32 a, const u32 n);
inline u32 rotl32(const u32 a, const u32 n)
{
#ifdef _MSC_VER
  return _rotl(a, n);
#else
  return ((a << n) | (a >> (32 - n)));
#endif
}

u32 rotr32(const u32 a, const u32 n);
inline u32 rotr32(const u32 a, const u32 n)
{
#ifdef _MSC_VER
  return _rotr(a, n);
#else
  return ((a >> n) | (a << (32 - n)));
#endif
}

u64 rotl64(const u64 a, const u64 n);
inline u64 rotl64(const u64 a, const u64 n)
{
#ifdef _MSC_VER
  return _rotl64(a, n);
#else
  return ((a << n) | (a >> (64 - n)));
#endif
}

u64 rotr64(const u64 a, const u64 n);
inline u64 rotr64(const u64 a, const u64 n)
{
#ifdef _MSC_VER
  return _rotr64(a,n);
#else
  return  ((a >> n) | (a << (64 - n)));
#endif
}

u32 byte_swap_32(const u32 n);
inline u32 byte_swap_32(const u32 n)
{
#ifdef _MSC_VER
  return _byteswap_ulong(n);
#elif defined(__GNU_C__) || defined(__MINGW32__)
  return _builtin_bswap32(n);
#else
  return (n & 0xff000000) >> 24
    | (n & 0x00ff0000) >> 8
    | (n & 0x0000ff00) << 8
    | (n & 0x000000ff) << 24;
#endif
}

u64 byte_swap_64(const u64 n);
inline u64 byte_swap_64(const u64 n)
{
#ifdef _MSC_VER
  return _byteswap_uint64(n);
#elif defined(__GNU_C__) || defined(__MINGW32__)
  return _builtin_bswap64(n);
#else
  return (n & 0xff00000000000000ULL) >> 56
    | (n & 0x00ff000000000000ULL) >> 40
    | (n & 0x0000ff0000000000ULL) >> 24
    | (n & 0x000000ff00000000ULL) >> 8
    | (n & 0x00000000ff000000ULL) << 8
    | (n & 0x0000000000ff0000ULL) << 24
    | (n & 0x000000000000ff00ULL) << 40
    | (n & 0x00000000000000ffULL) << 56;
#endif
}
