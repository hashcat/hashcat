#pragma once
/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef RP_CPU_H
#define RP_CPU_H

#ifdef _MSC_VER
u32 swap_workaround(const u32 n);
inline u32 swap_workaround(const u32 n)
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

#include "common.h"
#include "inc_rp.h"

u32 apply_rule(const u32 name, const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len);
u32 apply_rules(u32 *cmds, u32 buf0[4], u32 buf1[4], const u32 len);

#endif
