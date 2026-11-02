/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_rp_common.h"

#ifdef HC_CPU_OPENCL_EMU_H
#undef DECLSPEC
#define DECLSPEC static
#endif

CONSTANT_VK static u8 s_lookup[128] =
{
  // 0-31: control characters (0)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // 32: whitespace (1)
  1,
  // 33-47: punctuation (1)
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  // 48-57: digits (0)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // 58-64: punctuation (1)
  1, 1, 1, 1, 1, 1, 1,
  // 65-90: uppercase letters (0)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // 91-96: punctuation (1)
  1, 1, 1, 1, 1, 1,
  // 97-122: lowercase letters (0)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // 123-126: punctuation (1)
  1, 1, 1, 1,
  // 127: DEL (0)
  0
};

CONSTANT_VK static u8 cshift_lookup[256] =
{
  // 0-32:
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // 33-126:
  16, 5, 16, 16, 16, 17, 5, 17, 25, 18, 22, 16, 114, 16, 16, 25, 16, 114, 16, 16, 16, 104, 17, 18, 17, 1, 1, 16, 22, 16, 16, 114, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 104, 114, 30, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 30,
  // 127-255:
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

DECLSPEC MAYBE_UNUSED bool is_l (u8 c)
{
  return (c >= 'a' && c <= 'z');
}

DECLSPEC MAYBE_UNUSED bool is_u (u8 c)
{
  return (c >= 'A' && c <= 'Z');
}

DECLSPEC MAYBE_UNUSED bool is_d (u8 c)
{
  return (c >= '0' && c <= '9');
}

DECLSPEC MAYBE_UNUSED bool is_lh (u8 c)
{
  return (is_d (c) || (c >= 'a' && c <= 'f'));
}

DECLSPEC MAYBE_UNUSED bool is_uh (u8 c)
{
  return (is_d (c) || (c >= 'A' && c <= 'F'));
}

DECLSPEC MAYBE_UNUSED bool is_s (u8 c)
{
  return s_lookup[c] == 1;
}

DECLSPEC MAYBE_UNUSED u32 generate_cmask (const u32 value)
{
  const u32 rmask =  ((value & 0x40404040u) >> 1u)
                  & ~((value & 0x80808080u) >> 2u);

  const u32 hmask = (value & 0x1f1f1f1fu) + 0x05050505u;
  const u32 lmask = (value & 0x1f1f1f1fu) + 0x1f1f1f1fu;

  return rmask & ~hmask & lmask;
}

DECLSPEC MAYBE_UNUSED u32 generate_cshift_mask (const u32 value)
{
  const u32 mask = (((u32) cshift_lookup[(value >> 24) & 0xff]) << 24) |
                   (((u32) cshift_lookup[(value >> 16) & 0xff]) << 16) |
                   (((u32) cshift_lookup[(value >>  8) & 0xff]) <<  8) |
                   (((u32) cshift_lookup[(value >>  0) & 0xff]) <<  0);

  return mask;
}

#ifdef HC_CPU_OPENCL_EMU_H
#undef DECLSPEC
#define DECLSPEC
#endif
