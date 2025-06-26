/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_rp_common.h"

CONSTANT_VK u8 s_lookup[128] =
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

DECLSPEC bool is_l (u8 c)
{
  return (c >= 'a' && c <= 'z');
}

DECLSPEC bool is_u (u8 c)
{
  return (c >= 'A' && c <= 'Z');
}

DECLSPEC bool is_d (u8 c)
{
  return (c >= '0' && c <= '9');
}

DECLSPEC bool is_lh (u8 c)
{
  return (is_d (c) || (c >= 'a' && c <= 'f'));
}

DECLSPEC bool is_uh (u8 c)
{
  return (is_d (c) || (c >= 'A' && c <= 'F'));
}

DECLSPEC bool is_s (u8 c)
{
  return s_lookup[c] == 1;
}

DECLSPEC u32 generate_cmask (const u32 value)
{
  const u32 rmask =  ((value & 0x40404040u) >> 1u)
                  & ~((value & 0x80808080u) >> 2u);

  const u32 hmask = (value & 0x1f1f1f1fu) + 0x05050505u;
  const u32 lmask = (value & 0x1f1f1f1fu) + 0x1f1f1f1fu;

  return rmask & ~hmask & lmask;
}
