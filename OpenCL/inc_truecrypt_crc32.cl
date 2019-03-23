/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_truecrypt_crc32.h"

DECLSPEC u32 round_crc32 (u32 a, const u32 v)
{
  const u32 k = (a ^ v) & 0xff;

  const u32 s = a >> 8;

  a = crc32tab[k];

  a ^= s;

  return a;
}

DECLSPEC u32 round_crc32_4 (const u32 w, const u32 iv)
{
  u32 a = iv;

  a = round_crc32 (a, w >>  0);
  a = round_crc32 (a, w >>  8);
  a = round_crc32 (a, w >> 16);
  a = round_crc32 (a, w >> 24);

  return a;
}
