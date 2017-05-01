/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_BLAKE2_H
#define _CPU_BLAKE2_H

#include <string.h>

const u64 blake2b_IV[8] =
{
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

#endif // _CPU_BLAKE2_H
