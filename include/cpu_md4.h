/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_MD4_H
#define _CPU_MD4_H

#include <string.h>

void md4_64 (const u32 block[16], u32 digest[4]);

#endif // _CPU_MD4_H
