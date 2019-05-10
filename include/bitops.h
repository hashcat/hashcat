/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BITOPS_H
#define _BITOPS_H

u32 rotl32  (const u32 a, const int n);
u32 rotr32  (const u32 a, const int n);
u64 rotl64  (const u64 a, const int n);
u64 rotr64  (const u64 a, const int n);

u16 byte_swap_16  (const u16 n);
u32 byte_swap_32  (const u32 n);
u64 byte_swap_64  (const u64 n);

#endif // _BITOPS_H
