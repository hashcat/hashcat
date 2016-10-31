/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BITOPS_H
#define _BITOPS_H

u32 rotl32 (const u32 a, const u32 n) __attribute__ ((const));
u32 rotr32 (const u32 a, const u32 n) __attribute__ ((const));
u64 rotl64 (const u64 a, const u64 n) __attribute__ ((const));
u64 rotr64 (const u64 a, const u64 n) __attribute__ ((const));

u32 byte_swap_32 (const u32 n) __attribute__ ((const));
u64 byte_swap_64 (const u64 n) __attribute__ ((const));

#endif // _BITOPS_H
