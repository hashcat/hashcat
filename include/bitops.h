/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BITOPS_H
#define HC_BITOPS_H

HC_PLUGIN_API u32 rotl32  (const u32 a, const int n);
HC_PLUGIN_API u32 rotr32  (const u32 a, const int n);
HC_PLUGIN_API u64 rotl64  (const u64 a, const int n);
HC_PLUGIN_API u64 rotr64  (const u64 a, const int n);

HC_PLUGIN_API u16 byte_swap_16  (const u16 n);
HC_PLUGIN_API u32 byte_swap_32  (const u32 n);
HC_PLUGIN_API u64 byte_swap_64  (const u64 n);

#endif // HC_BITOPS_H
