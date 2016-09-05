/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

u32 is_power_of_2 (const u32 v);

u32 rotl32 (const u32 a, const u32 n);
u32 rotr32 (const u32 a, const u32 n);
u64 rotl64 (const u64 a, const u64 n);
u64 rotr64 (const u64 a, const u64 n);

u32 byte_swap_32 (const u32 n);
u64 byte_swap_64 (const u64 n);
