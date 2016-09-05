/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

#define swap_workaround(n) __builtin_bswap32(n)

u32 apply_rule (const u32 name, const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len);
u32 apply_rules (u32 *cmds, u32 buf0[4], u32 buf1[4], const u32 len);
