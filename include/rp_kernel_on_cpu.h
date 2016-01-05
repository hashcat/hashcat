/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef RP_CPU_H
#define RP_CPU_H

#define swap_workaround(n) __builtin_bswap32(n)

#include "common.h"
#include "rp_kernel.h"

uint apply_rule (const uint name, const uint p0, const uint p1, uint32_t buf0[4], uint32_t buf1[4], const uint in_len);
uint apply_rules (uint *cmds, uint32_t buf0[4], uint32_t buf1[4], const uint len);

#endif
