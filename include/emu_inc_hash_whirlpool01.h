/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_WHIRLPOOL01_H
#define HC_EMU_INC_HASH_WHIRLPOOL01_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_whirlpool01.h"

// The tables from inc_hash_whirlpool01.cl. The host passes these tables to whirlpool01_init (). A
// kernel passes its copy in shared memory where it makes one, or else the tables themselves.

extern u64a whirlpool01_t0[2][256];

#endif // HC_EMU_INC_HASH_WHIRLPOOL01_H
