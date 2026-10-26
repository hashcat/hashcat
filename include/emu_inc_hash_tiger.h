/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_TIGER_H
#define HC_EMU_INC_HASH_TIGER_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_tiger.h"

// The table from inc_hash_tiger.cl. The host passes this table to tiger_init (). A kernel passes
// its copy in shared memory where it makes one, or else the table itself.

extern u64a tiger_sbox[4][256];

#endif // HC_EMU_INC_HASH_TIGER_H
