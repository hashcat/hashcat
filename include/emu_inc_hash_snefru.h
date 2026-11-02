/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_SNEFRU_H
#define HC_EMU_INC_HASH_SNEFRU_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_snefru.h"

// The table from inc_hash_snefru.cl. The host passes this table to snefru_init (). A kernel passes
// its copy in shared memory where it makes one, or else the table itself.

extern u32a snefru_sbox[16][256];

#endif // HC_EMU_INC_HASH_SNEFRU_H
