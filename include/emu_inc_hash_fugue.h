/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_FUGUE_H
#define HC_EMU_INC_HASH_FUGUE_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_fugue.h"

// The table from inc_hash_fugue.cl. The host passes this table to fugue_init (). A kernel passes
// its copy in shared memory where it makes one, or else the table itself.

extern u32a fugue_mixtab[4][256];

#endif // HC_EMU_INC_HASH_FUGUE_H
