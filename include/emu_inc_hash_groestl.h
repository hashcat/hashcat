/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_GROESTL_H
#define HC_EMU_INC_HASH_GROESTL_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_groestl.h"

// The table from inc_hash_groestl.cl. The host passes this table to groestl256_init () and
// groestl512_init (). A kernel passes its copy in shared memory where it makes one, or else the
// table itself.

extern u64a groestl_t0[256];

#endif // HC_EMU_INC_HASH_GROESTL_H
