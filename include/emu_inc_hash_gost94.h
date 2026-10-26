/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_GOST94_H
#define HC_EMU_INC_HASH_GOST94_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_gost94.h"

// The tables from inc_hash_gost94.cl. The host passes one of these tables to gost94_init (). A
// kernel passes its copy in shared memory where it makes one, or else the table itself.

extern u32a c_tables[4][256];
extern u32a c_tables_cryptopro[4][256];

#endif // HC_EMU_INC_HASH_GOST94_H
