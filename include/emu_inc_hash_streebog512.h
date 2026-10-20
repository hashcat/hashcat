/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_STREEBOG512_H
#define HC_EMU_INC_HASH_STREEBOG512_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_streebog512.h"

// The table from inc_hash_streebog512.cl. The host passes this table to streebog512_init (). A
// kernel passes its copy in shared memory where it makes one, or else the table itself.

extern u64a sbob512_sl64[8][256];

#endif // HC_EMU_INC_HASH_STREEBOG512_H
