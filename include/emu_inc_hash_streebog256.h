/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_STREEBOG256_H
#define HC_EMU_INC_HASH_STREEBOG256_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_streebog256.h"

// The table from inc_hash_streebog256.cl. The host passes this table to streebog256_init (). A
// kernel passes its copy in shared memory where it makes one, or else the table itself.

extern u64a sbob256_sl64[8][256];

#endif // HC_EMU_INC_HASH_STREEBOG256_H
