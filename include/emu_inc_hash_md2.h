/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_MD2_H
#define HC_EMU_INC_HASH_MD2_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_md2.h"

// The table from inc_hash_md2.cl. The host passes this table to md2_init (). A kernel passes its
// copy in shared memory where it makes one, or else the table itself.

extern u32a md2_sbox[256];

#endif // HC_EMU_INC_HASH_MD2_H
