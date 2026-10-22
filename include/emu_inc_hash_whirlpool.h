/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EMU_INC_HASH_WHIRLPOOL_H
#define HC_EMU_INC_HASH_WHIRLPOOL_H

#include "emu_general.h"

#include "inc_vendor.h"
#include "inc_hash_whirlpool.h"

// The tables from inc_hash_whirlpool.cl. The host passes these tables to whirlpool_init (). A
// kernel passes its copies in shared memory where it makes them, or else the tables themselves.

extern u64a MT0[256];
extern u64a MT1[256];
extern u64a MT2[256];
extern u64a MT3[256];
extern u64a MT4[256];
extern u64a MT5[256];
extern u64a MT6[256];
extern u64a MT7[256];

#endif // HC_EMU_INC_HASH_WHIRLPOOL_H
