/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "emu_general.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define DGST_ELEM 4
#define DGST_POS0 0
#define DGST_POS1 1
#define DGST_POS2 2
#define DGST_POS3 3

typedef struct digest
{
  u32 digest_buf[DGST_ELEM];

} digest_t;

#include "m16801-pure.cl"

