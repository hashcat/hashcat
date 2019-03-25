/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "emu_general.h"

#define DGST_ELEM 4
#define DGST_R0   0
#define DGST_R1   1
#define DGST_R2   2
#define DGST_R3   3

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

#include "inc_cipher_kuznyechik.cl"

#pragma GCC diagnostic pop
