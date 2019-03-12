/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "ext_ADL.h"

void *HC_API_CALL ADL_Main_Memory_Alloc (const int iSize)
{
  return malloc ((size_t) iSize);
}
