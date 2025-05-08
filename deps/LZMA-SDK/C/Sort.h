/* Sort.h -- Sort functions
2023-03-05 : Igor Pavlov : Public domain */

#ifndef ZIP7_INC_SORT_H
#define ZIP7_INC_SORT_H

#include "7zTypes.h"

EXTERN_C_BEGIN

void HeapSort(UInt32 *p, size_t size);
void HeapSort64(UInt64 *p, size_t size);

/* void HeapSortRef(UInt32 *p, UInt32 *vals, size_t size); */

EXTERN_C_END

#endif
