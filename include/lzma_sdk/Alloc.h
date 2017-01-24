/* Alloc.h -- Memory allocation functions
2015-02-21 : Igor Pavlov : Public domain */

#ifndef __COMMON_ALLOC_H
#define __COMMON_ALLOC_H

#include "7zTypes.h"

EXTERN_C_BEGIN

void *MyAlloc(size_t size);
void MyFree(void *address);

#ifdef _WIN32

void SetLargePageSize(void);

void *MidAlloc(size_t size);
void MidFree(void *address);
void *BigAlloc(size_t size);
void BigFree(void *address);

#else

#define MidAlloc(size) MyAlloc(size)
#define MidFree(address) MyFree(address)
#define BigAlloc(size) MyAlloc(size)
#define BigFree(address) MyFree(address)

#endif

extern ISzAlloc g_Alloc;
extern ISzAlloc g_BigAlloc;

EXTERN_C_END

#endif
