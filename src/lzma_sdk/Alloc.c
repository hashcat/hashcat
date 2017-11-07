/* Alloc.c -- Memory allocation functions
2017-06-15 : Igor Pavlov : Public domain */

#include "Precomp.h"

#ifdef _WIN32
#include <windows.h>
#endif
#include <stdlib.h>

#include "Alloc.h"

/* #define _SZ_ALLOC_DEBUG */

/* use _SZ_ALLOC_DEBUG to debug alloc/free operations */
#ifdef _SZ_ALLOC_DEBUG
#include <stdio.h>
int g_allocCount = 0;
int g_allocCountMid = 0;
int g_allocCountBig = 0;
#endif

void *MyAlloc(size_t size)
{
  if (size == 0)
    return NULL;
  #ifdef _SZ_ALLOC_DEBUG
  {
    void *p = malloc(size);
    fprintf(stderr, "\nAlloc %10u bytes, count = %10d,  addr = %8X", size, g_allocCount++, (unsigned)p);
    return p;
  }
  #else
  return malloc(size);
  #endif
}

void MyFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address)
    fprintf(stderr, "\nFree; count = %10d,  addr = %8X", --g_allocCount, (unsigned)address);
  #endif
  free(address);
}

#ifdef _WIN32

void *MidAlloc(size_t size)
{
  if (size == 0)
    return NULL;
  #ifdef _SZ_ALLOC_DEBUG
  fprintf(stderr, "\nAlloc_Mid %10d bytes;  count = %10d", size, g_allocCountMid++);
  #endif
  return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

void MidFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address)
    fprintf(stderr, "\nFree_Mid; count = %10d", --g_allocCountMid);
  #endif
  if (!address)
    return;
  VirtualFree(address, 0, MEM_RELEASE);
}

#ifndef MEM_LARGE_PAGES
#undef _7ZIP_LARGE_PAGES
#endif

#ifdef _7ZIP_LARGE_PAGES
SIZE_T g_LargePageSize = 0;
typedef SIZE_T (WINAPI *GetLargePageMinimumP)();
#endif

void SetLargePageSize(void)
{
  #ifdef _7ZIP_LARGE_PAGES
  SIZE_T size;
  GetLargePageMinimumP largePageMinimum = (GetLargePageMinimumP)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetLargePageMinimum");
  if (!largePageMinimum)
    return;
  size = largePageMinimum();
  if (size == 0 || (size & (size - 1)) != 0)
    return;
  g_LargePageSize = size;
  #endif
}


void *BigAlloc(size_t size)
{
  if (size == 0)
    return NULL;
  #ifdef _SZ_ALLOC_DEBUG
  fprintf(stderr, "\nAlloc_Big %10u bytes;  count = %10d", size, g_allocCountBig++);
  #endif
  
  #ifdef _7ZIP_LARGE_PAGES
  {
    SIZE_T ps = g_LargePageSize;
    if (ps != 0 && ps <= (1 << 30) && size > (ps / 2))
    {
      size_t size2;
      ps--;
      size2 = (size + ps) & ~ps;
      if (size2 >= size)
      {
        void *res = VirtualAlloc(NULL, size2, MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (res)
          return res;
      }
    }
  }
  #endif

  return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

void BigFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address)
    fprintf(stderr, "\nFree_Big; count = %10d", --g_allocCountBig);
  #endif
  
  if (!address)
    return;
  VirtualFree(address, 0, MEM_RELEASE);
}

#endif


static void *SzAlloc(ISzAllocPtr p, size_t size) { UNUSED_VAR(p); return MyAlloc(size); }
static void SzFree(ISzAllocPtr p, void *address) { UNUSED_VAR(p); MyFree(address); }
ISzAlloc const g_Alloc = { SzAlloc, SzFree };

static void *SzBigAlloc(ISzAllocPtr p, size_t size) { UNUSED_VAR(p); return BigAlloc(size); }
static void SzBigFree(ISzAllocPtr p, void *address) { UNUSED_VAR(p); BigFree(address); }
ISzAlloc const g_BigAlloc = { SzBigAlloc, SzBigFree };
