/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "dynloader.h"

#ifdef _WIN

HMODULE hc_dlopen (LPCSTR lpLibFileName)
{
  return LoadLibraryA (lpLibFileName);
}

BOOL hc_dlclose (HMODULE hLibModule)
{
  return FreeLibrary (hLibModule);
}

FARPROC hc_dlsym (HMODULE hModule, LPCSTR lpProcName)
{
  return GetProcAddress (hModule, lpProcName);
}

#else

void *hc_dlopen (const char *fileName, int flag)
{
  return dlopen (fileName, flag);
}

int hc_dlclose (void * handle)
{
  return dlclose (handle);
}

void *hc_dlsym (void *module, const char *symbol)
{
  return dlsym (module, symbol);
}

#endif
