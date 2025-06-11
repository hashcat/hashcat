/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"
#include "shared.h"

#ifdef _WIN

hc_dynlib_t hc_dlopen (const char *lpLibFileName)
{
  wchar_t *wpath = NULL;
  if (utf8_to_widechar (lpLibFileName, &wpath) == 0)
  {
    hc_dynlib_t lib = LoadLibraryW(wpath);
    return lib;
  }
  else
  {
    return LoadLibraryA (lpLibFileName);
 }
}

BOOL hc_dlclose (hc_dynlib_t hLibModule)
{
  return FreeLibrary (hLibModule);
}

hc_dynfunc_t hc_dlsym (hc_dynlib_t hModule, LPCSTR lpProcName)
{
  return GetProcAddress (hModule, lpProcName);
}

#else

hc_dynlib_t hc_dlopen (const char *filename)
{
  
  return dlopen (filename, RTLD_NOW);
}

int hc_dlclose (hc_dynlib_t handle)
{
  return dlclose (handle);
}

hc_dynfunc_t hc_dlsym (hc_dynlib_t handle, const char *symbol)
{
  return dlsym (handle, symbol);
}

#endif
