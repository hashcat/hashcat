/* LzmaLibExports.c -- LZMA library DLL Entry point
2015-11-08 : Igor Pavlov : Public domain */

#include "../../Precomp.h"

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
  UNUSED_VAR(hInstance);
  UNUSED_VAR(dwReason);
  UNUSED_VAR(lpReserved);
  return TRUE;
}
