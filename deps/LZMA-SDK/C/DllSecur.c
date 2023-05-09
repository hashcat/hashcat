/* DllSecur.c -- DLL loading security
2022-07-15 : Igor Pavlov : Public domain */

#include "Precomp.h"

#ifdef _WIN32

#include <Windows.h>

#include "DllSecur.h"

#ifndef UNDER_CE

#if defined(__GNUC__) && (__GNUC__ >= 8)
  #pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

typedef BOOL (WINAPI *Func_SetDefaultDllDirectories)(DWORD DirectoryFlags);

#define MY_LOAD_LIBRARY_SEARCH_USER_DIRS 0x400
#define MY_LOAD_LIBRARY_SEARCH_SYSTEM32  0x800

static const char * const g_Dlls =
  #ifndef _CONSOLE
  "UXTHEME\0"
  #endif
  "USERENV\0"
  "SETUPAPI\0"
  "APPHELP\0"
  "PROPSYS\0"
  "DWMAPI\0"
  "CRYPTBASE\0"
  "OLEACC\0"
  "CLBCATQ\0"
  "VERSION\0"
  ;

#endif

// #define MY_CAST_FUNC  (void(*)())
#define MY_CAST_FUNC

void My_SetDefaultDllDirectories()
{
  #ifndef UNDER_CE
  
    OSVERSIONINFO vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!GetVersionEx(&vi) || vi.dwMajorVersion != 6 || vi.dwMinorVersion != 0)
    {
      Func_SetDefaultDllDirectories setDllDirs = (Func_SetDefaultDllDirectories)
          MY_CAST_FUNC GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "SetDefaultDllDirectories");
      if (setDllDirs)
        if (setDllDirs(MY_LOAD_LIBRARY_SEARCH_SYSTEM32 | MY_LOAD_LIBRARY_SEARCH_USER_DIRS))
          return;
    }

  #endif
}


void LoadSecurityDlls()
{
  #ifndef UNDER_CE
  
  wchar_t buf[MAX_PATH + 100];

  {
    // at Vista (ver 6.0) : CoCreateInstance(CLSID_ShellLink, ...) doesn't work after SetDefaultDllDirectories() : Check it ???
    OSVERSIONINFO vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!GetVersionEx(&vi) || vi.dwMajorVersion != 6 || vi.dwMinorVersion != 0)
    {
      Func_SetDefaultDllDirectories setDllDirs = (Func_SetDefaultDllDirectories)
          MY_CAST_FUNC GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "SetDefaultDllDirectories");
      if (setDllDirs)
        if (setDllDirs(MY_LOAD_LIBRARY_SEARCH_SYSTEM32 | MY_LOAD_LIBRARY_SEARCH_USER_DIRS))
          return;
    }
  }

  {
    unsigned len = GetSystemDirectoryW(buf, MAX_PATH + 2);
    if (len == 0 || len > MAX_PATH)
      return;
  }
  {
    const char *dll;
    unsigned pos = (unsigned)lstrlenW(buf);

    if (buf[pos - 1] != '\\')
      buf[pos++] = '\\';
    
    for (dll = g_Dlls; dll[0] != 0;)
    {
      unsigned k = 0;
      for (;;)
      {
        char c = *dll++;
        buf[pos + k] = (Byte)c;
        k++;
        if (c == 0)
          break;
      }

      lstrcatW(buf, L".dll");
      LoadLibraryExW(buf, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    }
  }
  
  #endif
}

#endif
