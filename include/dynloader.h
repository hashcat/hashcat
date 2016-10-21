/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DYNLOADER_H
#define _DYNLOADER_H

#include <stdlib.h>

#if defined (_POSIX)
#include <dlfcn.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__
#endif // _POSIX

#ifdef _WIN
#include <windows.h>
#endif

#ifdef _WIN
HMODULE hc_dlopen  (LPCSTR lpLibFileName);
BOOL    hc_dlclose (HMODULE hLibModule);
FARPROC hc_dlsym   (HMODULE hModule, LPCSTR lpProcName);
#else
void *hc_dlopen  (const char *fileName, int flag);
int   hc_dlclose (void *handle);
void *hc_dlsym   (void *module, const char *symbol);
#endif

#define HC_LOAD_FUNC2(ptr,name,type,var,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->var, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } else { \
        event_log_warning (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
        return 0; \
      } \
    } \
  }

#define HC_LOAD_FUNC(ptr,name,type,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->lib, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } else { \
        event_log_warning (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
        return 0; \
      } \
    } \
  }

#define HC_LOAD_ADDR(ptr,name,type,func,addr,libname,noerr) \
  ptr->name = (type) (*ptr->func) (addr); \
  if (!ptr->name) { \
    if (noerr == 1) { \
      event_log_error (hashcat_ctx, "%s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      return -1; \
    } else { \
      event_log_warning (hashcat_ctx, "%s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      return 0; \
    } \
  }

#endif // _DYNALOADER_H
