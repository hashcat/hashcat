/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DYNLOADER_H
#define _DYNLOADER_H

#include <stdlib.h>

#ifdef _WIN
#include <windows.h>
#else
#include <dlfcn.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__
#endif // _WIN

#ifdef _WIN
hc_dynlib_t  hc_dlopen  (LPCSTR lpLibFileName);
BOOL         hc_dlclose (hc_dynlib_t hLibModule);
hc_dynfunc_t hc_dlsym   (hc_dynlib_t hModule, LPCSTR lpProcName);
#else
hc_dynlib_t  hc_dlopen  (const char *filename);
int          hc_dlclose (hc_dynlib_t handle);
hc_dynfunc_t hc_dlsym   (hc_dynlib_t handle, const char *symbol);
#endif

#define HC_LOAD_FUNC2(ptr,name,type,var,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->var, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } \
      if (noerr != 1) { \
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
      } \
      if (noerr != 1) { \
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
    } \
    if (noerr != 1) { \
      event_log_warning (hashcat_ctx, "%s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      return 0; \
    } \
  }

#endif // _DYNALOADER_H
