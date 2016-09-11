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

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

#if defined (_WIN)
#define hc_dlopen  LoadLibrary
#define hc_dlclose FreeLibrary
#define hc_dlsym   GetProcAddress
#else
#define hc_dlopen  dlopen
#define hc_dlclose dlclose
#define hc_dlsym   dlsym
#endif

#define HC_LOAD_FUNC2(ptr,name,type,var,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->var, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        log_error ("ERROR: %s is missing from %s shared library.", #name, #libname); \
        exit (-1); \
      } else { \
        log_info ("WARNING: %s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } \
    } \
  }

#define HC_LOAD_FUNC(ptr,name,type,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->lib, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        log_error ("ERROR: %s is missing from %s shared library.", #name, #libname); \
        exit (-1); \
      } else { \
        log_info ("WARNING: %s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } \
    } \
  }

#define HC_LOAD_ADDR(ptr,name,type,func,addr,libname,noerr) \
  ptr->name = (type) (*ptr->func) (addr); \
  if (!ptr->name) { \
    if (noerr == 1) { \
      log_error ("ERROR: %s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      exit (-1); \
    } else { \
      log_error ("WARNING: %s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      return -1; \
    } \
  }

#endif // _DYNALOADER_H