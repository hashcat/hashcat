/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_DYNLOADER_H
#define HC_DYNLOADER_H

#include <stdlib.h>

#include <dlfcn.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__

hc_dynlib_t  hc_dlopen  (const char *filename);
int          hc_dlclose (hc_dynlib_t handle);
hc_dynfunc_t hc_dlsym   (hc_dynlib_t handle, const char *symbol);

#define HC_LOAD_FUNC2(ptr,name,type,var,libname,noerr) \
  do { \
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
    } \
  } while (0)

#define HC_LOAD_FUNC(ptr,name,type,libname,noerr) \
  do { \
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
    } \
  } while (0)

#define HC_LOAD_ADDR(ptr,name,type,func,addr,libname,noerr) \
  do { \
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
    } \
  } while (0)

#endif // HC__DYNALOADER_H
