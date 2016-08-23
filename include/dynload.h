#pragma once
/**
* libraries stuff
*/
#include "config.h"
#include "common.h"
#ifdef _WIN
inline HMODULE hc_dlopen(LPCSTR lpLibFileName) {
  return LoadLibraryA(lpLibFileName);
}
inline BOOL hc_dlclose(HMODULE hLibModule){
  return FreeLibrary(hLibModule);
}
inline FARPROC hc_dlsym(HMODULE hModule, LPCSTR lpProcName) {
  return GetProcAddress(hModule, lpProcName);
}
#else
#include <dlfcn.h>
inline void * hc_dlopen(const char * fileName, int flag) {
  return dlopen(fileName, flag);
}
inline int hc_dlclose(void * handle){
  return dlclose(handle);
}
inline void * hc_dlsym(void * module, const char * symbol) {
  return dlsym(module, symbol);
}
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
