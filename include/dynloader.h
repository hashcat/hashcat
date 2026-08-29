/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_DYNLOADER_H
#define HC_DYNLOADER_H

#include <stddef.h>
#include <stdlib.h>

#ifdef _WIN
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__
#endif // _WIN

#ifdef _WIN
HC_PLUGIN_API hc_dynlib_t  hc_dlopen  (LPCSTR lpLibFileName);
HC_PLUGIN_API BOOL         hc_dlclose (hc_dynlib_t hLibModule);
HC_PLUGIN_API hc_dynfunc_t hc_dlsym   (hc_dynlib_t hModule, LPCSTR lpProcName);
HC_PLUGIN_API char        *hc_dlerror ();
#else
HC_PLUGIN_API hc_dynlib_t  hc_dlopen  (const char *filename);
HC_PLUGIN_API int          hc_dlclose (hc_dynlib_t handle);
HC_PLUGIN_API hc_dynfunc_t hc_dlsym   (hc_dynlib_t handle, const char *symbol);
HC_PLUGIN_API char        *hc_dlerror ();
#endif

int hc_dlplugin_abi (const char *path);

// Take the working directory out of the library search order. Windows only, and a no-op elsewhere,
// because dlopen () of a bare soname never searches the working directory to begin with. Call it
// before anything is loaded.

#ifdef _WIN
void hc_dynlib_harden_search_path (void);
#else
#define hc_dynlib_harden_search_path()
#endif

// Run something once, whatever else is happening on other threads.
//
// A loader below keeps what it found in file scope, and file scope is per copy of the core.
// Under SHARED=0 every plugin is built with its own copy, and hashcat_init () starts only the one
// inside the hashcat binary, so a plugin's copy has to be able to start itself the first time it
// is asked for anything. That first ask can come from any thread.

#ifdef _WIN
typedef INIT_ONCE      hc_once_t;
#define HC_ONCE_INIT   INIT_ONCE_STATIC_INIT
#else
typedef pthread_once_t hc_once_t;
#define HC_ONCE_INIT   PTHREAD_ONCE_INIT
#endif

void hc_once (hc_once_t *once, void (*init) (void));

// Locating a library and reading its symbols out, written once.
//
// Every wrapper in the tree needs the same two steps: try a list of file names until one of them
// opens, then fill a struct of function pointers. Most of them write both by hand, as a platform
// #if chain and a column of load macros.
//
// The pair below is what a caller uses instead. Neither of them logs. HC_LOAD_FUNC calls
// event_log_error and returns -1, which is why only the core can use it: a feed reports through its
// own error buffer and cannot return -1 from a function that returns bool. These write the reason
// into a buffer the caller owns, and the caller decides what a reason is worth. The core hands it to
// event_log_error, a plugin puts it in the field its interface gives it.
//
// One wrapper does not fit and is not expected to. ext_nvrtc.c has no list of names to try, it
// builds them at runtime by counting CUDA versions down, so it keeps its own loop.

typedef struct hc_dynlib_sym
{
  const char *name;      // the symbol to look up
  size_t      offset;    // where it goes, as an offsetof () into the caller's struct
  bool        required;  // false leaves a null pointer behind instead of failing

} hc_dynlib_sym_t;

// The two ways to write a row. HC_DYNLIB_SYM is for the ordinary case where the struct field is
// named after the symbol, which is what every wrapper in the tree already does. HC_DYNLIB_SYM_AS is
// for the case where it cannot be, such as a field named for what hashcat wants and a symbol carrying
// a version suffix.

#define HC_DYNLIB_SYM(st,fn,req)        { #fn, offsetof (st, fn), req }
#define HC_DYNLIB_SYM_AS(st,fn,sym,req) { sym, offsetof (st, fn), req }
#define HC_DYNLIB_SYM_LAST              { NULL, 0, false }

HC_PLUGIN_API hc_dynlib_t hc_dynlib_open (const char *const *sonames, const size_t sonames_cnt, char *err, const size_t err_size);

HC_PLUGIN_API bool        hc_dynlib_syms (hc_dynlib_t lib, void *dst, const hc_dynlib_sym_t *syms, char *err, const size_t err_size);

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
