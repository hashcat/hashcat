/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"
#include "ext_iconv.h"

// The files to try, in order, after the process itself. glibc and musl need none of them, because
// there iconv is part of the C library and the process already has it. This list is what the other
// platforms need, where iconv is a library of its own.

static const char *const ICONV_SONAMES[] =
{
  #if   defined (_WIN)
  "libiconv-2.dll",
  "iconv.dll",
  "libiconv.dll",
  #elif defined (__CYGWIN__)
  "cygiconv-2.dll",
  "msys-iconv-2.dll",
  "libiconv-2.dll",
  #elif defined (__APPLE__)
  "/usr/lib/libiconv.2.dylib",
  "libiconv.2.dylib",
  "/opt/homebrew/lib/libiconv.2.dylib",
  "/usr/local/lib/libiconv.2.dylib",
  "libiconv.dylib",
  #else
  "libiconv.so.2",
  "libiconv.so",
  #endif
};

// The same three functions under the two names they are published as. An implementation that is the
// system iconv exports them plainly. GNU libiconv beside a C library that has an iconv of its own
// cannot, because the two would collide, so it prefixes every name and its header renames the calls
// behind the program's back. A program that resolves the names itself has to ask for both.

static const hc_dynlib_sym_t ICONV_SYMS[] =
{
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv_open,  true),
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv,       true),
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv_close, true),
  HC_DYNLIB_SYM_LAST
};

static const hc_dynlib_sym_t ICONV_SYMS_PREFIXED[] =
{
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv_open,  "libiconv_open",  true),
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv,       "libiconv",       true),
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv_close, "libiconv_close", true),
  HC_DYNLIB_SYM_LAST
};

static hc_iconv_lib_t iconv_lib;

static bool iconv_ready = false;

static char iconv_err[512];

static hc_once_t iconv_once = HC_ONCE_INIT;

// Read the three functions out of one handle, under either set of names, and keep the handle when
// they are all there. A handle that does not carry a whole set is closed again and the search goes
// on, which is what makes trying the process itself first free on the platforms where that misses.

static bool iconv_adopt (hc_dynlib_t lib)
{
  if (lib == NULL) return false;

  if (hc_dynlib_syms (lib, &iconv_lib, ICONV_SYMS, NULL, 0) == false)
  {
    if (hc_dynlib_syms (lib, &iconv_lib, ICONV_SYMS_PREFIXED, NULL, 0) == false)
    {
      memset (&iconv_lib, 0, sizeof (iconv_lib));

      hc_dlclose (lib);

      return false;
    }
  }

  iconv_lib.lib = lib;

  iconv_ready = true;

  return true;
}

static void iconv_load (void)
{
  memset (&iconv_lib, 0, sizeof (iconv_lib));

  iconv_ready  = false;
  iconv_err[0] = 0;

  // The process itself, which is where glibc and musl keep iconv. hc_dlopen () of a null name is
  // the handle for the running program and everything already loaded with it, so the symbols are
  // found without a file being opened. Windows has no such handle and no such iconv.

  #ifndef _WIN
  if (iconv_adopt (hc_dlopen (NULL)) == true) return;
  #endif

  const size_t sonames_cnt = sizeof (ICONV_SONAMES) / sizeof (ICONV_SONAMES[0]);

  hc_dynlib_t lib = hc_dynlib_open (ICONV_SONAMES, sonames_cnt, iconv_err, sizeof (iconv_err));

  if (lib == NULL) return;

  if (iconv_adopt (lib) == false)
  {
    snprintf (iconv_err, sizeof (iconv_err), "iconv_open, iconv and iconv_close are missing from the shared library");
  }
}

void hc_iconv_boot (void)
{
  hc_once (&iconv_once, iconv_load);
}

void hc_iconv_shutdown (void)
{
  if (iconv_ready == false) return;

  hc_dlclose (iconv_lib.lib);

  memset (&iconv_lib, 0, sizeof (iconv_lib));

  iconv_ready = false;
}

const hc_iconv_lib_t *hc_iconv (void)
{
  hc_once (&iconv_once, iconv_load);

  if (iconv_ready == false) return NULL;

  return &iconv_lib;
}

const char *hc_iconv_error (void)
{
  hc_once (&iconv_once, iconv_load);

  if (iconv_err[0] != 0) return iconv_err;

  return "no iconv was loaded";
}

const char *hc_iconv_hint (void)
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  return "put libiconv-2.dll next to hashcat.exe, from the MSYS2 package mingw-w64-x86_64-libiconv or from https://github.com/win-iconv/win-iconv";
  #elif defined (__APPLE__)
  return "install libiconv, for example with: brew install libiconv";
  #else
  return "install your distribution's libiconv runtime package, which a machine using the GNU C library or musl does not need because iconv is part of the C library there";
  #endif
}
