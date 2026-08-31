/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"
#include "ext_zlib.h"

// The versioned soname first and the development name second. The first is the file a box that only
// installed the runtime package actually has; the second exists only where the development package
// is installed, and is a fallback rather than the answer.

static const char *const ZLIB_SONAMES[] =
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  "zlib1.dll",
  "libz.dll",
  "zlib.dll",
  #elif defined (__APPLE__)
  "libz.1.dylib",
  "/usr/lib/libz.1.dylib",
  "/opt/homebrew/lib/libz.1.dylib",
  "/usr/local/lib/libz.1.dylib",
  "libz.dylib",
  #else
  "libz.so.1",
  "libz.so",
  #endif
};

// The oldest zlib this loads against is 1.2.3.3, from 2010, which is what gzseek64 and gztell64 need.
// That floor is deliberately low: the Windows package ships a known zlib1.dll, but everywhere else
// the zlib1.dll on a Windows machine is whatever some other program left there, and asking for a
// recent one would refuse a library that can do everything hashcat wants. gzread and gzwrite are used
// rather than gzfread and gzfwrite for the same reason, those two being 1.2.9 and later.
//
// gzbuffer only sets a buffer size and gzvprintf is only reached when writing a gzip file, which
// nothing does, so neither is worth refusing a library over.
//
// The 64 bit names are asked for directly. zlib's header turns gzopen into gzopen64 and gzseek into
// gzseek64 through a macro when the build wants large files, and a macro is not something dlsym can
// follow, so the names that carry the 64 bit offset are written out.
//
// gzopen64 rather than gzdopen, and this matters more than it looks. gzdopen takes a descriptor,
// and on Windows a descriptor belongs to the C runtime that produced it. hashcat links the UCRT
// while a zlib1.dll on that machine is usually built against msvcrt, so a descriptor handed over
// means nothing on the other side and every gzip read comes back empty. Letting zlib open the file
// itself keeps the descriptor inside the runtime that owns it. Vendored zlib never had this problem
// because it was compiled into hashcat and shared its runtime.

static const hc_dynlib_sym_t ZLIB_SYMS[] =
{
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzopen64,      true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzbuffer,      false),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzread,        true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzwrite,       true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzerror,       true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzseek64,      true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzrewind,      true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gztell64,      true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzputc,        true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzgetc,        true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzgets,        true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzvprintf,     false),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzeof,         true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzflush,       true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, gzclose,       true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, inflateInit2_, true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, inflate,       true),
  HC_DYNLIB_SYM (hc_zlib_lib_t, inflateEnd,    true),
  HC_DYNLIB_SYM_LAST
};

static hc_zlib_lib_t zlib_lib;

static bool zlib_ready = false;

static char zlib_err[512];

static hc_once_t zlib_once = HC_ONCE_INIT;

static void zlib_load (void)
{
  memset (&zlib_lib, 0, sizeof (zlib_lib));

  zlib_ready  = false;
  zlib_err[0] = 0;

  const size_t sonames_cnt = sizeof (ZLIB_SONAMES) / sizeof (ZLIB_SONAMES[0]);

  hc_dynlib_t lib = hc_dynlib_open (ZLIB_SONAMES, sonames_cnt, zlib_err, sizeof (zlib_err));

  if (lib == NULL) return;

  if (hc_dynlib_syms (lib, &zlib_lib, ZLIB_SYMS, zlib_err, sizeof (zlib_err)) == false)
  {
    hc_dlclose (lib);

    return;
  }

  zlib_lib.lib = lib;

  zlib_ready = true;
}

void hc_zlib_boot (void)
{
  hc_once (&zlib_once, zlib_load);
}

void hc_zlib_shutdown (void)
{
  if (zlib_ready == false) return;

  hc_dlclose (zlib_lib.lib);

  memset (&zlib_lib, 0, sizeof (zlib_lib));

  zlib_ready = false;
}

const hc_zlib_lib_t *hc_zlib (void)
{
  hc_once (&zlib_once, zlib_load);

  if (zlib_ready == false) return NULL;

  return &zlib_lib;
}

const char *hc_zlib_error (void)
{
  hc_once (&zlib_once, zlib_load);

  if (zlib_err[0] != 0) return zlib_err;

  return "zlib was not loaded";
}

// The Windows package ships a zlib1.dll built from a pinned source. zlib is still the one of the
// three whose project publishes no Windows build of its own, so anyone building hashcat themselves
// has no address to be sent to. Saying that plainly is more use than a link that does not exist.

const char *hc_zlib_hint (void)
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  return "put zlib1.dll next to hashcat.exe. The Windows package ships one. The zlib project publishes no Windows build, so a build of your own needs a zlib1.dll from elsewhere, or the file recompressed as .xz or .zst";
  #elif defined (__APPLE__)
  return "install zlib, for example with: brew install zlib";
  #else
  return "install your distribution's zlib runtime package, named zlib1g on Debian and Ubuntu and zlib on Arch";
  #endif
}

// A raw deflate stream, which is what zlib calls a negative window size, decompressed in one call.
// A 7-Zip archive holds one of these when its coder is DEFLATE.

bool hc_inflate_raw (const unsigned char *in, const size_t in_len, unsigned char *out, const size_t out_len)
{
  const hc_zlib_lib_t *z = hc_zlib ();

  if (z == NULL) return false;

  hc_z_stream inf;

  inf.zalloc = NULL;
  inf.zfree  = NULL;
  inf.opaque = NULL;

  inf.avail_in = in_len;
  inf.next_in  = (unsigned char *) in;

  inf.avail_out = out_len;
  inf.next_out  = out;

  if (z->inflateInit2_ (&inf, -HC_Z_MAX_WBITS, HC_ZLIB_VERSION, (int) sizeof (hc_z_stream)) != HC_Z_OK) return false;

  const int rc = z->inflate (&inf, HC_Z_NO_FLUSH);

  z->inflateEnd (&inf);

  if (rc == HC_Z_OK) return true;
  if (rc == HC_Z_STREAM_END) return true;

  return false;
}
