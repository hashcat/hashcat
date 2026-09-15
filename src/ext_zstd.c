/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"
#include "ext_zstd.h"

static const char *const ZSTD_SONAMES[] =
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  "libzstd.dll",
  "zstd.dll",
  #elif defined (__APPLE__)
  "libzstd.1.dylib",
  "/usr/lib/libzstd.1.dylib",
  "/opt/homebrew/lib/libzstd.1.dylib",
  "/usr/local/lib/libzstd.1.dylib",
  "libzstd.dylib",
  #else
  "libzstd.so.1",
  "libzstd.so",
  #endif
};

// Every name here has been in the library since the streaming interface was declared stable in
// 1.0, so there is no version floor worth naming beyond that.

static const hc_dynlib_sym_t ZSTD_SYMS[] =
{
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_createDStream,    true),
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_freeDStream,      true),
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_initDStream,      true),
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_decompressStream, true),
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_isError,          true),
  HC_DYNLIB_SYM (hc_zstd_lib_t, ZSTD_getErrorName,     true),
  HC_DYNLIB_SYM_LAST
};

static hc_zstd_lib_t zstd_lib;

static bool zstd_ready = false;

static char zstd_err[512];

static hc_once_t zstd_once = HC_ONCE_INIT;

static void zstd_load (void)
{
  memset (&zstd_lib, 0, sizeof (zstd_lib));

  zstd_ready  = false;
  zstd_err[0] = 0;

  const size_t sonames_cnt = sizeof (ZSTD_SONAMES) / sizeof (ZSTD_SONAMES[0]);

  hc_dynlib_t lib = hc_dynlib_open (ZSTD_SONAMES, sonames_cnt, zstd_err, sizeof (zstd_err));

  if (lib == NULL) return;

  if (hc_dynlib_syms (lib, &zstd_lib, ZSTD_SYMS, zstd_err, sizeof (zstd_err)) == false)
  {
    hc_dlclose (lib);

    return;
  }

  zstd_lib.lib = lib;

  zstd_ready = true;
}

void hc_zstd_boot (void)
{
  hc_once (&zstd_once, zstd_load);
}

void hc_zstd_shutdown (void)
{
  if (zstd_ready == false) return;

  hc_dlclose (zstd_lib.lib);

  memset (&zstd_lib, 0, sizeof (zstd_lib));

  zstd_ready = false;
}

const hc_zstd_lib_t *hc_zstd (void)
{
  hc_once (&zstd_once, zstd_load);

  if (zstd_ready == false) return NULL;

  return &zstd_lib;
}

const char *hc_zstd_error (void)
{
  hc_once (&zstd_once, zstd_load);

  if (zstd_err[0] != 0) return zstd_err;

  return "libzstd was not loaded";
}

const char *hc_zstd_hint (void)
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  return "put libzstd.dll next to hashcat.exe. The Windows package ships one. A build of your own takes it from the dll folder of the win64 zip at https://github.com/facebook/zstd/releases";
  #elif defined (__APPLE__)
  return "install zstd, for example with: brew install zstd";
  #else
  return "install your distribution's zstd runtime package, named libzstd1 on Debian and Ubuntu and zstd on Arch";
  #endif
}

bool hc_zstd_available (void)
{
  return (hc_zstd () != NULL);
}

// A single zstd frame, decompressed with the streaming entry points the symbol table already
// carries. Zero from ZSTD_decompressStream () is libzstd saying a frame ended exactly here and
// nothing of it is still owed. Filling the output buffer without an error is also success, because
// a 7-Zip hash may only CRC a prefix.

bool hc_zstd_decompress (const unsigned char *in, const size_t in_len, unsigned char *out, const size_t out_len)
{
  const hc_zstd_lib_t *z = hc_zstd ();

  if (z == NULL) return false;

  hc_zstd_dstream_t zds = z->ZSTD_createDStream ();

  if (zds == NULL) return false;

  if (z->ZSTD_isError (z->ZSTD_initDStream (zds)))
  {
    z->ZSTD_freeDStream (zds);

    return false;
  }

  hc_zstd_inbuf zin;

  zin.src  = in;
  zin.size = in_len;
  zin.pos  = 0;

  hc_zstd_outbuf zout;

  zout.dst  = out;
  zout.size = out_len;
  zout.pos  = 0;

  bool ok = false;

  for (;;)
  {
    const size_t rc = z->ZSTD_decompressStream (zds, &zout, &zin);

    if (z->ZSTD_isError (rc)) break;

    if (rc == 0)
    {
      ok = true;

      break;
    }

    if (zout.pos == zout.size)
    {
      ok = true;

      break;
    }

    if (zin.pos == zin.size) break;
  }

  z->ZSTD_freeDStream (zds);

  return ok;
}
