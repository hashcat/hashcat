/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "dynloader.h"
#include "ext_lzma.h"

static const char *const LZMA_SONAMES[] =
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  "liblzma.dll",
  "liblzma-5.dll",
  #elif defined (__APPLE__)
  "liblzma.5.dylib",
  "/usr/lib/liblzma.5.dylib",
  "/opt/homebrew/lib/liblzma.5.dylib",
  "/usr/local/lib/liblzma.5.dylib",
  "liblzma.dylib",
  #else
  "liblzma.so.5",
  "liblzma.so",
  #endif
};

// The three index names are optional. They arrived in xz 5.2.6 and Ubuntu 22.04 still ships
// 5.2.5, so requiring them would refuse a library that decompresses perfectly well. Without
// them the uncompressed size of an .xz file is simply not known, which is a case the file layer
// already had to handle.

static const hc_dynlib_sym_t LZMA_SYMS[] =
{
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_raw_decoder,       true),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_properties_decode, true),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_code,              true),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_end,                     true),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_stream_decoder,          true),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_file_info_decoder,       false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_index_uncompressed_size, false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_index_end,               false),
  HC_DYNLIB_SYM_LAST
};

static hc_lzma_lib_t lzma_lib;

static bool lzma_ready = false;

static char lzma_err[512];

static hc_once_t lzma_once = HC_ONCE_INIT;

static void lzma_load (void)
{
  memset (&lzma_lib, 0, sizeof (lzma_lib));

  lzma_ready  = false;
  lzma_err[0] = 0;

  const size_t sonames_cnt = sizeof (LZMA_SONAMES) / sizeof (LZMA_SONAMES[0]);

  hc_dynlib_t lib = hc_dynlib_open (LZMA_SONAMES, sonames_cnt, lzma_err, sizeof (lzma_err));

  if (lib == NULL) return;

  if (hc_dynlib_syms (lib, &lzma_lib, LZMA_SYMS, lzma_err, sizeof (lzma_err)) == false)
  {
    hc_dlclose (lib);

    return;
  }

  lzma_lib.lib = lib;

  lzma_ready = true;
}

void hc_lzma_boot (void)
{
  hc_once (&lzma_once, lzma_load);
}

void hc_lzma_shutdown (void)
{
  if (lzma_ready == false) return;

  hc_dlclose (lzma_lib.lib);

  memset (&lzma_lib, 0, sizeof (lzma_lib));

  lzma_ready = false;
}

const hc_lzma_lib_t *hc_lzma (void)
{
  hc_once (&lzma_once, lzma_load);

  if (lzma_ready == false) return NULL;

  return &lzma_lib;
}

const char *hc_lzma_error (void)
{
  hc_once (&lzma_once, lzma_load);

  if (lzma_err[0] != 0) return lzma_err;

  return "liblzma was not loaded";
}

const char *hc_lzma_hint (void)
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  return "put liblzma.dll next to hashcat.exe. The Windows package ships one. A build of your own takes it from the bin_x86-64 folder of the windows zip at https://github.com/tukaani-project/xz/releases";
  #elif defined (__APPLE__)
  return "install xz, for example with: brew install xz";
  #else
  return "install your distribution's xz runtime package, named liblzma5 on Debian and Ubuntu and xz on Arch";
  #endif
}

// One raw coder, with no container around it and its properties passed beside it, which is how a
// 7-Zip archive stores a compressed block and how the Markov table is stored.
//
// A raw stream carries no end marker, so liblzma reports running out of output rather than reaching
// an end. That is the expected finish here: every caller already knows the decompressed length and
// asks for exactly that, so the test for success is that the buffer came back full.

static bool hc_lzma_raw_decompress (const u64 filter_id, const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const unsigned char *props, const size_t props_size)
{
  const hc_lzma_lib_t *lz = hc_lzma ();

  if (lz == NULL) return false;

  hc_lzma_filter filters[2];

  filters[0].id      = filter_id;
  filters[0].options = NULL;

  if (lz->lzma_properties_decode (&filters[0], NULL, props, props_size) != HC_LZMA_OK) return false;

  filters[1].id      = HC_LZMA_VLI_UNKNOWN;
  filters[1].options = NULL;

  hc_lzma_stream strm;

  memset (&strm, 0, sizeof (strm));

  const int rc_init = lz->lzma_raw_decoder (&strm, filters);

  // liblzma allocated this from the properties and copied what it needed into its own state

  free (filters[0].options);

  if (rc_init != HC_LZMA_OK) return false;

  const size_t want_out = *out_len;

  strm.next_in   = in;
  strm.avail_in  = *in_len;
  strm.next_out  = out;
  strm.avail_out = want_out;

  const int rc = lz->lzma_code (&strm, HC_LZMA_FINISH);

  *in_len  = (size_t) strm.total_in;
  *out_len = (size_t) strm.total_out;

  lz->lzma_end (&strm);

  if (rc == HC_LZMA_MEM_ERROR)      return false;
  if (rc == HC_LZMA_MEMLIMIT_ERROR) return false;
  if (rc == HC_LZMA_FORMAT_ERROR)   return false;
  if (rc == HC_LZMA_OPTIONS_ERROR)  return false;
  if (rc == HC_LZMA_DATA_ERROR)     return false;
  if (rc == HC_LZMA_PROG_ERROR)     return false;

  const bool filled = (strm.total_out == want_out);

  return filled;
}

bool hc_lzma1_decompress (const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const char *props)
{
  const bool rc = hc_lzma_raw_decompress (HC_LZMA_FILTER_LZMA1, in, in_len, out, out_len, (const unsigned char *) props, HC_LZMA1_PROPS_SIZE);

  return rc;
}

bool hc_lzma2_decompress (const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const char *props)
{
  const bool rc = hc_lzma_raw_decompress (HC_LZMA_FILTER_LZMA2, in, in_len, out, out_len, (const unsigned char *) props, HC_LZMA2_PROPS_SIZE);

  return rc;
}
