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

// The index and block names are optional. lzma_file_info_decoder and the two index size calls
// arrived in xz 5.2.6 and Ubuntu 22.04 still ships 5.2.5, so requiring them would refuse a library
// that decompresses perfectly well. Without them the uncompressed size of an .xz file is simply not
// known, and the blocks it is made of cannot be walked, which are both cases the file layer already
// had to handle: such a file is read from its beginning, as every .xz was before.

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
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_index_iter_init,         false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_index_iter_next,         false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_index_iter_locate,       false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_block_header_decode,     false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_block_decoder,           false),
  HC_DYNLIB_SYM (hc_lzma_lib_t, lzma_filters_free,            false),
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

// liblzma allocated these from the properties and copied what it needed into its own state, so the
// library is what has to release them. On Windows a module linked against a different C runtime
// allocates from a different heap, and free () here corrupts the one hashcat itself allocates from.
// lzma_filters_free arrived in xz 5.4. Where it is missing, free () is what this did before and is
// still correct on a platform that gives the whole process one heap.

static void hc_lzma_filters_release (const hc_lzma_lib_t *lz, hc_lzma_filter *filters, const int filters_cnt)
{
  if (lz->lzma_filters_free != NULL)
  {
    lz->lzma_filters_free (filters, NULL);

    return;
  }

  for (int i = 0; i < filters_cnt; i++)
  {
    free (filters[i].options);

    filters[i].options = NULL;
  }
}

// One raw coder, with no container around it and its properties passed beside it, which is how a
// 7-Zip archive stores a compressed block and how the Markov table is stored. A filter can run in
// front of the coder, which pre_id names. The chain lists the filter first, in the order the data
// was encoded, and liblzma decodes it from the coder backwards.
//
// A raw stream carries no end marker, so liblzma reports running out of output rather than reaching
// an end. That is the expected finish here: every caller already knows the decompressed length and
// asks for exactly that, so the test for success is that the buffer came back full. *out_len says
// how much came back either way, and 0 when nothing was decoded at all.

static bool hc_lzma_raw_decompress (const u64 pre_id, const unsigned char *pre_props, const size_t pre_props_size, const u64 coder_id, const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const unsigned char *props, const size_t props_size)
{
  const size_t want_out = *out_len;

  *out_len = 0;

  const hc_lzma_lib_t *lz = hc_lzma ();

  if (lz == NULL) return false;

  hc_lzma_filter filters[3];

  int filters_cnt = 0;

  if (pre_id != HC_LZMA_VLI_UNKNOWN)
  {
    filters[filters_cnt].id      = pre_id;
    filters[filters_cnt].options = NULL;

    filters_cnt++;
  }

  filters[filters_cnt].id      = coder_id;
  filters[filters_cnt].options = NULL;

  filters_cnt++;

  filters[filters_cnt].id      = HC_LZMA_VLI_UNKNOWN;
  filters[filters_cnt].options = NULL;

  if (pre_id != HC_LZMA_VLI_UNKNOWN)
  {
    if (lz->lzma_properties_decode (&filters[0], NULL, pre_props, pre_props_size) != HC_LZMA_OK) return false;
  }

  if (lz->lzma_properties_decode (&filters[filters_cnt - 1], NULL, props, props_size) != HC_LZMA_OK)
  {
    hc_lzma_filters_release (lz, filters, filters_cnt);

    return false;
  }

  hc_lzma_stream strm;

  memset (&strm, 0, sizeof (strm));

  const int rc_init = lz->lzma_raw_decoder (&strm, filters);

  hc_lzma_filters_release (lz, filters, filters_cnt);

  if (rc_init != HC_LZMA_OK) return false;

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
  const bool rc = hc_lzma_raw_decompress (HC_LZMA_VLI_UNKNOWN, NULL, 0, HC_LZMA_FILTER_LZMA1, in, in_len, out, out_len, (const unsigned char *) props, HC_LZMA1_PROPS_SIZE);

  return rc;
}

bool hc_lzma2_decompress (const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const char *props)
{
  const bool rc = hc_lzma_raw_decompress (HC_LZMA_VLI_UNKNOWN, NULL, 0, HC_LZMA_FILTER_LZMA2, in, in_len, out, out_len, (const unsigned char *) props, HC_LZMA2_PROPS_SIZE);

  return rc;
}

// liblzma decodes a filter only in front of a coder, and a branch converter holds back its last
// bytes until the coder behind it reports an end. So the data is wrapped as uncompressed LZMA2
// chunks, which end with a 0 byte, and decoded through the filter and LZMA2. A chunk holds at most
// 64 KiB behind a control byte and its size less one in 2 bytes. The first chunk resets the
// dictionary and the later ones keep it, and since an uncompressed chunk refers to nothing before
// it, the smallest dictionary will do.

#define HC_LZMA2_CHUNK_MAX (64 * 1024)

bool hc_lzma_filter_decode (const u64 filter_id, const unsigned char *filter_props, const size_t filter_props_size, const unsigned char *in, const size_t in_len, unsigned char *out)
{
  if (in_len == 0) return true;

  const size_t chunks_cnt = (in_len + HC_LZMA2_CHUNK_MAX - 1) / HC_LZMA2_CHUNK_MAX;

  size_t wrapped_len = in_len + (chunks_cnt * 3) + 1;

  unsigned char *wrapped = (unsigned char *) hcmalloc (wrapped_len);

  if (wrapped == NULL) return false;

  size_t pos = 0;

  for (size_t off = 0; off < in_len; off += HC_LZMA2_CHUNK_MAX)
  {
    const size_t len = MIN (HC_LZMA2_CHUNK_MAX, in_len - off);

    wrapped[pos + 0] = (off == 0) ? 0x01 : 0x02;
    wrapped[pos + 1] = ((len - 1) >> 8) & 0xff;
    wrapped[pos + 2] = ((len - 1) >> 0) & 0xff;

    memcpy (&wrapped[pos + 3], &in[off], len);

    pos += 3 + len;
  }

  wrapped[pos] = 0x00;

  const unsigned char lzma2_props = 0;

  size_t out_len = in_len;

  const bool rc = hc_lzma_raw_decompress (filter_id, filter_props, filter_props_size, HC_LZMA_FILTER_LZMA2, wrapped, &wrapped_len, out, &out_len, &lzma2_props, HC_LZMA2_PROPS_SIZE);

  hcfree (wrapped);

  return rc;
}
