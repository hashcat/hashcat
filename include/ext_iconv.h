/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_ICONV_H
#define HC_EXT_ICONV_H

#include "dynloader.h"

#include <stddef.h>

// What hashcat asks an iconv implementation for, beside what it asks zlib for in ext_zlib.h and
// libzstd for in ext_zstd.h. Three functions cover the whole use: open a conversion, run it over a
// candidate, close it again.
//
// iconv is opened at runtime rather than linked. hashcat converts an encoding only when the user
// passes --encoding-from or --encoding-to with two different names, so a build that never sees
// those options never needs the library, and linking it made every binary carry a dependency that
// almost no run uses. Nothing here includes iconv.h, so nothing in the tree needs it to build.
//
// Where the implementation lives differs per platform, and that is the one thing this loader has to
// get right. glibc and musl carry iconv inside the C library, so on those there is no separate file
// to open and the symbols are read out of the process itself. macOS, the BSDs and Windows keep it
// in a library of its own.

// A conversion descriptor is a pointer the implementation hands back and that hashcat only ever
// hands to the implementation again, so what it points at does not have to be known here. A failed
// iconv_open () answers (iconv_t) -1 rather than a null pointer, which is what HC_ICONV_ERR is.

typedef void *hc_iconv_t;

#define HC_ICONV_ERR ((hc_iconv_t) -1)

typedef struct hc_iconv_lib
{
  hc_iconv_t (*iconv_open)  (const char *tocode, const char *fromcode);
  size_t     (*iconv)       (hc_iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
  int        (*iconv_close) (hc_iconv_t cd);

  hc_dynlib_t lib;

} hc_iconv_lib_t;

// Loading is tried once, from hashcat_init (), where there is still only one thread. A box without
// an iconv is not a startup failure: hashcat only cares when a candidate has to change encoding,
// and hc_iconv () answering NULL is how that question gets its answer.

void hc_iconv_boot     (void);
void hc_iconv_shutdown (void);

const hc_iconv_lib_t *hc_iconv       (void);
const char           *hc_iconv_error (void);

// Where to get the library on this platform, for the one message a user sees when it is missing.

const char           *hc_iconv_hint  (void);

#endif // HC_EXT_ICONV_H
