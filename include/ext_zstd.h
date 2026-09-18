/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_ZSTD_H
#define HC_EXT_ZSTD_H

#include "dynloader.h"

// What hashcat asks libzstd for, beside what it asks zlib for in ext_zlib.h and liblzma for in
// ext_lzma.h. zstd is one library, one format and one compressor, which makes it the plainest of
// the three: no container to pick apart and no second name for the same thing.
//
// It is opened at runtime with dlopen rather than linked, so a box needs the runtime library and
// not the development package. That gap is wider here than for the other two: a great many
// distributions install libzstd.so.1 as a dependency of something else while shipping no zstd
// development package at all, which is exactly the case a linked build cannot serve.

// A decompression stream is a pointer libzstd hands back and hashcat only hands to libzstd again.

typedef void *hc_zstd_dstream_t;

// These two libzstd reads and writes, so they carry its layout. Both are three words and have been
// since the streaming interface was declared stable in 1.0.

typedef struct hc_zstd_inbuf
{
  const void *src;
  size_t      size;
  size_t      pos;

} hc_zstd_inbuf;

typedef struct hc_zstd_outbuf
{
  void   *dst;
  size_t  size;
  size_t  pos;

} hc_zstd_outbuf;

// The first four bytes of a .zst file, little endian on disk as 28 b5 2f fd.

#define HC_ZSTD_MAGIC 0xfd2fb528

typedef struct hc_zstd_lib
{
  hc_zstd_dstream_t (*ZSTD_createDStream)    (void);
  size_t            (*ZSTD_freeDStream)      (hc_zstd_dstream_t zds);
  size_t            (*ZSTD_initDStream)      (hc_zstd_dstream_t zds);
  size_t            (*ZSTD_decompressStream) (hc_zstd_dstream_t zds, hc_zstd_outbuf *output, hc_zstd_inbuf *input);
  unsigned int      (*ZSTD_isError)          (size_t code);
  const char       *(*ZSTD_getErrorName)     (size_t code);

  hc_dynlib_t lib;

} hc_zstd_lib_t;

void hc_zstd_boot     (void);
void hc_zstd_shutdown (void);

const hc_zstd_lib_t *hc_zstd       (void);
const char          *hc_zstd_error (void);
const char          *hc_zstd_hint  (void);

#endif // HC_EXT_ZSTD_H
