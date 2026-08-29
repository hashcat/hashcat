/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_LZMA_H
#define HC_EXT_LZMA_H

#include "dynloader.h"

// What hashcat asks liblzma for on behalf of a hash line, next to what it asks zlib for in
// ext_zlib.h. A plugin calls this instead of liblzma, so liblzma's own interface stays in the core.
//
// liblzma is the XZ Utils library, and one name covering three things is worth saying out loud.
// LZMA is the compressor. LZMA2 is a container around it. xz is a file format holding LZMA2 and an
// index. liblzma reads all of them, which is why one library replaces everything hashcat used to
// carry its own copy of: the raw LZMA1 and LZMA2 coders a 7-Zip hash needs, the LZMA2 buffer the
// Markov table is stored as, and the .xz files the file layer opens.
//
// It is opened at runtime with dlopen rather than linked, so a box needs the runtime library and
// not the development package.

// liblzma reads and writes the caller's stream, so this has to be the layout liblzma was built
// with. Unlike zlib there is no size argument to check it against, so a mismatch would be silent.
// Every member is written with the type liblzma's own header uses, and deps-unvendor's
// lzma_abi_check.c compares this against the real header on a box that has it.

typedef struct hc_lzma_stream
{
  const unsigned char *next_in;
  size_t               avail_in;
  u64                  total_in;

  unsigned char       *next_out;
  size_t               avail_out;
  u64                  total_out;

  const void          *allocator;
  void                *internal;

  void                *reserved_ptr1;
  void                *reserved_ptr2;
  void                *reserved_ptr3;
  void                *reserved_ptr4;

  u64                  seek_pos;
  u64                  reserved_int2;
  size_t               reserved_int3;
  size_t               reserved_int4;

  int                  reserved_enum1;
  int                  reserved_enum2;

} hc_lzma_stream;

// A filter chain is terminated by an entry whose id is HC_LZMA_VLI_UNKNOWN.

typedef struct hc_lzma_filter
{
  u64   id;
  void *options;

} hc_lzma_filter;

#define HC_LZMA_OK              0
#define HC_LZMA_STREAM_END      1
#define HC_LZMA_MEM_ERROR       5
#define HC_LZMA_MEMLIMIT_ERROR  6
#define HC_LZMA_FORMAT_ERROR    7
#define HC_LZMA_OPTIONS_ERROR   8
#define HC_LZMA_DATA_ERROR      9
#define HC_LZMA_BUF_ERROR      10
#define HC_LZMA_PROG_ERROR     11
#define HC_LZMA_SEEK_NEEDED    12

#define HC_LZMA_RUN             0
#define HC_LZMA_FINISH          3

#define HC_LZMA_FILTER_LZMA1    0x4000000000000001ULL
#define HC_LZMA_FILTER_LZMA2    0x21ULL

#define HC_LZMA_VLI_UNKNOWN     0xffffffffffffffffULL

// Several .xz streams written one after another are one file, and reading past the first is what
// this flag asks for. The reader it replaces did the same.

#define HC_LZMA_CONCATENATED    0x08

// No limit. hashcat opens files a user pointed it at, and a decoder that refuses one for its
// dictionary size would be rejecting the user's own wordlist.

#define HC_LZMA_MEMLIMIT_NONE   0xffffffffffffffffULL

// The properties a 7-Zip archive carries for its coder: 5 bytes for LZMA1, 1 byte for LZMA2.

#define HC_LZMA1_PROPS_SIZE     5
#define HC_LZMA2_PROPS_SIZE     1

typedef struct hc_lzma_lib
{
  int (*lzma_raw_decoder)        (hc_lzma_stream *strm, const hc_lzma_filter *filters);
  int (*lzma_properties_decode)  (hc_lzma_filter *filter, const void *allocator, const unsigned char *props, size_t props_size);
  int (*lzma_code)               (hc_lzma_stream *strm, int action);
  void (*lzma_end)               (hc_lzma_stream *strm);

  // the .xz container, and its index, which is where the uncompressed size comes from

  int  (*lzma_stream_decoder)           (hc_lzma_stream *strm, u64 memlimit, u32 flags);
  int  (*lzma_file_info_decoder)        (hc_lzma_stream *strm, void **dest_index, u64 memlimit, u64 file_size);
  u64  (*lzma_index_uncompressed_size)  (const void *i);
  void (*lzma_index_end)                (void *i, const void *allocator);

  hc_dynlib_t lib;

} hc_lzma_lib_t;

void hc_lzma_boot     (void);
void hc_lzma_shutdown (void);

const hc_lzma_lib_t *hc_lzma       (void);
const char          *hc_lzma_error (void);
const char          *hc_lzma_hint  (void);

// A raw LZMA1 or LZMA2 stream, decompressed in one call. Both answer false unless the output buffer
// was filled: every caller asks for a length it already knows and uses all of it, so a short answer
// is a failure rather than a partial success.

HC_PLUGIN_API bool hc_lzma1_decompress (const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const char *props);
HC_PLUGIN_API bool hc_lzma2_decompress (const unsigned char *in, size_t *in_len, unsigned char *out, size_t *out_len, const char *props);

#endif // HC_EXT_LZMA_H
