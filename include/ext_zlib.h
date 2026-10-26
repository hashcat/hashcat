/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_ZLIB_H
#define HC_EXT_ZLIB_H

#include "dynloader.h"

#include <stdarg.h>

// What hashcat asks zlib for on behalf of a hash line, next to what it asks liblzma for in
// ext_lzma.h. A plugin calls this instead of zlib, so zlib's own interface stays inside the core.
//
// zlib is opened at runtime with dlopen rather than linked. A box then needs the runtime library
// and not the development package, and those are separate packages on most distributions with only
// the first normally installed. Nothing here includes zlib.h, so nothing in the tree needs it.

// A gzip handle is a pointer zlib hands back and that hashcat only ever hands to zlib again, so
// what it points at does not have to be known here.

typedef void *hc_gzfile_t;

// This one is different. inflate () reads and writes the caller's stream, so the layout has to be
// the layout zlib was built with. Every member below is written with the type zlib's own header
// uses, which makes the size agree on each platform without repeating zlib's own conditionals.
// inflateInit2_ () is handed that size and answers HC_Z_VERSION_ERROR when it disagrees, so a
// mismatch is a clean refusal at the first call rather than memory corruption later on.

typedef struct hc_z_stream
{
  unsigned char *next_in;
  unsigned int   avail_in;
  unsigned long  total_in;

  unsigned char *next_out;
  unsigned int   avail_out;
  unsigned long  total_out;

  const char    *msg;
  void          *state;

  void *(*zalloc) (void *opaque, unsigned int items, unsigned int size);
  void  (*zfree)  (void *opaque, void *address);
  void   *opaque;

  int            data_type;
  unsigned long  adler;
  unsigned long  reserved;

} hc_z_stream;

#define HC_Z_OK             0
#define HC_Z_STREAM_END     1
#define HC_Z_VERSION_ERROR (-6)

#define HC_Z_NO_FLUSH       0
#define HC_Z_SYNC_FLUSH     2

#define HC_Z_MAX_WBITS     15

// inflateInit2_ () compares only the first character of this against the version it was built as,
// so any 1.x string names the ABI this file describes.

#define HC_ZLIB_VERSION "1.2.11"

typedef struct hc_zlib_lib
{
  hc_gzfile_t (*gzopen64)  (const char *path, const char *mode);
  int         (*gzbuffer)  (hc_gzfile_t file, unsigned int size);
  int         (*gzread)    (hc_gzfile_t file, void *buf, unsigned int len);
  int         (*gzwrite)   (hc_gzfile_t file, const void *buf, unsigned int len);
  const char *(*gzerror)   (hc_gzfile_t file, int *errnum);
  long long   (*gzseek64)  (hc_gzfile_t file, long long offset, int whence);
  int         (*gzrewind)  (hc_gzfile_t file);
  long long   (*gztell64)  (hc_gzfile_t file);
  int         (*gzputc)    (hc_gzfile_t file, int c);
  int         (*gzgetc)    (hc_gzfile_t file);
  char       *(*gzgets)    (hc_gzfile_t file, char *buf, int len);
  int         (*gzvprintf) (hc_gzfile_t file, const char *format, va_list ap);
  int         (*gzeof)     (hc_gzfile_t file);
  int         (*gzflush)   (hc_gzfile_t file, int flush);
  int         (*gzclose)   (hc_gzfile_t file);

  int         (*inflateInit2_) (hc_z_stream *strm, int windowBits, const char *version, int stream_size);
  int         (*inflate)       (hc_z_stream *strm, int flush);
  int         (*inflateEnd)    (hc_z_stream *strm);

  hc_dynlib_t lib;

} hc_zlib_lib_t;

// Loading is tried once, from hashcat_init (), where there is still only one thread. A box without
// the library is not a startup failure: hashcat only cares when something asks for a gzip file, and
// hc_zlib () answering NULL is how that question gets its answer.

void hc_zlib_boot     (void);
void hc_zlib_shutdown (void);

const hc_zlib_lib_t *hc_zlib       (void);
const char          *hc_zlib_error (void);

// Where to get the library on this platform, for the one message a user sees when it is missing.

const char          *hc_zlib_hint  (void);

HC_PLUGIN_API bool hc_inflate_raw (const unsigned char *in, const size_t in_len, unsigned char *out, const size_t out_len);

#endif // HC_EXT_ZLIB_H
