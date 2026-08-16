/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_ZLIB_H
#define HC_EXT_ZLIB_H

// What hashcat asks zlib for on behalf of a hash line, next to what it asks the LZMA SDK for in
// ext_lzma.h. A plugin calls this instead of zlib, so zlib's own interface stays inside the core.

#include <zlib.h>

HC_PLUGIN_API bool hc_inflate_raw (const unsigned char *in, const size_t in_len, unsigned char *out, const size_t out_len);

#endif // HC_EXT_ZLIB_H
