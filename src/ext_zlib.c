/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "ext_zlib.h"

// A raw deflate stream, which is what zlib calls a negative window size, decompressed in one call.
// A 7-Zip archive holds one of these when its coder is DEFLATE.

bool hc_inflate_raw (const unsigned char *in, const size_t in_len, unsigned char *out, const size_t out_len)
{
  z_stream inf;

  inf.zalloc = Z_NULL;
  inf.zfree  = Z_NULL;
  inf.opaque = Z_NULL;

  inf.avail_in = in_len;
  inf.next_in  = (unsigned char *) in;

  inf.avail_out = out_len;
  inf.next_out  = out;

  if (inflateInit2 (&inf, -MAX_WBITS) != Z_OK) return false;

  const int rc = inflate (&inf, Z_NO_FLUSH);

  inflateEnd (&inf);

  if (rc == Z_OK) return true;
  if (rc == Z_STREAM_END) return true;

  return false;
}
