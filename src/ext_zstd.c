/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Thin wrapper around the bundled single-file zstd decoder (zstddeclib.c),
 * mirroring the existing ext_lzma.c pattern.
 */

#include "common.h"
#include "types.h"
#include "ext_zstd.h"

/* the single-file zstd decoder is self-contained (no external includes) */
#include "zstddeclib.c"

int hc_zstd_decompress (unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len)
{
  /*
   * ZSTD_decompress() requires srcSize to be *exactly* the size of the
   * frame: any trailing bytes (e.g. AES-CBC padding) make it fail with
   * srcSize_wrong. The caller (module_11600.c) therefore passes the
   * frame size (the 7z "unpack_size" of the AES coder), not the padded
   * AES buffer length.
   */

  const size_t capacity = *out_len;

  const size_t ret = ZSTD_decompress (out, capacity, in, in_len);

  if (ZSTD_isError (ret)) return -1;

  *out_len = ret;

  return 0;
}
