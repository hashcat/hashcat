/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * ZSTD decompression support for hashcat's 7-Zip module (mode 11600).
 * Uses the single-file zstd decoder (zstddeclib.c) bundled with hashcat.
 */

#ifndef HC_EXT_ZSTD_H
#define HC_EXT_ZSTD_H

#include <stddef.h>

/*
 * Decompress a zstd frame.
 *
 * in     : the compressed (zstd frame) data
 * in_len : exact size of the zstd frame (NOT the padded AES buffer size)
 * out    : output buffer, must be large enough for the whole frame
 * out_len: on entry the capacity of `out`; on success the decompressed size
 *
 * Returns 0 on success, -1 on error.
 */
int hc_zstd_decompress (unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len);

#endif // HC_EXT_ZSTD_H
