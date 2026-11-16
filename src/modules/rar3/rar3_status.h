/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_RAR3_STATUS_H
#define HC_RAR3_STATUS_H

// Why an unpack produced no usable CRC32, rather than only that it did not. Every value but
// HC_RAR3_UNPACK_OK means the CRC32 must be ignored, so a caller tests for that and never for one
// particular failure.
//
// Zero is what a hook entry holds when the host hook never ran for it, because the hook buffer is
// cleared after every chunk. A stopping attack skips the host hooks and still runs the compare
// kernel, so zero must not be the value that lets it compare.

typedef enum hc_rar3_unpack_status
{
  HC_RAR3_UNPACK_NOT_RUN      = 0, // the host hook did not run for this candidate
  HC_RAR3_UNPACK_OK           = 1, // unpacked to the expected length
  HC_RAR3_UNPACK_SHORT_OUTPUT = 2, // the unpack stopped before the expected length
  HC_RAR3_UNPACK_REJECTED_PPM = 3, // the PPM block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_REJECTED_LZ  = 4, // the LZ block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_UNSUPPORTED  = 5, // the stream uses a construct the decoder does not implement

} hc_rar3_unpack_status_t;

#endif // HC_RAR3_STATUS_H
