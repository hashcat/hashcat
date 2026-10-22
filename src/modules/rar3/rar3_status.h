/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_RAR3_STATUS_H
#define HC_RAR3_STATUS_H

// Why an unpack produced no usable CRC32, rather than only that it did not. Every value but
// HC_RAR3_UNPACK_OK means the CRC32 must be ignored, so a caller tests for that and never for one
// particular failure.

typedef enum hc_rar3_unpack_status
{
  HC_RAR3_UNPACK_OK           = 0, // unpacked to the expected length
  HC_RAR3_UNPACK_SHORT_OUTPUT = 1, // the unpack stopped before the expected length
  HC_RAR3_UNPACK_REJECTED_PPM = 2, // the PPM block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_REJECTED_LZ  = 3, // the LZ block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_UNSUPPORTED  = 4, // the stream uses a construct the decoder does not implement

} hc_rar3_unpack_status_t;

#endif // HC_RAR3_STATUS_H
