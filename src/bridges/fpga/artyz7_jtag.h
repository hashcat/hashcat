/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARTYZ7_JTAG_H
#define HC_ARTYZ7_JTAG_H

#include "artyz7_ftdi.h"

#define MPSSE_TMS_OUT_BITS      0x4B
#define MPSSE_TMS_IO_BITS       0x6B
#define MPSSE_DATA_IO_BYTES     0x39
#define MPSSE_DATA_IO_BITS      0x3B
#define MPSSE_DATA_OUT_BYTES    0x19
#define MPSSE_DATA_OUT_BYTES_MSB 0x11
#define MPSSE_DATA_OUT_BITS     0x1B

#define MPSSE_SEND_IMMEDIATE    0x87

#define MPSSE_CLOCK_ONLY_BYTES  0x8F

#define JTAG_MAX_CHAIN          16

typedef struct jtag_ctx
{
  ftdi_ctx_t *ftdi;

  u32 num_taps;
  u32 idcode[JTAG_MAX_CHAIN];

} jtag_ctx_t;

bool jtag_init      (jtag_ctx_t *ctx, ftdi_ctx_t *ftdi);
bool jtag_reset     (jtag_ctx_t *ctx);
bool jtag_scan_chain (jtag_ctx_t *ctx);

bool jtag_shift_dr  (jtag_ctx_t *ctx, const u8 *out, u8 *in, const u32 bits);
bool jtag_shift_ir  (jtag_ctx_t *ctx, const u8 *out, u8 *in, const u32 bits);

bool jtag_shift_dr_stream (jtag_ctx_t *ctx, const u8 *data, const size_t len);

bool jtag_runtest (jtag_ctx_t *ctx, const u32 cycles);

#endif
