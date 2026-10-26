/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_jtag.h"

#include <stdio.h>
#include <string.h>

static bool tms_bits (jtag_ctx_t *ctx, const u8 bits, const u32 count)
{
  const u8 cmd[3] = { MPSSE_TMS_OUT_BITS, (u8) (count - 1), bits };

  return ftdi_write (ctx->ftdi, cmd, sizeof (cmd));
}

bool jtag_init (jtag_ctx_t *ctx, ftdi_ctx_t *ftdi)
{
  memset (ctx, 0, sizeof (jtag_ctx_t));

  ctx->ftdi = ftdi;

  return true;
}

bool jtag_reset (jtag_ctx_t *ctx)
{
  if (tms_bits (ctx, 0x1F, 5) == false) return false;
  if (tms_bits (ctx, 0x00, 1) == false) return false;

  return true;
}

static bool shift_reg (jtag_ctx_t *ctx, const u8 to_shift, const u32 to_shift_len, const u8 *out, u8 *in, const u32 bits)
{
  if (bits == 0) return false;

  if (tms_bits (ctx, to_shift, to_shift_len) == false) return false;

  const u32 full_bytes = (bits - 1) / 8;
  const u32 tail_bits  = (bits - 1) - (full_bytes * 8);

  u8 cmd[16 + 4096];

  u32 n = 0;

  if (full_bytes > 0)
  {
    cmd[n++] = MPSSE_DATA_IO_BYTES;
    cmd[n++] = (u8) ((full_bytes - 1) & 0xFF);
    cmd[n++] = (u8) ((full_bytes - 1) >> 8);

    for (u32 i = 0; i < full_bytes; i++)
    {
      cmd[n++] = (out != NULL) ? out[i] : 0x00;
    }
  }

  if (tail_bits > 0)
  {
    u8 v = 0;

    if (out != NULL)
    {
      for (u32 i = 0; i < tail_bits; i++)
      {
        const u32 idx = (full_bytes * 8) + i;

        if ((out[idx / 8] >> (idx % 8)) & 1) v |= (u8) (1 << i);
      }
    }

    cmd[n++] = MPSSE_DATA_IO_BITS;
    cmd[n++] = (u8) (tail_bits - 1);
    cmd[n++] = v;
  }

  u8 last = 0;

  if (out != NULL)
  {
    const u32 idx = bits - 1;

    last = (u8) ((out[idx / 8] >> (idx % 8)) & 1);
  }

  cmd[n++] = MPSSE_TMS_IO_BITS;
  cmd[n++] = 0x00;
  cmd[n++] = (u8) (0x01 | (last << 7));

  cmd[n++] = MPSSE_SEND_IMMEDIATE;

  if (ftdi_write (ctx->ftdi, cmd, n) == false) return false;

  if (in != NULL)
  {
    memset (in, 0, (bits + 7) / 8);

    if (full_bytes > 0)
    {
      if (ftdi_read (ctx->ftdi, in, full_bytes) == false) return false;
    }

    if (tail_bits > 0)
    {
      u8 v = 0;

      if (ftdi_read (ctx->ftdi, &v, 1) == false) return false;

      v = (u8) (v >> (8 - tail_bits));

      for (u32 i = 0; i < tail_bits; i++)
      {
        const u32 idx = (full_bytes * 8) + i;

        if ((v >> i) & 1) in[idx / 8] |= (u8) (1 << (idx % 8));
      }
    }

    u8 lastb = 0;

    if (ftdi_read (ctx->ftdi, &lastb, 1) == false) return false;

    if ((lastb >> 7) & 1) in[(bits - 1) / 8] |= (u8) (1 << ((bits - 1) % 8));
  }
  else
  {
    u8 discard[4096];

    size_t n = full_bytes + ((tail_bits > 0) ? 1 : 0) + 1;

    if (n > sizeof (discard)) n = sizeof (discard);

    if (ftdi_read (ctx->ftdi, discard, n) == false) return false;
  }

  if (tms_bits (ctx, 0x01, 2) == false) return false;

  return true;
}

bool jtag_shift_dr (jtag_ctx_t *ctx, const u8 *out, u8 *in, const u32 bits)
{
  return shift_reg (ctx, 0x01, 3, out, in, bits);
}

bool jtag_shift_ir (jtag_ctx_t *ctx, const u8 *out, u8 *in, const u32 bits)
{
  return shift_reg (ctx, 0x03, 4, out, in, bits);
}

bool jtag_scan_chain (jtag_ctx_t *ctx)
{
  if (jtag_reset (ctx) == false) return false;

  u8 buf[JTAG_MAX_CHAIN * 4];

  memset (buf, 0, sizeof (buf));

  if (jtag_shift_dr (ctx, NULL, buf, JTAG_MAX_CHAIN * 32) == false) return false;

  ctx->num_taps = 0;

  for (u32 i = 0; i < JTAG_MAX_CHAIN; i++)
  {
    const u32 v = ((u32) buf[(i * 4) + 0] <<  0)
                | ((u32) buf[(i * 4) + 1] <<  8)
                | ((u32) buf[(i * 4) + 2] << 16)
                | ((u32) buf[(i * 4) + 3] << 24);

    if (v == 0xFFFFFFFF) break;
    if (v == 0x00000000) break;
    if ((v & 1) == 0) break;

    ctx->idcode[ctx->num_taps] = v;

    ctx->num_taps++;
  }

  return true;
}

bool jtag_shift_dr_stream (jtag_ctx_t *ctx, const u8 *data, const size_t len)
{
  if (len == 0) return false;

  if (tms_bits (ctx, 0x01, 3) == false) return false;

  u8 cmd[3 + 509];

  size_t off = 0;

  while (off < len)
  {
    size_t chunk = len - off;

    if (chunk > 509) chunk = 509;

    cmd[0] = MPSSE_DATA_OUT_BYTES_MSB;
    cmd[1] = (u8) ((chunk - 1) & 0xFF);
    cmd[2] = (u8) ((chunk - 1) >> 8);

    memcpy (&cmd[3], &data[off], chunk);

    if (ftdi_write (ctx->ftdi, cmd, 3 + chunk) == false) return false;

    off += chunk;
  }

  const u8 tms_last[3] = { MPSSE_TMS_OUT_BITS, 0x00, 0x01 };

  if (ftdi_write (ctx->ftdi, tms_last, sizeof (tms_last)) == false) return false;

  if (tms_bits (ctx, 0x01, 2) == false) return false;

  return true;
}

bool jtag_runtest (jtag_ctx_t *ctx, const u32 cycles)
{
  u32 bytes = (cycles + 7) / 8;

  while (bytes > 0)
  {
    const u32 chunk = (bytes > 65536) ? 65536 : bytes;

    const u8 cmd[3] = { MPSSE_CLOCK_ONLY_BYTES, (u8) ((chunk - 1) & 0xFF), (u8) ((chunk - 1) >> 8) };

    if (ftdi_write (ctx->ftdi, cmd, sizeof (cmd)) == false) return false;

    bytes -= chunk;
  }

  return true;
}
