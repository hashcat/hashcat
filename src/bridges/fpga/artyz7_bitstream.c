/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_bitstream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PL_IR_CFG_OUT     0x04
#define PL_IR_CFG_IN      0x05
#define PL_IR_IDCODE      0x09
#define PL_IR_JPROGRAM    0x0B
#define PL_IR_JSTART      0x0C
#define PL_IR_BYPASS      0x3F

#define DAP_IR_BYPASS_4   0xF

#define IR_STATUS_ISC_DONE   (1u << 1)
#define IR_STATUS_ISC_ENA    (1u << 2)
#define IR_STATUS_INIT       (1u << 3)
#define IR_STATUS_DONE       (1u << 4)

static bool pl_ir (jtag_ctx_t *jtag, const u8 instr, u32 *status)
{
  const u32 ir = ((u32) DAP_IR_BYPASS_4 << 6) | (instr & 0x3F);

  u8 out[2];
  u8 in[2];

  out[0] = (u8) (ir & 0xFF);
  out[1] = (u8) ((ir >> 8) & 0xFF);

  memset (in, 0, sizeof (in));

  if (jtag_shift_ir (jtag, out, in, 10) == false) return false;

  if (status != NULL) *status = (u32) (in[0] & 0x3F);

  return true;
}

bool artyz7_pl_blank (jtag_ctx_t *jtag)
{
  if (pl_ir (jtag, PL_IR_JPROGRAM, NULL) == false) return false;

  if (pl_ir (jtag, PL_IR_BYPASS, NULL) == false) return false;

  return jtag_runtest (jtag, 120000);
}

bool artyz7_load_bitstream (jtag_ctx_t *jtag, const char *path)
{
  FILE *f = fopen (path, "rb");

  if (f == NULL)
  {
    fprintf (stderr, "artyz7: cannot open %s\n", path);

    return false;
  }

  fseek (f, 0, SEEK_END);

  const long size = ftell (f);

  fseek (f, 0, SEEK_SET);

  if (size <= 0)
  {
    fclose (f);

    return false;
  }

  u8 *img = malloc ((size_t) size);

  if (img == NULL)
  {
    fclose (f);

    return false;
  }

  const bool read_ok = (fread (img, 1, (size_t) size, f) == (size_t) size);

  fclose (f);

  if (read_ok == false)
  {
    free (img);

    return false;
  }

  bool synced = false;

  for (long i = 0; (i + 4) <= size; i++)
  {
    if ((img[i] == 0xAA) && (img[i + 1] == 0x99) && (img[i + 2] == 0x55) && (img[i + 3] == 0x66))
    {
      synced = true;

      break;
    }

    if (i > 256) break;
  }

  if (synced == false)
  {
    fprintf (stderr, "artyz7: %s has no sync word near its start, so it is not a raw bitstream\n", path);
    fprintf (stderr, "artyz7: build with write_bitstream -bin_file, or strip the .bit container\n");

    free (img);

    return false;
  }

  const u8 *rev = img;
  const u32 len = (u32) size;

  artyz7_say ("  bitstream %u bytes\n", len);

  if (jtag_reset (jtag) == false)         { free (img); return false; }

  if (artyz7_pl_blank (jtag) == false) { free (img); return false; }

  if (pl_ir (jtag, PL_IR_CFG_IN, NULL) == false)   { free (img); return false; }

  if (jtag_shift_dr_stream (jtag, rev, len) == false)
  {
    free (img);

    return false;
  }

  free (img);

  if (pl_ir (jtag, PL_IR_JSTART, NULL) == false) return false;

  if (jtag_runtest (jtag, 2000) == false) return false;

  if (jtag_reset (jtag) == false) return false;

  u32 st = 0;

  if (pl_ir (jtag, PL_IR_BYPASS, &st) == false) return false;

  artyz7_say ("  IR status 0x%02X  init=%u isc_done=%u done=%u\n", st,
          (st & IR_STATUS_INIT)     ? 1u : 0u,
          (st & IR_STATUS_ISC_DONE) ? 1u : 0u,
          (st & IR_STATUS_DONE)     ? 1u : 0u);

  if ((st & IR_STATUS_DONE) == 0)
  {
    fprintf (stderr, "artyz7: configuration finished but DONE never asserted\n");

    return false;
  }

  return true;
}

bool artyz7_cfg_status (jtag_ctx_t *jtag, u32 *stat)
{
  static const u8 CMD[] =
  {
    0xFF, 0xFF, 0xFF, 0xFF,
    0xAA, 0x99, 0x55, 0x66,
    0x20, 0x00, 0x00, 0x00,
    0x28, 0x00, 0xE0, 0x01,
    0x20, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
  };

  if (pl_ir (jtag, PL_IR_CFG_IN, NULL) == false) return false;
  if (jtag_shift_dr_stream (jtag, CMD, sizeof (CMD)) == false) return false;

  if (pl_ir (jtag, PL_IR_CFG_OUT, NULL) == false) return false;

  u8 in[8];

  memset (in, 0, sizeof (in));

  if (jtag_shift_dr (jtag, NULL, in, 33) == false) return false;

  u32 v = 0;

  for (u32 i = 0; i < 32; i++)
  {
    if ((in[i / 8] >> (i % 8)) & 1) v |= (1u << (31 - i));
  }

  *stat = v;

  return true;
}

void artyz7_print_cfg_status (const u32 s)
{
  artyz7_say ("  STAT = 0x%08X\n", s);
  artyz7_say ("    CRC_ERROR     %u   <- 1 means the bitstream did not arrive intact\n", (s >> 0)  & 1);
  artyz7_say ("    ID_ERROR      %u   <- 1 means it was built for a different part\n",   (s >> 2)  & 1);
  artyz7_say ("    DONE          %u\n", (s >> 3)  & 1);
  artyz7_say ("    RELEASE_DONE  %u\n", (s >> 4)  & 1);
  artyz7_say ("    INIT_B        %u\n", (s >> 5)  & 1);
  artyz7_say ("    INIT_COMPLETE %u\n", (s >> 6)  & 1);
  artyz7_say ("    GHIGH_B       %u\n", (s >> 10) & 1);
  artyz7_say ("    GWE           %u   <- 0 means every flip flop is still held\n", (s >> 11) & 1);
  artyz7_say ("    GTS_CFG_B     %u\n", (s >> 12) & 1);
  artyz7_say ("    EOS           %u   <- 1 means the startup sequence actually finished\n", (s >> 13) & 1);
}
