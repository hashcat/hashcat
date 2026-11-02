/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_loader.h"
#include "artyz7_ps7_init.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ARTY_VID     0x0403
#define ARTY_PID     0x6010
#define ARTY_SERIAL  NULL

#define TCK_HZ       1000000

#define LOG_MAGIC    0x00010000
#define LOG_COUNT    0x00010004
#define LOG_STATE    0x00010008

#define LOG_MAGIC_VALUE   0xB0DEC0DE
#define LOG_STATE_RUNNING 2
#define LOG_STATE_NOSHELL 3

#define SLCR_PSS_IDCODE   0xF8000530

#define SLCR_GEM0_CLK     0xF8000140
#define SLCR_MIO_PIN_16   0xF8000740

int main (int argc, char **argv)
{
  const char *elf    = NULL;
  const char *serial = ARTY_SERIAL;

  if (argc > 1) elf    = argv[1];
  if (argc > 2) serial = argv[2];

  if (elf == NULL)
  {
    printf ("usage: %s <app.bin> [ftdi-serial]\n", argv[0]);

    return 1;
  }

  printf ("Arty Z7-20 loader, usbfs only\n\n");

  ftdi_ctx_t ftdi;

  if (ftdi_open (&ftdi, ARTY_VID, ARTY_PID, serial) == false) return 1;
  if (ftdi_mpsse_enable (&ftdi, TCK_HZ) == false) { ftdi_close (&ftdi); return 1; }
  if (ftdi_mpsse_sync (&ftdi) == false)           { ftdi_close (&ftdi); return 1; }

  jtag_ctx_t jtag;

  jtag_init (&jtag, &ftdi);

  if (jtag_scan_chain (&jtag) == false) { ftdi_close (&ftdi); return 1; }

  printf ("  chain: %u taps, PL 0x%08X, DAP 0x%08X\n", jtag.num_taps, jtag.idcode[0], jtag.idcode[1]);

  dap_ctx_t dap;

  if (dap_init (&dap, &jtag) == false) { ftdi_close (&ftdi); return 1; }

  u32 pss = 0;

  dap_mem_read32 (&dap, SLCR_PSS_IDCODE, &pss);

  printf ("  PSS_IDCODE = 0x%08X\n\n", pss);

  printf ("  replaying ps7_init, %d operations\n", PS7_INIT_OPS);

  if (artyz7_ps7_init (&dap) == false) { ftdi_close (&ftdi); return 1; }

  u32 gem = 0;
  u32 mio = 0;

  dap_mem_read32 (&dap, SLCR_GEM0_CLK,   &gem);
  dap_mem_read32 (&dap, SLCR_MIO_PIN_16, &mio);

  printf ("    GEM0_CLK_CTRL = 0x%08X   (expect 0x00100801)\n", gem);
  printf ("    MIO_PIN_16    = 0x%08X   (expect 0x00001202, L0_SEL for RGMII)\n\n", mio);

  dap_mem_write32 (&dap, LOG_MAGIC, 0x00000000);
  dap_mem_write32 (&dap, LOG_STATE, 0x00000000);
  dap_mem_write32 (&dap, LOG_COUNT, 0x00000000);

  printf ("  loading %s\n", elf);

  if (artyz7_load_binary (&dap, elf) == false) { ftdi_close (&ftdi); return 1; }

  int millic = 0;

  if (artyz7_temperature (&dap, &millic) == true)
  {
    printf ("  die temperature before start: %d.%d C\n", millic / 1000, (millic % 1000) / 100);
  }

  printf ("\n  starting CPU0\n");

  if (artyz7_start_cpu (&dap) == false) { ftdi_close (&ftdi); return 1; }

  sleep (2);

  u32 magic = 0;
  u32 state = 0;
  u32 count = 0;

  dap_mem_read32 (&dap, LOG_MAGIC, &magic);
  dap_mem_read32 (&dap, LOG_STATE, &state);
  dap_mem_read32 (&dap, LOG_COUNT, &count);

  printf ("    log magic = 0x%08X   state = %u   samples = %u\n\n", magic, state, count);

  ftdi_close (&ftdi);

  if (magic != LOG_MAGIC_VALUE)
  {
    printf ("  FAIL  the application never wrote its signature, so it did not run\n");

    return 1;
  }

  printf ("  PASS  the application ran and is writing its log\n");

  if (state == LOG_STATE_NOSHELL)
  {
    printf ("  note  it could not see the PL, so no bitstream is loaded. That is expected if the\n");
    printf ("        fabric was not programmed: this loader does not program it.\n");
  }

  return 0;
}
