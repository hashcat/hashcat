/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"

#include "fpga/hcfpga.h"
#include "fpga/ztex_tool_ctx.h"
#include "fpga/ztex_usb.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *status_name (const fpga_status_t status)
{
  switch (status)
  {
    case FPGA_STATUS_OK:             return "OK";
    case FPGA_STATUS_UNSUPPORTED_OS: return "UNSUPPORTED_OS";
    case FPGA_STATUS_NO_PCI_DEVICE:  return "NO_DEVICE";
    case FPGA_STATUS_NO_CHAR_DEVICE: return "NO_CHAR_DEVICE";
    case FPGA_STATUS_NO_PERMISSION:  return "NO_PERMISSION";
    case FPGA_STATUS_CSR_WINDOW:     return "CSR_WINDOW";
    case FPGA_STATUS_BAD_IDENT:      return "BAD_IDENT";
    case FPGA_STATUS_WRONG_ALGO:     return "WRONG_ALGO";
    case FPGA_STATUS_ABI_MISMATCH:   return "ABI_MISMATCH";
    case FPGA_STATUS_NO_BITSTREAM:   return "NO_BITSTREAM";
  }

  return "?";
}

int main (int argc, char **argv)
{
  const char *dir = (argc > 1) ? argv[1] : NULL;

  const char *algo = (argc > 2) ? argv[2] : "bcrypt";

  hashcat_ctx_t *hashcat_ctx = ztex_tool_ctx (dir);

  const char *want = getenv ("HCFPGA_TRANSPORT");

  if (want == NULL) want = "ztex115y";

  const fpga_transport_t *transport = NULL;

  for (int i = 0; i < fpga_transports_cnt; i++)
  {
    if (strcmp (fpga_transports[i]->name, want) != 0) continue;

    transport = fpga_transports[i];

    break;
  }

  if (transport == NULL)
  {
    printf ("no transport named %s. HCFPGA_TRANSPORT picks one of:", want);

    for (int i = 0; i < fpga_transports_cnt; i++) printf (" %s", fpga_transports[i]->name);

    printf ("\n");

    return 1;
  }

  printf ("transport      %s\n\n", transport->name);

  fpga_dev_t devs[FPGA_MAX_DEVICES];

  fpga_status_t status = FPGA_STATUS_OK;

  const int cnt = transport->enumerate (hashcat_ctx, devs, FPGA_MAX_DEVICES, &status);

  printf ("enumerate      %d unit(s)", cnt);

  if (cnt == 0) printf (", status %s", status_name (status));

  printf ("\n\n");

  if (cnt == 0) return 1;

  for (int i = 0; i < cnt; i++)
  {
    fpga_dev_t *dev = &devs[i];

    dev->transport = transport;

    printf ("unit %d\n", i);
    printf ("  path         %s\n", dev->path);

    if (dir)
    {
      const fpga_status_t prog = transport->program (hashcat_ctx, dev, algo);

      const bool ok = (prog == FPGA_STATUS_OK);

      printf ("  program      %s\n", (ok == true) ? "ok" : status_name (prog));

      if (ok == false)
      {
        printf ("\n");

        continue;
      }
    }

    const fpga_status_t st = transport->identify (dev);

    printf ("  identify     %s\n", status_name (st));
    printf ("  board        %s\n", dev->ident.board);

    if (st == FPGA_STATUS_OK)
    {
      printf ("  algo         %s\n", dev->ident.algo);
      printf ("  cores        %u\n", dev->ident.cores);
      printf ("  clk          %u MHz\n", dev->ident.clk_mhz);
      printf ("  raw          %s\n", dev->ident.raw);
    }

    if (dev->transport->csr_read && (strcmp (transport->name, "ztex213") == 0))
    {
      const u32 in_words  = transport->csr_read (dev, 0x18 << 2);
      const u32 out_words = transport->csr_read (dev, 0x19 << 2);
      const u32 status    = transport->csr_read (dev, 0x06 << 2);

      printf ("  moved in     %u words = %u records\n", in_words, in_words / 32);
      printf ("  moved out    %u halfwords = %u frames\n", out_words, out_words / 16);
      printf ("  frame_status %08x\n", status);

      if (ztex_claim (dev->fd) == true)
      {
        u8 sink[512];

        u32 drained = 0;

        for (u32 k = 0; k < 64; k++)
        {
          const int got = ztex_bulk_in (dev->fd, 2, sink, sizeof (sink), 300);

          if (got <= 0) break;

          drained += (u32) got;
        }

        printf ("  drained      %u bytes = %u frames left in the microcontroller\n", drained, drained / 32);
      }
    }

    if (transport->temperature)
    {
      const int c = transport->temperature (dev);

      if (c >= 0) printf ("  die temp     %d C\n", c);
      else        printf ("  die temp     unavailable\n");
    }

    printf ("\n");
  }

  for (int i = 0; i < cnt; i++)
  {
    transport->close (&devs[i]);
  }

  return 0;
}
