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
#include <unistd.h>

#define H2C_TAG        0xbcu
#define H2C_PW_LEN     8
#define H2C_REC_WORDS  (2 + ((H2C_PW_LEN + 3) / 4))
#define H2C_REC_BYTES  (H2C_REC_WORDS * 4)

#define H2C_BATCH_ALIGN 32

#define C2H_FRAME_BYTES 32

#define REG_CTRL        0x00
#define REG_SALT0       0x01
#define REG_ITER_COUNT  0x05
#define REG_FRAME_ST    0x06
#define REG_DBG_IN      0x18
#define REG_DBG_OUT     0x19

#define REG_FLAGB_LOW   0x1a
#define REG_FLAGB_FALL  0x1b
#define REG_RESEND      0x1c

#define REG_IF_OUT_LOW  0x1d
#define REG_ARM         0x1e
#define REG_PKTEND      0x1f
#define REG_ARM_WAIT    0x20

#define CTRL_FRAMING_RESET 1

#define EP_OUT 6
#define EP_IN  2

#define ZTEX_MAXPKT 512

#define EKID_BASE 0x00000100

#define ITER_COUNT 32

static void report_flush (fpga_dev_t *dev);

static u32 csr (fpga_dev_t *dev, const u32 reg)
{
  const u32 val = dev->transport->csr_read (dev, reg << 2);

  return val;
}

static void csr_set (fpga_dev_t *dev, const u32 reg, const u32 val)
{
  dev->transport->csr_write (dev, reg << 2, val);
}

static void report_flush (fpga_dev_t *dev)
{
  const u32 if_out_low = csr (dev, REG_IF_OUT_LOW);
  const u32 arms       = csr (dev, REG_ARM);
  const u32 pktends    = csr (dev, REG_PKTEND);
  const u32 arm_wait   = csr (dev, REG_ARM_WAIT);

  printf ("flush          %u arms, %u flushes, %u cycles waiting (%u us), bus in the input direction for %u cycles (%u us)\n",
          arms, pktends, arm_wait, arm_wait / 48, if_out_low, if_out_low / 48);

  if ((arms == 0) && (pktends == 0)) return;

  printf ("\n");

  if (arms > pktends)
  {
    printf ("*** %u flushes were asked for and %u happened, so %u request(s) were starved.\n", arms, pktends, arms - pktends);
    printf ("*** They waited %u cycles in total, %u us, with the bus in the input direction for\n", arm_wait, arm_wait / 48);
    printf ("*** %u cycles of the run. A wait near the host's thirty second timeout is the fault; a\n", if_out_low);
    printf ("*** wait of a few cycles per flush is what healthy looks like.\n");
  }
  else
  {
    printf ("*** Every flush that was asked for happened, %u of %u, after %u cycles (%u us) of\n", pktends, arms, arm_wait, arm_wait / 48);
    printf ("*** waiting in total. So nothing is being held off. If results are still missing, then\n");
    printf ("*** nothing ASKED for the flush that would have moved them, and the arming is where to\n");
    printf ("*** look, not the gate.\n");
  }
}

static u32 fill_batch (u32 *h2c, const u32 cands)
{
  for (u32 i = 0; i < cands; i++)
  {
    u32 *rec = &h2c[i * H2C_REC_WORDS];

    rec[0] = (H2C_TAG << 24) | H2C_PW_LEN;
    rec[1] = EKID_BASE + i;
    rec[2] = 0x70617373;
    rec[3] = 0x776f7264;
  }

  const u32 used = cands * H2C_REC_BYTES;

  const u32 tail = used % H2C_BATCH_ALIGN;

  if (tail == 0) return used;

  const u32 pad = H2C_BATCH_ALIGN - tail;

  memset ((u8 *) h2c + used, 0, pad);

  const u32 padded = used + pad;

  return padded;
}

#define WAIT_SLICE_MS 2

static void mode_bridge (fpga_dev_t *dev, const u32 batches, const u32 cands, const u32 deadline_ms, const u32 slice_ms)
{
  const u32 want = cands * C2H_FRAME_BYTES;

  u32 *h2c = (u32 *) malloc ((cands * H2C_REC_BYTES) + H2C_BATCH_ALIGN);
  u8  *rx  = (u8 *)  malloc (want + 4096);

  if ((h2c == NULL) || (rx == NULL))
  {
    free (h2c);
    free (rx);

    return;
  }

  const u32 h2c_bytes = fill_batch (h2c, cands);

  printf ("bridge mode    %u batches of %u candidates, %u bytes out and %u back per batch\n", batches, cands, h2c_bytes, want);
  printf ("               reads of %u bytes with a %u ms slice, %u ms before a batch is called dead\n\n", ZTEX_MAXPKT, slice_ms, deadline_ms);

  u32 stalls = 0;

  u64 timeouts = 0;

  for (u32 b = 0; b < batches; b++)
  {
    dev->transport->batch_begin (dev, h2c_bytes, want, C2H_FRAME_BYTES, 0);

    if (dev->transport->batch_send (dev, h2c, h2c_bytes) == false)
    {
      printf ("batch %-4u  the write did not complete\n", b);

      dev->transport->batch_end (dev);

      stalls++;

      continue;
    }

    const u32 out_at_send = csr (dev, REG_DBG_OUT);

    u32 got_total = 0;
    u32 packets   = 0;
    u32 quiet_ms  = 0;

    u32 pkt[64];

    while (got_total < want)
    {
      u64 bytes = 0;

      const void *buf = dev->transport->batch_recv (dev, &bytes, slice_ms);

      if ((buf != NULL) && (bytes > 0))
      {
        if (packets < 64) pkt[packets] = (u32) bytes;

        packets++;

        memcpy (rx + got_total, buf, (size_t) bytes);

        got_total += (u32) bytes;
        quiet_ms   = 0;

        continue;
      }

      timeouts++;

      quiet_ms += (slice_ms > 0) ? slice_ms : 1;

      if (quiet_ms >= deadline_ms) break;
    }

    if (got_total >= want)
    {
      dev->transport->batch_end (dev);

      continue;
    }

    stalls++;

    const u32 out_now = csr (dev, REG_DBG_OUT);

    printf ("batch %-4u  STALLED with %u of %u bytes in %u packets:", b, got_total, want, packets);

    for (u32 i = 0; (i < packets) && (i < 64); i++) printf (" %u", pkt[i]);

    printf ("\n");

    printf ("            shell reports %u half words this batch = %u bytes = %u frames\n",
            out_now - out_at_send, (out_now - out_at_send) * 2, (out_now - out_at_send) / 16);

    if (((out_now - out_at_send) * 2) > got_total)
    {
      printf ("            so %u bytes left the shell and never reached the host\n", ((out_now - out_at_send) * 2) - got_total);
    }
    else
    {
      printf ("            so the shell never produced them: this is the ARRAY being short, not the wire\n");
    }

    u8 sink[512];

    u32 drained = 0;

    for (u32 k = 0; k < 64; k++)
    {
      const int got = ztex_bulk_in (dev->fd, EP_IN, sink, sizeof (sink), 50);

      if (got <= 0) break;

      drained += (u32) got;
    }

    printf ("            %u bytes drained afterwards\n", drained);

    csr_set (dev, REG_CTRL, CTRL_FRAMING_RESET);
    csr_set (dev, REG_CTRL, 0);

    dev->transport->batch_end (dev);
  }

  printf ("\n%u of %u batches came up short, over %llu reads that timed out", stalls, batches, (unsigned long long) timeouts);

  if (stalls > 0) printf (", so one loss per %llu timeouts", (unsigned long long) (timeouts / stalls));

  printf ("\n\n");

  free (h2c);
  free (rx);
}

static void usage (void)
{
  printf ("usage: ztex_flagb <bitstream dir> <mode> [args]\n");
  printf ("\n");
  printf ("  read                       the counters only, no programming, so a hashcat run can be read\n");
  printf ("  stall  [cands] [ms]        write a batch, wait, then read. Fills the endpoint on purpose.\n");
  printf ("  bridge [batches] [cands] [slice ms]\n");
  printf ("                             the bridge's own pattern: write, then read immediately in\n");
  printf ("                             slices, batch after batch. This is the one that fails.\n");
  printf ("                             The slice defaults to the bridge's own 2 ms.\n");
}

int main (int argc, char **argv)
{
  const char *dir  = (argc > 1) ? argv[1] : NULL;
  const char *mode = (argc > 2) ? argv[2] : NULL;

  if ((dir == NULL) || (mode == NULL))
  {
    usage ();

    return 1;
  }

  const bool want_read   = (strcmp (mode, "read")   == 0) ? true : false;
  const bool want_stall  = (strcmp (mode, "stall")  == 0) ? true : false;
  const bool want_bridge = (strcmp (mode, "bridge") == 0) ? true : false;

  if ((want_read == false) && (want_stall == false) && (want_bridge == false))
  {
    usage ();

    return 1;
  }

  const u32 arg3 = (argc > 3) ? (u32) strtoul (argv[3], NULL, 10) : 0;
  const u32 arg4 = (argc > 4) ? (u32) strtoul (argv[4], NULL, 10) : 0;

  const u32 arg5 = (argc > 5) ? (u32) strtoul (argv[5], NULL, 10) : 0;

  const u32 batches  = (want_bridge == true) ? ((arg3 > 0) ? arg3 : 200) : 0;
  const u32 cands    = (want_bridge == true) ? ((arg4 > 0) ? arg4 : 48) : ((arg3 > 0) ? arg3 : 48);
  const u32 stall_ms = (arg4 > 0) ? arg4 : 200;

  const u32 slice_ms = (arg5 > 0) ? arg5 : WAIT_SLICE_MS;

  hashcat_ctx_t *hashcat_ctx = ztex_tool_ctx (dir);

  const fpga_transport_t *transport = NULL;

  for (int i = 0; i < fpga_transports_cnt; i++)
  {
    if (strcmp (fpga_transports[i]->name, "ztex213") != 0) continue;

    transport = fpga_transports[i];

    break;
  }

  if (transport == NULL)
  {
    printf ("this build has no ztex213 transport\n");

    return 1;
  }

  fpga_dev_t devs[FPGA_MAX_DEVICES];

  fpga_status_t status = FPGA_STATUS_OK;

  const int cnt = transport->enumerate (hashcat_ctx, devs, FPGA_MAX_DEVICES, &status);

  if (cnt == 0)
  {
    printf ("no ZTEX 2.13 found\n");

    return 1;
  }

  fpga_dev_t *dev = &devs[0];

  dev->transport = transport;

  if (want_read == true)
  {
    if (transport->identify (dev) != FPGA_STATUS_OK)
    {
      printf ("the board is not running an hcfpga design, so its registers are unavailable\n");

      return 1;
    }

    printf ("board          %s, %u cores at %u MHz\n", dev->ident.board, dev->ident.cores, dev->ident.clk_mhz);

    printf ("               counters are cumulative since the fabric was last programmed\n\n");

    printf ("moved in       %u words = %u records\n", csr (dev, REG_DBG_IN), csr (dev, REG_DBG_IN) / H2C_REC_WORDS);
    printf ("moved out      %u half words = %u frames\n", csr (dev, REG_DBG_OUT), csr (dev, REG_DBG_OUT) / 16);
    printf ("frame_status   %08x\n\n", csr (dev, REG_FRAME_ST));

    printf ("FLAGB          low for %u cycles, %u falls, %u resends\n", csr (dev, REG_FLAGB_LOW), csr (dev, REG_FLAGB_FALL), csr (dev, REG_RESEND));

    report_flush (dev);

    transport->close (dev);

    return 0;
  }

  if (transport->program (hashcat_ctx, dev, "bcrypt") != FPGA_STATUS_OK)
  {
    printf ("could not program the board\n");

    return 1;
  }

  if (transport->identify (dev) != FPGA_STATUS_OK)
  {
    printf ("the board did not identify itself after programming\n");

    return 1;
  }

  printf ("board          %s, %u cores at %u MHz\n", dev->ident.board, dev->ident.cores, dev->ident.clk_mhz);
  printf ("candidates     %u, which is %u bytes in and %u bytes of results\n", cands, cands * H2C_REC_BYTES, cands * C2H_FRAME_BYTES);

  if (want_stall == true) printf ("stall          %u ms with the host not reading\n", stall_ms);

  printf ("\n");

  csr_set (dev, REG_SALT0 + 0, 0x00010203);
  csr_set (dev, REG_SALT0 + 1, 0x04050607);
  csr_set (dev, REG_SALT0 + 2, 0x08090a0b);
  csr_set (dev, REG_SALT0 + 3, 0x0c0d0e0f);
  csr_set (dev, REG_ITER_COUNT, ITER_COUNT);

  csr_set (dev, REG_CTRL, CTRL_FRAMING_RESET);
  csr_set (dev, REG_CTRL, 0);

  if (transport->session_open (dev) == false)
  {
    printf ("could not claim the interface\n");

    return 1;
  }

  u8 sink[512];

  u32 stale = 0;

  for (u32 k = 0; k < 64; k++)
  {
    const int got = ztex_bulk_in (dev->fd, EP_IN, sink, sizeof (sink), 100);

    if (got <= 0) break;

    stale += (u32) got;
  }

  if (stale > 0) printf ("stale          %u bytes drained before the run\n\n", stale);

  if (want_bridge == true)
  {
    mode_bridge (dev, batches, cands, 2000, slice_ms);

    printf ("FLAGB          low for %u cycles, %u falls, %u resends\n", csr (dev, REG_FLAGB_LOW), csr (dev, REG_FLAGB_FALL), csr (dev, REG_RESEND));

    report_flush (dev);

    printf ("\nmoved in       %u words = %u records\n", csr (dev, REG_DBG_IN), csr (dev, REG_DBG_IN) / H2C_REC_WORDS);
    printf ("moved out      %u half words = %u frames\n", csr (dev, REG_DBG_OUT), csr (dev, REG_DBG_OUT) / 16);

    transport->session_close (dev);

    for (int i = 0; i < cnt; i++) transport->close (&devs[i]);

    return 0;
  }

  const u32 magic = csr (dev, 0x10);
  const u32 cores = csr (dev, 0x07);

  printf ("lsi check      magic=%08x cores=%u  (want 68636667)\n", magic, cores);

  const u32 in_before  = csr (dev, REG_DBG_IN);
  const u32 out_before = csr (dev, REG_DBG_OUT);

  printf ("counters       in=%u out=%u before the run\n\n", in_before, out_before);

  u32 *h2c = (u32 *) malloc ((cands * H2C_REC_BYTES) + H2C_BATCH_ALIGN);

  if (h2c == NULL) return 1;

  const u32 h2c_bytes = fill_batch (h2c, cands);

  const bool wrote = ztex_bulk_write (dev->fd, EP_OUT, h2c, h2c_bytes);

  if (wrote == false) printf ("the candidate write did not complete, which is backpressure reaching the host\n\n");

  usleep (stall_ms * 1000);

  #define PKT_MAX 512

  u32 pkt_len[PKT_MAX];
  u32 pkt_cnt = 0;

  u8 *rx = (u8 *) malloc (cands * C2H_FRAME_BYTES + 4096);

  if (rx == NULL) return 1;

  u32 rx_len = 0;

  u32 quiet = 0;

  while (quiet < 20)
  {
    const int got = ztex_bulk_in (dev->fd, EP_IN, rx + rx_len, 512, 100);

    if (got < 0) break;

    if (got == 0)
    {
      quiet++;

      continue;
    }

    quiet = 0;

    if (pkt_cnt < PKT_MAX) pkt_len[pkt_cnt] = (u32) got;

    pkt_cnt++;

    rx_len += (u32) got;

    if (rx_len >= (cands * C2H_FRAME_BYTES) + 2048) break;
  }

  const u32 in_after  = csr (dev, REG_DBG_IN);
  const u32 out_after = csr (dev, REG_DBG_OUT);

  const u32 flagb_low  = csr (dev, REG_FLAGB_LOW);
  const u32 flagb_fall = csr (dev, REG_FLAGB_FALL);
  const u32 resends    = csr (dev, REG_RESEND);

  const u32 in_words   = in_after  - in_before;
  const u32 out_halves = out_after - out_before;

  const u32 shell_bytes = out_halves * 2;

  printf ("records sent   %u\n", cands);
  printf ("shell took in  %u words = %u records\n", in_words, in_words / H2C_REC_WORDS);
  printf ("shell put out  %u half words = %u bytes = %u frames\n", out_halves, shell_bytes, shell_bytes / C2H_FRAME_BYTES);
  printf ("host received  %u bytes = %u frames, in %u packets\n", rx_len, rx_len / C2H_FRAME_BYTES, pkt_cnt);

  printf ("packets       ");

  for (u32 i = 0; (i < pkt_cnt) && (i < PKT_MAX); i++) printf (" %u", pkt_len[i]);

  printf ("\n\n");

  const u32 want_bytes = cands * C2H_FRAME_BYTES;

  if (rx_len < want_bytes) printf ("*** %u of %u result bytes came back, short by %u.\n\n", rx_len, want_bytes, want_bytes - rx_len);
  else                     printf ("*** all %u result bytes came back.\n\n", rx_len);

  if ((shell_bytes > rx_len) && (out_halves > 0))
  {
    const u32 lost = shell_bytes - rx_len;

    printf ("*** %u bytes = %u words did NOT survive the microcontroller.\n", lost, lost / 2);
    printf ("*** The shell handed them to ezusb_io and the host never saw them, so FLAGB is the plain\n");
    printf ("*** full flag and the write shadow behind it is real on this board.\n");
  }
  else if ((in_words == 0) && (out_halves == 0))
  {
    printf ("this bitstream has no movement counters, so the shell cannot be compared with the host.\n");
    printf ("What is still measurable is below: how many result bytes came back and whether the stream\n");
    printf ("is still on frame boundaries. A lost word shows up as both.\n");
  }
  else if (shell_bytes < rx_len)
  {
    printf ("*** the host received %u more bytes than the shell reports sending. Data may remain\n", rx_len - shell_bytes);
    printf ("*** over from an earlier run, or a word was sent twice.\n");
  }
  else
  {
    printf ("*** every byte reported by the shell reached the host.\n");

    if (rx_len < (cands * C2H_FRAME_BYTES))
    {
      printf ("*** The run is still short of its own results, so the shell did not produce them all:\n");
      printf ("*** that is a different fault from the one this tool is looking for.\n");
    }
  }

  printf ("\n");

  u32 bad_at = 0;
  bool aligned = true;

  for (u32 off = 0; (off + C2H_FRAME_BYTES) <= rx_len; off += C2H_FRAME_BYTES)
  {
    const u32 ekid = (u32) rx[off + 0] | ((u32) rx[off + 1] << 8) | ((u32) rx[off + 2] << 16) | ((u32) rx[off + 3] << 24);

    if ((ekid >= EKID_BASE) && (ekid < (EKID_BASE + cands))) continue;

    aligned = false;
    bad_at  = off;

    break;
  }

  if (aligned == false)
  {
    printf ("the stream stops being frames at byte %u, which is frame %u of %u.\n", bad_at, bad_at / C2H_FRAME_BYTES, cands);
    printf ("Everything from there on is shifted, which is what one lost word does to a fixed frame stream.\n");
  }
  else
  {
    printf ("every received frame has an ekid from this run, so frame boundaries remain aligned.\n");
  }

  printf ("frame_status   %08x\n", csr (dev, REG_FRAME_ST));

  printf ("\n");
  printf ("FLAGB          low for %u cycles, %u falls, %u resends\n", flagb_low, flagb_fall, resends);

  report_flush (dev);

  if ((flagb_low == 0) && (flagb_fall == 0) && (resends == 0))
  {
    printf ("\n");
    printf ("Either this bitstream has no FLAGB counters, or the endpoint never filled in this run.\n");
    printf ("Check whether the counters above are available, then run with more\n");
    printf ("candidates than the endpoint can hold, which is more than %u bytes of results.\n", 4u * 512u);

    return 0;
  }

  printf ("\n");

  if (flagb_low == 0)
  {
    printf ("*** FLAGB never went low, so this run cannot test the write shadow. Send more data.\n");

    return 0;
  }

  printf ("*** The endpoint filled %u times without host-side loss:\n", flagb_fall);

  if (resends == 0)
  {
    printf ("*** ezusb_io never had to re-send a word. FLAGB is asserted early enough that no write\n");
    printf ("*** ever lands behind it, which means this firmware gives the flag headroom and the\n");
    printf ("*** write shadow does not exist on this board.\n");
  }
  else if (rx_len == want_bytes)
  {
    printf ("*** ezusb_io re-sent %u words and the host received every byte exactly once. So exactly\n", resends);
    printf ("*** ONE word entered the shadow each time, and ezusb_io's single word replay is exactly\n");
    printf ("*** deep enough for this board. The shadow is real and it is covered.\n");
  }
  else
  {
    printf ("*** ezusb_io re-sent %u words and the host is still short. The shadow is DEEPER than the\n", resends);
    printf ("*** one word replay, which is the failure the simulation predicts.\n");
  }

  transport->session_close (dev);

  for (int i = 0; i < cnt; i++) transport->close (&devs[i]);

  return 0;
}
