/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

#include "liblitepcie.h"
#include "csr.h"
#include "hcfpga_iface.h"
#include "bcrypt_ek.h"

#define CSR_CTRL       (CSR_BASE + HCFPGA_CSR_CTRL)
#define CSR_SALT0      (CSR_BASE + HCFPGA_CSR_SALT0)
#define CSR_SALT1      (CSR_BASE + HCFPGA_CSR_SALT1)
#define CSR_SALT2      (CSR_BASE + HCFPGA_CSR_SALT2)
#define CSR_SALT3      (CSR_BASE + HCFPGA_CSR_SALT3)
#define CSR_ITER_COUNT (CSR_BASE + HCFPGA_CSR_ITER_COUNT)
#define CSR_CORE_COUNT (CSR_BASE + HCFPGA_CSR_CORE_COUNT)

#define CSR_CMP_BM0    (CSR_BASE + HCFPGA_CSR_CMP_BM0)
#define CSR_CMP_BM1    (CSR_BASE + HCFPGA_CSR_CMP_BM1)
#define CSR_CMP_BM2    (CSR_BASE + HCFPGA_CSR_CMP_BM2)
#define CSR_CMP_BM3    (CSR_BASE + HCFPGA_CSR_CMP_BM3)

#define CSR_BATCH_TARGET (CSR_BASE + HCFPGA_CSR_BATCH_TARGET)
#define CSR_PAD_RECS     (CSR_BASE + HCFPGA_CSR_PAD_RECS)
#define CSR_RETIRED      (CSR_BASE + HCFPGA_CSR_RETIRED)

#define PROBE_STATUS     (CSR_BASE + HCFPGA_CSR_STATUS)

#define NCAND 1024

static int g_seed = 0;

static bool probe_identity (const int fd, char *buf, const size_t buf_size);

#ifndef HCFPGA_ABI
#define HCFPGA_ABI 3
#endif

static uint32_t be32 (const uint8_t *b)
{
  const uint32_t v = ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) | (uint32_t) b[3];

  return v;
}

static void send_config (const int fd, const uint32_t cost, const uint8_t *salt16)
{
  litepcie_writel (fd, CSR_CTRL, 1);
  litepcie_writel (fd, CSR_CTRL, 0);

  litepcie_writel (fd, CSR_SALT0, be32 (salt16 + 0));
  litepcie_writel (fd, CSR_SALT1, be32 (salt16 + 4));
  litepcie_writel (fd, CSR_SALT2, be32 (salt16 + 8));
  litepcie_writel (fd, CSR_SALT3, be32 (salt16 + 12));

  const uint32_t rounds = 1u << cost;

  litepcie_writel (fd, CSR_ITER_COUNT, rounds);

  litepcie_writel (fd, CSR_CMP_BM0, 0xffffffffu);
  litepcie_writel (fd, CSR_CMP_BM1, 0xffffffffu);
  litepcie_writel (fd, CSR_CMP_BM2, 0xffffffffu);

  litepcie_writel (fd, CSR_CMP_BM3, 0xffffffffu);

  litepcie_writel (fd, CSR_BATCH_TARGET, 0);
  litepcie_writel (fd, CSR_PAD_RECS, 1);

}

static const uint32_t CAND_LEN[4] = { 3, 8, 11, 71 };

#define CAND_GROUP_BYTES 128

static uint32_t make_cand (const int idx, uint8_t *pw)
{
  const uint32_t len = CAND_LEN[idx % 4];

  for (uint32_t i = 0; i < len; i++)
  {
    const uint32_t v = (uint32_t) idx + ((uint32_t) g_seed * 7u) + (i * 31u);

    pw[i] = (uint8_t) (0x21 + (v % 94u));
  }

  return len;
}

static void expand_cand (const uint8_t *pw, const uint32_t len, uint32_t ek[18])
{
  const size_t period = (size_t) len + 1;

  uint8_t km[72];

  for (uint32_t i = 0; i < 72; i++)
  {
    const size_t j = i % period;

    km[i] = (j == (size_t) len) ? 0 : pw[j];
  }

  for (uint32_t w = 0; w < 18; w++)
  {
    ek[w] = ((uint32_t) km[4*w + 0] << 24) | ((uint32_t) km[4*w + 1] << 16) | ((uint32_t) km[4*w + 2] << 8) | (uint32_t) km[4*w + 3];
  }
}

static int mode_test (int argc, char **argv)
{
  const char *node = "/dev/litepcie0";

  const char *want_board = NULL;

  const char *pos[3] = { NULL, NULL, NULL };

  int npos = 0;

  for (int i = 1; i < argc; i++)
  {
    if (strncmp (argv[i], "/dev/", 5) == 0)
    {
      node = argv[i];

      continue;
    }

    if (strncmp (argv[i], "--board=", 8) == 0)
    {
      want_board = &argv[i][8];

      continue;
    }

    if (npos < 3)
    {
      pos[npos] = argv[i];
      npos = npos + 1;
    }
  }

  const uint32_t cost = (pos[0] != NULL) ? (uint32_t) atoi (pos[0]) : 5;

  if (cost > 19)
  {
    printf ("cost %u is above the array's 20 bit counter, the highest it can run is 19\n", cost);

    return 1;
  }
  const int      secs = (pos[1] != NULL) ? atoi (pos[1]) : 8;

  g_seed = (pos[2] != NULL) ? atoi (pos[2]) : 0;

  struct litepcie_dma_ctrl dma = {0};

  dma.use_reader = 1;
  dma.use_writer = 1;

  if (litepcie_dma_init (&dma, node, 0))
  {
    fprintf (stderr, "dma_init failed\n");

    return 1;
  }

  const int fd = dma.fds.fd;

  const uint32_t core_count = litepcie_readl (fd, CSR_CORE_COUNT);

  char ident_buf[512];

  if (probe_identity (fd, ident_buf, sizeof (ident_buf)) == true)
  {
    printf ("[> identity: %s on %s\n", ident_buf, node);

    if (want_board != NULL)
    {
      char board[64];

      board[0] = 0;

      const char *b = strstr (ident_buf, "board=");

      if (b != NULL) sscanf (&b[6], "%63[^;]", board);

      if (strcmp (board, want_board) != 0)
      {
        fprintf (stderr, "%s is a '%s' card, not '%s'. Name the node of the card to test.\n", node, board, want_board);

        return 1;
      }
    }

    const char *at = strstr (ident_buf, ";abi=");

    const int card_abi = (at != NULL) ? atoi (at + 5) : -1;

    if (card_abi != HCFPGA_ABI)
    {
      fprintf (stderr, "this card reports ABI %d and this tool speaks ABI %d.\n", card_abi, HCFPGA_ABI);
      fprintf (stderr, "identity: %s\n", ident_buf);
      fprintf (stderr, "The record format differs between them, so anything measured here would be\n");
      fprintf (stderr, "meaningless. Program the board with a v%d bitstream, see docs/hashcat-fpga-setup.md\n", HCFPGA_ABI);

      return 1;
    }
  }

  uint8_t salt16[16];

  for (uint32_t i = 0; i < 16; i++) salt16[i] = i;

  send_config (fd, cost, salt16);

  static uint8_t  cand_pw   [NCAND][HCFPGA_PW_MAX];
  static uint32_t cand_len  [NCAND];
  static uint8_t  cand_gold [NCAND][24];

  const int rounds = 1 << cost;

  for (int c = 0; c < NCAND; c++)
  {
    uint32_t ek[18];

    cand_len[c] = make_cand (c, cand_pw[c]);

    expand_cand (cand_pw[c], cand_len[c], ek);

    bcrypt_raw_ek (ek, salt16, rounds, cand_gold[c]);
  }

  printf ("[> NCAND=%d cost=%u rounds=%d seed=%d core_count=%u\n", NCAND, cost, rounds, g_seed, core_count);

  const size_t NBUF       = DMA_BUFFER_TOTAL_SIZE / DMA_BUFFER_SIZE;
  const size_t ALIGNED_WR = NBUF * DMA_BUFFER_SIZE;

  uint8_t *bw = (uint8_t *) dma.buf_wr;

  memset (bw, 0, ALIGNED_WR);

  const size_t NGROUP   = ALIGNED_WR / CAND_GROUP_BYTES;
  const size_t H2C_RECS = NGROUP * 4;

  size_t used = 0;

  for (size_t g = 0; g < H2C_RECS; g++)
  {
    const uint32_t cand = (uint32_t) (g % NCAND);

    used += hcfpga_h2c_put (bw + used, cand, cand_pw[cand], cand_len[cand]);
  }

  if (used != ALIGNED_WR)
  {
    fprintf (stderr, "h2c fill covered %zu of %zu bytes, the candidate lengths no longer tile the ring\n", used, ALIGNED_WR);

    return 1;
  }

  dma.reader_enable = 1;
  dma.writer_enable = 1;

  uint64_t ok = 0, bad = 0, oor = 0, ndump = 0, noor_dump = 0;

  uint64_t nskip = 0;

  const uint64_t SETTLE_FRAMES = (uint64_t) H2C_RECS;

  static uint8_t seen [NCAND];

  memset (seen, 0, sizeof (seen));

  static uint32_t corehist [65536];

  memset (corehist, 0, sizeof (corehist));

  const int64_t t0 = get_time_ms ();
  int64_t tdiag = 0;

  size_t wr_off = 0;

  int64_t t_score = 0;

  const int64_t SETTLE_LIMIT_MS = 180000;

  while (1)
  {
    const int64_t now = get_time_ms ();

    if ((t_score == 0) && ((now - t0) >= SETTLE_LIMIT_MS)) break;
    if ((t_score  > 0) && ((now - t_score) >= ((int64_t) secs * 1000))) break;

    litepcie_dma_writer (fd, 1, &dma.writer_hw_count, &dma.writer_sw_count);
    litepcie_dma_reader (fd, 1, &dma.reader_hw_count, &dma.reader_sw_count);

    const int pr = poll (&dma.fds, 1, 100);

    if (pr <= 0) continue;

    if (dma.fds.revents & POLLOUT)
    {
      const ssize_t wn = write (fd, bw + wr_off, DMA_BUFFER_SIZE);

      (void) wn;

      wr_off += DMA_BUFFER_SIZE;

      if (wr_off >= ALIGNED_WR) wr_off = 0;
    }

    if ((dma.fds.revents & POLLIN) == 0) continue;

    const ssize_t rlen = read (fd, dma.buf_rd, DMA_BUFFER_TOTAL_SIZE);

    if (rlen <= 0) continue;

    const int nbuf = rlen / DMA_BUFFER_SIZE;

    for (int bi = 0; bi < nbuf; bi++)
    {
      const uint8_t *br = (const uint8_t *) dma.buf_rd + (size_t) bi * DMA_BUFFER_SIZE;

      const uint32_t recs_per_buf = DMA_BUFFER_SIZE / HCFPGA_C2H_REC_BYTES;

      for (uint32_t r = 0; r < recs_per_buf; r++)
      {
        const hcfpga_c2h_rec_t *f = (const hcfpga_c2h_rec_t *) (br + r * HCFPGA_C2H_REC_BYTES);

        if ((f->ekid == 0) && (f->core_id == 0) && (f->digest[0] == 0) && (f->digest[1] == 0)) continue;

        if (f->ekid >= NCAND)
        {
          oor++;

          if (noor_dump < 4)
          {
            noor_dump++;

            printf ("[> FOREIGN ekid=%u (0x%08x) core_id=%u flags=0x%04x raw=", f->ekid, f->ekid, f->core_id, f->flags);

            const uint8_t *raw = (const uint8_t *) f;

            for (uint32_t i = 0; i < HCFPGA_C2H_REC_BYTES; i++) printf ("%02x", raw[i]);

            printf ("\n");
          }

          continue;
        }

        if (nskip < SETTLE_FRAMES)
        {
          nskip++;

          continue;
        }

        if (t_score == 0) t_score = get_time_ms ();

        corehist[f->core_id]++;

        if (memcmp (f->digest, cand_gold[f->ekid], 24) == 0)
        {
          ok++;
          seen[f->ekid] = 1;
        }
        else
        {
          bad++;

          if (ndump < 8)
          {
            ndump++;

            printf ("[> MISPAIR ekid=%u core_id=%u got=", f->ekid, f->core_id);
            for (uint32_t i = 0; i < 24; i++) printf ("%02x", f->digest[i]);
            printf (" want=");
            for (uint32_t i = 0; i < 24; i++) printf ("%02x", cand_gold[f->ekid][i]);
            printf ("\n");
          }
        }
      }
    }

    if (get_time_ms () - tdiag >= 1000)
    {
      tdiag = get_time_ms ();

      if (t_score == 0)
      {
        printf ("  t=%lds settling %llu of %llu frames rd_hw=%lld wr_hw=%lld\n",
          (long) ((tdiag - t0) / 1000), (unsigned long long) nskip, (unsigned long long) SETTLE_FRAMES,
          (long long) dma.reader_hw_count, (long long) dma.writer_hw_count);
      }
      else
      {
        printf ("  t=%lds ok=%llu bad=%llu oor=%llu rd_hw=%lld wr_hw=%lld\n",
          (long) ((tdiag - t0) / 1000), (unsigned long long) ok, (unsigned long long) bad,
          (unsigned long long) oor, (long long) dma.reader_hw_count, (long long) dma.writer_hw_count);
      }
    }
  }

  const uint32_t end_status = litepcie_readl (fd, PROBE_STATUS);

  const uint32_t end_retired = litepcie_readl (fd, CSR_RETIRED);

  litepcie_dma_cleanup (&dma);

  printf ("[> retired: %u candidates completed by the array\n", end_retired);

  printf ("[> framing: status=0x%08x last_seen=%u frame_slip=%u slip_count=%u\n",
    end_status, (end_status >> 1) & 1, (end_status >> 0) & 1, (end_status >> 8) & 0xff);

  int distinct = 0;

  for (int c = 0; c < NCAND; c++) if (seen[c]) distinct++;

  int cores_used = 0;

  for (int i = 0; i < 65536; i++) if (corehist[i]) cores_used++;

  const int64_t elapsed_ms = get_time_ms () - ((t_score > 0) ? t_score : t0);

  const double rate = (elapsed_ms > 0) ? ((double) ok * 1000.0 / (double) elapsed_ms) : 0.0;

  printf ("[> %llu scored in %lldms -> %.0f H/s\n", (unsigned long long) ok, (long long) elapsed_ms, rate);

  printf ("[> ok=%llu bad=%llu foreign-skipped=%llu ; %d/%d candidates covered ; %d distinct core_ids seen\n",
    (unsigned long long) ok, (unsigned long long) bad, (unsigned long long) oor, distinct, NCAND, cores_used);

  const int pass = (ok > 0) && (bad == 0);

  printf ("[> %s\n", pass ? "*** STRESS PASS *** every digest pairs with its ekid's candidate (identity holds)"
                          : "*** STRESS FAIL *** ekid<->digest mispairing or bad frames");

  return pass ? 0 : 1;
}

#define PROBE_CORE_COUNT  (CSR_BASE + HCFPGA_CSR_CORE_COUNT)

#define PROBE_IDENT_MAX   256

#define PROBE_SCRATCH_MAGIC 0x12345678

static bool probe_identity (const int fd, char *buf, const size_t buf_size)
{
  const uint32_t scratch = litepcie_readl (fd, CSR_CTRL_SCRATCH_ADDR);

  if (scratch != PROBE_SCRATCH_MAGIC)
  {
    snprintf (buf, buf_size, "CSR path dead: scratch reads 0x%08x, expected 0x%08x", scratch, PROBE_SCRATCH_MAGIC);

    return false;
  }

  size_t n = 0;

  for (uint32_t i = 0; i < PROBE_IDENT_MAX; i++)
  {
    const uint32_t w = litepcie_readl (fd, CSR_IDENTIFIER_MEM_BASE + 4 * i);

    const char c = (char) (w & 0xff);

    if (c == 0) break;
    if (n >= (buf_size - 1)) break;

    buf[n] = c;

    n++;
  }

  buf[n] = 0;

  return true;
}

static double xadc_temp_c (const uint32_t raw)
{
  const double celsius = ((double) raw) * 503.975 / 4096.0 - 273.15;

  return celsius;
}

static double xadc_volts (const uint32_t raw)
{
  const double volts = ((double) raw) * 3.0 / 4096.0;

  return volts;
}

static int mode_probe (int argc, char **argv)
{
  const char *path = (argc > 2) ? argv[2] : "/dev/litepcie0";

  const int fd = open (path, O_RDWR);

  if (fd < 0)
  {
    fprintf (stderr, "cannot open %s\n", path);

    return 1;
  }

  char ident[512];

  const bool csr_alive = probe_identity (fd, ident, sizeof (ident));

  printf ("identity....: %s\n", ident);

  if (csr_alive == false)
  {
    printf ("              Other register readings would be unreliable. The endpoint opened, but the\n");
    printf ("              board did not answer. PCIe enumeration may be stale after reprogramming.\n");
    printf ("              Reboot the host.\n");

    close (fd);

    return 1;
  }

  const uint32_t core_count = litepcie_readl (fd, PROBE_CORE_COUNT);
  const uint32_t status     = litepcie_readl (fd, PROBE_STATUS);

  const uint32_t frame_slip = (status >> 0) & 1;
  const uint32_t last_seen  = (status >> 1) & 1;
  const uint32_t slip_count = (status >> 8) & 0xff;

  printf ("cores.......: %u\n", core_count);
  printf ("status......: 0x%08x\n", status);

  if (last_seen == 0)
  {
    printf ("framing.....: not observable yet, no buffer end has been sent in this session.\n");
    printf ("              This is the normal reading on a card that is working. Opening the\n");
    printf ("              device re-arms the datapath, so the marker only appears once traffic\n");
    printf ("              has run. To get a real answer, stream some: '%s 5 10'\n", argv[0]);
  }
  else if (frame_slip == 0)
  {
    printf ("framing.....: OK, every buffer end landed on a record boundary\n");
  }
  else
  {
    printf ("framing.....: SLIPPED %u times, a buffer end did not land on a record boundary\n", slip_count);
  }

  const uint32_t temp     = litepcie_readl (fd, CSR_XADC_TEMPERATURE_ADDR);
  const uint32_t vccint   = litepcie_readl (fd, CSR_XADC_VCCINT_ADDR);
  const uint32_t vccaux   = litepcie_readl (fd, CSR_XADC_VCCAUX_ADDR);
  const uint32_t vccbram  = litepcie_readl (fd, CSR_XADC_VCCBRAM_ADDR);

  printf ("die temp....: %.1f C   (raw 0x%03x)\n", xadc_temp_c (temp), temp);
  printf ("vccint......: %.3f V\n", xadc_volts (vccint));
  printf ("vccaux......: %.3f V\n", xadc_volts (vccaux));
  printf ("vccbram.....: %.3f V\n", xadc_volts (vccbram));

  close (fd);

  return 0;
}

static void usage (void)
{
  fprintf (stderr, "dma_ek_test: verify and inspect the bcrypt design\n\n");
  fprintf (stderr, "  dma_ek_test [cost] [seconds] [/dev/node]  stream distinct candidates and check every digest\n");
  fprintf (stderr, "  dma_ek_test --probe [/dev/node]     framing state, die temperature and supply rails\n\n");
  fprintf (stderr, "Timing closure is not sufficient to trust a bitstream. The default mode is what makes\n");
  fprintf (stderr, "one valid: it checks each digest against a software bcrypt and reports a per-core\n");
  fprintf (stderr, "histogram, so a single core computing wrongly cannot hide behind an aggregate rate.\n");
}

int main (int argc, char **argv)
{
  if (argc > 1)
  {
    if (strcmp (argv[1], "--probe") == 0) return mode_probe (argc, argv);

    if ((strcmp (argv[1], "--help") == 0) || (strcmp (argv[1], "-h") == 0))
    {
      usage ();

      return 0;
    }
  }

  const int rc = mode_test (argc, argv);

  return rc;
}
