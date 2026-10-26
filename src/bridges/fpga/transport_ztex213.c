/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"

#include "fpga/hcfpga.h"
#include "fpga/ztex_usb.h"

#include <stdio.h>
#include <string.h>

#if defined (__linux__)

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>

#define ZTEX213_PRODUCT_2_13  17

#define ZTEX213_BOARD  "ztex213"

#define ZTEX213_EP_CONFIG   6
#define ZTEX213_EP_OUT      6
#define ZTEX213_EP_IN       2

#define ZTEX213_LSI_GAP_US  200

#define ZTEX213_VC_LSI_SET  0x62
#define ZTEX213_VR_LSI_GET  0x63

#define ZTEX213_CAP_DEFAULT_BYTE  1
#define ZTEX213_CAP_DEFAULT_BIT   4

#define ZTEX213_REG_STATUS      0x06
#define ZTEX213_REG_CORE_COUNT  0x07

#define ZTEX213_REG_MAGIC       0x10
#define ZTEX213_REG_ABI         0x11
#define ZTEX213_REG_ALGO_LO     0x12
#define ZTEX213_REG_ALGO_HI     0x13
#define ZTEX213_REG_CLK_MHZ     0x14
#define ZTEX213_REG_BUILD       0x15
#define ZTEX213_REG_TEMP        0x16

#define ZTEX213_TEMP_VALID      0x80000000u

#define ZTEX213_MAGIC           0x68636667

#define ZTEX213_BITSTREAM_FMT  "bcrypt-" ZTEX213_BOARD ".bit"

#define ZTEX213_NODE_MAX  32

#define ZTEX213_WRITE_TIMEOUT_MS 30000

#define ZTEX213_OUT_BYTES  (128 * 1024)

#define ZTEX213_IN_BUF  8192

#define ZTEX213_EP_MAXPKT  512

#define ZTEX213_CONFIG_SETTLE_US  200000

#define ZTEX213_IDENT_TRIES  8
#define ZTEX213_IDENT_WAIT   20000

typedef struct ztex213_priv
{
  int  fd;

  bool claimed;

  char node[ZTEX213_NODE_MAX];
  char serial[ZTEX_DESC_SERIAL_BYTES + 2];

  u32  link_mbit;

  u8  *rx;

  u8   carry[256];
  u32  carry_len;

  u32  in_grain;

  u32  in_recs;

  bool eob_seen;
  u32  eob_processed;

  u8  *pend;
  u32  pend_size;
  u32  pend_head;
  u32  pend_tail;

  bool in_failed;

} ztex213_priv_t;

static ztex213_priv_t *ztex213_priv (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = (ztex213_priv_t *) dev->priv;

  return priv;
}

static u32 ztex213_lsi_gap_us (void)
{
  static int cached = -1;

  if (cached >= 0) return (u32) cached;

  const char *env = getenv ("HCFPGA_LSI_US");

  cached = (env != NULL) ? atoi (env) : ZTEX213_LSI_GAP_US;

  if (cached < 0) cached = 0;

  return (u32) cached;
}

static pthread_mutex_t ZTEX213_LSI_MUX = PTHREAD_MUTEX_INITIALIZER;

static bool ztex213_lsi_set (const int fd, const u8 addr, const u32 val)
{
  u8 buf[5];

  buf[0] = (u8) (val >>  0);
  buf[1] = (u8) (val >>  8);
  buf[2] = (u8) (val >> 16);
  buf[3] = (u8) (val >> 24);
  buf[4] = addr;

  pthread_mutex_lock (&ZTEX213_LSI_MUX);

  const bool sent = ztex_control_write_data (fd, ZTEX213_VC_LSI_SET, 0, 0, buf, sizeof (buf));

  const u32 gap = ztex213_lsi_gap_us ();

  if ((sent == true) && (gap > 0)) usleep (gap);

  pthread_mutex_unlock (&ZTEX213_LSI_MUX);

  if (sent == false)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex213] lsi_set 0x%02x failed\n", addr);

    return false;
  }

  return true;
}

static bool ztex213_lsi_get (const int fd, const u8 addr, u32 *out)
{
  u8 buf[4];

  pthread_mutex_lock (&ZTEX213_LSI_MUX);

  const bool got = (ztex_control_read (fd, ZTEX213_VR_LSI_GET, 0, addr, buf, sizeof (buf)) == (int) sizeof (buf)) ? true : false;

  const u32 gap = ztex213_lsi_gap_us ();

  if ((got == true) && (gap > 0)) usleep (gap);

  pthread_mutex_unlock (&ZTEX213_LSI_MUX);

  if (got == false) return false;

  *out = (u32) buf[0] | ((u32) buf[1] << 8) | ((u32) buf[2] << 16) | ((u32) buf[3] << 24);

  return true;
}

static u32 ztex213_csr_read (fpga_dev_t *dev, const u32 addr)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  u32 val = 0;

  if (ztex213_lsi_get (priv->fd, (u8) ((addr - dev->csr_base) >> 2), &val) == false) return 0;

  return val;
}

static bool ztex213_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  const bool ok = ztex213_lsi_set (priv->fd, (u8) ((addr - dev->csr_base) >> 2), val);

  return ok;
}

static void ztex213_close (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv)
  {
    if (priv->rx) hcfree (priv->rx);

    if (priv->pend) hcfree (priv->pend);

    if (priv->fd >= 0) close (priv->fd);

    hcfree (priv);

    dev->priv = NULL;
  }

  dev->fd = -1;
}

static int ztex213_add_board (const char *node, const char *devdir, fpga_dev_t *devs, const int max)
{
  if (max < 1) return 0;

  const int fd = open (node, O_RDWR);

  if (fd < 0) return 0;

  u8 desc[ZTEX_DESC_BYTES];

  if (ztex_control_read (fd, ZTEX_VR_DESCRIPTOR, 0, 0, desc, sizeof (desc)) != (int) sizeof (desc))
  {
    close (fd);

    return 0;
  }

  if (memcmp (&desc[ZTEX_DESC_MAGIC_OFFSET], "ZTEX", 4) != 0)
  {
    close (fd);

    return 0;
  }

  if (desc[ZTEX_DESC_PRODUCT_OFFSET + 0] != ZTEX_PRODUCT_FPGA_MODULE) { close (fd); return 0; }
  if (desc[ZTEX_DESC_PRODUCT_OFFSET + 1] != ZTEX213_PRODUCT_2_13)     { close (fd); return 0; }

  const u32 caps = desc[ZTEX_DESC_CAPS_OFFSET + ZTEX213_CAP_DEFAULT_BYTE];

  if (((caps >> ZTEX213_CAP_DEFAULT_BIT) & 1) == 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex213] %s has no default firmware interface, capability 1.4 is clear\n", node);

    close (fd);

    return 0;
  }

  fpga_dev_t *dev = &devs[0];

  memset (dev, 0, sizeof (fpga_dev_t));

  snprintf (dev->path, sizeof (dev->path), "%s", node);

  snprintf (dev->ident.board, sizeof (dev->ident.board), "%s", ZTEX213_BOARD);

  dev->fd = fd;

  ztex213_priv_t *priv = (ztex213_priv_t *) hcmalloc (sizeof (ztex213_priv_t));

  if (priv == NULL)
  {
    close (fd);

    return 0;
  }

  priv->fd       = fd;
  priv->claimed  = false;
  priv->rx       = NULL;
  priv->carry_len = 0;
  priv->in_grain = 0;

  snprintf (priv->node, sizeof (priv->node), "%s", node);

  memcpy (priv->serial, &desc[ZTEX_DESC_SERIAL_OFFSET], ZTEX_DESC_SERIAL_BYTES);

  priv->serial[ZTEX_DESC_SERIAL_BYTES] = 0;

  priv->link_mbit = 0;

  char speed[32];

  if (ztex_sysfs_read (devdir, "speed", speed, sizeof (speed)) == true)
  {
    priv->link_mbit = (u32) strtoul (speed, NULL, 10);
  }

  dev->priv = priv;

  return 1;
}

static int ztex213_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  (void) hashcat_ctx;

  int cnt = 0;

  bool saw_board      = false;
  bool saw_permission = false;

  DIR *d = opendir ("/sys/bus/usb/devices");

  if (d == NULL)
  {
    *status = FPGA_STATUS_NO_PCI_DEVICE;

    return 0;
  }

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if (cnt >= max) break;

    if (e->d_name[0] == '.') continue;

    char devdir[FPGA_PATH_MAX];

    snprintf (devdir, sizeof (devdir), "/sys/bus/usb/devices/%s", e->d_name);

    char vendor[32];

    if (ztex_sysfs_read (devdir, "idVendor", vendor, sizeof (vendor)) == false) continue;

    if (strtol (vendor, NULL, 16) != ZTEX_VENDOR_ID) continue;

    char busnum[32];
    char devnum[32];

    if (ztex_sysfs_read (devdir, "busnum", busnum, sizeof (busnum)) == false) continue;
    if (ztex_sysfs_read (devdir, "devnum", devnum, sizeof (devnum)) == false) continue;

    char node[ZTEX213_NODE_MAX];

    snprintf (node, sizeof (node), "/dev/bus/usb/%03ld/%03ld", strtol (busnum, NULL, 10), strtol (devnum, NULL, 10));

    saw_board = true;

    if (access (node, R_OK | W_OK) != 0)
    {
      saw_permission = true;

      continue;
    }

    cnt += ztex213_add_board (node, devdir, &devs[cnt], max - cnt);
  }

  closedir (d);

  if (cnt == 0)
  {
    if (saw_permission == true)  *status = FPGA_STATUS_NO_PERMISSION;
    else if (saw_board == true)  *status = FPGA_STATUS_NO_PCI_DEVICE;
    else                         *status = FPGA_STATUS_NO_PCI_DEVICE;
  }

  return cnt;
}

static fpga_status_t ztex213_identify (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  fpga_ident_t *ident = &dev->ident;

  memset (ident, 0, sizeof (fpga_ident_t));

  snprintf (ident->board,  sizeof (ident->board),  "%s", ZTEX213_BOARD);
  snprintf (ident->serial, sizeof (ident->serial), "%s", priv->serial);

  if (ztex_fpga_is_configured (priv->fd) == false) return FPGA_STATUS_NO_BITSTREAM;

  u32 magic = 0;

  bool got = false;

  for (u32 i = 0; i < ZTEX213_IDENT_TRIES; i++)
  {
    if (ztex213_lsi_get (priv->fd, ZTEX213_REG_MAGIC, &magic) == true)
    {
      if (magic == ZTEX213_MAGIC)
      {
        got = true;

        break;
      }
    }

    usleep (ZTEX213_IDENT_WAIT);
  }

  if (got == false) return FPGA_STATUS_BAD_IDENT;

  u32 abi     = 0;
  u32 algo_lo = 0;
  u32 algo_hi = 0;
  u32 cores   = 0;
  u32 clk     = 0;
  u32 build   = 0;

  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_ABI,        &abi)     == false) return FPGA_STATUS_BAD_IDENT;
  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_ALGO_LO,    &algo_lo) == false) return FPGA_STATUS_BAD_IDENT;
  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_ALGO_HI,    &algo_hi) == false) return FPGA_STATUS_BAD_IDENT;
  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_CORE_COUNT, &cores)   == false) return FPGA_STATUS_BAD_IDENT;
  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_CLK_MHZ,    &clk)     == false) return FPGA_STATUS_BAD_IDENT;
  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_BUILD,      &build)   == false) return FPGA_STATUS_BAD_IDENT;

  u8 algo[9];

  algo[0] = (u8) (algo_lo >>  0); algo[1] = (u8) (algo_lo >>  8);
  algo[2] = (u8) (algo_lo >> 16); algo[3] = (u8) (algo_lo >> 24);
  algo[4] = (u8) (algo_hi >>  0); algo[5] = (u8) (algo_hi >>  8);
  algo[6] = (u8) (algo_hi >> 16); algo[7] = (u8) (algo_hi >> 24);
  algo[8] = 0;

  for (u32 i = 0; i < 8; i++)
  {
    if (algo[i] == 0) break;

    if ((algo[i] < 0x20) || (algo[i] > 0x7e)) return FPGA_STATUS_BAD_IDENT;
  }

  snprintf (ident->algo, sizeof (ident->algo), "%s", (const char *) algo);

  ident->cores   = cores;
  ident->clk_mhz = clk;
  ident->abi     = abi;

  const time_t t = (time_t) build;

  struct tm tm_buf;

  if (gmtime_r (&t, &tm_buf) != NULL)
  {
    strftime (ident->build, sizeof (ident->build), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  }

  snprintf (ident->raw, sizeof (ident->raw),
            FPGA_IDENT_PREFIX "%u;board=%s;algo=%s;cores=%u;clk=%u;abi=%u;build=%s",
            abi, ident->board, ident->algo, ident->cores, ident->clk_mhz, ident->abi, ident->build);

  if (ident->abi != FPGA_ABI_CURRENT) return FPGA_STATUS_ABI_MISMATCH;

  return FPGA_STATUS_OK;
}

static fpga_status_t ztex213_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (strcmp (algo, "bcrypt") != 0) return FPGA_STATUS_ALGO_UNAVAILABLE;

  char path[FPGA_PATH_MAX];

  if (fpga_shipped_file (hashcat_ctx->folder_config, ZTEX213_BITSTREAM_FMT, path, sizeof (path)) == false)
  {
    const char *names[1] = { ZTEX213_BITSTREAM_FMT };

    fpga_shipped_report_missing (hashcat_ctx, hashcat_ctx->folder_config, names, 1, fpga_board_find (ZTEX213_BOARD));

    return FPGA_STATUS_NO_BITSTREAM;
  }

  if (priv->claimed == false)
  {
    if (ztex_claim (priv->fd) == false) return FPGA_STATUS_NO_PERMISSION;

    priv->claimed = true;
  }

  if (ztex_hs_upload (priv->fd, ZTEX213_EP_CONFIG, path) == false) return FPGA_STATUS_BAD_IDENT;

  usleep (ZTEX213_CONFIG_SETTLE_US);

  if (ztex_fpga_is_configured (priv->fd) == false) return FPGA_STATUS_BAD_IDENT;

  return FPGA_STATUS_OK;
}

static bool ztex213_session_open (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv->claimed == false)
  {
    if (ztex_claim (priv->fd) == false) return false;

    priv->claimed = true;
  }

  if (priv->rx == NULL) priv->rx = (u8 *) hcmalloc (ZTEX213_IN_BUF);

  if (priv->rx == NULL) return false;

  if (ztex213_csr_write (dev, 0x00, 0x00000001) == false) return false;

  u8 sink[512];

  u32 stale = 0;

  for (u32 i = 0; i < 64; i++)
  {
    const int got = ztex_bulk_in (priv->fd, ZTEX213_EP_IN, sink, sizeof (sink), 20);

    if (got <= 0) break;

    stale += (u32) got;
  }

  priv->carry_len = 0;
  priv->pend_head = 0;
  priv->pend_tail = 0;

  if (ztex213_csr_write (dev, 0x00, 0x00000000) == false) return false;

  if (ztex_dbg () == true) fprintf (stderr, "[ztex213] session_open discarded %u bytes left by an earlier run\n", stale);

  return true;
}

static void ztex213_session_close (fpga_dev_t *dev)
{
  (void) dev;
}

static bool ztex213_session_refresh (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (ztex213_csr_write (dev, 0x00, 0x00000001) == false) return false;

  u8 sink[512];

  for (u32 i = 0; i < 64; i++)
  {
    const int got = ztex_bulk_in (priv->fd, ZTEX213_EP_IN, sink, sizeof (sink), 20);

    if (got <= 0) break;
  }

  priv->carry_len = 0;
  priv->pend_head = 0;
  priv->pend_tail = 0;

  if (ztex213_csr_write (dev, 0x00, 0x00000000) == false) return false;

  return true;
}

static u64 ztex213_out_capacity (fpga_dev_t *dev)
{
  (void) dev;

  return ZTEX213_OUT_BYTES;
}

static bool ztex213_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{

  ztex213_priv_t *priv = ztex213_priv (dev);

  priv->in_grain = in_grain;
  priv->carry_len = 0;

  priv->in_recs       = in_recs;
  priv->eob_seen      = false;
  priv->eob_processed = 0;
  priv->in_failed     = false;

  const u64 pkts = (in_bytes + ZTEX213_EP_MAXPKT - 1) / ZTEX213_EP_MAXPKT;

  const u64 need = MAX ((pkts + 1) * ZTEX213_EP_MAXPKT, (u64) ZTEX213_IN_BUF);

  if (priv->pend_size < need)
  {
    if (priv->pend) hcfree (priv->pend);

    priv->pend      = (u8 *) hcmalloc (need);
    priv->pend_size = (priv->pend == NULL) ? 0 : (u32) need;
  }

  if (priv->pend == NULL) return false;

  priv->pend_head = 0;
  priv->pend_tail = 0;

  if (ztex_dbg () == true) fprintf (stderr, "[ztex213] batch_begin out %llu in %llu grain %u\n", (unsigned long long) out_bytes, (unsigned long long) in_bytes, in_grain);

  return true;
}

static bool ztex213_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  const u32 wait_ms = (u32) MIN (MAX (dev->batch_wait_ms, (u64) ZTEX213_WRITE_TIMEOUT_MS), 0xffffffffu);

  u32 got = 0;

  const int rc = ztex_bulk_write_reading (priv->fd, ZTEX213_EP_OUT, (void *) src, (u32) bytes, ZTEX213_EP_IN, priv->pend, priv->pend_size, ZTEX213_EP_MAXPKT, &got, wait_ms);

  priv->pend_head = got;
  priv->pend_tail = 0;

  if (ztex_dbg () == true) fprintf (stderr, "[ztex213] send %llu bytes -> %d, %u bytes of results read beside it\n", (unsigned long long) bytes, rc, got);

  const bool ok = (rc == (int) bytes) ? true : false;

  return ok;
}

static const void *ztex213_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  const u32 grain = (priv->in_grain == 0) ? 1 : priv->in_grain;

  memcpy (priv->rx, priv->carry, priv->carry_len);

  int got = 0;

  if (priv->pend_tail < priv->pend_head)
  {
    got = (int) MIN (priv->pend_head - priv->pend_tail, ZTEX213_IN_BUF - priv->carry_len);

    memcpy (priv->rx + priv->carry_len, priv->pend + priv->pend_tail, (size_t) got);

    priv->pend_tail += (u32) got;
  }
  else
  {
    const u32 room = (ZTEX213_EP_MAXPKT < (ZTEX213_IN_BUF - priv->carry_len)) ? ZTEX213_EP_MAXPKT : (ZTEX213_IN_BUF - priv->carry_len);

    got = ztex_bulk_in (priv->fd, ZTEX213_EP_IN, priv->rx + priv->carry_len, room, timeout_ms);

    if (got < 0)
    {
      *bytes = 0;

      priv->in_failed = true;

      return NULL;
    }
  }

  const u32 total = priv->carry_len + (u32) got;

  const u32 whole = (total / grain) * grain;

  if (whole == 0)
  {
    priv->carry_len = total;

    if (total > 0) memcpy (priv->carry, priv->rx, total);

    *bytes = 0;

    return NULL;
  }

  const u32 rest = total - whole;

  if (rest > 0) memcpy (priv->carry, priv->rx + whole, rest);

  priv->carry_len = rest;

  if (priv->eob_seen == false)
  {
    u32 processed = 0;

    if (hcfpga_c2h_scan_eob (priv->rx, whole, grain, priv->in_recs, &processed) == true)
    {
      priv->eob_seen      = true;
      priv->eob_processed = processed;
    }
  }

  *bytes = whole;

  if (ztex_dbg () == true) fprintf (stderr, "[ztex213] recv grain %u timeout %u -> got %d, whole %u, carry %u\n", grain, timeout_ms, got, whole, rest);

  return priv->rx;
}

static bool ztex213_batch_done (fpga_dev_t *dev, u32 *processed)
{
  const ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv == NULL) return false;

  if (priv->eob_seen == false) return false;

  if (processed != NULL) *processed = priv->eob_processed;

  return true;
}

static bool ztex213_batch_failed (fpga_dev_t *dev)
{
  const ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv == NULL) return false;

  return priv->in_failed;
}

static void ztex213_batch_end (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv->carry_len > 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex213] batch ended with %u bytes of partial record buffered\n", priv->carry_len);

    priv->carry_len = 0;
  }

  priv->pend_head = 0;
  priv->pend_tail = 0;
}

static int ztex213_temperature (fpga_dev_t *dev)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv == NULL) return -1;

  u32 raw = 0;

  if (ztex213_lsi_get (priv->fd, ZTEX213_REG_TEMP, &raw) == false) return -1;

  if ((raw & ZTEX213_TEMP_VALID) == 0) return -1;

  const u32 code = raw & 0xfff;

  const int celsius = (int) ((((double) code) * 503.975) / 4096.0 - 273.15);

  if (celsius > 125) return -1;
  if (celsius < -40) return -1;

  return celsius;
}

static bool ztex213_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  ztex213_priv_t *priv = ztex213_priv (dev);

  if (priv->link_mbit == 0)
  {
    snprintf (buf, len, "USB");

    return true;
  }

  snprintf (buf, len, "USB:%uMb", priv->link_mbit);

  return true;
}

const fpga_transport_t fpga_transport_ztex213 =
{
  .name            = "ztex213",
  .bus             = "USB",
  .udev            = "99-ztex.rules",

  .dialect         = FPGA_DIALECT_HCFPGA,

  .retired_reads_zero = true,

  .enumerate       = ztex213_enumerate,
  .close           = ztex213_close,
  .identify        = ztex213_identify,

  .csr_read        = ztex213_csr_read,
  .csr_write       = ztex213_csr_write,

  .session_open    = ztex213_session_open,
  .session_close   = ztex213_session_close,
  .session_refresh = ztex213_session_refresh,
  .out_capacity    = ztex213_out_capacity,

  .batch_begin     = ztex213_batch_begin,
  .batch_send      = ztex213_batch_send,
  .control         = NULL,
  .batch_recv      = ztex213_batch_recv,
  .batch_end       = ztex213_batch_end,

  .batch_done      = ztex213_batch_done,
  .batch_failed    = ztex213_batch_failed,

  .in_granule      = 0,

  .program         = ztex213_program,

  .temperature     = ztex213_temperature,
  .temperature_all = NULL,

  .temperature_is_die = true,

  .clock_step_down = NULL,

  .link_str        = ztex213_link_str,
};

#else

static int ztex213_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  (void) hashcat_ctx;
  (void) devs;
  (void) max;

  *status = FPGA_STATUS_UNSUPPORTED_OS;

  return 0;
}

const fpga_transport_t fpga_transport_ztex213 =
{
  .name      = "ztex213",
  .bus       = "USB",
  .udev      = "99-ztex.rules",
  .dialect   = FPGA_DIALECT_HCFPGA,
  .enumerate = ztex213_enumerate,
};

#endif
