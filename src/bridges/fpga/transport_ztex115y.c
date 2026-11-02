/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "thread.h"

#include "fpga/hcfpga.h"
#include "fpga/ztex_usb.h"

#if defined (__linux__)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/usbdevice_fs.h>

#define ZTEX_VENDOR_CYPRESS    0x04b4
#define ZTEX_PRODUCT_FX2_BOOT  0x8613

static bool ztex_firmware_upload (const int fd, const char *path, const char **why, bool *wire_fault);

static void ztex_firmware_wire_report (hashcat_ctx_t *hashcat_ctx, const char *who, const char *why)
{
  event_log_error (hashcat_ctx, "FPGA bridge: the FX2 firmware upload to ZTEX board %s failed, because %s.", who, why);
  event_log_info (hashcat_ctx, "  Check the board's power, its USB cable and the hub it is on, then run again.");
  event_log_info (hashcat_ctx, NULL);
}

static void ztex_firmware_bad_report (hashcat_ctx_t *hashcat_ctx, const char *firmware, const char *why)
{
  if (fpga_report_once (fpga_board_find ("ztex115y"), "fx2-firmware-bad") == false) return;

  event_log_error (hashcat_ctx, "FPGA bridge: the ZTEX FX2 firmware file cannot be used, because %s.", why);

  event_log_info (hashcat_ctx, "  - File: %s", firmware);

  struct stat st;

  if (stat (firmware, &st) == 0) event_log_info (hashcat_ctx, "  - Size: %lld bytes", (long long) st.st_size);

  event_log_info (hashcat_ctx, NULL);

  event_log_info (hashcat_ctx, "  Download the file again and verify it against manifest.json. A file only a few");
  event_log_info (hashcat_ctx, "  kilobytes long is likely a server error page saved under the requested name.");

  event_log_info (hashcat_ctx, NULL);
}

#define ZTEX_FIRMWARE_NAME "inouttraffic.ihx"
#define ZTEX_BITSTREAM_FMT "ztex115y_%s.bit"

#define ZTEX_FIRMWARE_PRODUCT "inouttraffic 1.0.0 JtR"

#define ZTEX_NODE_MAX  32

#define ZTEX_PRODUCT_1_15Y        15

#define ZTEX_VR_TEMPERATURE   0x58

#define ZTEX_VR_OUTPUT_LIMIT  0x85

#define ZTEX_VC_SELECT_FPGA   0x51
#define ZTEX_VC_FX2_RAM       0xa0

#define ZTEX_VC_APP_MODE      0x82
#define ZTEX_VC_FPGA_RESET    0x8b
#define ZTEX_VC_PROGCLK       0x93
#define ZTEX_VC_SELECT_IO     0x8e
#define ZTEX_VR_SELECT_SETUP  0x8c

#define ZTEX_PKT_WORD_LIST    0x01

#define ZTEX_PKT_WORD_GEN     0x02

#define ZTEX_FX2_CPUCS        0xe600

#define ZTEX_HS_EP_DEFAULT       2
#define ZTEX_HS_EP_INOUTTRAFFIC  6

static const u32 ZTEX_TEMP_INDEX[4] = { 3, 4, 1, 2 };

#define ZTEX_TEMP_BYTES   5
#define ZTEX_TEMP_TAG     1
#define ZTEX_TEMP_OFFSET  77.2727
#define ZTEX_TEMP_SCALE   1.5454

#define ZTEX_TEMP_ABSENT  0xff

#define ZTEX_CAP_TEMP_SENSOR   8

#define ZTEX_VR_ECHO          0x88

#define ZTEX_ECHO_MAGIC       0x5a5a

typedef struct ztex_design
{
  u16         bitstream_type;

  const char *algo;

  u32         cores;

  u32         clk_mhz;

} ztex_design_t;

static const ztex_design_t ZTEX_DESIGNS[] =
{
  { 0xbc01, "bcrypt",      124, 150 },
  { 0x0101, "descrypt",    448, 150 },
  { 0xd5c0, "md5crypt",    252, 150 },
  { 0x256c, "sha256crypt",  90, 150 },
  { 0x512c, "sha512crypt",  45, 150 },
};

static const u32 ZTEX_DESIGNS_CNT = (u32) (sizeof (ZTEX_DESIGNS) / sizeof (ZTEX_DESIGNS[0]));

static u32 ztex_env_u32 (const char *name, const u32 fallback)
{
  const char *env = getenv (name);

  if (env == NULL) return fallback;

  const int n = atoi (env);

  if (n <= 0) return fallback;

  const u32 result = (u32) n;

  return result;
}

typedef struct ztex_clk
{
  u32 mhz;

  u32 m;
  u32 d;

} ztex_clk_t;

static const ztex_clk_t ZTEX_CLOCKS[] =
{
  { 135, 36, 81 },
  { 140, 35, 76 }, { 141, 38, 82 }, { 142, 35, 75 }, { 143, 32, 68 }, { 144, 37, 78 },
  { 145, 31, 65 }, { 146, 37, 77 }, { 147, 29, 60 }, { 148, 37, 76 }, { 149, 24, 49 },
  { 150, 31, 63 }, { 151, 39, 79 }, { 152, 39, 78 }, { 153, 39, 77 }, { 154, 32, 63 },
  { 155, 25, 49 }, { 156, 39, 76 }, { 157, 31, 60 }, { 158, 39, 75 }, { 159, 34, 65 },
  { 160, 30, 57 }, { 161, 36, 68 }, { 162, 32, 60 }, { 163, 37, 69 }, { 164, 34, 63 },
  { 165, 38, 70 }, { 166, 36, 66 }, { 167, 39, 71 }, { 168, 37, 67 }, { 169, 35, 63 },
  { 170, 33, 59 },
};

static const u32 ZTEX_CLOCKS_CNT = (u32) (sizeof (ZTEX_CLOCKS) / sizeof (ZTEX_CLOCKS[0]));

#define ZTEX_CLK_STEP_MHZ  5
#define ZTEX_CLK_FLOOR_MHZ 135

static const ztex_clk_t *ztex_clock (const ztex_design_t *design, const char *serial, const u32 steps)
{
  u32 asked = ztex_env_u32 ("HCFPGA_ZTEX_MHZ", design->clk_mhz);

  if ((serial) && (serial[0] != 0))
  {
    char name[64];

    snprintf (name, sizeof (name), "HCFPGA_ZTEX_MHZ_%s", serial);

    asked = ztex_env_u32 (name, asked);
  }

  asked = MIN (asked, design->clk_mhz);

  const u32 drop = steps * ZTEX_CLK_STEP_MHZ;

  const u32 want = (asked > (ZTEX_CLK_FLOOR_MHZ + drop)) ? (asked - drop) : ZTEX_CLK_FLOOR_MHZ;

  const ztex_clk_t *pick = &ZTEX_CLOCKS[0];

  for (u32 i = 0; i < ZTEX_CLOCKS_CNT; i++)
  {
    if (ZTEX_CLOCKS[i].mhz > want) break;

    pick = &ZTEX_CLOCKS[i];
  }

  return pick;
}

typedef struct ztex_board
{
  int  fd;
  int  refs;

  u32  num_fpgas;

  int  selected;

  bool firmware_ready;

  bool claimed;

  bool locked;
  int  dormant;

  u32  link_mbit;

  bool has_temp_sensor;

  char product[128];

  u32  clk_steps;

  char serial[16];

  char node[ZTEX_NODE_MAX];

} ztex_board_t;

#define ZTEX_RX_SLACK  65536

typedef struct ztex_priv
{
  ztex_board_t *board;

  u32           fpga_num;

  u16           bitstream_type;

  u16           pkt_id;

  u64           t0_ns;

  bool          done;
  u32           done_cnt;

  bool          packet_fault;

  u64           base;
  u64           words;

  u8           *rx;
  u64           rx_size;
  u64           rx_len;
  u64           rx_taken;

  u8           *tx;
  u64           tx_size;
  u64           tx_len;
  u64           tx_pos;

  u8           *out_buf;
  u64           out_size;

  u32           in_grain;
  u64           out_len;

} ztex_priv_t;

#define ZTEX_MAX_FPGA  4

typedef struct ztex_dev
{
  ztex_board_t *board;

  u32           fpga_cnt;

  ztex_priv_t   u[ZTEX_MAX_FPGA];

  u8           *out_buf;
  u64           out_size;

  u32           in_grain;

  u64           t0_ns;

  u8            gen_buf[32];
  u32           gen_len;

} ztex_dev_t;

static ztex_dev_t *ztex_dev (fpga_dev_t *dev)
{
  ztex_dev_t *result = (ztex_dev_t *) dev->priv;

  return result;
}

#define ZTEX_BULK_TIMEOUT 5000

#define ZTEX_DRAIN_TIMEOUT 100

#define ZTEX_SEND_STALL_MS 3000

#define ZTEX_SFIFO_TRIES 2000
#define ZTEX_SFIFO_WAIT  50

static bool ztex_select_fpga (ztex_board_t *board, const u32 fpga_num)
{
  if (fpga_num >= board->num_fpgas) return false;

  if (board->selected == (int) fpga_num) return true;

  if (ztex_control_write (board->fd, ZTEX_VC_SELECT_FPGA, (u16) fpga_num, 0) == false)
  {
    board->selected = -1;

    return false;
  }

  board->selected = (int) fpga_num;

  return true;
}

static bool ztex_select_io (ztex_board_t *board, const u32 fpga_num)
{
  if (fpga_num >= board->num_fpgas) return false;

  if (ztex_control_write (board->fd, ZTEX_VC_SELECT_IO, (u16) fpga_num, 0) == false) return false;

  board->selected = -1;

  return true;
}

static bool ztex_select_setup_io (ztex_board_t *board, const u32 fpga_num, u8 *io, u32 *limit)
{
  if (fpga_num >= board->num_fpgas) return false;

  u8 buf[8];

  if (ztex_control_read (board->fd, ZTEX_VR_SELECT_SETUP, (u16) fpga_num, 0, buf, sizeof (buf)) != (int) sizeof (buf))
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u select_setup_io failed, errno %d (%s)\n", fpga_num, errno, strerror (errno));

    return false;
  }

  board->selected = -1;

  memcpy (io, buf, 6);

  *limit = (u32) (buf[6] | (buf[7] << 8)) * 2;

  return true;
}

#define ZTEX_STATE_TRIES 8
#define ZTEX_STATE_WAIT  20000

static bool ztex_fpga_configured (ztex_board_t *board, const u32 fpga_num)
{
  if (ztex_select_fpga (board, fpga_num) == false) return false;

  u8 buf[9];

  for (u32 attempt = 0; attempt < ZTEX_STATE_TRIES; attempt++)
  {
    const int got = ztex_control_read (board->fd, ZTEX_VR_FPGA_STATE, 0, 0, buf, sizeof (buf));

    if (got == (int) sizeof (buf))
    {
      const bool configured = (buf[0] == 0);

      return configured;
    }

    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u state reply was %d bytes, asking again\n", fpga_num, got);

    usleep (ZTEX_STATE_WAIT);
  }

  return false;
}

#define ZTEX_ECHO_TRIES 8
#define ZTEX_ECHO_WAIT  20000

static bool ztex_echo_once (ztex_board_t *board, const u32 fpga_num, u16 *bitstream_type)
{
  const u16 out0 = 0xa53c;
  const u16 out1 = 0x0f96;

  u8 reply[8];

  if (ztex_control_read (board->fd, ZTEX_VR_ECHO, out0, out1, reply, sizeof (reply)) != (int) sizeof (reply)) return false;

  const u16 back0 = (u16) (reply[0] | (reply[1] << 8));
  const u16 back1 = (u16) (reply[2] | (reply[3] << 8));

  if ((back0 ^ ZTEX_ECHO_MAGIC) != out0) return false;
  if ((back1 ^ ZTEX_ECHO_MAGIC) != out1) return false;

  if (reply[4] != (u8) fpga_num) return false;

  *bitstream_type = (u16) (reply[6] | (reply[7] << 8));

  return true;
}

static bool ztex_echo (ztex_board_t *board, const u32 fpga_num, u16 *bitstream_type)
{
  if (ztex_select_fpga (board, fpga_num) == false) return false;

  for (u32 attempt = 0; attempt < ZTEX_ECHO_TRIES; attempt++)
  {
    if (ztex_echo_once (board, fpga_num, bitstream_type) == true) return true;

    usleep (ZTEX_ECHO_WAIT);
  }

  return false;
}

static int ztex_temperature_all (fpga_dev_t *dev, int *out, const u32 out_max)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return -1;

  if (zd->board->has_temp_sensor == false) return -1;

  u8 buf[ZTEX_TEMP_BYTES];

  const int got = ztex_control_read (zd->board->fd, ZTEX_VR_TEMPERATURE, 0, 0, buf, sizeof (buf));

  if (got != (int) sizeof (buf)) return -1;

  if (buf[0] != ZTEX_TEMP_TAG) return -1;

  int hottest = -1;

  for (u32 i = 0; i < zd->fpga_cnt; i++)
  {
    const u8 raw = buf[ZTEX_TEMP_INDEX[i]];

    if (raw == ZTEX_TEMP_ABSENT)
    {
      if ((out != NULL) && (i < out_max)) out[i] = -1;

      continue;
    }

    const int celsius = (int) (((double) raw - ZTEX_TEMP_OFFSET) / ZTEX_TEMP_SCALE);

    int val = celsius;

    if (celsius > 125) val = -1;
    if (celsius < -40) val = -1;

    if ((out != NULL) && (i < out_max)) out[i] = val;

    if (val > hottest) hottest = val;
  }

  if (out != NULL) return (int) ((zd->fpga_cnt < out_max) ? zd->fpga_cnt : out_max);

  return hottest;
}

static bool ztex_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  if (zd->board->link_mbit == 0) return false;

  snprintf (buf, len, "USB:%uMb/s", zd->board->link_mbit);

  return true;
}

static int ztex_temperature (fpga_dev_t *dev)
{
  const int result = ztex_temperature_all (dev, NULL, 0);

  return result;
}

static void ztex_close (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd)
  {
    for (u32 i = 0; i < zd->fpga_cnt; i++)
    {
      ztex_priv_t *priv = &zd->u[i];

      if (priv->rx)      hcfree (priv->rx);
      if (priv->tx)      hcfree (priv->tx);
      if (priv->out_buf) hcfree (priv->out_buf);
    }

    if (zd->out_buf) hcfree (zd->out_buf);

    ztex_board_t *board = zd->board;

    board->refs--;

    if (board->refs == 0)
    {
      if (board->fd >= 0) close (board->fd);

      hcfree (board);
    }

    hcfree (zd);

    dev->priv = NULL;
  }

  dev->fd = -1;
}

static void ztex_release (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return;

  ztex_board_t *board = zd->board;

  board->dormant++;

  if (board->dormant < board->refs) return;
  if (board->locked == false)       return;

  flock (board->fd, LOCK_UN);

  board->locked = false;
}

static int ztex_add_board (const char *node, const char *devdir, fpga_dev_t *devs, const int max)
{
  const int fd = open (node, O_RDWR);

  if (fd < 0) return 0;

  u8 desc[40];

  if (ztex_control_read (fd, ZTEX_VR_DESCRIPTOR, 0, 0, desc, sizeof (desc)) != (int) sizeof (desc))
  {
    close (fd);

    return 0;
  }

  if (memcmp (&desc[2], "ZTEX", 4) != 0)
  {
    close (fd);

    return 0;
  }

  if (desc[6] != ZTEX_PRODUCT_FPGA_MODULE) { close (fd); return 0; }
  if (desc[7] != ZTEX_PRODUCT_1_15Y)       { close (fd); return 0; }

  u8 multi[3];

  if (ztex_control_read (fd, ZTEX_VR_MULTI_FPGA, 0, 0, multi, sizeof (multi)) != (int) sizeof (multi))
  {
    close (fd);

    return 0;
  }

  const u32 num_fpgas = (u32) multi[0] + 1;

  if (num_fpgas != 4)
  {
    close (fd);

    return 0;
  }

  ztex_board_t *board = (ztex_board_t *) hcmalloc (sizeof (ztex_board_t));

  if (board == NULL)
  {
    close (fd);

    return 0;
  }

  board->fd             = fd;
  board->refs           = 0;
  board->clk_steps      = 0;
  board->num_fpgas      = num_fpgas;
  board->selected       = -1;
  board->firmware_ready = false;
  board->claimed        = false;
  board->locked         = false;
  board->dormant        = 0;

  const u32 caps = (u32) desc[ZTEX_DESC_CAPS_OFFSET + 0] | ((u32) desc[ZTEX_DESC_CAPS_OFFSET + 1] << 8);

  board->has_temp_sensor = (((caps >> ZTEX_CAP_TEMP_SENSOR) & 1) != 0);

  board->link_mbit = 0;

  char speed[32];

  if (ztex_sysfs_read (devdir, "speed", speed, sizeof (speed)) == true)
  {
    board->link_mbit = (u32) strtoul (speed, NULL, 10);
  }

  board->product[0] = 0;

  ztex_sysfs_read (devdir, "product", board->product, sizeof (board->product));

  snprintf (board->node, sizeof (board->node), "%s", node);

  memcpy (board->serial, &desc[30], 10);

  board->serial[10] = 0;

  int cnt = 0;

  if (cnt < max)
  {
    fpga_dev_t *dev = &devs[cnt];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->path, sizeof (dev->path), "%s", node);

    dev->fd = fd;

    ztex_dev_t *zd = (ztex_dev_t *) hcmalloc (sizeof (ztex_dev_t));

    if (zd == NULL)
    {
      close (fd);

      hcfree (board);

      return 0;
    }

    zd->board    = board;
    zd->fpga_cnt = (num_fpgas > ZTEX_MAX_FPGA) ? ZTEX_MAX_FPGA : num_fpgas;

    zd->out_buf  = NULL;
    zd->out_size = 0;
    zd->in_grain = 0;

    for (u32 i = 0; i < zd->fpga_cnt; i++)
    {
      ztex_priv_t *priv = &zd->u[i];

      priv->board          = board;
      priv->fpga_num       = i;
      priv->bitstream_type = 0;
      priv->packet_fault   = false;

      priv->pkt_id = (u16) (i + 1);

      priv->rx       = NULL;
      priv->rx_size  = 0;
      priv->rx_len   = 0;
      priv->rx_taken = 0;

      priv->tx       = NULL;
      priv->tx_size  = 0;
      priv->tx_len   = 0;
      priv->tx_pos   = 0;

      priv->out_buf  = NULL;
      priv->out_size = 0;

      priv->in_grain = 0;
      priv->out_len  = 0;
    }

    dev->priv = zd;

    board->refs++;

    cnt++;
  }

  if (cnt == 0)
  {
    close (fd);

    hcfree (board);
  }

  return cnt;
}

#define ZTEX_FX2_BOOT_WAIT 2000000

static int ztex_wake_blank_boards (hashcat_ctx_t *hashcat_ctx)
{
  char firmware[FPGA_PATH_MAX];

  if (fpga_shipped_file (hashcat_ctx->folder_config, ZTEX_FIRMWARE_NAME, firmware, sizeof (firmware)) == false) return 0;

  DIR *d = opendir ("/sys/bus/usb/devices");

  if (d == NULL) return 0;

  int woke = 0;

  bool told = false;

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if (e->d_name[0] == '.') continue;

    char devdir[FPGA_PATH_MAX];

    snprintf (devdir, sizeof (devdir), "/sys/bus/usb/devices/%s", e->d_name);

    char vendor[32];
    char product[32];

    if (ztex_sysfs_read (devdir, "idVendor",  vendor,  sizeof (vendor))  == false) continue;
    if (ztex_sysfs_read (devdir, "idProduct", product, sizeof (product)) == false) continue;

    if (strtol (vendor,  NULL, 16) != ZTEX_VENDOR_CYPRESS)   continue;
    if (strtol (product, NULL, 16) != ZTEX_PRODUCT_FX2_BOOT) continue;

    char busnum[32];
    char devnum[32];

    if (ztex_sysfs_read (devdir, "busnum", busnum, sizeof (busnum)) == false) continue;
    if (ztex_sysfs_read (devdir, "devnum", devnum, sizeof (devnum)) == false) continue;

    char node[ZTEX_NODE_MAX];

    snprintf (node, sizeof (node), "/dev/bus/usb/%03ld/%03ld", strtol (busnum, NULL, 10), strtol (devnum, NULL, 10));

    if (getenv ("HCFPGA_ZTEX_WAKE") == NULL)
    {
      if (told == false) event_log_warning (hashcat_ctx, "FPGA bridge: %s is a Cypress FX2 without firmware. If it is a ZTEX 1.15y, run with HCFPGA_ZTEX_WAKE=1 to load its firmware.", node);

      told = true;

      continue;
    }

    const int fd = open (node, O_RDWR);

    if (fd < 0) continue;

    if (ztex_dbg () == true) fprintf (stderr, "[ztex] %s is a blank FX2, uploading %s\n", node, firmware);

    const char *why = "the upload itself failed on the wire";

    bool wire_fault = false;

    const bool ok = ztex_firmware_upload (fd, firmware, &why, &wire_fault);

    close (fd);

    if (ok == false)
    {
      if (wire_fault == true) ztex_firmware_wire_report (hashcat_ctx, node, why);
      else                    ztex_firmware_bad_report  (hashcat_ctx, firmware, why);

      if (ztex_dbg () == true) fprintf (stderr, "[ztex] %s firmware upload FAILED: %s\n", node, why);

      continue;
    }

    woke++;
  }

  closedir (d);

  return woke;
}

static int ztex_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  int cnt = 0;

  bool saw_board      = false;
  bool saw_permission = false;

  if (ztex_wake_blank_boards (hashcat_ctx) > 0) usleep (ZTEX_FX2_BOOT_WAIT);

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

    saw_board = true;

    char busnum[32];
    char devnum[32];

    if (ztex_sysfs_read (devdir, "busnum", busnum, sizeof (busnum)) == false) continue;
    if (ztex_sysfs_read (devdir, "devnum", devnum, sizeof (devnum)) == false) continue;

    char node[ZTEX_NODE_MAX];

    snprintf (node, sizeof (node), "/dev/bus/usb/%03ld/%03ld", strtol (busnum, NULL, 10), strtol (devnum, NULL, 10));

    if (access (node, R_OK | W_OK) != 0)
    {
      if (errno == EACCES) saw_permission = true;

      continue;
    }

    cnt += ztex_add_board (node, devdir, &devs[cnt], max - cnt);
  }

  closedir (d);

  if (cnt == 0)
  {
    if (saw_permission == true)
    {
      *status = FPGA_STATUS_NO_PERMISSION;
    }
    else if (saw_board == true)
    {
      *status = FPGA_STATUS_BAD_IDENT;
    }
    else
    {
      *status = FPGA_STATUS_NO_PCI_DEVICE;
    }
  }

  return cnt;
}

static fpga_status_t ztex_identify (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return FPGA_STATUS_BAD_IDENT;

  snprintf (dev->ident.board, sizeof (dev->ident.board), "ztex115y");

  snprintf (dev->ident.serial, sizeof (dev->ident.serial), "%s", zd->board->serial);

  if (zd->board->locked == false)
  {
    if (flock (zd->board->fd, LOCK_EX | LOCK_NB) != 0) return FPGA_STATUS_IN_USE;

    zd->board->locked = true;
  }

  dev->ident.n   = 0;
  dev->ident.r   = 0;
  dev->ident.abi = FPGA_ABI_CURRENT;

  const ztex_design_t *design = NULL;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    if (ztex_fpga_configured (zd->board, priv->fpga_num) == false)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] identify: fpga %u reports not configured\n", priv->fpga_num);

      return FPGA_STATUS_BAD_IDENT;
    }

    u16 bitstream_type = 0;

    if (ztex_echo (zd->board, priv->fpga_num, &bitstream_type) == false)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] identify: fpga %u is configured and does not answer the echo\n", priv->fpga_num);

      return FPGA_STATUS_BAD_IDENT;
    }

    priv->bitstream_type = bitstream_type;

    const ztex_design_t *found = NULL;

    for (u32 i = 0; i < ZTEX_DESIGNS_CNT; i++)
    {
      if (ZTEX_DESIGNS[i].bitstream_type != bitstream_type) continue;

      found = &ZTEX_DESIGNS[i];

      break;
    }

    if (found == NULL)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] identify: fpga %u answered with unknown bitstream type 0x%04x\n", priv->fpga_num, bitstream_type);

      return FPGA_STATUS_BAD_IDENT;
    }

    if (design == NULL) design = found;

    if (found != design)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] identify: fpga %u runs %s and an earlier fpga runs %s\n", priv->fpga_num, found->algo, design->algo);

      return FPGA_STATUS_BAD_IDENT;
    }
  }

  if (design == NULL)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] identify: board has no fpga to ask, fpga_cnt %u\n", zd->fpga_cnt);

    return FPGA_STATUS_BAD_IDENT;
  }

  snprintf (dev->ident.algo, sizeof (dev->ident.algo), "%s", design->algo);

  dev->ident.cores   = design->cores * zd->fpga_cnt;
  dev->ident.clk_mhz = ztex_clock (design, zd->board->serial, zd->board->clk_steps)->mhz;

  dev->ident.build[0] = 0;

  snprintf (dev->ident.raw, sizeof (dev->ident.raw), "%s1;board=%s;algo=%s;cores=%u;clk=%u;abi=%u;sn=%s;fpgas=%u",
    FPGA_IDENT_PREFIX, dev->ident.board, dev->ident.algo, dev->ident.cores, dev->ident.clk_mhz, dev->ident.abi,
    zd->board->serial, zd->fpga_cnt);

  return FPGA_STATUS_OK;
}

#define ZTEX_EP_OUT  0x06
#define ZTEX_EP_IN   0x82

#define ZTEX_LINK_OUT_MAX  6144
#define ZTEX_LINK_IN_MAX   8190
#define ZTEX_LINK_ALIGN    2

#define ZTEX_IO_INPUT_PROG_FULL  0x01

#define ZTEX_IO_SFIFO_NOT_EMPTY  0x08

#define ZTEX_VR_IO_STATE  0x84

#define ZTEX_PKT_VERSION     2
#define ZTEX_PKT_HEADER_LEN  10
#define ZTEX_PKT_CSUM_LEN    4

#define ZTEX_PKT_MAX_DATA_LEN  ((16 * 65536) - ZTEX_PKT_HEADER_LEN - (2 * ZTEX_PKT_CSUM_LEN))

#define ZTEX_PKT_PACKET_DONE  0xd2
#define ZTEX_PKT_CMP_RESULT   0xd4

#define ZTEX_RESULT_LEN       24
#define ZTEX_REC_CMP_RESULT   (2 + 4 + 2 + ZTEX_RESULT_LEN)

#define ZTEX_TASK_CANDIDATES  8192
#define ZTEX_TASK_CAND_BYTES  72
#define ZTEX_TASK_WORD_BYTES  (ZTEX_TASK_CAND_BYTES + 1)

#define ZTEX_SLOT_MAX  65536

#define ZTEX_TASK_CANDIDATES_MAX  (ZTEX_SLOT_MAX / ZTEX_MAX_FPGA)

static u32 ztex_task_candidates (void)
{
  const u32 asked = ztex_env_u32 ("ZTEX_CANDS", ZTEX_TASK_CANDIDATES);

  const u32 result = MIN (asked, ZTEX_TASK_CANDIDATES_MAX);

  return result;
}

#define ZTEX_WORD_PKT_MAX  (ZTEX_TASK_CANDIDATES * ZTEX_TASK_CAND_BYTES)

static u32 ztex_pkt_checksum (const u8 *data, const u32 len)
{
  u32 sum = 0;
  u32 acc = 0;

  u32 n = 0;

  for (u32 i = 0; i < len; i++)
  {
    acc |= ((u32) data[i]) << (8 * n);

    n++;

    if (n < ZTEX_PKT_CSUM_LEN) continue;

    sum += acc;

    acc = 0;
    n   = 0;
  }

  sum += acc;

  const u32 checksum = ~sum;

  return checksum;
}

static void ztex_put32 (u8 *dst, const u32 val)
{
  dst[0] = (u8) (val >>  0);
  dst[1] = (u8) (val >>  8);
  dst[2] = (u8) (val >> 16);
  dst[3] = (u8) (val >> 24);
}

static bool ztex_bulk_read (const int fd, const u32 ep, void *dst, const u32 len, const u32 timeout_ms, u32 *got)
{
  const int rc = ztex_bulk_xfer (fd, (u8) ep, dst, len, timeout_ms);

  if (rc < 0) return false;

  *got = (u32) rc;

  return true;
}

static bool ztex_service (ztex_board_t *board, ztex_priv_t *priv, const u32 timeout_ms);

static bool ztex_pkt_queue (ztex_priv_t *priv, const u8 type, const void *src, const u32 len)
{
  if (len > ZTEX_PKT_MAX_DATA_LEN) return false;

  if ((priv->tx_len > 0) && (priv->tx_pos >= priv->tx_len))
  {
    priv->tx_len = 0;
    priv->tx_pos = 0;
  }

  const u64 total = ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN + len + ZTEX_PKT_CSUM_LEN;

  const u64 pad = total & 1;

  if ((priv->tx_len + total + pad) > priv->tx_size)
  {
    const u64 want = priv->tx_len + total + pad + ZTEX_RX_SLACK;

    u8 *tx = (u8 *) hcrealloc (priv->tx, priv->tx_size, want - priv->tx_size);

    if (tx == NULL) return false;

    priv->tx      = tx;
    priv->tx_size = want;
  }

  u8 *buf = &priv->tx[priv->tx_len];

  memset (buf, 0, ZTEX_PKT_HEADER_LEN);

  buf[0] = ZTEX_PKT_VERSION;
  buf[1] = type;
  buf[4] = (u8) (len >>  0);
  buf[5] = (u8) (len >>  8);
  buf[6] = (u8) (len >> 16);

  buf[8] = (u8) (priv->pkt_id >> 0);
  buf[9] = (u8) (priv->pkt_id >> 8);

  ztex_put32 (&buf[ZTEX_PKT_HEADER_LEN], ztex_pkt_checksum (buf, ZTEX_PKT_HEADER_LEN));

  if (len > 0) memcpy (&buf[ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN], src, len);

  ztex_put32 (&buf[ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN + len], ztex_pkt_checksum (&buf[ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN], len));

  if (pad > 0) buf[total] = 0;

  priv->tx_len += total + pad;

  return true;
}

static bool ztex_service (ztex_board_t *board, ztex_priv_t *priv, const u32 timeout_ms)
{
  u8 io[6];

  u32 limit = 0;

  if (ztex_select_setup_io (board, priv->fpga_num, io, &limit) == false) return false;

  if (io[2] != 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u app_status 0x%02x\n", priv->fpga_num, io[2]);

    return false;
  }

  if (io[3] != 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u pkt_comm_status 0x%02x\n", priv->fpga_num, io[3]);

    return false;
  }

  if ((io[0] & ~(ZTEX_IO_INPUT_PROG_FULL | ZTEX_IO_SFIFO_NOT_EMPTY)) != 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u io_state 0x%02x\n", priv->fpga_num, io[0]);

    return false;
  }

  if ((io[0] & ZTEX_IO_INPUT_PROG_FULL) == 0)
  {
    if (priv->tx_pos < priv->tx_len)
    {
      u64 n = priv->tx_len - priv->tx_pos;

      if (n > ZTEX_LINK_OUT_MAX) n = ZTEX_LINK_OUT_MAX;

      if (ztex_bulk_write (board->fd, ZTEX_EP_OUT, &priv->tx[priv->tx_pos], (u32) n) == false) return false;

      priv->tx_pos += n;

      bool drained = false;

      for (u32 attempt = 0; attempt < ZTEX_SFIFO_TRIES; attempt++)
      {
        u8 st[6];

        if (ztex_control_read (board->fd, ZTEX_VR_IO_STATE, 0, 0, st, 6) != 6) return false;

        if ((st[0] & ZTEX_IO_SFIFO_NOT_EMPTY) == 0)
        {
          drained = true;

          break;
        }

        usleep (ZTEX_SFIFO_WAIT);
      }

      if (drained == false) return false;
    }
  }

  if (limit == 0) return true;

  if ((priv->rx_len + limit) > priv->rx_size)
  {
    const u64 want = priv->rx_len + limit + ZTEX_RX_SLACK;

    u8 *rx = (u8 *) hcrealloc (priv->rx, priv->rx_len, want - priv->rx_len);

    if (rx == NULL) return false;

    priv->rx      = rx;
    priv->rx_size = want;
  }

  u32 done = 0;

  while (done < limit)
  {
    u32 got = 0;

    if (ztex_bulk_read (board->fd, ZTEX_EP_IN, &priv->rx[priv->rx_len], limit - done, timeout_ms, &got) == false) return false;

    if (got == 0) return false;

    priv->rx_len += got;

    done += got;
  }

  return true;
}

static bool ztex_pkt_take (ztex_priv_t *priv, u8 *type, u16 *pkt_id, const u8 **data, u32 *len)
{
  if (priv->rx_len < (ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN)) return false;

  const u8 *h = priv->rx;

  if (h[0] != ZTEX_PKT_VERSION)
  {
    priv->packet_fault = true;

    return false;
  }

  const u32 header_checksum = (u32) h[10] | ((u32) h[11] << 8) | ((u32) h[12] << 16) | ((u32) h[13] << 24);

  if (header_checksum != ztex_pkt_checksum (h, ZTEX_PKT_HEADER_LEN))
  {
    priv->packet_fault = true;

    return false;
  }

  const u32 data_len = (u32) h[4] | ((u32) h[5] << 8) | ((u32) h[6] << 16);

  const u32 total = ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN + data_len + ZTEX_PKT_CSUM_LEN;

  if (priv->rx_len < total) return false;

  const u8 *payload = &h[ZTEX_PKT_HEADER_LEN + ZTEX_PKT_CSUM_LEN];

  const u8 *payload_checksum_ptr = &payload[data_len];

  const u32 payload_checksum = (u32) payload_checksum_ptr[0]
                             | ((u32) payload_checksum_ptr[1] << 8)
                             | ((u32) payload_checksum_ptr[2] << 16)
                             | ((u32) payload_checksum_ptr[3] << 24);

  if (payload_checksum != ztex_pkt_checksum (payload, data_len))
  {
    priv->packet_fault = true;

    return false;
  }

  *type   = h[1];
  *pkt_id = (u16) (h[8] | (h[9] << 8));
  *data   = payload;
  *len    = data_len;

  priv->rx_taken = total;

  return true;
}

static void ztex_pkt_drop (ztex_priv_t *priv)
{
  if (priv->rx_taken == 0) return;

  memmove (priv->rx, &priv->rx[priv->rx_taken], priv->rx_len - priv->rx_taken);

  priv->rx_len -= priv->rx_taken;

  priv->rx_taken = 0;
}

#define ZTEX_APP_MODE_COMPAR  0

static bool ztex_arm_one (ztex_board_t *board, ztex_priv_t *priv)
{
  bool ok = ztex_select_io (board, priv->fpga_num);

  if (ok == true)
  {
    const ztex_design_t *design = NULL;

    for (u32 i = 0; i < ZTEX_DESIGNS_CNT; i++)
    {
      if (ZTEX_DESIGNS[i].bitstream_type != priv->bitstream_type) continue;

      design = &ZTEX_DESIGNS[i];

      break;
    }

    if (design == NULL) return false;

    const ztex_clk_t *clk = ztex_clock (design, board->serial, board->clk_steps);

    const u16 value = (u16) (priv->fpga_num | (0 << 8));

    const u16 index = (u16) (clk->d | (clk->m << 8));

    ok = ztex_control_write (board->fd, ZTEX_VC_PROGCLK, value, index);
  }

  if (ok == true) ok = ztex_control_write (board->fd, ZTEX_VC_FPGA_RESET, 0, 0);

  if (ok == true) ok = ztex_control_write (board->fd, ZTEX_VC_APP_MODE, ZTEX_APP_MODE_COMPAR, 0);

  const bool result = ok;

  return result;
}

static u32 ztex_clock_step_down (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return 0;

  if (zd->fpga_cnt == 0) return 0;

  const ztex_design_t *design = NULL;

  for (u32 i = 0; i < ZTEX_DESIGNS_CNT; i++)
  {
    if (ZTEX_DESIGNS[i].bitstream_type != zd->u[0].bitstream_type) continue;

    design = &ZTEX_DESIGNS[i];

    break;
  }

  if (design == NULL) return 0;

  ztex_board_t *board = zd->board;

  const u32 now = ztex_clock (design, board->serial, board->clk_steps)->mhz;

  if (now <= ZTEX_CLK_FLOOR_MHZ) return 0;

  board->clk_steps++;

  const u32 next = ztex_clock (design, board->serial, board->clk_steps)->mhz;

  if (next >= now)
  {
    board->clk_steps--;

    return 0;
  }

  dev->ident.clk_mhz = next;

  if (ztex_dbg () == true) fprintf (stderr, "[ztex] %s stepping down %u -> %u MHz\n", board->serial, now, next);

  return next;
}

static bool ztex_session_open_one (ztex_board_t *board, ztex_priv_t *priv)
{
  if (ztex_arm_one (board, priv) == false) return false;

  priv->rx_size = ZTEX_RX_SLACK;
  priv->rx      = (u8 *) hcmalloc (priv->rx_size);
  priv->rx_len  = 0;

  if (priv->rx == NULL)
  {
    priv->rx_size = 0;

    return false;
  }

  return true;
}

#define ZTEX_DRAIN_PASSES   8
#define ZTEX_DRAIN_BYTES    4096
#define ZTEX_DRAIN_WAIT_MS  20

static void ztex_drain_one (ztex_board_t *board, ztex_priv_t *priv)
{
  if (ztex_select_io (board, priv->fpga_num) == false) return;

  for (u32 pass = 0; pass < ZTEX_DRAIN_PASSES; pass++)
  {
    u8 sink[ZTEX_DRAIN_BYTES];

    u32 got = 0;

    if (ztex_bulk_read (board->fd, ZTEX_EP_IN, sink, (u32) sizeof (sink), ZTEX_DRAIN_WAIT_MS, &got) == false) break;

    if (got == 0) break;
  }
}

static bool ztex_session_refresh (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  bool ok = true;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    ztex_drain_one (zd->board, priv);

    if (ztex_arm_one (zd->board, priv) == false) ok = false;

    priv->rx_len    = 0;
    priv->rx_taken  = 0;

    priv->tx_len    = 0;
    priv->tx_pos    = 0;

    priv->out_len   = 0;

    priv->done      = false;
    priv->done_cnt  = 0;
    priv->packet_fault = false;

    priv->base      = 0;
    priv->words     = 0;
  }

  const bool result = ok;

  return result;
}

static bool ztex_session_open (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  ztex_board_t *board = zd->board;

  if (board->claimed == false)
  {
    if (ztex_claim (board->fd) == false) return false;

    board->claimed = true;
  }

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    if (ztex_session_open_one (zd->board, &zd->u[f]) == false) return false;
  }

  return true;
}

static void ztex_session_close (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    if (priv->rx)
    {
      hcfree (priv->rx);

      priv->rx = NULL;
    }

    priv->rx_size  = 0;
    priv->rx_len   = 0;
    priv->rx_taken = 0;

    if (priv->tx)
    {
      hcfree (priv->tx);

      priv->tx = NULL;
    }

    priv->tx_size = 0;
    priv->tx_len  = 0;
    priv->tx_pos  = 0;
  }
}

static u64 ztex_out_capacity (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return 0;

  const u64 result = (u64) ztex_task_candidates () * ZTEX_TASK_WORD_BYTES * zd->fpga_cnt;

  return result;
}

static bool ztex_batch_begin (fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, MAYBE_UNUSED const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  if (in_recs > ZTEX_SLOT_MAX)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] batch refused: %u records, and a result names its candidate in 16 bits\n", in_recs);

    return false;
  }

  zd->in_grain = in_grain;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    priv->in_grain = in_grain;

    priv->rx_len   = 0;
    priv->rx_taken = 0;
    priv->out_len  = 0;

    priv->done      = false;
    priv->done_cnt  = 0;
    priv->packet_fault = false;

    priv->base  = 0;
    priv->words = 0;
  }

  zd->t0_ns = fpga_now_ns ();

  return true;
}

static bool ztex_batch_done (fpga_dev_t *dev, u32 *processed)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  u32 total = 0;

  bool all = true;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    const ztex_priv_t *priv = &zd->u[f];

    if (priv->packet_fault == true)
    {
      if (processed != NULL) *processed = 0;

      return true;
    }

    if (priv->done == false) all = false;

    total += priv->done_cnt;
  }

  if (processed != NULL) *processed = total;

  return all;
}

static u64 ztex_word_end (const u8 *buf, const u64 bytes, const u64 off)
{
  u64 i = off;

  u64 n = 0;

  while ((i < bytes) && (n < ZTEX_TASK_CAND_BYTES))
  {
    const bool nul = (buf[i] == 0) ? true : false;

    i++;

    if (nul == true) return i;

    n++;
  }

  return i;
}

static bool ztex_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  if (bytes > ztex_out_capacity (dev))
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] send refused before any transfer: %llu bytes wanted, capacity %llu\n", (unsigned long long) bytes, (unsigned long long) ztex_out_capacity (dev));

    return false;
  }

  const u8 *buf = (const u8 *) src;

  u64 total_words = 0;

  for (u64 i = 0; i < bytes; )
  {
    i = ztex_word_end (buf, bytes, i);

    total_words++;
  }

  if (total_words == 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] send refused: %llu bytes hold no whole word\n", (unsigned long long) bytes);

    return false;
  }

  const u64 per = (total_words + zd->fpga_cnt - 1) / zd->fpga_cnt;

  u64 off  = 0;
  u64 base = 0;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    priv->base  = base;
    priv->words = 0;

    if (off >= bytes)
    {
      priv->done     = true;
      priv->done_cnt = 0;

      continue;
    }

    u64 end   = off;
    u64 words = 0;

    while ((end < bytes) && (words < per))
    {
      end = ztex_word_end (buf, bytes, end);

      words++;
    }

    const u64 len = end - off;

    if (zd->gen_len > 0)
    {
      if (ztex_pkt_queue (priv, ZTEX_PKT_WORD_GEN, zd->gen_buf, zd->gen_len) == false)
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u could not queue the generator packet, %u bytes\n", priv->fpga_num, zd->gen_len);

        return false;
      }
    }

    const bool queued = ztex_pkt_queue (priv, ZTEX_PKT_WORD_LIST, &buf[off], (u32) len);

    if (queued == false)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u could not queue a word list of %llu bytes, limit %u\n", priv->fpga_num, (unsigned long long) len, (u32) ZTEX_PKT_MAX_DATA_LEN);

      return false;
    }

    priv->words = words;

    base += words;
    off   = end;
  }

  u64 deadline_ns = fpga_now_ns () + ((u64) ZTEX_SEND_STALL_MS * 1000000ull);

  for (;;)
  {
    bool pending  = false;
    bool progress = false;

    for (u32 f = 0; f < zd->fpga_cnt; f++)
    {
      ztex_priv_t *priv = &zd->u[f];

      if (priv->tx_pos >= priv->tx_len) continue;

      pending = true;

      const u64 before = priv->tx_pos;

      if (ztex_service (zd->board, priv, 1) == false) return false;

      if (priv->tx_pos > before) progress = true;
    }

    if (pending == false) break;

    if (progress == true)
    {
      deadline_ns = fpga_now_ns () + ((u64) ZTEX_SEND_STALL_MS * 1000000ull);

      continue;
    }

    if (fpga_now_ns () > deadline_ns)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] board stalled with data still queued\n");

      return false;
    }
  }

  return true;
}

static const void *ztex_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  ztex_dev_t *zd = ztex_dev (dev);

  *bytes = 0;

  if (zd == NULL) return NULL;

  u64 out = 0;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    ztex_priv_t *priv = &zd->u[f];

    if (priv->words == 0) continue;

    if (ztex_service (zd->board, priv, (timeout_ms > 0) ? timeout_ms : 1) == false) break;

    for (;;)
    {
      u8         type   = 0;
      u16        pkt_id = 0;
      const u8  *data   = NULL;
      u32        len    = 0;

      if (ztex_pkt_take (priv, &type, &pkt_id, &data, &len) == false) break;

      if (pkt_id != priv->pkt_id)
      {
        ztex_pkt_drop (priv);

        continue;
      }

      if (type == ZTEX_PKT_PACKET_DONE)
      {
        if (len != 4)
        {
          priv->packet_fault = true;

          break;
        }

        priv->done_cnt = (u32) data[0] | ((u32) data[1] << 8) | ((u32) data[2] << 16) | ((u32) data[3] << 24);

        priv->done = true;

        if (ztex_dbg () == true)
        {
          const double ms = (double) (fpga_now_ns () - zd->t0_ns) / 1.0e6;

          fprintf (stderr, "[ztex] fpga %u done, %u processed in %.2f ms\n", priv->fpga_num, priv->done_cnt, ms);
        }

        ztex_pkt_drop (priv);

        continue;
      }

      if (type != ZTEX_PKT_CMP_RESULT)
      {
        ztex_pkt_drop (priv);

        continue;
      }

      if (len != zd->in_grain)
      {
        ztex_pkt_drop (priv);

        continue;
      }

      const u64 word_id = (u64) data[0] | ((u64) data[1] << 8);

      if (word_id >= priv->words)
      {
        ztex_pkt_drop (priv);

        continue;
      }

      if ((out + len) > zd->out_size)
      {
        const u64 want_size = out + len + ZTEX_RX_SLACK;

        u8 *out_buf = (u8 *) hcrealloc (zd->out_buf, zd->out_size, want_size - zd->out_size);

        if (out_buf == NULL)
        {
          priv->packet_fault = true;

          break;
        }

        zd->out_buf  = out_buf;
        zd->out_size = want_size;
      }

      memcpy (&zd->out_buf[out], data, len);

      const u64 slot = priv->base + word_id;

      zd->out_buf[out + 0] = (u8) (slot >> 0);
      zd->out_buf[out + 1] = (u8) (slot >> 8);

      out += len;

      ztex_pkt_drop (priv);
    }
  }

  if (out == 0) return NULL;

  *bytes = out;

  return zd->out_buf;
}

static void ztex_batch_end (fpga_dev_t *dev)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return;

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    zd->u[f].rx_len   = 0;
    zd->u[f].rx_taken = 0;
  }
}

static bool ztex_control_msg (fpga_dev_t *dev, const u32 type, const void *src, const u64 bytes)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return false;

  if (bytes > ZTEX_PKT_MAX_DATA_LEN) return false;

  if (type == ZTEX_PKT_WORD_GEN)
  {
    if (bytes > sizeof (zd->gen_buf)) return false;

    memcpy (zd->gen_buf, src, bytes);

    zd->gen_len = (u32) bytes;

    return true;
  }

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    if (ztex_pkt_queue (&zd->u[f], (u8) type, src, (u32) bytes) == false) return false;
  }

  u64 deadline_ns = fpga_now_ns () + ((u64) ZTEX_SEND_STALL_MS * 1000000ull);

  for (;;)
  {
    bool pending  = false;
    bool progress = false;

    for (u32 f = 0; f < zd->fpga_cnt; f++)
    {
      ztex_priv_t *priv = &zd->u[f];

      if (priv->tx_pos >= priv->tx_len) continue;

      pending = true;

      const u64 before = priv->tx_pos;

      if (ztex_service (zd->board, priv, 1) == false) return false;

      if (priv->tx_pos > before) progress = true;
    }

    if (pending == false) break;

    if (progress == true)
    {
      deadline_ns = fpga_now_ns () + ((u64) ZTEX_SEND_STALL_MS * 1000000ull);

      continue;
    }

    if (fpga_now_ns () > deadline_ns) return false;
  }

  return true;
}

static bool ztex_firmware_is_ours (const ztex_board_t *board)
{
  if (board->product[0] == 0) return false;

  const bool ours = (strcmp (board->product, ZTEX_FIRMWARE_PRODUCT) == 0);

  return ours;
}

static bool ztex_fx2_write (const int fd, const u16 addr, const void *src, const u16 len)
{
  struct usbdevfs_ctrltransfer ctrl;

  memset (&ctrl, 0, sizeof (ctrl));

  ctrl.bRequestType = 0x40;
  ctrl.bRequest     = ZTEX_VC_FX2_RAM;
  ctrl.wValue       = addr;
  ctrl.wIndex       = 0;
  ctrl.wLength      = len;
  ctrl.timeout      = 2000;
  ctrl.data         = (void *) src;

  const int rc = ioctl (fd, USBDEVFS_CONTROL, &ctrl);

  if (rc != (int) len) return false;

  return true;
}

static bool ztex_fx2_reset (const int fd, const bool held)
{
  const u8 val = (held == true) ? 1 : 0;

  const bool ok = ztex_fx2_write (fd, ZTEX_FX2_CPUCS, &val, 1);

  if (held == false) return true;

  return ok;
}

#define ZTEX_IHX_MAX  65536

static bool ztex_ihx_load (const char *path, short *image, const char **why)
{
  for (u32 i = 0; i < (ZTEX_IHX_MAX + 2); i++) image[i] = -1;

  FILE *fp = fopen (path, "rb");

  if (fp == NULL)
  {
    *why = "it cannot be opened";

    return false;
  }

  char line[1024];

  bool saw_eof   = false;
  bool saw_record = false;

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    if (line[0] != ':') continue;

    saw_record = true;

    u32 count = 0;
    u32 addr  = 0;
    u32 type  = 0;

    if (sscanf (&line[1], "%2x%4x%2x", &count, &addr, &type) != 3)
    {
      fclose (fp);

      *why = "one of its records is malformed";

      return false;
    }

    if (type == 1)
    {
      saw_eof = true;

      break;
    }

    if (type != 0) continue;

    if ((addr + count) > ZTEX_IHX_MAX)
    {
      fclose (fp);

      *why = "it addresses more memory than the FX2 has";

      return false;
    }

    for (u32 i = 0; i < count; i++)
    {
      u32 byte = 0;

      if (sscanf (&line[9 + (2 * i)], "%2x", &byte) != 1)
      {
        fclose (fp);

        *why = "one of its records has a bad data byte";

        return false;
      }

      image[addr + i] = (short) byte;
    }
  }

  fclose (fp);

  if (saw_record == false)
  {
    *why = "it is not an Intel HEX file at all, which usually means a download saved an error page";

    return false;
  }

  if (saw_eof == false)
  {
    *why = "it has no end record, so it was truncated in transit";

    return false;
  }

  return true;
}

#define ZTEX_FX2_CHUNK  4096

static bool ztex_firmware_upload (const int fd, const char *path, const char **why, bool *wire_fault)
{
  *wire_fault = false;

  short *image = (short *) hcmalloc ((ZTEX_IHX_MAX + 2) * sizeof (short));

  if (image == NULL)
  {
    *why = "out of memory";

    return false;
  }

  if (ztex_ihx_load (path, image, why) == false)
  {
    hcfree (image);

    return false;
  }

  if (ztex_fx2_reset (fd, true) == false)
  {
    *wire_fault = true;

    hcfree (image);

    return false;
  }

  u8 buf[ZTEX_FX2_CHUNK];

  u32 i = 0;

  while (i < ZTEX_IHX_MAX)
  {
    if ((image[i + 0] == -1) && (image[i + 1] == -1))
    {
      i += 2;

      continue;
    }

    u32 len = 0;
    u32 j   = 0;

    for (j = 0; (j < ZTEX_FX2_CHUNK) && (j < (ZTEX_IHX_MAX - i)); j += 2)
    {
      if (image[i + j + 0] == -1)
      {
        if (image[i + j + 1] == -1) break;

        buf[j + 0] = 0;
        buf[j + 1] = (u8) image[i + j + 1];

        len += 2;

        continue;
      }

      buf[j + 0] = (u8) image[i + j + 0];

      len++;

      if (image[i + j + 1] == -1)
      {
        j += 2;

        break;
      }

      buf[j + 1] = (u8) image[i + j + 1];

      len++;
    }

    if (ztex_fx2_write (fd, (u16) i, buf, (u16) len) == false)
    {
      ztex_fx2_reset (fd, false);

      hcfree (image);

      *why = "the upload stopped part way through and the board now holds an incomplete image";

      *wire_fault = true;

      return false;
    }

    i += j;
  }

  hcfree (image);

  ztex_fx2_reset (fd, false);

  return true;
}

#define ZTEX_RENUMERATE_TRIES  50
#define ZTEX_RENUMERATE_WAIT   100000

static bool ztex_reopen (ztex_board_t *board)
{
  if (board->fd >= 0)
  {
    close (board->fd);

    board->fd = -1;
  }

  board->selected = -1;
  board->claimed  = false;

  for (u32 attempt = 0; attempt < ZTEX_RENUMERATE_TRIES; attempt++)
  {
    usleep (ZTEX_RENUMERATE_WAIT);

    DIR *d = opendir ("/sys/bus/usb/devices");

    if (d == NULL) continue;

    struct dirent *e = NULL;

    while ((e = readdir (d)) != NULL)
    {
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

      char node[ZTEX_NODE_MAX];

      snprintf (node, sizeof (node), "/dev/bus/usb/%03ld/%03ld", strtol (busnum, NULL, 10), strtol (devnum, NULL, 10));

      const int fd = open (node, O_RDWR);

      if (fd < 0) continue;

      u8 desc[40];

      if (ztex_control_read (fd, ZTEX_VR_DESCRIPTOR, 0, 0, desc, sizeof (desc)) != (int) sizeof (desc))
      {
        close (fd);

        continue;
      }

      if (memcmp (&desc[30], board->serial, 10) != 0)
      {
        close (fd);

        continue;
      }

      board->fd = fd;

      if ((board->locked == true) && (flock (board->fd, LOCK_EX | LOCK_NB) != 0)) board->locked = false;

      snprintf (board->node, sizeof (board->node), "%s", node);

      board->product[0] = 0;

      ztex_sysfs_read (devdir, "product", board->product, sizeof (board->product));

      closedir (d);

      return true;
    }

    closedir (d);
  }

  return false;
}

static bool ztex_bitstream_upload (ztex_board_t *board, const u32 fpga_num, const char *path, const u32 endpoint)
{
  if (board->claimed == false)
  {
    if (ztex_claim (board->fd) == false)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u: upload stopped at claim\n", fpga_num);

      return false;
    }

    board->claimed = true;
  }

  if (ztex_select_fpga (board, fpga_num) == false)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u: upload stopped at select_fpga\n", fpga_num);

    return false;
  }

  const bool ok = ztex_hs_upload (board->fd, endpoint, path);

  return ok;
}

#define ZTEX_CONFIG_TRIES 3
#define ZTEX_CONFIG_WAIT  200000

static fpga_status_t ztex_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo)
{
  ztex_dev_t *zd = ztex_dev (dev);

  if (zd == NULL) return FPGA_STATUS_BAD_IDENT;

  bool known = false;

  for (u32 i = 0; i < ZTEX_DESIGNS_CNT; i++)
  {
    if (strcmp (ZTEX_DESIGNS[i].algo, algo) != 0) continue;

    known = true;

    break;
  }

  if (known == false) return FPGA_STATUS_ALGO_UNAVAILABLE;

  char firmware[FPGA_PATH_MAX];
  char path[FPGA_PATH_MAX];

  char bitstream_name[FPGA_PATH_MAX];

  snprintf (bitstream_name, sizeof (bitstream_name), ZTEX_BITSTREAM_FMT, algo);

  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  const bool have_firmware  = fpga_shipped_file (folder_config, ZTEX_FIRMWARE_NAME, firmware, sizeof (firmware));
  const bool have_bitstream = fpga_shipped_file (folder_config, bitstream_name,     path,     sizeof (path));

  if ((have_firmware == false) || (have_bitstream == false))
  {
    const char *missing[2];

    u32 missing_cnt = 0;

    if (have_firmware  == false) missing[missing_cnt++] = ZTEX_FIRMWARE_NAME;
    if (have_bitstream == false) missing[missing_cnt++] = bitstream_name;

    fpga_shipped_report_missing (hashcat_ctx, folder_config, missing, missing_cnt, fpga_board_find ("ztex115y"));

    return FPGA_STATUS_NO_BITSTREAM;
  }

  ztex_board_t *board = zd->board;

  if (fpga_say_progress (hashcat_ctx) == true) event_log_info_nn (hashcat_ctx, "Programming FPGA board %s, this takes about a second each...", board->serial);

  if (board->firmware_ready == false)
  {
    if (ztex_firmware_is_ours (board) == false)
    {
      if (ztex_dbg () == true) fprintf (stderr, "[ztex] firmware is \"%s\", uploading %s\n", (board->product[0] != 0) ? board->product : "unreadable", firmware);

      const char *why = "the upload itself failed on the wire";

      bool wire_fault = false;

      if (ztex_firmware_upload (board->fd, firmware, &why, &wire_fault) == false)
      {
        if (wire_fault == true) ztex_firmware_wire_report (hashcat_ctx, board->serial, why);
        else                    ztex_firmware_bad_report  (hashcat_ctx, firmware, why);

        if (ztex_dbg () == true) fprintf (stderr, "[ztex] firmware upload FAILED: %s\n", why);

        return FPGA_STATUS_BAD_IDENT;
      }

      if (ztex_reopen (board) == false)
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] board did not come back after firmware\n");

        return FPGA_STATUS_BAD_IDENT;
      }

      if (ztex_dbg () == true) fprintf (stderr, "[ztex] after firmware, product is \"%s\"\n", (board->product[0] != 0) ? board->product : "unreadable");

      if (ztex_firmware_is_ours (board) == false) return FPGA_STATUS_BAD_IDENT;
    }

    board->firmware_ready = true;
  }

  for (u32 f = 0; f < zd->fpga_cnt; f++)
  {
    const u32 fpga_num = zd->u[f].fpga_num;

    bool done = false;

    for (u32 attempt = 0; attempt < ZTEX_CONFIG_TRIES; attempt++)
    {
      if (ztex_bitstream_upload (board, fpga_num, path, ZTEX_HS_EP_INOUTTRAFFIC) == false)
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u: bitstream upload FAILED\n", fpga_num);

        return FPGA_STATUS_BAD_IDENT;
      }

      if (ztex_fpga_configured (board, fpga_num) == false)
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u: upload accepted but not configured (try %u)\n", fpga_num, attempt + 1);

        usleep (ZTEX_CONFIG_WAIT);

        continue;
      }

      u16 type = 0;

      if (ztex_echo (board, fpga_num, &type) == true)
      {
        done = true;

        break;
      }

      if (ztex_dbg () == true) fprintf (stderr, "[ztex] fpga %u: configured but echo silent (try %u)\n", fpga_num, attempt + 1);

      usleep (ZTEX_CONFIG_WAIT);
    }

    if (done == true) continue;

    return FPGA_STATUS_BAD_IDENT;
  }

  return FPGA_STATUS_OK;
}

const fpga_transport_t fpga_transport_ztex115y =
{
  .name            = "ztex115y",
  .bus             = "USB",
  .udev            = "99-ztex.rules",

  .dialect         = FPGA_DIALECT_ZTEX,

  .enumerate       = ztex_enumerate,
  .identify        = ztex_identify,
  .close           = ztex_close,
  .release         = ztex_release,

  .csr_read        = NULL,
  .csr_write       = NULL,

  .session_open    = ztex_session_open,
  .session_close   = ztex_session_close,
  .session_refresh = ztex_session_refresh,
  .out_capacity    = ztex_out_capacity,

  .batch_begin     = ztex_batch_begin,
  .batch_send      = ztex_batch_send,
  .batch_recv      = ztex_batch_recv,
  .batch_end       = ztex_batch_end,
  .batch_done      = ztex_batch_done,

  .control         = ztex_control_msg,

  .program         = ztex_program,
  .temperature     = ztex_temperature,
  .temperature_all = ztex_temperature_all,
  .clock_step_down = ztex_clock_step_down,
  .link_str        = ztex_link_str,
};

#else

static int ztex_enumerate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED fpga_dev_t *devs, MAYBE_UNUSED const int max, fpga_status_t *status) { *status = FPGA_STATUS_UNSUPPORTED_OS; return 0; }
static fpga_status_t ztex_identify (MAYBE_UNUSED fpga_dev_t *dev)                                            { return FPGA_STATUS_UNSUPPORTED_OS; }
static void ztex_close (MAYBE_UNUSED fpga_dev_t *dev)                                                        { }

static bool ztex_session_open  (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static void ztex_session_close (MAYBE_UNUSED fpga_dev_t *dev) { }
static u64  ztex_out_capacity  (MAYBE_UNUSED fpga_dev_t *dev) { return 0; }

static bool ztex_batch_begin (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, MAYBE_UNUSED const u64 in_bytes, MAYBE_UNUSED const u32 in_grain, MAYBE_UNUSED const u32 in_recs) { return false; }
static bool ztex_batch_send  (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const void *src, MAYBE_UNUSED const u64 bytes) { return false; }
static void ztex_batch_end   (MAYBE_UNUSED fpga_dev_t *dev) { }
static bool ztex_batch_done  (MAYBE_UNUSED fpga_dev_t *dev, u32 *processed) { if (processed != NULL) *processed = 0; return false; }

static const void *ztex_batch_recv (MAYBE_UNUSED fpga_dev_t *dev, u64 *bytes, MAYBE_UNUSED const u32 timeout_ms) { *bytes = 0; return NULL; }

const fpga_transport_t fpga_transport_ztex115y =
{
  .name            = "unsupported",
  .bus             = "USB",
  .udev            = "99-ztex.rules",
  .dialect         = FPGA_DIALECT_ZTEX,

  .enumerate       = ztex_enumerate,
  .identify        = ztex_identify,
  .close           = ztex_close,

  .csr_read        = NULL,
  .csr_write       = NULL,

  .session_open    = ztex_session_open,
  .session_close   = ztex_session_close,
  .out_capacity    = ztex_out_capacity,

  .batch_begin     = ztex_batch_begin,
  .batch_send      = ztex_batch_send,
  .batch_recv      = ztex_batch_recv,
  .batch_end       = ztex_batch_end,
  .batch_done      = ztex_batch_done,

  .control         = NULL,

  .program         = NULL,
  .temperature     = NULL,
  .link_str        = NULL,
};

#endif
