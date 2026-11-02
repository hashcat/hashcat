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

#include "fpga/artyz7_ftdi.h"
#include "fpga/artyz7_jtag.h"
#include "fpga/artyz7_dap.h"
#include "fpga/artyz7_loader.h"
#include "fpga/artyz7_bitstream.h"
#include "fpga/artyz7_ps_app.h"

#include <stdio.h>
#include <string.h>

#ifdef __linux__

#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include "fpga/hcfpga_aead.h"

#define ARTYZ7_VID          0x0403
#define ARTYZ7_PID          0x6010
#define ARTYZ7_MANUFACTURER "Digilent"

#define ARTYZ7_SYSFS        "/sys/bus/usb/devices"

#define ARTYZ7_BOARD        "artyz7"
#define ARTYZ7_ALGO         "bcrypt"

#define ARTYZ7_BITSTREAM    "bcrypt-artyz7.bin"

#define ARTYZ7_PL_BASE      0x40000000
#define ARTYZ7_REG_CORES    (ARTYZ7_PL_BASE + 0x1C)
#define ARTYZ7_REG_MAGIC    (ARTYZ7_PL_BASE + 0x5C)
#define ARTYZ7_MAGIC        0x7A700068

#define ARTYZ7_REG_ABI      (ARTYZ7_PL_BASE + 0x60)
#define ARTYZ7_REG_ALGO_LO  (ARTYZ7_PL_BASE + 0x64)
#define ARTYZ7_REG_ALGO_HI  (ARTYZ7_PL_BASE + 0x68)
#define ARTYZ7_REG_CLK_MHZ  (ARTYZ7_PL_BASE + 0x6C)
#define ARTYZ7_REG_BUILD    (ARTYZ7_PL_BASE + 0x70)

#define ARTYZ7_CFG_EOS_BIT  13

#define ARTYZ7_CLK_MHZ      91

#define ARTYZ7_TCK_HZ       15000000

#define ARTYZ7_IDCODE_PL    0x03727093
#define ARTYZ7_IDCODE_DAP   0x4BA00477

#define ARTYZ7_IP_FIRST     "192.168.224.138"
#define ARTYZ7_BOARD_PORT   31344

#define ARTYZ7_NETCFG_ADDR  0x0001FF00
#define ARTYZ7_NETCFG_MAGIC 0x4E455443

static const u8 ARTYZ7_MAC_FIRST[6] = { 0x00, 0x0A, 0x35, 0x00, 0x1E, 0x53 };

#define HC_OP_PING          0x01
#define HC_OP_CONFIG        0x02
#define HC_OP_FEED          0x03
#define HC_OP_RESET         0x04
#define HC_OP_CSR_WR        0x05
#define HC_OP_CSR_RD        0x06
#define HC_OP_PONG          0x81
#define HC_OP_RESULT        0x82
#define HC_OP_CSR_VAL       0x83
#define HC_OP_FEED_ACK      0x84

#define HC_HDR_BYTES        4

#define ARTYZ7_SEQ_BYTES    8
#define ARTYZ7_SEAL_HDR     (HC_HDR_BYTES + ARTYZ7_SEQ_BYTES)
#define ARTYZ7_TAG_BYTES    HCFPGA_AEAD_TAG_BYTES

#define ARTYZ7_DIR_TO_BOARD 0
#define ARTYZ7_DIR_TO_HOST  1

#define ARTYZ7_KEY_ADDR     0x0001FF40
#define ARTYZ7_KEY_MAGIC    0x59454B53

#define ARTYZ7_FORGED_MAX   64

#define ARTYZ7_MAX_PAYLOAD  1400

#define ARTYZ7_RECV_MS      2000
#define ARTYZ7_TRIES        4

#define ARTYZ7_PROBE_MS     100
#define ARTYZ7_PROBE_TRIES  3

#define ARTYZ7_PROBE_SKIP   64

#define ARTYZ7_PONG_CRC_OFF 24

#define ARTYZ7_PEND_BYTES   (64 * 1024)

#define ARTYZ7_OUT_BYTES    (1024 * 1024)

typedef struct artyz7_priv
{
  char serial[32];

  u8   ip[4];
  u8   mac[6];

  int  fd;

  u8   key[HCFPGA_AEAD_KEY_BYTES];
  bool key_set;
  u64  tx_seq;
  u64  rx_seq;

  bool in_batch;
  bool seq_synced;
  bool lost;

  u32  recv_ms;

  u8   in_buf[2048];

  u32  grain;
  u32  want;

  u8  *pend;
  u32  pend_size;
  u32  pend_head;
  u32  pend_tail;

  bool done;
  u32  processed;

  int  temp_c;
  u64  temp_ns;

  bool shell_ident;

  bool app_loaded;

  const folder_config_t *folder_config;

} artyz7_priv_t;

static artyz7_priv_t ARTYZ7_PRIV[FPGA_MAX_DEVICES];

static bool artyz7_sysfs_read (const char *devdir, const char *attr, char *out, const size_t len)
{
  char path[FPGA_PATH_MAX];

  snprintf (path, sizeof (path), "%s/%s", devdir, attr);

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return false;

  if (fgets (out, (int) len, fp) == NULL)
  {
    fclose (fp);

    return false;
  }

  fclose (fp);

  const size_t n = strlen (out);

  if ((n > 0) && (out[n - 1] == '\n')) out[n - 1] = 0;

  return true;
}

static int artyz7_pinned_ip (const char *serial, u8 *ip)
{
  char name[96];

  snprintf (name, sizeof (name), "HCFPGA_ARTYZ7_IP_%s", serial);

  const char *val = getenv (name);

  if (val == NULL) return 0;

  if (inet_pton (AF_INET, val, ip) == 1) return 1;

  return -1;
}

static bool artyz7_ip_taken (const u8 taken[][4], const int taken_cnt, const u8 *ip)
{
  for (int i = 0; i < taken_cnt; i++)
  {
    if (memcmp (taken[i], ip, 4) == 0) return true;
  }

  return false;
}

static int artyz7_assign_addresses (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int cnt)
{
  u8 first[4];

  const char *first_env = getenv ("HCFPGA_ARTYZ7_IP");

  const char *first_str = (first_env != NULL) ? first_env : ARTYZ7_IP_FIRST;

  if (inet_pton (AF_INET, first_str, first) != 1)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: HCFPGA_ARTYZ7_IP=%s is not an IPv4 address.", first_str);

    return 0;
  }

  u8 legacy[4];

  inet_pton (AF_INET, ARTYZ7_IP_FIRST, legacy);

  int order[FPGA_MAX_DEVICES];

  for (int i = 0; i < cnt; i++) order[i] = i;

  for (int i = 1; i < cnt; i++)
  {
    const int v = order[i];

    int j = i;

    while ((j > 0) && (strcmp (ARTYZ7_PRIV[order[j - 1]].serial, ARTYZ7_PRIV[v].serial) > 0))
    {
      order[j] = order[j - 1];

      j--;
    }

    order[j] = v;
  }

  u8 taken[FPGA_MAX_DEVICES][4];

  int taken_cnt = 0;

  bool assigned[FPGA_MAX_DEVICES];

  for (int i = 0; i < cnt; i++)
  {
    artyz7_priv_t *priv = &ARTYZ7_PRIV[i];

    assigned[i] = false;

    u8 ip[4];

    const int pinned = artyz7_pinned_ip (priv->serial, ip);

    if (pinned == 0) continue;

    if (pinned < 0)
    {
      event_log_warning (hashcat_ctx, "FPGA bridge: HCFPGA_ARTYZ7_IP_%s is not an IPv4 address and is ignored.", priv->serial);

      continue;
    }

    if (artyz7_ip_taken ((const u8 (*)[4]) taken, taken_cnt, ip) == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: Arty Z7 %s is pinned to %u.%u.%u.%u, which another board already has. It will not be used.", priv->serial, ip[0], ip[1], ip[2], ip[3]);

      continue;
    }

    memcpy (priv->ip, ip, 4);
    memcpy (taken[taken_cnt], ip, 4);

    taken_cnt++;

    assigned[i] = true;
  }

  u32 next = (first[3] == 0) ? 1 : first[3];

  for (int k = 0; k < cnt; k++)
  {
    const int i = order[k];

    artyz7_priv_t *priv = &ARTYZ7_PRIV[i];

    if (assigned[i] == true) continue;

    u8 pinned[4];

    if (artyz7_pinned_ip (priv->serial, pinned) > 0) continue;

    u8 ip[4] = { first[0], first[1], first[2], 0 };

    while (next <= 254)
    {
      ip[3] = (u8) next;

      if (artyz7_ip_taken ((const u8 (*)[4]) taken, taken_cnt, ip) == false) break;

      next++;
    }

    if (next > 254)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: no address is left in %u.%u.%u.0/24 for Arty Z7 %s. It will not be used.", first[0], first[1], first[2], priv->serial);
      event_log_info  (hashcat_ctx, "Set HCFPGA_ARTYZ7_IP to a lower first address, or pin the board with HCFPGA_ARTYZ7_IP_%s.", priv->serial);

      continue;
    }

    next++;

    memcpy (priv->ip, ip, 4);
    memcpy (taken[taken_cnt], ip, 4);

    taken_cnt++;

    assigned[i] = true;
  }

  for (int i = 0; i < cnt; i++)
  {
    artyz7_priv_t *priv = &ARTYZ7_PRIV[i];

    if (assigned[i] == false) continue;

    if (memcmp (priv->ip, legacy, 4) == 0)
    {
      memcpy (priv->mac, ARTYZ7_MAC_FIRST, 6);

      continue;
    }

    priv->mac[0] = 0x02;
    priv->mac[1] = 0x68;
    priv->mac[2] = priv->ip[0];
    priv->mac[3] = priv->ip[1];
    priv->mac[4] = priv->ip[2];
    priv->mac[5] = priv->ip[3];
  }

  int kept = 0;

  for (int i = 0; i < cnt; i++)
  {
    if (assigned[i] == false) continue;

    if (kept != i)
    {
      ARTYZ7_PRIV[kept] = ARTYZ7_PRIV[i];

      devs[kept] = devs[i];

      devs[kept].priv = &ARTYZ7_PRIV[kept];
    }

    kept++;
  }

  return kept;
}

static int artyz7_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  int cnt = 0;

  bool saw_board      = false;
  bool saw_permission = false;

  DIR *d = opendir (ARTYZ7_SYSFS);

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

    snprintf (devdir, sizeof (devdir), "%s/%s", ARTYZ7_SYSFS, e->d_name);

    char vendor[32];
    char product[32];

    if (artyz7_sysfs_read (devdir, "idVendor",  vendor,  sizeof (vendor))  == false) continue;
    if (artyz7_sysfs_read (devdir, "idProduct", product, sizeof (product)) == false) continue;

    if (strtol (vendor,  NULL, 16) != ARTYZ7_VID) continue;
    if (strtol (product, NULL, 16) != ARTYZ7_PID) continue;

    char manufacturer[64];

    if (artyz7_sysfs_read (devdir, "manufacturer", manufacturer, sizeof (manufacturer)) == false) continue;

    if (strcmp (manufacturer, ARTYZ7_MANUFACTURER) != 0) continue;

    char busnum[32];
    char devnum[32];

    if (artyz7_sysfs_read (devdir, "busnum", busnum, sizeof (busnum)) == false) continue;
    if (artyz7_sysfs_read (devdir, "devnum", devnum, sizeof (devnum)) == false) continue;

    char node[FPGA_PATH_MAX];

    snprintf (node, sizeof (node), "/dev/bus/usb/%03ld/%03ld", strtol (busnum, NULL, 10), strtol (devnum, NULL, 10));

    saw_board = true;

    if (access (node, R_OK | W_OK) != 0)
    {
      saw_permission = true;

      continue;
    }

    char serial[32];

    if (artyz7_sysfs_read (devdir, "serial", serial, sizeof (serial)) == false) continue;

    fpga_dev_t *dev = &devs[cnt];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->path, sizeof (dev->path), "%s", node);

    memset (&ARTYZ7_PRIV[cnt], 0, sizeof (artyz7_priv_t));

    snprintf (ARTYZ7_PRIV[cnt].serial, sizeof (ARTYZ7_PRIV[cnt].serial), "%s", serial);

    ARTYZ7_PRIV[cnt].fd = -1;

    if (hashcat_ctx != NULL) ARTYZ7_PRIV[cnt].folder_config = hashcat_ctx->folder_config;

    dev->fd        = -1;
    dev->priv      = &ARTYZ7_PRIV[cnt];
    dev->transport = &fpga_transport_artyz7;

    cnt++;
  }

  closedir (d);

  if (cnt > 0)
  {
    const int kept = artyz7_assign_addresses (hashcat_ctx, devs, cnt);

    if (kept > 0) return kept;

    *status = FPGA_STATUS_NO_CHAR_DEVICE;

    return 0;
  }

  if (saw_permission == true) *status = FPGA_STATUS_NO_PERMISSION;
  else if (saw_board  == true) *status = FPGA_STATUS_NO_CHAR_DEVICE;
  else                         *status = FPGA_STATUS_NO_PCI_DEVICE;

  return 0;
}

static void artyz7_close (fpga_dev_t *dev)
{
  (void) dev;
}

static bool artyz7_dap_open (fpga_dev_t *dev, ftdi_ctx_t *ftdi, jtag_ctx_t *jtag, dap_ctx_t *dap)
{
  const artyz7_priv_t *priv = (const artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (ftdi_open (ftdi, ARTYZ7_VID, ARTYZ7_PID, priv->serial) == false) return false;

  if (ftdi_mpsse_enable (ftdi, ARTYZ7_TCK_HZ) == false) { ftdi_close (ftdi); return false; }
  if (ftdi_mpsse_sync (ftdi) == false)                  { ftdi_close (ftdi); return false; }

  jtag_init (jtag, ftdi);

  if (jtag_scan_chain (jtag) == false) { ftdi_close (ftdi); return false; }

  if (jtag->num_taps != 2)                                { ftdi_close (ftdi); return false; }
  if ((jtag->idcode[0] & 0x0FFFFFFF) != ARTYZ7_IDCODE_PL) { ftdi_close (ftdi); return false; }
  if (jtag->idcode[1] != ARTYZ7_IDCODE_DAP)               { ftdi_close (ftdi); return false; }

  if (dap_init (dap, jtag) == false) { ftdi_close (ftdi); return false; }

  return true;
}

static bool artyz7_random (u8 *buf, const size_t len)
{
  FILE *fp = fopen ("/dev/urandom", "rb");

  if (fp == NULL) return false;

  const size_t got = fread (buf, 1, len, fp);

  fclose (fp);

  const bool ok = (got == len);

  return ok;
}

static bool artyz7_key_write (dap_ctx_t *dap, artyz7_priv_t *priv)
{
  if (priv == NULL) return false;

  u8 key[HCFPGA_AEAD_KEY_BYTES];

  if (artyz7_random (key, sizeof (key)) == false) return false;

  u32 gen = 0;

  if (dap_mem_read32 (dap, ARTYZ7_KEY_ADDR + 0x04, &gen) == false) return false;

  gen = (gen + 1) & ~1u;

  priv->key_set = false;

  if (dap_mem_write32 (dap, ARTYZ7_KEY_ADDR + 0x04, gen + 1) == false) return false;

  for (u32 i = 0; i < 8; i++)
  {
    const u32 w = ((u32) key[(i * 4) + 0] <<  0) | ((u32) key[(i * 4) + 1] <<  8)
                | ((u32) key[(i * 4) + 2] << 16) | ((u32) key[(i * 4) + 3] << 24);

    if (dap_mem_write32 (dap, ARTYZ7_KEY_ADDR + 0x08 + (i * 4), w) == false) return false;
  }

  if (dap_mem_write32 (dap, ARTYZ7_KEY_ADDR + 0x04, gen + 2)          == false) return false;
  if (dap_mem_write32 (dap, ARTYZ7_KEY_ADDR + 0x00, ARTYZ7_KEY_MAGIC) == false) return false;

  memcpy (priv->key, key, sizeof (key));

  priv->tx_seq  = 0;
  priv->rx_seq  = 0;
  priv->key_set = true;

  return true;
}

static fpga_status_t artyz7_identify (fpga_dev_t *dev)
{
  fpga_ident_t *ident = &dev->ident;

  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  memset (ident, 0, sizeof (fpga_ident_t));

  if (priv != NULL) priv->shell_ident = false;

  snprintf (ident->board, sizeof (ident->board), "%s", ARTYZ7_BOARD);

  if (priv != NULL) snprintf (ident->serial, sizeof (ident->serial), "%.15s", priv->serial);

  ftdi_ctx_t ftdi;
  jtag_ctx_t jtag;
  dap_ctx_t  dap;

  if (artyz7_dap_open (dev, &ftdi, &jtag, &dap) == false) return FPGA_STATUS_NO_CHAR_DEVICE;

  u32 cfg = 0;

  if (artyz7_cfg_status (&jtag, &cfg) == false)
  {
    ftdi_close (&ftdi);

    return FPGA_STATUS_NO_BITSTREAM;
  }

  if (((cfg >> ARTYZ7_CFG_EOS_BIT) & 1) == 0)
  {
    ftdi_close (&ftdi);

    return FPGA_STATUS_NO_BITSTREAM;
  }

  u32 magic = 0;
  u32 cores = 0;

  u32 abi     = 0;
  u32 algo_lo = 0;
  u32 algo_hi = 0;
  u32 clk     = 0;
  u32 build   = 0;

  const bool got = dap_mem_read32 (&dap, ARTYZ7_REG_MAGIC, &magic);

  if ((got == true) && (magic == ARTYZ7_MAGIC))
  {
    dap_mem_read32 (&dap, ARTYZ7_REG_CORES,   &cores);
    dap_mem_read32 (&dap, ARTYZ7_REG_ABI,     &abi);
    dap_mem_read32 (&dap, ARTYZ7_REG_ALGO_LO, &algo_lo);
    dap_mem_read32 (&dap, ARTYZ7_REG_ALGO_HI, &algo_hi);
    dap_mem_read32 (&dap, ARTYZ7_REG_CLK_MHZ, &clk);
    dap_mem_read32 (&dap, ARTYZ7_REG_BUILD,   &build);
  }

  ftdi_close (&ftdi);

  if (got == false) return FPGA_STATUS_NO_BITSTREAM;

  if (magic != ARTYZ7_MAGIC) return FPGA_STATUS_NO_BITSTREAM;

  if (abi == 0)
  {
    snprintf (ident->algo, sizeof (ident->algo), "%s", ARTYZ7_ALGO);

    ident->cores    = cores;
    ident->clk_mhz  = ARTYZ7_CLK_MHZ;
    ident->abi      = FPGA_ABI_CURRENT;
    ident->asserted = true;

    snprintf (ident->raw, sizeof (ident->raw), "hcfpga/1;board=%s;algo=%s;cores=%u;clk=%u;abi=%u",
              ARTYZ7_BOARD, ARTYZ7_ALGO, cores, (u32) ARTYZ7_CLK_MHZ, (u32) FPGA_ABI_CURRENT);

    return FPGA_STATUS_OK;
  }

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

  if (gmtime_r (&t, &tm_buf) != NULL) strftime (ident->build, sizeof (ident->build), "%Y-%m-%dT%H:%M:%S", &tm_buf);

  snprintf (ident->raw, sizeof (ident->raw), FPGA_IDENT_PREFIX "%u;board=%s;algo=%s;cores=%u;clk=%u;abi=%u;build=%s",
            abi, ARTYZ7_BOARD, ident->algo, cores, clk, abi, ident->build);

  if (priv != NULL) priv->shell_ident = true;

  ident->asserted = ((priv == NULL) || (priv->app_loaded == false)) ? true : false;

  return FPGA_STATUS_OK;
}

static bool    artyz7_send_op    (artyz7_priv_t *priv, const u8 op, const void *payload, const u32 len);
static int     artyz7_recv_op    (artyz7_priv_t *priv, const u8 want, u8 *out, const u32 max);
static ssize_t artyz7_recv_frame (artyz7_priv_t *priv, u8 *d, const size_t max);

#define ARTYZ7_TEMP_PERIOD_NS  (1000ull * 1000ull * 1000ull)

#define ARTYZ7_PONG_TEMP_OFF   12

static void artyz7_set_recv_ms (artyz7_priv_t *priv, const u32 ms)
{
  if (priv->fd < 0) return;
  if (priv->recv_ms == ms) return;

  struct timeval tv;

  tv.tv_sec  = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;

  setsockopt (priv->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

  priv->recv_ms = ms;
}

static void artyz7_temp_from_pong (artyz7_priv_t *priv, const u8 *pong, const int len)
{
  if (len < (ARTYZ7_PONG_TEMP_OFF + 4)) return;

  const u32 raw = ((u32) pong[ARTYZ7_PONG_TEMP_OFF + 0] << 0) | ((u32) pong[ARTYZ7_PONG_TEMP_OFF + 1] << 8) | ((u32) pong[ARTYZ7_PONG_TEMP_OFF + 2] << 16) | ((u32) pong[ARTYZ7_PONG_TEMP_OFF + 3] << 24);

  const int celsius = (int) (((double) raw * 503.975 / 65536.0) - 273.15);

  if (celsius > 125) return;
  if (celsius < -40) return;

  priv->temp_c  = celsius;
  priv->temp_ns = fpga_now_ns ();
}

static void artyz7_temp_refresh (artyz7_priv_t *priv)
{
  if (priv->fd < 0) return;

  if ((priv->temp_c >= 0) && ((fpga_now_ns () - priv->temp_ns) < ARTYZ7_TEMP_PERIOD_NS)) return;

  if (artyz7_send_op (priv, HC_OP_PING, NULL, 0) == false) return;

  u8 pong[64];

  const int got = artyz7_recv_op (priv, HC_OP_PONG, pong, sizeof (pong));

  if (got < 0) return;

  artyz7_temp_from_pong (priv, pong, got);
}

static int artyz7_temp_cached (fpga_dev_t *dev)
{
  const artyz7_priv_t *priv = (const artyz7_priv_t *) dev->priv;

  if (priv == NULL) return -1;

  return priv->temp_c;
}

static bool artyz7_socket_open (artyz7_priv_t *priv)
{
  priv->fd = socket (AF_INET, SOCK_DGRAM, 0);

  if (priv->fd < 0) return false;

  struct sockaddr_in board;

  memset (&board, 0, sizeof (board));

  board.sin_family = AF_INET;
  board.sin_port   = htons (ARTYZ7_BOARD_PORT);

  memcpy (&board.sin_addr.s_addr, priv->ip, 4);

  if (connect (priv->fd, (struct sockaddr *) &board, sizeof (board)) < 0)
  {
    close (priv->fd);

    priv->fd = -1;

    return false;
  }

  priv->recv_ms = 0;

  return true;
}

static void artyz7_socket_close (artyz7_priv_t *priv)
{
  if (priv->fd < 0) return;

  close (priv->fd);

  priv->fd = -1;
}

static bool artyz7_app_crc (artyz7_priv_t *priv, u32 *crc)
{
  if (artyz7_socket_open (priv) == false) return false;

  artyz7_set_recv_ms (priv, ARTYZ7_PROBE_MS);

  bool found = false;
  bool old   = false;

  for (u32 i = 0; i < ARTYZ7_PROBE_TRIES; i++)
  {
    if (artyz7_send_op (priv, HC_OP_PING, NULL, 0) == false) continue;

    for (u32 j = 0; j < ARTYZ7_PROBE_SKIP; j++)
    {
      u8 d[2048];

      const ssize_t n = artyz7_recv_frame (priv, d, sizeof (d));

      if (n < (ssize_t) HC_HDR_BYTES) break;

      if (d[0] != HC_OP_PONG) continue;

      const u32 len = (u32) d[2] | ((u32) d[3] << 8);

      const u32 need = ARTYZ7_PONG_CRC_OFF + 4;

      if ((len < need) || (n < (ssize_t) (HC_HDR_BYTES + need)))
      {
        old = true;

        break;
      }

      const u8 *p = &d[HC_HDR_BYTES];

      const u32 magic = ((u32) p[0] << 0) | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24);

      if (magic != ARTYZ7_MAGIC) continue;

      *crc = ((u32) p[ARTYZ7_PONG_CRC_OFF + 0] <<  0) | ((u32) p[ARTYZ7_PONG_CRC_OFF + 1] <<  8)
           | ((u32) p[ARTYZ7_PONG_CRC_OFF + 2] << 16) | ((u32) p[ARTYZ7_PONG_CRC_OFF + 3] << 24);

      found = true;

      break;
    }

    if (found == true) break;
    if (old   == true) break;
  }

  artyz7_socket_close (priv);

  return found;
}

static bool artyz7_key_ensure (fpga_dev_t *dev, artyz7_priv_t *priv)
{
  if (priv->key_set == true) return true;

  ftdi_ctx_t ftdi;
  jtag_ctx_t jtag;
  dap_ctx_t  dap;

  if (artyz7_dap_open (dev, &ftdi, &jtag, &dap) == false) return false;

  const bool written = artyz7_key_write (&dap, priv);

  ftdi_close (&ftdi);

  return written;
}

static bool artyz7_confirm (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (priv->shell_ident == false) return false;

  if (artyz7_key_ensure (dev, priv) == false) return false;

  u32 crc = 0;

  if (artyz7_app_crc (priv, &crc) == false) return false;

  const bool same = (crc == ARTYZ7_PS_APP_CRC32) ? true : false;

  return same;
}

static bool artyz7_session_open (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (artyz7_key_ensure (dev, priv) == false) return false;

  if (artyz7_socket_open (priv) == false) return false;

  artyz7_set_recv_ms (priv, ARTYZ7_RECV_MS);

  priv->done      = false;
  priv->processed = 0;

  priv->temp_c    = -1;
  priv->temp_ns   = 0;

  u8 pong[64];

  for (u32 i = 0; i < ARTYZ7_TRIES; i++)
  {
    if (artyz7_send_op (priv, HC_OP_PING, NULL, 0) == false) continue;

    const int got = artyz7_recv_op (priv, HC_OP_PONG, pong, sizeof (pong));

    if (got < 4) continue;

    const u32 magic = ((u32) pong[0] << 0) | ((u32) pong[1] << 8) | ((u32) pong[2] << 16) | ((u32) pong[3] << 24);

    if (magic != ARTYZ7_MAGIC) continue;

    artyz7_temp_from_pong (priv, pong, got);

    return true;
  }

  artyz7_socket_close (priv);

  return false;
}

static bool artyz7_reload (fpga_dev_t *dev);

static bool artyz7_session_refresh (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (priv->fd < 0)
  {
    const bool reloaded = artyz7_reload (dev);

    return reloaded;
  }

  if (artyz7_send_op (priv, HC_OP_RESET, NULL, 0) == false) return false;

  priv->done      = false;
  priv->processed = 0;

  artyz7_set_recv_ms (priv, 200);

  for (;;)
  {
    u8 d[2048];

    if (recv (priv->fd, d, sizeof (d), 0) <= 0) break;
  }

  u8 pong[64];

  for (u32 i = 0; i < ARTYZ7_TRIES; i++)
  {
    if (artyz7_send_op (priv, HC_OP_PING, NULL, 0) == false) continue;

    if (artyz7_recv_op (priv, HC_OP_PONG, pong, sizeof (pong)) >= 4) return true;
  }

  const bool reloaded = artyz7_reload (dev);

  return reloaded;
}

static bool artyz7_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  const artyz7_priv_t *priv = (const artyz7_priv_t *) dev->priv;

  if (priv == NULL)
  {
    snprintf (buf, len, "Eth:1Gb/s");

    return true;
  }

  snprintf (buf, len, "Eth:%u.%u.%u.%u", priv->ip[0], priv->ip[1], priv->ip[2], priv->ip[3]);

  return true;
}

static void artyz7_session_close (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return;
  if (priv->fd < 0) return;

  close (priv->fd);

  priv->fd = -1;

  if (priv->pend != NULL)
  {
    hcfree (priv->pend);

    priv->pend      = NULL;
    priv->pend_size = 0;
  }
}

static void artyz7_nonce (u8 *nonce, const u32 dir, const u64 seq)
{
  nonce[0] = (u8) (dir >>  0);
  nonce[1] = (u8) (dir >>  8);
  nonce[2] = (u8) (dir >> 16);
  nonce[3] = (u8) (dir >> 24);

  for (u32 i = 0; i < 8; i++) nonce[4 + i] = (u8) (seq >> (i * 8));
}

static bool artyz7_send_op (artyz7_priv_t *priv, const u8 op, const void *payload, const u32 len)
{
  if (priv->fd < 0) return false;
  if (priv->key_set == false) return false;
  if (len > ARTYZ7_MAX_PAYLOAD) return false;

  u8 d[ARTYZ7_SEAL_HDR + ARTYZ7_MAX_PAYLOAD + ARTYZ7_TAG_BYTES];

  priv->tx_seq++;

  const u64 seq = priv->tx_seq;

  d[0] = op;
  d[1] = 0;
  d[2] = (u8) (len & 0xFF);
  d[3] = (u8) (len >> 8);

  for (u32 i = 0; i < 8; i++) d[HC_HDR_BYTES + i] = (u8) (seq >> (i * 8));

  if (len > 0) memcpy (&d[ARTYZ7_SEAL_HDR], payload, len);

  u8 nonce[HCFPGA_AEAD_NONCE_BYTES];

  artyz7_nonce (nonce, ARTYZ7_DIR_TO_BOARD, seq);

  hcfpga_aead_seal (priv->key, nonce, d, ARTYZ7_SEAL_HDR, &d[ARTYZ7_SEAL_HDR], len, &d[ARTYZ7_SEAL_HDR + len]);

  const u32 total = ARTYZ7_SEAL_HDR + len + ARTYZ7_TAG_BYTES;

  const ssize_t n = send (priv->fd, d, total, 0);

  const bool sent = (n == (ssize_t) total);

  return sent;
}

static ssize_t artyz7_recv_frame (artyz7_priv_t *priv, u8 *d, const size_t max)
{
  if (priv->key_set == false) return -1;

  for (u32 i = 0; i < ARTYZ7_FORGED_MAX; i++)
  {
    const ssize_t n = recv (priv->fd, d, max, 0);

    if (n < 0) return n;

    if (n < (ssize_t) (ARTYZ7_SEAL_HDR + ARTYZ7_TAG_BYTES)) continue;

    const u32 len = (u32) d[2] | ((u32) d[3] << 8);

    if ((size_t) n != (ARTYZ7_SEAL_HDR + len + ARTYZ7_TAG_BYTES)) continue;

    u64 seq = 0;

    for (u32 b = 0; b < 8; b++) seq |= (u64) d[HC_HDR_BYTES + b] << (b * 8);

    if (seq <= priv->rx_seq) continue;

    u8 nonce[HCFPGA_AEAD_NONCE_BYTES];

    artyz7_nonce (nonce, ARTYZ7_DIR_TO_HOST, seq);

    if (hcfpga_aead_open (priv->key, nonce, d, ARTYZ7_SEAL_HDR, &d[ARTYZ7_SEAL_HDR], len, &d[ARTYZ7_SEAL_HDR + len]) == false) continue;

    if (priv->in_batch == true)
    {
      if ((priv->seq_synced == true) && (seq != (priv->rx_seq + 1))) priv->lost = true;

      priv->seq_synced = true;
    }

    priv->rx_seq = seq;

    memmove (&d[HC_HDR_BYTES], &d[ARTYZ7_SEAL_HDR], len);

    const ssize_t plain = (ssize_t) (HC_HDR_BYTES + len);

    return plain;
  }

  return -1;
}

static int artyz7_recv_op (artyz7_priv_t *priv, const u8 want, u8 *out, const u32 max)
{
  if (priv->fd < 0) return -1;

  artyz7_set_recv_ms (priv, ARTYZ7_RECV_MS);

  for (u32 i = 0; i < ARTYZ7_TRIES; )
  {
    u8 d[2048];

    const ssize_t n = artyz7_recv_frame (priv, d, sizeof (d));

    if (n < (ssize_t) HC_HDR_BYTES) return -1;

    if ((d[0] == HC_OP_RESULT) && (want != HC_OP_RESULT))
    {
      u32 l = (u32) d[2] | ((u32) d[3] << 8);

      if (l > (u32) (n - HC_HDR_BYTES)) l = (u32) (n - HC_HDR_BYTES);

      if ((priv->pend != NULL) && ((priv->pend_head + l) <= priv->pend_size))
      {
        memcpy (&priv->pend[priv->pend_head], &d[HC_HDR_BYTES], l);

        priv->pend_head += l;
      }

      continue;
    }

    if (d[0] != want)
    {
      i++;

      continue;
    }

    u32 l = (u32) d[2] | ((u32) d[3] << 8);

    if (l > max) l = max;
    if (l > (u32) (n - HC_HDR_BYTES)) l = (u32) (n - HC_HDR_BYTES);

    if (l > 0) memcpy (out, &d[HC_HDR_BYTES], l);

    return (int) l;
  }

  return -1;
}

static bool artyz7_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  u8 p[8];

  p[0] = (u8) (addr >>  0); p[1] = (u8) (addr >>  8); p[2] = (u8) (addr >> 16); p[3] = (u8) (addr >> 24);
  p[4] = (u8) (val  >>  0); p[5] = (u8) (val  >>  8); p[6] = (u8) (val  >> 16); p[7] = (u8) (val  >> 24);

  return artyz7_send_op (priv, HC_OP_CSR_WR, p, sizeof (p));
}

static u32 artyz7_csr_read (fpga_dev_t *dev, const u32 addr)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return 0;

  u8 p[4];

  p[0] = (u8) (addr >> 0); p[1] = (u8) (addr >> 8); p[2] = (u8) (addr >> 16); p[3] = (u8) (addr >> 24);

  for (u32 i = 0; i < ARTYZ7_TRIES; i++)
  {
    if (artyz7_send_op (priv, HC_OP_CSR_RD, p, sizeof (p)) == false) return 0;

    u8 r[8];

    if (artyz7_recv_op (priv, HC_OP_CSR_VAL, r, sizeof (r)) < 8) continue;

    const u32 got = ((u32) r[0] << 0) | ((u32) r[1] << 8) | ((u32) r[2] << 16) | ((u32) r[3] << 24);

    if (got != addr) continue;

    return ((u32) r[4] << 0) | ((u32) r[5] << 8) | ((u32) r[6] << 16) | ((u32) r[7] << 24);
  }

  return 0;
}

static u64 artyz7_out_capacity (fpga_dev_t *dev)
{
  (void) dev;

  return ARTYZ7_OUT_BYTES;
}

static bool artyz7_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  (void) out_bytes;

  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  priv->grain     = in_grain;
  priv->want      = in_recs;
  priv->done      = false;
  priv->processed = 0;
  priv->pend_head = 0;
  priv->pend_tail = 0;

  priv->in_batch   = true;
  priv->seq_synced = false;
  priv->lost       = false;

  const u64 need = MAX (in_bytes, (u64) ARTYZ7_PEND_BYTES);

  if (priv->pend_size < need)
  {
    hcfree (priv->pend);

    priv->pend      = (u8 *) hcmalloc (need);
    priv->pend_size = (priv->pend == NULL) ? 0 : (u32) need;
  }

  if (priv->pend == NULL)
  {
    close (priv->fd);

    priv->fd = -1;

    return false;
  }

  return true;
}

static bool artyz7_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  const u8 *p = (const u8 *) src;

  const u32 chunk = (ARTYZ7_MAX_PAYLOAD - 4) & ~3u;

  u64 off = 0;

  while (off < bytes)
  {
    u64 n = bytes - off;

    if (n > chunk) n = chunk;

    u8 f[ARTYZ7_MAX_PAYLOAD];

    f[0] = (u8) (off >>  0);
    f[1] = (u8) (off >>  8);
    f[2] = (u8) (off >> 16);
    f[3] = (u8) (off >> 24);

    memcpy (&f[4], &p[off], n);

    u64 pos = 0;

    for (u32 i = 0; (i < ARTYZ7_TRIES) && (pos <= off); i++)
    {
      if (artyz7_send_op (priv, HC_OP_FEED, f, (u32) (4 + n)) == false) return false;

      u8 ack[12];

      if (artyz7_recv_op (priv, HC_OP_FEED_ACK, ack, sizeof (ack)) < 8) continue;

      const u64 echo = ((u64) ack[0] << 0) | ((u64) ack[1] << 8) | ((u64) ack[2] << 16) | ((u64) ack[3] << 24);

      if (echo != off) continue;

      pos = ((u64) ack[4] << 0) | ((u64) ack[5] << 8) | ((u64) ack[6] << 16) | ((u64) ack[7] << 24);
    }

    if (pos <= off) return false;

    if (pos > bytes) return false;

    off = pos;
  }

  return true;
}

static const void *artyz7_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  *bytes = 0;

  if (priv == NULL) return NULL;
  if (priv->fd < 0) return NULL;

  if (priv->lost == true) return NULL;

  artyz7_set_recv_ms (priv, timeout_ms);

  u32 l = 0;

  if (priv->pend_tail < priv->pend_head)
  {
    l = priv->pend_head - priv->pend_tail;

    if (l > sizeof (priv->in_buf)) l = sizeof (priv->in_buf);

    if (priv->grain != 0) l = (l / priv->grain) * priv->grain;

    if (l == 0) return NULL;

    memcpy (priv->in_buf, &priv->pend[priv->pend_tail], l);

    priv->pend_tail += l;

    if (priv->pend_tail == priv->pend_head)
    {
      priv->pend_head = 0;
      priv->pend_tail = 0;
    }
  }
  else
  {
    u8 d[2048];

    const ssize_t n = artyz7_recv_frame (priv, d, sizeof (d));

    if (n < (ssize_t) HC_HDR_BYTES) return NULL;

    if (d[0] != HC_OP_RESULT) return NULL;

    l = (u32) d[2] | ((u32) d[3] << 8);

    if (l > (u32) (n - HC_HDR_BYTES)) l = (u32) (n - HC_HDR_BYTES);
    if (l > sizeof (priv->in_buf)) l = sizeof (priv->in_buf);

    if (priv->grain != 0) l = (l / priv->grain) * priv->grain;

    if (l == 0) return NULL;

    memcpy (priv->in_buf, &d[HC_HDR_BYTES], l);
  }

  u32 processed = 0;

  if (hcfpga_c2h_scan_eob (priv->in_buf, l, priv->grain, priv->want, &processed) == true)
  {
    priv->processed = processed;
    priv->done      = true;
  }

  *bytes = l;

  return priv->in_buf;
}

static void artyz7_batch_end (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return;

  priv->done      = false;
  priv->processed = 0;
  priv->in_batch  = false;

  artyz7_temp_refresh (priv);
}

static bool artyz7_batch_done (fpga_dev_t *dev, u32 *processed)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (processed != NULL) *processed = priv->processed;

  return priv->done;
}

static bool artyz7_batch_failed (fpga_dev_t *dev)
{
  const artyz7_priv_t *priv = (const artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;

  return priv->lost;
}

static bool artyz7_netcfg_write (dap_ctx_t *dap, const artyz7_priv_t *priv)
{
  if (priv == NULL) return false;

  const u32 ip  = ((u32) priv->ip[0]  <<  0) | ((u32) priv->ip[1]  <<  8) | ((u32) priv->ip[2]  << 16) | ((u32) priv->ip[3]  << 24);
  const u32 mlo = ((u32) priv->mac[0] <<  0) | ((u32) priv->mac[1] <<  8) | ((u32) priv->mac[2] << 16) | ((u32) priv->mac[3] << 24);
  const u32 mhi = ((u32) priv->mac[4] <<  0) | ((u32) priv->mac[5] <<  8);

  if (dap_mem_write32 (dap, ARTYZ7_NETCFG_ADDR + 0x00, 0)                   == false) return false;
  if (dap_mem_write32 (dap, ARTYZ7_NETCFG_ADDR + 0x04, ip)                  == false) return false;
  if (dap_mem_write32 (dap, ARTYZ7_NETCFG_ADDR + 0x08, mlo)                 == false) return false;
  if (dap_mem_write32 (dap, ARTYZ7_NETCFG_ADDR + 0x0C, mhi)                 == false) return false;
  if (dap_mem_write32 (dap, ARTYZ7_NETCFG_ADDR + 0x00, ARTYZ7_NETCFG_MAGIC) == false) return false;

  return true;
}

static fpga_status_t artyz7_load (fpga_dev_t *dev, const char *path)
{
  ftdi_ctx_t ftdi;
  jtag_ctx_t jtag;
  dap_ctx_t  dap;

  if (artyz7_dap_open (dev, &ftdi, &jtag, &dap) == false) return FPGA_STATUS_NO_CHAR_DEVICE;

  if (artyz7_ps7_init (&dap) == false)                 { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }
  if (artyz7_hold_cpu (&dap) == false)                 { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }
  if (artyz7_pl_disable (&dap) == false)               { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }
  if (artyz7_load_bitstream (&jtag, path) == false)    { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }
  if (artyz7_pl_enable (&dap) == false)                { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }

  if (artyz7_load_image (&dap, ARTYZ7_PS_APP, ARTYZ7_PS_APP_SIZE) == false) { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }

  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (artyz7_netcfg_write (&dap, priv) == false) { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }

  if (artyz7_key_write (&dap, priv) == false) { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }

  if (artyz7_start_cpu (&dap) == false)                { ftdi_close (&ftdi); return FPGA_STATUS_BAD_IDENT; }

  ftdi_close (&ftdi);

  if (priv != NULL) priv->app_loaded = true;

  return FPGA_STATUS_OK;
}

static fpga_status_t artyz7_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo)
{
  if (strcmp (algo, ARTYZ7_ALGO) != 0) return FPGA_STATUS_ALGO_UNAVAILABLE;

  char path[FPGA_PATH_MAX];

  if (fpga_shipped_file (hashcat_ctx->folder_config, ARTYZ7_BITSTREAM, path, sizeof (path)) == false)
  {
    const char *names[1] = { ARTYZ7_BITSTREAM };

    fpga_shipped_report_missing (hashcat_ctx, hashcat_ctx->folder_config, names, 1, fpga_board_find (ARTYZ7_BOARD));

    return FPGA_STATUS_NO_BITSTREAM;
  }

  if (fpga_say_progress (hashcat_ctx) == true) event_log_info_nn (hashcat_ctx, "Programming FPGA board %s, this takes about 6 seconds...", dev->ident.serial);

  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv != NULL) priv->folder_config = hashcat_ctx->folder_config;

  const fpga_status_t status = artyz7_load (dev, path);

  return status;
}

#define ARTYZ7_RELOAD_TRIES  10
#define ARTYZ7_RELOAD_WAIT   500000

static bool artyz7_reload (fpga_dev_t *dev)
{
  artyz7_priv_t *priv = (artyz7_priv_t *) dev->priv;

  if (priv == NULL) return false;
  if (priv->folder_config == NULL) return false;

  char path[FPGA_PATH_MAX];

  if (fpga_shipped_file (priv->folder_config, ARTYZ7_BITSTREAM, path, sizeof (path)) == false) return false;

  artyz7_socket_close (priv);

  bool loaded = false;

  for (u32 attempt = 0; attempt < ARTYZ7_RELOAD_TRIES; attempt++)
  {
    if (artyz7_load (dev, path) == FPGA_STATUS_OK)
    {
      loaded = true;

      break;
    }

    usleep (ARTYZ7_RELOAD_WAIT);
  }

  if (loaded == false) return false;

  if (artyz7_socket_open (priv) == false) return false;

  artyz7_set_recv_ms (priv, ARTYZ7_RECV_MS);

  u8 pong[64];

  for (u32 i = 0; i < ARTYZ7_TRIES; i++)
  {
    if (artyz7_send_op (priv, HC_OP_PING, NULL, 0) == false) continue;

    const int got = artyz7_recv_op (priv, HC_OP_PONG, pong, sizeof (pong));

    if (got < 4) continue;

    artyz7_temp_from_pong (priv, pong, got);

    return true;
  }

  return false;
}

#else

static int artyz7_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  (void) hashcat_ctx;
  (void) devs;
  (void) max;

  *status = FPGA_STATUS_UNSUPPORTED_OS;

  return 0;
}

static void artyz7_close (fpga_dev_t *dev)
{
  (void) dev;
}

static fpga_status_t artyz7_identify (fpga_dev_t *dev)
{
  (void) dev;

  return FPGA_STATUS_UNSUPPORTED_OS;
}

static bool artyz7_confirm (fpga_dev_t *dev)
{
  (void) dev;

  return false;
}

static fpga_status_t artyz7_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo)
{
  (void) hashcat_ctx;
  (void) dev;
  (void) algo;

  return FPGA_STATUS_UNSUPPORTED_OS;
}

static bool artyz7_session_open (fpga_dev_t *dev)
{
  (void) dev;

  return false;
}

static void artyz7_session_close (fpga_dev_t *dev)
{
  (void) dev;
}

static u64 artyz7_out_capacity (fpga_dev_t *dev)
{
  (void) dev;

  return 0;
}

static u32 artyz7_csr_read (fpga_dev_t *dev, const u32 addr)
{
  (void) dev;
  (void) addr;

  return 0;
}

static bool artyz7_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  (void) dev;
  (void) addr;
  (void) val;

  return false;
}

static bool artyz7_session_refresh (fpga_dev_t *dev)
{
  (void) dev;

  return false;
}

static bool artyz7_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  (void) dev;
  (void) out_bytes;
  (void) in_bytes;
  (void) in_grain;
  (void) in_recs;

  return false;
}

static bool artyz7_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  (void) dev;
  (void) src;
  (void) bytes;

  return false;
}

static const void *artyz7_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  (void) dev;
  (void) timeout_ms;

  *bytes = 0;

  return NULL;
}

static void artyz7_batch_end (fpga_dev_t *dev)
{
  (void) dev;
}

static bool artyz7_batch_done (fpga_dev_t *dev, u32 *processed)
{
  (void) dev;
  (void) processed;

  return false;
}

static bool artyz7_batch_failed (fpga_dev_t *dev)
{
  (void) dev;

  return false;
}

static int artyz7_temp_cached (fpga_dev_t *dev)
{
  (void) dev;

  return -1;
}

static bool artyz7_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  (void) dev;
  (void) buf;
  (void) len;

  return false;
}

#endif

const fpga_transport_t fpga_transport_artyz7 =
{
  .name            = "artyz7",
  .bus             = "USB",
  .data_link       = "Ethernet",
  .udev            = "99-digilent.rules",

  .dialect         = FPGA_DIALECT_HCFPGA,

  .enumerate       = artyz7_enumerate,
  .close           = artyz7_close,
  .identify        = artyz7_identify,
  .confirm         = artyz7_confirm,

  .csr_read        = artyz7_csr_read,
  .csr_write       = artyz7_csr_write,

  .session_open    = artyz7_session_open,
  .session_close   = artyz7_session_close,
  .session_refresh = artyz7_session_refresh,
  .out_capacity    = artyz7_out_capacity,

  .batch_begin     = artyz7_batch_begin,
  .batch_send      = artyz7_batch_send,
  .control         = NULL,
  .batch_recv      = artyz7_batch_recv,
  .batch_end       = artyz7_batch_end,
  .batch_done      = artyz7_batch_done,
  .batch_failed    = artyz7_batch_failed,

  .in_granule      = 0,

  .program         = artyz7_program,

  .temperature     = artyz7_temp_cached,
  .temperature_all = NULL,

  .temperature_is_die = true,

  .clock_step_down = NULL,

  .link_str        = artyz7_link_str,
};
