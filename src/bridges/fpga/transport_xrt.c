/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "dynloader.h"
#include "hcfpga.h"
#include "xrt_abi.h"

#if defined (__linux__)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define XRT_BOARD "u50"

#define XRT_BCRYPT_CSR_CTRL       0x00
#define XRT_BCRYPT_CSR_CMP_BM0    0x20
#define XRT_BCRYPT_CSR_RETIRED    0x38

#define XRT_BCRYPT_CSR_SALT0      0x04
#define XRT_BCRYPT_CSR_SALT3      0x10
#define XRT_BCRYPT_CSR_ITER_COUNT 0x14

#define XRT_BCRYPT_REG_IDENT     0x40
#define XRT_BCRYPT_REG_NUM_CORES 0x44
#define XRT_BCRYPT_REG_NUM_DIST  0x48
#define XRT_BCRYPT_REG_ABI       0x54

#define XRT_BCRYPT_IDENT_MAGIC   0x68636263

typedef enum xrt_algo
{
  XRT_ALGO_NONE   = 0,
  XRT_ALGO_BCRYPT = 2,

} xrt_algo_t;

#define XRT_OUT_CAPACITY (4 * 1024 * 1024)

#define XCLBIN_SECTION_CLOCK_FREQ_TOPOLOGY  11
#define XCLBIN_CLOCK_TYPE_DATA               1

#define XCLBIN_HDR_OFF          (8 + 4 + 28 + 256 + 8)
#define XCLBIN_NUM_SECTIONS_OFF (XCLBIN_HDR_OFF + 144)
#define XCLBIN_SECTIONS_OFF     (XCLBIN_HDR_OFF + 152)
#define XCLBIN_SECTION_HDR_SZ   40
#define XCLBIN_CLOCK_ENTRY_SZ   136

static u32 xrt_clk_mhz_from_xclbin (const char *path)
{
  if (path == NULL) return 0;

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return 0;

  u32 mhz = 0;

  unsigned char hdr[XCLBIN_SECTIONS_OFF];

  if (fread (hdr, 1, sizeof (hdr), fp) != sizeof (hdr))
  {
    fclose (fp);

    return 0;
  }

  if (memcmp (hdr, "xclbin2", 8) != 0)
  {
    fclose (fp);

    return 0;
  }

  u64 declared = 0;

  memcpy (&declared, hdr + XCLBIN_HDR_OFF, sizeof (declared));

  u32 sections = 0;

  memcpy (&sections, hdr + XCLBIN_NUM_SECTIONS_OFF, sizeof (sections));

  if (fseek (fp, 0, SEEK_END) != 0)
  {
    fclose (fp);

    return 0;
  }

  const long size = ftell (fp);

  if (size <= 0)                    { fclose (fp); return 0; }
  if ((u64) size != declared)       { fclose (fp); return 0; }
  if (sections == 0)                { fclose (fp); return 0; }
  if (sections > 256)               { fclose (fp); return 0; }

  for (u32 i = 0; i < sections; i++)
  {
    unsigned char sh[XCLBIN_SECTION_HDR_SZ];

    if (fseek (fp, (long) (XCLBIN_SECTIONS_OFF + (i * XCLBIN_SECTION_HDR_SZ)), SEEK_SET) != 0) break;
    if (fread (sh, 1, sizeof (sh), fp) != sizeof (sh)) break;

    u32 kind = 0;
    u64 off  = 0;
    u64 len  = 0;

    memcpy (&kind, sh +  0, sizeof (kind));
    memcpy (&off,  sh + 24, sizeof (off));
    memcpy (&len,  sh + 32, sizeof (len));

    if (kind != XCLBIN_SECTION_CLOCK_FREQ_TOPOLOGY) continue;

    if (off >= (u64) size)          break;
    if (len < 2)                    break;
    if ((off + len) > (u64) size)   break;

    if (fseek (fp, (long) off, SEEK_SET) != 0) break;

    u16 cnt = 0;

    if (fread (&cnt, 1, sizeof (cnt), fp) != sizeof (cnt)) break;

    if ((u64) (2 + ((u64) cnt * XCLBIN_CLOCK_ENTRY_SZ)) > len) break;

    for (u16 c = 0; c < cnt; c++)
    {
      unsigned char e[XCLBIN_CLOCK_ENTRY_SZ];

      if (fread (e, 1, sizeof (e), fp) != sizeof (e)) break;

      u16 e_mhz = 0;

      memcpy (&e_mhz, e, sizeof (e_mhz));

      const unsigned char e_type = e[2];

      if (e_type != XCLBIN_CLOCK_TYPE_DATA) continue;
      if (e_mhz == 0)                       continue;
      if (e_mhz >= 2000)                    continue;

      mhz = e_mhz;

      break;
    }

    break;
  }

  fclose (fp);

  return mhz;
}

typedef struct xrt_priv
{
  hc_xrt_lib_t xrt;

  unsigned int idx;

  xrtDeviceHandle dev;
  xrtKernelHandle kernel;
  xrtRunHandle    run;

  bool cu_shared;

  hc_xrt_uuid_t uuid;

  xrt_algo_t algo;

  u32 cores;

  u32 dist;

  u32 clk_mhz;

  u32 card_abi;

  u32 salt[4];
  u32 iter_count;

  xrtBufferHandle bo_in;
  xrtBufferHandle bo_out;

  u8 *map_in;
  u8 *map_out;

  u64  batch_in_bytes;
  u32  batch_jobs;
  bool batch_running;

  bool batch_failed;
  u32  batch_fail_state;
  bool batch_taken;

} xrt_priv_t;

static const char *const XRT_LIB_PATHS[] =
{
  "libxrt_coreutil.so.2",
  "libxrt_coreutil.so",
  "/opt/xilinx/xrt/lib/libxrt_coreutil.so.2",
  "/opt/xilinx/xrt/lib/libxrt_coreutil.so",
  "/usr/lib/libxrt_coreutil.so.2",
  "/usr/local/xilinx/xrt/lib/libxrt_coreutil.so.2",
};

static bool xrt_lib_open (hc_xrt_lib_t *xrt)
{
  xrt->lib = NULL;

  for (size_t i = 0; i < sizeof (XRT_LIB_PATHS) / sizeof (XRT_LIB_PATHS[0]); i++)
  {
    xrt->lib = hc_dlopen (XRT_LIB_PATHS[i]);

    if (xrt->lib != NULL) break;
  }

  if (xrt->lib == NULL)
  {
    const char *root = getenv ("XILINX_XRT");

    if (root != NULL)
    {
      char path[FPGA_PATH_MAX];

      snprintf (path, sizeof (path), "%s/lib/libxrt_coreutil.so.2", root);

      xrt->lib = hc_dlopen (path);
    }
  }

  if (xrt->lib == NULL) return false;

  #define XRT_SYM(ptr,name,type)                                       \
    do                                                                 \
    {                                                                  \
      xrt->ptr = (type) hc_dlsym (xrt->lib, name);                     \
                                                                       \
      if (xrt->ptr == NULL)                                            \
      {                                                                \
        hc_dlclose (xrt->lib);                                         \
                                                                       \
        xrt->lib = NULL;                                               \
                                                                       \
        return false;                                                  \
      }                                                                \
    } while (0)

  XRT_SYM (xrtDeviceOpen,           "xrtDeviceOpen",           HC_XRT_DEVICE_OPEN);
  XRT_SYM (xrtDeviceClose,          "xrtDeviceClose",          HC_XRT_DEVICE_CLOSE);
  XRT_SYM (xrtDeviceLoadXclbinFile, "xrtDeviceLoadXclbinFile", HC_XRT_DEVICE_LOAD_XCLBIN_FILE);
  XRT_SYM (xrtDeviceGetXclbinUUID,  "xrtDeviceGetXclbinUUID",  HC_XRT_DEVICE_GET_XCLBIN_UUID);

  XRT_SYM (xrtPLKernelOpen,         "xrtPLKernelOpen",         HC_XRT_PL_KERNEL_OPEN);
  XRT_SYM (xrtKernelClose,          "xrtKernelClose",          HC_XRT_KERNEL_CLOSE);
  XRT_SYM (xrtKernelArgGroupId,     "xrtKernelArgGroupId",     HC_XRT_KERNEL_ARG_GROUP_ID);

  XRT_SYM (xrtRunOpen,              "xrtRunOpen",              HC_XRT_RUN_OPEN);
  XRT_SYM (xrtRunSetArg,            "xrtRunSetArg",            HC_XRT_RUN_SET_ARG);
  XRT_SYM (xrtRunStart,             "xrtRunStart",             HC_XRT_RUN_START);
  XRT_SYM (xrtRunWaitFor,           "xrtRunWaitFor",           HC_XRT_RUN_WAIT_FOR);
  XRT_SYM (xrtRunState,             "xrtRunState",             HC_XRT_RUN_STATE);
  XRT_SYM (xrtRunClose,             "xrtRunClose",             HC_XRT_RUN_CLOSE);

  XRT_SYM (xrtBOAlloc,              "xrtBOAlloc",              HC_XRT_BO_ALLOC);
  XRT_SYM (xrtBOFree,               "xrtBOFree",               HC_XRT_BO_FREE);
  XRT_SYM (xrtBOSync,               "xrtBOSync",               HC_XRT_BO_SYNC);
  XRT_SYM (xrtBOMap,                "xrtBOMap",                HC_XRT_BO_MAP);

  #undef XRT_SYM

  xrt->xrtKernelReadRegister    = (HC_XRT_KERNEL_READ_REGISTER) hc_dlsym (xrt->lib, "xrtKernelReadRegister");
  xrt->xrtPLKernelOpenExclusive = (HC_XRT_PL_KERNEL_OPEN_EXCL)  hc_dlsym (xrt->lib, "xrtPLKernelOpenExclusive");

  return true;
}

static bool xrt_ident_from_name (const char *name, xrt_priv_t *priv)
{
  const char *p = strstr (name, "hcfpga_bcrypt_c");

  if (p != NULL)
  {
    unsigned int c = 0;
    unsigned int d = 0;

    if (sscanf (p, "hcfpga_bcrypt_c%u_d%u", &c, &d) != 2) return false;

    if (c == 0) return false;
    if (d > c) return false;

    priv->algo   = XRT_ALGO_BCRYPT;
    priv->cores  = (u32) c;
    priv->dist   = (u32) d;

    const char *f = strstr (p, "_f");

    if (f != NULL)
    {
      unsigned int mhz = 0;

      int end = 0;

      if (sscanf (f, "_f%u%n", &mhz, &end) == 1)
      {
        const char tail = f[end];

        if ((tail == 0) || (tail == '.'))
        {
          if ((mhz > 0) && (mhz < 2000)) priv->clk_mhz = (u32) mhz;
        }
      }
    }

    return true;
  }

  return false;
}

static bool xrt_report_once (const char *tag)
{
  const bool first = fpga_report_once (fpga_board_find (XRT_BOARD), tag);

  return first;
}

static fpga_status_t xrt_ident_from_card (hashcat_ctx_t *hashcat_ctx, xrt_priv_t *priv, const bool named)
{
  if (priv->xrt.xrtKernelReadRegister == NULL)
  {
    if (xrt_report_once ("ident-no-register-read") == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: the installed XRT library cannot read kernel registers, so the design's identity is unavailable.");
      event_log_error (hashcat_ctx, "             Update XRT.");
    }

    return FPGA_STATUS_BAD_IDENT;
  }

  unsigned int magic = 0;
  unsigned int cores = 0;
  unsigned int dist  = 0;
  unsigned int abi   = 0;

  const bool answered = ((priv->xrt.xrtKernelReadRegister (priv->kernel, XRT_BCRYPT_REG_IDENT,     &magic) == 0)
                      && (priv->xrt.xrtKernelReadRegister (priv->kernel, XRT_BCRYPT_REG_NUM_CORES, &cores) == 0)
                      && (priv->xrt.xrtKernelReadRegister (priv->kernel, XRT_BCRYPT_REG_NUM_DIST,  &dist)  == 0)) ? true : false;

  if (priv->xrt.xrtKernelReadRegister (priv->kernel, XRT_BCRYPT_REG_ABI, &abi) != 0) abi = 0;

  priv->card_abi = (u32) abi;

  if (answered == false)
  {
    if (priv->cu_shared == true)
    {
      if (xrt_report_once ("ident-shared") == true)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: the card's compute unit could only be opened shared, so its identity registers cannot be read.");
        event_log_error (hashcat_ctx, "             Another process may be using the card.");
      }

      return FPGA_STATUS_IN_USE;
    }

    if (xrt_report_once ("ident-no-answer") == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: the loaded design does not answer its identity register, so its identity is unavailable.");
    }

    return FPGA_STATUS_BAD_IDENT;
  }

  if (magic != XRT_BCRYPT_IDENT_MAGIC)
  {
    if (xrt_report_once ("ident-not-bcrypt") == true) event_log_error (hashcat_ctx, "FPGA bridge: the loaded design reports identity 0x%08x, not an hcfpga bcrypt kernel.", magic);

    return FPGA_STATUS_BAD_IDENT;
  }

  if (cores == 0)
  {
    if (xrt_report_once ("ident-no-cores") == true) event_log_error (hashcat_ctx, "FPGA bridge: the loaded design reports 0 cores, which is not a usable array size.");

    return FPGA_STATUS_BAD_IDENT;
  }

  if (named == false)
  {
    priv->algo  = XRT_ALGO_BCRYPT;
    priv->cores = (u32) cores;
    priv->dist  = (u32) dist;

    return FPGA_STATUS_OK;
  }

  if (((u32) cores != priv->cores) || ((u32) dist != priv->dist))
  {
    if (xrt_report_once ("ident-shape-mismatch") == true) event_log_error (hashcat_ctx, "FPGA bridge: the xclbin filename specifies %u cores (%u distributed), but the card reports %u (%u). The file may have been renamed or replaced.", priv->cores, priv->dist, cores, dist);

    return FPGA_STATUS_BAD_IDENT;
  }

  return FPGA_STATUS_OK;
}

static bool xrt_board_serial (const unsigned int idx, char *out, const size_t out_size);

static fpga_status_t xrt_identify (fpga_dev_t *dev)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return FPGA_STATUS_BAD_IDENT;

  if (priv->algo == XRT_ALGO_NONE)
  {
    snprintf (dev->ident.board, sizeof (dev->ident.board), XRT_BOARD);
    snprintf (dev->ident.raw,   sizeof (dev->ident.raw),   "%s not loaded", XRT_BOARD);
    snprintf (dev->ident.algo,  sizeof (dev->ident.algo),  "bcrypt");

    xrt_board_serial (priv->idx, dev->ident.serial, sizeof (dev->ident.serial));

    dev->ident.abi      = FPGA_ABI_CURRENT;
    dev->ident.asserted = true;

    return FPGA_STATUS_OK;
  }

  if (priv->kernel == NULL) return FPGA_STATUS_BAD_IDENT;

  snprintf (dev->ident.board, sizeof (dev->ident.board), XRT_BOARD);

  xrt_board_serial (priv->idx, dev->ident.serial, sizeof (dev->ident.serial));

  if (priv->algo == XRT_ALGO_BCRYPT)
  {
    snprintf (dev->ident.raw,   sizeof (dev->ident.raw),   "u50 bcrypt c%u d%u", priv->cores, priv->dist);
    snprintf (dev->ident.algo,  sizeof (dev->ident.algo),  "bcrypt");
    snprintf (dev->ident.build, sizeof (dev->ident.build), "c%u d%u", priv->cores, priv->dist);

    dev->ident.cores = priv->cores;

    dev->ident.n = 0;
    dev->ident.r = 0;

    dev->ident.clk_mhz = priv->clk_mhz;
  }
  else
  {
    return FPGA_STATUS_BAD_IDENT;
  }

  dev->ident.abi = priv->card_abi;

  return FPGA_STATUS_OK;
}

#define XRT_HWMON_ROOT  "/sys/bus/pci/devices"

#define XRT_BDF_MAX    24
#define XRT_SYSFS_MAX  256

static bool xrt_hwmon_name_is_user (const char *dir)
{
  char path[XRT_SYSFS_MAX];

  snprintf (path, sizeof (path), "%s/name", dir);

  FILE *fp = fopen (path, "r");

  if (fp == NULL) return false;

  char name[128];

  const char *got = fgets (name, sizeof (name), fp);

  fclose (fp);

  if (got == NULL) return false;

  const size_t len = strlen (name);

  if (len < 6) return false;

  const char *tail = strstr (name, "_user");

  if (tail == NULL) return false;

  return true;
}

static bool xrt_user_bdf (const unsigned int idx, char out[XRT_BDF_MAX])
{
  DIR *root = opendir (XRT_HWMON_ROOT);

  if (root == NULL) return false;

  char bdfs[FPGA_MAX_DEVICES][XRT_BDF_MAX];

  u32 cnt = 0;

  struct dirent *e = NULL;

  while ((e = readdir (root)) != NULL)
  {
    if (e->d_name[0] == '.') continue;
    if (cnt >= FPGA_MAX_DEVICES) break;

    if (strlen (e->d_name) >= XRT_BDF_MAX) continue;

    char hwmon_root[XRT_SYSFS_MAX];

    snprintf (hwmon_root, sizeof (hwmon_root), "%s/%s/hwmon", XRT_HWMON_ROOT, e->d_name);

    DIR *hw = opendir (hwmon_root);

    if (hw == NULL) continue;

    bool is_user = false;

    struct dirent *h = NULL;

    while ((h = readdir (hw)) != NULL)
    {
      if (strncmp (h->d_name, "hwmon", 5) != 0) continue;

      char cand[XRT_SYSFS_MAX];

      snprintf (cand, sizeof (cand), "%.*s/%.16s", 200, hwmon_root, h->d_name);

      if (xrt_hwmon_name_is_user (cand) == false) continue;

      is_user = true;

      break;
    }

    closedir (hw);

    if (is_user == false) continue;

    snprintf (bdfs[cnt], sizeof (bdfs[cnt]), "%s", e->d_name);

    cnt++;
  }

  closedir (root);

  if (idx >= cnt) return false;

  for (u32 i = 0; i + 1 < cnt; i++)
  {
    for (u32 j = 0; j + 1 < cnt - i; j++)
    {
      if (strcmp (bdfs[j], bdfs[j + 1]) <= 0) continue;

      char tmp[XRT_BDF_MAX];

      memcpy (tmp,          bdfs[j],     XRT_BDF_MAX);
      memcpy (bdfs[j],      bdfs[j + 1], XRT_BDF_MAX);
      memcpy (bdfs[j + 1],  tmp,         XRT_BDF_MAX);
    }
  }

  snprintf (out, XRT_BDF_MAX, "%s", bdfs[idx]);

  return true;
}

static bool xrt_board_serial (const unsigned int idx, char *out, const size_t out_size)
{
  char bdf[XRT_BDF_MAX];

  if (xrt_user_bdf (idx, bdf) == false) return false;

  char mgmt[XRT_BDF_MAX];

  snprintf (mgmt, sizeof (mgmt), "%s", bdf);

  char *dot = strrchr (mgmt, '.');

  if (dot == NULL) return false;

  dot[1] = '0';
  dot[2] = 0;

  char mgmt_root[XRT_SYSFS_MAX];

  snprintf (mgmt_root, sizeof (mgmt_root), "%s/%s", XRT_HWMON_ROOT, mgmt);

  DIR *d = opendir (mgmt_root);

  if (d == NULL) return false;

  char xmc[XRT_SYSFS_MAX];

  bool have_xmc = false;

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if (strncmp (e->d_name, "xmc.", 4) != 0) continue;
    if (strlen (e->d_name) >= 64) continue;

    snprintf (xmc, sizeof (xmc), "%.*s/%.63s", 180, mgmt_root, e->d_name);

    have_xmc = true;

    break;
  }

  closedir (d);

  if (have_xmc == false) return false;

  char path[XRT_SYSFS_MAX];

  snprintf (path, sizeof (path), "%.*s/serial_num", 240, xmc);

  FILE *fp = fopen (path, "r");

  if (fp == NULL) return false;

  char buf[64];

  const char *got = fgets (buf, sizeof (buf), fp);

  fclose (fp);

  if (got == NULL) return false;

  size_t len = strlen (buf);

  while ((len > 0) && ((buf[len - 1] == '\n') || (buf[len - 1] == '\r') || (buf[len - 1] == ' '))) len--;

  buf[len] = 0;

  if (len == 0) return false;

  snprintf (out, out_size, "%s", buf);

  return true;
}

static bool xrt_hwmon_dir (const unsigned int idx, char out[XRT_SYSFS_MAX])
{
  char bdf[XRT_BDF_MAX];

  if (xrt_user_bdf (idx, bdf) == false) return false;

  char hwmon_root[XRT_SYSFS_MAX];

  snprintf (hwmon_root, sizeof (hwmon_root), "%s/%s/hwmon", XRT_HWMON_ROOT, bdf);

  DIR *hw = opendir (hwmon_root);

  if (hw == NULL) return false;

  bool found = false;

  struct dirent *h = NULL;

  while ((h = readdir (hw)) != NULL)
  {
    if (strncmp (h->d_name, "hwmon", 5) != 0) continue;

    char cand[XRT_SYSFS_MAX];

    snprintf (cand, sizeof (cand), "%.*s/%.16s", 200, hwmon_root, h->d_name);

    if (xrt_hwmon_name_is_user (cand) == false) continue;

    snprintf (out, XRT_SYSFS_MAX, "%s", cand);

    found = true;

    break;
  }

  closedir (hw);

  return found;
}

static int xrt_temperature (fpga_dev_t *dev)
{
  const xrt_priv_t *priv = (const xrt_priv_t *) dev->priv;

  if (priv == NULL) return -1;

  char dir[XRT_SYSFS_MAX];

  if (xrt_hwmon_dir (priv->idx, dir) == false) return -1;

  for (u32 i = 1; i <= 32; i++)
  {
    char path[XRT_SYSFS_MAX + 32];

    snprintf (path, sizeof (path), "%s/temp%u_label", dir, i);

    FILE *fp = fopen (path, "r");

    if (fp == NULL) continue;

    char label[64];

    const char *got = fgets (label, sizeof (label), fp);

    fclose (fp);

    if (got == NULL) continue;

    if (strstr (label, "FPGA TEMP") == NULL) continue;

    snprintf (path, sizeof (path), "%s/temp%u_input", dir, i);

    fp = fopen (path, "r");

    if (fp == NULL) return -1;

    long milli = 0;

    const int rc = fscanf (fp, "%ld", &milli);

    fclose (fp);

    if (rc != 1)      return -1;
    if (milli <= 0)   return -1;

    return (int) (milli / 1000);
  }

  return -1;
}

static fpga_status_t xrt_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return FPGA_STATUS_BAD_IDENT;

  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  const char *kernel_name = NULL;

  if (strcmp (algo, "bcrypt") == 0)
  {
    kernel_name = "hcfpga_bcrypt";
  }
  else
  {
    return FPGA_STATUS_ALGO_UNAVAILABLE;
  }

  char name[256];

  const char *want = getenv ("HCFPGA_XCLBIN");

  if (want != NULL)
  {
    snprintf (name, sizeof (name), "%s", want);
  }
  else
  {
    const fpga_release_t *release = fpga_release_find (algo, XRT_BOARD, 0, 0);

    if (fpga_release_filename (release, name, sizeof (name)) == false)
    {
      if (xrt_report_once ("no-release") == true) event_log_error (hashcat_ctx, "FPGA bridge: this build publishes no %s design for the %s.", algo, XRT_BOARD);

      return FPGA_STATUS_ALGO_UNAVAILABLE;
    }
  }

  char path[FPGA_PATH_MAX];

  if (fpga_shipped_file (folder_config, name, path, sizeof (path)) == false)
  {
    const char *missing[1];

    missing[0] = name;

    fpga_shipped_report_missing (hashcat_ctx, folder_config, missing, 1, fpga_board_find (XRT_BOARD));

    return FPGA_STATUS_NO_BITSTREAM;
  }

  if (priv->xrt.xrtDeviceLoadXclbinFile (priv->dev, path) != 0)
  {
    if (xrt_report_once ("xclbin-refused") == true) event_log_error (hashcat_ctx, "FPGA bridge: XRT refused the xclbin %s.", path);

    return FPGA_STATUS_BAD_IDENT;
  }

  if (priv->xrt.xrtDeviceGetXclbinUUID (priv->dev, priv->uuid) != 0) return FPGA_STATUS_BAD_IDENT;

  const bool named = xrt_ident_from_name (name, priv);

  const u32 xclbin_mhz = xrt_clk_mhz_from_xclbin (path);

  if (xclbin_mhz > 0) priv->clk_mhz = xclbin_mhz;

  if ((named == true) && (strcmp (algo, "bcrypt") == 0) && (priv->algo != XRT_ALGO_BCRYPT))
  {
    if (xrt_report_once ("xclbin-wrong-algo") == true) event_log_error (hashcat_ctx, "FPGA bridge: %s is not a %s design.", name, algo);

    priv->algo = XRT_ALGO_NONE;

    return FPGA_STATUS_BAD_IDENT;
  }

  priv->kernel = NULL;

  if (priv->xrt.xrtPLKernelOpenExclusive != NULL)
  {
    priv->kernel = priv->xrt.xrtPLKernelOpenExclusive (priv->dev, priv->uuid, kernel_name);
  }

  priv->cu_shared = (priv->kernel == NULL) ? true : false;

  if (priv->kernel == NULL) priv->kernel = priv->xrt.xrtPLKernelOpen (priv->dev, priv->uuid, kernel_name);

  if (priv->kernel == NULL)
  {
    if (xrt_report_once ("xclbin-no-kernel") == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: the kernel %s in %s could not be opened.", kernel_name, name);
      event_log_info (hashcat_ctx, "Another hashcat process may be using the card. If nothing else uses it, the file is not");
      event_log_info (hashcat_ctx, "the xclbin this build expects.");
    }

    return FPGA_STATUS_IN_USE;
  }

  const fpga_status_t vs = xrt_ident_from_card (hashcat_ctx, priv, named);

  if (vs != FPGA_STATUS_OK) return vs;

  return FPGA_STATUS_OK;
}

static bool xrt_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (priv->algo != XRT_ALGO_BCRYPT) return false;

  if ((addr >= XRT_BCRYPT_CSR_SALT0) && (addr <= XRT_BCRYPT_CSR_SALT3))
  {
    priv->salt[(addr - XRT_BCRYPT_CSR_SALT0) / 4] = val;

    return true;
  }

  if (addr == XRT_BCRYPT_CSR_ITER_COUNT)
  {
    priv->iter_count = val;

    return true;
  }

  if (addr == XRT_BCRYPT_CSR_CTRL) return true;

  if ((addr >= XRT_BCRYPT_CSR_CMP_BM0) && (addr <= XRT_BCRYPT_CSR_RETIRED)) return true;

  return false;
}

static void xrt_close (fpga_dev_t *dev)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return;

  if (priv->kernel) priv->xrt.xrtKernelClose (priv->kernel);

  if (priv->dev) priv->xrt.xrtDeviceClose (priv->dev);

  if (priv->xrt.lib) hc_dlclose (priv->xrt.lib);

  hcfree (priv);

  dev->priv = NULL;
}

static int xrt_hw_count (void)
{
  DIR *d = opendir ("/sys/bus/pci/devices");

  if (d == NULL) return 0;

  char seen[FPGA_MAX_DEVICES][XRT_BDF_MAX];

  int cnt = 0;

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if (e->d_name[0] == '.') continue;
    if (cnt >= FPGA_MAX_DEVICES) break;

    char path[512];

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/vendor", e->d_name);

    FILE *fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int vendor = 0;

    const int rc_ven = fscanf (fp, "0x%x", &vendor);

    fclose (fp);

    if (rc_ven != 1) continue;
    if (vendor != 0x10ee) continue;

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/class", e->d_name);

    fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int class_code = 0;

    const int rc_cls = fscanf (fp, "0x%x", &class_code);

    fclose (fp);

    if (rc_cls != 1) continue;

    if ((class_code >> 8) != 0x1200) continue;

    if (strlen (e->d_name) >= XRT_BDF_MAX) continue;

    char bdf[XRT_BDF_MAX];

    snprintf (bdf, sizeof (bdf), "%s", e->d_name);

    char *dot = strrchr (bdf, '.');

    if (dot) *dot = 0;

    bool dup = false;

    for (int i = 0; i < cnt; i++)
    {
      if (strcmp (seen[i], bdf) == 0) dup = true;
    }

    if (dup == true) continue;

    snprintf (seen[cnt], sizeof (seen[cnt]), "%s", bdf);

    cnt++;
  }

  closedir (d);

  return cnt;
}

static int xrt_enumerate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  *status = FPGA_STATUS_NO_PCI_DEVICE;

  const int hw = xrt_hw_count ();

  if (hw == 0) return 0;

  hc_xrt_lib_t probe;

  memset (&probe, 0, sizeof (probe));

  if (xrt_lib_open (&probe) == false)
  {
    event_log_warning (hashcat_ctx, "FPGA bridge: %d Alveo card(s) are on the bus, but the XRT runtime could not be loaded, so they are NOT being used.", hw);
    event_log_warning (hashcat_ctx, NULL);

    *status = FPGA_STATUS_NO_RUNTIME;

    return 0;
  }

  hc_dlclose (probe.lib);

  const int want = (hw < max) ? hw : max;

  int found = 0;

  for (int i = 0; i < want; i++)
  {
    xrt_priv_t *priv = (xrt_priv_t *) hcmalloc (sizeof (xrt_priv_t));

    if (priv == NULL) break;

    memset (priv, 0, sizeof (xrt_priv_t));

    if (xrt_lib_open (&priv->xrt) == false)
    {
      hcfree (priv);

      break;
    }

    priv->dev = priv->xrt.xrtDeviceOpen ((unsigned int) i);

    if (priv->dev == NULL)
    {
      hc_dlclose (priv->xrt.lib);

      hcfree (priv);

      break;
    }

    priv->idx = (unsigned int) i;

    fpga_dev_t *dev = &devs[found];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->ident.board, sizeof (dev->ident.board), XRT_BOARD);

    snprintf (dev->path, sizeof (dev->path), "xrt%d", i);

    dev->fd        = -1;
    dev->priv      = priv;
    dev->transport = &fpga_transport_xrt;

    found++;
  }

  if (found > 0)
  {
    *status = FPGA_STATUS_OK;

    return found;
  }

  event_log_warning (hashcat_ctx, "FPGA bridge: %d Alveo card(s) are on the bus, but XRT could not open any of them, so they are NOT being used. Check that the xocl driver is loaded and that xrt-smi examine lists the card.", hw);
  event_log_warning (hashcat_ctx, NULL);

  *status = FPGA_STATUS_NO_RUNTIME;

  return 0;
}

static void xrt_session_close (fpga_dev_t *dev)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return;

  if (priv->run) priv->xrt.xrtRunClose (priv->run);

  priv->run = NULL;

  if (priv->bo_out) priv->xrt.xrtBOFree (priv->bo_out);
  if (priv->bo_in)  priv->xrt.xrtBOFree (priv->bo_in);

  priv->bo_out  = NULL;
  priv->bo_in   = NULL;
  priv->map_in  = NULL;
  priv->map_out = NULL;
}

static bool xrt_session_open (fpga_dev_t *dev)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return false;
  if (priv->kernel == NULL) return false;

  const int grp_in = priv->xrt.xrtKernelArgGroupId (priv->kernel, 1);
  const int grp_out = priv->xrt.xrtKernelArgGroupId (priv->kernel, 2);

  if (grp_in < 0) return false;
  if (grp_out < 0) return false;

  priv->bo_in = priv->xrt.xrtBOAlloc (priv->dev, XRT_OUT_CAPACITY, 0, (xrtMemoryGroup) grp_in);

  if (priv->bo_in == NULL) return false;

  priv->bo_out = priv->xrt.xrtBOAlloc (priv->dev, XRT_OUT_CAPACITY, 0, (xrtMemoryGroup) grp_out);

  if (priv->bo_out == NULL)
  {
    xrt_session_close (dev);

    return false;
  }

  priv->map_in = (u8 *) priv->xrt.xrtBOMap (priv->bo_in);

  priv->map_out = (u8 *) priv->xrt.xrtBOMap (priv->bo_out);

  if (priv->map_in == NULL)
  {
    xrt_session_close (dev);

    return false;
  }

  if (priv->map_out == NULL)
  {
    xrt_session_close (dev);

    return false;
  }

  priv->run = priv->xrt.xrtRunOpen (priv->kernel);

  if (priv->run == NULL)
  {
    xrt_session_close (dev);

    return false;
  }

  return true;
}

static bool xrt_session_refresh (fpga_dev_t *dev)
{
  xrt_session_close (dev);

  const bool ok = xrt_session_open (dev);

  return ok;
}

static u64 xrt_out_capacity (MAYBE_UNUSED fpga_dev_t *dev)
{
  return XRT_OUT_CAPACITY;
}

static bool xrt_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, MAYBE_UNUSED const u32 in_grain, MAYBE_UNUSED const u32 in_recs)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return false;
  if (priv->run == NULL) return false;

  if (out_bytes > XRT_OUT_CAPACITY) return false;
  if (in_bytes  > XRT_OUT_CAPACITY) return false;

  if (in_grain == 0) return false;

  priv->batch_jobs     = (u32) (in_bytes / in_grain);
  priv->batch_in_bytes = in_bytes;
  priv->batch_running  = false;
  priv->batch_taken    = false;

  return true;
}

static bool xrt_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return false;
  if (priv->run == NULL) return false;

  if (bytes > XRT_OUT_CAPACITY) return false;

  memcpy (priv->map_in, src, bytes);

  if (priv->xrt.xrtBOSync (priv->bo_in, HC_XCL_BO_SYNC_BO_TO_DEVICE, bytes, 0) != 0) return false;

  memset (priv->map_out, 0xff, (size_t) priv->batch_in_bytes);

  if (priv->xrt.xrtBOSync (priv->bo_out, HC_XCL_BO_SYNC_BO_TO_DEVICE, priv->batch_in_bytes, 0) != 0) return false;

  if (priv->xrt.xrtRunSetArg (priv->run, 0, (u32) priv->batch_jobs) != 0) return false;
  if (priv->xrt.xrtRunSetArg (priv->run, 1, priv->bo_in)  != 0) return false;
  if (priv->xrt.xrtRunSetArg (priv->run, 2, priv->bo_out) != 0) return false;

  if (priv->algo == XRT_ALGO_BCRYPT)
  {
    if (priv->xrt.xrtRunSetArg (priv->run, 3, (u32) priv->salt[0])   != 0) return false;
    if (priv->xrt.xrtRunSetArg (priv->run, 4, (u32) priv->salt[1])   != 0) return false;
    if (priv->xrt.xrtRunSetArg (priv->run, 5, (u32) priv->salt[2])   != 0) return false;
    if (priv->xrt.xrtRunSetArg (priv->run, 6, (u32) priv->salt[3])   != 0) return false;
    if (priv->xrt.xrtRunSetArg (priv->run, 7, (u32) priv->iter_count) != 0) return false;

    if (priv->xrt.xrtRunSetArg (priv->run, 8, (u32) bytes) != 0) return false;
  }

  if (priv->xrt.xrtRunStart (priv->run) != 0) return false;

  priv->batch_running = true;
  priv->batch_failed  = false;

  return true;
}

static const void *xrt_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  *bytes = 0;

  if (priv == NULL) return NULL;
  if (priv->batch_running == false) return NULL;

  if (priv->batch_taken == true) return NULL;

  const int state = priv->xrt.xrtRunWaitFor (priv->run, timeout_ms);

  if (state == HC_ERT_CMD_STATE_TIMEOUT)   return NULL;

  if (state == HC_ERT_CMD_STATE_RUNNING)   return NULL;
  if (state == HC_ERT_CMD_STATE_QUEUED)    return NULL;
  if (state == HC_ERT_CMD_STATE_SUBMITTED) return NULL;
  if (state == HC_ERT_CMD_STATE_NEW)       return NULL;

  if (state != HC_ERT_CMD_STATE_COMPLETED)
  {
    priv->batch_running    = false;
    priv->batch_failed     = true;
    priv->batch_fail_state = state;

    return NULL;
  }

  if (priv->xrt.xrtBOSync (priv->bo_out, HC_XCL_BO_SYNC_BO_FROM_DEVICE, priv->batch_in_bytes, 0) != 0)
  {
    priv->batch_running    = false;
    priv->batch_failed     = true;
    priv->batch_fail_state = state;

    return NULL;
  }

  priv->batch_taken = true;

  *bytes = priv->batch_in_bytes;

  return priv->map_out;
}

static bool xrt_batch_failed (fpga_dev_t *dev)
{
  const xrt_priv_t *priv = (const xrt_priv_t *) dev->priv;

  if (priv == NULL) return false;

  return priv->batch_failed;
}

static void xrt_batch_end (fpga_dev_t *dev)
{
  xrt_priv_t *priv = (xrt_priv_t *) dev->priv;

  if (priv == NULL) return;

  priv->batch_running = false;
  priv->batch_taken   = false;
}

const fpga_transport_t fpga_transport_xrt =
{
  .name    = "xrt",
  .bus     = "PCIe",
  .dialect = FPGA_DIALECT_HCFPGA,

  .enumerate = xrt_enumerate,
  .close     = xrt_close,
  .identify  = xrt_identify,

  .csr_read  = NULL,
  .csr_write = xrt_csr_write,

  .session_open    = xrt_session_open,
  .session_close   = xrt_session_close,
  .session_refresh = xrt_session_refresh,
  .out_capacity  = xrt_out_capacity,

  .batch_begin = xrt_batch_begin,
  .batch_send  = xrt_batch_send,
  .control     = NULL,
  .batch_recv  = xrt_batch_recv,
  .batch_end   = xrt_batch_end,
  .batch_done  = NULL,
  .batch_failed = xrt_batch_failed,

  .program = xrt_program,

  .temperature     = xrt_temperature,
  .temperature_all = NULL,

  .temperature_is_die = true,

  .temperature_abort = 90,

  .link_str        = NULL,
};

#else

static int xrt_enumerate_stub (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED fpga_dev_t *devs, MAYBE_UNUSED const int max, fpga_status_t *status)
{
  *status = FPGA_STATUS_UNSUPPORTED_OS;

  return 0;
}

static fpga_status_t xrt_identify_stub (MAYBE_UNUSED fpga_dev_t *dev) { return FPGA_STATUS_UNSUPPORTED_OS; }

static void xrt_close_stub (MAYBE_UNUSED fpga_dev_t *dev) { }

const fpga_transport_t fpga_transport_xrt =
{
  .name    = "xrt",
  .bus     = "PCIe",
  .dialect = FPGA_DIALECT_HCFPGA,

  .enumerate = xrt_enumerate_stub,
  .close     = xrt_close_stub,
  .identify  = xrt_identify_stub,
};

#endif
