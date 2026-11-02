/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "event.h"
#include "path.h"

#include "fpga/hcfpga.h"
#include "fpga/litepcie_abi.h"

#define CSR_CTRL_SCRATCH_DEFAULT  0x12345678

const fpga_csr_map_t fpga_csr_map_no_cpu =
{
  .name                    = "no-cpu",

  .base                    = FPGA_CSR_BASE_NO_CPU,
  .scratch                 = 0x0804,
  .identifier_mem          = 0x1000,

  .dma0_reader_loop_status = 0x2034,
  .dma0_writer_loop_status = 0x2014,

  .dna                     = 0x4800,
};

#define LITEPCIE_DMA_BUFFER_COUNT 256

#if defined (__linux__)

#include <poll.h>

typedef struct litepcie_priv
{
  u8    *tx;
  u8    *rx;

  size_t ring_size;

  bool   oneshot;

  u64    out_bytes;
  u64    out_sent;

  u64    in_bytes;
  u64    in_taken;

  u64    in_pos;

  bool   eob_seen;
  u32    eob_processed;

  u32    in_grain;
  u32    in_recs;

} litepcie_priv_t;

#endif

void fpga_report_supported (hashcat_ctx_t *hashcat_ctx, const char *want_algo, const char *want_board);

static bool fpga_running_installed (const folder_config_t *folder_config)
{
  if (folder_config == NULL)               return true;
  if (folder_config->install_dir == NULL)  return true;
  if (folder_config->shared_dir  == NULL)  return true;

  const bool installed = (strcmp (folder_config->install_dir, folder_config->shared_dir) != 0) ? true : false;

  return installed;
}

static const char *fpga_path_display (const folder_config_t *folder_config, const char *path, char *out, const size_t out_sz)
{
  if (path == NULL) return "?";

  if (fpga_running_installed (folder_config) == true) return path;

  const char *root = folder_config->install_dir;

  const size_t len = strlen (root);

  if (strncmp (path, root, len) != 0) return path;

  const char *rel = path + len;

  while (rel[0] == '/') rel++;

  if (rel[0] == 0) return path;

  snprintf (out, out_sz, "./%s", rel);

  return out;
}

static u32 fpga_shipped_dirs (const folder_config_t *folder_config, char out[2][FPGA_PATH_MAX])
{
  if (folder_config == NULL) return 0;

  u32 cnt = 0;

  if (folder_config->profile_dir)
  {
    snprintf (out[cnt], FPGA_PATH_MAX, "%s/%s", folder_config->profile_dir, FPGA_BITSTREAM_SUBDIR);

    cnt++;
  }

  if (folder_config->shared_dir)
  {
    char shared[FPGA_PATH_MAX];

    snprintf (shared, sizeof (shared), "%s/%s", folder_config->shared_dir, FPGA_BITSTREAM_SUBDIR);

    if ((cnt == 0) || (strcmp (shared, out[0]) != 0))
    {
      snprintf (out[cnt], FPGA_PATH_MAX, "%s", shared);

      cnt++;
    }
  }

  return cnt;
}

bool fpga_shipped_file (const folder_config_t *folder_config, const char *name, char *out, const size_t out_sz)
{
  char dirs[2][FPGA_PATH_MAX];

  const u32 dirs_cnt = fpga_shipped_dirs (folder_config, dirs);

  if (dirs_cnt == 0)
  {
    snprintf (out, out_sz, "%s", name);

    return false;
  }

  for (u32 i = 0; i < dirs_cnt; i++)
  {
    snprintf (out, out_sz, "%s/%s", dirs[i], name);

    if (hc_path_read (out) == true) return true;
  }

  snprintf (out, out_sz, "%s/%s", dirs[0], name);

  return false;
}

const char *fpga_doc_path (const hashcat_ctx_t *hashcat_ctx, char *out, const size_t out_sz)
{
  const folder_config_t *folder_config = (hashcat_ctx) ? hashcat_ctx->folder_config : NULL;

  if ((folder_config) && (folder_config->shared_dir))
  {
    char parent[FPGA_PATH_MAX];

    snprintf (parent, sizeof (parent), "%s", folder_config->shared_dir);

    char *cut = strrchr (parent, '/');

    if (cut)
    {
      cut[0] = 0;

      snprintf (out, out_sz, "%s/doc/hashcat/%s", parent, FPGA_DOC_RELPATH);

      if (hc_path_read (out) == true) return out;
    }

    snprintf (out, out_sz, "%s/%s", folder_config->shared_dir, FPGA_DOC_RELPATH);

    if (hc_path_read (out) == true) return out;
  }

  snprintf (out, out_sz, "%s", FPGA_DOC_RELPATH);

  return out;
}

const char *fpga_support_file (const hashcat_ctx_t *hashcat_ctx, const char *name, char *out, const size_t out_sz)
{
  const folder_config_t *folder_config = (hashcat_ctx) ? hashcat_ctx->folder_config : NULL;

  if ((folder_config) && (folder_config->shared_dir))
  {
    snprintf (out, out_sz, "%s/%s/%s", folder_config->shared_dir, FPGA_SUPPORT_SUBDIR, name);

    if (hc_path_read (out) == true) return out;
  }

  snprintf (out, out_sz, "%s/%s", FPGA_SUPPORT_SUBDIR, name);

  return out;
}

bool fpga_report_once (const fpga_board_t *info, const char *tag)
{
  #define FPGA_REPORTED_MAX 32

  typedef struct fpga_reported
  {
    const fpga_board_t *info;
    const char         *tag;

  } fpga_reported_t;

  static fpga_reported_t reported[FPGA_REPORTED_MAX];
  static u32             reported_cnt = 0;

  for (u32 i = 0; i < reported_cnt; i++)
  {
    if (reported[i].info != info) continue;
    if (strcmp (reported[i].tag, tag) != 0) continue;

    return false;
  }

  if (reported_cnt >= FPGA_REPORTED_MAX) return true;

  reported[reported_cnt].info = info;
  reported[reported_cnt].tag  = tag;

  reported_cnt++;

  return true;
}

void fpga_shipped_report_missing (hashcat_ctx_t *hashcat_ctx, const folder_config_t *folder_config, const char *const *names, const u32 names_cnt, const fpga_board_t *info)
{
  if (fpga_report_once (info, "shipped-file-missing") == false) return;

  const char *pretty = (info) ? info->pretty : "An FPGA board";

  event_log_error (hashcat_ctx, "FPGA bridge: %s requires an uninstalled design file and will not be used.", pretty);

  for (u32 i = 0; i < names_cnt; i++) event_log_info (hashcat_ctx, "  - Missing: %s", names[i]);

  char dirs[2][FPGA_PATH_MAX];

  const u32 dirs_cnt = fpga_shipped_dirs (folder_config, dirs);

  char shown[FPGA_PATH_MAX];

  for (u32 i = 0; i < dirs_cnt; i++) event_log_info (hashcat_ctx, "  - Path: %s/", fpga_path_display (folder_config, dirs[i], shown, sizeof (shown)));

  if (dirs_cnt == 0) event_log_info (hashcat_ctx, "  - Path: unavailable; hashcat could not resolve its data directories");

  event_log_info (hashcat_ctx, NULL);

  char doc[FPGA_PATH_MAX];

  fpga_doc_path (hashcat_ctx, doc, sizeof (doc));

  if ((info) && (info->doc_section))
  {
    event_log_info (hashcat_ctx, "  Installation instructions: \"%s\", section \"%s\"", fpga_path_display (folder_config, doc, shown, sizeof (shown)), info->doc_section);
  }
  else
  {
    event_log_info (hashcat_ctx, "  Installation instructions: \"%s\"", fpga_path_display (folder_config, doc, shown, sizeof (shown)));
  }

  event_log_info (hashcat_ctx, NULL);
}

#if defined (_WIN)

u64 fpga_now_ns (void)
{
  static LARGE_INTEGER freq;

  if (freq.QuadPart == 0) QueryPerformanceFrequency (&freq);

  LARGE_INTEGER now;

  QueryPerformanceCounter (&now);

  const u64 ns = (u64) ((now.QuadPart * 1000000000ull) / (u64) freq.QuadPart);

  return ns;
}

#else

u64 fpga_now_ns (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);

  const u64 ns = ((u64) ts.tv_sec * 1000000000ull) + (u64) ts.tv_nsec;

  return ns;
}

#endif

void fpga_timing_begin (fpga_timing_t *t)
{
  t->enabled  = (getenv ("HCFPGA_TIMING") != NULL);

  t->in_ns    = fpga_now_ns ();
  t->first_ns = 0;
  t->last_ns  = 0;
}

void fpga_timing_first (fpga_timing_t *t)
{
  if (t->enabled == false) return;
  if (t->first_ns != 0) return;

  t->first_ns = fpga_now_ns ();
}

void fpga_timing_last (fpga_timing_t *t)
{
  if (t->enabled == false) return;

  t->last_ns = fpga_now_ns ();
}

void fpga_timing_end (fpga_timing_t *t, const char *tag, const u64 recs, const u64 recv, const u64 pws_cnt)
{
  const u64 out_ns = fpga_now_ns ();

  if (t->enabled == true)
  {
    const double gap_outside = (t->exit_ns)  ? (double) (t->in_ns - t->exit_ns)   / 1e6 : 0.0;
    const double inside      =                 (double) (out_ns - t->in_ns)       / 1e6;
    const double first_frame = (t->first_ns) ? (double) (t->first_ns - t->in_ns)  / 1e6 : 0.0;
    const double last_frame  = (t->last_ns)  ? (double) (t->last_ns - t->in_ns)   / 1e6 : 0.0;

    fprintf (stderr, "[hcfpga] %s gap_outside=%.2fms inside=%.2fms first_frame=%.2fms last_frame=%.2fms recs=%" PRIu64 " recv=%" PRIu64 " pws=%" PRIu64 "\n", tag, gap_outside, inside, first_frame, last_frame, recs, recv, pws_cnt);
  }

  t->exit_ns = out_ns;
}

#define HCFPGA_C2H_FLAGS_OFF  30
#define HCFPGA_C2H_EOB_FLAG   0x8000u

bool hcfpga_c2h_scan_eob (const void *buf, const u64 bytes, const u32 rec_bytes, const u32 want, u32 *processed)
{
  if (buf == NULL) return false;

  if (rec_bytes < (HCFPGA_C2H_FLAGS_OFF + 2)) return false;

  const u8 *p = (const u8 *) buf;

  for (u64 off = 0; (off + rec_bytes) <= bytes; off += rec_bytes)
  {
    const u8 *r = &p[off];

    const u32 flags = (u32) r[HCFPGA_C2H_FLAGS_OFF + 0] | ((u32) r[HCFPGA_C2H_FLAGS_OFF + 1] << 8);

    if (flags != HCFPGA_C2H_EOB_FLAG) continue;

    const u32 got = (u32) r[0] | ((u32) r[1] << 8) | ((u32) r[2] << 16) | ((u32) r[3] << 24);

    if ((want != 0) && (got != want)) continue;

    if (processed != NULL) *processed = got;

    return true;
  }

  return false;
}

bool fpga_ident_parse (const char *raw, fpga_ident_t *ident)
{
  if (raw == NULL) return false;

  if (strncmp (raw, FPGA_IDENT_PREFIX, strlen (FPGA_IDENT_PREFIX)) != 0) return false;

  memset (ident, 0, sizeof (fpga_ident_t));

  strncpy (ident->raw, raw, FPGA_IDENT_MAX - 1);

  const char *p = strchr (raw, ';');

  while (p)
  {
    p++;

    const char *eq = strchr (p, '=');

    if (eq == NULL) break;

    const char *end = strchr (eq, ';');

    const size_t val_len = (end) ? (size_t) (end - eq - 1) : strlen (eq + 1);

    const size_t key_len = (size_t) (eq - p);

    if      ((key_len == 5) && (strncmp (p, "board", 5) == 0)) snprintf (ident->board, sizeof (ident->board), "%.*s", (int) val_len, eq + 1);
    else if ((key_len == 4) && (strncmp (p, "algo",  4) == 0)) snprintf (ident->algo,  sizeof (ident->algo),  "%.*s", (int) val_len, eq + 1);
    else if ((key_len == 5) && (strncmp (p, "build", 5) == 0)) snprintf (ident->build, sizeof (ident->build), "%.*s", (int) val_len, eq + 1);
    else if ((key_len == 2) && (strncmp (p, "sn",    2) == 0)) snprintf (ident->serial, sizeof (ident->serial), "%.*s", (int) val_len, eq + 1);
    else if ((key_len == 5) && (strncmp (p, "cores", 5) == 0)) ident->cores   = (u32) strtoul (eq + 1, NULL, 10);
    else if ((key_len == 3) && (strncmp (p, "clk",   3) == 0)) ident->clk_mhz = (u32) strtoul (eq + 1, NULL, 10);
    else if ((key_len == 1) && (strncmp (p, "n",     1) == 0)) ident->n       = (u32) strtoul (eq + 1, NULL, 10);
    else if ((key_len == 1) && (strncmp (p, "r",     1) == 0)) ident->r       = (u32) strtoul (eq + 1, NULL, 10);
    else if ((key_len == 3) && (strncmp (p, "abi",   3) == 0)) ident->abi     = (u32) strtoul (eq + 1, NULL, 10);

    p = end;
  }

  if (ident->algo[0] == 0) return false;

  return true;
}

static bool fpga_report_release (hashcat_ctx_t *hashcat_ctx, const fpga_ident_t *ident, const char *want_algo, const u32 want_n, const u32 want_r)
{
  if (ident == NULL) return false;

  const fpga_release_t *release = fpga_release_find (want_algo, ident->board, want_n, want_r);

  if (release == NULL) return false;

  fpga_bitstream_report_missing (hashcat_ctx, release);

  return true;
}

const fpga_ident_t *fpga_reject_worst_ident (const fpga_reject_t *rejects, const int rejects_cnt, const fpga_status_t status)
{
  for (int i = 0; i < rejects_cnt; i++)
  {
    if (rejects[i].status != status) continue;
    if (rejects[i].have_ident == false) continue;

    return &rejects[i].ident;
  }

  return NULL;
}

const char *fpga_reject_worst_transport (const fpga_reject_t *rejects, const int rejects_cnt, const fpga_status_t status)
{
  for (int i = 0; i < rejects_cnt; i++)
  {
    if (rejects[i].status != status) continue;

    return rejects[i].transport;
  }

  return NULL;
}

#define FPGA_CMD_MAX 192

static void fpga_headers_cmd (const char *want_algo, const char *board, char *buf, const size_t buf_sz)
{
  const char *algo = (want_algo) ? want_algo : "<algo>";

  if ((board) && (board[0] != 0))
  {
    snprintf (buf, buf_sz, "make -C src/fpga headers ALGO=%s BOARD=%s", algo, board);

    return;
  }

  snprintf (buf, buf_sz, "make -C src/fpga headers ALGO=%s BOARD=<the board= from that line>", algo);
}

static void fpga_foreign_fw_report (hashcat_ctx_t *hashcat_ctx, const char *who, const fpga_board_t *info)
{
  if (fpga_report_once (info, "foreign-firmware") == false) return;

  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  event_log_error (hashcat_ctx, "FPGA bridge: %s is running its factory firmware rather than a hashcat design and will not be used.", who);

  event_log_info (hashcat_ctx, "  - Program it with the bitstream for this board");
  event_log_info (hashcat_ctx, "  - Reboot so the host can enumerate the programmed endpoint");

  event_log_info (hashcat_ctx, NULL);

  char doc[FPGA_PATH_MAX];
  char shown[FPGA_PATH_MAX];

  fpga_doc_path (hashcat_ctx, doc, sizeof (doc));

  if ((info) && (info->doc_section))
  {
    event_log_info (hashcat_ctx, "  Installation instructions: \"%s\", section \"%s\"", fpga_path_display (folder_config, doc, shown, sizeof (shown)), info->doc_section);
  }
  else
  {
    event_log_info (hashcat_ctx, "  Installation instructions: \"%s\"", fpga_path_display (folder_config, doc, shown, sizeof (shown)));
  }

  event_log_info (hashcat_ctx, NULL);
}

static void fpga_reject_report_brief (hashcat_ctx_t *hashcat_ctx, const fpga_reject_t *reject, const char *want_algo, const int more, const char *more_paths)
{
  if (reject->status == FPGA_STATUS_OK) return;

  if (reject->status == FPGA_STATUS_NO_BITSTREAM)
  {
    const fpga_board_t *b = fpga_board_find (reject->ident.board);

    if ((b) && (b->prog == FPGA_PROG_HASHCAT)) return;
  }

  const fpga_board_t *info = fpga_board_find (reject->ident.board);

  char who[256];

  fpga_board_describe (info, &reject->ident, reject->path, who, sizeof (who));

  if (reject->status == FPGA_STATUS_FOREIGN_FW)
  {
    fpga_foreign_fw_report (hashcat_ctx, who, info);

    return;
  }

  const bool ours = (info != NULL) ? ((info->prog == FPGA_PROG_HASHCAT) ? true : false) : fpga_transport_programs (reject->transport);

  const char *why = "was refused for an unrecorded reason";
  const char *fix = NULL;

  char fix_buf[FPGA_PATH_MAX + 160];

  switch (reject->status)
  {
    case FPGA_STATUS_OK:               return;
    case FPGA_STATUS_UNSUPPORTED_OS:   why = "cannot be reached: this build has no FPGA transport"; break;
    case FPGA_STATUS_ALGO_UNAVAILABLE: why = "has no design for this algorithm and cannot get one"; break;
    case FPGA_STATUS_NO_PCI_DEVICE:    why = "is no longer present"; break;
    case FPGA_STATUS_IN_USE:           why = "is in use by another hashcat process"; break;

    case FPGA_STATUS_NO_RUNTIME:
      why = "is present but the userspace runtime it needs is not installed";
      fix = "install XRT, then confirm with: xrt-smi examine";
      break;

    case FPGA_STATUS_NO_CHAR_DEVICE:

      if (fpga_transport_is_usb (reject->transport) == true)
      {
        why = "is present but its JTAG interface could not be opened";
        fix = "close hw_server, the Vivado hardware manager or openFPGALoader, then run again";
        break;
      }

      why = "is present but its kernel driver is not loaded";
      fix = "sudo make -C src/fpga/driver dkms-install";
      break;

    case FPGA_STATUS_NO_PERMISSION:
    {
      why = "is present but this account cannot open it";

      const char *udev = ((info) && (info->udev)) ? info->udev : fpga_transport_udev (reject->transport);

      const bool is_usb = (info) ? (strcmp (info->bus, "USB") == 0) : fpga_transport_is_usb (reject->transport);

      if (udev)
      {
        char rule_path[FPGA_PATH_MAX];

        fpga_support_file (hashcat_ctx, udev, rule_path, sizeof (rule_path));

        snprintf (fix_buf, sizeof (fix_buf), "sudo cp %s /etc/udev/rules.d/%s", rule_path, (is_usb == true) ? " and replug the board" : ", then: sudo udevadm control --reload-rules && sudo udevadm trigger");

        fix = fix_buf;
      }
      break;
    }

    case FPGA_STATUS_CSR_WINDOW:
    {
      why = "answers in a different register window, so the driver was built for another design";

      char headers_cmd[FPGA_CMD_MAX];

      fpga_headers_cmd (want_algo, (reject->have_ident == true) ? reject->ident.board : NULL, headers_cmd, sizeof (headers_cmd));

      snprintf (fix_buf, sizeof (fix_buf), "%s && sudo make -C src/fpga/driver dkms-install", headers_cmd);

      fix = fix_buf;

      break;
    }

    case FPGA_STATUS_BAD_IDENT:
      why = (ours == true) ? "was programmed by hashcat and did not come up" : "is not running a hashcat design";
      fix = (ours == true) ? "run again with HCFPGA_DEBUG=1 to see which step failed" : NULL;
      break;

    case FPGA_STATUS_WRONG_ALGO:     why = "is running a different algorithm";  break;
    case FPGA_STATUS_ABI_MISMATCH:   why = "has a bitstream this build does not speak"; break;
    case FPGA_STATUS_NO_BITSTREAM:   why = "needs a design file that is not installed"; break;

    case FPGA_STATUS_FOREIGN_FW:
      why = "is still running the firmware it shipped with, not a hashcat design";
      break;
  }

  if ((reject->have_ident == true) && (reject->ident.algo[0] != 0) && (reject->status == FPGA_STATUS_WRONG_ALGO))
  {
    event_log_warning (hashcat_ctx, "FPGA bridge: %s %s ('%s'; this hash mode requires '%s') and will not be used.", who, why, reject->ident.algo, (want_algo) ? want_algo : "?");
  }
  else
  {
    event_log_warning (hashcat_ctx, "FPGA bridge: %s %s and will not be used.", who, why);
  }

  if (more > 0)
  {
    event_log_warning (hashcat_ctx, "             and %d more in the same state: %s", more, (more_paths) ? more_paths : "?");
  }

  if (fix) event_log_warning (hashcat_ctx, "             fix: %s", fix);

  if ((info) && (info->doc_section))
  {
    char doc[FPGA_PATH_MAX];
    char shown[FPGA_PATH_MAX];

    const folder_config_t *folder_config = (hashcat_ctx) ? hashcat_ctx->folder_config : NULL;

    fpga_doc_path (hashcat_ctx, doc, sizeof (doc));

    event_log_warning (hashcat_ctx, "             see %s, section \"%s\"", fpga_path_display (folder_config, doc, shown, sizeof (shown)), info->doc_section);
  }
}

static bool fpga_same_transport (const fpga_reject_t *a, const fpga_reject_t *b)
{
  if (a->transport == b->transport) return true;

  if (a->transport == NULL) return false;
  if (b->transport == NULL) return false;

  const bool same = (strcmp (a->transport, b->transport) == 0) ? true : false;

  return same;
}

void fpga_reject_report_all (hashcat_ctx_t *hashcat_ctx, const fpga_reject_t *rejects, const int rejects_cnt, const char *want_algo)
{
  bool done[FPGA_MAX_REJECTS];

  memset (done, 0, sizeof (done));

  const int cnt = MIN (rejects_cnt, FPGA_MAX_REJECTS);

  bool dup[FPGA_MAX_REJECTS];

  memset (dup, 0, sizeof (dup));

  for (int i = 0; i < cnt; i++)
  {
    if (dup[i] == true) continue;

    for (int j = i + 1; j < cnt; j++)
    {
      if (dup[j] == true) continue;
      if (rejects[j].bus_level != rejects[i].bus_level) continue;

      if (rejects[i].bus_level == true)
      {
        if (rejects[j].status != rejects[i].status) continue;
        if (fpga_transport_same_bus (rejects[i].transport, rejects[j].transport) == false) continue;
      }
      else
      {
        if (strcmp (rejects[i].path, rejects[j].path) != 0) continue;
      }

      dup[j] = true;
    }
  }

  for (int i = 0; i < cnt; i++)
  {
    if (done[i] == true) continue;
    if (dup[i]  == true) continue;

    done[i] = true;

    char more_paths[256];

    more_paths[0] = 0;

    size_t off = 0;

    bool cut = false;

    int more = 0;

    for (int j = i + 1; j < cnt; j++)
    {
      if (done[j] == true) continue;
      if (dup[j]  == true) continue;
      if (rejects[j].status != rejects[i].status) continue;
      if (strcmp (rejects[j].ident.board, rejects[i].ident.board) != 0) continue;
      if (fpga_same_transport (&rejects[j], &rejects[i]) == false) continue;

      done[j] = true;

      more++;

      if (cut == true) continue;

      if ((off + strlen (rejects[j].path) + 6) >= sizeof (more_paths))
      {
        snprintf (more_paths + off, sizeof (more_paths) - off, " ...");

        cut = true;

        continue;
      }

      off += (size_t) snprintf (more_paths + off, sizeof (more_paths) - off, "%s%s", (off == 0) ? "" : ", ", rejects[j].path);
    }

    fpga_reject_report_brief (hashcat_ctx, &rejects[i], want_algo, more, more_paths);
  }
}

void fpga_status_report (hashcat_ctx_t *hashcat_ctx, const fpga_status_t status, const char *want_algo, const u32 want_n, const u32 want_r, const fpga_ident_t *ident, const char *transport)
{
  const fpga_board_t *board_info = (ident) ? fpga_board_find (ident->board) : NULL;

  const bool usb = (board_info) ? (strcmp (board_info->bus, "USB") == 0) : fpga_transport_is_usb (transport);

  char headers_cmd[FPGA_CMD_MAX];

  switch (status)
  {
    case FPGA_STATUS_OK:
      return;

    case FPGA_STATUS_UNSUPPORTED_OS:
      event_log_error (hashcat_ctx, "FPGA bridge: this build has no FPGA transport (Linux only).");
      break;

    case FPGA_STATUS_IN_USE:
      event_log_error (hashcat_ctx, "FPGA bridge: no board is usable, and at least one is in use by another hashcat process.");
      event_log_info (hashcat_ctx, "A board is driven by one process at a time. Wait for the other run to end, or start");
      event_log_info (hashcat_ctx, "that run with -d so that it leaves the boards out that this one should use.");
      break;

    case FPGA_STATUS_NO_RUNTIME:
      event_log_error (hashcat_ctx, "FPGA bridge: the only card found needs a runtime that is not installed.");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "An Alveo is programmed by hashcat itself at every run, so there is no bitstream to");
      event_log_info (hashcat_ctx, "install and no kernel driver of ours to build. What is missing is AMD's XRT runtime.");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "  1. install XRT and its xocl/xclmgmt drivers, see 'Installing XRT' in the guide");
      event_log_info (hashcat_ctx, "  2. confirm it sees the card               xrt-smi examine");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "If XRT is installed somewhere unusual, point XILINX_XRT at its root. Do NOT put XRT's");
      event_log_info (hashcat_ctx, "library directory on LD_LIBRARY_PATH: it ships copies of system libraries and shadowing");
      event_log_info (hashcat_ctx, "them breaks unrelated programs.");
      event_log_info (hashcat_ctx, NULL);
      break;

    case FPGA_STATUS_NO_PCI_DEVICE:
      event_log_error (hashcat_ctx, "FPGA bridge: no Xilinx PCIe device found.");
      event_log_info (hashcat_ctx, "No programmed FPGA endpoint was detected. Load a design before starting hashcat.");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "Initial setup sequence:");

      char seq_rule_path[FPGA_PATH_MAX];

      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "  1. get a bitstream for your board   %s/", FPGA_BITSTREAM_URL_BASE);
      event_log_info (hashcat_ctx, "  2. program the card                 openFPGALoader over JTAG, or SD card boot");
      event_log_info (hashcat_ctx, "  3. reboot the host                  the PCIe endpoint only appears after one");
      event_log_info (hashcat_ctx, "  4. build and load the driver        sudo make -C src/fpga/driver dkms-install");
      event_log_info (hashcat_ctx, "  5. allow your user to open it       sudo cp %s /etc/udev/rules.d/", fpga_support_file (hashcat_ctx, "99-litepcie.rules", seq_rule_path, sizeof (seq_rule_path)));
      event_log_info (hashcat_ctx, "                                      sudo udevadm control --reload-rules");
      event_log_info (hashcat_ctx, "                                      sudo usermod -aG plugdev $USER   (then log out and back in)");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "Step 5 prevents the device node from remaining accessible only to root.");
      event_log_info (hashcat_ctx, NULL);

      fpga_report_supported (hashcat_ctx, want_algo, NULL);
      break;

    case FPGA_STATUS_NO_CHAR_DEVICE:
      if (usb == true)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: the USB board was found, but its JTAG interface could not be opened.");
        event_log_info (hashcat_ctx, "Another program may hold it. Close hw_server, the Vivado hardware manager or");
        event_log_info (hashcat_ctx, "openFPGALoader, then run again. HCFPGA_DEBUG=1 shows what the scan found.");
        break;
      }

      event_log_error (hashcat_ctx, "FPGA bridge: Xilinx PCIe device present, but no /dev/litepcie* node.");
      event_log_info (hashcat_ctx, "The FPGA endpoint is present, but the LitePCIe kernel driver is not loaded:");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "  sudo apt install dkms linux-headers-$(uname -r)");
      event_log_info (hashcat_ctx, "  sudo make -C src/fpga/driver dkms-install");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "dkms rebuilds it automatically on kernel upgrades, and on Debian and Ubuntu it");
      event_log_info (hashcat_ctx, "signs it with your enrolled MOK, which is what Secure Boot needs. Without that");
      event_log_info (hashcat_ctx, "signature loading fails with 'Key was rejected by service'.");
      break;

    case FPGA_STATUS_CSR_WINDOW:
      event_log_error (hashcat_ctx, "FPGA bridge: the card answers, but not in the register window '%s' needs.", want_algo);

      event_log_info (hashcat_ctx, "Designs come in two shapes. One carries a soft CPU, because LiteDRAM needs it,");
      event_log_info (hashcat_ctx, "and its registers live at 0xf0000000. One does not, and its registers live at 0.");
      event_log_info (hashcat_ctx, "The driver is built for whichever shape it was generated against, and it refused");
      event_log_info (hashcat_ctx, "this address as outside the card's memory window.");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "The card may be running a different design. Check the reported identity before reprogramming:");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "  sudo dmesg | grep 'Version hcfpga'");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "If that names the algorithm you wanted, the driver is the mismatched half and");
      event_log_info (hashcat_ctx, "needs rebuilding for this design:");
      event_log_info (hashcat_ctx, NULL);

      fpga_headers_cmd (want_algo, NULL, headers_cmd, sizeof (headers_cmd));

      event_log_info (hashcat_ctx, "  %s", headers_cmd);
      event_log_info (hashcat_ctx, "  sudo make -C src/fpga/driver dkms-install");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "If it names a different one, program the bitstream you actually want.");
      break;

    case FPGA_STATUS_NO_PERMISSION:
    {
      char rule_path[FPGA_PATH_MAX];

      if (usb == true)
      {
        const char *udev = fpga_transport_udev (transport);

        if (udev == NULL) udev = "99-ztex.rules";

        const bool ztex = (strcmp (udev, "99-ztex.rules") == 0) ? true : false;

        event_log_error (hashcat_ctx, "FPGA bridge: the %s board was found but cannot be opened (permission denied).", (ztex == true) ? "ZTEX" : "USB");
        event_log_info (hashcat_ctx, "A USB device remains root-only until a udev rule grants access:");
        event_log_info (hashcat_ctx, NULL);
        event_log_info (hashcat_ctx, "  sudo cp %s /etc/udev/rules.d/", fpga_support_file (hashcat_ctx, udev, rule_path, sizeof (rule_path)));
        event_log_info (hashcat_ctx, "  sudo udevadm control --reload-rules");
        event_log_info (hashcat_ctx, "  sudo udevadm trigger --subsystem-match=usb --action=add");
        event_log_info (hashcat_ctx, "  sudo usermod -aG plugdev $USER      # log out and back in");
        event_log_info (hashcat_ctx, NULL);

        if (ztex == true)
        {
          event_log_info (hashcat_ctx, "The rule matches only the vendor ID because programming changes the product ID and product string.");
          event_log_info (hashcat_ctx, NULL);
        }

        event_log_info (hashcat_ctx, "Reconnect the board instead of running the trigger command if preferred.");
        break;
      }

      event_log_error (hashcat_ctx, "FPGA bridge: /dev/litepcie* exists but cannot be opened (permission denied).");
      event_log_info (hashcat_ctx, "  sudo cp %s /etc/udev/rules.d/", fpga_support_file (hashcat_ctx, "99-litepcie.rules", rule_path, sizeof (rule_path)));
      event_log_info (hashcat_ctx, "  sudo udevadm control --reload-rules");
      event_log_info (hashcat_ctx, "  sudo udevadm trigger --name-match=/dev/litepcie0");
      event_log_info (hashcat_ctx, "  sudo usermod -aG plugdev $USER");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "The 'trigger' line matters: reloading the rules does not re-apply them to a node");
      event_log_info (hashcat_ctx, "that already exists, and this one was created when the driver loaded. Without it");
      event_log_info (hashcat_ctx, "the node stays root-only and you will see this same message again.");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "Then check 'id -nG' lists plugdev, logging out and back in if it does not.");
      event_log_info (hashcat_ctx, "Running as root bypasses this check; install the udev rule for normal user access.");
      break;
    }

    case FPGA_STATUS_NO_BITSTREAM:

      return;

    case FPGA_STATUS_ALGO_UNAVAILABLE:
      event_log_error (hashcat_ctx, "FPGA bridge: no '%s' design is available for this board.", (want_algo) ? want_algo : "?");
      event_log_info (hashcat_ctx, "The board is operational, but this algorithm is unsupported on its hardware.");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "A ZTEX 1.15y carries four Spartan-6 FPGAs and no DRAM at all. A memory hard hash keeps a 16 MB");
      event_log_info (hashcat_ctx, "scratchpad per job, so the part is the wrong shape for it even before the question of");
      event_log_info (hashcat_ctx, "building one comes up, and no toolchain we have targets a Spartan-6 anyway.");
      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, "Use another device for this hash mode. The board remains available for supported modes.");
      event_log_info (hashcat_ctx, NULL);

      fpga_report_supported (hashcat_ctx, want_algo, (ident) ? ident->board : NULL);
      break;

    case FPGA_STATUS_BAD_IDENT:

      if ((transport != NULL) && (strcmp (transport, "artyz7") == 0))
      {
        event_log_error (hashcat_ctx, "FPGA bridge: hashcat could not load the Arty Z7.");
        event_log_info (hashcat_ctx, "Check that the JP4 boot jumper is set to JTAG, then press the board's PS_SRST");
        event_log_info (hashcat_ctx, "button or power-cycle it, and run again. HCFPGA_DEBUG=1 shows which load step failed.");
        break;
      }

      if (usb == true)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: the board was programmed but did not come up.");
        event_log_info (hashcat_ctx, "The design upload completed, but the fabric did not respond afterward.");
        event_log_info (hashcat_ctx, NULL);
        event_log_info (hashcat_ctx, "Physically power-cycle the ZTEX board. Its firmware survives USB and host resets,");
        event_log_info (hashcat_ctx, "so neither a reboot nor another firmware upload clears this state.");
        break;
      }

      event_log_error (hashcat_ctx, "FPGA bridge: device responds, but is not running a hashcat FPGA design.");

      event_log_info (hashcat_ctx, "The card may be running another LiteX bitstream, or the driver may target a");
      event_log_info (hashcat_ctx, "different algorithm. The identity is read through the driver's register map,");
      event_log_info (hashcat_ctx, "so this check cannot distinguish the two causes.");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "If you just changed the bitstream, finish the switch:");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "  sudo dmesg | grep 'Version hcfpga'      # this names the board");

      fpga_headers_cmd (want_algo, (ident) ? ident->board : NULL, headers_cmd, sizeof (headers_cmd));

      event_log_info (hashcat_ctx, "  %s", headers_cmd);
      event_log_info (hashcat_ctx, "  sudo make -C src/fpga/driver dkms-install");
      event_log_info (hashcat_ctx, NULL);

      event_log_info (hashcat_ctx, "Otherwise program the hashcat bitstream for your board and reboot.");
      break;

    case FPGA_STATUS_WRONG_ALGO:
      event_log_error (hashcat_ctx, "FPGA bridge: device is running a hashcat design for a different algorithm.");

      if (ident) event_log_info (hashcat_ctx, "  device..: %s, %u cores at %u MHz, running '%s'", ident->board, ident->cores, ident->clk_mhz, ident->algo);

      event_log_info (hashcat_ctx, "  needed..: a '%s' bitstream for this board", (want_algo) ? want_algo : "?");

      event_log_info (hashcat_ctx, NULL);

      if (fpga_report_release (hashcat_ctx, ident, want_algo, want_n, want_r) == true) return;

      break;

    case FPGA_STATUS_ABI_MISMATCH:
      event_log_error (hashcat_ctx, "FPGA bridge: bitstream ABI does not match this hashcat build.");

      if (ident) event_log_info (hashcat_ctx, "  device..: %s, running '%s' at ABI %u", ident->board, ident->algo, ident->abi);

      event_log_info (hashcat_ctx, "  needed..: ABI %d", FPGA_ABI_CURRENT);

      event_log_info (hashcat_ctx, NULL);

      if (fpga_report_release (hashcat_ctx, ident, want_algo, want_n, want_r) == true) return;

      event_log_info (hashcat_ctx, "Update the bitstream, or update hashcat.");

      break;

    case FPGA_STATUS_FOREIGN_FW:

      event_log_info (hashcat_ctx, "A card programmed since the last boot keeps its factory PCIe identity until the host reboots.");

      break;
  }

  event_log_info (hashcat_ctx, NULL);

  char doc_path[FPGA_PATH_MAX];
  char doc_shown[FPGA_PATH_MAX];

  fpga_doc_path (hashcat_ctx, doc_path, sizeof (doc_path));

  event_log_info (hashcat_ctx, "For the full setup procedure, see %s", fpga_path_display (hashcat_ctx->folder_config, doc_path, doc_shown, sizeof (doc_shown)));

  event_log_info (hashcat_ctx, NULL);
}

#define FPGA_BOARD(b,p,u,g,r,d) { b, p, u, g, r, d },

static const fpga_board_t FPGA_BOARDS[] =
{
  #include "fpga/fpga_boards.def"
};

#undef FPGA_BOARD

const fpga_board_t *fpga_board_find (const char *board)
{
  if (board == NULL)   return NULL;
  if (board[0] == 0)   return NULL;

  const size_t cnt = sizeof (FPGA_BOARDS) / sizeof (FPGA_BOARDS[0]);

  for (size_t i = 0; i < cnt; i++)
  {
    if (strcmp (FPGA_BOARDS[i].board, board) != 0) continue;

    return &FPGA_BOARDS[i];
  }

  return NULL;
}

const char *fpga_board_describe (const fpga_board_t *info, const fpga_ident_t *ident, const char *path, char *buf, const size_t len)
{
  const char *name = (info) ? info->pretty : NULL;

  if (name == NULL) name = "an unidentified board";

  const char *bus = (info) ? info->bus : NULL;

  const char *serial = ((ident) && (ident->serial[0] != 0)) ? ident->serial : NULL;

  if (bus == NULL)
  {
    snprintf (buf, len, "%s (%s)", name, (path) ? path : "?");
  }
  else if (serial == NULL)
  {
    snprintf (buf, len, "%s (%s %s)", name, bus, (path) ? path : "?");
  }
  else
  {
    snprintf (buf, len, "%s (%s %s, serial %s)", name, bus, (path) ? path : "?", serial);
  }

  return buf;
}

#define FPGA_RELEASE(a,b,n,r,e,d,s) { a, b, n, r, e, d, s },

static const fpga_release_t FPGA_RELEASES[] =
{
  #include "fpga/fpga_releases.def"
};

#undef FPGA_RELEASE

static int fpga_release_basename (const fpga_release_t *release, char *out, const size_t out_size)
{
  if ((release->n == 0) && (release->r == 0))
  {
    const int len = snprintf (out, out_size, "%s-%s", release->algo, release->board);

    return len;
  }

  const int len = snprintf (out, out_size, "%s-%s-n%u-r%u", release->algo, release->board, release->n, release->r);

  return len;
}

bool fpga_release_filename (const fpga_release_t *release, char *out, const size_t out_sz)
{
  if (release == NULL) return false;

  if (release->dist != FPGA_DIST_PUBLISHED) return false;

  char base[FPGA_PATH_MAX];

  if (fpga_release_basename (release, base, sizeof (base)) < 0) return false;

  snprintf (out, out_sz, "%s.%s", base, release->ext);

  return true;
}

void fpga_report_supported (hashcat_ctx_t *hashcat_ctx, const char *want_algo, const char *want_board)
{
  const size_t cnt = sizeof (FPGA_RELEASES) / sizeof (FPGA_RELEASES[0]);

  if ((want_algo) && (want_board)) event_log_info (hashcat_ctx, "Published bitstreams for '%s':", want_algo);
  else if (want_algo)              event_log_info (hashcat_ctx, "Published bitstreams for '%s'. No board was identified, so pick the one you own:", want_algo);
  else                             event_log_info (hashcat_ctx, "Published bitstreams:");

  event_log_info (hashcat_ctx, NULL);

  for (size_t i = 0; i < cnt; i++)
  {
    const fpga_release_t *rel = &FPGA_RELEASES[i];

    char name[FPGA_PATH_MAX];

    if (rel->dist == FPGA_DIST_PUBLISHED)
    {
      if (fpga_release_basename (rel, name, sizeof (name)) < 0) continue;
    }
    else
    {
      snprintf (name, sizeof (name), "%s: see %s/%s/", rel->board, FPGA_BITSTREAM_URL_BASE, rel->subdir);
    }

    const bool mine = ((want_board) && (strcmp (rel->board, want_board) == 0));

    event_log_info (hashcat_ctx, "  %-28s %s", name, (mine == true) ? "<- your board" : "");
  }

  event_log_info (hashcat_ctx, NULL);

  event_log_info (hashcat_ctx, NULL);
}

const fpga_release_t *fpga_release_find (const char *algo, const char *board, const u32 n, const u32 r)
{
  if (algo == NULL) return NULL;

  if (board == NULL) return NULL;

  const size_t cnt = sizeof (FPGA_RELEASES) / sizeof (FPGA_RELEASES[0]);

  for (size_t i = 0; i < cnt; i++)
  {
    if (strcmp (FPGA_RELEASES[i].algo, algo) != 0) continue;

    if (strcmp (FPGA_RELEASES[i].board, board) != 0) continue;

    if (FPGA_RELEASES[i].n != n) continue;

    if (FPGA_RELEASES[i].r != r) continue;

    return &FPGA_RELEASES[i];
  }

  return NULL;
}

void fpga_bitstream_report_missing (hashcat_ctx_t *hashcat_ctx, const fpga_release_t *release)
{
  char base[FPGA_PATH_MAX];

  if (fpga_release_basename (release, base, sizeof (base)) < 0) return;

  const folder_config_t *folder_config = (hashcat_ctx) ? hashcat_ctx->folder_config : NULL;

  const fpga_board_t *info = fpga_board_find (release->board);

  const bool ours = ((info) && (info->prog == FPGA_PROG_HASHCAT)) ? true : false;

  if (ours == true)
  {
    event_log_info (hashcat_ctx, "hashcat opens this file itself at every run, and only looks for it in its own");
    event_log_info (hashcat_ctx, "data directories:");

    char dirs[2][FPGA_PATH_MAX];

    const u32 dirs_cnt = fpga_shipped_dirs (folder_config, dirs);

    char shown[FPGA_PATH_MAX];

    for (u32 i = 0; i < dirs_cnt; i++) event_log_info (hashcat_ctx, "  - Path: %s/", fpga_path_display (folder_config, dirs[i], shown, sizeof (shown)));

    if (dirs_cnt == 0) event_log_info (hashcat_ctx, "  - Path: unavailable; hashcat could not resolve its data directories");

    event_log_info (hashcat_ctx, NULL);
    event_log_info (hashcat_ctx, "Fetch it, then move the uncompressed file into one of them.");
  }
  else
  {
    event_log_info (hashcat_ctx, "hashcat does not download or open bitstreams for manually programmed cards.");
    event_log_info (hashcat_ctx, "Store the file at any convenient path and pass it to the board programmer.");
  }

  event_log_info (hashcat_ctx, NULL);

  if (release->dist == FPGA_DIST_PUBLISHED)
  {
    event_log_info (hashcat_ctx, "  curl -o %s.%s.xz %s/%s/%s.%s.xz", base, release->ext, FPGA_BITSTREAM_URL_BASE, release->subdir, base, release->ext);
    event_log_info (hashcat_ctx, "  xz -d %s.%s.xz", base, release->ext);
  }
  else
  {
    event_log_info (hashcat_ctx, "  see %s/%s/", FPGA_BITSTREAM_URL_BASE, release->subdir);
  }
  event_log_info (hashcat_ctx, NULL);

  event_log_info (hashcat_ctx, "%s/manifest.json lists the SHA-256 digest of every published bitstream.", FPGA_BITSTREAM_URL_BASE);
  event_log_info (hashcat_ctx, "Verify the file before programming. At runtime, hashcat validates the identity reported by the design.");
  event_log_info (hashcat_ctx, NULL);

  char doc_path[FPGA_PATH_MAX];
  char doc_shown[FPGA_PATH_MAX];

  fpga_doc_path (hashcat_ctx, doc_path, sizeof (doc_path));

  event_log_info (hashcat_ctx, "Programming is board specific, so for that step see %s", fpga_path_display (folder_config, doc_path, doc_shown, sizeof (doc_shown)));

  event_log_info (hashcat_ctx, NULL);
}

#if defined (__linux__)

static bool pci_device_present (void)
{
  DIR *dir = opendir ("/sys/bus/pci/devices");

  if (dir == NULL) return false;

  bool found = false;

  struct dirent *entry = NULL;

  while ((entry = readdir (dir)) != NULL)
  {
    if (entry->d_name[0] == '.') continue;

    char path[FPGA_PATH_MAX];

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);

    FILE *fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int vendor = 0;

    const int rc = fscanf (fp, "0x%x", &vendor);

    fclose (fp);

    if (rc != 1) continue;

    if (vendor != PCIE_XILINX_VENDOR_ID) continue;

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/class", entry->d_name);

    fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int class_code = 0;

    const int rc_class = fscanf (fp, "0x%x", &class_code);

    fclose (fp);

    if (rc_class != 1) continue;

    if ((class_code >> 8) != PCIE_HCFPGA_CLASS) continue;

    found = true;

    break;
  }

  closedir (dir);

  return found;
}

typedef struct fpga_foreign_fw
{
  u32         device_id;
  const char *board;
  const char *running;

} fpga_foreign_fw_t;

static const fpga_foreign_fw_t FPGA_FOREIGN_FW[] =
{
  { 0x0666, "enigmax1", "the PCILeech firmware it shipped with" },
};

static void pci_foreign_fw_scan (fpga_reject_t *rejects, int *rejects_cnt)
{
  DIR *dir = opendir ("/sys/bus/pci/devices");

  if (dir == NULL) return;

  struct dirent *entry = NULL;

  while ((entry = readdir (dir)) != NULL)
  {
    if (entry->d_name[0] == '.') continue;
    if (*rejects_cnt >= FPGA_MAX_REJECTS) break;

    char path[FPGA_PATH_MAX];

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);

    FILE *fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int vendor = 0;

    const int rc = fscanf (fp, "0x%x", &vendor);

    fclose (fp);

    if (rc != 1) continue;
    if (vendor != PCIE_XILINX_VENDOR_ID) continue;

    snprintf (path, sizeof (path), "/sys/bus/pci/devices/%s/device", entry->d_name);

    fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int device_id = 0;

    const int rc_dev = fscanf (fp, "0x%x", &device_id);

    fclose (fp);

    if (rc_dev != 1) continue;

    const size_t cnt = sizeof (FPGA_FOREIGN_FW) / sizeof (FPGA_FOREIGN_FW[0]);

    for (size_t i = 0; i < cnt; i++)
    {
      if (FPGA_FOREIGN_FW[i].device_id != device_id) continue;

      fpga_reject_t *reject = &rejects[*rejects_cnt];

      memset (reject, 0, sizeof (fpga_reject_t));

      snprintf (reject->path, sizeof (reject->path), "%s", entry->d_name);

      snprintf (reject->ident.board, sizeof (reject->ident.board), "%s", FPGA_FOREIGN_FW[i].board);

      reject->transport  = "litepcie";
      reject->status     = FPGA_STATUS_FOREIGN_FW;
      reject->have_ident = false;

      (*rejects_cnt)++;

      break;
    }
  }

  closedir (dir);
}

static u32 litepcie_csr_read (fpga_dev_t *dev, const u32 addr)
{
  struct litepcie_ioctl_reg m;

  memset (&m, 0, sizeof (m));

  m.addr     = dev->csr_base + addr;
  m.val      = 0;
  m.is_write = 0;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_REG, &m) < 0) return 0;

  return m.val;
}

static bool litepcie_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  struct litepcie_ioctl_reg m;

  memset (&m, 0, sizeof (m));

  m.addr     = dev->csr_base + addr;
  m.val      = val;
  m.is_write = 1;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_REG, &m) < 0) return false;

  return true;
}

static bool litepcie_csr_probe (fpga_dev_t *dev, const u32 addr, u32 *val)
{
  struct litepcie_ioctl_reg m;

  memset (&m, 0, sizeof (m));

  m.addr     = dev->csr_base + addr;
  m.val      = 0;
  m.is_write = 0;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_REG, &m) < 0) return false;

  *val = m.val;

  return true;
}

static fpga_status_t litepcie_identify (fpga_dev_t *dev)
{
  u32 scratch = 0;

  if (litepcie_csr_probe (dev, dev->map->scratch, &scratch) == false) return FPGA_STATUS_CSR_WINDOW;

  if (scratch != CSR_CTRL_SCRATCH_DEFAULT) return FPGA_STATUS_BAD_IDENT;

  char raw[FPGA_IDENT_MAX];

  u32 i = 0;

  for (i = 0; i < (FPGA_IDENT_MAX - 1); i++)
  {
    const u32 c = litepcie_csr_read (dev, dev->map->identifier_mem + (4 * i)) & 0xff;

    if (c == 0) break;

    raw[i] = (char) c;
  }

  raw[i] = 0;

  if (fpga_ident_parse (raw, &dev->ident) == false) return FPGA_STATUS_BAD_IDENT;

  const u64 dna_lo = litepcie_csr_read (dev, dev->map->dna + 4);
  const u64 dna_hi = litepcie_csr_read (dev, dev->map->dna + 0);

  const u64 dna = ((dna_hi << 32) | dna_lo) & 0x01ffffffffffffffULL;

  if ((dna != 0) && (dna != 0x01ffffffffffffffULL))
  {
    snprintf (dev->ident.serial, sizeof (dev->ident.serial), "%014" PRIx64, dna);
  }

  return FPGA_STATUS_OK;
}

static bool litepcie_map_rings (fpga_dev_t *dev)
{
  struct litepcie_ioctl_mmap_dma_info info;

  memset (&info, 0, sizeof (info));

  if (ioctl (dev->fd, LITEPCIE_IOCTL_MMAP_DMA_INFO, &info) < 0) return false;

  if (info.dma_rx_buf_size != LITEPCIE_DMA_BUFFER_SIZE_EXPECTED) return false;
  if (info.dma_tx_buf_size != LITEPCIE_DMA_BUFFER_SIZE_EXPECTED) return false;

  if (info.dma_rx_buf_count != LITEPCIE_DMA_BUFFER_COUNT) return false;
  if (info.dma_tx_buf_count != LITEPCIE_DMA_BUFFER_COUNT) return false;

  const size_t ring_size = (size_t) info.dma_tx_buf_size * info.dma_tx_buf_count;

  u8 *tx = mmap (NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, (off_t) info.dma_tx_buf_offset);

  if (tx == MAP_FAILED) return false;

  u8 *rx = mmap (NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, (off_t) info.dma_rx_buf_offset);

  if (rx == MAP_FAILED)
  {
    munmap (tx, ring_size);

    return false;
  }

  litepcie_priv_t *priv = (litepcie_priv_t *) hcmalloc (sizeof (litepcie_priv_t));

  if (priv == NULL)
  {
    munmap (tx, ring_size);
    munmap (rx, ring_size);

    return false;
  }

  priv->tx        = tx;
  priv->rx        = rx;
  priv->ring_size = ring_size;

  dev->priv = priv;

  return true;
}

static void litepcie_close (fpga_dev_t *dev)
{
  litepcie_priv_t *priv = dev->priv;

  if (priv)
  {
    munmap (priv->tx, priv->ring_size);
    munmap (priv->rx, priv->ring_size);

    hcfree (priv);

    dev->priv = NULL;
  }

  if (dev->fd >= 0)
  {
    close (dev->fd);

    dev->fd = -1;
  }
}

static int litepcie_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  int cnt = 0;

  bool saw_node       = false;
  bool saw_permission = false;

  for (int i = 0; i < FPGA_MAX_DEVICES; i++)
  {
    if (cnt >= max) break;

    char path[FPGA_PATH_MAX];

    snprintf (path, sizeof (path), "/dev/litepcie%d", i);

    if (hc_path_exist (path) == false) continue;

    saw_node = true;

    const int fd = open (path, O_RDWR);

    if (fd < 0)
    {
      if (errno == EACCES) saw_permission = true;

      continue;
    }

    fpga_dev_t *dev = &devs[cnt];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->path, sizeof (dev->path), "%s", path);

    dev->fd = fd;

    if (litepcie_map_rings (dev) == false)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: %s did not hand over its DMA rings.", path);
      event_log_info (hashcat_ctx, "The driver was built with a DMA geometry this hashcat does not expect. Rebuild it:");
      event_log_info (hashcat_ctx, "  sudo make -C src/fpga/driver dkms-install");

      litepcie_close (dev);

      continue;
    }

    cnt++;
  }

  if (cnt == 0)
  {
    if (saw_permission == true)
    {
      *status = FPGA_STATUS_NO_PERMISSION;
    }
    else if (saw_node == true)
    {
      *status = FPGA_STATUS_BAD_IDENT;
    }
    else if (pci_device_present () == true)
    {
      *status = FPGA_STATUS_NO_CHAR_DEVICE;
    }
    else
    {
      *status = FPGA_STATUS_NO_PCI_DEVICE;
    }
  }

  return cnt;
}

static bool litepcie_dma_claim (fpga_dev_t *dev)
{
  struct litepcie_ioctl_lock lock;

  memset (&lock, 0, sizeof (lock));

  lock.dma_reader_request = 1;
  lock.dma_writer_request = 1;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_LOCK, &lock) < 0) return false;

  if (lock.dma_reader_status == 0) return false;
  if (lock.dma_writer_status == 0) return false;

  struct litepcie_ioctl_dma dma;

  memset (&dma, 0, sizeof (dma));

  dma.loopback_enable = 0;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_DMA, &dma) < 0) return false;

  return true;
}

static bool litepcie_dma_set_oneshot (fpga_dev_t *dev, const bool enable)
{
  struct litepcie_ioctl_dma_oneshot m;

  memset (&m, 0, sizeof (m));

  m.enable = (enable == true) ? 1 : 0;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_DMA_ONESHOT, &m) < 0) return false;

  litepcie_priv_t *priv = dev->priv;

  priv->oneshot = enable;

  return true;
}

static bool litepcie_dma_arm (fpga_dev_t *dev, const bool is_writer, const u32 count, const u32 last_length)
{
  struct litepcie_ioctl_dma_arm m;

  memset (&m, 0, sizeof (m));

  m.count       = count;
  m.last_length = last_length;

  const unsigned long req = (is_writer == true) ? LITEPCIE_IOCTL_DMA_WRITER_ARM : LITEPCIE_IOCTL_DMA_READER_ARM;

  if (ioctl (dev->fd, req, &m) < 0) return false;

  return true;
}

static bool litepcie_wait_in (fpga_dev_t *dev, const u32 timeout_ms)
{
  struct pollfd pfd;

  pfd.fd      = dev->fd;
  pfd.events  = POLLIN;
  pfd.revents = 0;

  const int rc = poll (&pfd, 1, (int) timeout_ms);

  if (rc <= 0) return false;

  if ((pfd.revents & POLLIN) == 0) return false;

  return true;
}

static bool litepcie_dma_enable (fpga_dev_t *dev)
{
  struct litepcie_ioctl_dma_writer wr;

  memset (&wr, 0, sizeof (wr));

  wr.enable = 1;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_DMA_WRITER, &wr) < 0) return false;

  struct litepcie_ioctl_dma_reader rd;

  memset (&rd, 0, sizeof (rd));

  rd.enable = 1;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_DMA_READER, &rd) < 0) return false;

  return true;
}

static void litepcie_dma_release (fpga_dev_t *dev)
{
  struct litepcie_ioctl_dma_writer wr;

  memset (&wr, 0, sizeof (wr));

  ioctl (dev->fd, LITEPCIE_IOCTL_DMA_WRITER, &wr);

  struct litepcie_ioctl_dma_reader rd;

  memset (&rd, 0, sizeof (rd));

  ioctl (dev->fd, LITEPCIE_IOCTL_DMA_READER, &rd);

  struct litepcie_ioctl_lock lock;

  memset (&lock, 0, sizeof (lock));

  lock.dma_reader_release = 1;
  lock.dma_writer_release = 1;

  ioctl (dev->fd, LITEPCIE_IOCTL_LOCK, &lock);
}

static u64 litepcie_ring_pos (fpga_dev_t *dev, const int64_t hw_count, const u32 csr_addr)
{
  litepcie_priv_t *priv = dev->priv;

  if (priv->oneshot == true)
  {
    const u64 pos = (u64) hw_count;

    return pos;
  }

  const u32 loop = litepcie_csr_read (dev, csr_addr);

  const u64 live = ((u64) (loop >> 16) * LITEPCIE_DMA_BUFFER_COUNT) + (loop & 0xffff);

  const u64 span = (u64) LITEPCIE_DMA_BUFFER_COUNT << 16;

  const u64 ahead = (live - (u64) hw_count) & (span - 1);

  const u64 pos = (u64) hw_count + ahead;

  return pos;
}

static u64 litepcie_stream_in_pos (fpga_dev_t *dev)
{
  struct litepcie_ioctl_dma_writer m;

  memset (&m, 0, sizeof (m));

  m.enable = 1;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_DMA_WRITER, &m) < 0) return 0;

  const u64 pos = litepcie_ring_pos (dev, m.hw_count, dev->map->dma0_writer_loop_status);

  return pos;
}

static void *litepcie_stream_in_buf (fpga_dev_t *dev, const u64 pos)
{
  litepcie_priv_t *priv = dev->priv;

  u8 *buf = priv->rx + ((pos % LITEPCIE_DMA_BUFFER_COUNT) * LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);

  return buf;
}

static bool litepcie_stream_in_seek (fpga_dev_t *dev, const u64 pos)
{
  struct litepcie_ioctl_mmap_dma_update m;

  memset (&m, 0, sizeof (m));

  m.sw_count = (int64_t) pos;

  if (ioctl (dev->fd, LITEPCIE_IOCTL_MMAP_DMA_WRITER_UPDATE, &m) < 0) return false;

  return true;
}

static bool litepcie_session_open (fpga_dev_t *dev)
{
  if (litepcie_dma_claim (dev) == false) return false;

  if (litepcie_dma_set_oneshot (dev, true) == false)
  {
    litepcie_dma_release (dev);

    return false;
  }

  if (litepcie_dma_enable (dev) == false)
  {
    litepcie_dma_release (dev);

    return false;
  }

  return true;
}

static void litepcie_session_close (fpga_dev_t *dev)
{
  litepcie_dma_release (dev);
}

static bool litepcie_session_refresh (fpga_dev_t *dev)
{
  litepcie_dma_release (dev);

  return litepcie_session_open (dev);
}

static u64 litepcie_out_capacity (MAYBE_UNUSED fpga_dev_t *dev)
{
  const u64 capacity = (u64) LITEPCIE_DMA_BUFFER_COUNT * LITEPCIE_DMA_BUFFER_SIZE_EXPECTED;

  return capacity;
}

static bool litepcie_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  if (in_grain == 0) return false;

  if ((LITEPCIE_DMA_BUFFER_SIZE_EXPECTED % in_grain) != 0) return false;

  if (out_bytes > litepcie_out_capacity (dev)) return false;
  if (in_bytes  > litepcie_out_capacity (dev)) return false;

  litepcie_priv_t *priv = dev->priv;

  priv->out_bytes = out_bytes;
  priv->out_sent  = 0;

  priv->in_bytes  = in_bytes;
  priv->in_taken  = 0;
  priv->in_pos    = 0;

  priv->in_grain      = in_grain;
  priv->in_recs       = in_recs;
  priv->eob_seen      = false;
  priv->eob_processed = 0;

  const u32 in_bufs = (u32) ((in_bytes + LITEPCIE_DMA_BUFFER_SIZE_EXPECTED - 1) / LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);
  const u32 in_last = (u32) (in_bytes % LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);

  const u64 poison = (in_bytes < priv->ring_size) ? in_bytes : priv->ring_size;

  memset (priv->rx, 0xff, (size_t) poison);

  if (litepcie_dma_arm (dev, true, in_bufs, in_last) == false) return false;

  return true;
}

static bool litepcie_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  litepcie_priv_t *priv = dev->priv;

  if ((priv->out_sent + bytes) > priv->out_bytes) return false;

  const u8 *in = (const u8 *) src;

  u64 done = 0;

  while (done < bytes)
  {
    const u64 at   = priv->out_sent + done;
    const u64 off  = at % LITEPCIE_DMA_BUFFER_SIZE_EXPECTED;
    const u64 room = LITEPCIE_DMA_BUFFER_SIZE_EXPECTED - off;
    const u64 left = bytes - done;
    const u64 len  = MIN (room, left);

    u8 *dst = priv->tx + (((at / LITEPCIE_DMA_BUFFER_SIZE_EXPECTED) % LITEPCIE_DMA_BUFFER_COUNT) * LITEPCIE_DMA_BUFFER_SIZE_EXPECTED) + off;

    memcpy (dst, &in[done], len);

    done += len;
  }

  priv->out_sent += bytes;

  if (priv->out_sent < priv->out_bytes) return true;

  const u32 out_bufs = (u32) ((priv->out_bytes + LITEPCIE_DMA_BUFFER_SIZE_EXPECTED - 1) / LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);
  const u32 out_last = (u32) (priv->out_bytes % LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);

  if (litepcie_dma_arm (dev, false, out_bufs, out_last) == false) return false;

  return true;
}

static const void *litepcie_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  litepcie_priv_t *priv = dev->priv;

  *bytes = 0;

  if (priv->in_taken >= priv->in_bytes) return NULL;

  const u64 in_hw = litepcie_stream_in_pos (dev);

  if (in_hw <= priv->in_pos)
  {
    litepcie_wait_in (dev, timeout_ms);

    return NULL;
  }

  const u8 *buf = (const u8 *) litepcie_stream_in_buf (dev, priv->in_pos);

  const u64 left = priv->in_bytes - priv->in_taken;
  const u64 len  = MIN ((u64) LITEPCIE_DMA_BUFFER_SIZE_EXPECTED, left);

  priv->in_pos++;
  priv->in_taken += len;

  litepcie_stream_in_seek (dev, priv->in_pos);

  if (priv->eob_seen == false)
  {
    u32 processed = 0;

    if (hcfpga_c2h_scan_eob (buf, len, priv->in_grain, priv->in_recs, &processed) == true)
    {
      priv->eob_seen      = true;
      priv->eob_processed = processed;

      if (getenv ("HCFPGA_DEBUG") != NULL)
      {
        fprintf (stderr, "[hcfpga] eob in buffer %" PRIu64 " of this batch, processed=%u, first rec flags=%04x\n",
          priv->in_pos - 1, processed, (u32) (((const u8 *) buf)[30] | (((const u8 *) buf)[31] << 8)));
      }
    }
  }

  *bytes = len;

  return buf;
}

static bool litepcie_batch_done (fpga_dev_t *dev, u32 *processed)
{
  const litepcie_priv_t *priv = dev->priv;

  if (priv->eob_seen == false) return false;

  if (processed != NULL) *processed = priv->eob_processed;

  return true;
}

static void litepcie_batch_end (MAYBE_UNUSED fpga_dev_t *dev)
{
}

void hcfpga_debug_window (fpga_dev_t *dev)
{
  if (dev == NULL) return;
  if (dev->transport != &fpga_transport_litepcie) return;

  const litepcie_priv_t *priv = dev->priv;

  if (priv == NULL) return;
  if (priv->rx == NULL) return;

  const u32 rec = (priv->in_grain > 0) ? priv->in_grain : 32;

  const u64 nbuf = (priv->in_bytes + LITEPCIE_DMA_BUFFER_SIZE_EXPECTED - 1) / LITEPCIE_DMA_BUFFER_SIZE_EXPECTED;

  fprintf (stderr, "[dbg] window: in_bytes=%" PRIu64 " bufs=%" PRIu64 " taken=%" PRIu64 " pos=%" PRIu64 " hw=%" PRIu64 "\n",
    priv->in_bytes, nbuf, priv->in_taken, priv->in_pos, litepcie_stream_in_pos (dev));

  for (u64 b = 0; b < nbuf; b++)
  {
    const u8 *buf = (const u8 *) priv->rx + ((b % LITEPCIE_DMA_BUFFER_COUNT) * LITEPCIE_DMA_BUFFER_SIZE_EXPECTED);

    u32 n_poison = 0;
    u32 n_result = 0;
    u32 n_eob    = 0;
    u32 n_other  = 0;

    u32 first_flags = 0xffffffffu;
    u32 last_flags  = 0xffffffffu;

    for (u32 off = 0; (off + rec) <= LITEPCIE_DMA_BUFFER_SIZE_EXPECTED; off += rec)
    {
      const u32 flags = (u32) buf[off + 30] | ((u32) buf[off + 31] << 8);

      if (first_flags == 0xffffffffu) first_flags = flags;

      last_flags = flags;

      if      (flags == 0xffff) n_poison++;
      else if (flags == 0x0000) n_result++;
      else if (flags == 0x8000) n_eob++;
      else                      n_other++;
    }

    if ((n_result == 0) && (n_eob == 0) && (n_other == 0)) continue;

    const u32 eob_cnt = (u32) buf[0] | ((u32) buf[1] << 8) | ((u32) buf[2] << 16) | ((u32) buf[3] << 24);

    fprintf (stderr, "[dbg]   buf %2" PRIu64 ": result=%u eob=%u poison=%u other=%u first=%04x last=%04x w0=%u\n",
      b, n_result, n_eob, n_poison, n_other, first_flags, last_flags, eob_cnt);
  }
}

const fpga_transport_t fpga_transport_litepcie =
{
  .name            = "litepcie",
  .bus             = "PCIe",
  .udev            = "99-litepcie.rules",
  .dialect         = FPGA_DIALECT_HCFPGA,

  .enumerate       = litepcie_enumerate,
  .identify        = litepcie_identify,
  .close           = litepcie_close,

  .csr_read        = litepcie_csr_read,
  .csr_write       = litepcie_csr_write,

  .session_open    = litepcie_session_open,
  .session_close   = litepcie_session_close,
  .session_refresh = litepcie_session_refresh,
  .out_capacity    = litepcie_out_capacity,

  .batch_begin     = litepcie_batch_begin,
  .batch_send      = litepcie_batch_send,
  .batch_recv      = litepcie_batch_recv,
  .batch_end       = litepcie_batch_end,
  .batch_done      = litepcie_batch_done,

  .in_granule      = LITEPCIE_DMA_BUFFER_SIZE_EXPECTED,

  .program         = NULL,

  .temperature     = NULL,
};

#else

void hcfpga_debug_window (MAYBE_UNUSED fpga_dev_t *dev) { }

static void pci_foreign_fw_scan (MAYBE_UNUSED fpga_reject_t *rejects, MAYBE_UNUSED int *rejects_cnt) { }

static int  stub_enumerate  (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED fpga_dev_t *devs, MAYBE_UNUSED const int max, fpga_status_t *status) { *status = FPGA_STATUS_UNSUPPORTED_OS; return 0; }
static fpga_status_t stub_identify (MAYBE_UNUSED fpga_dev_t *dev)                                              { return FPGA_STATUS_UNSUPPORTED_OS; }
static void stub_close      (MAYBE_UNUSED fpga_dev_t *dev)                                                     { }

static u32  stub_csr_read   (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr)                        { return 0; }
static bool stub_csr_write  (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr, MAYBE_UNUSED const u32 val) { return false; }

static bool stub_session_open  (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static void stub_session_close (MAYBE_UNUSED fpga_dev_t *dev) { }
static u64  stub_out_capacity  (MAYBE_UNUSED fpga_dev_t *dev) { return 0; }

static bool stub_batch_begin (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, MAYBE_UNUSED const u64 in_bytes, MAYBE_UNUSED const u32 in_grain, MAYBE_UNUSED const u32 in_recs) { return false; }
static bool stub_batch_send  (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const void *src, MAYBE_UNUSED const u64 bytes) { return false; }
static void stub_batch_end   (MAYBE_UNUSED fpga_dev_t *dev) { }

static const void *stub_batch_recv (MAYBE_UNUSED fpga_dev_t *dev, u64 *bytes, MAYBE_UNUSED const u32 timeout_ms) { *bytes = 0; return NULL; }

const fpga_transport_t fpga_transport_litepcie =
{
  .name            = "litepcie",
  .bus             = "PCIe",
  .udev            = "99-litepcie.rules",
  .dialect         = FPGA_DIALECT_HCFPGA,

  .enumerate       = stub_enumerate,
  .identify        = stub_identify,
  .close           = stub_close,

  .csr_read        = stub_csr_read,
  .csr_write       = stub_csr_write,

  .session_open    = stub_session_open,
  .session_close   = stub_session_close,
  .out_capacity    = stub_out_capacity,

  .batch_begin     = stub_batch_begin,
  .batch_send      = stub_batch_send,
  .batch_recv      = stub_batch_recv,
  .batch_end       = stub_batch_end,

  .program         = NULL,
  .temperature     = NULL,
};

#endif

bool fpga_say_progress (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet            == true) return false;
  if (user_options->keyspace         == true) return false;
  if (user_options->stdout_flag      == true) return false;
  if (user_options->machine_readable == true) return false;
  if (user_options->show             == true) return false;
  if (user_options->left             == true) return false;
  if (user_options->backend_info      >  0)   return false;

  return true;
}

const fpga_transport_t *const fpga_transports[] =
{
  &fpga_transport_litepcie,
  &fpga_transport_ztex115y,
  &fpga_transport_ztex213,
  &fpga_transport_xrt,
  &fpga_transport_artyz7,
};

const int fpga_transports_cnt = (int) (sizeof (fpga_transports) / sizeof (fpga_transports[0]));

static const fpga_transport_t *fpga_transport_find (const char *transport)
{
  if (transport == NULL) return NULL;

  for (int i = 0; i < fpga_transports_cnt; i++)
  {
    if (strcmp (fpga_transports[i]->name, transport) != 0) continue;

    return fpga_transports[i];
  }

  return NULL;
}

bool fpga_transport_programs (const char *transport)
{
  const fpga_transport_t *t = fpga_transport_find (transport);

  if (t == NULL) return false;

  return (t->program != NULL) ? true : false;
}

bool fpga_transport_is_usb (const char *transport)
{
  const fpga_transport_t *t = fpga_transport_find (transport);

  if (t == NULL)      return false;
  if (t->bus == NULL) return false;

  return (strcmp (t->bus, "USB") == 0) ? true : false;
}

const char *fpga_transport_udev (const char *transport)
{
  const fpga_transport_t *t = fpga_transport_find (transport);

  if (t == NULL) return NULL;

  return t->udev;
}

bool fpga_transport_same_bus (const char *a, const char *b)
{
  const fpga_transport_t *ta = fpga_transport_find (a);
  const fpga_transport_t *tb = fpga_transport_find (b);

  if (ta == NULL) return false;
  if (tb == NULL) return false;

  if (ta->bus == NULL) return false;
  if (tb->bus == NULL) return false;

  return (strcmp (ta->bus, tb->bus) == 0) ? true : false;
}

static fpga_status_t fpga_program_identify (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *want_algo)
{
  const fpga_status_t prog = dev->transport->program (hashcat_ctx, dev, want_algo);

  if (prog != FPGA_STATUS_OK) return prog;

  const fpga_status_t after = dev->transport->identify (dev);

  if (getenv ("HCFPGA_DEBUG") != NULL) fprintf (stderr, "[hcfpga] %s programmed: status %d, %s\n", dev->ident.serial, (int) after, dev->ident.raw);

  return after;
}

static fpga_status_t fpga_ident_check (const fpga_dev_t *dev, const char *want_algo)
{
  if (dev->ident.abi != FPGA_ABI_CURRENT) return FPGA_STATUS_ABI_MISMATCH;

  if (strcmp (dev->ident.algo, want_algo) != 0) return FPGA_STATUS_WRONG_ALGO;

  return FPGA_STATUS_OK;
}

static void fpga_reject_add (fpga_reject_t *rejects, int *rejects_cnt, const fpga_dev_t *dev, const fpga_status_t st, const bool have_ident)
{
  if (*rejects_cnt >= FPGA_MAX_REJECTS) return;

  fpga_reject_t *reject = &rejects[*rejects_cnt];

  snprintf (reject->path, sizeof (reject->path), "%s", dev->path);

  reject->transport  = dev->transport->name;
  reject->bus_level  = false;
  reject->status     = st;
  reject->ident      = dev->ident;
  reject->have_ident = have_ident;

  (*rejects_cnt)++;
}

static bool fpga_confirm (fpga_dev_t *dev)
{
  if (dev->transport->confirm == NULL) return false;

  const bool ok = dev->transport->confirm (dev);

  if (ok == true) dev->ident.asserted = false;

  if (getenv ("HCFPGA_DEBUG") != NULL) fprintf (stderr, "[hcfpga] %s confirm: %s\n", dev->ident.serial, (ok == true) ? "runs what this build loads, reused" : "not confirmed");

  return ok;
}

static fpga_status_t fpga_identify_or_program (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *want_algo, const bool defer_program)
{
  const fpga_status_t st = dev->transport->identify (dev);

  if (st == FPGA_STATUS_IN_USE) return st;

  const bool dbg = (getenv ("HCFPGA_DEBUG") != NULL);

  if (dbg == true) fprintf (stderr, "[hcfpga] %s identify: status %d, %s%s\n", dev->ident.serial, (int) st, dev->ident.raw, (dev->ident.asserted == true) ? " (asserted)" : "");

  const bool verified = (dev->ident.asserted == false);

  const bool usable = ((st == FPGA_STATUS_OK) && (fpga_ident_check (dev, want_algo) == FPGA_STATUS_OK));

  if ((usable == true) && (verified == true)) return st;

  if (dev->transport->program == NULL) return st;

  if (hashcat_ctx == NULL) return st;

  if ((usable == true) && (defer_program == true))
  {
    dev->program_pending = true;

    return st;
  }

  if ((usable == true) && (fpga_confirm (dev) == true)) return st;

  const fpga_status_t after = fpga_program_identify (hashcat_ctx, dev, want_algo);

  return after;
}

fpga_status_t fpga_unit_program_pending (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *want_algo, fpga_reject_t *rejects, int *rejects_cnt)
{
  if (dev->program_pending == false) return FPGA_STATUS_OK;

  dev->program_pending = false;

  if (fpga_confirm (dev) == true) return FPGA_STATUS_OK;

  fpga_status_t st = fpga_program_identify (hashcat_ctx, dev, want_algo);

  const bool have_ident = (st == FPGA_STATUS_OK);

  if (st == FPGA_STATUS_OK) st = fpga_ident_check (dev, want_algo);

  if (st != FPGA_STATUS_OK) fpga_reject_add (rejects, rejects_cnt, dev, st, have_ident);

  return st;
}

int fpga_units_open (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, const char *want_algo, const fpga_csr_map_t *map, const bool defer_program, fpga_status_t *status, fpga_reject_t *rejects, int *rejects_cnt)
{
  *status = FPGA_STATUS_OK;

  *rejects_cnt = 0;

  int found = 0;

  fpga_status_t enum_worst = FPGA_STATUS_OK;

  for (int t = 0; t < fpga_transports_cnt; t++)
  {
    const fpga_transport_t *transport = fpga_transports[t];

    fpga_status_t st = FPGA_STATUS_OK;

    const int n = transport->enumerate (hashcat_ctx, &devs[found], max - found, &st);

    for (int i = 0; i < n; i++) devs[found + i].transport = transport;

    for (int i = 0; i < n; i++)
    {
      char board[sizeof (devs[0].ident.board)];

      snprintf (board, sizeof (board), "%s", devs[found + i].ident.board);

      memset (&devs[found + i].ident, 0, sizeof (fpga_ident_t));

      snprintf (devs[found + i].ident.board, sizeof (devs[found + i].ident.board), "%s", board);
    }

    found += n;

    if ((n == 0) && (st > enum_worst)) enum_worst = st;

    const bool present = ((st == FPGA_STATUS_NO_CHAR_DEVICE) || (st == FPGA_STATUS_NO_PERMISSION));

    if ((n == 0) && (present == true) && (*rejects_cnt < FPGA_MAX_REJECTS))
    {
      fpga_reject_t *reject = &rejects[*rejects_cnt];

      const char *bus = (transport->bus) ? transport->bus : "PCIe";

      snprintf (reject->path, sizeof (reject->path), "on the %s bus", bus);

      reject->transport  = transport->name;
      reject->bus_level  = true;
      reject->status     = st;
      reject->have_ident = false;

      memset (&reject->ident, 0, sizeof (fpga_ident_t));

      (*rejects_cnt)++;
    }

    if (found >= max) break;
  }

  if (found == 0)
  {
    const int before = *rejects_cnt;

    pci_foreign_fw_scan (rejects, rejects_cnt);

    *status = enum_worst;

    if ((*rejects_cnt > before) && (enum_worst == FPGA_STATUS_NO_PCI_DEVICE)) *status = FPGA_STATUS_FOREIGN_FW;

    return 0;
  }

  for (int i = 0; i < found; i++)
  {
    devs[i].csr_base = map->base;
    devs[i].map      = map;
  }

  fpga_status_t worst = FPGA_STATUS_OK;

  int kept = 0;

  for (int i = 0; i < found; i++)
  {
    fpga_dev_t *dev = &devs[i];

    dev->program_pending = false;

    fpga_status_t st = fpga_identify_or_program (hashcat_ctx, dev, want_algo, defer_program);

    const bool have_ident = (st == FPGA_STATUS_OK);

    if (st == FPGA_STATUS_OK) st = fpga_ident_check (dev, want_algo);

    if (st != FPGA_STATUS_OK)
    {
      if (st > worst) worst = st;

      fpga_reject_add (rejects, rejects_cnt, dev, st, have_ident);

      dev->transport->close (dev);

      continue;
    }

    if (kept != i) devs[kept] = *dev;

    kept++;
  }

  if (kept == 0) *status = (worst != FPGA_STATUS_OK) ? worst : FPGA_STATUS_BAD_IDENT;

  pci_foreign_fw_scan (rejects, rejects_cnt);

  return kept;
}

void fpga_units_close (fpga_dev_t *devs, const int cnt)
{
  for (int i = 0; i < cnt; i++)
  {
    devs[i].transport->close (&devs[i]);
  }
}
