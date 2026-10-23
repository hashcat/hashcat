/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_HCFPGA_H
#define HC_FPGA_HCFPGA_H

#include "common.h"
#include "types.h"

#if defined (__linux__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#endif

#define FPGA_MAX_DEVICES    128
#define FPGA_MAX_UNITS      FPGA_MAX_DEVICES
#define FPGA_IDENT_MAX      256
#define FPGA_PATH_MAX       4096

typedef enum fpga_status
{
  FPGA_STATUS_OK              = 0,
  FPGA_STATUS_UNSUPPORTED_OS  = 1,
  FPGA_STATUS_ALGO_UNAVAILABLE= 2,
  FPGA_STATUS_NO_PCI_DEVICE   = 3,
  FPGA_STATUS_NO_CHAR_DEVICE  = 4,
  FPGA_STATUS_NO_PERMISSION   = 5,
  FPGA_STATUS_CSR_WINDOW      = 6,
  FPGA_STATUS_BAD_IDENT       = 7,
  FPGA_STATUS_WRONG_ALGO      = 8,
  FPGA_STATUS_ABI_MISMATCH    = 9,
  FPGA_STATUS_NO_BITSTREAM    = 10,
  FPGA_STATUS_FOREIGN_FW      = 11,
  FPGA_STATUS_NO_RUNTIME      = 12,
  FPGA_STATUS_IN_USE          = 13,

} fpga_status_t;

#define FPGA_IDENT_PREFIX   "hcfpga/"

#define FPGA_ABI_CURRENT    4

#define FPGA_SET_CURRENT    7

#define FPGA_ABI_STR_(x)    #x
#define FPGA_ABI_STR(x)     FPGA_ABI_STR_(x)
#define FPGA_ABI_SUBDIR     "v" FPGA_ABI_STR (FPGA_ABI_CURRENT)
#define FPGA_SET_SUBDIR     "v" FPGA_ABI_STR (FPGA_SET_CURRENT)

typedef struct fpga_ident
{
  char raw[FPGA_IDENT_MAX];

  char board[32];
  char algo[32];
  char build[32];

  char serial[16];

  u32  cores;
  u32  clk_mhz;
  u32  abi;

  u32  n;
  u32  r;

  bool asserted;

} fpga_ident_t;

#define FPGA_CSR_BASE_NO_CPU  0x00000000

typedef struct fpga_csr_map
{
  const char *name;

  u32 base;
  u32 scratch;
  u32 identifier_mem;

  u32 dma0_reader_loop_status;
  u32 dma0_writer_loop_status;

  u32 dna;

} fpga_csr_map_t;

extern const fpga_csr_map_t fpga_csr_map_no_cpu;

typedef struct fpga_dev
{
  char          path[FPGA_PATH_MAX];
  int           fd;

  u32           csr_base;

  const fpga_csr_map_t *map;

  fpga_ident_t  ident;

  const struct fpga_transport *transport;

  void         *priv;

  bool          program_pending;

  u64           batch_wait_ms;

} fpga_dev_t;

typedef enum fpga_dialect
{
  FPGA_DIALECT_HCFPGA = 0,

  FPGA_DIALECT_ZTEX   = 1,

} fpga_dialect_t;

typedef struct fpga_transport
{
  const char *name;

  const char *bus;

  const char *data_link;

  const char *udev;

  fpga_dialect_t dialect;

  bool retired_reads_zero;

  int   (*enumerate)  (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status);
  void  (*close)      (fpga_dev_t *dev);

  void  (*release)    (fpga_dev_t *dev);

  fpga_status_t (*identify) (fpga_dev_t *dev);

  bool (*confirm) (fpga_dev_t *dev);

  u32   (*csr_read)   (fpga_dev_t *dev, const u32 addr);
  bool  (*csr_write)  (fpga_dev_t *dev, const u32 addr, const u32 val);

  bool  (*session_open)  (fpga_dev_t *dev);
  void  (*session_close) (fpga_dev_t *dev);

  bool  (*session_refresh) (fpga_dev_t *dev);

  u64   (*out_capacity)  (fpga_dev_t *dev);

  bool  (*batch_begin) (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs);
  bool  (*batch_send)  (fpga_dev_t *dev, const void *src, const u64 bytes);

  bool  (*control)     (fpga_dev_t *dev, const u32 type, const void *src, const u64 bytes);

  const void *(*batch_recv) (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms);

  void  (*batch_end)   (fpga_dev_t *dev);

  bool  (*batch_done)  (fpga_dev_t *dev, u32 *processed);

  u32   in_granule;

  bool  (*batch_failed) (fpga_dev_t *dev);

  fpga_status_t (*program) (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *algo);

  int   (*temperature) (fpga_dev_t *dev);

  int   (*temperature_all) (fpga_dev_t *dev, int *out, const u32 out_max);

  bool  temperature_is_die;

  u32   temperature_abort;

  u32   (*clock_step_down) (fpga_dev_t *dev);

  bool  (*link_str) (fpga_dev_t *dev, char *buf, const size_t len);

} fpga_transport_t;

extern const fpga_transport_t fpga_transport_litepcie;
extern const fpga_transport_t fpga_transport_ztex115y;
extern const fpga_transport_t fpga_transport_ztex213;
extern const fpga_transport_t fpga_transport_xrt;
extern const fpga_transport_t fpga_transport_artyz7;

extern const fpga_transport_t *const fpga_transports[];
extern const int                     fpga_transports_cnt;

typedef enum fpga_prog
{
  FPGA_PROG_HASHCAT = 0,

  FPGA_PROG_USER    = 1,

} fpga_prog_t;

typedef struct fpga_board
{
  const char *board;
  const char *pretty;
  const char *bus;

  fpga_prog_t prog;

  const char *udev;
  const char *doc_section;

} fpga_board_t;

const fpga_board_t *fpga_board_find (const char *board);

bool        fpga_transport_is_usb   (const char *transport);
bool        fpga_transport_programs (const char *transport);
const char *fpga_transport_udev     (const char *transport);
bool        fpga_transport_same_bus (const char *a, const char *b);

const char *fpga_board_describe (const fpga_board_t *info, const fpga_ident_t *ident, const char *path, char *buf, const size_t len);

typedef struct fpga_reject
{
  char          path[FPGA_PATH_MAX];

  const char   *transport;

  bool          bus_level;

  fpga_status_t status;

  fpga_ident_t  ident;
  bool          have_ident;

} fpga_reject_t;

#define FPGA_MAX_REJECTS  FPGA_MAX_DEVICES

#define FPGA_BITSTREAM_SUBDIR "fpga"

#define FPGA_SUPPORT_SUBDIR "extra/fpga"

bool        fpga_shipped_file  (const folder_config_t *folder_config, const char *name, char *out, const size_t out_sz);

#define FPGA_DOC_RELPATH "docs/hashcat-fpga-setup.md"

const char *fpga_support_file  (const hashcat_ctx_t *hashcat_ctx, const char *name, char *out, const size_t out_sz);

const char *fpga_doc_path      (const hashcat_ctx_t *hashcat_ctx, char *out, const size_t out_sz);

void        fpga_shipped_report_missing (hashcat_ctx_t *hashcat_ctx, const folder_config_t *folder_config, const char *const *names, const u32 names_cnt, const fpga_board_t *info);

bool        fpga_report_once (const fpga_board_t *info, const char *tag);

int         fpga_units_open   (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, const char *want_algo, const fpga_csr_map_t *map, const bool defer_program, fpga_status_t *status, fpga_reject_t *rejects, int *rejects_cnt);

fpga_status_t fpga_unit_program_pending (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *dev, const char *want_algo, fpga_reject_t *rejects, int *rejects_cnt);

void        fpga_reject_report_all   (hashcat_ctx_t *hashcat_ctx, const fpga_reject_t *rejects, const int rejects_cnt, const char *want_algo);

const fpga_ident_t *fpga_reject_worst_ident     (const fpga_reject_t *rejects, const int rejects_cnt, const fpga_status_t status);
const char         *fpga_reject_worst_transport (const fpga_reject_t *rejects, const int rejects_cnt, const fpga_status_t status);
void        fpga_units_close  (fpga_dev_t *devs, const int cnt);

bool        fpga_ident_parse  (const char *raw, fpga_ident_t *ident);

bool        hcfpga_c2h_scan_eob (const void *buf, const u64 bytes, const u32 rec_bytes, const u32 want, u32 *processed);

void        hcfpga_debug_window (fpga_dev_t *dev);

typedef struct fpga_timing
{
  bool enabled;

  u64  in_ns;
  u64  first_ns;
  u64  last_ns;

  u64  exit_ns;

} fpga_timing_t;

u64  fpga_now_ns       (void);

void fpga_timing_begin (fpga_timing_t *t);
void fpga_timing_first (fpga_timing_t *t);
void fpga_timing_last  (fpga_timing_t *t);
void fpga_timing_end   (fpga_timing_t *t, const char *tag, const u64 recs, const u64 recv, const u64 pws_cnt);

void        fpga_status_report (hashcat_ctx_t *hashcat_ctx, const fpga_status_t status, const char *want_algo, const u32 want_n, const u32 want_r, const fpga_ident_t *ident, const char *transport);

#define FPGA_BITSTREAM_URL_BASE "https://hashcat.net/bitstreams"

typedef enum fpga_dist
{
  FPGA_DIST_PUBLISHED     = 0,

  FPGA_DIST_REDISTRIBUTED = 1,

} fpga_dist_t;

typedef struct fpga_release
{
  const char *algo;
  const char *board;

  u32         n;
  u32         r;

  const char *ext;

  fpga_dist_t dist;

  const char *subdir;

} fpga_release_t;

const fpga_release_t *fpga_release_find (const char *algo, const char *board, const u32 n, const u32 r);

bool        fpga_release_filename (const fpga_release_t *release, char *out, const size_t out_sz);

void        fpga_bitstream_report_missing (hashcat_ctx_t *hashcat_ctx, const fpga_release_t *release);

bool fpga_say_progress (hashcat_ctx_t *hashcat_ctx);

#endif
