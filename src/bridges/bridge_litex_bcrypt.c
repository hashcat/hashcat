/**
 * Hashcat bridge for LiteX bcrypt FPGA accelerator
 *
 * This bridge interfaces hashcat with custom bcrypt FPGA hardware built using
 * LiteX/Migen, accessed via the LitePCIe driver.
 *
 * Hardware requirements:
 * - FPGA with LitePCIe interface
 * - Bcrypt core with packet-based protocol (compatible with JtR ZTEX format)
 * - Linux with litepcie kernel module loaded
 *
 * Protocol:
 * - Packets sent to streamer memory region
 * - Results captured in recorder memory region
 * - Packet format: [header][hdr_checksum][payload][payload_checksum]
 *
 * Reference implementation: litex_bcrypt/software/user/cleanup2_test.c
 */

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "event.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

/**
 * LitePCIe IOCTL definitions (from litepcie.h)
 */

struct litepcie_ioctl_reg {
  uint32_t addr;
  uint32_t val;
  uint8_t  is_write;
};

#define LITEPCIE_IOCTL      'S'
#define LITEPCIE_IOCTL_REG  _IOWR(LITEPCIE_IOCTL, 0, struct litepcie_ioctl_reg)

/**
 * CSR addresses (from csr.h - CSR_BASE is 0x0)
 */

#define CSR_IDENTIFIER_MEM_BASE     0x00001000

#define CSR_BCRYPT_CTRL_ADDR            0x00000000
#define CSR_BCRYPT_APP_STATUS_ADDR      0x00000004
#define CSR_BCRYPT_PKT_COMM_STATUS_ADDR 0x00000008
#define CSR_BCRYPT_IDLE_ADDR            0x0000000C
#define CSR_BCRYPT_ERROR_ADDR           0x00000010
#define CSR_BCRYPT_CLEAR_ERROR_ADDR     0x00000014

#define CSR_STREAMER_LENGTH_ADDR    0x00004800
#define CSR_STREAMER_KICK_ADDR      0x00004804
#define CSR_STREAMER_DONE_ADDR      0x00004808

#define CSR_RECORDER_KICK_ADDR      0x00004000
#define CSR_RECORDER_DONE_ADDR      0x00004004
#define CSR_RECORDER_COUNT_ADDR     0x00004008

/**
 * Memory addresses (from mem.h)
 */

#define STREAMER_MEM_BASE           0x00040000
#define STREAMER_MEM_SIZE           0x00000400

#define RECORDER_MEM_BASE           0x00080000
#define RECORDER_MEM_SIZE           0x00000400

/**
 * Packet protocol definitions (from cleanup2_test.c)
 */

#define PKT_VERSION           2
#define PKT_TYPE_WORD_LIST    0x01
#define PKT_TYPE_WORD_GEN     0x02
#define PKT_TYPE_CMP_CONFIG   0x03
#define PKT_TYPE_RESET        0x05

#define PKT_RESP_CMP_RESULT   0xd4
#define PKT_RESP_PACKET_DONE  0xd2

/**
 * Bridge configuration
 */

#define MAX_FPGA_DEVICES    64
#define BASE_WORKITEM_COUNT 16   // Must not exceed hashcat's kernel_power
#define MAX_WORKITEM_COUNT  256
#define MAX_PASSWORD_LEN    72
#define FPGA_TIMEOUT        10000000
#define DRAIN_SHORT_TIMEOUT 5000
#define DRAIN_MAX_PACKETS   10

// Payload size limit: 1KB buffer - header(10) - checksums(8)
#define MAX_PAYLOAD_SIZE    1006
#define MAX_SUB_BATCH_SIZE  512

/**
 * FPGA tmp structure (must match module_70300.c)
 */

typedef struct bcrypt_fpga_tmp
{
  u32 pw_buf[18];
  u32 pw_len;
  u32 cracked;      // Must be right after pw_len to match OpenCL struct!
  // Note: NO digest field here - that was wrong and caused offset mismatch

} bcrypt_fpga_tmp_t;

/**
 * Per-FPGA unit context
 */

typedef struct
{
  int       fd;
  char      device_path[64];

  char      unit_info_buf[1024];
  int       unit_info_len;
  u64       workitem_count;

  int       num_proxies;
  int       cores_per_proxy;
  int       total_cores;

  uint8_t  *streamer_buf;
  uint8_t  *recorder_buf;
  uint16_t  next_pkt_id;

} unit_t;

/**
 * Platform-wide context
 */

typedef struct
{
  unit_t   *units_buf;
  int       units_cnt;

} bridge_litex_bcrypt_t;

/**
 * LitePCIe helper functions
 */

static uint32_t litepcie_readl (int fd, uint32_t addr)
{
  struct litepcie_ioctl_reg reg;

  reg.addr = addr;
  reg.is_write = 0;

  if (ioctl (fd, LITEPCIE_IOCTL_REG, &reg) < 0)
  {
    return 0xFFFFFFFF;
  }

  return reg.val;
}

static void litepcie_writel (int fd, uint32_t addr, uint32_t val)
{
  struct litepcie_ioctl_reg reg;

  reg.addr = addr;
  reg.val = val;
  reg.is_write = 1;

  ioctl (fd, LITEPCIE_IOCTL_REG, &reg);
}

/**
 * Write multiple bytes to LitePCIe memory region (from cleanup2_test.c)
 */

static void write_bytes (int fd, uint32_t base, const uint8_t *data, size_t len)
{
  uint8_t buf[4] = {0};

  for (size_t i = 0; i < len; i += 4)
  {
    memset (buf, 0, 4);

    size_t rem = len - i > 4 ? 4 : len - i;

    memcpy (buf, data + i, rem);

    litepcie_writel (fd, base + i, buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
  }
}

/**
 * Read multiple bytes from LitePCIe memory region (from cleanup2_test.c)
 */

static void read_bytes (int fd, uint32_t base, uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i += 4)
  {
    uint32_t w = litepcie_readl (fd, base + i);

    size_t rem = len - i > 4 ? 4 : len - i;

    for (size_t j = 0; j < rem; j++)
    {
      data[i + j] = (w >> (8 * j)) & 0xFF;
    }
  }
}

/**
 * Encoding helpers (from cleanup2_test.c)
 */

static void le16_encode (uint16_t x, uint8_t *out)
{
  out[0] = x & 0xFF;
  out[1] = (x >> 8) & 0xFF;
}

static void le24_encode (uint32_t x, uint8_t *out)
{
  out[0] = x & 0xFF;
  out[1] = (x >> 8) & 0xFF;
  out[2] = (x >> 16) & 0xFF;
}

static void le32_encode (uint32_t x, uint8_t *out)
{
  out[0] = x & 0xFF;
  out[1] = (x >> 8) & 0xFF;
  out[2] = (x >> 16) & 0xFF;
  out[3] = (x >> 24) & 0xFF;
}

static uint16_t le16_decode (const uint8_t *data)
{
  return data[0] | (data[1] << 8);
}

/**
 * Checksum calculation (from cleanup2_test.c)
 */

static uint32_t csum32_le (const uint8_t *data, size_t len)
{
  uint32_t sum = 0;

  for (size_t i = 0; i < len; i += 4)
  {
    uint32_t w = 0;

    for (int j = 0; j < 4 && i + j < len; j++)
    {
      w |= data[i + j] << (8 * j);
    }

    sum = (sum + w) & 0xFFFFFFFF;
  }

  return sum ^ 0xFFFFFFFF;
}

/**
 * Build packet header (from cleanup2_test.c - EXACT format)
 *
 * Header layout (10 bytes):
 *   [0]     = version (PKT_VERSION = 2)
 *   [1]     = pkt_type
 *   [2]     = 0x00 (reserved)
 *   [3]     = 0x00 (reserved)
 *   [4-6]   = payload_len (3 bytes little-endian)
 *   [7]     = 0x00 (reserved)
 *   [8-9]   = pkt_id (2 bytes little-endian)
 */

static void build_header (uint8_t *out, uint8_t pkt_type, uint16_t pkt_id, uint32_t payload_len)
{
  out[0] = PKT_VERSION;
  out[1] = pkt_type;
  out[2] = 0x00;
  out[3] = 0x00;
  le24_encode (payload_len, out + 4);
  out[7] = 0x00;
  le16_encode (pkt_id, out + 8);
}

/**
 * Add checksums around payload (from cleanup2_test.c)
 *
 * Output: [header][hdr_checksum][payload][payload_checksum]
 */

static void add_checksums_around_payload (uint8_t *pkt, size_t *pkt_len,
                                          const uint8_t *header, size_t hlen,
                                          const uint8_t *payload, size_t plen)
{
  uint8_t hsum[4], psum[4];

  uint32_t h = csum32_le (header, hlen);
  uint32_t p = csum32_le (payload, plen);

  le32_encode (h, hsum);
  le32_encode (p, psum);

  memcpy (pkt, header, hlen);
  memcpy (pkt + hlen, hsum, 4);
  memcpy (pkt + hlen + 4, payload, plen);
  memcpy (pkt + hlen + 4 + plen, psum, 4);

  *pkt_len = hlen + 4 + plen + 4;
}

/**
 * Build CMP_CONFIG payload for bcrypt (from cleanup2_test.c)
 */

static void build_cmp_config_payload_bcrypt (uint8_t *out, size_t *len,
                                             uint32_t iter_count,
                                             const uint8_t *salt16,
                                             uint8_t subtype,
                                             size_t nhashes,
                                             const uint32_t *hashes)
{
  uint8_t *p = out;

  // Salt (16 bytes)
  memcpy (p, salt16, 16);
  p += 16;

  // Subtype (1 byte)
  *p++ = subtype;

  // Iteration count (4 bytes little-endian)
  le32_encode (iter_count, p);
  p += 4;

  // Number of hashes (2 bytes little-endian)
  le16_encode ((uint16_t) nhashes, p);
  p += 2;

  // Hash comparison values (4 bytes each)
  for (size_t i = 0; i < nhashes; i++)
  {
    le32_encode (hashes[i], p);
    p += 4;
  }

  // Magic terminator
  *p++ = 0xCC;

  *len = p - out;
}

/**
 * Build WORD_LIST payload (from cleanup2_test.c)
 */

static void build_word_list_payload (uint8_t *out, size_t *len,
                                     const u8 **words, const u32 *word_lens,
                                     size_t nwords)
{
  uint8_t *p = out;

  for (size_t i = 0; i < nwords; i++)
  {
    const u8 *w = words[i];
    u32 wlen = word_lens[i];

    memcpy (p, w, wlen);
    p += wlen;
    *p++ = 0x00;  // null terminator
  }

  *len = p - out;
}

/**
 * Build empty WORD_GEN payload (from cleanup2_test.c)
 */

static void build_empty_word_gen_payload (uint8_t *out, size_t *len)
{
  uint8_t payload[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xBB};

  memcpy (out, payload, sizeof (payload));

  *len = sizeof (payload);
}

/**
 * Kick streamer (from cleanup2_test.c)
 */

static bool kick_streamer (unit_t *unit, const uint8_t *pkt_bytes, size_t pkt_len)
{
  write_bytes (unit->fd, STREAMER_MEM_BASE, pkt_bytes, pkt_len);

  litepcie_writel (unit->fd, CSR_STREAMER_LENGTH_ADDR, pkt_len);
  litepcie_writel (unit->fd, CSR_STREAMER_KICK_ADDR, 0);
  litepcie_writel (unit->fd, CSR_STREAMER_KICK_ADDR, 1);

  uint32_t cnt = 0;

  while (!(litepcie_readl (unit->fd, CSR_STREAMER_DONE_ADDR) & 1))
  {
    cnt++;

    if (cnt >= FPGA_TIMEOUT)
    {
      return false;
    }
  }

  return true;
}

/**
 * Start recorder (from cleanup2_test.c)
 */

static void start_recorder (unit_t *unit)
{
  litepcie_writel (unit->fd, CSR_RECORDER_KICK_ADDR, 0);
  litepcie_writel (unit->fd, CSR_RECORDER_KICK_ADDR, 1);
}

/**
 * Wait for recorder (from cleanup2_test.c)
 */

static bool wait_recorder (unit_t *unit, uint32_t *len)
{
  uint32_t cnt = 0;

  while (!(litepcie_readl (unit->fd, CSR_RECORDER_DONE_ADDR) & 1))
  {
    cnt++;

    if (cnt >= FPGA_TIMEOUT)
    {
      *len = 0;
      return false;
    }
  }

  *len = litepcie_readl (unit->fd, CSR_RECORDER_COUNT_ADDR);

  return true;
}

/**
 * Drain output FIFO (from cleanup2_test.c)
 */

static uint32_t drain_output_fifo (unit_t *unit)
{
  uint32_t total_drained = 0;
  int packets_drained = 0;
  uint8_t discard_buf[256];

  while (packets_drained < DRAIN_MAX_PACKETS)
  {
    litepcie_writel (unit->fd, CSR_RECORDER_KICK_ADDR, 0);
    litepcie_writel (unit->fd, CSR_RECORDER_KICK_ADDR, 1);

    uint32_t cnt = 0;

    while (!(litepcie_readl (unit->fd, CSR_RECORDER_DONE_ADDR) & 1))
    {
      cnt++;

      if (cnt >= DRAIN_SHORT_TIMEOUT)
      {
            return total_drained;
      }
    }

    uint32_t captured = litepcie_readl (unit->fd, CSR_RECORDER_COUNT_ADDR);

    if (captured == 0)
    {
      return total_drained;
    }

    // MUST read the data to fully clear the FIFO
    size_t read_len = captured < sizeof(discard_buf) ? captured : sizeof(discard_buf);
    read_bytes (unit->fd, RECORDER_MEM_BASE, discard_buf, read_len);

    packets_drained++;
    total_drained += captured;
  }

  return total_drained;
}

/**
 * Detect FPGA configuration from identifier string
 *
 * CRITICAL: Read identifier one character per 32-bit read
 * (from kernel module behavior)
 */

static bool detect_fpga_config (unit_t *unit)
{
  char ident[256];

  // Read identifier: one character per 32-bit read
  for (int i = 0; i < 256; i++)
  {
    uint32_t w = litepcie_readl (unit->fd, CSR_IDENTIFIER_MEM_BASE + i * 4);

    ident[i] = (char) (w & 0xFF);

    if (ident[i] == 0) break;
  }

  ident[255] = 0;

  // Parse identifier for proxy/core counts: "(pN x cM)"
  char *p = strstr (ident, "(p");

  if (p != NULL)
  {
    int proxies = 0, cores = 0;

    if (sscanf (p, "(p%d x c%d)", &proxies, &cores) == 2)
    {
      unit->num_proxies = proxies;
      unit->cores_per_proxy = cores;
      unit->total_cores = proxies * cores;

      unit->workitem_count = BASE_WORKITEM_COUNT * unit->total_cores;

      if (unit->workitem_count > MAX_WORKITEM_COUNT)
      {
        unit->workitem_count = MAX_WORKITEM_COUNT;
      }

      unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf),
                                      "LiteX bcrypt FPGA: %s", ident);

      return true;
    }
  }

  // Fallback
  unit->num_proxies = 1;
  unit->cores_per_proxy = 1;
  unit->total_cores = 1;
  unit->workitem_count = BASE_WORKITEM_COUNT;

  unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf),
                                  "LiteX bcrypt FPGA: %s", ident);

  return true;
}

/**
 * Calculate sub-batch size based on password lengths
 */

static u32 calculate_sub_batch_size (const bcrypt_fpga_tmp_t *bcrypt_tmp, u64 pws_cnt)
{
  u32 sub_batch = 0;
  size_t payload_size = 0;

  for (u64 i = 0; i < pws_cnt; i++)
  {
    size_t pw_packet_size = bcrypt_tmp[i].pw_len + 1;  // +1 for null terminator

    if (payload_size + pw_packet_size > MAX_PAYLOAD_SIZE) break;

    payload_size += pw_packet_size;
    sub_batch++;
  }

  return sub_batch > 0 ? sub_batch : 1;
}

/**
 * Initialize FPGA units
 */

static bool units_init (bridge_litex_bcrypt_t *bridge)
{
  bridge->units_buf = (unit_t *) hccalloc (MAX_FPGA_DEVICES, sizeof (unit_t));
  bridge->units_cnt = 0;

  for (int i = 0; i < MAX_FPGA_DEVICES; i++)
  {
    char path[64];

    snprintf (path, sizeof (path), "/dev/litepcie%d", i);

    int fd = open (path, O_RDWR);

    if (fd < 0) continue;

    unit_t *unit = &bridge->units_buf[bridge->units_cnt];

    unit->fd = fd;
    strncpy (unit->device_path, path, sizeof (unit->device_path) - 1);

    unit->streamer_buf = (uint8_t *) hcmalloc (STREAMER_MEM_SIZE);
    unit->recorder_buf = (uint8_t *) hcmalloc (RECORDER_MEM_SIZE);
    unit->next_pkt_id = 0;

    if (!detect_fpga_config (unit))
    {
      hcfree (unit->streamer_buf);
      hcfree (unit->recorder_buf);
      close (fd);
      continue;
    }

    // Drain any leftover packets
    drain_output_fifo (unit);

    bridge->units_cnt++;
  }

  return bridge->units_cnt > 0;
}

/**
 * Bridge interface functions
 */

void *platform_init (MAYBE_UNUSED user_options_t *user_options)
{
  bridge_litex_bcrypt_t *bridge = (bridge_litex_bcrypt_t *) hcmalloc (sizeof (bridge_litex_bcrypt_t));

  if (units_init (bridge) == false)
  {
    hcfree (bridge);
    return NULL;
  }

  return bridge;
}

void platform_term (void *platform_context)
{
  bridge_litex_bcrypt_t *bridge = platform_context;

  if (bridge != NULL)
  {
    for (int i = 0; i < bridge->units_cnt; i++)
    {
      unit_t *unit = &bridge->units_buf[i];

      if (unit->fd >= 0)
      {
        close (unit->fd);
      }

      hcfree (unit->streamer_buf);
      hcfree (unit->recorder_buf);
    }

    hcfree (bridge->units_buf);
    hcfree (bridge);
  }
}

int get_unit_count (void *platform_context)
{
  bridge_litex_bcrypt_t *bridge = platform_context;

  return bridge->units_cnt;
}

char *get_unit_info (void *platform_context, const int unit_idx)
{
  bridge_litex_bcrypt_t *bridge = platform_context;

  unit_t *unit = &bridge->units_buf[unit_idx];

  return unit->unit_info_buf;
}

int get_workitem_count (void *platform_context, const int unit_idx)
{
  bridge_litex_bcrypt_t *bridge = platform_context;

  unit_t *unit = &bridge->units_buf[unit_idx];

  return unit->workitem_count;
}

bool salt_prepare (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  return true;
}

void salt_destroy (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
}

/**
 * Main launch loop - process passwords against FPGA
 *
 * Protocol (from cleanup2_test.c):
 * 1. Start recorder (kick toggle: write 0, then write 1)
 * 2. Send CMP_CONFIG packet
 * 3. Send WORD_GEN packet (empty for -a0 mode)
 * 4. Send WORD_LIST packet
 * 5. Wait for recorder done
 * 6. Read response
 */

bool launch_loop (void *platform_context, hc_device_param_t *device_param,
                  MAYBE_UNUSED hashconfig_t *hashconfig, hashes_t *hashes,
                  const u32 salt_pos, const u64 pws_cnt)
{
  bridge_litex_bcrypt_t *bridge = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit = &bridge->units_buf[unit_idx];

  // Force-reset FPGA via clear_error CSR (unsticks inpkt_header if in PKT_STATE_ERROR)
  litepcie_writel(unit->fd, CSR_BCRYPT_CLEAR_ERROR_ADDR, 1);

  // Send reset and drain any stale data (like cleanup2_test does)
  {
    uint8_t reset_pl[1] = {0xCC};
    uint8_t reset_hdr[10];
    // Use packet ID 0x0000 for reset (like cleanup2_test)
    build_header(reset_hdr, PKT_TYPE_RESET, 0x0000, 1);
    uint8_t pkt_reset[32];
    size_t pkt_reset_len = 0;
    add_checksums_around_payload(pkt_reset, &pkt_reset_len, reset_hdr, 10, reset_pl, 1);
    kick_streamer(unit, pkt_reset, pkt_reset_len);
  }
  // Drain AFTER reset, BEFORE starting work
  drain_output_fifo(unit);

  // Clear error latch after reset (in case error_r was latched from a previous run)
  litepcie_writel(unit->fd, CSR_BCRYPT_CLEAR_ERROR_ADDR, 1);

  // Reset packet ID counter after reset
  unit->next_pkt_id = 1;

  // Get salt information
  salt_t *salts_buf = (salt_t *) hashes->salts_buf;
  salt_t *salt_buf = &salts_buf[salt_pos];

  // Get digests for this salt
  u32 *digests_buf = (u32 *) hashes->digests_buf;
  u32 digests_offset = salt_buf->digests_offset;
  u32 digests_cnt = salt_buf->digests_cnt;

  // Workaround: During self-test, salt_buf->digests_cnt may be 0
  if (digests_cnt == 0 && hashes->salts_cnt == 1 && hashes->digests_cnt > 0)
  {
    digests_cnt = hashes->digests_cnt;
  }

  bcrypt_fpga_tmp_t *bcrypt_tmp = (bcrypt_fpga_tmp_t *) device_param->h_tmps;

  // Clear cracked flags
  for (u64 i = 0; i < pws_cnt; i++)
  {
    bcrypt_tmp[i].cracked = 0;
  }

  // Build salt16 from salt_buf
  uint8_t salt16[16];

  memcpy (salt16, salt_buf->salt_buf, 16);

  // Get bcrypt subtype from salt_sign
  const char *salt_sign_str = (const char *) salt_buf->salt_sign;
  uint8_t subtype = 'a';

  if (salt_sign_str[2] != 0)
  {
    subtype = salt_sign_str[2];
  }

  // Build target hashes array (first 4 bytes of each hash for comparison)
  uint32_t *target_hashes = (uint32_t *) hcmalloc (digests_cnt * sizeof (uint32_t));

  for (u32 i = 0; i < digests_cnt; i++)
  {
    u32 *digest = &digests_buf[(digests_offset + i) * 6];
    target_hashes[i] = digest[0];
  }

  // Build CMP_CONFIG packet
  uint8_t cmp_pl[512];
  size_t cmp_pl_len = 0;

  build_cmp_config_payload_bcrypt (cmp_pl, &cmp_pl_len,
                                   salt_buf->salt_iter,
                                   salt16, subtype,
                                   digests_cnt, target_hashes);

  uint8_t cmp_hdr[10];

  build_header (cmp_hdr, PKT_TYPE_CMP_CONFIG, unit->next_pkt_id++, cmp_pl_len);

  uint8_t pkt_cmp[1024];
  size_t pkt_cmp_len = 0;

  add_checksums_around_payload (pkt_cmp, &pkt_cmp_len, cmp_hdr, 10, cmp_pl, cmp_pl_len);

  // target_hashes freed at cleanup label

  // Build WORD_GEN packet (empty for -a0 mode)
  uint8_t wg_pl[16];
  size_t wg_pl_len = 0;

  build_empty_word_gen_payload (wg_pl, &wg_pl_len);

  uint8_t wg_hdr[10];

  build_header (wg_hdr, PKT_TYPE_WORD_GEN, unit->next_pkt_id++, wg_pl_len);

  uint8_t pkt_wg[64];
  size_t pkt_wg_len = 0;

  add_checksums_around_payload (pkt_wg, &pkt_wg_len, wg_hdr, 10, wg_pl, wg_pl_len);

  // Process passwords in sub-batches (1KB buffer limit)
  u64 processed = 0;
  bool first_batch = true;

  while (processed < pws_cnt)
  {
    u32 sub_batch = calculate_sub_batch_size (&bcrypt_tmp[processed], pws_cnt - processed);

    if (sub_batch > MAX_SUB_BATCH_SIZE)
    {
      sub_batch = MAX_SUB_BATCH_SIZE;
    }

    // Build WORD_LIST packet for this sub-batch
    const u8 *words[MAX_SUB_BATCH_SIZE];
    u32 word_lens[MAX_SUB_BATCH_SIZE];

    for (u32 i = 0; i < sub_batch; i++)
    {
      words[i] = (const u8 *) bcrypt_tmp[processed + i].pw_buf;
      word_lens[i] = bcrypt_tmp[processed + i].pw_len;
    }

    uint8_t wl_pl[MAX_PAYLOAD_SIZE + 64];
    size_t wl_pl_len = 0;

    build_word_list_payload (wl_pl, &wl_pl_len, words, word_lens, sub_batch);

    uint8_t wl_hdr[10];

    build_header (wl_hdr, PKT_TYPE_WORD_LIST, unit->next_pkt_id++, wl_pl_len);

    uint8_t pkt_wl[MAX_PAYLOAD_SIZE + 64];
    size_t pkt_wl_len = 0;

    add_checksums_around_payload (pkt_wl, &pkt_wl_len, wl_hdr, 10, wl_pl, wl_pl_len);

    // Protocol: start recorder BEFORE sending packets
    start_recorder (unit);

    // First batch: send CMP_CONFIG, WORD_GEN, then WORD_LIST
    if (first_batch)
    {
      if (!kick_streamer (unit, pkt_cmp, pkt_cmp_len))
      {
        drain_output_fifo (unit);
        return false;
      }

      if (!kick_streamer (unit, pkt_wg, pkt_wg_len))
      {
        drain_output_fifo (unit);
        return false;
      }

      first_batch = false;
    }

    // Send WORD_LIST
    if (!kick_streamer (unit, pkt_wl, pkt_wl_len))
    {
      drain_output_fifo (unit);
      return false;
    }

    // Wait for recorder
    uint32_t recorder_len = 0;

    if (!wait_recorder (unit, &recorder_len))
    {
      drain_output_fifo (unit);
      return false;
    }

    // Process response
    if (recorder_len > 0 && recorder_len <= RECORDER_MEM_SIZE)
    {
      read_bytes (unit->fd, RECORDER_MEM_BASE, unit->recorder_buf, recorder_len);

      if (recorder_len >= 2)
      {
        uint8_t version = unit->recorder_buf[0];
        uint8_t pkt_type = unit->recorder_buf[1];

        if (version == PKT_VERSION && pkt_type == PKT_RESP_CMP_RESULT)
        {
          // Match found - extract word_id from response
          // word_id is a single byte at offset 14 (from cleanup2_test.c)
          if (recorder_len >= 15)
          {
            uint8_t local_word_id = unit->recorder_buf[14];

            if (local_word_id < sub_batch)
            {
              u64 global_word_id = processed + local_word_id;

              // FPGA already confirmed the match - trust it
              bcrypt_tmp[global_word_id].cracked = 1;
            }
          }

          // Drain PACKET_DONE that follows CMP_RESULT
          start_recorder (unit);

          uint32_t drain_len = 0;

          if (wait_recorder (unit, &drain_len))
          {
            if (drain_len > 0)
            {
              // MUST read the data to clear the FIFO
              uint8_t drain_buf[64];
              size_t read_len = drain_len < sizeof(drain_buf) ? drain_len : sizeof(drain_buf);
              read_bytes (unit->fd, RECORDER_MEM_BASE, drain_buf, read_len);
            }
          }
          
          // Found a match - stop processing this batch
          goto cleanup;
        }
      }
    }

    processed += sub_batch;
  }

  // Check for FPGA errors
  uint32_t err = litepcie_readl (unit->fd, CSR_BCRYPT_ERROR_ADDR);

  if (err != 0)
  {
    drain_output_fifo (unit);
  }

cleanup:
  hcfree(target_hashes);
  return true;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size       = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version  = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init       = platform_init;
  bridge_ctx->platform_term       = platform_term;
  bridge_ctx->get_unit_count      = get_unit_count;
  bridge_ctx->get_unit_info       = get_unit_info;
  bridge_ctx->get_workitem_count  = get_workitem_count;
  bridge_ctx->thread_init         = BRIDGE_DEFAULT;
  bridge_ctx->thread_term         = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare        = salt_prepare;
  bridge_ctx->salt_destroy        = salt_destroy;
  bridge_ctx->launch_loop         = launch_loop;
  bridge_ctx->launch_loop2        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash      = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass      = BRIDGE_DEFAULT;
}
