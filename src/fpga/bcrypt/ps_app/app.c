/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "gem.h"
#include "udp.h"
#include "proto.h"
#include "hcfpga_aead.h"

#define PL_BASE           0x40000000

#define R_CTRL            0x00
#define R_SALT0           0x04
#define R_SALT1           0x08
#define R_SALT2           0x0C
#define R_SALT3           0x10
#define R_ITER            0x14
#define R_STATUS          0x18
#define R_CORE_COUNT      0x1C
#define R_CMP0            0x20
#define R_CMP1            0x24
#define R_CMP2            0x28
#define R_CMP3            0x2C
#define R_BATCH           0x30
#define R_PAD             0x34
#define R_RETIRED         0x38
#define R_TX_DATA         0x40
#define R_TX_STAT         0x44
#define R_RX_DATA         0x48
#define R_RX_STAT         0x4C
#define R_MAGIC           0x5C

#define SHELL_MAGIC       0x7A700068

#define TX_STAT_FULL      0x00000001
#define TX_LEVEL_SHIFT    16

#define XADC_CFG          0xF8007100
#define XADC_MSTS         0xF800710C
#define XADC_CMDFIFO      0xF8007110
#define XADC_RDFIFO       0xF8007114
#define XADC_MCTL         0xF8007118

#define XADC_REG_TEMP     0x00

#define GT_COUNTER_LO     0xF8F00200
#define GT_COUNTER_HI     0xF8F00204
#define GT_CONTROL        0xF8F00208

#define GT_HZ             325000000

#define LOG_BASE          0x00010000
#define LOG_MAGIC_VALUE   0xB0DEC0DE
#define LOG_MAX_SAMPLES   4000

#define LOG_MAGIC         (LOG_BASE + 0x00)
#define LOG_COUNT         (LOG_BASE + 0x04)
#define LOG_STATE         (LOG_BASE + 0x08)
#define LOG_PUSHED        (LOG_BASE + 0x0C)
#define LOG_SAMPLES       (LOG_BASE + 0x10)

#define LOG_STATE_INIT    1
#define LOG_STATE_RUNNING 2
#define LOG_STATE_NOSHELL 3

#define SAMPLE_WORDS      4

#define PUSH_PER_SAMPLE   512

static inline void wr32 (const u32 addr, const u32 val)
{
  *(volatile u32 *) addr = val;
}

static inline u32 rd32 (const u32 addr)
{
  return *(volatile u32 *) addr;
}

static inline void pl_w (const u32 off, const u32 val)
{
  wr32 (PL_BASE + off, val);
}

static inline u32 pl_r (const u32 off)
{
  return rd32 (PL_BASE + off);
}

static void delay_loop (const u32 n)
{
  for (volatile u32 i = 0; i < n; i++);
}

static void xadc_init (void)
{
  wr32 (XADC_MCTL, 0x00000010);
  wr32 (XADC_MCTL, 0x00000000);

  wr32 (XADC_CFG, 0x80003214);

  delay_loop (10000);
}

static u32 xadc_read (const u32 reg)
{
  wr32 (XADC_CMDFIFO, 0x04000000 | (reg << 16));
  wr32 (XADC_CMDFIFO, 0x00000000);

  delay_loop (2000);

  rd32 (XADC_RDFIFO);

  const u32 v = rd32 (XADC_RDFIFO);

  return v & 0xFFFF;
}

static u32 xadc_temp_raw (void)
{
  const u32 raw = xadc_read (XADC_REG_TEMP);

  return raw;
}

static void timer_init (void)
{
  wr32 (GT_CONTROL, 0x00000000);
  wr32 (GT_COUNTER_LO, 0x00000000);
  wr32 (GT_COUNTER_HI, 0x00000000);
  wr32 (GT_CONTROL, 0x00000001);
}

static u32 timer_now (void)
{
  return rd32 (GT_COUNTER_LO);
}

static void push_record (const u32 ekid)
{
  pl_w (R_TX_DATA, (0xbc << 24) | 8);
  pl_w (R_TX_DATA, ekid);
  pl_w (R_TX_DATA, 0x70617373);
  pl_w (R_TX_DATA, 0x776F7264);
}

static u32 tx_level (void)
{
  const u32 st = pl_r (R_TX_STAT);

  return st >> TX_LEVEL_SHIFT;
}

static void shell_configure (void)
{
  pl_w (R_CTRL, 0x00000001);

  delay_loop (10000);

  pl_w (R_CTRL, 0x00000000);

  delay_loop (10000);

  pl_w (R_SALT0, 0x01234567);
  pl_w (R_SALT1, 0x89ABCDEF);
  pl_w (R_SALT2, 0xFEDCBA98);
  pl_w (R_SALT3, 0x76543210);

  pl_w (R_ITER, 32);
  pl_w (R_PAD, 0);

  pl_w (R_CMP0, 0x00000000);
  pl_w (R_CMP1, 0x00000000);
  pl_w (R_CMP2, 0x00000000);

  pl_w (R_CMP3, 0x00000000);

  pl_w (R_BATCH, 0x00000000);
}

static void log_sample (const u32 index, const u32 t, const u32 temp, const u32 retired, const u32 lvl)
{
  const u32 base = LOG_SAMPLES + (index * SAMPLE_WORDS * 4);

  wr32 (base + 0,  t);
  wr32 (base + 4,  temp);
  wr32 (base + 8,  retired);
  wr32 (base + 12, lvl);
}

static u8 rxbuf[HC_MAX_DATAGRAM];
static u8 txbuf[HC_MAX_DATAGRAM];

static u32 rd_le32 (const u8 *p)
{
  return ((u32) p[0] << 0) | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24);
}

static void wr_le32 (u8 *p, const u32 v)
{
  p[0] = (u8) (v >> 0);
  p[1] = (u8) (v >> 8);
  p[2] = (u8) (v >> 16);
  p[3] = (u8) (v >> 24);
}

static u8   session_key[HCFPGA_AEAD_KEY_BYTES];
static u32  session_gen = 0;
static bool session_ok  = false;

static u64  rx_seq      = 0;
static u64  tx_seq      = 0;

static bool key_take (void)
{
  const u32 m1 = rd32 (HC_KEY_ADDR + 0x00);
  const u32 g1 = rd32 (HC_KEY_ADDR + 0x04);

  if (m1 != HC_KEY_MAGIC) return false;
  if ((g1 & 1) != 0)      return false;

  for (u32 i = 0; i < 8; i++) wr_le32 (&session_key[i * 4], rd32 (HC_KEY_ADDR + 0x08 + (i * 4)));

  const u32 g2 = rd32 (HC_KEY_ADDR + 0x04);
  const u32 m2 = rd32 (HC_KEY_ADDR + 0x00);

  if (g2 != g1)           return false;
  if (m2 != HC_KEY_MAGIC) return false;

  session_gen = g1;

  rx_seq = 0;
  tx_seq = 0;

  return true;
}

static void key_check (void)
{
  if ((session_ok == true) && (rd32 (HC_KEY_ADDR + 0x04) == session_gen)) return;

  session_ok = key_take ();
}

static void seal_nonce (u8 *nonce, const u32 dir, const u64 seq)
{
  wr_le32 (&nonce[0], dir);
  wr_le32 (&nonce[4], (u32) (seq >>  0));
  wr_le32 (&nonce[8], (u32) (seq >> 32));
}

static void reply (const u8 op, const u32 len)
{
  if (session_ok == false) return;

  tx_seq++;

  txbuf[0] = op;
  txbuf[1] = 0;
  txbuf[2] = (u8) (len & 0xFF);
  txbuf[3] = (u8) (len >> 8);

  wr_le32 (&txbuf[4], (u32) (tx_seq >>  0));
  wr_le32 (&txbuf[8], (u32) (tx_seq >> 32));

  u8 nonce[HCFPGA_AEAD_NONCE_BYTES];

  seal_nonce (nonce, HC_DIR_TO_HOST, tx_seq);

  hcfpga_aead_seal (session_key, nonce, txbuf, HC_SEAL_HDR, &txbuf[HC_SEAL_HDR], len, &txbuf[HC_SEAL_HDR + len]);

  udp_send (txbuf, HC_SEAL_HDR + len + HC_TAG_BYTES);
}

#define HC_NOT_OURS       0xFFFFFFFF

static u32 open_datagram (const u32 got, const udp_peer_t *from)
{
  if (got > sizeof (rxbuf)) return HC_NOT_OURS;

  if (got < (HC_SEAL_HDR + HC_TAG_BYTES)) return HC_NOT_OURS;

  const u32 len = (u32) rxbuf[2] | ((u32) rxbuf[3] << 8);

  if (got != (HC_SEAL_HDR + len + HC_TAG_BYTES)) return HC_NOT_OURS;

  key_check ();

  if (session_ok == false) return HC_NOT_OURS;

  const u64 seq = (u64) rd_le32 (&rxbuf[4]) | ((u64) rd_le32 (&rxbuf[8]) << 32);

  if (seq <= rx_seq) return HC_NOT_OURS;

  u8 nonce[HCFPGA_AEAD_NONCE_BYTES];

  seal_nonce (nonce, HC_DIR_TO_BOARD, seq);

  if (hcfpga_aead_open (session_key, nonce, rxbuf, HC_SEAL_HDR, &rxbuf[HC_SEAL_HDR], len, &rxbuf[HC_SEAL_HDR + len]) == false) return HC_NOT_OURS;

  rx_seq = seq;

  udp_set_peer (from);

  return len;
}

static u32 feed_pos = 0;

static void do_config (const u8 *p)
{
  pl_w (R_SALT0, rd_le32 (&p[0]));
  pl_w (R_SALT1, rd_le32 (&p[4]));
  pl_w (R_SALT2, rd_le32 (&p[8]));
  pl_w (R_SALT3, rd_le32 (&p[12]));
  pl_w (R_ITER,  rd_le32 (&p[16]));

  pl_w (R_CMP0, rd_le32 (&p[20]));
  pl_w (R_CMP1, rd_le32 (&p[24]));
  pl_w (R_CMP2, rd_le32 (&p[28]));

  pl_w (R_CMP3, rd_le32 (&p[32]));

  pl_w (R_PAD, (u32) p[36] | ((u32) p[37] << 8));

  pl_w (R_BATCH, rd_le32 (&p[38]));

  feed_pos = 0;
}

static bool array_held = false;

static void drain_results (void)
{
  u32 n = 0;

  for (;;)
  {
    if ((pl_r (R_RX_STAT) >> 16) < HC_RESULT_REC) break;

    for (u32 i = 0; i < HC_RESULT_REC; i++)
    {
      txbuf[HC_SEAL_HDR + n + i] = (u8) (pl_r (R_RX_DATA) & 0xFF);
    }

    n += HC_RESULT_REC;

    if ((n + HC_RESULT_REC) > HC_MAX_PAYLOAD)
    {
      reply (HC_OP_RESULT, n);

      n = 0;
    }
  }

  if (n > 0) reply (HC_OP_RESULT, n);
}

#define FEED_WAIT_TICKS   GT_HZ

static u32 do_feed (const u8 *p, const u32 len)
{
  if (array_held == true) return 0;

  u32 off = 0;

  while ((off + 4) <= len)
  {
    const u32 t0 = timer_now ();

    while ((pl_r (R_TX_STAT) & TX_STAT_FULL) != 0)
    {
      drain_results ();

      if ((timer_now () - t0) > FEED_WAIT_TICKS) return off;
    }

    pl_w (R_TX_DATA, rd_le32 (&p[off]));

    wr32 (GEM_LOG_FEEDWORDS, rd32 (GEM_LOG_FEEDWORDS) + 1);

    off += 4;
  }

  return off;
}

static u32 shell_magic = 0;
static u32 shell_cores = 0;

extern const u8 _start[];
extern const u8 __image_end[];

static u32 image_crc = 0;

static u32 image_crc32 (void)
{
  const u32 len = (u32) __image_end - (u32) _start;

  u32 crc = 0xFFFFFFFF;

  for (u32 i = 0; i < len; i++)
  {
    crc ^= _start[i];

    for (u32 b = 0; b < 8; b++)
    {
      const u32 mask = 0 - (crc & 1);

      crc = (crc >> 1) ^ (0xEDB88320 & mask);
    }
  }

  const u32 result = ~crc;

  return result;
}

static void do_ping (void)
{
  const bool live = (array_held == false);

  wr_le32 (&txbuf[HC_SEAL_HDR + 0],  (live == true) ? pl_r (R_MAGIC)         : shell_magic);
  wr_le32 (&txbuf[HC_SEAL_HDR + 4],  (live == true) ? pl_r (R_CORE_COUNT)    : shell_cores);
  wr_le32 (&txbuf[HC_SEAL_HDR + 8],  (live == true) ? pl_r (R_RETIRED)       : 0);
  wr_le32 (&txbuf[HC_SEAL_HDR + 12], (u32) xadc_temp_raw ());
  wr_le32 (&txbuf[HC_SEAL_HDR + 16], rd32 (GEM_LOG_RXFRAMES));
  wr_le32 (&txbuf[HC_SEAL_HDR + 20], (live == true) ? (pl_r (R_TX_STAT) >> 16) : 0);
  wr_le32 (&txbuf[HC_SEAL_HDR + 24], image_crc);

  reply (HC_OP_PONG, HC_PONG_BYTES);
}

static void net_loop (void)
{
  u32 loops = 0;

  for (;;)
  {
    loops++;

    if ((loops & 0xFFF) == 0) wr32 (GEM_LOG_LOOPS, loops);

    udp_peer_t from;

    const u32 got = udp_recv (rxbuf, sizeof (rxbuf), &from);

    const u32 len = (got > 0) ? open_datagram (got, &from) : HC_NOT_OURS;

    if (len != HC_NOT_OURS)
    {
      const u8 op = rxbuf[0];

      wr32 (GEM_LOG_LASTOP, op);

      if (op == HC_OP_PING) do_ping ();

      if ((op == HC_OP_CONFIG) && (len == HC_CONFIG_BYTES)) do_config (&rxbuf[HC_SEAL_HDR]);

      if (op == HC_OP_FEED)
      {
        const u32 avail = len;

        u32 at = 0xFFFFFFFF;

        if (avail >= 4)
        {
          at = rd_le32 (&rxbuf[HC_SEAL_HDR + 0]);

          if (at == feed_pos) feed_pos += do_feed (&rxbuf[HC_SEAL_HDR + 4], avail - 4);
        }

        wr_le32 (&txbuf[HC_SEAL_HDR + 0], at);
        wr_le32 (&txbuf[HC_SEAL_HDR + 4], feed_pos);
        wr_le32 (&txbuf[HC_SEAL_HDR + 8], rd32 (GEM_LOG_FEEDWORDS));

        reply (HC_OP_FEED_ACK, 12);
      }

      if ((op == HC_OP_CSR_WR) && (len == 8))
      {
        const u32 off = rd_le32 (&rxbuf[HC_SEAL_HDR + 0]);
        const u32 val = rd_le32 (&rxbuf[HC_SEAL_HDR + 4]);

        const bool off_ok = (off < HC_CSR_MAX_OFF) && ((off & 3) == 0) && (off != R_TX_DATA);

        if (off_ok == true) pl_w (off, val);

        if (off == R_BATCH) feed_pos = 0;

        if (off == R_CTRL)
        {
          array_held = ((val & 0x00000001) != 0) ? true : false;

          if (array_held == true) feed_pos = 0;
        }
      }

      if ((op == HC_OP_CSR_RD) && (len == 4))
      {
        const u32 off = rd_le32 (&rxbuf[HC_SEAL_HDR + 0]);

        const bool rd_ok = (off < HC_CSR_MAX_OFF) && ((off & 3) == 0) && (array_held == false) && (off != R_RX_DATA);

        wr_le32 (&txbuf[HC_SEAL_HDR + 0], off);
        wr_le32 (&txbuf[HC_SEAL_HDR + 4], (rd_ok == true) ? pl_r (off) : 0);

        reply (HC_OP_CSR_VAL, 8);
      }

      if (op == HC_OP_RESET)
      {
        pl_w (R_CTRL, 0x00000001);
        delay_loop (10000);
        pl_w (R_CTRL, 0x00000000);

        array_held = false;

        feed_pos = 0;
      }
    }

    if (array_held == false) drain_results ();
  }
}

static void netcfg_take (void)
{
  if (rd32 (HC_NETCFG_ADDR + 0x00) != HC_NETCFG_MAGIC) return;

  const u32 ip  = rd32 (HC_NETCFG_ADDR + 0x04);
  const u32 mlo = rd32 (HC_NETCFG_ADDR + 0x08);
  const u32 mhi = rd32 (HC_NETCFG_ADDR + 0x0C);

  u8 ipb[4];
  u8 mac[6];

  ipb[0] = (u8) (ip >>  0);
  ipb[1] = (u8) (ip >>  8);
  ipb[2] = (u8) (ip >> 16);
  ipb[3] = (u8) (ip >> 24);

  mac[0] = (u8) (mlo >>  0);
  mac[1] = (u8) (mlo >>  8);
  mac[2] = (u8) (mlo >> 16);
  mac[3] = (u8) (mlo >> 24);
  mac[4] = (u8) (mhi >>  0);
  mac[5] = (u8) (mhi >>  8);

  udp_set_ip (ipb);
  gem_set_mac (mac);
}

int main (void)
{
  image_crc = image_crc32 ();

  netcfg_take ();

  wr32 (LOG_MAGIC, LOG_MAGIC_VALUE);
  wr32 (LOG_COUNT, 0);
  wr32 (LOG_PUSHED, 0);
  wr32 (LOG_STATE, LOG_STATE_INIT);

  timer_init ();
  xadc_init ();

  if (pl_r (R_MAGIC) != SHELL_MAGIC)
  {
    wr32 (LOG_STATE, LOG_STATE_NOSHELL);

    return 0;
  }

  shell_magic = pl_r (R_MAGIC);
  shell_cores = pl_r (R_CORE_COUNT);

  shell_configure ();

  if (udp_init () == true)
  {
    wr32 (LOG_STATE, LOG_STATE_RUNNING);

    net_loop ();
  }

  wr32 (LOG_STATE, LOG_STATE_RUNNING);

  u32 ekid    = 0x1000;
  u32 pushed  = 0;
  u32 samples = 0;

  log_sample (samples, timer_now (), xadc_temp_raw (), pl_r (R_RETIRED), tx_level ());

  samples++;

  wr32 (LOG_COUNT, samples);

  while (samples < LOG_MAX_SAMPLES)
  {
    for (u32 i = 0; i < PUSH_PER_SAMPLE; i++)
    {
      while ((pl_r (R_TX_STAT) & TX_STAT_FULL) != 0);

      push_record (ekid);

      ekid++;
      pushed++;
    }

    log_sample (samples, timer_now (), xadc_temp_raw (), pl_r (R_RETIRED), tx_level ());

    samples++;

    wr32 (LOG_COUNT, samples);
    wr32 (LOG_PUSHED, pushed);
  }

  return 0;
}
