/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "gem.h"

#define SLCR_LOCK           0xF8000004
#define SLCR_UNLOCK         0xF8000008
#define SLCR_GEM0_CLK_CTRL  0xF8000140

#define SLCR_UNLOCK_KEY     0x0000DF0D
#define SLCR_LOCK_KEY       0x0000767B

static u8 OUR_MAC[6] = { 0x00, 0x0A, 0x35, 0x00, 0x1E, 0x53 };

static u8 PEER_MAC[6];

static u32 TX_SLOT;

static u32 RX_NEXT;

static u32 RX_HELD = GEM_RX_RING;

static u32 IDLE_POLLS;

#define RX_STALL_POLLS 50000

static inline void wr32 (const u32 addr, const u32 val)
{
  *(volatile u32 *) addr = val;
}

static inline u32 rd32 (const u32 addr)
{
  return *(volatile u32 *) addr;
}

static inline void gem_w (const u32 off, const u32 val)
{
  wr32 (GEM0_BASE + off, val);
}

static inline u32 gem_r (const u32 off)
{
  return rd32 (GEM0_BASE + off);
}

static void spin (const u32 n)
{
  for (volatile u32 i = 0; i < n; i++);
}

static inline void dmb (void)
{
  __asm__ volatile ("dmb sy" ::: "memory");
}

static inline void dsb (void)
{
  __asm__ volatile ("dsb sy" ::: "memory");
}

static void mdio_wait (void)
{
  for (u32 i = 0; i < 200000; i++)
  {
    if ((gem_r (GEM_NET_STATUS) & GEM_NET_STATUS_MDIO_IDLE) != 0) return;
  }
}

static u16 mdio_read (const u32 reg)
{
  gem_w (GEM_PHY_MAINT, 0x60020000 | (PHY_ADDR << 23) | (reg << 18));

  mdio_wait ();

  return (u16) (gem_r (GEM_PHY_MAINT) & 0xFFFF);
}

static void tx_desc_set (const u32 len)
{
  const u32 slot  = TX_SLOT;
  const u32 other = slot ^ 1;

  const u32 wrap_slot  = (slot  == 1) ? 0x40000000 : 0x00000000;
  const u32 wrap_other = (other == 1) ? 0x40000000 : 0x00000000;

  wr32 (GEM_TXDESC + (other * 8) + 0, 0x00000000);
  wr32 (GEM_TXDESC + (other * 8) + 4, 0x80000000 | wrap_other);

  wr32 (GEM_TXDESC + (slot * 8) + 0, GEM_TXBUF);
  wr32 (GEM_TXDESC + (slot * 8) + 4, wrap_slot | 0x00008000 | (len & 0x3FFF));

  TX_SLOT = other;
}

static void rx_ring_init (void)
{
  RX_NEXT = 0;
  RX_HELD = GEM_RX_RING;

  for (u32 i = 0; i < GEM_RX_RING; i++)
  {
    const u32 d   = GEM_RXDESC + (i * 8);
    const u32 buf = GEM_RXBUF + (i * GEM_RXBUF_SIZE);

    u32 w0 = buf & 0xFFFFFFFC;

    if (i == (GEM_RX_RING - 1)) w0 |= 0x2;

    wr32 (d + 0, w0);
    wr32 (d + 4, 0x00000000);
  }
}

static void gem_set_speed (const u32 spd, const u32 duplex)
{
  u32 cfg = gem_r (GEM_NET_CFG);

  cfg = cfg & ~0x00000403u;

  if (duplex != 0) cfg |= 0x2;

  u32 clk = 0;

  if (spd == 2)
  {
    cfg |= 0x400;
    clk  = 0x00100801;
  }
  else if (spd == 1)
  {
    cfg |= 0x1;
    clk  = 0x00500801;
  }
  else
  {
    clk  = 0x03200801;
  }

  wr32 (SLCR_UNLOCK, SLCR_UNLOCK_KEY);
  wr32 (SLCR_GEM0_CLK_CTRL, clk);
  wr32 (SLCR_LOCK, SLCR_LOCK_KEY);

  gem_w (GEM_NET_CFG, cfg);
}

void gem_set_mac (const u8 *mac)
{
  for (u32 i = 0; i < 6; i++) OUR_MAC[i] = mac[i];
}

bool gem_init (void)
{
  wr32 (GEM_LOG_MAGIC, GEM_LOG_MAGIC_VALUE);
  wr32 (GEM_LOG_STATE, GEM_STATE_INIT);
  wr32 (GEM_LOG_TXFRAMES, 0);
  wr32 (GEM_LOG_RXFRAMES, 0);
  wr32 (GEM_LOG_TXFAIL, 0);
  wr32 (GEM_LOG_RXSTATUS, 0);
  wr32 (GEM_LOG_BNARESET, 0);
  wr32 (GEM_LOG_RESYNC, 0);
  wr32 (GEM_LOG_LOOPS, 0);
  wr32 (GEM_LOG_LASTOP, 0);
  wr32 (GEM_LOG_FEEDWORDS, 0);

  gem_w (GEM_NET_CTRL, 0x00000000);

  u32 cfg = gem_r (GEM_NET_CFG);

  cfg = (cfg & ~0x001C0000u) | 0x00100000u;

  gem_w (GEM_NET_CFG, cfg);
  gem_w (GEM_NET_CTRL, GEM_NET_CTRL_MDEN);

  const u32 id = ((u32) mdio_read (PHY_REG_ID1) << 16) | mdio_read (PHY_REG_ID2);

  wr32 (GEM_LOG_PHYID, id);

  if ((id == 0xFFFFFFFF) || (id == 0x00000000))
  {
    wr32 (GEM_LOG_STATE, GEM_STATE_NOPHY);

    return false;
  }

  u32 waited = 0;
  u32 bmsr   = 0;

  while (waited < 15000)
  {
    bmsr = mdio_read (PHY_REG_BMSR);

    if (((bmsr & PHY_BMSR_LINK) != 0) && ((bmsr & PHY_BMSR_ANEG_DONE) != 0)) break;

    spin (200000);

    waited = waited + 10;
  }

  wr32 (GEM_LOG_BMSR, bmsr);
  wr32 (GEM_LOG_LINKWAIT, waited);

  if (((bmsr & PHY_BMSR_LINK) == 0) || ((bmsr & PHY_BMSR_ANEG_DONE) == 0))
  {
    wr32 (GEM_LOG_STATE, GEM_STATE_NOLINK);

    return false;
  }

  const u16 physr  = mdio_read (PHY_REG_PHYSR);
  const u32 spd    = (physr >> 14) & 0x3;
  const u32 duplex = (physr >> 13) & 0x1;

  wr32 (GEM_LOG_SPEED, (spd << 1) | duplex);

  gem_set_speed (spd, duplex);

  gem_w (GEM_SPEC_ADDR1_BOT, ((u32) OUR_MAC[3] << 24) | ((u32) OUR_MAC[2] << 16)
                           | ((u32) OUR_MAC[1] <<  8) | ((u32) OUR_MAC[0] <<  0));

  gem_w (GEM_SPEC_ADDR1_TOP, ((u32) OUR_MAC[5] << 8) | ((u32) OUR_MAC[4] << 0));

  gem_w (GEM_DMACR, 0x00180704);

  TX_SLOT = 0;

  tx_desc_set (60);

  TX_SLOT = 0;

  rx_ring_init ();

  gem_w (GEM_TX_QBAR, GEM_TXDESC);
  gem_w (GEM_RX_QBAR, GEM_RXDESC);

  gem_w (GEM_NET_CTRL, GEM_NET_CTRL_MDEN | GEM_NET_CTRL_TXEN | GEM_NET_CTRL_RXEN);

  wr32 (GEM_LOG_STATE, GEM_STATE_UP);

  return true;
}

static bool gem_tx (const u32 total)
{
  tx_desc_set (total);

  gem_w (GEM_TX_STATUS, 0x000000FF);

  gem_w (GEM_NET_CTRL, GEM_NET_CTRL_MDEN | GEM_NET_CTRL_TXEN | GEM_NET_CTRL_RXEN);
  gem_w (GEM_NET_CTRL, GEM_NET_CTRL_MDEN | GEM_NET_CTRL_TXEN | GEM_NET_CTRL_RXEN | GEM_NET_CTRL_STARTTX);

  for (u32 i = 0; i < 100000; i++)
  {
    if ((gem_r (GEM_TX_STATUS) & 0x20) != 0)
    {
      gem_w (GEM_NET_CTRL, GEM_NET_CTRL_MDEN | GEM_NET_CTRL_TXEN | GEM_NET_CTRL_RXEN);

      wr32 (GEM_LOG_TXFRAMES, rd32 (GEM_LOG_TXFRAMES) + 1);

      return true;
    }
  }

  wr32 (GEM_LOG_TXFAIL, rd32 (GEM_LOG_TXFAIL) + 1);

  return false;
}

bool gem_send (const u8 *dst, const u8 *payload, const u32 len)
{
  volatile u8 *b = (volatile u8 *) GEM_TXBUF;

  for (u32 i = 0; i < 6; i++) b[i] = dst[i];
  for (u32 i = 0; i < 6; i++) b[6 + i] = OUR_MAC[i];

  b[12] = (u8) (HC_ETHERTYPE >> 8);
  b[13] = (u8) (HC_ETHERTYPE & 0xFF);

  for (u32 i = 0; i < len; i++) b[14 + i] = payload[i];

  u32 total = 14 + len;

  while (total < 60)
  {
    b[total] = 0x00;

    total++;
  }

  return gem_tx (total);
}

static void rx_resync (void)
{
  const u32 ctrl = gem_r (GEM_NET_CTRL);

  gem_w (GEM_NET_CTRL, ctrl & ~GEM_NET_CTRL_RXEN);

  rx_ring_init ();

  gem_w (GEM_RX_QBAR, GEM_RXDESC);
  gem_w (GEM_NET_CTRL, ctrl | GEM_NET_CTRL_RXEN);

  wr32 (GEM_LOG_RESYNC, rd32 (GEM_LOG_RESYNC) + 1);
}

static void link_recheck (void)
{
  const u16 bmsr = mdio_read (PHY_REG_BMSR);

  if ((bmsr & PHY_BMSR_LINK) == 0) return;
  if ((bmsr & PHY_BMSR_ANEG_DONE) == 0) return;

  const u16 physr  = mdio_read (PHY_REG_PHYSR);
  const u32 spd    = (physr >> 14) & 0x3;
  const u32 duplex = (physr >> 13) & 0x1;

  const u32 now = (spd << 1) | duplex;

  if (now == rd32 (GEM_LOG_SPEED)) return;

  gem_set_speed (spd, duplex);

  wr32 (GEM_LOG_BMSR, bmsr);
  wr32 (GEM_LOG_SPEED, now);
}

u32 gem_recv (u8 *payload, const u32 max)
{
  const u32 rxs = gem_r (GEM_RX_STATUS);

  if (rxs != 0)
  {
    wr32 (GEM_LOG_RXSTATUS, rd32 (GEM_LOG_RXSTATUS) | rxs);

    gem_w (GEM_RX_STATUS, rxs);

    if ((rxs & GEM_RX_STATUS_BNA) != 0)
    {
      gem_w (GEM_NET_CTRL, gem_r (GEM_NET_CTRL) | GEM_NET_CTRL_FLUSH_RX);

      wr32 (GEM_LOG_BNARESET, rd32 (GEM_LOG_BNARESET) + 1);
    }
  }

  for (u32 n = 0; n < GEM_RX_RING; n++)
  {
    const u32 k  = RX_NEXT;
    const u32 d  = GEM_RXDESC + (k * 8);
    const u32 w0 = rd32 (d + 0);

    if ((w0 & 0x1) == 0) break;

    IDLE_POLLS = 0;

    dmb ();

    const u32 w1  = rd32 (d + 4);
    const u32 len = w1 & 0x1FFF;

    RX_NEXT = (k + 1) & (GEM_RX_RING - 1);

    u32 out = 0;

    if (((w1 & GEM_RXD_SOF) != 0) && ((w1 & GEM_RXD_EOF) != 0) && (len > 14))
    {
      const volatile u8 *b = (const volatile u8 *) (w0 & 0xFFFFFFFC);

      const u16 type = (u16) (((u32) b[12] << 8) | b[13]);

      if (type == HC_ETHERTYPE)
      {
        out = len - 14;

        if (out > max) out = max;

        for (u32 i = 0; i < 6; i++) PEER_MAC[i] = b[6 + i];

        for (u32 i = 0; i < out; i++) payload[i] = b[14 + i];

        wr32 (GEM_LOG_RXFRAMES, rd32 (GEM_LOG_RXFRAMES) + 1);
      }
    }

    wr32 (d + 4, 0x00000000);

    dsb ();

    wr32 (d + 0, w0 & 0xFFFFFFFE);

    if (out > 0) return out;
  }

  IDLE_POLLS++;

  if (IDLE_POLLS < RX_STALL_POLLS) return 0;

  IDLE_POLLS = 0;

  link_recheck ();

  for (u32 k = 0; k < GEM_RX_RING; k++)
  {
    if (k == RX_NEXT) continue;

    const u32 w0 = rd32 (GEM_RXDESC + (k * 8));

    if ((w0 & 0x1) == 0) continue;

    rx_resync ();

    break;
  }

  return 0;
}

void gem_our_mac (u8 *mac)
{
  for (u32 i = 0; i < 6; i++) mac[i] = OUR_MAC[i];
}

bool gem_send_raw (const u8 *dst, const u8 *body, const u32 body_len)
{
  volatile u8 *b = (volatile u8 *) GEM_TXBUF;

  for (u32 i = 0; i < 6; i++) b[i] = dst[i];
  for (u32 i = 0; i < 6; i++) b[6 + i] = OUR_MAC[i];

  for (u32 i = 0; i < body_len; i++) b[12 + i] = body[i];

  u32 total = 12 + body_len;

  while (total < 60)
  {
    b[total] = 0x00;

    total++;
  }

  return gem_tx (total);
}

u32 gem_recv_frame (const volatile u8 **frame)
{
  if (RX_HELD != GEM_RX_RING)
  {
    const u32 hd = GEM_RXDESC + (RX_HELD * 8);
    const u32 hw = rd32 (hd + 0);

    wr32 (hd + 4, 0x00000000);

    dsb ();

    wr32 (hd + 0, hw & 0xFFFFFFFE);

    RX_HELD = GEM_RX_RING;
  }

  const u32 rxs = gem_r (GEM_RX_STATUS);

  if (rxs != 0)
  {
    wr32 (GEM_LOG_RXSTATUS, rd32 (GEM_LOG_RXSTATUS) | rxs);

    gem_w (GEM_RX_STATUS, rxs);

    if ((rxs & GEM_RX_STATUS_BNA) != 0)
    {
      gem_w (GEM_NET_CTRL, gem_r (GEM_NET_CTRL) | GEM_NET_CTRL_FLUSH_RX);

      wr32 (GEM_LOG_BNARESET, rd32 (GEM_LOG_BNARESET) + 1);
    }
  }

  for (u32 n = 0; n < GEM_RX_RING; n++)
  {
    const u32 k  = RX_NEXT;
    const u32 d  = GEM_RXDESC + (k * 8);
    const u32 w0 = rd32 (d + 0);

    if ((w0 & 0x1) == 0) break;

    IDLE_POLLS = 0;

    dmb ();

    const u32 w1  = rd32 (d + 4);
    const u32 len = w1 & 0x1FFF;

    RX_NEXT = (k + 1) & (GEM_RX_RING - 1);

    u32 out = 0;

    if (((w1 & GEM_RXD_SOF) != 0) && ((w1 & GEM_RXD_EOF) != 0) && (len > 14))
    {
      *frame = (const volatile u8 *) (w0 & 0xFFFFFFFC);

      out = len;

      wr32 (GEM_LOG_RXFRAMES, rd32 (GEM_LOG_RXFRAMES) + 1);
    }

    if (out > 0)
    {
      RX_HELD = k;

      return out;
    }

    wr32 (d + 4, 0x00000000);

    dsb ();

    wr32 (d + 0, w0 & 0xFFFFFFFE);
  }

  IDLE_POLLS++;

  if (IDLE_POLLS < RX_STALL_POLLS) return 0;

  IDLE_POLLS = 0;

  link_recheck ();

  for (u32 k = 0; k < GEM_RX_RING; k++)
  {
    if (k == RX_NEXT) continue;

    const u32 w0 = rd32 (GEM_RXDESC + (k * 8));

    if ((w0 & 0x1) == 0) continue;

    rx_resync ();

    break;
  }

  return 0;
}

void gem_peer (u8 *mac)
{
  for (u32 i = 0; i < 6; i++) mac[i] = PEER_MAC[i];
}
