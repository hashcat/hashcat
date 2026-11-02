/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_GEM_H
#define HC_GEM_H

typedef unsigned long long u64;
typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char  u8;
typedef int            bool;

#define true  1
#define false 0

#define GEM0_BASE           0xE000B000

#define GEM_NET_CTRL        0x000
#define GEM_NET_CFG         0x004
#define GEM_NET_STATUS      0x008
#define GEM_DMACR           0x010
#define GEM_TX_STATUS       0x014
#define GEM_RX_QBAR         0x018
#define GEM_TX_QBAR         0x01C
#define GEM_RX_STATUS       0x020
#define GEM_PHY_MAINT       0x034

#define GEM_SPEC_ADDR1_BOT  0x088
#define GEM_SPEC_ADDR1_TOP  0x08C

#define GEM_NET_CTRL_MDEN   (1u << 4)
#define GEM_NET_CTRL_TXEN   (1u << 3)
#define GEM_NET_CTRL_RXEN   (1u << 2)
#define GEM_NET_CTRL_STARTTX (1u << 9)

#define GEM_NET_CTRL_FLUSH_RX (1u << 18)

#define GEM_RXD_SOF         (1u << 14)
#define GEM_RXD_EOF         (1u << 15)

#define GEM_NET_STATUS_MDIO_IDLE (1u << 2)

#define GEM_RX_STATUS_BNA   (1u << 0)
#define GEM_RX_STATUS_DONE  (1u << 1)
#define GEM_RX_STATUS_OVR   (1u << 2)

#define PHY_ADDR            1

#define PHY_REG_BMCR        0
#define PHY_REG_BMSR        1
#define PHY_REG_ID1         2
#define PHY_REG_ID2         3
#define PHY_REG_GBCR        9
#define PHY_REG_PHYSR       17

#define PHY_BMSR_LINK       (1u << 2)
#define PHY_BMSR_ANEG_DONE  (1u << 5)

#define GEM_TXDESC          0x00009000
#define GEM_RXDESC          0x00009100
#define GEM_TXBUF           0x0000A000
#define GEM_RXBUF           0x00020000

#define GEM_RX_RING         32
#define GEM_RXBUF_SIZE      1536

#define HC_ETHERTYPE        0x88B5

#define GEM_LOG_BASE        0x0000F000
#define GEM_LOG_MAGIC       (GEM_LOG_BASE + 0x00)
#define GEM_LOG_PHYID       (GEM_LOG_BASE + 0x04)
#define GEM_LOG_BMSR        (GEM_LOG_BASE + 0x08)
#define GEM_LOG_SPEED       (GEM_LOG_BASE + 0x0C)
#define GEM_LOG_TXFRAMES    (GEM_LOG_BASE + 0x10)
#define GEM_LOG_RXFRAMES    (GEM_LOG_BASE + 0x14)
#define GEM_LOG_LINKWAIT    (GEM_LOG_BASE + 0x18)
#define GEM_LOG_STATE       (GEM_LOG_BASE + 0x1C)
#define GEM_LOG_TXFAIL      (GEM_LOG_BASE + 0x20)

#define GEM_LOG_LOOPS       (GEM_LOG_BASE + 0x24)
#define GEM_LOG_LASTOP      (GEM_LOG_BASE + 0x28)
#define GEM_LOG_FEEDWORDS   (GEM_LOG_BASE + 0x2C)
#define GEM_LOG_RXSTATUS    (GEM_LOG_BASE + 0x30)
#define GEM_LOG_BNARESET    (GEM_LOG_BASE + 0x34)

#define GEM_LOG_RESYNC      (GEM_LOG_BASE + 0x38)

#define GEM_LOG_MAGIC_VALUE 0x6E657430

#define GEM_STATE_INIT      1
#define GEM_STATE_NOPHY     2
#define GEM_STATE_NOLINK    3
#define GEM_STATE_UP        4

bool gem_init (void);

void gem_set_mac (const u8 *mac);

bool gem_send (const u8 *dst, const u8 *payload, const u32 len);

u32 gem_recv (u8 *payload, const u32 max);

bool gem_send_raw (const u8 *dst, const u8 *body, const u32 body_len);

u32 gem_recv_frame (const volatile u8 **frame);

void gem_our_mac (u8 *mac);

void gem_peer (u8 *mac);

#endif
