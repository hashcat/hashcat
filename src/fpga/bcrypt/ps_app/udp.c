/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "udp.h"

static u8 OUR_IP[4] = { HC_IP0, HC_IP1, HC_IP2, HC_IP3 };

static u8   PEER_IP[4];
static u8   PEER_MAC_IP[6];
static u16  PEER_PORT;
static bool PEER_KNOWN;

static u8 TXF[1600];

static u16 rd_be16 (const volatile u8 *p)
{
  return (u16) (((u32) p[0] << 8) | (u32) p[1]);
}

static void wr_be16 (u8 *p, const u16 v)
{
  p[0] = (u8) (v >> 8);
  p[1] = (u8) (v >> 0);
}

static u16 checksum (const u8 *p, const u32 len)
{
  u32 sum = 0;

  for (u32 i = 0; (i + 1) < len; i += 2)
  {
    sum += ((u32) p[i] << 8) | (u32) p[i + 1];
  }

  if ((len & 1) != 0) sum += (u32) p[len - 1] << 8;

  while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);

  return (u16) (~sum & 0xFFFF);
}

static bool ip_is_ours (const volatile u8 *p)
{
  for (u32 i = 0; i < 4; i++)
  {
    if (p[i] != OUR_IP[i]) return false;
  }

  return true;
}

void udp_set_ip (const u8 *ip)
{
  for (u32 i = 0; i < 4; i++) OUR_IP[i] = ip[i];
}

bool udp_init (void)
{
  PEER_KNOWN = false;

  return gem_init ();
}

void udp_set_peer (const udp_peer_t *peer)
{
  for (u32 i = 0; i < 6; i++) PEER_MAC_IP[i] = peer->mac[i];
  for (u32 i = 0; i < 4; i++) PEER_IP[i]     = peer->ip[i];

  PEER_PORT  = peer->port;
  PEER_KNOWN = true;
}

static void arp_reply (const volatile u8 *f, const u32 len)
{
  if (len < 42) return;

  const volatile u8 *a = &f[14];

  if (rd_be16 (&a[0]) != 1) return;
  if (rd_be16 (&a[2]) != ETHERTYPE_IPV4) return;
  if (rd_be16 (&a[6]) != 1) return;

  if (ip_is_ours (&a[24]) == false) return;

  for (u32 i = 0; i < 6; i++) TXF[i] = a[8 + i];

  wr_be16 (&TXF[12], ETHERTYPE_ARP);

  wr_be16 (&TXF[14], 1);
  wr_be16 (&TXF[16], ETHERTYPE_IPV4);

  TXF[18] = 6;
  TXF[19] = 4;

  wr_be16 (&TXF[20], 2);

  gem_our_mac (&TXF[22]);

  for (u32 i = 0; i < 4; i++) TXF[28 + i] = OUR_IP[i];

  for (u32 i = 0; i < 6; i++) TXF[32 + i] = a[8 + i];
  for (u32 i = 0; i < 4; i++) TXF[38 + i] = a[14 + i];

  gem_send_raw (&TXF[0], &TXF[12], 42 - 12);
}

static void icmp_reply (const volatile u8 *f, const u32 iphl, const u32 iplen)
{
  const volatile u8 *ip = &f[14];
  const volatile u8 *ic = &ip[iphl];

  if (iplen < (iphl + 8)) return;

  if (ic[0] != 8) return;

  const u32 iclen = iplen - iphl;

  if ((14 + iplen) > sizeof (TXF)) return;

  for (u32 i = 0; i < 6; i++) TXF[i] = f[6 + i];

  wr_be16 (&TXF[12], ETHERTYPE_IPV4);

  u8 *oip = &TXF[14];
  u8 *oic = &oip[iphl];

  for (u32 i = 0; i < iplen; i++) oip[i] = ip[i];

  for (u32 i = 0; i < 4; i++) oip[12 + i] = OUR_IP[i];
  for (u32 i = 0; i < 4; i++) oip[16 + i] = ip[12 + i];

  oip[8] = 64;

  wr_be16 (&oip[10], 0);
  wr_be16 (&oip[10], checksum (oip, iphl));

  oic[0] = 0;

  wr_be16 (&oic[2], 0);
  wr_be16 (&oic[2], checksum (oic, iclen));

  gem_send_raw (&TXF[0], &TXF[12], 2 + iplen);
}

u32 udp_recv (u8 *payload, const u32 max, udp_peer_t *from)
{
  const volatile u8 *f = 0;

  const u32 len = gem_recv_frame (&f);

  if (len == 0) return 0;

  const u16 type = rd_be16 (&f[12]);

  if (type == ETHERTYPE_ARP)
  {
    arp_reply (f, len);

    return 0;
  }

  if (type != ETHERTYPE_IPV4) return 0;
  if (len < 34) return 0;

  const volatile u8 *ip = &f[14];

  if ((ip[0] >> 4) != 4) return 0;

  const u32 iphl = (u32) (ip[0] & 0x0F) * 4;

  if (iphl < 20) return 0;

  const u32 iplen = rd_be16 (&ip[2]);

  if (iplen < iphl) return 0;
  if ((14 + iplen) > len) return 0;

  if ((rd_be16 (&ip[6]) & 0x3FFF) != 0) return 0;

  if (ip_is_ours (&ip[16]) == false) return 0;

  if (ip[9] == IP_PROTO_ICMP)
  {
    icmp_reply (f, iphl, iplen);

    return 0;
  }

  if (ip[9] != IP_PROTO_UDP) return 0;

  const volatile u8 *ud = &ip[iphl];

  if ((iplen - iphl) < 8) return 0;

  if (rd_be16 (&ud[2]) != HC_UDP_PORT) return 0;

  const u32 ulen = rd_be16 (&ud[4]);

  if (ulen < 8) return 0;
  if ((iphl + ulen) > iplen) return 0;

  for (u32 i = 0; i < 6; i++) from->mac[i] = f[6 + i];
  for (u32 i = 0; i < 4; i++) from->ip[i]  = ip[12 + i];

  from->port = rd_be16 (&ud[0]);

  const u32 out = ulen - 8;

  if (out > max) return max + 1;

  for (u32 i = 0; i < out; i++) payload[i] = ud[8 + i];

  return out;
}

bool udp_send (const u8 *payload, const u32 len)
{
  if (PEER_KNOWN == false) return false;

  const u32 total = 14 + 20 + 8 + len;

  if (total > sizeof (TXF)) return false;

  for (u32 i = 0; i < 6; i++) TXF[i] = PEER_MAC_IP[i];

  wr_be16 (&TXF[12], ETHERTYPE_IPV4);

  u8 *ip = &TXF[14];

  ip[0] = 0x45;
  ip[1] = 0;

  wr_be16 (&ip[2], (u16) (20 + 8 + len));
  wr_be16 (&ip[4], 0);

  wr_be16 (&ip[6], 0x4000);

  ip[8] = 64;
  ip[9] = IP_PROTO_UDP;

  wr_be16 (&ip[10], 0);

  for (u32 i = 0; i < 4; i++) ip[12 + i] = OUR_IP[i];
  for (u32 i = 0; i < 4; i++) ip[16 + i] = PEER_IP[i];

  wr_be16 (&ip[10], checksum (ip, 20));

  u8 *ud = &ip[20];

  wr_be16 (&ud[0], HC_UDP_PORT);
  wr_be16 (&ud[2], PEER_PORT);
  wr_be16 (&ud[4], (u16) (8 + len));

  wr_be16 (&ud[6], 0);

  for (u32 i = 0; i < len; i++) ud[8 + i] = payload[i];

  return gem_send_raw (&TXF[0], &TXF[12], total - 12);
}
