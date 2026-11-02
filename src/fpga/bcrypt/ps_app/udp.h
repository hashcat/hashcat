/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_UDP_H
#define HC_UDP_H

#include "gem.h"

#define HC_IP0            192
#define HC_IP1            168
#define HC_IP2            224
#define HC_IP3            138

#define HC_UDP_PORT       31344

#define ETHERTYPE_IPV4    0x0800
#define ETHERTYPE_ARP     0x0806

#define IP_PROTO_ICMP     1
#define IP_PROTO_UDP      17

typedef struct udp_peer
{
  u8  mac[6];
  u8  ip[4];
  u16 port;

} udp_peer_t;

bool udp_init (void);

void udp_set_ip (const u8 *ip);

u32 udp_recv (u8 *payload, const u32 max, udp_peer_t *from);

void udp_set_peer (const udp_peer_t *peer);

bool udp_send (const u8 *payload, const u32 len);

#endif
