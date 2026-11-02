/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PROTO_H
#define HC_PROTO_H

#define HC_OP_PING      0x01
#define HC_OP_CONFIG    0x02
#define HC_OP_FEED      0x03
#define HC_OP_RESET     0x04

#define HC_OP_CSR_WR    0x05
#define HC_OP_CSR_RD    0x06

#define HC_OP_PONG      0x81
#define HC_OP_RESULT    0x82
#define HC_OP_CSR_VAL   0x83

#define HC_OP_FEED_ACK  0x84

#define HC_NETCFG_ADDR   0x0001FF00
#define HC_NETCFG_MAGIC  0x4E455443

#define HC_HDR_BYTES    4
#define HC_SEQ_BYTES    8
#define HC_SEAL_HDR     (HC_HDR_BYTES + HC_SEQ_BYTES)
#define HC_TAG_BYTES    16

#define HC_DIR_TO_BOARD 0
#define HC_DIR_TO_HOST  1

#define HC_KEY_ADDR      0x0001FF40
#define HC_KEY_MAGIC     0x59454B53

#define HC_CSR_MAX_OFF  0x100

#define HC_PONG_BYTES   28

#define HC_CONFIG_BYTES 42

#define HC_RESULT_REC   32

#define HC_MAX_DATAGRAM 1472
#define HC_MAX_PAYLOAD  (HC_MAX_DATAGRAM - HC_SEAL_HDR - HC_TAG_BYTES)

#endif
