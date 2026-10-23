/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARTYZ7_FTDI_H
#define HC_ARTYZ7_FTDI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef INC_TYPES_H
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define FTDI_SIO_RESET              0x00
#define FTDI_SIO_SET_BAUDRATE       0x03
#define FTDI_SIO_SET_LATENCY_TIMER  0x09
#define FTDI_SIO_SET_BITMODE        0x0B

#define FTDI_RESET_SIO              0
#define FTDI_RESET_PURGE_RX         1
#define FTDI_RESET_PURGE_TX         2

#define FTDI_BITMODE_RESET          0x00
#define FTDI_BITMODE_MPSSE          0x02

#define FTDI_INTERFACE_A_INDEX      1
#define FTDI_INTERFACE_A_NUMBER     0

#define FTDI_EP_OUT                 0x02
#define FTDI_EP_IN                  0x81

#define FTDI_STATUS_BYTES           2

#define MPSSE_SEND_IMMEDIATE_BYTE   0x87

typedef struct ftdi_ctx
{
  int fd;

  u16 vid;
  u16 pid;

  char serial[64];

  u32 in_packet_size;

  bool claimed;
  bool detached;

  u8  rx[8192];
  u32 rx_len;
  u32 rx_pos;

} ftdi_ctx_t;

extern bool ARTYZ7_VERBOSE;

#define artyz7_say(...) do { if (ARTYZ7_VERBOSE == true) printf (__VA_ARGS__); } while (0)

bool ftdi_open   (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const char *serial);
void ftdi_close  (ftdi_ctx_t *ctx);

bool ftdi_mpsse_enable (ftdi_ctx_t *ctx, const u32 tck_hz);
bool ftdi_mpsse_sync   (ftdi_ctx_t *ctx);

bool ftdi_write (ftdi_ctx_t *ctx, const u8 *buf, const size_t len);
bool ftdi_read  (ftdi_ctx_t *ctx, u8 *buf, const size_t len);

#endif
