/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_ZTEX_USB_H
#define HC_FPGA_ZTEX_USB_H

#include "common.h"
#include "types.h"

#define ZTEX_VENDOR_ID        0x221a

#define ZTEX_VR_DESCRIPTOR    0x22
#define ZTEX_VR_FPGA_STATE    0x30
#define ZTEX_VR_MULTI_FPGA    0x50
#define ZTEX_VR_HS_SETTINGS   0x33

#define ZTEX_VC_RESET_FPGA    0x31
#define ZTEX_VC_HS_CONF_INIT  0x34
#define ZTEX_VC_HS_CONF_DONE  0x35

#define ZTEX_DESC_BYTES           40
#define ZTEX_DESC_MAGIC_OFFSET     2
#define ZTEX_DESC_PRODUCT_OFFSET   6
#define ZTEX_DESC_CAPS_OFFSET     12
#define ZTEX_DESC_SERIAL_OFFSET   30
#define ZTEX_DESC_SERIAL_BYTES    10

#define ZTEX_PRODUCT_FPGA_MODULE  10

#if defined (__linux__)

bool ztex_dbg           (void);

int  ztex_control_read  (const int fd, const u8 request, const u16 value, const u16 index, void *buf, const u16 len);
bool ztex_control_write (const int fd, const u8 request, const u16 value, const u16 index);
bool ztex_control_write_data (const int fd, const u8 request, const u16 value, const u16 index, void *buf, const u16 len);

bool ztex_claim         (const int fd);

bool ztex_bulk_write    (const int fd, const u32 ep, void *src, const u32 len);
int  ztex_bulk_in       (const int fd, const u32 ep, void *dst, const u32 len, const u32 timeout_ms);

int  ztex_bulk_xfer     (const int fd, const u8 ep, void *buf, const u32 len, const u32 timeout_ms);

int  ztex_bulk_write_reading (const int fd, const u8 ep_out, void *src, const u32 len, const u8 ep_in, u8 *dst, const u32 dst_room, const u32 pkt, u32 *dst_got, const u32 timeout_ms);

bool ztex_sysfs_read    (const char *dir, const char *name, char *out, const size_t out_size);

void ztex_swap_bits     (u8 *buf, const size_t len);

bool ztex_hs_upload     (const int fd, const u32 endpoint, const char *path);

bool ztex_fpga_is_configured (const int fd);

#endif

#endif
