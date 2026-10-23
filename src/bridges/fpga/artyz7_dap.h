/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARTYZ7_DAP_H
#define HC_ARTYZ7_DAP_H

#include "artyz7_jtag.h"

#define DAP_IR_ABORT      0x8
#define DAP_IR_DPACC      0xA
#define DAP_IR_APACC      0xB
#define DAP_IR_IDCODE     0xE
#define DAP_IR_BYPASS     0xF

#define DAP_IR_LEN        4
#define PL_IR_LEN         6

#define DAP_DR_LEN        35

#define DP_ADDR_ABORT     0x0
#define DP_ADDR_CTRLSTAT  0x4
#define DP_ADDR_SELECT    0x8
#define DP_ADDR_RDBUFF    0xC

#define AP_ADDR_CSW       0x00
#define AP_ADDR_TAR       0x04
#define AP_ADDR_DRW       0x0C

#define AP_CSW_32BIT      0x23000002

#define DP_CTRL_PWRUPREQ  0x50000000
#define DP_CTRL_PWRUPACK  0xA0000000

#define DP_CTRL_STICKYORUN 0x00000002
#define DP_CTRL_STICKYCMP  0x00000010
#define DP_CTRL_STICKYERR  0x00000020

#define DP_CTRL_STICKY_ALL (DP_CTRL_STICKYORUN | DP_CTRL_STICKYCMP | DP_CTRL_STICKYERR)

#define DAP_ACK_OK        0x2
#define DAP_ACK_WAIT      0x1

typedef struct dap_ctx
{
  jtag_ctx_t *jtag;

  u32 sel_cache;

} dap_ctx_t;

bool dap_init       (dap_ctx_t *ctx, jtag_ctx_t *jtag);
bool dap_status (dap_ctx_t *ctx, u32 *stat);
bool dap_clear_sticky (dap_ctx_t *ctx, bool *was_dirty);

bool dap_mem_read32 (dap_ctx_t *ctx, const u32 addr, u32 *out);
bool dap_mem_write32 (dap_ctx_t *ctx, const u32 addr, const u32 val);

#endif
