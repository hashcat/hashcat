/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_dap.h"

#include <stdio.h>
#include <string.h>

static bool dap_ir (dap_ctx_t *ctx, const u8 instr)
{
  const u32 ir = ((u32) instr << PL_IR_LEN) | ((1u << PL_IR_LEN) - 1);

  u8 buf[2];

  buf[0] = (u8) (ir & 0xFF);
  buf[1] = (u8) ((ir >> 8) & 0xFF);

  return jtag_shift_ir (ctx->jtag, buf, NULL, DAP_IR_LEN + PL_IR_LEN);
}

static bool dap_xfer (dap_ctx_t *ctx, const bool is_ap, const u8 addr, const bool is_read, const u32 wdata, u32 *rdata, u32 *ack)
{
  if (dap_ir (ctx, (is_ap == true) ? DAP_IR_APACC : DAP_IR_DPACC) == false) return false;

  u8 out[5];
  u8 in[5];

  memset (out, 0, sizeof (out));
  memset (in,  0, sizeof (in));

  u64 v = 0;

  v |= (is_read == true) ? 1ull : 0ull;
  v |= (u64) ((addr >> 2) & 0x3) << 1;
  v |= (u64) wdata << 3;

  v = v << 1;

  for (u32 i = 0; i < 5; i++) out[i] = (u8) ((v >> (i * 8)) & 0xFF);

  if (jtag_shift_dr (ctx->jtag, out, in, DAP_DR_LEN + 1) == false) return false;

  u64 r = 0;

  for (u32 i = 0; i < 5; i++) r |= (u64) in[i] << (i * 8);

  r = r >> 1;

  if (ack   != NULL) *ack   = (u32) (r & 0x7);
  if (rdata != NULL) *rdata = (u32) ((r >> 3) & 0xFFFFFFFF);

  return true;
}

static bool dp_write (dap_ctx_t *ctx, const u8 addr, const u32 val)
{
  u32 ack = 0;

  for (u32 try = 0; try < 20; try++)
  {
    if (dap_xfer (ctx, false, addr, false, val, NULL, &ack) == false) return false;

    if (ack == DAP_ACK_OK)   return true;
    if (ack == DAP_ACK_WAIT) continue;

    fprintf (stderr, "dap: dp write addr 0x%02X bad ack %u\n", addr, ack);

    return false;
  }

  fprintf (stderr, "dap: dp write addr 0x%02X stayed in WAIT\n", addr);

  return false;
}

static bool dp_read (dap_ctx_t *ctx, const u8 addr, u32 *out)
{
  u32 ack = 0;

  if (dap_xfer (ctx, false, addr, true, 0, NULL, &ack) == false) return false;

  for (u32 try = 0; try < 20; try++)
  {
    if (dap_xfer (ctx, false, DP_ADDR_RDBUFF, true, 0, out, &ack) == false) return false;

    if (ack == DAP_ACK_OK)   return true;
    if (ack == DAP_ACK_WAIT) continue;

    fprintf (stderr, "dap: dp read addr 0x%02X bad ack %u\n", addr, ack);

    return false;
  }

  return false;
}

static bool ap_select (dap_ctx_t *ctx, const u8 ap, const u8 addr)
{
  const u32 sel = ((u32) ap << 24) | ((u32) (addr & 0xF0));

  if (sel == ctx->sel_cache) return true;

  if (dp_write (ctx, DP_ADDR_SELECT, sel) == false) return false;

  ctx->sel_cache = sel;

  return true;
}

static bool ap_write (dap_ctx_t *ctx, const u8 addr, const u32 val)
{
  if (ap_select (ctx, 0, addr) == false) return false;

  u32 ack = 0;

  for (u32 try = 0; try < 20; try++)
  {
    if (dap_xfer (ctx, true, addr, false, val, NULL, &ack) == false) return false;

    if (ack == DAP_ACK_OK)   return true;
    if (ack == DAP_ACK_WAIT) continue;

    fprintf (stderr, "dap: ap write addr 0x%02X bad ack %u\n", addr, ack);

    return false;
  }

  fprintf (stderr, "dap: ap write addr 0x%02X stayed in WAIT\n", addr);

  return false;
}

static bool ap_read (dap_ctx_t *ctx, const u8 addr, u32 *out)
{
  if (ap_select (ctx, 0, addr) == false) return false;

  u32 ack = 0;

  if (dap_xfer (ctx, true, addr, true, 0, NULL, &ack) == false) return false;

  for (u32 try = 0; try < 20; try++)
  {
    if (dap_xfer (ctx, false, DP_ADDR_RDBUFF, true, 0, out, &ack) == false) return false;

    if (ack == DAP_ACK_OK)   return true;
    if (ack == DAP_ACK_WAIT) continue;

    fprintf (stderr, "dap: ap read addr 0x%02X bad ack %u\n", addr, ack);

    return false;
  }

  return false;
}

static bool dap_abort (dap_ctx_t *ctx)
{
  const u32 ir = ((u32) DAP_IR_ABORT << PL_IR_LEN) | ((1u << PL_IR_LEN) - 1);

  u8 irbuf[2];

  irbuf[0] = (u8) (ir & 0xFF);
  irbuf[1] = (u8) ((ir >> 8) & 0xFF);

  if (jtag_shift_ir (ctx->jtag, irbuf, NULL, DAP_IR_LEN + PL_IR_LEN) == false) return false;

  u8 out[5];

  memset (out, 0, sizeof (out));

  const u64 v = (1ull << 3) << 1;

  for (u32 i = 0; i < 5; i++) out[i] = (u8) ((v >> (i * 8)) & 0xFF);

  return jtag_shift_dr (ctx->jtag, out, NULL, DAP_DR_LEN + 1);
}

bool dap_init (dap_ctx_t *ctx, jtag_ctx_t *jtag)
{
  memset (ctx, 0, sizeof (dap_ctx_t));

  ctx->jtag      = jtag;

  ctx->sel_cache = 0xFFFFFFFF;

  if (jtag_reset (jtag) == false) return false;

  if (dap_abort (ctx) == false) return false;

  if (dp_write (ctx, DP_ADDR_CTRLSTAT, DP_CTRL_PWRUPREQ) == false) return false;

  u32 stat = 0;

  for (u32 try = 0; try < 100; try++)
  {
    if (dp_read (ctx, DP_ADDR_CTRLSTAT, &stat) == false) return false;

    if ((stat & DP_CTRL_PWRUPACK) == DP_CTRL_PWRUPACK) break;
  }

  if ((stat & DP_CTRL_PWRUPACK) != DP_CTRL_PWRUPACK)
  {
    fprintf (stderr, "dap: debug power never came up, CTRL/STAT = 0x%08X\n", stat);

    return false;
  }

  for (u32 try = 0; try < 10; try++)
  {
    if ((stat & DP_CTRL_STICKY_ALL) == 0) break;

    if (dap_abort (ctx) == false) return false;

    if (dp_write (ctx, DP_ADDR_CTRLSTAT, DP_CTRL_PWRUPREQ | DP_CTRL_STICKY_ALL) == false) return false;
    if (dp_read  (ctx, DP_ADDR_CTRLSTAT, &stat) == false) return false;
  }

  if ((stat & DP_CTRL_STICKY_ALL) != 0)
  {
    fprintf (stderr, "dap: sticky flags will not clear, CTRL/STAT = 0x%08X\n", stat);
    fprintf (stderr, "dap: a processor whose clock is stopped will do this, and needs power removed\n");

    return false;
  }

  artyz7_say ("  CTRL/STAT = 0x%08X, debug and system power acknowledged\n", stat);

  if (ap_write (ctx, AP_ADDR_CSW, AP_CSW_32BIT) == false) return false;

  return true;
}

bool dap_clear_sticky (dap_ctx_t *ctx, bool *was_dirty)
{
  u32 stat = 0;

  if (dp_read (ctx, DP_ADDR_CTRLSTAT, &stat) == false) return false;

  if ((stat & DP_CTRL_STICKY_ALL) == 0)
  {
    *was_dirty = false;

    return true;
  }

  *was_dirty = true;

  if (dap_abort (ctx) == false) return false;
  if (dp_write (ctx, DP_ADDR_CTRLSTAT, DP_CTRL_PWRUPREQ | DP_CTRL_STICKY_ALL) == false) return false;

  return true;
}

bool dap_status (dap_ctx_t *ctx, u32 *stat)
{
  return dp_read (ctx, DP_ADDR_CTRLSTAT, stat);
}

bool dap_mem_read32 (dap_ctx_t *ctx, const u32 addr, u32 *out)
{
  for (u32 attempt = 0; attempt < 2; attempt++)
  {
    if (ap_write (ctx, AP_ADDR_TAR, addr) == false) return false;
    if (ap_read  (ctx, AP_ADDR_DRW, out)  == false) return false;

    bool dirty = false;

    if (dap_clear_sticky (ctx, &dirty) == false) return false;

    if (dirty == false) return true;
  }

  fprintf (stderr, "dap: read of 0x%08X kept faulting, the value would have been stale\n", addr);

  return false;
}

bool dap_mem_write32 (dap_ctx_t *ctx, const u32 addr, const u32 val)
{
  if (ap_write (ctx, AP_ADDR_TAR, addr) == false) return false;

  return ap_write (ctx, AP_ADDR_DRW, val);
}
