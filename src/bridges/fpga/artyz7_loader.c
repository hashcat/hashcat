/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_loader.h"
#include "artyz7_ps7_init.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLCR_LOCK           0xF8000004
#define SLCR_UNLOCK         0xF8000008
#define SLCR_A9_CPU_RST     0xF8000244
#define SLCR_OCM_CFG        0xF8000910
#define SLCR_FPGA_RST_CTRL  0xF8000240
#define SLCR_LVL_SHFTR_EN   0xF8000900

#define SLCR_UNLOCK_KEY     0x0000DF0D
#define SLCR_LOCK_KEY       0x0000767B

#define A9_RST0             (1u << 0)
#define A9_CLKSTOP0         (1u << 4)

#define OCM_LOW_BASE        0x00000000
#define OCM_LOW_SIZE        0x00030000

#define XADC_CFG            0xF8007100
#define XADC_CMDFIFO        0xF8007110
#define XADC_RDFIFO         0xF8007114
#define XADC_MCTL           0xF8007118

#define XADC_CMD_READ       0x04000000
#define XADC_REG_TEMP       0x00

bool artyz7_ps7_init (dap_ctx_t *ctx)
{
  for (u32 i = 0; i < PS7_INIT_OPS; i++)
  {
    const ps7_op_t *op = &PS7_INIT[i];

    if (op->op == PS7_OP_WRITE)
    {
      if (op->mask == 0xFFFFFFFF)
      {
        if (dap_mem_write32 (ctx, op->addr, op->val) == false) return false;
      }
      else
      {
        u32 cur = 0;

        if (dap_mem_read32 (ctx, op->addr, &cur) == false) return false;

        const u32 next = (cur & ~op->mask) | (op->val & op->mask);

        if (dap_mem_write32 (ctx, op->addr, next) == false) return false;
      }

      continue;
    }

    if (op->op == PS7_OP_POLL)
    {
      bool locked = false;

      for (u32 try = 0; try < 2000; try++)
      {
        u32 cur = 0;

        if (dap_mem_read32 (ctx, op->addr, &cur) == false) return false;

        if ((cur & op->mask) != 0)
        {
          locked = true;

          break;
        }
      }

      if (locked == false)
      {
        u32 cur = 0;

        dap_mem_read32 (ctx, op->addr, &cur);

        fprintf (stderr, "artyz7: ps7_init poll never satisfied at 0x%08X mask 0x%08X, reads 0x%08X\n", op->addr, op->mask, cur);

        if (op->addr == 0xF800010C)
        {
          fprintf (stderr, "artyz7:   PLL_STATUS: arm=%u ddr=%u io=%u\n", cur & 1, (cur >> 1) & 1, (cur >> 2) & 1);
        }

        return false;
      }

      continue;
    }

    if (op->op == PS7_OP_DELAY)
    {
      usleep (1000);

      continue;
    }
  }

  return true;
}

bool artyz7_load_image (dap_ctx_t *ctx, const u8 *img, const size_t size)
{
  if (size == 0)
  {
    fprintf (stderr, "artyz7: the application image is empty\n");

    return false;
  }

  if (size > OCM_LOW_SIZE)
  {
    fprintf (stderr, "artyz7: the application is %" PRIu64 " bytes, on-chip memory holds %u\n", (u64) size, OCM_LOW_SIZE);

    return false;
  }

  bool dirty = false;

  if (dap_clear_sticky (ctx, &dirty) == false) return false;

  for (size_t off = 0; off < size; off += 4)
  {
    u8 w[4] = { 0, 0, 0, 0 };

    const size_t n = ((size - off) < 4) ? (size - off) : 4;

    memcpy (w, &img[off], n);

    const u32 v = ((u32) w[0] << 0) | ((u32) w[1] << 8) | ((u32) w[2] << 16) | ((u32) w[3] << 24);

    if (dap_mem_write32 (ctx, OCM_LOW_BASE + (u32) off, v) == false) return false;
  }

  if (dap_clear_sticky (ctx, &dirty) == false) return false;

  if (dirty == true)
  {
    fprintf (stderr, "artyz7: a write to on-chip memory faulted while loading the application\n");
    fprintf (stderr, "artyz7: every word after it was dropped, so the image there is not the one loaded\n");

    return false;
  }

  return true;
}

bool artyz7_load_binary (dap_ctx_t *ctx, const char *path)
{
  FILE *f = fopen (path, "rb");

  if (f == NULL)
  {
    fprintf (stderr, "artyz7: cannot open %s\n", path);

    return false;
  }

  fseek (f, 0, SEEK_END);

  const long size = ftell (f);

  fseek (f, 0, SEEK_SET);

  if (size <= 0)
  {
    fprintf (stderr, "artyz7: %s is empty\n", path);

    fclose (f);

    return false;
  }

  u8 *img = malloc ((size_t) size);

  if (img == NULL)
  {
    fclose (f);

    return false;
  }

  const bool read_ok = (fread (img, 1, (size_t) size, f) == (size_t) size);

  fclose (f);

  if (read_ok == false)
  {
    free (img);

    return false;
  }

  const bool ok = artyz7_load_image (ctx, img, (size_t) size);

  free (img);

  if (ok == false) return false;

  artyz7_say ("  loaded %ld bytes at 0x%08X\n", size, OCM_LOW_BASE);

  return true;
}

bool artyz7_pl_disable (dap_ctx_t *ctx)
{
  if (dap_mem_write32 (ctx, SLCR_UNLOCK, SLCR_UNLOCK_KEY) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_FPGA_RST_CTRL, 0x0000000F) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_LVL_SHFTR_EN, 0x00000000) == false) return false;
  if (dap_mem_write32 (ctx, SLCR_LVL_SHFTR_EN, 0x0000000A) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_LOCK, SLCR_LOCK_KEY) == false) return false;

  return true;
}

bool artyz7_pl_enable (dap_ctx_t *ctx)
{
  if (dap_mem_write32 (ctx, SLCR_UNLOCK, SLCR_UNLOCK_KEY) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_LVL_SHFTR_EN, 0x0000000F) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_FPGA_RST_CTRL, 0x00000000) == false) return false;

  if (dap_mem_write32 (ctx, SLCR_LOCK, SLCR_LOCK_KEY) == false) return false;

  return true;
}

#define DBG_BASE_CPU0       0xF8890000

#define DBG_DTRRX           0x080
#define DBG_ITR             0x084
#define DBG_DSCR            0x088
#define DBG_DRCR            0x090
#define DBG_LAR             0xFB0

#define DSCR_HALTED         (1u <<  0)
#define DSCR_RESTARTED      (1u <<  1)
#define DSCR_ITREN          (1u << 13)
#define DSCR_HDBGEN         (1u << 14)
#define DSCR_INSTRCOMPL     (1u << 24)

#define DRCR_HRQ            (1u <<  0)
#define DRCR_RRQ            (1u <<  1)
#define DRCR_CSE            (1u <<  2)

#define DBG_LAR_KEY         0xC5ACCE55

#define OP_MRC_DTR_TO_R0    0xEE100E15

#define OP_MOV_PC_R0        0xE1A0F000

static bool dbg_write (dap_ctx_t *ctx, const u32 off, const u32 val)
{
  return dap_mem_write32 (ctx, DBG_BASE_CPU0 + off, val);
}

static bool dbg_read (dap_ctx_t *ctx, const u32 off, u32 *val)
{
  return dap_mem_read32 (ctx, DBG_BASE_CPU0 + off, val);
}

static bool dbg_exec (dap_ctx_t *ctx, const u32 insn)
{
  if (dbg_write (ctx, DBG_ITR, insn) == false) return false;

  for (u32 try = 0; try < 200; try++)
  {
    u32 dscr = 0;

    if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;

    if ((dscr & DSCR_INSTRCOMPL) != 0) return true;
  }

  fprintf (stderr, "artyz7: instruction 0x%08X never completed on the halted core\n", insn);

  return false;
}

static bool dbg_halt (dap_ctx_t *ctx)
{
  if (dbg_write (ctx, DBG_LAR, DBG_LAR_KEY) == false) return false;

  u32 dscr = 0;

  if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;

  if ((dscr & DSCR_HALTED) != 0) return true;

  if (dbg_write (ctx, DBG_DSCR, dscr | DSCR_HDBGEN) == false) return false;
  if (dbg_write (ctx, DBG_DRCR, DRCR_HRQ) == false) return false;

  for (u32 try = 0; try < 200; try++)
  {
    if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;

    if ((dscr & DSCR_HALTED) != 0) return true;
  }

  fprintf (stderr, "artyz7: CPU0 did not halt, DSCR = 0x%08X\n", dscr);
  fprintf (stderr, "artyz7: press the board's own reset button, PS_SRST. That re-runs the boot ROM,\n");
  fprintf (stderr, "artyz7: which parks the core where a halt can reach it. Cycling the HOST does not\n");
  fprintf (stderr, "artyz7: clear this, and no reset a loader can issue does either.\n");

  return false;
}

bool artyz7_hold_cpu (dap_ctx_t *ctx)
{
  return dbg_halt (ctx);
}

bool artyz7_start_cpu (dap_ctx_t *ctx)
{
  if (dbg_halt (ctx) == false) return false;

  u32 dscr = 0;

  if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;

  if (dbg_write (ctx, DBG_DSCR, dscr | DSCR_ITREN) == false) return false;

  if (dbg_write (ctx, DBG_DTRRX, OCM_LOW_BASE) == false) return false;

  if (dbg_exec (ctx, OP_MRC_DTR_TO_R0) == false) return false;
  if (dbg_exec (ctx, OP_MOV_PC_R0) == false) return false;

  if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;
  if (dbg_write (ctx, DBG_DSCR, dscr & ~DSCR_ITREN) == false) return false;

  if (dbg_write (ctx, DBG_DRCR, DRCR_CSE) == false) return false;
  if (dbg_write (ctx, DBG_DRCR, DRCR_RRQ) == false) return false;

  for (u32 try = 0; try < 200; try++)
  {
    if (dbg_read (ctx, DBG_DSCR, &dscr) == false) return false;

    if ((dscr & DSCR_RESTARTED) != 0) return true;
  }

  fprintf (stderr, "artyz7: CPU0 did not restart, DSCR = 0x%08X\n", dscr);

  return false;
}

bool artyz7_temperature (dap_ctx_t *ctx, int *millic)
{
  if (dap_mem_write32 (ctx, XADC_MCTL, 0x00000010) == false) return false;
  if (dap_mem_write32 (ctx, XADC_MCTL, 0x00000000) == false) return false;
  if (dap_mem_write32 (ctx, XADC_CFG,  0x80003214) == false) return false;

  usleep (10000);

  if (dap_mem_write32 (ctx, XADC_CMDFIFO, XADC_CMD_READ | (XADC_REG_TEMP << 16)) == false) return false;
  if (dap_mem_write32 (ctx, XADC_CMDFIFO, 0x00000000) == false) return false;

  usleep (5000);

  u32 a = 0;
  u32 b = 0;

  if (dap_mem_read32 (ctx, XADC_RDFIFO, &a) == false) return false;
  if (dap_mem_read32 (ctx, XADC_RDFIFO, &b) == false) return false;

  const u32 raw = b & 0xFFFF;

  *millic = (int) (((u64) raw * 503975ull) / 65536ull) - 273150;

  return true;
}
