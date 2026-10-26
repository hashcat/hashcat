/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_HCFPGA_POOL_H
#define HC_FPGA_HCFPGA_POOL_H

#include "common.h"
#include "types.h"

#include "fpga/hcfpga.h"

#define FPGA_POOL_MAX  FPGA_MAX_DEVICES

#define FPGA_POOL_REDO_MAX  (FPGA_POOL_MAX * 4)

#define FPGA_POOL_RETRIES  2

typedef enum fpga_pool_verdict
{
  FPGA_POOL_DONE  = 0,
  FPGA_POOL_RETRY = 1,
  FPGA_POOL_DEAD  = 2,

} fpga_pool_verdict_t;

typedef fpga_pool_verdict_t (*fpga_pool_work_fn) (void *arg, const int member, const u64 from, const u64 cnt);

typedef struct fpga_pool fpga_pool_t;

fpga_pool_t *fpga_pool_create  (const int members, const u32 *grain, const u32 *capacity, const u32 chunks);
void         fpga_pool_destroy (fpga_pool_t *pool);

bool         fpga_pool_run     (fpga_pool_t *pool, const u64 total, fpga_pool_work_fn fn, void *arg);

bool         fpga_pool_alive   (const fpga_pool_t *pool, const int member);
int          fpga_pool_alive_cnt (const fpga_pool_t *pool);

double       fpga_pool_rate    (const fpga_pool_t *pool, const int member);

u64          fpga_pool_done    (const fpga_pool_t *pool, const int member);

#endif
