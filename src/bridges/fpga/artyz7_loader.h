/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARTYZ7_LOADER_H
#define HC_ARTYZ7_LOADER_H

#include "artyz7_dap.h"

bool artyz7_ps7_init (dap_ctx_t *ctx);

bool artyz7_load_binary (dap_ctx_t *ctx, const char *path);

bool artyz7_load_image (dap_ctx_t *ctx, const u8 *img, const size_t size);

bool artyz7_pl_enable (dap_ctx_t *ctx);

bool artyz7_pl_disable (dap_ctx_t *ctx);

bool artyz7_hold_cpu (dap_ctx_t *ctx);

bool artyz7_start_cpu (dap_ctx_t *ctx);

bool artyz7_temperature (dap_ctx_t *ctx, int *millic);

#endif
