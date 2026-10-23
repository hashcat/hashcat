/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARTYZ7_BITSTREAM_H
#define HC_ARTYZ7_BITSTREAM_H

#include "artyz7_jtag.h"

bool artyz7_load_bitstream (jtag_ctx_t *jtag, const char *path);

bool artyz7_pl_blank (jtag_ctx_t *jtag);

bool artyz7_cfg_status (jtag_ctx_t *jtag, u32 *stat);
void artyz7_print_cfg_status (const u32 s);

#endif
