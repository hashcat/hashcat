/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INDUCT_H
#define _INDUCT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char INDUCT_DIR[] = "induct";

int  induct_ctx_init    (induct_ctx_t *induct_ctx, const user_options_t *user_options, const folder_config_t *folder_config, const status_ctx_t *status_ctx);
void induct_ctx_scan    (induct_ctx_t *induct_ctx);
void induct_ctx_cleanup (induct_ctx_t *induct_ctx);
void induct_ctx_destroy (induct_ctx_t *induct_ctx);

#endif // _INDUCT_H
