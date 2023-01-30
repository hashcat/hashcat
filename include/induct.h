/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_INDUCT_H
#define HC_INDUCT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char INDUCT_DIR[] = "induct";

int  induct_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void induct_ctx_scan    (hashcat_ctx_t *hashcat_ctx);
void induct_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_INDUCT_H
