/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRIDGE_H
#define HC_BRIDGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

static const int BRIDGE_INTERFACE_VERSION_MINIMUM = 700;

static const size_t BRIDGE_CONTEXT_SIZE_CURRENT = sizeof (bridge_ctx_t);

/**
 * output functions
 */

bool  bridges_init    (hashcat_ctx_t *hashcat_ctx);
void  bridges_destroy (hashcat_ctx_t *hashcat_ctx);

bool  bridges_salt_prepare (hashcat_ctx_t *hashcat_ctx);
void  bridges_salt_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_BRIDGE_H
