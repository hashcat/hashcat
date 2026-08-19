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

#if defined (HC_PLUGIN_ABI_MISSING)
#error "a bridge names the plugin interface it is built against: -DHC_PLUGIN_ABI_VERSION=<n>, see docs/hashcat-plugin-development-guide.md"
#endif

static const int BRIDGE_INTERFACE_VERSION_MINIMUM = 720;

static const size_t BRIDGE_CONTEXT_SIZE_CURRENT = sizeof (bridge_ctx_t);

// The one name a bridge hands the core. Everything it can do is a pointer bridge_init () writes into
// the bridge context, so a built bridge exports this and nothing else.

HC_PLUGIN_ENTRY void bridge_init (bridge_ctx_t *bridge_ctx);

/**
 * output functions
 */

bool  bridge_active            (hashcat_ctx_t *hashcat_ctx, const int bridge_link_device);
bool  bridge_same_unit_class   (hashcat_ctx_t *hashcat_ctx, const int unit_a, const int unit_b);
u32   bridge_workitem_multiple (hashcat_ctx_t *hashcat_ctx, const int bridge_link_device);

bool  bridges_init    (hashcat_ctx_t *hashcat_ctx);
void  bridges_destroy (hashcat_ctx_t *hashcat_ctx);

bool  bridges_salt_prepare (hashcat_ctx_t *hashcat_ctx);
void  bridges_salt_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_BRIDGE_H
