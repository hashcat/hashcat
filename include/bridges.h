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
u32   bridge_workitem_count    (hashcat_ctx_t *hashcat_ctx, const int bridge_link_device);

// Attack mode 9 gives every candidate its own salt. The kernel reads it at pws_pos + gid and a
// hook does the same sum on the host through salt_per_pw, so a bridge, which reaches neither, works it
// out here. Inline because a bridge is a plugin and the core exports none of its own symbols to one.

static inline u32 bridge_salt_pos (const hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param, const hashes_t *hashes, const u32 salt_pos, const u64 pw_pos)
{
  // The self test hands a hashes_t holding the one self test salt and names it by index, so there is
  // no batch to place a candidate in.

  if (hashes->salts_buf == hashes->st_salts_buf) return salt_pos;

  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    const u32 pos = (u32) (device_param->kernel_param.pws_pos + pw_pos);

    return pos;
  }

  return salt_pos;
}

bool  bridges_init      (hashcat_ctx_t *hashcat_ctx);
bool  bridges_init_late (hashcat_ctx_t *hashcat_ctx);
void  bridges_destroy   (hashcat_ctx_t *hashcat_ctx);

bool  bridges_salt_prepare (hashcat_ctx_t *hashcat_ctx);
void  bridges_salt_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_BRIDGE_H
