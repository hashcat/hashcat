
#ifndef HC_MODULES_H
#define HC_MODULES_H

#if defined (HC_PLUGIN_ABI_MISSING)
#error "a module names the plugin interface it is built against: -DHC_PLUGIN_ABI_VERSION=<n>, see docs/hashcat-plugin-development-guide.md"
#endif

static const size_t MODULE_CONTEXT_SIZE_CURRENT = sizeof (module_ctx_t);

// The one name a module hands the core. Everything below is the shape of what module_init () puts
// into the module context, and none of it is resolved by name, so a built module exports this and
// nothing else.

HC_PLUGIN_ENTRY void module_init            (module_ctx_t *module_ctx);













#endif // HC_MODULES_H
