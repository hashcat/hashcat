/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_GENERIC_H
#define HC_GENERIC_H

// The oldest plugin interface hashcat still accepts. A feed declares which interface it was built
// against with GENERIC_PLUGIN_VERSION, and it takes that number from FEEDS_INTERFACE_VERSION_CURRENT
// on the compile line, the same way a module takes MODULE_INTERFACE_VERSION_CURRENT. A feed must not
// declare this constant instead, because then a rebuild would re-declare compatibility that the
// source has not earned.

#define GENERIC_PLUGIN_VERSION_REQ 720

// What a call into a feed did. thread_next () returns the candidate length on success, so only the
// negative values are listed here and they must stay negative.
//
// Telling an empty feed apart from a broken one matters: a feed that has run out has finished the
// attack, and a feed that has failed has abandoned it. Reporting the second as the first ends the
// session with "Exhausted" and an exit status that says everything went fine.

#define GENERIC_RC_EOF   -1
#define GENERIC_RC_ERROR -2

// What global_keyspace () may say. A feed that cannot count itself returns GENERIC_KEYSPACE_UNKNOWN
// and hashcat runs it without a denominator. GENERIC_KEYSPACE_ERROR is hashcat's own value and a
// plugin never returns it, it is what the wrapper reports when the plugin failed. The two were the
// same value once, so a feed that could not open its input became an endless feed instead of a
// stopped session.

#define GENERIC_KEYSPACE_UNKNOWN ((u64) -1)
#define GENERIC_KEYSPACE_ERROR   ((u64) -2)

typedef enum generic_plugin_options
{
  GENERIC_PLUGIN_OPTIONS_AUTOHEX   = 1 << 0,
  GENERIC_PLUGIN_OPTIONS_ICONV     = 1 << 1,
  GENERIC_PLUGIN_OPTIONS_RULES     = 1 << 2,

  GENERIC_PLUGIN_OPTIONS_UNDEFINED = 0,

} generic_plugin_options_t;

#define HC_LOAD_FUNC_GENERIC(ptr, name, type)                                                \
do                                                                                           \
{                                                                                            \
  (ptr)->name = (type) hc_dlsym ((ptr)->lib, #name);                                         \
  if ((ptr)->name == NULL)                                                                   \
  {                                                                                          \
    event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, (ptr)->dynlib_filename); \
    return -1;                                                                               \
  }                                                                                          \
} while (0)

int   generic_filename       (const folder_config_t *folder_config, const char *plugin_name, const char *prefix, char *out_buf, const size_t out_size);
char *generic_resolve        (const folder_config_t *folder_config, const char *plugin_name, bool *by_name);

bool generic_global_init     (hashcat_ctx_t *hashcat_ctx);
void generic_global_term     (hashcat_ctx_t *hashcat_ctx);
u64  generic_global_keyspace (hashcat_ctx_t *hashcat_ctx);
bool generic_thread_init     (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
void generic_thread_term     (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int  generic_thread_next     (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, u8 *out_buf, const int out_size);
int  generic_thread_seek     (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, const u64 offset);

int  generic_ctx_init        (hashcat_ctx_t *hashcat_ctx);
void generic_ctx_destroy     (hashcat_ctx_t *hashcat_ctx);

#endif // HC_GENERIC_H
