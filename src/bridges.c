/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "modules.h"
#include "backend.h"
#include "dynloader.h"
#include "bridges.h"
#include "interface.h"

/**
 * parsing
 */

int bridge_filename (const folder_config_t *folder_config, const char *bridge_name, char *out_buf, const size_t out_size)
{
  // native compiled
  #if defined (_WIN) || defined (__CYGWIN__)
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.dll", folder_config->shared_dir, bridge_name);
  #else
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.so", folder_config->shared_dir, bridge_name);
  #endif
}

bool bridge_load (hashcat_ctx_t *hashcat_ctx, bridge_ctx_t *bridge_ctx, const char *bridge_name)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  char *bridge_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  bridge_filename (folder_config, bridge_name, bridge_file, HCBUFSIZ_TINY);

  struct stat s;

  memset (&s, 0, sizeof (struct stat));

  if (stat (bridge_file, &s) == -1)
  {
    event_log_warning (hashcat_ctx, "The bridge plugin '%s' couldn't be found.", bridge_file);
    event_log_warning (hashcat_ctx, NULL);
  }

  bridge_ctx->bridge_handle = hc_dlopen (bridge_file);

  if (bridge_ctx->bridge_handle == NULL)
  {
    #if defined (_WIN)
    event_log_error (hashcat_ctx, "Cannot load bridge %s", bridge_file); // todo: maybe there's a dlerror () equivalent
    #else
    event_log_error (hashcat_ctx, "%s", dlerror ());
    #endif

    return false;
  }

  bridge_ctx->bridge_init = (BRIDGE_INIT) hc_dlsym (bridge_ctx->bridge_handle, "bridge_init");

  if (bridge_ctx->bridge_init == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot load symbol 'bridge_init' in bridge %s", bridge_file);

    return false;
  }

  hcfree (bridge_file);

  return true;
}

void bridge_unload (bridge_ctx_t *bridge_ctx)
{
  if (bridge_ctx->bridge_handle)
  {
    hc_dlclose (bridge_ctx->bridge_handle);
  }
}

bool bridges_init (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t    *bridge_ctx   = hashcat_ctx->bridge_ctx;
  user_options_t  *user_options = hashcat_ctx->user_options;
  hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;

  if (user_options->hash_info    == true) return true;
  if (user_options->left         == true) return true;
  if (user_options->show         == true) return true;
  if (user_options->usage         > 0)    return true;
  if (user_options->version      == true) return true;
  if (user_options->backend_info  > 0)    return true;

  // There is a problem here. At this point, hashconfig is not yet initialized.
  // This is because initializing hashconfig requires the module to be loaded,
  // but in order to load the module, we need to know the backend devices.
  // However, the backend devices are also not yet initialized, because
  // they require the virtualization count, which we only determine here.
  // To break this chicken-and-egg problem, we cheat by quick-loading the module
  // and unloading it afterwards, so it can be properly initialized later.

  const int hashconfig_init_rc = hashconfig_init (hashcat_ctx);

  if (hashconfig_init_rc == -1) return false;

  // ok, we can start

  if (hashconfig->bridge_type == BRIDGE_TYPE_NONE)
  {
    hashconfig_destroy (hashcat_ctx);

    return true;
  } 

  bridge_ctx->enabled = true;

  // finally, the real stuff

  const bool rc_load = bridge_load (hashcat_ctx, bridge_ctx, hashconfig->bridge_name);

  if (rc_load == false) return false;

  bridge_ctx->bridge_init (bridge_ctx);

  if (bridge_ctx->bridge_context_size != BRIDGE_CONTEXT_SIZE_CURRENT)
  {
    event_log_error (hashcat_ctx, "bridge context size is invalid. Old template?");

    return false;
  }

  if (bridge_ctx->bridge_interface_version < BRIDGE_INTERFACE_VERSION_MINIMUM)
  {
    event_log_error (hashcat_ctx, "bridge interface version is outdated, please compile");

    return false;
  }

  // check for missing pointer assignements

  #define CHECK_DEFINED(func)                                                     \
    if ((func) == NULL)                                                           \
    {                                                                             \
      event_log_error (hashcat_ctx, "Missing symbol definitions in bridge '%s'. Old template?", hashconfig->bridge_name); \
                                                                                  \
      return false;                                                               \
    }

  CHECK_DEFINED (bridge_ctx->platform_init);
  CHECK_DEFINED (bridge_ctx->platform_term);
  CHECK_DEFINED (bridge_ctx->get_unit_count);
  CHECK_DEFINED (bridge_ctx->get_unit_info);
  CHECK_DEFINED (bridge_ctx->get_workitem_count);
  CHECK_DEFINED (bridge_ctx->thread_init);
  CHECK_DEFINED (bridge_ctx->thread_term);
  CHECK_DEFINED (bridge_ctx->salt_prepare);
  CHECK_DEFINED (bridge_ctx->salt_destroy);
  CHECK_DEFINED (bridge_ctx->launch_loop);
  CHECK_DEFINED (bridge_ctx->launch_loop2);
  CHECK_DEFINED (bridge_ctx->st_update_hash);
  CHECK_DEFINED (bridge_ctx->st_update_pass);

  #undef CHECK_DEFINED

  // mandatory functions check

  #define CHECK_MANDATORY(func)                                               \
    if ((func) == MODULE_DEFAULT)                                             \
    {                                                                         \
      event_log_error (hashcat_ctx, "Missing mandatory symbol definitions");  \
                                                                              \
      return false;                                                           \
    }

  CHECK_MANDATORY (bridge_ctx->platform_init);
  CHECK_MANDATORY (bridge_ctx->platform_term);
  CHECK_MANDATORY (bridge_ctx->get_unit_count);
  CHECK_MANDATORY (bridge_ctx->get_unit_info);
  CHECK_MANDATORY (bridge_ctx->get_workitem_count);

  if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP)  CHECK_MANDATORY (bridge_ctx->launch_loop);
  if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP2) CHECK_MANDATORY (bridge_ctx->launch_loop2);

  #undef CHECK_MANDATORY

  bridge_ctx->platform_context = bridge_ctx->platform_init (user_options);

  if (bridge_ctx->platform_context == NULL)
  {
    event_log_error (hashcat_ctx, "Platform initialization failed");

    return false;
  }

  // auto adjust workitem counts

  if (hashconfig->bridge_type & BRIDGE_TYPE_MATCH_TUNINGS)
  {
    if ((hashconfig->opts_type & OPTS_TYPE_NATIVE_THREADS) == 0)
    {
      event_log_error (hashcat_ctx, "BRIDGE_TYPE_MATCH_TUNINGS requires OPTS_TYPE_NATIVE_THREADS");

      return false;
    }

    if ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) == 0)
    {
      event_log_error (hashcat_ctx, "BRIDGE_TYPE_MATCH_TUNINGS requires OPTS_TYPE_MP_MULTI_DISABLE");

      return false;
    }
  }

  // clean up

  hashconfig_destroy (hashcat_ctx);

  return true;
}

void bridges_destroy (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->enabled == false) return;

  bridge_ctx->platform_term (bridge_ctx->platform_context);

  bridge_unload (bridge_ctx);
}

bool bridges_salt_prepare (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t    *bridge_ctx   = hashcat_ctx->bridge_ctx;
  hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t        *hashes       = hashcat_ctx->hashes;
  user_options_t  *user_options = hashcat_ctx->user_options;

  if (user_options->hash_info    == true) return true;
  if (user_options->left         == true) return true;
  if (user_options->show         == true) return true;
  if (user_options->usage         > 0)    return true;
  if (user_options->version      == true) return true;
  if (user_options->backend_info  > 0)    return true;

  if (bridge_ctx->enabled == false) return true;

  if (bridge_ctx->salt_prepare == MODULE_DEFAULT) return true;

  if (bridge_ctx->salt_prepare (bridge_ctx->platform_context, hashconfig, hashes) == false)
  {
    event_log_error (hashcat_ctx, "Couldn't prepare salt specific data in bridge");

    return false;
  }

  return true;
}

void bridges_salt_destroy (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t    *bridge_ctx   = hashcat_ctx->bridge_ctx;
  hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t        *hashes       = hashcat_ctx->hashes;

  if (bridge_ctx->enabled == false) return;

  if (bridge_ctx->salt_destroy == MODULE_DEFAULT) return;

  bridge_ctx->salt_destroy (bridge_ctx->platform_context, hashconfig, hashes);
}
