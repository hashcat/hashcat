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

// Does this session run its workload through an assimilation bridge?
//
// Callers use it to decide that hardware_power is 1, so it is worth saying why that follows.
// kernel_power is hardware_power * kernel_accel, and hardware_power describes the GPU that GENERATES
// candidates. For an ordinary kernel that is right, because the generator is also the consumer.
//
// Under a bridge the consumer is the bridge unit and the generator is barely working, so multiplying
// -n by the generator's geometry makes -n mean something different on every host and stops it being
// the knob that sizes a bridge launch. The status view already presents -n and -u as bridge settings;
// this makes them so.
//
// Only the ACCOUNTING changes: kernel_threads still sets the generator's real launch geometry. This
// deliberately does NOT use OPTS_TYPE_THREAD_MULTI_DISABLE, which would also stop num_elements being
// divided by kernel_threads (backend.c) and so launch every candidate kernel_threads times over.

bool bridge_active (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const int bridge_link_device)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  bridge_ctx_t       *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (hashconfig->bridge_type == 0) return false;
  if (bridge_ctx->enabled == false) return false;

  return true;
}

// The multiple a bridge computes in, or 1 when there is no bridge.
//
// get_workitem_multiple is mandatory, so the BRIDGE_DEFAULT test is a guard rather than a normal path.
// It is written as a comparison and not as a truthiness test on purpose: BRIDGE_DEFAULT is
// (void *) -1, so a truthiness test passes and then calls address -1.

u32 bridge_workitem_multiple (hashcat_ctx_t *hashcat_ctx, const int bridge_link_device)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  bridge_ctx_t       *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (hashconfig->bridge_type == 0) return 1;
  if (bridge_ctx->enabled == false) return 1;
  if (bridge_ctx->get_workitem_multiple == BRIDGE_DEFAULT) return 1;

  const int multiple = bridge_ctx->get_workitem_multiple (bridge_ctx->platform_context, bridge_link_device);

  if (multiple < 1) return 1;

  return (u32) multiple;
}

bool bridges_init (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t    *bridge_ctx    = hashcat_ctx->bridge_ctx;
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  user_options_t  *user_options  = hashcat_ctx->user_options;
  hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;

  if (user_options->backend_info  > 0)    return true;
  if (user_options->hash_info     > 0)    return true;
  if (user_options->usage         > 0)    return true;
  if (user_options->left         == true) return true;
  if (user_options->show         == true) return true;
  if (user_options->version      == true) return true;

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
  CHECK_DEFINED (bridge_ctx->get_workitem_multiple);
  CHECK_DEFINED (bridge_ctx->thread_init);
  CHECK_DEFINED (bridge_ctx->thread_term);
  CHECK_DEFINED (bridge_ctx->salt_prepare);
  CHECK_DEFINED (bridge_ctx->salt_destroy);
  CHECK_DEFINED (bridge_ctx->launch_loop);
  CHECK_DEFINED (bridge_ctx->launch_loop2);
  CHECK_DEFINED (bridge_ctx->st_update_hash);
  CHECK_DEFINED (bridge_ctx->st_update_pass);
  CHECK_DEFINED (bridge_ctx->get_unit_temperature);
  CHECK_DEFINED (bridge_ctx->get_unit_fanspeed);
  CHECK_DEFINED (bridge_ctx->get_unit_utilization);
  CHECK_DEFINED (bridge_ctx->get_unit_corespeed);
  CHECK_DEFINED (bridge_ctx->get_unit_memoryspeed);
  CHECK_DEFINED (bridge_ctx->get_unit_buslanes);
  CHECK_DEFINED (bridge_ctx->get_unit_power);

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
  CHECK_MANDATORY (bridge_ctx->get_workitem_multiple);

  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)  CHECK_MANDATORY (bridge_ctx->launch_loop);
  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP2) CHECK_MANDATORY (bridge_ctx->launch_loop2);
  if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP)   CHECK_MANDATORY (bridge_ctx->launch_loop);
  if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP2)  CHECK_MANDATORY (bridge_ctx->launch_loop2);

  #undef CHECK_MANDATORY

  bridge_ctx->platform_context = bridge_ctx->platform_init (user_options, folder_config);

  if (bridge_ctx->platform_context == NULL)
  {
    event_log_error (hashcat_ctx, "Platform initialization failed");

    return false;
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

  if (user_options->backend_info  > 0)    return true;
  if (user_options->hash_info     > 0)    return true;
  if (user_options->usage         > 0)    return true;
  if (user_options->left         == true) return true;
  if (user_options->show         == true) return true;
  if (user_options->version      == true) return true;

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
