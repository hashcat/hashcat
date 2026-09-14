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
    const int plugin_abi = hc_dlplugin_abi (bridge_file);

    if ((plugin_abi != -1) && (plugin_abi != HC_PLUGIN_ABI_VERSION))
    {
      event_log_error (hashcat_ctx, "Bridge %s was built for plugin interface %d, this hashcat provides %d", bridge_file, plugin_abi, HC_PLUGIN_ABI_VERSION);
    }
    else
    {
      #if defined (_WIN)
      event_log_error (hashcat_ctx, "Cannot load bridge %s: %s", bridge_file, hc_dlerror ());
      #else
      event_log_error (hashcat_ctx, "%s", hc_dlerror ());
      #endif
    }

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

// Are these two units the same kind of thing, so that a tuning result found on one is valid on the
// other?
//
// A bridge appears to the backend as one virtual device cloned per unit, so every test that asks the
// BACKEND what a device is answers identically for all of them and can only ever say "all the same".
// The bridge is the only thing that knows, which is also why this is cheap: it reports what its units
// are rather than having it inferred from a driver API.
//
// get_unit_class is optional. Without it, compare what the units call themselves, which is right when
// a bridge's units really are identical. A bridge whose info string names the individual device, by
// carrying its device node for instance, needs the class or no two units ever match.

bool bridge_same_unit_class (hashcat_ctx_t *hashcat_ctx, const int unit_a, const int unit_b)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->enabled == false) return false;

  if (unit_a == unit_b) return true;

  if ((unit_a < 0) || (unit_b < 0)) return false;

  char *(*describe) (hashcat_ctx_t *, void *, const int) = bridge_ctx->get_unit_class;

  if ((describe == NULL) || (describe == BRIDGE_DEFAULT)) describe = bridge_ctx->get_unit_info;

  if ((describe == NULL) || (describe == BRIDGE_DEFAULT)) return false;

  const char *class_a = describe (hashcat_ctx, bridge_ctx->platform_context, unit_a);
  const char *class_b = describe (hashcat_ctx, bridge_ctx->platform_context, unit_b);

  // Nothing to compare is not the same as comparing equal. Saying yes here would copy one unit's
  // tuning onto a unit nobody could describe.

  if ((class_a == NULL) || (class_b == NULL)) return false;

  const bool same = (strcmp (class_a, class_b) == 0);

  return same;
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

  const int multiple = bridge_ctx->get_workitem_multiple (hashcat_ctx, bridge_ctx->platform_context, bridge_link_device);

  if (multiple < 1) return 1;

  return (u32) multiple;
}

// The most candidates a bridge unit takes in one launch, or 0 when there is no bridge to take any.
//
// Gated on the bridge being loaded and not only on the mode wanting one. Those are different
// questions: hashconfig->bridge_type is a property of the hash mode, and whether a bridge is up is a
// property of the run. A benchmark that walks every hash mode passes through modes that want one
// while none is loaded, and calling the hook then is a call through a null pointer.
//
// Written as a comparison against BRIDGE_DEFAULT rather than a truthiness test, the same as
// bridge_workitem_multiple () above: BRIDGE_DEFAULT is (void *) -1, which passes a truthiness test
// and then calls address -1.

u32 bridge_workitem_count (hashcat_ctx_t *hashcat_ctx, const int bridge_link_device)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  bridge_ctx_t       *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (hashconfig->bridge_type == 0) return 0;
  if (bridge_ctx->enabled == false) return 0;
  if (bridge_ctx->get_workitem_count == NULL) return 0;
  if (bridge_ctx->get_workitem_count == BRIDGE_DEFAULT) return 0;

  const int count = bridge_ctx->get_workitem_count (hashcat_ctx, bridge_ctx->platform_context, bridge_link_device);

  if (count < 1) return 0;

  return (u32) count;
}

// Bring up the bridge this hash mode selects. hashconfig has to be live, so bridges_init () quick
// loads one and a caller that already has one calls this directly.
//
// A bridge that is already up is left alone. Loading one is not free: an FPGA bridge programs the
// boards it finds as part of coming up.

bool bridges_init_late (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (bridge_ctx->bridge_handle != NULL) return true;

  if (hashconfig->bridge_type == BRIDGE_TYPE_NONE) return true;

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

  bridge_ctx->platform_context = bridge_ctx->platform_init (hashcat_ctx);

  if (bridge_ctx->platform_context == NULL)
  {
    event_log_error (hashcat_ctx, "Platform initialization failed");

    return false;
  }

  return true;
}

bool bridges_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // -I normally has no hash mode, and a bridge is chosen by the mode, so there is nothing to load and
  // the device list is the whole answer. When a mode IS named the bridge it selects is loaded, because
  // for that mode the units are what compute and a device list without them is not an answer at all.
  //
  // Gated on the mode being named rather than on -I alone, because loading a bridge is not free: an
  // FPGA bridge programs the boards it finds as part of coming up. Naming the mode is the user asking
  // for exactly that, which is the same thing a real run would do.

  if ((user_options->backend_info > 0) && (user_options->hash_mode_chgd == false)) return true;
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

  const bool rc = bridges_init_late (hashcat_ctx);

  // The quick load was only ever to read bridge_type and bridge_name out of the mode. outer_loop
  // initialises hashconfig properly for the mode it is about to run.

  hashconfig_destroy (hashcat_ctx);

  return rc;
}



void bridges_destroy (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->enabled == false) return;

  // A bridge that never came up is torn down through here as well, because a sweep over the hash modes
  // carries on past one that cannot start. Two things can be missing by then. The hooks exist only
  // once the library loaded, and the platform context exists only once platform_init returned one,
  // which is the same NULL bridges_init_late reads as a failure. A term hook is written against a
  // context it built, and half of the ones shipped here dereference it without checking, so neither
  // can be assumed. The unload below still has to run, which is why enabled is set before the load
  // rather than after it.

  if ((bridge_ctx->platform_term != NULL) && (bridge_ctx->platform_term != BRIDGE_DEFAULT) && (bridge_ctx->platform_context != NULL))
  {
    bridge_ctx->platform_term (hashcat_ctx, bridge_ctx->platform_context);
  }

  bridge_unload (bridge_ctx);

  // Every hook in here pointed into the library that was just closed, and enabled said one was
  // loaded. A run that walks several hash modes comes back through here between them, so leaving
  // either behind hands the next mode a pointer into an unmapped library.

  memset (bridge_ctx, 0, sizeof (bridge_ctx_t));
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

  if (bridge_ctx->salt_prepare (hashcat_ctx, bridge_ctx->platform_context, hashconfig, hashes) == false)
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

  bridge_ctx->salt_destroy (hashcat_ctx, bridge_ctx->platform_context, hashconfig, hashes);
}
