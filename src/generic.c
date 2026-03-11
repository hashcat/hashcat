/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "logfile.h"
#include "shared.h"
#include "folder.h"
#include "rp.h"
#include "generic.h"
#include "dynloader.h"

bool generic_global_init (hashcat_ctx_t *hashcat_ctx)
{
  generic_ctx_t        *generic_ctx        = hashcat_ctx->generic_ctx;
  folder_config_t      *folder_config      = hashcat_ctx->folder_config;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // we probably need to add more stuff here

  generic_ctx->global_ctx.quiet = user_options->quiet;

  generic_ctx->global_ctx.workc = user_options_extra->hc_workc;
  generic_ctx->global_ctx.workv = user_options_extra->hc_workv;

  generic_ctx->global_ctx.cache_dir   = folder_config->cache_dir;
  generic_ctx->global_ctx.profile_dir = folder_config->profile_dir;

  // ok we can also add hashcat_ctx, which might be hard to bind, but we make it optional
  // so those who support it, can have full access into hashcat core

  const bool rc = generic_ctx->global_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);

    return false;
  }

  return rc;
}

void generic_global_term (hashcat_ctx_t *hashcat_ctx)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  generic_ctx->global_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);
  }
}

u64 generic_global_keyspace (hashcat_ctx_t *hashcat_ctx)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  const u64 keyspace = generic_ctx->global_keyspace (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);

    return -1ULL;
  }

  return keyspace;
}

bool generic_thread_init (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  const bool rc = generic_ctx->thread_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);

    return false;
  }

  return rc;
}

void generic_thread_term (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);
  }
}

int generic_thread_next (hashcat_ctx_t *hashcat_ctx, const int device_id, u8 *out_buf)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  const int out_len = generic_ctx->thread_next (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id], out_buf);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);

    return -1U;
  }

  return out_len;
}

bool generic_thread_seek (hashcat_ctx_t *hashcat_ctx, const int device_id, const u64 offset)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  const bool rc = generic_ctx->thread_seek (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id], offset);

  if (generic_ctx->global_ctx.error == true)
  {
    event_log_error (hashcat_ctx, "%s", generic_ctx->global_ctx.error_msg);
  }

  return rc;
}

int generic_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  generic_ctx_t        *generic_ctx        = hashcat_ctx->generic_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  generic_ctx->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;

  if (user_options->attack_mode  == ATTACK_MODE_STRAIGHT)     return 0;
  if (user_options->attack_mode  == ATTACK_MODE_COMBI)        return 0;
  if (user_options->attack_mode  == ATTACK_MODE_BF)           return 0;
  if (user_options->attack_mode  == ATTACK_MODE_HYBRID1)      return 0;
  if (user_options->attack_mode  == ATTACK_MODE_HYBRID2)      return 0;
  if (user_options->attack_mode  == ATTACK_MODE_ASSOCIATION)  return 0;
  if (user_options->attack_mode  == ATTACK_MODE_PCFG)         return 0;

  generic_ctx->enabled = true;

  /**
   * dynloader
   */

  generic_ctx->dynlib_filename = user_options_extra->hc_workv[0];

  generic_ctx->lib = hc_dlopen (generic_ctx->dynlib_filename);

  if (generic_ctx->lib == NULL)
  {
    event_log_error (hashcat_ctx, "%s", hc_dlerror ());

    return -1;
  }

  const int *generic_plugin_version = (const int *) hc_dlsym (generic_ctx->lib, "GENERIC_PLUGIN_VERSION");

  if (generic_plugin_version == NULL)
  {
    event_log_error (hashcat_ctx, "%s", hc_dlerror ());

    return -1;
  }

  if (GENERIC_PLUGIN_VERSION_REQ > *generic_plugin_version)
  {
    event_log_error (hashcat_ctx, "%s: Plugin version is outdated: %d > %d", generic_ctx->dynlib_filename, GENERIC_PLUGIN_VERSION_REQ, *generic_plugin_version);

    return -1;
  }

  const generic_plugin_options_t *generic_plugin_options = (const generic_plugin_options_t *) hc_dlsym (generic_ctx->lib, "GENERIC_PLUGIN_OPTIONS");

  if (generic_plugin_options == NULL)
  {
    event_log_error (hashcat_ctx, "%s", hc_dlerror ());

    return -1;
  }

  generic_ctx->thread_ctx = hccalloc (sizeof (generic_thread_ctx_t), DEVICES_MAX);

  generic_ctx->autohex_enable = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_AUTOHEX) ? true : false;
  generic_ctx->iconv_enable   = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_ICONV)   ? true : false;
  generic_ctx->rules_enable   = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_RULES)   ? true : false;

  HC_LOAD_FUNC_GENERIC (generic_ctx, global_init,     GENERIC_GLOBAL_INIT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, global_term,     GENERIC_GLOBAL_TERM);
  HC_LOAD_FUNC_GENERIC (generic_ctx, global_keyspace, GENERIC_GLOBAL_KEYSPACE);

  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_init,     GENERIC_THREAD_INIT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_term,     GENERIC_THREAD_TERM);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_next,     GENERIC_THREAD_NEXT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_seek,     GENERIC_THREAD_SEEK);

  /**
   * generate NOP rules
   */

  if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
  {
    straight_ctx->kernel_rules_buf = (kernel_rule_t *) hcmalloc (sizeof (kernel_rule_t));

    straight_ctx->kernel_rules_buf[0].cmds[0] = RULE_OP_MANGLE_NOOP;

    straight_ctx->kernel_rules_cnt = 1;
  }
  else
  {
    if (user_options->rp_files_cnt)
    {
      EVENT (EVENT_RULESFILES_PARSE_PRE);

      if (kernel_rules_load (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt) == -1) return -1;

      EVENT (EVENT_RULESFILES_PARSE_POST);
    }
    else if (user_options->rp_gen)
    {
      if (kernel_rules_generate (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt, user_options->rp_gen_func_sel) == -1) return -1;
    }
  }

  EVENT (EVENT_CLEAR_EVENT_LINE);

  if (generic_global_init (hashcat_ctx) == false) return -1;

  status_ctx->words_cnt = generic_global_keyspace (hashcat_ctx);

  if (status_ctx->words_cnt != -1ULL)
  {
    status_ctx->words_cnt *= straight_ctx->kernel_rules_cnt;
  }

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (generic_thread_init (hashcat_ctx, device_param->device_id) == false) return -1;
  }

  return 0;
}

void generic_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  generic_ctx_t  *generic_ctx  = hashcat_ctx->generic_ctx;
  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  if (generic_ctx->enabled == false) return;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    generic_thread_term (hashcat_ctx, device_param->device_id);
  }

  hcfree (generic_ctx->thread_ctx);

  generic_global_term (hashcat_ctx);

  hcfree (straight_ctx->kernel_rules_buf);

  memset (generic_ctx,  0, sizeof (generic_ctx_t));
  memset (straight_ctx, 0, sizeof (straight_ctx_t));
}
