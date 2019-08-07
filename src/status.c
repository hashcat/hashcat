/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "convert.h"
#include "thread.h"
#include "timer.h"
#include "hashes.h"
#include "hwmon.h"
#include "outfile.h"
#include "monitor.h"
#include "mpsp.h"
#include "terminal.h"
#include "shared.h"
#include "status.h"

static const char *ST_0000 = "Initializing";
static const char *ST_0001 = "Autotuning";
static const char *ST_0002 = "Selftest";
static const char *ST_0003 = "Running";
static const char *ST_0004 = "Paused";
static const char *ST_0005 = "Exhausted";
static const char *ST_0006 = "Cracked";
static const char *ST_0007 = "Aborted";
static const char *ST_0008 = "Quit";
static const char *ST_0009 = "Bypass";
static const char *ST_0010 = "Aborted (Checkpoint)";
static const char *ST_0011 = "Aborted (Runtime)";
static const char *ST_0012 = "Running (Checkpoint Quit requested)";
static const char *ST_0013 = "Error";
static const char *ST_9999 = "Unknown! Bug!";

static const char UNITS[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

static const char *ETA_ABSOLUTE_MAX_EXCEEDED = "Next Big Bang"; // in honor of ighashgpu
static const char *ETA_RELATIVE_MAX_EXCEEDED = "> 10 years";

static char *status_get_rules_file (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->rp_files_cnt > 0)
  {
    char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_TINY);

    int tmp_len = 0;

    u32 i;

    for (i = 0; i < user_options->rp_files_cnt - 1; i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len, "%s, ", user_options->rp_files[i]);
    }

    tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len, "%s", user_options->rp_files[i]);

    tmp_buf[tmp_len] = 0;

    return tmp_buf; // yes, user need to free()
  }

  return NULL;
}

void format_timer_display (struct tm *tm, char *buf, size_t len)
{
  const char *const time_entities_s[] = { "year",  "day",  "hour",  "min",  "sec"  };
  const char *const time_entities_m[] = { "years", "days", "hours", "mins", "secs" };

  if (tm->tm_year - 70)
  {
    const char *time_entity1 = ((tm->tm_year - 70) == 1) ? time_entities_s[0] : time_entities_m[0];
    const char *time_entity2 = ( tm->tm_yday       == 1) ? time_entities_s[1] : time_entities_m[1];

    snprintf (buf, len, "%d %s, %d %s", tm->tm_year - 70, time_entity1, tm->tm_yday, time_entity2);
  }
  else if (tm->tm_yday)
  {
    const char *time_entity1 = (tm->tm_yday == 1) ? time_entities_s[1] : time_entities_m[1];
    const char *time_entity2 = (tm->tm_hour == 1) ? time_entities_s[2] : time_entities_m[2];

    snprintf (buf, len, "%d %s, %d %s", tm->tm_yday, time_entity1, tm->tm_hour, time_entity2);
  }
  else if (tm->tm_hour)
  {
    const char *time_entity1 = (tm->tm_hour == 1) ? time_entities_s[2] : time_entities_m[2];
    const char *time_entity2 = (tm->tm_min  == 1) ? time_entities_s[3] : time_entities_m[3];

    snprintf (buf, len, "%d %s, %d %s", tm->tm_hour, time_entity1, tm->tm_min, time_entity2);
  }
  else if (tm->tm_min)
  {
    const char *time_entity1 = (tm->tm_min == 1) ? time_entities_s[3] : time_entities_m[3];
    const char *time_entity2 = (tm->tm_sec == 1) ? time_entities_s[4] : time_entities_m[4];

    snprintf (buf, len, "%d %s, %d %s", tm->tm_min, time_entity1, tm->tm_sec, time_entity2);
  }
  else
  {
    const char *time_entity1 = (tm->tm_sec == 1) ? time_entities_s[4] : time_entities_m[4];

    snprintf (buf, len, "%d %s", tm->tm_sec, time_entity1);
  }
}

void format_speed_display (double val, char *buf, size_t len)
{
  if (val <= 0)
  {
    buf[0] = '0';
    buf[1] = ' ';
    buf[2] = 0;

    return;
  }

  u32 level = 0;

  while (val > 99999)
  {
    val /= 1000;

    level++;
  }

  /* generate output */

  if (level == 0)
  {
    snprintf (buf, len, "%.0f ", val);
  }
  else
  {
    snprintf (buf, len, "%.1f %c", val, UNITS[level]);
  }
}

void format_speed_display_1k (double val, char *buf, size_t len)
{
  if (val <= 0)
  {
    buf[0] = '0';
    buf[1] = ' ';
    buf[2] = 0;

    return;
  }

  u32 level = 0;

  while (val > 999)
  {
    val /= 1000;

    level++;
  }

  /* generate output */

  if (level == 0)
  {
    snprintf (buf, len, "%.0f ", val);
  }
  else
  {
    snprintf (buf, len, "%.1f %c", val, UNITS[level]);
  }
}

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries)
{
  int exec_pos = (int) device_param->exec_pos - last_num_entries;

  if (exec_pos < 0) exec_pos += EXEC_CACHE;

  double exec_msec_sum = 0;

  int exec_msec_cnt = 0;

  for (int i = 0; i < last_num_entries; i++)
  {
    double exec_msec = device_param->exec_msec[(exec_pos + i) % EXEC_CACHE];

    if (exec_msec > 0)
    {
      exec_msec_sum += exec_msec;

      exec_msec_cnt++;
    }
  }

  if (exec_msec_cnt == 0) return 0;

  return exec_msec_sum / exec_msec_cnt;
}

int status_get_device_info_cnt (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  return backend_ctx->backend_devices_cnt;
}

int status_get_device_info_active (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  return backend_ctx->backend_devices_active;
}

bool status_get_skipped_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  return device_param->skipped;
}

bool status_get_skipped_warning_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  return device_param->skipped_warning;
}

char *status_get_session (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  return strdup (user_options->session);
}

#ifdef WITH_BRAIN
int status_get_brain_session (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  return user_options->brain_session;
}

int status_get_brain_attack (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  return user_options->brain_attack;
}
#endif

const char *status_get_status_string (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const int devices_status = status_ctx->devices_status;

  // special case: running but checkpoint quit requested

  if (devices_status == STATUS_RUNNING)
  {
    if (status_ctx->checkpoint_shutdown == true)
    {
      return ST_0012;
    }
  }

  switch (devices_status)
  {
    case STATUS_INIT:               return ST_0000;
    case STATUS_AUTOTUNE:           return ST_0001;
    case STATUS_SELFTEST:           return ST_0002;
    case STATUS_RUNNING:            return ST_0003;
    case STATUS_PAUSED:             return ST_0004;
    case STATUS_EXHAUSTED:          return ST_0005;
    case STATUS_CRACKED:            return ST_0006;
    case STATUS_ABORTED:            return ST_0007;
    case STATUS_QUIT:               return ST_0008;
    case STATUS_BYPASS:             return ST_0009;
    case STATUS_ABORTED_CHECKPOINT: return ST_0010;
    case STATUS_ABORTED_RUNTIME:    return ST_0011;
    case STATUS_ERROR:              return ST_0013;
  }

  return ST_9999;
}

int status_get_status_number (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  return status_ctx->devices_status;
}

char *status_get_hash_name (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  return hcstrdup (hashconfig->hash_name);
}

char *status_get_hash_target (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  if ((hashes->digests_cnt == 1) || (hashes->hashfile == NULL))
  {
    if (module_ctx->module_hash_encode_status != MODULE_DEFAULT)
    {
      char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

      const int tmp_len = module_ctx->module_hash_encode_status (hashconfig, hashes->digests_buf, hashes->salts_buf, hashes->esalts_buf, hashes->hook_salts_buf, NULL, tmp_buf, HCBUFSIZ_LARGE);

      char *tmp_buf2 = (char *) hcmalloc (tmp_len + 1);

      memcpy (tmp_buf2, tmp_buf, tmp_len);

      tmp_buf2[tmp_len] = 0;

      free (tmp_buf);

      return tmp_buf2;
    }

    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
    {
      return hcstrdup (hashes->hashfile);
    }

    char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

    const int tmp_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, tmp_buf, HCBUFSIZ_LARGE, 0, 0);

    tmp_buf[tmp_len] = 0;

    compress_terminal_line_length (tmp_buf, 19, 6); // 19 = strlen ("Hash.Target......: ")

    char *tmp_buf2 = strdup (tmp_buf);

    free (tmp_buf);

    return tmp_buf2;
  }

  return hcstrdup (hashes->hashfile);
}

int status_get_guess_mode (const hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  bool has_wordlist   = false;
  bool has_rule_file  = false;
  bool has_rule_gen   = false;
  bool has_base_left  = false;
  bool has_mask_cs    = false;

  if (user_options_extra->wordlist_mode == WL_MODE_FILE) has_wordlist = true;

  if (user_options->rp_files_cnt > 0) has_rule_file = true;
  if (user_options->rp_gen       > 0) has_rule_gen  = true;

  if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT) has_base_left = true;

  if (user_options->custom_charset_1) has_mask_cs = true;
  if (user_options->custom_charset_2) has_mask_cs = true;
  if (user_options->custom_charset_3) has_mask_cs = true;
  if (user_options->custom_charset_4) has_mask_cs = true;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (has_wordlist == true)
    {
      if (has_rule_file == true)
      {
        return GUESS_MODE_STRAIGHT_FILE_RULES_FILE;
      }
      if (has_rule_gen == true)
      {
        return GUESS_MODE_STRAIGHT_FILE_RULES_GEN;
      }
      return GUESS_MODE_STRAIGHT_FILE;
    }
    if (has_rule_file == true)
    {
      return GUESS_MODE_STRAIGHT_STDIN_RULES_FILE;
    }
    if (has_rule_gen == true)
    {
      return GUESS_MODE_STRAIGHT_STDIN_RULES_GEN;
    }
    return GUESS_MODE_STRAIGHT_STDIN;
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    if (has_base_left == true)
    {
      return GUESS_MODE_COMBINATOR_BASE_LEFT;
    }
    return GUESS_MODE_COMBINATOR_BASE_RIGHT;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (has_mask_cs == true)
    {
      return GUESS_MODE_MASK_CS;
    }
    return GUESS_MODE_MASK;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (has_mask_cs == true)
    {
      return GUESS_MODE_HYBRID1_CS;
    }
    return GUESS_MODE_HYBRID1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (has_mask_cs == true)
    {
      return GUESS_MODE_HYBRID2_CS;
    }
    return GUESS_MODE_HYBRID2;
  }

  return GUESS_MODE_NONE;
}

char *status_get_guess_base (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
    {
      const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

      return strdup (straight_ctx->dict);
    }
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

    if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      return strdup (combinator_ctx->dict1);
    }
    return strdup (combinator_ctx->dict2);
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return strdup (mask_ctx->mask);
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return strdup (straight_ctx->dict);
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

      return strdup (mask_ctx->mask);
    }

    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return strdup (straight_ctx->dict);
  }
  return NULL;
}

int status_get_guess_base_offset (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

      return mask_ctx->masks_pos + 1;
    }

    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_pos + 1;
  }

  return 0;
}

int status_get_guess_base_count (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

      return mask_ctx->masks_cnt;
    }

    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_cnt;
  }

  return 0;
}

double status_get_guess_base_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const int guess_base_offset = status_get_guess_base_offset (hashcat_ctx);
  const int guess_base_count  = status_get_guess_base_count (hashcat_ctx);

  if (guess_base_count == 0) return 0;

  return ((double) guess_base_offset / (double) guess_base_count) * 100;
}

char *status_get_guess_mod (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    return status_get_rules_file (hashcat_ctx);
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

    if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      return strdup (combinator_ctx->dict2);
    }
    return strdup (combinator_ctx->dict1);
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {

  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return strdup (mask_ctx->mask);
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

      return strdup (straight_ctx->dict);
    }

    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return strdup (mask_ctx->mask);
  }

  return NULL;
}

int status_get_guess_mod_offset (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

      return straight_ctx->dicts_pos + 1;
    }

    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_pos + 1;
  }

  return 0;
}

int status_get_guess_mod_count (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

      return straight_ctx->dicts_cnt;
    }

    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_cnt;
  }

  return 0;
}

double status_get_guess_mod_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const int guess_mod_offset = status_get_guess_mod_offset (hashcat_ctx);
  const int guess_mod_count  = status_get_guess_mod_count  (hashcat_ctx);

  if (guess_mod_count == 0) return 0;

  return ((double) guess_mod_offset / (double) guess_mod_count) * 100;
}

char *status_get_guess_charset (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  const char *custom_charset_1 = user_options->custom_charset_1;
  const char *custom_charset_2 = user_options->custom_charset_2;
  const char *custom_charset_3 = user_options->custom_charset_3;
  const char *custom_charset_4 = user_options->custom_charset_4;

  if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL))
  {
    char *tmp_buf;

    if (custom_charset_1 == NULL) custom_charset_1 = "Undefined";
    if (custom_charset_2 == NULL) custom_charset_2 = "Undefined";
    if (custom_charset_3 == NULL) custom_charset_3 = "Undefined";
    if (custom_charset_4 == NULL) custom_charset_4 = "Undefined";

    hc_asprintf (&tmp_buf, "-1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);

    return tmp_buf;
  }

  return NULL;
}

int status_get_guess_mask_length (const hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  if (mask_ctx == NULL) return -1;

  if (mask_ctx->mask == NULL) return -1;

  return mp_get_length (mask_ctx->mask);
}

char *status_get_guess_candidates_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (status_ctx->accessible == false) return NULL;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  if ((device_param->skipped == true) || (device_param->skipped_warning == true))
  {
    snprintf (display, HCBUFSIZ_TINY, "[Skipped]");

    return display;
  }

  if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    snprintf (display, HCBUFSIZ_TINY, "[Generating]");
  }
  else
  {
    snprintf (display, HCBUFSIZ_TINY, "[Copying]");
  }

  if ((device_param->outerloop_left == 0) || (device_param->innerloop_left == 0)) return display;

  const u64 outerloop_first = 0;
  const u64 outerloop_last  = device_param->outerloop_left - 1;

  const u32 innerloop_first = 0;
  const u32 innerloop_last  = device_param->innerloop_left - 1;

  plain_t plain1 = { outerloop_first, innerloop_first, 0, 0, 0, 0, 0 };
  plain_t plain2 = { outerloop_last,  innerloop_last,  0, 0, 0, 0, 0 };

  u32 plain_buf1[(64 * 2) + 2] = { 0 };
  u32 plain_buf2[(64 * 2) + 2] = { 0 };

  u8 *plain_ptr1 = (u8 *) plain_buf1;
  u8 *plain_ptr2 = (u8 *) plain_buf2;

  int plain_len1 = 0;
  int plain_len2 = 0;

  build_plain ((hashcat_ctx_t *) hashcat_ctx, device_param, &plain1, plain_buf1, &plain_len1);
  build_plain ((hashcat_ctx_t *) hashcat_ctx, device_param, &plain2, plain_buf2, &plain_len2);

  const bool always_ascii = (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_ASCII) ? true : false;

  const bool need_hex1 = need_hexify (plain_ptr1, plain_len1, 0, always_ascii);
  const bool need_hex2 = need_hexify (plain_ptr2, plain_len2, 0, always_ascii);

  if ((need_hex1 == true) || (need_hex2 == true))
  {
    exec_hexify (plain_ptr1, plain_len1, plain_ptr1);
    exec_hexify (plain_ptr2, plain_len2, plain_ptr2);

    plain_ptr1[plain_len1 * 2] = 0;
    plain_ptr2[plain_len2 * 2] = 0;

    snprintf (display, HCBUFSIZ_TINY, "$HEX[%s] -> $HEX[%s]", plain_ptr1, plain_ptr2);
  }
  else
  {
    plain_ptr1[plain_len1] = 0;
    plain_ptr2[plain_len2] = 0;

    snprintf (display, HCBUFSIZ_TINY, "%s -> %s", plain_ptr1, plain_ptr2);
  }

  return display;
}

int status_get_digests_done (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->digests_done;
}

int status_get_digests_cnt (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->digests_cnt;
}

double status_get_digests_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  if (hashes->digests_cnt == 0) return 0;

  return ((double) hashes->digests_done / (double) hashes->digests_cnt) * 100;
}

int status_get_salts_done (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->salts_done;
}

int status_get_salts_cnt (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->salts_cnt;
}

double status_get_salts_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  if (hashes->salts_cnt == 0) return 0;

  return ((double) hashes->salts_done / (double) hashes->salts_cnt) * 100;
}

double status_get_msec_running (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  double msec_running = hc_timer_get (status_ctx->timer_running);

  return msec_running;
}

double status_get_msec_paused (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  double msec_paused = status_ctx->msec_paused;

  if (status_ctx->devices_status == STATUS_PAUSED)
  {
    double msec_paused_tmp = hc_timer_get (status_ctx->timer_paused);

    msec_paused += msec_paused_tmp;
  }

  return msec_paused;
}

double status_get_msec_real (const hashcat_ctx_t *hashcat_ctx)
{
  const double msec_running = status_get_msec_running (hashcat_ctx);
  const double msec_paused  = status_get_msec_paused  (hashcat_ctx);

  const double msec_real = msec_running - msec_paused;

  return msec_real;
}

char *status_get_time_started_absolute (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const time_t time_start = status_ctx->runtime_start;

  char buf[32] = { 0 };

  char *start = ctime_r (&time_start, buf);

  const size_t start_len = strlen (start);

  if (start[start_len - 1] == '\n') start[start_len - 1] = 0;
  if (start[start_len - 2] == '\r') start[start_len - 2] = 0;

  return strdup (start);
}

char *status_get_time_started_relative (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  time_t time_now;

  time (&time_now);

  const time_t time_start = status_ctx->runtime_start;

  time_t sec_run = time_now - time_start;

  struct tm *tmp;
  struct tm  tm;

  tmp = gmtime_r (&sec_run, &tm);

  char *display_run = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_timer_display (tmp, display_run, HCBUFSIZ_TINY);

  return display_run;
}

time_t status_get_sec_etc (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  time_t sec_etc = 0;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (status_ctx->devices_status != STATUS_CRACKED)
    {
      const u64 progress_cur_relative_skip = status_get_progress_cur_relative_skip (hashcat_ctx);
      const u64 progress_end_relative_skip = status_get_progress_end_relative_skip (hashcat_ctx);

      const u64 progress_ignore = status_get_progress_ignore (hashcat_ctx);

      const double hashes_msec_all = status_get_hashes_msec_all (hashcat_ctx);

      if (hashes_msec_all > 0)
      {
        const u64 progress_left_relative_skip = progress_end_relative_skip - progress_cur_relative_skip;

        u64 msec_left = (u64) ((progress_left_relative_skip - progress_ignore) / hashes_msec_all);

        sec_etc = msec_left / 1000;
      }
    }
  }

  return sec_etc;
}

char *status_get_time_estimated_absolute (const hashcat_ctx_t *hashcat_ctx)
{
  time_t sec_etc = status_get_sec_etc (hashcat_ctx);

  time_t now;
  time (&now);


  char buf[32] = { 0 };

  char *etc;

  if (overflow_check_u64_add (now, sec_etc) == false)
  {
    etc = (char *) ETA_ABSOLUTE_MAX_EXCEEDED;
  }
  else
  {
    time_t end = now + sec_etc;

    etc = ctime_r (&end, buf);

    if (etc == NULL) etc = (char *) ETA_ABSOLUTE_MAX_EXCEEDED;
  }

  const size_t etc_len = strlen (etc);

  if (etc[etc_len - 1] == '\n') etc[etc_len - 1] = 0;
  if (etc[etc_len - 2] == '\r') etc[etc_len - 2] = 0;

  return strdup (etc);
}

char *status_get_time_estimated_relative (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  time_t sec_etc = status_get_sec_etc (hashcat_ctx);

  struct tm *tmp;
  struct tm  tm;

  tmp = gmtime_r (&sec_etc, &tm);

  if (tmp == NULL)
  {
    snprintf (display, HCBUFSIZ_TINY, "%s", ETA_RELATIVE_MAX_EXCEEDED);
  }
  else
  {
    format_timer_display (tmp, display, HCBUFSIZ_TINY);
  }

  if (user_options->runtime > 0)
  {
    const int runtime_left = get_runtime_left (hashcat_ctx);

    char *tmp_display = strdup (display);

    if (runtime_left > 0)
    {
      time_t sec_left = runtime_left;

      struct tm *tmp_left;
      struct tm  tm_left;

      tmp_left = gmtime_r (&sec_left, &tm_left);

      char *display_left = (char *) hcmalloc (HCBUFSIZ_TINY);

      format_timer_display (tmp_left, display_left, HCBUFSIZ_TINY);

      snprintf (display, HCBUFSIZ_TINY, "%s; Runtime limited: %s", tmp_display, display_left);

      free (display_left);
    }
    else
    {
      snprintf (display, HCBUFSIZ_TINY, "%s; Runtime limit exceeded", tmp_display);
    }

    free (tmp_display);
  }

  return display;
}

u64 status_get_restore_point (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 restore_point = status_ctx->words_cur;

  return restore_point;
}

u64 status_get_restore_total (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 restore_total = status_ctx->words_base;

  return restore_total;
}

double status_get_restore_percent (const hashcat_ctx_t *hashcat_ctx)
{
  double restore_percent = 0;

  const u64 restore_point = status_get_restore_point (hashcat_ctx);
  const u64 restore_total = status_get_restore_total (hashcat_ctx);

  if (restore_total > 0)
  {
    restore_percent = ((double) restore_point / (double) restore_total) * 100;
  }

  return restore_percent;
}

int status_get_progress_mode (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_end_relative_skip = status_get_progress_end_relative_skip (hashcat_ctx);

  if (progress_end_relative_skip > 0)
  {
    return PROGRESS_MODE_KEYSPACE_KNOWN;
  }
  return PROGRESS_MODE_KEYSPACE_UNKNOWN;
}

double status_get_progress_finished_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_cur_relative_skip = status_get_progress_cur_relative_skip (hashcat_ctx);
  const u64 progress_end_relative_skip = status_get_progress_end_relative_skip (hashcat_ctx);

  double progress_finished_percent = 0;

  if (progress_end_relative_skip > 0)
  {
    progress_finished_percent = ((double) progress_cur_relative_skip / (double) progress_end_relative_skip) * 100;
  }

  return progress_finished_percent;
}

u64 status_get_progress_done (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  u64 progress_done = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    progress_done += status_ctx->words_progress_done[salt_pos];
  }

  return progress_done;
}

u64 status_get_progress_rejected (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  u64 progress_rejected = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    progress_rejected += status_ctx->words_progress_rejected[salt_pos];
  }

  return progress_rejected;
}

double status_get_progress_rejected_percent (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_cur      = status_get_progress_cur      (hashcat_ctx);
  const u64 progress_rejected = status_get_progress_rejected (hashcat_ctx);

  double percent_rejected = 0;

  if (progress_cur)
  {
    percent_rejected = ((double) (progress_rejected) / (double) progress_cur) * 100;
  }

  return percent_rejected;
}

u64 status_get_progress_restored (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  u64 progress_restored = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    progress_restored += status_ctx->words_progress_restored[salt_pos];
  }

  return progress_restored;
}

u64 status_get_progress_cur (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_done     = status_get_progress_done     (hashcat_ctx);
  const u64 progress_rejected = status_get_progress_rejected (hashcat_ctx);
  const u64 progress_restored = status_get_progress_restored (hashcat_ctx);

  const u64 progress_cur = progress_done + progress_rejected + progress_restored;

  return progress_cur;
}

u64 status_get_progress_ignore (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // Important for ETA only

  u64 progress_ignore = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    if (hashes->salts_shown[salt_pos] == 1)
    {
      const u64 all = status_ctx->words_progress_done[salt_pos]
                    + status_ctx->words_progress_rejected[salt_pos]
                    + status_ctx->words_progress_restored[salt_pos];

      const u64 left = status_ctx->words_cnt - all;

      progress_ignore += left;
    }
  }

  return progress_ignore;
}

u64 status_get_progress_end (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  u64 progress_end = status_ctx->words_cnt * hashes->salts_cnt;

  if (user_options->limit)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
    const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
    const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;

    progress_end = MIN (user_options->limit, status_ctx->words_base) * hashes->salts_cnt;

    if (user_options->slow_candidates == true)
    {
      // nothing to do
    }
    else
    {
      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_end  *= combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_end  *= mask_ctx->bfs_cnt;
    }
  }

  return progress_end;
}

u64 status_get_progress_skip (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  u64 progress_skip = 0;

  if (user_options->skip)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
    const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
    const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;

    progress_skip = MIN (user_options->skip, status_ctx->words_base) * hashes->salts_cnt;

    if (user_options->slow_candidates == true)
    {
      // nothing to do
    }
    else
    {
      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_skip *= combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_skip *= mask_ctx->bfs_cnt;
    }
  }

  return progress_skip;
}

u64 status_get_progress_cur_relative_skip (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_skip = status_get_progress_skip (hashcat_ctx);
  const u64 progress_cur  = status_get_progress_cur  (hashcat_ctx);

  u64 progress_cur_relative_skip = 0;

  if (progress_cur > 0)
  {
    progress_cur_relative_skip = progress_cur - progress_skip;
  }

  return progress_cur_relative_skip;
}

u64 status_get_progress_end_relative_skip (const hashcat_ctx_t *hashcat_ctx)
{
  const u64 progress_skip = status_get_progress_skip (hashcat_ctx);
  const u64 progress_end  = status_get_progress_end  (hashcat_ctx);

  u64 progress_end_relative_skip = 0;

  if (progress_end > 0)
  {
    progress_end_relative_skip = progress_end - progress_skip;
  }

  return progress_end_relative_skip;
}

double status_get_hashes_msec_all (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  double hashes_all_msec = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hashes_all_msec += status_get_hashes_msec_dev (hashcat_ctx, backend_devices_idx);
  }

  return hashes_all_msec;
}

double status_get_hashes_msec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64    speed_cnt  = 0;
  double speed_msec = 0;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    const u32 speed_pos = MAX (device_param->speed_pos, 1);

    for (u32 i = 0; i < speed_pos; i++)
    {
      speed_cnt  += device_param->speed_cnt[i];
      speed_msec += device_param->speed_msec[i];
    }

    speed_cnt  /= speed_pos;
    speed_msec /= speed_pos;
  }

  double hashes_dev_msec = 0;

  if (speed_msec > 0)
  {
    hashes_dev_msec = (double) speed_cnt / speed_msec;
  }

  return hashes_dev_msec;
}

double status_get_hashes_msec_dev_benchmark (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  // this function increases accuracy for benchmark modes

  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64    speed_cnt  = 0;
  double speed_msec = 0;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    const u32 speed_pos = MAX (device_param->speed_pos, 1);

    speed_cnt  += device_param->speed_cnt[speed_pos - 1];
    speed_msec += device_param->speed_msec[speed_pos - 1];
  }

  double hashes_dev_msec = 0;

  if (speed_msec > 0)
  {
    hashes_dev_msec = (double) speed_cnt / speed_msec;
  }

  return hashes_dev_msec;
}

double status_get_exec_msec_all (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  double exec_all_msec = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    exec_all_msec += status_get_exec_msec_dev (hashcat_ctx, backend_devices_idx);
  }

  return exec_all_msec;
}

double status_get_exec_msec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  double exec_dev_msec = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    exec_dev_msec = get_avg_exec_time (device_param, EXEC_CACHE);
  }

  return exec_dev_msec;
}

char *status_get_speed_sec_all (const hashcat_ctx_t *hashcat_ctx)
{
  const double hashes_msec_all = status_get_hashes_msec_all (hashcat_ctx);

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display (hashes_msec_all * 1000, display, HCBUFSIZ_TINY);

  return display;
}

char *status_get_speed_sec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const double hashes_msec_dev = status_get_hashes_msec_dev (hashcat_ctx, backend_devices_idx);

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display (hashes_msec_dev * 1000, display, HCBUFSIZ_TINY);

  return display;
}

int status_get_cpt_cur_min (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t    *cpt_ctx    = hashcat_ctx->cpt_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->accessible == false) return 0;

  const time_t now = time (NULL);

  int cpt_cur_min = 0;

  for (int i = 0; i < CPT_CACHE; i++)
  {
    const u32       cracked   = cpt_ctx->cpt_buf[i].cracked;
    const time_t timestamp = cpt_ctx->cpt_buf[i].timestamp;

    if ((timestamp + 60) > now)
    {
      cpt_cur_min += cracked;
    }
  }

  return cpt_cur_min;
}

int status_get_cpt_cur_hour (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t    *cpt_ctx    = hashcat_ctx->cpt_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->accessible == false) return 0;

  const time_t now = time (NULL);

  int cpt_cur_hour = 0;

  for (int i = 0; i < CPT_CACHE; i++)
  {
    const u32       cracked   = cpt_ctx->cpt_buf[i].cracked;
    const time_t timestamp = cpt_ctx->cpt_buf[i].timestamp;

    if ((timestamp + 3600) > now)
    {
      cpt_cur_hour += cracked;
    }
  }

  return cpt_cur_hour;
}

int status_get_cpt_cur_day (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t    *cpt_ctx    = hashcat_ctx->cpt_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->accessible == false) return 0;

  const time_t now = time (NULL);

  int cpt_cur_day = 0;

  for (int i = 0; i < CPT_CACHE; i++)
  {
    const u32       cracked   = cpt_ctx->cpt_buf[i].cracked;
    const time_t timestamp = cpt_ctx->cpt_buf[i].timestamp;

    if ((timestamp + 86400) > now)
    {
      cpt_cur_day += cracked;
    }
  }

  return cpt_cur_day;
}

int status_get_cpt_avg_min (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double cpt_avg_min = (double) cpt_ctx->cpt_total / ((msec_real / 1000) / 60);

  return (int) cpt_avg_min;
}

int status_get_cpt_avg_hour (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double cpt_avg_hour = (double) cpt_ctx->cpt_total / ((msec_real / 1000) / 3600);

  return (int) cpt_avg_hour;
}

int status_get_cpt_avg_day (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double cpt_avg_day = (double) cpt_ctx->cpt_total / ((msec_real / 1000) / 86400);

  return (int) cpt_avg_day;
}

char *status_get_cpt (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const time_t now = time (NULL);

  char *cpt;

  const int cpt_cur_min  = status_get_cpt_cur_min  (hashcat_ctx);
  const int cpt_cur_hour = status_get_cpt_cur_hour (hashcat_ctx);
  const int cpt_cur_day  = status_get_cpt_cur_day  (hashcat_ctx);

  const int cpt_avg_min  = status_get_cpt_avg_min  (hashcat_ctx);
  const int cpt_avg_hour = status_get_cpt_avg_hour (hashcat_ctx);
  const int cpt_avg_day  = status_get_cpt_avg_day  (hashcat_ctx);

  if ((cpt_ctx->cpt_start + 86400) < now)
  {
    hc_asprintf (&cpt, "CUR:%d,%d,%d AVG:%d,%d,%d (Min,Hour,Day)",
      cpt_cur_min,
      cpt_cur_hour,
      cpt_cur_day,
      cpt_avg_min,
      cpt_avg_hour,
      cpt_avg_day);
  }
  else if ((cpt_ctx->cpt_start + 3600) < now)
  {
    hc_asprintf (&cpt, "CUR:%d,%d,N/A AVG:%d,%d,%d (Min,Hour,Day)",
      cpt_cur_min,
      cpt_cur_hour,
      cpt_avg_min,
      cpt_avg_hour,
      cpt_avg_day);
  }
  else if ((cpt_ctx->cpt_start + 60) < now)
  {
    hc_asprintf (&cpt, "CUR:%d,N/A,N/A AVG:%d,%d,%d (Min,Hour,Day)",
      cpt_cur_min,
      cpt_avg_min,
      cpt_avg_hour,
      cpt_avg_day);
  }
  else
  {
    hc_asprintf (&cpt, "CUR:N/A,N/A,N/A AVG:%d,%d,%d (Min,Hour,Day)",
      cpt_avg_min,
      cpt_avg_hour,
      cpt_avg_day);
  }

  return cpt;
}

int status_get_salt_pos_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int salt_pos = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    salt_pos = (int) device_param->kernel_params_buf32[27];
  }

  return salt_pos;
}

int status_get_innerloop_pos_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int innerloop_pos = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    innerloop_pos = (int) device_param->innerloop_pos;
  }

  return innerloop_pos;
}

int status_get_innerloop_left_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int innerloop_left = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    innerloop_left = (int) device_param->innerloop_left;
  }

  return innerloop_left;
}

int status_get_iteration_pos_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int iteration_pos = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    iteration_pos = (int) device_param->kernel_params_buf32[28];
  }

  return iteration_pos;
}

int status_get_iteration_left_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int iteration_left = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    iteration_left = (int) device_param->kernel_params_buf32[29];
  }

  return iteration_left;
}

#ifdef WITH_BRAIN
int status_get_brain_link_client_id_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int brain_client_id = -1;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    brain_client_id = device_param->brain_link_client_fd;
  }

  return brain_client_id;
}

int status_get_brain_link_status_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  int brain_link_status_dev = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    if (device_param->brain_link_client_fd   != -1)   brain_link_status_dev = BRAIN_LINK_STATUS_CONNECTED;
    if (device_param->brain_link_recv_active == true) brain_link_status_dev = BRAIN_LINK_STATUS_RECEIVING;
    if (device_param->brain_link_send_active == true) brain_link_status_dev = BRAIN_LINK_STATUS_SENDING;
  }

  return brain_link_status_dev;
}

char *status_get_brain_link_recv_bytes_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 brain_link_recv_bytes = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    brain_link_recv_bytes = device_param->brain_link_recv_bytes;
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display_1k (brain_link_recv_bytes, display, HCBUFSIZ_TINY);

  return display;
}

char *status_get_brain_rx_all (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  double brain_rx_all = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];
    if ((device_param->skipped == false) && (device_param->skipped_warning == false))
    {
      brain_rx_all += device_param->brain_link_recv_bytes;
    }
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display_1k (brain_rx_all, display, HCBUFSIZ_TINY);

  return display;

}

char *status_get_brain_link_send_bytes_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 brain_link_send_bytes = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    brain_link_send_bytes = device_param->brain_link_send_bytes;
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display_1k (brain_link_send_bytes, display, HCBUFSIZ_TINY);

  return display;
}

char *status_get_brain_tx_all (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  double brain_tx_all = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];
    if ((device_param->skipped == false) && (device_param->skipped_warning == false))
    {
      brain_tx_all += device_param->brain_link_send_bytes;
    }
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  format_speed_display_1k (brain_tx_all, display, HCBUFSIZ_TINY);

  return display;

}

char *status_get_brain_link_recv_bytes_sec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 brain_link_recv_bytes = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    for (int idx = 0; idx < LINK_SPEED_COUNT; idx++)
    {
      double ms = hc_timer_get (device_param->brain_link_recv_speed.timer[idx]);

      if (ms >= 1000) continue;

      brain_link_recv_bytes += device_param->brain_link_recv_speed.bytes[idx];
    }
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

  snprintf (display, HCBUFSIZ_TINY, "%.2f M", (double) (brain_link_recv_bytes * 8) / 1024 / 1024);

  return display;
}

char *status_get_brain_link_send_bytes_sec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 brain_link_send_bytes = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    for (int idx = 0; idx < LINK_SPEED_COUNT; idx++)
    {
      double ms = hc_timer_get (device_param->brain_link_send_speed.timer[idx]);

      if (ms >= 1000) continue;

      brain_link_send_bytes += device_param->brain_link_send_speed.bytes[idx];
    }
  }

  char *display = (char *) hcmalloc (HCBUFSIZ_TINY);

 snprintf (display, HCBUFSIZ_TINY, "%.2f M", (double) (brain_link_send_bytes * 8) / 1024 / 1024);

  return display;
}
#endif

char *status_get_hwmon_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  char *output_buf = (char *) hcmalloc (HCBUFSIZ_TINY);

  snprintf (output_buf, HCBUFSIZ_TINY, "N/A");

  if (device_param->skipped == true) return output_buf;

  if (device_param->skipped_warning == true) return output_buf;

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_hwmon);

  const int num_temperature = hm_get_temperature_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_fanspeed    = hm_get_fanspeed_with_devices_idx    ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_utilization = hm_get_utilization_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_corespeed   = hm_get_corespeed_with_devices_idx   ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_memoryspeed = hm_get_memoryspeed_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_buslanes    = hm_get_buslanes_with_devices_idx    ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);

  int output_len = 0;

  if (num_temperature >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Temp:%3dc ", num_temperature);
  }

  if (num_fanspeed >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Fan:%3d%% ", num_fanspeed);
  }

  if (num_utilization >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Util:%3d%% ", num_utilization);
  }

  if (num_corespeed >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Core:%4dMHz ", num_corespeed);
  }

  if (num_memoryspeed >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Mem:%4dMHz ", num_memoryspeed);
  }

  if (num_buslanes >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Bus:%d ", num_buslanes);
  }

  if (output_len > 0)
  {
    // trims the trailing space

    output_buf[output_len - 1] = 0;
  }
  else
  {
    snprintf (output_buf, HCBUFSIZ_TINY, "N/A");
  }

  hc_thread_mutex_unlock (status_ctx->mux_hwmon);

  return output_buf;
}

int status_get_corespeed_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return -1;

  if (device_param->skipped_warning == true) return -1;

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_hwmon);

  const int num_corespeed = hm_get_corespeed_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);

  hc_thread_mutex_unlock (status_ctx->mux_hwmon);

  return num_corespeed;
}

int status_get_memoryspeed_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return -1;

  if (device_param->skipped_warning == true) return -1;

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_hwmon);

  const int num_memoryspeed = hm_get_memoryspeed_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);

  hc_thread_mutex_unlock (status_ctx->mux_hwmon);

  return num_memoryspeed;
}

u64 status_get_progress_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  return device_param->outerloop_left;
}

double status_get_runtime_msec_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  return device_param->outerloop_msec;
}

int status_get_kernel_accel_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  if (device_param->kernel_accel_prev) return device_param->kernel_accel_prev;

  return device_param->kernel_accel;
}

int status_get_kernel_loops_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  if (device_param->kernel_loops_prev) return device_param->kernel_loops_prev;

  return device_param->kernel_loops;
}

int status_get_kernel_threads_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  return device_param->kernel_threads;
}

int status_get_vector_width_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;

  if (device_param->skipped_warning == true) return 0;

  return device_param->vector_width;
}

int status_progress_init (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  hashes_t     *hashes     = hashcat_ctx->hashes;

  status_ctx->words_progress_done     = (u64 *) hccalloc (hashes->salts_cnt, sizeof (u64));
  status_ctx->words_progress_rejected = (u64 *) hccalloc (hashes->salts_cnt, sizeof (u64));
  status_ctx->words_progress_restored = (u64 *) hccalloc (hashes->salts_cnt, sizeof (u64));

  return 0;
}

void status_progress_destroy (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hcfree (status_ctx->words_progress_done);
  hcfree (status_ctx->words_progress_rejected);
  hcfree (status_ctx->words_progress_restored);

  status_ctx->words_progress_done     = NULL;
  status_ctx->words_progress_rejected = NULL;
  status_ctx->words_progress_restored = NULL;
}

void status_progress_reset (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  hashes_t     *hashes     = hashcat_ctx->hashes;

  memset (status_ctx->words_progress_done,     0, hashes->salts_cnt * sizeof (u64));
  memset (status_ctx->words_progress_rejected, 0, hashes->salts_cnt * sizeof (u64));
  memset (status_ctx->words_progress_restored, 0, hashes->salts_cnt * sizeof (u64));
}

int status_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_INIT;

  status_ctx->run_main_level1     = true;
  status_ctx->run_main_level2     = true;
  status_ctx->run_main_level3     = true;
  status_ctx->run_thread_level1   = true;
  status_ctx->run_thread_level2   = true;

  status_ctx->shutdown_inner      = false;
  status_ctx->shutdown_outer      = false;

  status_ctx->checkpoint_shutdown = false;

  status_ctx->hashcat_status_final = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  hc_thread_mutex_init (status_ctx->mux_dispatcher);
  hc_thread_mutex_init (status_ctx->mux_counter);
  hc_thread_mutex_init (status_ctx->mux_display);
  hc_thread_mutex_init (status_ctx->mux_hwmon);

  return 0;
}

void status_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_delete (status_ctx->mux_dispatcher);
  hc_thread_mutex_delete (status_ctx->mux_counter);
  hc_thread_mutex_delete (status_ctx->mux_display);
  hc_thread_mutex_delete (status_ctx->mux_hwmon);

  hcfree (status_ctx->hashcat_status_final);

  memset (status_ctx, 0, sizeof (status_ctx_t));
}

void status_status_destroy (hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx == NULL) return;

  if (status_ctx->accessible == false) return;

  hcfree (hashcat_status->hash_target);
  hcfree (hashcat_status->hash_name);
  hcfree (hashcat_status->session);
  hcfree (hashcat_status->time_estimated_absolute);
  hcfree (hashcat_status->time_estimated_relative);
  hcfree (hashcat_status->time_started_absolute);
  hcfree (hashcat_status->time_started_relative);
  hcfree (hashcat_status->speed_sec_all);
  hcfree (hashcat_status->guess_base);
  hcfree (hashcat_status->guess_mod);
  hcfree (hashcat_status->guess_charset);
  hcfree (hashcat_status->cpt);

  hashcat_status->hash_target             = NULL;
  hashcat_status->hash_name               = NULL;
  hashcat_status->session                 = NULL;
  hashcat_status->time_estimated_absolute = NULL;
  hashcat_status->time_estimated_relative = NULL;
  hashcat_status->time_started_absolute   = NULL;
  hashcat_status->time_started_relative   = NULL;
  hashcat_status->speed_sec_all           = NULL;
  hashcat_status->guess_base              = NULL;
  hashcat_status->guess_mod               = NULL;
  hashcat_status->guess_charset           = NULL;
  hashcat_status->cpt                     = NULL;

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    hcfree (device_info->speed_sec_dev);
    hcfree (device_info->guess_candidates_dev);
    hcfree (device_info->hwmon_dev);
    #ifdef WITH_BRAIN
    hcfree (device_info->brain_link_recv_bytes_dev);
    hcfree (device_info->brain_link_send_bytes_dev);
    hcfree (device_info->brain_link_recv_bytes_sec_dev);
    hcfree (device_info->brain_link_send_bytes_sec_dev);
    #endif

    device_info->speed_sec_dev                  = NULL;
    device_info->guess_candidates_dev           = NULL;
    device_info->hwmon_dev                      = NULL;
    #ifdef WITH_BRAIN
    device_info->brain_link_recv_bytes_dev      = NULL;
    device_info->brain_link_send_bytes_dev      = NULL;
    device_info->brain_link_recv_bytes_sec_dev  = NULL;
    device_info->brain_link_send_bytes_sec_dev  = NULL;
    #endif
  }
}
