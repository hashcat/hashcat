/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "restore.h"
#include "thread.h"
#include "timer.h"
#include "interface.h"
#include "hwmon.h"
#include "outfile.h"
#include "status.h"

static const char ST_0000[] = "Initializing";
static const char ST_0001[] = "Autotuning";
static const char ST_0002[] = "Running";
static const char ST_0003[] = "Paused";
static const char ST_0004[] = "Exhausted";
static const char ST_0005[] = "Cracked";
static const char ST_0006[] = "Aborted";
static const char ST_0007[] = "Quit";
static const char ST_0008[] = "Bypass";
static const char ST_9999[] = "Unknown! Bug!";

static char *status_get_rules_file (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->rp_files_cnt > 0)
  {
    char *tmp_buf = (char *) malloc (HCBUFSIZ_TINY);

    int tmp_len = 0;

    u32 i;

    for (i = 0; i < user_options->rp_files_cnt - 1; i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len - 1, "%s, ", user_options->rp_files[i]);
    }

    tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len - 1, "%s", user_options->rp_files[i]);

    return tmp_buf; // yes, user need to free()
  }

  return NULL;
}

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries)
{
  int exec_pos = (int) device_param->exec_pos - last_num_entries;

  if (exec_pos < 0) exec_pos += EXEC_CACHE;

  double exec_ms_sum = 0;

  int exec_ms_cnt = 0;

  for (int i = 0; i < last_num_entries; i++)
  {
    double exec_ms = device_param->exec_ms[(exec_pos + i) % EXEC_CACHE];

    if (exec_ms > 0)
    {
      exec_ms_sum += exec_ms;

      exec_ms_cnt++;
    }
  }

  if (exec_ms_cnt == 0) return 0;

  return exec_ms_sum / exec_ms_cnt;
}

char *status_get_session (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  return user_options->session;
}

char *status_get_status_string (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const int devices_status = status_ctx->devices_status;

  switch (devices_status)
  {
    case STATUS_INIT:      return ((char *) ST_0000);
    case STATUS_AUTOTUNE:  return ((char *) ST_0001);
    case STATUS_RUNNING:   return ((char *) ST_0002);
    case STATUS_PAUSED:    return ((char *) ST_0003);
    case STATUS_EXHAUSTED: return ((char *) ST_0004);
    case STATUS_CRACKED:   return ((char *) ST_0005);
    case STATUS_ABORTED:   return ((char *) ST_0006);
    case STATUS_QUIT:      return ((char *) ST_0007);
    case STATUS_BYPASS:    return ((char *) ST_0008);
  }

  return ((char *) ST_9999);
}

char *status_get_hash_type (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  return strhashtype (hashconfig->hash_mode);
}

char *status_get_hash_target (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const hashes_t     *hashes     = hashcat_ctx->hashes;

  if (hashes->digests_cnt == 1)
  {
    if (hashconfig->hash_mode == 2500)
    {
      char *tmp_buf = (char *) malloc (HCBUFSIZ_TINY);

      wpa_t *wpa = (wpa_t *) hashes->esalts_buf;

      snprintf (tmp_buf, HCBUFSIZ_TINY - 1, "%s (%02x:%02x:%02x:%02x:%02x:%02x <-> %02x:%02x:%02x:%02x:%02x:%02x)",
        (char *) hashes->salts_buf[0].salt_buf,
        wpa->orig_mac1[0],
        wpa->orig_mac1[1],
        wpa->orig_mac1[2],
        wpa->orig_mac1[3],
        wpa->orig_mac1[4],
        wpa->orig_mac1[5],
        wpa->orig_mac2[0],
        wpa->orig_mac2[1],
        wpa->orig_mac2[2],
        wpa->orig_mac2[3],
        wpa->orig_mac2[4],
        wpa->orig_mac2[5]);

      return tmp_buf;
    }
    else if (hashconfig->hash_mode == 5200)
    {
      return hashes->hashfile;
    }
    else if (hashconfig->hash_mode == 9000)
    {
      return hashes->hashfile;
    }
    else if ((hashconfig->hash_mode >= 6200) && (hashconfig->hash_mode <= 6299))
    {
      return hashes->hashfile;
    }
    else if ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799))
    {
      return hashes->hashfile;
    }
    else
    {
      char *tmp_buf = (char *) malloc (HCBUFSIZ_TINY);

      ascii_digest ((hashcat_ctx_t *) hashcat_ctx, tmp_buf, 0, 0);

      return tmp_buf;
    }
  }
  else
  {
    if (hashconfig->hash_mode == 3000)
    {
      char *tmp_buf = (char *) malloc (HCBUFSIZ_TINY);

      char out_buf1[32] = { 0 };
      char out_buf2[32] = { 0 };

      ascii_digest ((hashcat_ctx_t *) hashcat_ctx, out_buf1, 0, 0);
      ascii_digest ((hashcat_ctx_t *) hashcat_ctx, out_buf2, 0, 1);

      snprintf (tmp_buf, HCBUFSIZ_TINY - 1, "%s, %s", out_buf1, out_buf2);

      return tmp_buf;
    }
    else
    {
      return hashes->hashfile;
    }
  }

  return NULL;
}

int status_get_input_mode (const hashcat_ctx_t *hashcat_ctx)
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
        return INPUT_MODE_STRAIGHT_FILE_RULES_FILE;
      }
      else if (has_rule_gen == true)
      {
        return INPUT_MODE_STRAIGHT_FILE_RULES_GEN;
      }
      else
      {
        return INPUT_MODE_STRAIGHT_FILE;
      }
    }
    else
    {
      if (has_rule_file == true)
      {
        return INPUT_MODE_STRAIGHT_STDIN_RULES_FILE;
      }
      else if (has_rule_gen == true)
      {
        return INPUT_MODE_STRAIGHT_STDIN_RULES_GEN;
      }
      else
      {
        return INPUT_MODE_STRAIGHT_STDIN;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    if (has_base_left == true)
    {
      return INPUT_MODE_COMBINATOR_BASE_LEFT;
    }
    else
    {
      return INPUT_MODE_COMBINATOR_BASE_RIGHT;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (has_mask_cs == true)
    {
      return INPUT_MODE_MASK_CS;
    }
    else
    {
      return INPUT_MODE_MASK;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (has_mask_cs == true)
    {
      return INPUT_MODE_HYBRID1_CS;
    }
    else
    {
      return INPUT_MODE_HYBRID1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (has_mask_cs == true)
    {
      return INPUT_MODE_HYBRID2_CS;
    }
    else
    {
      return INPUT_MODE_HYBRID2;
    }
  }

  return INPUT_MODE_NONE;
}

char *status_get_input_base (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dict;
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

    if (combinator_ctx->combs_mode == INPUT_MODE_COMBINATOR_BASE_LEFT)
    {
      return combinator_ctx->dict1;
    }
    else
    {
      return combinator_ctx->dict2;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->mask;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dict;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dict;
  }

  return NULL;
}

char *status_get_input_mod (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    return status_get_rules_file (hashcat_ctx);
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

    if (combinator_ctx->combs_mode == INPUT_MODE_COMBINATOR_BASE_LEFT)
    {
      return combinator_ctx->dict2;
    }
    else
    {
      return combinator_ctx->dict1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {

  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->mask;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->mask;
  }

  return NULL;
}

char *status_get_input_charset (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  const char *custom_charset_1 = user_options->custom_charset_1;
  const char *custom_charset_2 = user_options->custom_charset_2;
  const char *custom_charset_3 = user_options->custom_charset_3;
  const char *custom_charset_4 = user_options->custom_charset_4;

  if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL))
  {
    char *tmp_buf = (char *) malloc (HCBUFSIZ_TINY);

    if (custom_charset_1 == NULL) custom_charset_1 = "Undefined";
    if (custom_charset_2 == NULL) custom_charset_2 = "Undefined";
    if (custom_charset_3 == NULL) custom_charset_3 = "Undefined";
    if (custom_charset_4 == NULL) custom_charset_4 = "Undefined";

    snprintf (tmp_buf, HCBUFSIZ_TINY - 1, "-1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);

    return tmp_buf;
  }

  return NULL;
}


int status_progress_init (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  hashes_t     *hashes     = hashcat_ctx->hashes;

  status_ctx->words_progress_done     = (u64 *) hccalloc (hashcat_ctx, hashes->salts_cnt, sizeof (u64)); VERIFY_PTR (status_ctx->words_progress_done);
  status_ctx->words_progress_rejected = (u64 *) hccalloc (hashcat_ctx, hashes->salts_cnt, sizeof (u64)); VERIFY_PTR (status_ctx->words_progress_rejected);
  status_ctx->words_progress_restored = (u64 *) hccalloc (hashcat_ctx, hashes->salts_cnt, sizeof (u64)); VERIFY_PTR (status_ctx->words_progress_restored);

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

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  hc_thread_mutex_init (status_ctx->mux_dispatcher);
  hc_thread_mutex_init (status_ctx->mux_counter);
  hc_thread_mutex_init (status_ctx->mux_display);
  hc_thread_mutex_init (status_ctx->mux_hwmon);

  time (&status_ctx->proc_start);

  return 0;
}

void status_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_delete (status_ctx->mux_dispatcher);
  hc_thread_mutex_delete (status_ctx->mux_counter);
  hc_thread_mutex_delete (status_ctx->mux_display);
  hc_thread_mutex_delete (status_ctx->mux_hwmon);

  memset (status_ctx, 0, sizeof (status_ctx_t));
}
