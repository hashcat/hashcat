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
#include "backend.h"
#include "outfile.h"
#include "monitor.h"
#include "mpsp.h"
#include "terminal.h"
#include "shared.h"
#include "status.h"

static const char *const  ST_0000 = "Initializing";
static const char *const  ST_0001 = "Autotuning";
static const char *const  ST_0002 = "Selftest";
static const char *const  ST_0003 = "Running";
static const char *const  ST_0004 = "Paused";
static const char *const  ST_0005 = "Exhausted";
static const char *const  ST_0006 = "Cracked";
static const char *const  ST_0007 = "Aborted";
static const char *const  ST_0008 = "Quit";
static const char *const  ST_0009 = "Bypass";
static const char *const  ST_0010 = "Aborted (Checkpoint)";
static const char *const  ST_0011 = "Aborted (Runtime)";
static const char *const  ST_0012 = "Running (Checkpoint Quit requested)";
static const char *const  ST_0013 = "Error";
static const char *const  ST_0014 = "Aborted (Finish)";
static const char *const  ST_0015 = "Running (Quit after attack requested)";
static const char *const  ST_0016 = "Autodetect";
static const char *const  ST_0017 = "Paused (Checkpoint Quit requested)";
static const char *const  ST_0018 = "Paused (Quit after attack requested)";
static const char *const  ST_9999 = "Unknown! Bug!";

static const char UNITS[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

static const char *const  ETA_ABSOLUTE_MAX_EXCEEDED = "Next Big Bang"; // in honor of ighashgpu
static const char *const  ETA_RELATIVE_MAX_EXCEEDED = "> 10 years";

static char *status_get_rules_file (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->rp_files_cnt > 0)
  {
    char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_TINY);

    int tmp_len = 0;

    u32 i;

    // snprintf returns the length it would have written and not the length it wrote, so once the
    // list fills the buffer tmp_len runs past it. HCBUFSIZ_TINY - tmp_len is then negative, and
    // snprintf takes its size as a size_t, so the next name would be written out of bounds with no
    // limit at all. Enough -r arguments, or long enough paths, is all that takes. The list is
    // truncated instead, and the terminator below always lands inside the buffer.

    for (i = 0; i < user_options->rp_files_cnt - 1; i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len, "%s, ", user_options->rp_files[i]);

      if (tmp_len >= HCBUFSIZ_TINY) break;
    }

    if (tmp_len < HCBUFSIZ_TINY)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_TINY - tmp_len, "%s", user_options->rp_files[i]);
    }

    if (tmp_len >= HCBUFSIZ_TINY) tmp_len = HCBUFSIZ_TINY - 1;

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

    snprintf (buf, len, "%u %s, %u %s", tm->tm_year - 70, time_entity1, tm->tm_yday, time_entity2);
  }
  else if (tm->tm_yday)
  {
    const char *time_entity1 = (tm->tm_yday == 1) ? time_entities_s[1] : time_entities_m[1];
    const char *time_entity2 = (tm->tm_hour == 1) ? time_entities_s[2] : time_entities_m[2];

    snprintf (buf, len, "%u %s, %u %s", tm->tm_yday, time_entity1, tm->tm_hour, time_entity2);
  }
  else if (tm->tm_hour)
  {
    const char *time_entity1 = (tm->tm_hour == 1) ? time_entities_s[2] : time_entities_m[2];
    const char *time_entity2 = (tm->tm_min  == 1) ? time_entities_s[3] : time_entities_m[3];

    snprintf (buf, len, "%u %s, %u %s", tm->tm_hour, time_entity1, tm->tm_min, time_entity2);
  }
  else if (tm->tm_min)
  {
    const char *time_entity1 = (tm->tm_min == 1) ? time_entities_s[3] : time_entities_m[3];
    const char *time_entity2 = (tm->tm_sec == 1) ? time_entities_s[4] : time_entities_m[4];

    snprintf (buf, len, "%u %s, %u %s", tm->tm_min, time_entity1, tm->tm_sec, time_entity2);
  }
  else
  {
    const char *time_entity1 = (tm->tm_sec == 1) ? time_entities_s[4] : time_entities_m[4];

    snprintf (buf, len, "%u %s", tm->tm_sec, time_entity1);
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

// How many presentation groups are running. One line is printed per group, so this is what says
// whether a total line underneath them would add anything.

int status_get_group_info_active (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  int cnt = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (backend_ctx_device_is_group_leader (hashcat_ctx, backend_devices_idx) == false) continue;

    cnt++;
  }

  return cnt;
}

int status_get_group_id_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  return device_param->group_id;
}

int status_get_group_size_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const int size = backend_ctx_device_group_size (hashcat_ctx, backend_devices_idx, NULL);

  return size;
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

  if (devices_status == STATUS_RUNNING)
  {
    if (status_ctx->checkpoint_shutdown == true)
    {
      return ST_0012;
    }

    if (status_ctx->finish_shutdown == true)
    {
      return ST_0015;
    }
  }
  else if (devices_status == STATUS_PAUSED)
  {
    if (status_ctx->checkpoint_shutdown == true)
    {
      return ST_0017;
    }

    if (status_ctx->finish_shutdown == true)
    {
      return ST_0018;
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
    case STATUS_ABORTED_FINISH:     return ST_0014;
    case STATUS_AUTODETECT:         return ST_0016;
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

      int tmp_len = module_ctx->module_hash_encode_status (hashconfig, hashes->digests_buf, hashes->salts_buf, hashes->esalts_buf, hashes->hook_salts_buf, NULL, tmp_buf, HCBUFSIZ_LARGE);

      // A module that builds its line with snprintf returns what it would have written rather than
      // what it did. hash_encode clamps that for the callers that go through it, and this arm does
      // not, so the length is clamped to the buffer here as well.

      if (tmp_len < 0) tmp_len = 0;

      if (tmp_len >= HCBUFSIZ_LARGE) tmp_len = HCBUFSIZ_LARGE - 1;

      char *tmp_buf2 = (char *) hcmalloc (tmp_len + 1);

      memcpy (tmp_buf2, tmp_buf, tmp_len);

      tmp_buf2[tmp_len] = 0;

      hcfree (tmp_buf);

      return tmp_buf2;
    }

    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
    {
      if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
      {
        if (hashes->hashfile)
        {
          return hcstrdup (hashes->hashfile);
        }
      }
      else
      {
        return hcstrdup (hashes->hashfile);
      }
    }

    char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

    const int tmp_len = hash_encode (hashcat_ctx->user_options, hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, tmp_buf, HCBUFSIZ_LARGE, 0, 0);

    tmp_buf[tmp_len] = 0;

    compress_terminal_line_length (tmp_buf, 19, 6); // 19 = strlen ("Hash.Target......: ")

    char *tmp_buf2 = strdup (tmp_buf);

    hcfree (tmp_buf);

    return tmp_buf2;
  }

  return hcstrdup (hashes->hashfile);
}

int status_get_guess_mode (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  bool has_rule_file  = false;
  bool has_rule_gen   = false;
  bool has_mask_cs    = false;

  if (user_options->rp_files_cnt > 0) has_rule_file = true;
  if (user_options->rp_gen       > 0) has_rule_gen  = true;

  if (user_options->custom_charset_1) has_mask_cs = true;
  if (user_options->custom_charset_2) has_mask_cs = true;
  if (user_options->custom_charset_3) has_mask_cs = true;
  if (user_options->custom_charset_4) has_mask_cs = true;
  if (user_options->custom_charset_5) has_mask_cs = true;
  if (user_options->custom_charset_6) has_mask_cs = true;
  if (user_options->custom_charset_7) has_mask_cs = true;
  if (user_options->custom_charset_8) has_mask_cs = true;

  // Only the straight kernel family displays as a feed. -a 1, -a 6 and -a 7 keep their own labels even
  // when the base words come from one, because the label describes how a candidate is put together and
  // that has not changed: the mask is still one half of it and the second wordlist is still the other.

  // The device engine is a feed too, and one that names itself: feed_pcfg.c writes "<ruleset> (scale N)"
  // into guess_base during global_init (). Testing only for the straight kernel left ATTACK_KERN_PCFG
  // falling through every branch below to GUESS_MODE_NONE, so a pcfg run printed no Guess.Base line at
  // all and the status screen did not say what was generating the candidates.

  if ((user_options_extra->base_source == BASE_SOURCE_FEED) && ((user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) || (user_options_extra->attack_kern == ATTACK_KERN_PCFG)))
  {
    if (has_rule_file == true)
    {
      return GUESS_MODE_GENERIC_RULES_FILE;
    }
    if (has_rule_gen == true)
    {
      return GUESS_MODE_GENERIC_RULES_GEN;
    }
    return GUESS_MODE_GENERIC;
  }

  // What is left here reads its candidates from stdin. Every other straight attack answered the feed
  // test above, so GUESS_MODE_STRAIGHT_FILE and its two rule variants have nothing left to name.

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
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

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (has_mask_cs == true)
    {
      return GUESS_MODE_MASK_CS;
    }
    return GUESS_MODE_MASK;
  }

  // -a 12 reads its base words through a feed the way -a 6 and -a 7 do, so the feed test above does
  // not claim it, and it is not one of the two older hybrids either. Without a label of its own the
  // status display has nothing to print for it at all.

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // -a 1, -a 6 and -a 7 run as -a 12 layouts but they are still what the user typed, and the labels
    // they had are part of what a script or a tutorial reading the status expects to see. So the mode
    // the user asked for names them, not the one that runs.

    if (user_options->attack_mode_typed == ATTACK_MODE_COMBI)
    {
      // Both sides are wordlists here, so the label says which of them the base word comes from. The
      // roles are swapped when the second one turned out to be the bigger, and that is the same thing
      // COMBINATOR_MODE_BASE_RIGHT used to say.

      const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

      if (combinator_ctx->roles_swapped == true)
      {
        return GUESS_MODE_COMBINATOR_BASE_RIGHT;
      }
      return GUESS_MODE_COMBINATOR_BASE_LEFT;
    }

    if (user_options->attack_mode_typed == ATTACK_MODE_HYBRID1)
    {
      if (has_mask_cs == true)
      {
        return GUESS_MODE_HYBRID1_CS;
      }
      return GUESS_MODE_HYBRID1;
    }

    if (user_options->attack_mode_typed == ATTACK_MODE_HYBRID2)
    {
      if (has_mask_cs == true)
      {
        return GUESS_MODE_HYBRID2_CS;
      }
      return GUESS_MODE_HYBRID2;
    }

    // A ?q names a second wordlist and the mask does not say which, so that shape has a label of its
    // own and the display names it beside the mask.

    if (user_options_extra->hybrid_q == true)
    {
      if (has_mask_cs == true)
      {
        return GUESS_MODE_HYBRID_Q_CS;
      }
      return GUESS_MODE_HYBRID_Q;
    }

    if (has_mask_cs == true)
    {
      return GUESS_MODE_HYBRID_CS;
    }
    return GUESS_MODE_HYBRID;
  }

  return GUESS_MODE_NONE;
}

// How far into the keyspace the work has got, as the furthest point any device has finished. That is
// deliberately not the restore point: the restore point is the prefix EVERY device is past, so with
// several devices working separate ranges it trails behind, and it is what makes a resume safe rather
// than what tells a user where the run is.

static u64 status_get_words_cur_furthest (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  const status_ctx_t  *status_ctx  = hashcat_ctx->status_ctx;

  u64 words_cur = status_ctx->words_cur;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    words_cur = MAX (words_cur, device_param->words_done);
  }

  return words_cur;
}

// Name the source a feed has reached. Every attack mode reading through a feed shows this, and -a 7 is
// the one that shows it as Guess.Mod rather than Guess.Base, because there the word is the right hand
// side of the candidate and the mask is the left.

static char *status_get_guess_feed (const hashcat_ctx_t *hashcat_ctx)
{
  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  const generic_global_ctx_t *global_ctx = &generic_ctx->global_ctx;

  // A feed made of several sources says which one the run has reached, because naming only the first
  // of eighteen wordlists tells the user nothing about where the attack is. This is the same thing
  // Guess.Queue said when several dictionaries were several attacks.
  //
  // The position is the furthest any device has reached, not the restore point. Devices work
  // separate ranges at the same time, so the restore point is the contiguous prefix all of them are
  // past, which lags a long way behind the file actually being read and can sit at zero for a whole
  // run. Asking where the work has got to answers the question the user is asking.

  if (global_ctx->segments_cnt > 1)
  {
    const u64 words_cur = status_get_words_cur_furthest (hashcat_ctx);

    u64 segment_idx = 0;

    for (u64 i = 0; i < global_ctx->segments_cnt; i++)
    {
      if (global_ctx->segment_first[i] > words_cur) break;

      segment_idx = i;
    }

    char buf[HCBUFSIZ_TINY];

    snprintf (buf, sizeof (buf), "[%" PRIu64 "/%" PRIu64 "] %s", segment_idx + 1, global_ctx->segments_cnt, global_ctx->segment_names[segment_idx]);

    char *guess_base = strdup (buf);

    return guess_base;
  }

  // a feed that named itself during global_init () gets to say what it is generating from. One
  // that did not is named by the plugin the user asked for.

  if (global_ctx->guess_base[0] != 0) return strdup (global_ctx->guess_base);

  if (generic_ctx->plugin_name) return strdup (generic_ctx->plugin_name);

  return NULL;
}

// The mask the way the user wrote it. A mask that -a 6 or -a 7 was rewritten into carries a ?w the
// user never typed, put there by mask_append_final () at the end the marker policy names, so it comes
// back off before the mask is shown.

// Whether -a 7 is running the arrangement that puts the mask in front of the base word, which is what
// the optimized kernel builds. Guess.Base names the left hand side of the candidate and for -a 7 that
// is the mask, so this is the one arrangement where the mask answers for Guess.Base and the wordlist
// moves to Guess.Mod. status_display () decides which way round to print the two the same way, so the
// answers below have to be selected on the same test and not on where the base words happen to be read.

static bool status_guess_mask_first (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode_typed != ATTACK_MODE_HYBRID2) return false;

  return (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;
}

static char *status_get_guess_mask (const hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (mask_ctx->mask == NULL) return NULL;

  char *mask = strdup (mask_ctx->mask);

  if (mask == NULL) return NULL;

  const size_t mask_len = strlen (mask);

  if (mask_len < 2) return mask;

  if (user_options->marker_policy == MARKER_POLICY_PREFIX_W)
  {
    memmove (mask, mask + 2, mask_len - 1);
  }
  else if (user_options->marker_policy == MARKER_POLICY_SUFFIX_W)
  {
    mask[mask_len - 2] = 0;
  }

  return mask;
}

char *status_get_guess_base (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // -a 7 puts the mask on the left of the candidate and the word on the right, and Guess.Base names the
  // left hand side. So it keeps answering with the mask whatever the base words are read through.

  if (status_guess_mask_first (hashcat_ctx) == true)
  {
    return status_get_guess_mask (hashcat_ctx);
  }

  if (user_options_extra->base_source == BASE_SOURCE_FEED)
  {
    return status_get_guess_feed (hashcat_ctx);
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return strdup (mask_ctx->mask);
  }

  // Only reachable when the mask is the base word source, because every other -a 12 was claimed by
  // the feed shortcut above. That is the arrangement -a 7 has under a pure kernel, so it answers the
  // same way: the wordlist here and the mask in Guess.Mod.

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return strdup (straight_ctx->dict);
  }

  return NULL;
}

int status_get_guess_base_offset (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // -a 7 puts the mask on the left of the candidate and the word on the right, and Guess.Base names the
  // left hand side. So it keeps answering with the mask whatever the base words are read through.

  if (status_guess_mask_first (hashcat_ctx) == true)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_pos + 1;
  }

  if (user_options_extra->base_source == BASE_SOURCE_FEED)
  {
    // A feed handed every source at once is one entry in the queue, and it says where inside itself the
    // run has reached with its own segments instead. A feed scoped to one source per round is a real
    // queue of rounds, and the round is the position in it, so those fall through to the answer below.

    if (user_options_extra->base_scope == BASE_SCOPE_ALL_SOURCES) return 1;
  }

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_pos + 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_pos + 1;
  }

  return 0;
}

int status_get_guess_base_count (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // -a 7 puts the mask on the left of the candidate and the word on the right, and Guess.Base names the
  // left hand side. So it keeps answering with the mask whatever the base words are read through.

  if (status_guess_mask_first (hashcat_ctx) == true)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_cnt;
  }

  if (user_options_extra->base_source == BASE_SOURCE_FEED)
  {
    // A feed handed every source at once is one entry in the queue, and it says where inside itself the
    // run has reached with its own segments instead. A feed scoped to one source per round is a real
    // queue of rounds, and the round is the position in it, so those fall through to the answer below.

    if (user_options_extra->base_scope == BASE_SCOPE_ALL_SOURCES) return 1;
  }

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    return straight_ctx->dicts_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

    return mask_ctx->masks_cnt;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
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

// The wordlist a ?q names, or nothing when the mask has no ?q. Guess.Mod is the mask, and the mask
// does not say which wordlist the ?q reads, so this is the only place its name reaches the display.

char *status_get_guess_mod_q (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options_extra->hybrid_q == false) return NULL;

  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP];

  if (generic_ctx->workv == NULL) return NULL;

  return strdup (generic_ctx->workv[generic_ctx->workc - 1]);
}

char *status_get_guess_mod (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    return status_get_rules_file (hashcat_ctx);
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {

  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // -a 7 names the mask in Guess.Base, so what is left for Guess.Mod is where the words come from.

    if (status_guess_mask_first (hashcat_ctx) == true)
    {
      if (user_options_extra->base_source == BASE_SOURCE_FEED) return status_get_guess_feed (hashcat_ctx);

      const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

      return strdup (straight_ctx->dict);
    }

    // -a 1 has no mask of its own. The ?w?q it runs as was written by the alias and both of its sides
    // are wordlists, so the one that is not the base word source is what Guess.Mod names.

    if (user_options->attack_mode_typed == ATTACK_MODE_COMBI)
    {
      return status_get_guess_mod_q (hashcat_ctx);
    }

    return status_get_guess_mask (hashcat_ctx);
  }

  return NULL;
}

int status_get_guess_mod_offset (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // -a 7 with the mask in Guess.Base counts wordlists here rather than masks, and a feed is one
    // entry however many sources it was handed.

    if (status_guess_mask_first (hashcat_ctx) == true)
    {
      if (user_options_extra->base_source == BASE_SOURCE_FEED) return 1;

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
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    return 1;
  }

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // -a 7 with the mask in Guess.Base counts wordlists here rather than masks, and a feed is one
    // entry however many sources it was handed.

    if (status_guess_mask_first (hashcat_ctx) == true)
    {
      if (user_options_extra->base_source == BASE_SOURCE_FEED) return 1;

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
  const char *custom_charset_5 = user_options->custom_charset_5;
  const char *custom_charset_6 = user_options->custom_charset_6;
  const char *custom_charset_7 = user_options->custom_charset_7;
  const char *custom_charset_8 = user_options->custom_charset_8;

  if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL) || (custom_charset_5 != NULL) || (custom_charset_6 != NULL) || (custom_charset_7 != NULL) || (custom_charset_8 != NULL))
  {
    char *tmp_buf;

    if (custom_charset_1 == NULL) custom_charset_1 = "N/A";
    if (custom_charset_2 == NULL) custom_charset_2 = "N/A";
    if (custom_charset_3 == NULL) custom_charset_3 = "N/A";
    if (custom_charset_4 == NULL) custom_charset_4 = "N/A";
    if (custom_charset_5 == NULL) custom_charset_5 = "N/A";
    if (custom_charset_6 == NULL) custom_charset_6 = "N/A";
    if (custom_charset_7 == NULL) custom_charset_7 = "N/A";
    if (custom_charset_8 == NULL) custom_charset_8 = "N/A";

    hc_asprintf (&tmp_buf, "-1 %s, -2 %s, -3 %s, -4 %s, -5 %s, -6 %s, -7 %s, -8 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4, custom_charset_5, custom_charset_6, custom_charset_7, custom_charset_8);

    return tmp_buf;
  }

  return NULL;
}

int status_get_guess_mask_length (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (mask_ctx == NULL) return -1;

  if (mask_ctx->mask == NULL) return -1;

  // mp_get_length counts every ?x pair as one character, but ?w and ?q are positions rather than
  // charsets and contribute nothing to the mask. css_cnt is what the mask actually produces.

  if (user_options->attack_mode == ATTACK_MODE_HYBRID) return (int) mask_ctx->css_cnt;

  return mp_get_length (mask_ctx->mask, hashconfig->opts_type);
}

char *status_get_guess_candidates_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  const pubkey_ctx_t         *pubkey_ctx         = hashcat_ctx->pubkey_ctx;

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

  // Under --encrypt-with-pubkey the operator must not see candidate material either: as the
  // keyspace is walked the correct candidate passes through this display like any other, so
  // showing the range would hand over what the encryption is there to withhold.

  if (pubkey_ctx->enabled == true)
  {
    snprintf (display, HCBUFSIZ_TINY, "[Protected]");

    return display;
  }

  const u64 outerloop_first = 0;
  const u64 outerloop_last  = device_param->outerloop_left - 1;

  const u64 innerloop_first = 0;
  const u64 innerloop_last  = device_param->innerloop_left - 1;

  plain_t plain1 = { outerloop_first, innerloop_first, 0, 0, 0, 0, 0 };
  plain_t plain2 = { outerloop_last,  innerloop_last,  0, 0, 0, 0, 0 };

  // build_plain returns up to PW_MAX * 2 bytes for a combinator candidate, and hexifying doubles it
  // again, so both buffers have to hold twice the longest candidate plus the terminator.
  //
  // exec_hexify stops reading at PW_MAX, so a candidate longer than that is shown only as far as it
  // got. The terminator goes where exec_hexify says it stopped rather than where the whole candidate
  // would have ended, because the bytes in between were never written.

  u32 plain_buf1[((PW_MAX * 2 * 2) / 4) + 2] = { 0 };
  u32 plain_buf2[((PW_MAX * 2 * 2) / 4) + 2] = { 0 };

  u8 *plain_ptr1 = (u8 *) plain_buf1;
  u8 *plain_ptr2 = (u8 *) plain_buf2;

  int plain_len1 = 0;
  int plain_len2 = 0;

  build_plain ((hashcat_ctx_t *) hashcat_ctx, device_param, &plain1, plain_buf1, &plain_len1);
  build_plain ((hashcat_ctx_t *) hashcat_ctx, device_param, &plain2, plain_buf2, &plain_len2);

  const bool always_ascii = (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_ASCII) ? true : false;

  const bool need_hex1 = need_hexify (plain_ptr1, plain_len1, 0, always_ascii);
  const bool need_hex2 = need_hexify (plain_ptr2, plain_len2, 0, always_ascii);

  if((need_hex1 == true) || (need_hex2 == true))
  {
    // Right candidate needs to be $HEX-ed
    if(need_hex1 == false)
    {
      const size_t hex_len2 = exec_hexify (plain_ptr2, plain_len2, plain_ptr2);

      plain_ptr1[plain_len1] = 0;
      plain_ptr2[hex_len2]   = 0;

      snprintf (display, HCBUFSIZ_TINY, "%s -> $HEX[%s]", plain_ptr1, plain_ptr2);
    }
    // Left candidate needs to be $HEX-ed
    else if(need_hex2 == false)
    {
      const size_t hex_len1 = exec_hexify (plain_ptr1, plain_len1, plain_ptr1);

      plain_ptr1[hex_len1]   = 0;
      plain_ptr2[plain_len2] = 0;

      snprintf (display, HCBUFSIZ_TINY, "$HEX[%s] -> %s", plain_ptr1, plain_ptr2);
    }
    // Both candidates need to be $HEX-ed
    else {
      const size_t hex_len1 = exec_hexify (plain_ptr1, plain_len1, plain_ptr1);
      const size_t hex_len2 = exec_hexify (plain_ptr2, plain_len2, plain_ptr2);

      plain_ptr1[hex_len1] = 0;
      plain_ptr2[hex_len2] = 0;

      snprintf (display, HCBUFSIZ_TINY, "$HEX[%s] -> $HEX[%s]", plain_ptr1, plain_ptr2);
    }
  }
  // Neither candidate needs to be $HEX-ed
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

int status_get_digests_done_pot (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->digests_done_pot;
}

int status_get_digests_done_zero (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->digests_done_zero;
}

int status_get_digests_done_new (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->digests_done_new;
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

double status_get_digests_percent_new (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  if (hashes->digests_cnt == 0) return 0;

  return ((double) hashes->digests_done_new / (double) hashes->digests_cnt) * 100;
}

int status_get_salts_done (const hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  return hashes->salts_done;
}

// How many amplifiers the run applies to each base word, and how many iterations the current salt
// costs. Both are what the per device positions on the Restore.Sub line count towards, so the line
// above prints them and the rows underneath stay short.

u64 status_get_amplifier_cnt (const hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  const straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) return straight_ctx->kernel_rules_cnt;
  if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    return combinator_ctx->combs_cnt;
  if (user_options_extra->attack_kern == ATTACK_KERN_BF)       return mask_ctx->bfs_cnt;

  return 1;
}

u32 status_get_iteration_cnt (const hashcat_ctx_t *hashcat_ctx, const int salt_pos)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  if (hashes->salts_buf == NULL) return 0;
  if (salt_pos < 0) return 0;
  if (salt_pos >= (int) hashes->salts_cnt) return 0;

  return hashes->salts_buf[salt_pos].salt_iter;
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

  if ((user_options_extra->wordlist_mode == WL_MODE_MASK) || (user_options_extra->wordlist_mode == WL_MODE_GENERIC))
  {
    if (status_ctx->devices_status != STATUS_CRACKED)
    {
      const u64 progress_cur_relative_skip = status_get_progress_cur_relative_skip (hashcat_ctx);
      const u64 progress_end_relative_skip = status_get_progress_end_relative_skip (hashcat_ctx);

      const u64 progress_ignore = status_get_progress_ignore (hashcat_ctx);

      const double hashes_msec_all = status_get_hashes_msec_all (hashcat_ctx);

      if ((progress_end_relative_skip) > 0 && (hashes_msec_all > 0))
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

  if (overflow_check_u64_add (now, sec_etc) == true)
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

      hcfree (display_left);
    }
    else
    {
      snprintf (display, HCBUFSIZ_TINY, "%s; Runtime limit exceeded", tmp_display);
    }

    hcfree (tmp_display);
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

#ifdef WITH_BRAIN
u64 status_get_brain_rejects_attacks (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  return status_ctx->brain_rejects_attacks;
}

u64 status_get_brain_rejects_hashes (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  return status_ctx->brain_rejects_hashes;
}
#endif

double status_get_progress_rejected_percent (const hashcat_ctx_t *hashcat_ctx)
{
  // The status line prints this percentage next to the fraction it belongs to, and that fraction is
  // measured against the work this run was asked for. Measuring the percentage against the whole
  // keyspace instead made the two disagree as soon as --skip left anything out.

  const u64 progress_cur_relative_skip = status_get_progress_cur_relative_skip (hashcat_ctx);
  const u64 progress_rejected          = status_get_progress_rejected          (hashcat_ctx);

  double percent_rejected = 0;

  if (progress_cur_relative_skip)
  {
    percent_rejected = ((double) (progress_rejected) / (double) progress_cur_relative_skip) * 100;
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
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    // we have no salt based skips in this attack mode
    // ?? words_progress_restored[]

    return 0;
  }

  u64 words_cnt = status_ctx->words_cnt;

  if (words_cnt == -1ULL) words_cnt = 0;

  if (status_ctx->words_limit)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
    const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
    const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;

    words_cnt = MIN (status_ctx->words_limit, status_ctx->words_base);

    if (user_options->slow_candidates == true)
    {
      // nothing to do
    }
    else
    {
      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) words_cnt  *= straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    words_cnt  *= combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       words_cnt  *= mask_ctx->bfs_cnt;
    }
  }
  // Important for ETA only

  u64 progress_ignore = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    if (hashes->salts_shown[salt_pos] == 1)
    {
      const u64 all = status_ctx->words_progress_done[salt_pos]
                    + status_ctx->words_progress_rejected[salt_pos]
                    + status_ctx->words_progress_restored[salt_pos];

      const u64 left = words_cnt - all;

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

  u64 progress_end = status_ctx->words_cnt;

  if (progress_end == -1ULL) progress_end = 0;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    // nothing to do
  }
  else
  {
    progress_end *= hashes->salts_cnt;
  }

  if (status_ctx->words_limit)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
    const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
    const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;

    progress_end = MIN (status_ctx->words_limit, status_ctx->words_base);

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // nothing to do
    }
    else
    {
      progress_end *= hashes->salts_cnt;
    }

    if (user_options->slow_candidates == true)
    {
      // nothing to do
    }
    else
    {
      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_end  *= combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_end  *= mask_ctx->bfs_cnt;

      // The device engine expands a base word the same way, and --skip and --limit count base words for it
      // as they do for every other mode. Without this the total stayed in base words while the
      // progress counted candidates, so --limit 200000 reported 208122% done.
      //
      // dev_avg is the mean cell over the whole keyspace, which is what the unlimited total uses
      // too, so the two agree. It is still only a mean: the cheap cost levels a run starts in hold
      // cells several times wider than that, so a limit near the front of the stream reads high. A
      // feed that can say how many candidates lie before a given base word is asked instead, and
      // the mean is what is left when it cannot.

      else if (user_options_extra->attack_kern == ATTACK_KERN_PCFG)
      {
        const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

        u64 span = 0;

        if (generic_ctx->global_dev_span != NULL)
        {
          // --limit is where the run stops, not how far it goes, so --skip 500000 --limit 20000 is
          // an empty window. Never behind where the run starts, or the subtraction the status line
          // makes goes under.

          u64 upto = MIN (status_ctx->words_limit, status_ctx->words_base);

          if (upto < status_ctx->words_skip) upto = status_ctx->words_skip;

          span = generic_ctx->global_dev_span ((generic_global_ctx_t *) &generic_ctx->global_ctx, 0, upto);
        }

        if (span > 0)
        {
          progress_end = span;

          if (user_options->attack_mode != ATTACK_MODE_ASSOCIATION) progress_end *= hashes->salts_cnt;
        }
        else
        {
          progress_end *= generic_ctx->dev_avg;
        }
      }
    }
  }

  // -a 9 splitting its own hash file runs its rounds as one attack, so the progress it counts is the
  // whole queue and the total it is measured against has to be the whole queue too.
  //
  // The multiplication is exact rather than an estimate. Every round pairs one word with every digest,
  // and generic_association_in_sync refuses any round where that is not true, so a round is always
  // words_cnt candidates and there are dicts_cnt of them.

  if (user_options_extra->association_autosplit == true)
  {
    const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

    if (straight_ctx->dicts_cnt > 1) progress_end *= straight_ctx->dicts_cnt;
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

  // words_skip is this round's share of --skip and not --skip itself, which is a position in the
  // whole queue of rounds. Reading --skip here also used to read a zero, because it was cleared as
  // soon as the first round had taken it, so the progress line counted the skipped part as work
  // already done instead of leaving it out.

  if (status_ctx->words_skip)
  {
    const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
    const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
    const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;

    progress_skip = MIN (status_ctx->words_skip, status_ctx->words_base);

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // nothing to do
    }
    else
    {
      progress_skip *= hashes->salts_cnt;
    }

    if (user_options->slow_candidates == true)
    {
      // nothing to do
    }
    else
    {
      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_skip *= combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_skip *= mask_ctx->bfs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_PCFG)
      {
        // This one had no branch at all, so a count in base words was taken off a count in
        // candidates.

        const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

        u64 span = 0;

        // From the word count: the salts were multiplied in above, and this asks for a position in
        // base words.

        const u64 words = MIN (status_ctx->words_skip, status_ctx->words_base);

        if (generic_ctx->global_dev_span != NULL)
        {
          span = generic_ctx->global_dev_span ((generic_global_ctx_t *) &generic_ctx->global_ctx, 0, words);
        }

        if (span > 0) progress_skip = span * ((user_options->attack_mode == ATTACK_MODE_ASSOCIATION) ? 1 : hashes->salts_cnt);
        else          progress_skip *= generic_ctx->dev_avg;
      }
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
    const u32    cracked   = cpt_ctx->cpt_buf[i].cracked;
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
    const u32    cracked   = cpt_ctx->cpt_buf[i].cracked;
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
    const u32    cracked   = cpt_ctx->cpt_buf[i].cracked;
    const time_t timestamp = cpt_ctx->cpt_buf[i].timestamp;

    if ((timestamp + 86400) > now)
    {
      cpt_cur_day += cracked;
    }
  }

  return cpt_cur_day;
}

double status_get_cpt_avg_min (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double min_real = (msec_real / 1000) / 60;

  double cpt_avg_min = 0;

  if (min_real > 1)
  {
    cpt_avg_min = (double) cpt_ctx->cpt_total / min_real;
  }

  return cpt_avg_min;
}

double status_get_cpt_avg_hour (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double hour_real = (msec_real / 1000) / (60 * 60);

  double cpt_avg_hour = 0;

  if (hour_real > 1)
  {
    cpt_avg_hour = (double) cpt_ctx->cpt_total / hour_real;
  }

  return cpt_avg_hour;
}

double status_get_cpt_avg_day (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const double msec_real = status_get_msec_real (hashcat_ctx);

  const double day_real = (msec_real / 1000) / (60 * 60 * 24);

  double cpt_avg_day = 0;

  if (day_real > 1)
  {
    cpt_avg_day = (double) cpt_ctx->cpt_total / day_real;
  }

  return cpt_avg_day;
}

char *status_get_cpt (const hashcat_ctx_t *hashcat_ctx)
{
  const cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  const time_t now = time (NULL);

  char *cpt;

  const int cpt_cur_min  = status_get_cpt_cur_min  (hashcat_ctx);
  const int cpt_cur_hour = status_get_cpt_cur_hour (hashcat_ctx);
  const int cpt_cur_day  = status_get_cpt_cur_day  (hashcat_ctx);

  const double cpt_avg_min  = status_get_cpt_avg_min  (hashcat_ctx);
  const double cpt_avg_hour = status_get_cpt_avg_hour (hashcat_ctx);
  const double cpt_avg_day  = status_get_cpt_avg_day  (hashcat_ctx);

  if ((cpt_ctx->cpt_start + (60 * 60 * 24)) < now)
  {
    hc_asprintf (&cpt, "CUR:%u,%u,%u AVG:%.2f,%.2f,%.2f (Min,Hour,Day)",
      cpt_cur_min,
      cpt_cur_hour,
      cpt_cur_day,
      cpt_avg_min,
      cpt_avg_hour,
      cpt_avg_day);
  }
  else if ((cpt_ctx->cpt_start + (60 * 60)) < now)
  {
    hc_asprintf (&cpt, "CUR:%u,%u,N/A AVG:%.2f,%.2f,N/A (Min,Hour,Day)",
      cpt_cur_min,
      cpt_cur_hour,
      cpt_avg_min,
      cpt_avg_hour);
  }
  else if ((cpt_ctx->cpt_start + 60) < now)
  {
    hc_asprintf (&cpt, "CUR:%u,N/A,N/A AVG:%.2f,N/A,N/A (Min,Hour,Day)",
      cpt_cur_min,
      cpt_avg_min);
  }
  else
  {
    hc_asprintf (&cpt, "CUR:N/A,N/A,N/A AVG:N/A,N/A,N/A (Min,Hour,Day)");
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
    salt_pos = (int) device_param->kernel_param.salt_pos_host;
  }

  return salt_pos;
}

u64 status_get_innerloop_pos_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 innerloop_pos = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    innerloop_pos = device_param->innerloop_pos;
  }

  return innerloop_pos;
}

u64 status_get_innerloop_left_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  u64 innerloop_left = 0;

  if ((device_param->skipped == false) && (device_param->skipped_warning == false))
  {
    innerloop_left = device_param->innerloop_left;
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
    iteration_pos = (int) device_param->kernel_param.loop_pos;
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
    iteration_left = (int) device_param->kernel_param.loop_cnt;
  }

  return iteration_left;
}

char *status_get_device_name (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  return device_param->device_name;
}

cl_device_type status_get_device_type (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  return device_param->opencl_device_type;
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

#if defined (__APPLE__)
char *status_get_hwmon_fan_dev (const hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  char *fanspeed_str = (char *) hcmalloc (HCBUFSIZ_TINY);

  hc_thread_mutex_lock (status_ctx->mux_hwmon);

  hm_get_fanspeed_apple ((hashcat_ctx_t *) hashcat_ctx, fanspeed_str);

  hc_thread_mutex_unlock (status_ctx->mux_hwmon);

  return fanspeed_str;
}
#endif

char *status_get_hwmon_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return NULL;
  if (device_param->skipped_warning == true) return NULL;

  // Several backend devices can share one piece of hardware, and then they share its sensors too.
  // Only the first device of each group reports, so a machine with one card does not print the same
  // temperature once per virtual device. Returning NULL here is what the callers already treat as
  // "this device has nothing to show".

  if (hm_is_hwmon_group_leader ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx) == false) return NULL;

  // Then the DISPLAY's own grouping, which is a separate question from which devices carry sensors.
  // A group is one line whatever it is made of, and the line below is built by walking its members. The watchdog above walks every device and is deliberately not narrowed by this.

  if (backend_ctx_device_is_group_leader (hashcat_ctx, backend_devices_idx) == false) return NULL;

  char *output_buf = (char *) hcmalloc (HCBUFSIZ_TINY);

  snprintf (output_buf, HCBUFSIZ_TINY, "N/A");

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_hwmon);

  const int num_temperature = hm_get_temperature_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_fanspeed    = hm_get_fanspeed_with_devices_idx    ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_utilization = hm_get_utilization_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_corespeed   = hm_get_corespeed_with_devices_idx   ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_memoryspeed = hm_get_memoryspeed_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int num_buslanes    = hm_get_buslanes_with_devices_idx    ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);
  const int64_t num_power   = hm_get_power_with_devices_idx       ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx);

  int output_len = 0;

  // A bridge unit carrying several temperature sensors renders its own field, so all of the readings
  // show on one line. The plain reading is still what the abort watchdog uses, because the unit is
  // only as cool as its hottest sensor.

  // Wide enough for a large group. A group names the hottest few of its members, and a name plus a
  // reading is far longer than the "62/61/59/58c" a single device produces.

  char temp_str[256];

  temp_str[0] = 0;

  // A bridge unit that renders its own field renders the WHOLE line, and the fields below are skipped
  // for it. They describe one piece of hardware and a unit can be forty, so a single clock and a single
  // lane count would be picking one member to speak for all of them. What does not change during a run
  // is reported once at startup instead, per member, which is where a large unit needs it anyway.

  // A GROUP of several devices renders its own field across its members, because a group is what the
  // user is looking at and every member is a separate piece of hardware with its own sensor.
  //
  // The hottest few, NAMED, re-picked on every refresh so the set is dynamic. That is readable at
  // sixty four members and it never hides the hot one, which an average would. The rest are counted
  // rather than listed, and members with no sensor are counted separately: a group where five members
  // show a temperature and fifty nine show nothing looks broken until you can see that fifty nine
  // have no sensor fitted.

  const int group_size = backend_ctx_device_group_size (hashcat_ctx, backend_devices_idx, NULL);

  if (group_size > 1)
  {
    const backend_ctx_t *backend_ctx_grp = hashcat_ctx->backend_ctx;

    const hc_device_param_t *leader_param = &backend_ctx_grp->devices_param[backend_devices_idx];

    int hottest_idx[HWMON_GROUP_SHOW];
    int hottest_val[HWMON_GROUP_SHOW];

    int shown = 0;
    int with_sensor = 0;
    int without_sensor = 0;

    for (int i = backend_devices_idx; i < backend_ctx_grp->backend_devices_cnt; i++)
    {
      const hc_device_param_t *member_param = &backend_ctx_grp->devices_param[i];

      if (member_param->skipped == true) continue;
      if (member_param->skipped_warning == true) continue;
      if (member_param->group_id != leader_param->group_id) continue;

      const int temp = hm_get_temperature_with_devices_idx ((hashcat_ctx_t *) hashcat_ctx, i);

      if (temp < 0)
      {
        without_sensor++;

        continue;
      }

      with_sensor++;

      // insertion sort into the top list, which is cheap because the list is five long

      int pos = shown;

      for (int k = 0; k < shown; k++)
      {
        if (temp > hottest_val[k]) { pos = k; break; }
      }

      if (pos >= HWMON_GROUP_SHOW) continue;

      for (int k = MIN (shown, HWMON_GROUP_SHOW - 1); k > pos; k--)
      {
        hottest_val[k] = hottest_val[k - 1];
        hottest_idx[k] = hottest_idx[k - 1];
      }

      hottest_val[pos] = temp;
      hottest_idx[pos] = i;

      if (shown < HWMON_GROUP_SHOW) shown++;
    }

    int len = snprintf (output_buf, HCBUFSIZ_TINY, "Temp:");

    for (int k = 0; k < shown; k++)
    {
      len += snprintf (output_buf + len, HCBUFSIZ_TINY - len, " #%02u:%dc", hottest_idx[k] + 1, hottest_val[k]);
    }

    if (with_sensor > shown) len += snprintf (output_buf + len, HCBUFSIZ_TINY - len, " +%d", with_sensor - shown);

    if (without_sensor > 0) len += snprintf (output_buf + len, HCBUFSIZ_TINY - len, " %dxN/A", without_sensor);

    if (with_sensor == 0) snprintf (output_buf, HCBUFSIZ_TINY, "Temp: N/A (%d devices, no sensors)", without_sensor);

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);

    return output_buf;
  }

  if (hm_get_bridge_temperature_str ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx, temp_str, sizeof (temp_str)) == true)
  {
    snprintf (output_buf, HCBUFSIZ_TINY, "%s", temp_str);

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);

    return output_buf;
  }

  if (num_temperature >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Temp:%3dc ", num_temperature);
  }
  else if (hm_bridge_owns_device ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx) == true)
  {
    // A bridge unit with no reading at all, which is a property of the hardware rather than a failure
    // to read it: a 1.15y clone is built without the die sensors and says so, and a design without a
    // system monitor has nothing to report either.
    //
    // Say so. Dropping the field leaves a line that reads as though the temperature were forgotten,
    // next to sibling units that show one, and the obvious reading of that is that something broke.

    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Temp: N/A ");
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
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Bus:%u ", num_buslanes);
  }
  else
  {
    // Lanes are a PCIe idea and a unit reached some other way has none, so the bridge reports no
    // number here and it is right not to. Dropping the field is what misleads: beside sibling units
    // that DO show a lane count, a line ending after the clock reads as a unit attached to nothing.
    //
    // So let it say what the link actually is. "USB 480Mb/s" answers the same question a lane count
    // answers, how fat the pipe is, and answers it better than a placeholder would.

    char bus_str[64];

    if (hm_get_bridge_buslanes_str ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx, bus_str, sizeof (bus_str)) == true)
    {
      output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "%s ", bus_str);
    }
    else if (hm_bridge_owns_device ((hashcat_ctx_t *) hashcat_ctx, backend_devices_idx) == true)
    {
      output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Bus: N/A ");
    }
  }

  if (num_power >= 0)
  {
    output_len += snprintf (output_buf + output_len, HCBUFSIZ_TINY - output_len, "Pwr:%" PRId64 "mW ", num_power);
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

  if (device_param->kernel_threads_prev) return device_param->kernel_threads_prev;

  return device_param->kernel_threads;
}

u64 status_get_kernel_power_dev (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

  if (device_param->skipped == true) return 0;
  if (device_param->skipped_warning == true) return 0;

  return device_param->kernel_power;
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

  #ifdef WITH_BRAIN
  status_ctx->brain_rejects_attacks = 0;
  status_ctx->brain_rejects_hashes  = 0;
  #endif
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
  status_ctx->checkpoint_taken    = false;
  status_ctx->finish_shutdown     = false;

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
  hcfree (hashcat_status->guess_mod_q);
  hcfree (hashcat_status->guess_charset);
  hcfree (hashcat_status->cpt);
  #ifdef WITH_BRAIN
  hcfree (hashcat_status->brain_rx_all);
  hcfree (hashcat_status->brain_tx_all);
  #endif

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
  hashcat_status->guess_mod_q             = NULL;
  hashcat_status->guess_charset           = NULL;
  hashcat_status->cpt                     = NULL;
  #ifdef WITH_BRAIN
  hashcat_status->brain_rx_all            = NULL;
  hashcat_status->brain_tx_all            = NULL;
  #endif

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
