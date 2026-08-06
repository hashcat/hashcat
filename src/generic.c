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
#include "user_options.h"

// Report and clear a global error, same reasoning as generic_thread_error ().

static bool generic_global_error (hashcat_ctx_t *hashcat_ctx, generic_global_ctx_t *global_ctx)
{
  if (global_ctx->error == false) return false;

  event_log_error (hashcat_ctx, "%s", global_ctx->error_msg);

  global_ctx->error = false;

  global_ctx->error_msg[0] = 0;

  return true;
}

// Where a feed named on the command line is looked for. A feed is named, not pathed: "-a 8 hash
// wordlist" finds the shipped wordlist feed the same way "-m 0" finds its module, so a user does not
// have to know where hashcat installed its shared files. Two prefixes are tried because a feed
// written in Rust is installed as rust_<name> and one written in C as feed_<name>.
//
// A name that matches nothing is used as a path, so a plugin still under development keeps working
// from wherever it was built.

int generic_filename (const folder_config_t *folder_config, const char *plugin_name, const char *prefix, char *out_buf, const size_t out_size)
{
  #if defined (_WIN) || defined (__CYGWIN__)
  return snprintf (out_buf, out_size, "%s/feeds/%s%s.dll", folder_config->shared_dir, prefix, plugin_name);
  #else
  return snprintf (out_buf, out_size, "%s/feeds/%s%s.so", folder_config->shared_dir, prefix, plugin_name);
  #endif
}

char *generic_resolve (const folder_config_t *folder_config, const char *plugin_name, bool *by_name)
{
  const char *prefixes[] = { "feed_", "rust_", "" };

  for (int i = 0; i < 3; i++)
  {
    char *filename = (char *) hcmalloc (HCBUFSIZ_TINY);

    generic_filename (folder_config, plugin_name, prefixes[i], filename, HCBUFSIZ_TINY);

    if (hc_path_read (filename) == true)
    {
      if (by_name) *by_name = true;

      return filename;
    }

    hcfree (filename);
  }

  if (by_name) *by_name = false;

  char *filename = hcstrdup (plugin_name);

  return filename;
}

static bool generic_global_init (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  // we probably need to add more stuff here

  generic_ctx->global_ctx.quiet = user_options->quiet;

  generic_ctx->global_ctx.workc = generic_ctx->workc;
  generic_ctx->global_ctx.workv = generic_ctx->workv;

  generic_ctx->global_ctx.cache_dir   = folder_config->cache_dir;
  generic_ctx->global_ctx.profile_dir = folder_config->profile_dir;

  // ok we can also add hashcat_ctx, which might be hard to bind, but we make it optional
  // so those who support it, can have full access into hashcat core

  const bool rc = generic_ctx->global_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  if (generic_global_error (hashcat_ctx, &generic_ctx->global_ctx) == true) return false;

  return rc;
}

static void generic_global_term (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx)
{
  generic_ctx->global_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  generic_global_error (hashcat_ctx, &generic_ctx->global_ctx);
}

// Returns the keyspace, GENERIC_KEYSPACE_UNKNOWN for a feed that cannot count itself, or
// GENERIC_KEYSPACE_ERROR when the plugin failed. The last two used to be the same value, so a plugin
// that could not open its input ran on as an endless feed.

static u64 generic_global_keyspace (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx)
{
  const u64 keyspace = generic_ctx->global_keyspace (&generic_ctx->global_ctx, &generic_ctx->thread_ctx, hashcat_ctx);

  if (generic_global_error (hashcat_ctx, &generic_ctx->global_ctx) == true) return GENERIC_KEYSPACE_ERROR;

  return keyspace;
}

// Report and clear a per-device error. The flag has to be cleared, because nothing else does it and
// a flag that stays set makes every later call on that device look like it failed too.

static bool generic_thread_error (hashcat_ctx_t *hashcat_ctx, generic_thread_ctx_t *thread_ctx)
{
  if (thread_ctx->error == false) return false;

  event_log_error (hashcat_ctx, "%s", thread_ctx->error_msg);

  thread_ctx->error = false;

  thread_ctx->error_msg[0] = 0;

  return true;
}

static bool generic_thread_init (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx, const int device_id)
{
  const bool rc = generic_ctx->thread_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  if (generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]) == true) return false;

  return rc;
}

static void generic_thread_term (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx, const int device_id)
{
  generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]);
}

int generic_thread_next (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int device_id, u8 *out_buf, const int out_size)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  const int out_len = generic_ctx->thread_next (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id], out_buf, out_size);

  if (generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]) == true) return GENERIC_RC_ERROR;

  // a plugin that returns any other negative value has not said what it means, so it is a failure and
  // not a quiet end of input

  if (out_len < 0)
  {
    if (out_len == GENERIC_RC_EOF) return GENERIC_RC_EOF;

    event_log_error (hashcat_ctx, "%s: thread_next returned %d", generic_ctx->dynlib_filename, out_len);

    return GENERIC_RC_ERROR;
  }

  return out_len;
}

int generic_thread_seek (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int device_id, const u64 offset)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  const bool rc = generic_ctx->thread_seek (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id], offset);

  if (generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]) == true) return GENERIC_RC_ERROR;

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s: seek to %" PRIu64 " failed", generic_ctx->dynlib_filename, offset);

    return GENERIC_RC_ERROR;
  }

  return 0;
}

// Bring one instance up: resolve the plugin, load its symbols, let it initialise itself and ask it how
// large it is. Everything an instance needs is inside its own generic_ctx_t, which is what lets a run
// hold more than one at a time. The shipped feed keeps all of its per run state behind
// global_ctx->gbldata and thread_ctx->thrdata and has no file scope state of its own, so one dlopen
// handle backs any number of instances.
//
// workc and workv have to be set by the caller, because where an instance's sources come from is the
// one thing the attack modes disagree about.
//
// announce says whether to put a line on the screen around the plugin's own startup. The instances an
// attack runs on do. An instance opened only to count one file does not, because the wordlist reader
// asks for one of those per round and the plugin already reports the counting itself.

static int generic_instance_init (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx, const bool announce)
{
  backend_ctx_t   *backend_ctx   = hashcat_ctx->backend_ctx;
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  generic_ctx->plugin_name = generic_ctx->workv[0];

  /**
   * dynloader
   */

  generic_ctx->dynlib_filename = generic_resolve (folder_config, generic_ctx->plugin_name, NULL);

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

  // From here on the instance owns resources, so a failure below still has to be torn down

  generic_ctx->enabled = true;

  // A feed can have a lot to do before it produces its first word. A PCFG plugin loads a grammar,
  // and a grammar trained on a modest wordlist is already hundreds of megabytes. Without a line
  // around it that is a silent freeze on startup with no output at all.

  if (announce == true)
  {
    EVENT (EVENT_CLEAR_EVENT_LINE);

    EVENT_DATA (EVENT_GENERIC_INIT_PRE, generic_ctx->plugin_name, strlen (generic_ctx->plugin_name) + 1);
  }

  const bool rc_init = generic_global_init (hashcat_ctx, generic_ctx);

  if (announce == true)
  {
    EVENT_DATA (EVENT_GENERIC_INIT_POST, generic_ctx->plugin_name, strlen (generic_ctx->plugin_name) + 1);
  }

  if (rc_init == false) return -1;

  // The keyspace is kept in base words and finished later. -a 6 and -a 7 amplify with the mask, which
  // mask_ctx_update_loop sizes once per round, so there is nothing here to multiply by yet.

  generic_ctx->keyspace = generic_global_keyspace (hashcat_ctx, generic_ctx);

  if (generic_ctx->keyspace == GENERIC_KEYSPACE_ERROR) return -1;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (generic_thread_init (hashcat_ctx, generic_ctx, device_param->device_id) == false) return -1;
  }

  return 0;
}

static void generic_instance_destroy (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (generic_ctx->enabled == false) return;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    generic_thread_term (hashcat_ctx, generic_ctx, device_param->device_id);
  }

  hcfree (generic_ctx->thread_ctx);

  generic_global_term (hashcat_ctx, generic_ctx);

  hcfree (generic_ctx->dynlib_filename);

  if (generic_ctx->workv_owned == true) hcfree (generic_ctx->workv);

  memset (generic_ctx, 0, sizeof (generic_ctx_t));
}

// Open one instance over a range of the work arguments. A feed is always handed its plugin name as
// workv[0] and its sources after it, which is the shape the plugin interface documents and the
// shipped feeds read. Every mode that reaches here asked for a wordlist, so the plugin is the shipped
// wordlist feed and the name has to be put in front of the dictionaries the user typed.
//
// The array is built here rather than by rewriting the work arguments themselves, and that is the
// point of doing it here at all. The wordlist checks, the outfile checks, the combinator and the mask
// all address those arguments by position, so moving every index by one to make room for a plugin
// name changes what all of them see.

static int generic_instance_open (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int from, const int to)
{
  generic_ctx_t        *generic_ctx        = &hashcat_ctx->generic_ctx[role];
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  generic_ctx->workc = (to - from) + 1;
  generic_ctx->workv = (char **) hcmalloc ((size_t) generic_ctx->workc * sizeof (char *));

  generic_ctx->workv[0] = "wordlist";

  for (int i = from; i < to; i++)
  {
    generic_ctx->workv[(i - from) + 1] = user_options_extra->hc_workv[i];
  }

  generic_ctx->workv_owned = true;

  const int rc = generic_instance_init (hashcat_ctx, generic_ctx, true);

  return rc;
}

// Open the base word instance over one path, replacing whatever it held before.
//
// This is the per round scope. An attack that is really a queue of attacks reads one dictionary per
// round, and the dictionary an induction round reads does not exist until the round before it: it is
// written by the round that found the words. So the instance is opened when the round starts rather
// than when the session does, which is the only thing that was ever in the way.
//
// The workv is built here and owned by the instance, because the path is not always a work argument.
// An induction dictionary is a file hashcat wrote itself. Only the array is owned, as everywhere else:
// the plugin takes its own copy of every path while it is initialising.

int generic_ctx_base_round (hashcat_ctx_t *hashcat_ctx, const char *path)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  generic_instance_destroy (hashcat_ctx, generic_ctx);

  generic_ctx->workc = 2;
  generic_ctx->workv = (char **) hcmalloc (2 * sizeof (char *));

  generic_ctx->workv[0] = "wordlist";
  generic_ctx->workv[1] = (char *) path;

  generic_ctx->workv_owned = true;

  const int rc = generic_instance_init (hashcat_ctx, generic_ctx, false);

  return rc;
}

// Read and throw away the first count base words, so that a source which cannot be seeked still
// starts where --skip or --restore says.
//
// Every other source answers offset N with the same word every time, so hashcat reaches a position by
// asking for it. A pipe cannot: the word at offset N is whichever word arrives next, and the only way
// to be at position N is to have consumed N words. So it is done here, once, before the device threads
// exist, because the offsets the device threads ask for are one per device and none of them is the
// position the run starts at.
//
// Feeding the same candidates in the same order is the user's part of this. hashcat cannot check it
// and does not try to: "cat wordlist.txt | hashcat --skip 1000" is a thing people run and a thing an
// overlay hands out, and refusing it because a pipe could have been something else helps nobody.
//
// The words are gone rather than tried, so they are booked as rejected. That is what they are: a
// position that produced no candidate. It also keeps the progress line adding up, because the caller
// leaves the restored counter alone for a source that gets here.

int generic_ctx_base_discard (hashcat_ctx_t *hashcat_ctx, const int device_id, const u64 count)
{
  hashes_t     *hashes     = hashcat_ctx->hashes;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  u8 *out_buf = (u8 *) hcmalloc (PW_MAX);

  for (u64 i = 0; i < count; i++)
  {
    const int out_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, device_id, out_buf, PW_MAX);

    if (out_len == GENERIC_RC_ERROR)
    {
      hcfree (out_buf);

      return -1;
    }

    // The source ran out before the position was reached. That is not an error: the run has nothing
    // left to do and says so by starting where the source ended.

    if (out_len == GENERIC_RC_EOF)
    {
      status_ctx->words_off = i;
      status_ctx->words_cur = i;

      break;
    }

    if (status_ctx->run_thread_level1 == false) break;
  }

  hcfree (out_buf);

  const u64 amplifier_cnt = user_options_extra_amplifier (hashcat_ctx);

  const u64 rejected = status_ctx->words_off * amplifier_cnt;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    status_ctx->words_progress_rejected[salt_pos] += rejected;
  }

  return 0;
}

// Which modes amplify with a second wordlist rather than with a mask or with rules, and so need an
// instance for the amplifier as well as one for the base. -a 1 always does. -a 7 does it only under
// the pure kernel, where the mask is the base and the dictionary is what each base word is combined
// with, and not under --slow-candidates, which builds the whole candidate on the host and never asks
// for an amplifier count.

static bool generic_amp_is_wordlist (const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_COMBI) return true;

  if (user_options->attack_mode != ATTACK_MODE_HYBRID2) return false;

  if (user_options->slow_candidates == true) return false;

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) return false;

  return true;
}

int generic_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  for (int role = 0; role < GENERIC_ROLE_CNT; role++) hashcat_ctx->generic_ctx[role].enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;

  // -a 1 is the mode whose amplifier is a wordlist too, so both of its dictionaries are counted by a
  // feed. Which of the two is the base is not decided yet: combinator_ctx_init makes that choice from
  // the two counts and runs after this. So the instances are created in the order the dictionaries
  // were typed and combinator_ctx_init swaps the two slots if it picks the right hand one.
  //
  // Both are created whatever base_source says, because the count is wanted even when the wordlist
  // reader is the one doing the reading.

  if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    for (int i = 0; i < 2; i++)
    {
      // at this point we know the file actually exists

      if (hc_path_is_file (user_options_extra->hc_workv[i]) == false)
      {
        event_log_error (hashcat_ctx, "%s: Not a regular file.", user_options_extra->hc_workv[i]);

        return -1;
      }
    }

    if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_BASE, 0, 1) == -1) return -1;
    if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_AMP,  1, 2) == -1) return -1;

    return 0;
  }

  if (generic_amp_is_wordlist (hashcat_ctx) == true)
  {
    // -a 7 under the pure kernel names its mask first and its dictionary second

    if (hc_path_is_file (user_options_extra->hc_workv[1]) == false)
    {
      event_log_error (hashcat_ctx, "%s: Not a regular file.", user_options_extra->hc_workv[1]);

      return -1;
    }

    if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_AMP, 1, 2) == -1) return -1;
  }

  // Candidates read from a pipe are a feed too, and the one whose plugin the user never named because
  // there was no source to name. Everything else about it is a feed: it says so on the status line, it
  // is counted the same way, and the brain builds its attack id from the plugin name like any other.

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

    generic_ctx->workc = 1;
    generic_ctx->workv = (char **) hcmalloc (sizeof (char *));

    generic_ctx->workv[0] = "stdin";

    generic_ctx->workv_owned = true;

    const int rc = generic_instance_init (hashcat_ctx, generic_ctx, true);

    return rc;
  }

  if (user_options_extra->base_source != BASE_SOURCE_FEED) return 0;

  // A per round instance is opened by the round that reads it, in straight_ctx_update_loop. Its
  // dictionary is not known here, and for an induction round it does not exist yet.

  if (user_options_extra->base_scope == BASE_SCOPE_PER_ROUND) return 0;

  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  // -a 8 names its own plugin and is handed the command line as it stands

  if (user_options->attack_mode == ATTACK_MODE_GENERIC)
  {
    generic_ctx->workc = user_options_extra->hc_workc;
    generic_ctx->workv = user_options_extra->hc_workv;

    if (generic_instance_init (hashcat_ctx, generic_ctx, true) == -1) return -1;
  }
  else
  {
    // Which of the work arguments are the base word instance's sources. -a 6 leaves its last argument
    // to the mask and -a 7 leaves its first, exactly as straight_ctx_add_workv splits them for the
    // wordlist reader.

    int from = 0;
    int to   = user_options_extra->hc_workc;

    if (user_options->attack_mode == ATTACK_MODE_HYBRID1) to   = to - 1;
    if (user_options->attack_mode == ATTACK_MODE_HYBRID2) from = 1;

    if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_BASE, from, to) == -1) return -1;
  }

  // -a 9 pairs word N with salt N, so the two counts have to agree exactly. Asked here as well as per
  // round, because a scope that knows its keyspace at init should be refused before any device is
  // brought up rather than after the self-test.

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    const hashes_t *hashes = hashcat_ctx->hashes;

    if (generic_ctx->keyspace != hashes->salts_cnt)
    {
      event_log_error (hashcat_ctx, "Number of words in wordlist '%s' is not in sync with number of unique salts", generic_ctx->workv[1]);
      event_log_error (hashcat_ctx, "Words: %" PRIu64 ", salts: %d", generic_ctx->keyspace, hashes->salts_cnt);

      return -1;
    }
  }

  return 0;
}

// Put the two instances in the slots their roles say. -a 1 counts both of its dictionaries before it
// can say which is the base, so the instances are created in the order they were typed and this runs
// once combinator_ctx_init has chosen.
//
// Moving a whole instance is safe because the plugin holds no pointer into it: every call is handed
// the addresses again, and all of the plugin's own state hangs off the gbldata and thrdata pointers,
// which travel with the struct. Nothing has started reading yet either, this is still init.

void generic_ctx_roles_swap (hashcat_ctx_t *hashcat_ctx)
{
  generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  generic_ctx_t tmp;

  memcpy (&tmp,                              &generic_ctx[GENERIC_ROLE_BASE], sizeof (generic_ctx_t));
  memcpy (&generic_ctx[GENERIC_ROLE_BASE],   &generic_ctx[GENERIC_ROLE_AMP],  sizeof (generic_ctx_t));
  memcpy (&generic_ctx[GENERIC_ROLE_AMP],    &tmp,                            sizeof (generic_ctx_t));
}

void generic_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  for (int role = 0; role < GENERIC_ROLE_CNT; role++)
  {
    generic_instance_destroy (hashcat_ctx, &hashcat_ctx->generic_ctx[role]);
  }
}
