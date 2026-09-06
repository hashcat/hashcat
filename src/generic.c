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
#include "path.h"
#include "folder.h"
#include "filehandling.h"
#include "rp.h"
#include "mpsp.h"
#include "wordlist.h"
#include "feed_ctx.h"
#include "dynloader.h"
#include "user_options.h"
#include "backend.h"

#include <inttypes.h>

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
  generic_ctx->global_ctx.seekdb_dir  = user_options->seekdb_path;
  generic_ctx->global_ctx.shared_dir  = folder_config->shared_dir;

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
// GENERIC_KEYSPACE_ERROR when the plugin failed. The last two are different values, so a plugin that
// could not open its input is an error rather than an endless feed.

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

// thread_init () and thread_term () both run on the main thread, one device after another, so the
// device a feed is being initialised for is made current around each call rather than once for the
// thread. A feed that builds device resources here is otherwise building them on whichever device
// happened to be current, which for the second device onward is the wrong one.
//
// A device that cannot be made current is not a device this feed can be initialised on, and saying
// so here is better than letting the plugin discover it.

static bool generic_thread_init (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx, const int device_id)
{
  if (feed_device_bind_id (hashcat_ctx, device_id) == false) return false;

  const bool rc = generic_ctx->thread_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  feed_device_unbind_id (hashcat_ctx, device_id);

  if (generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]) == true) return false;

  return rc;
}

static void generic_thread_term (hashcat_ctx_t *hashcat_ctx, generic_ctx_t *generic_ctx, const int device_id)
{
  const bool bound = feed_device_bind_id (hashcat_ctx, device_id);

  generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id]);

  if (bound == true) feed_device_unbind_id (hashcat_ctx, device_id);

  generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]);
}

// The device engine's answer: a base word and the cell that extends it. One call stands for a whole inner
// loop, so the feed's own position advances by il_cnt rather than by one.

int generic_thread_next_dev (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int device_id, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  const int out_len = generic_ctx->thread_next_dev (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[device_id], out_buf, out_size, cell);

  if (generic_thread_error (hashcat_ctx, &generic_ctx->thread_ctx[device_id]) == true) return GENERIC_RC_ERROR;

  if (out_len < 0)
  {
    if (out_len == GENERIC_RC_EOF) return GENERIC_RC_EOF;

    event_log_error (hashcat_ctx, "%s: thread_next_dev returned %d", generic_ctx->dynlib_filename, out_len);

    return GENERIC_RC_ERROR;
  }

  return out_len;
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
    const int plugin_abi = hc_dlplugin_abi (generic_ctx->dynlib_filename);

    if ((plugin_abi != -1) && (plugin_abi != HC_PLUGIN_ABI_VERSION))
    {
      event_log_error (hashcat_ctx, "Feed %s was built for plugin interface %d, this hashcat provides %d", generic_ctx->dynlib_filename, plugin_abi, HC_PLUGIN_ABI_VERSION);
    }
    else
    {
      event_log_error (hashcat_ctx, "%s", hc_dlerror ());
    }

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

  // These are indexed by device id everywhere, so each one can say which device it belongs to. It is
  // set here rather than in generic_thread_init () because global_keyspace () runs before any device
  // thread starts and plugins call their own thread_init () on thread_ctx[0] from inside it.

  for (int device_id = 0; device_id < DEVICES_MAX; device_id++)
  {
    generic_ctx->thread_ctx[device_id].device_id = device_id;
  }

  generic_ctx->autohex_enable = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_AUTOHEX) ? true : false;
  generic_ctx->iconv_enable   = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_ICONV)   ? true : false;
  generic_ctx->rules_enable   = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_RULES)   ? true : false;
  generic_ctx->dev_enable     = (*generic_plugin_options & GENERIC_PLUGIN_OPTIONS_DEVICE)     ? true : false;

  const bool dev_offered = generic_ctx->dev_enable;

  HC_LOAD_FUNC_GENERIC (generic_ctx, global_init,     GENERIC_GLOBAL_INIT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, global_term,     GENERIC_GLOBAL_TERM);
  HC_LOAD_FUNC_GENERIC (generic_ctx, global_keyspace, GENERIC_GLOBAL_KEYSPACE);

  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_init,     GENERIC_THREAD_INIT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_term,     GENERIC_THREAD_TERM);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_next,     GENERIC_THREAD_NEXT);
  HC_LOAD_FUNC_GENERIC (generic_ctx, thread_seek,     GENERIC_THREAD_SEEK);

  // Only a feed that said it runs on the device has to have these, and one that said so and does not is a
  // broken feed rather than a feed without an device engine.

  if (generic_ctx->dev_enable == true)
  {
    HC_LOAD_FUNC_GENERIC (generic_ctx, global_dev_init, GENERIC_GLOBAL_DEV_INIT);
    HC_LOAD_FUNC_GENERIC (generic_ctx, thread_next_dev, GENERIC_THREAD_NEXT_DEV);
  }

  // Whether the device engine is going to be used, settled here and nowhere else.
  //
  // It has to be settled before global_init () runs, because a feed that can generate two different
  // ways counts a different keyspace for each and global_init () is where it counts. It also has to be
  // settled before backend_session_begin (), because the device engine is a different kernel; this runs
  // from generic_ctx_init (), which is ahead of both.
  //
  // Five things can take it away from a feed that advertised one.
  //
  // Only the base feed gets the device engine. The amplifier instance of a combinator attack is a
  // second word list and has nothing to do with this, and neither does a feed used as anything
  // but the -a 8 base. A -a 4 run is one of those: user_options_alias_attack_mode () rewrote it into
  // -a 8 with the pcfg feed named, long before this reads the mode.
  //
  // And a slow hash does not get one, because it could not have run one.
  // ATTACK_EXEC_OUTSIDE_KERNEL is hashcat's own line between a mode whose attack kernel carries the
  // whole hash and one where a separate iteration kernel does. An device engine is an inner loop, and an
  // outside-kernel mode has no attack kernel to put one in: generate_source_kernel_filename () ignores
  // attack_kern entirely on that side and takes mXXXXX-pure.cl. So the run announced the device engine,
  // moved attack_kern to ATTACK_KERN_PCFG, and then died looking for an OpenCL/amp_a2.cl that does not
  // exist, before the first launch and with nothing said about why.
  //
  // On a genuinely slow mode it does not want one either, and that is what makes the switch a gain
  // rather than a retreat. bcrypt on an RTX 4090 is 237 kH/s and one core of the pcfg feed's plain
  // path gives 8 to 47 million candidates a second, so the device engine there buys a factor nobody needs
  // while costing every compromise it forced to exist: a fixed candidate array, a slot ceiling, one
  // byte length per bucket, a quantised terminal cost, and no OMEN escape.
  //
  // That headroom is not a property of every outside-kernel mode and must not be read as one. All 294
  // of them were measured on that card, and the fastest which takes a password rather than a key is
  // 12700 at 355 MH/s, then 10500, 25400 and 06700 between 108 and 165. One core cannot feed those.
  // They land here anyway, because a mode with no attack kernel has nowhere else to go, and what
  // limits them is the feed rather than the card.
  //
  // A feed keeps both exits, so clearing the flag here is the whole switch. dispatch.c reads it to
  // choose thread_next () over thread_next_dev (), attack_kern stays ATTACK_KERN_STRAIGHT, and dev_avg
  // stays zero so the status line counts candidates rather than base words.

  const bool is_base = (generic_ctx == &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE]);

  if (is_base == false) generic_ctx->dev_enable = false;

  if (hashcat_ctx->user_options->attack_mode != ATTACK_MODE_GENERIC) generic_ctx->dev_enable = false;

  if (hashcat_ctx->hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL) generic_ctx->dev_enable = false;

  // And --stdout does not get one, for the third time the same reason. It prints what the host
  // produced and never starts a kernel, so with the device engine on there was nothing to print: it
  // borrows hash mode 2000, which is inside-kernel, and the run died naming a missing
  // OpenCL/m02000_a4-pure.cl. An amplifying feed was therefore the one thing --stdout could not show
  // you, which is the opposite of what it is for.

  if (hashcat_ctx->user_options->stdout_flag == true) generic_ctx->dev_enable = false;

  // And --slow-candidates does not get one, for the fourth time the same reason. Every candidate is
  // built on the host under it, which is what it is named after, so the device never runs a generator
  // and generate_source_kernel_filename () takes m00000_a0-pure.cl whatever attack_kern holds. That
  // test is the first one in the function rather than an arm of the attack_kern switch, so it is easy
  // to read the switch and conclude the device engine is safe here.
  //
  // With the flag left on, the run announced the device engine, moved attack_kern to
  // ATTACK_KERN_PCFG, compiled the straight kernel, and then bound the three cell arguments the
  // straight kernel does not have and launched it. That is an illegal memory access on the first
  // launch and a session that never exits, so it had to be killed.
  //
  // --brain-client reaches this the same way, because user_options_preprocess () turns it into
  // --slow-candidates before anything here runs.
  //
  // hashcat's own status line already read it this way: terminal.c clears Candidate.Engine for
  // --slow-candidates whatever the amplifier count says, so the display and the feed disagreed.

  if (hashcat_ctx->user_options->slow_candidates == true) generic_ctx->dev_enable = false;

  // And rules take it away, for the fifth time the same reason, rather than ending the run.
  //
  // The inner loop that would apply them is the one walking the cell and there is no second one, so
  // the device engine cannot have rules. The host engine can: it is attack mode 0 with a different
  // reader in front of it, and hashcat's own rules kernel applies them there exactly as it does to a
  // word list. So -r asks for the host engine rather than for something that does not exist, and the
  // run is the one the user asked for, slower, instead of an error about a missing rules kernel.
  //
  // It has to be cleared here and not where the other refusals live, because the feed counts a
  // different keyspace for each exit and global_init () is where it counts.

  if (hashcat_ctx->user_options->rp_files_cnt > 0) generic_ctx->dev_enable = false;
  if (hashcat_ctx->user_options->rp_gen > 0) generic_ctx->dev_enable = false;

  // And a hash mode with no device engine kernel takes it away, for the sixth time the same reason.
  //
  // The device engine's kernel is OpenCL/mNNNNN_a4-pure.cl, named by the mode's KERN_TYPE. Most fast
  // hash modes have one. The rest do not, because their rules kernel does something the hooks cannot
  // express: it records the crack itself rather than handing back four words to compare, or it takes
  // the candidate as register words instead of an array. Reading which ones those are means reading
  // the kernels, and the file being there is the same answer with nothing to keep in step.
  //
  // Without this the run ended on a missing file, which said which file but not what to do about it.
  // The host engine builds every candidate on the host and hands it to the mode's own straight
  // kernel, so it works for every mode there is. So a PCFG run on a mode with no device kernel is now
  // the run the user asked for, slower, and the startup line says which engine it got.
  //
  // The three modes that pick their kernel from the hash they parsed rather than from a constant,
  // 14500, 16500 and 16501, are tested here on the constant instead, because backend_session_begin ()
  // asks module_kern_type_dynamic () a long way after this runs. Every kernel any of the three can
  // land on has a device engine file, and so does the constant, so the two answers agree today. A
  // mode whose two answers disagreed would reach the missing file again.

  // -O has to be answered before the kernel file is looked for, or the answer is never given.
  //
  // The name generated below is built from opti_type, so with -O it is the optimized kernel's name.
  // The device engine ships only a pure kernel, so that file is never there, the lookup clears
  // dev_enable, and a refusal placed after it never runs because it sits inside a dev_enable test.
  // What the user gets instead is the host generator, silently: measured on -m 0, 21182.7 kH/s with
  // -O against 221.0 MH/s without it, and nothing said that -O was the reason.
  //
  // The two cases have to be told apart before the lookup, because after it they look identical. A
  // mode with no device engine kernel is meant to fall back and does. -O is meant to be refused.
  //
  // There was an optimized form of the device engine kernel. It kept the md5 block in registers and
  // padded it once outside the inner loop, and at its own best lane count it measured 4 to 5 per cent
  // ahead of the pure one. What it cost was 6 kernel bodies, a write path that had to name every word
  // of the block at compile time, a password length capped at 55 instead of 256, and a candidate
  // length fixed for the whole inner loop, which is exactly what a grammar with multi byte characters
  // cannot promise. 5 per cent did not pay for that.
  //
  // -O is refused rather than ignored because hashconfig settled it long before the attack kernel was
  // known, and the hashes were parsed under it on the way: a raw md5 digest has had the initial state
  // subtracted out of it for a kernel that is now not going to run. Clearing the flag here leaves
  // those digests wrong, which shows up as a self-test failure and, with the self-test disabled, as
  // an attack that cracks nothing.

  if ((generic_ctx->dev_enable == true) && (hashcat_ctx->hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL))
  {
    event_log_error (hashcat_ctx, "The device engine has no optimized kernel. Run this without -O.");

    return -1;
  }

  if (generic_ctx->dev_enable == true)
  {
    char source_file[256];

    generate_source_kernel_filename (false, hashcat_ctx->hashconfig->attack_exec, ATTACK_KERN_PCFG,
                                     hashcat_ctx->hashconfig->kern_type, hashcat_ctx->hashconfig->opti_type,
                                     hashcat_ctx->folder_config->shared_dir, source_file);

    if (hc_path_read (source_file) == false) generic_ctx->dev_enable = false;
  }

  generic_ctx->global_ctx.dev_enable = generic_ctx->dev_enable;

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

  // A feed says what it loaded on its own account, and every other block of startup output ends with
  // a blank line. Whether this one has anything to end is not a question the display can answer for
  // itself, so it is counted: the two marks bracket what the feed said and skip the two lines this
  // function logs itself, which are the ones that would otherwise make a silent feed look talkative.

  const u64 log_mark_init = event_log_count (hashcat_ctx);

  const bool rc_init = generic_global_init (hashcat_ctx, generic_ctx);

  u64 said = event_log_count (hashcat_ctx) - log_mark_init;

  if (announce == true)
  {
    EVENT_DATA (EVENT_GENERIC_INIT_POST, generic_ctx->plugin_name, strlen (generic_ctx->plugin_name) + 1);
  }

  if (rc_init == false) return -1;

  // The keyspace is kept in base words and finished later. -a 6 and -a 7 amplify with the mask, which
  // mask_ctx_update_loop sizes once per round, so there is nothing here to multiply by yet.

  // The two exits are not the same attack, so they must not look like one to the brain. They
  // enumerate the same set only when the feed has nothing the device engine cannot carry, and even then a
  // position means a base word on one side and a candidate on the other, so a brain that took them for
  // one attack would hand out ranges in the wrong unit.
  //
  // Only a feed that offered an device engine and did not get one is moved. A feed that never had one is
  // running the attack it always ran, and shifting its identity would throw away every brain session
  // and restore point anybody has for it.

  if ((dev_offered == true) && (generic_ctx->dev_enable == false))
  {
    generic_ctx->global_ctx.source_ident ^= 0x50434647534c4f57ULL;
  }

  if (generic_ctx->dev_enable == true)
  {
    user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

    if (generic_ctx->global_dev_init (&generic_ctx->global_ctx, &generic_ctx->dev_pool, &generic_ctx->dev_pool_size, &generic_ctx->dev_il_cnt, &generic_ctx->dev_avg, &generic_ctx->dev_maxword, &generic_ctx->dev_front, &generic_ctx->dev_step, &generic_ctx->dev_varlen, &generic_ctx->dev_probe) == false)
    {
      event_log_error (hashcat_ctx, "%s: device engine init failed: %s", generic_ctx->dynlib_filename, generic_ctx->global_ctx.error_msg);

      return -1;
    }

    user_options_extra->attack_kern = ATTACK_KERN_PCFG;

  }

  // A feed whose settings asked it a question has answered it by now, and there is nothing here to
  // run. Both engines can answer, but not in the same place: the device engine counts base words,
  // and the tables that number comes from are built inside global_dev_init (), so the device half of
  // an answer does not exist until the call above has returned. Testing it here catches both.
  //
  // The keyspace is not asked for and no device thread is started. thread_init () is where a feed
  // starts its producer threads, and there is nothing left for them to produce.

  if (generic_ctx->global_ctx.described == true) return 0;

  const u64 log_mark_rest = event_log_count (hashcat_ctx);

  generic_ctx->keyspace = generic_global_keyspace (hashcat_ctx, generic_ctx);

  if (generic_ctx->keyspace == GENERIC_KEYSPACE_ERROR) return -1;


  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (generic_thread_init (hashcat_ctx, generic_ctx, device_param->device_id) == false) return -1;
  }

  // global_keyspace () and thread_init () are inside the block too. A feed that reports its keyspace
  // or declines a device is still the same feed talking about the same startup.

  said += event_log_count (hashcat_ctx) - log_mark_rest;

  // The shipped wordlist feed already ends its own block with a blank line, so the separator is due
  // only when the feed said something and did not finish with one itself.

  if (announce == false) return 0;
  if (said == 0) return 0;

  // And only when there is a block to separate. --quiet silences the two lines this brackets with,
  // so a separator without them would be a blank line on its own, and --stdout, which sets quiet
  // itself, would put that blank line on the candidate stream: an empty password, handed to whatever
  // is reading, ahead of everything the feed produced. A feed that says something through
  // feed_say () says it on stderr under --stdout and still counts here, which is what makes this
  // reachable rather than theoretical.

  if (hashcat_ctx->user_options->quiet == true) return 0;

  if (event_log_last_blank (hashcat_ctx) == false) event_log_info (hashcat_ctx, NULL);

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

// A base wordlist that is a single zstd stream is handed to the shipped zstd feed, which decompresses
// and seeks inside it; anything else goes to the plain wordlist feed. Detected by magic so a .zst under
// any name is classified by content and a plaintext file never is. Only the base source is auto-routed;
// amplifiers (-a 1/6/7) stay on the wordlist feed.
static const char *generic_base_feed (const char *path)
{
  if (path == NULL) return "wordlist";

  HCFILE fp;

  if (hc_fopen_raw (&fp, path, "rb") == false) return "wordlist";

  u8 m[4] = { 0 };

  const size_t n = hc_fread (m, 1, sizeof (m), &fp);

  hc_fclose (&fp);

  if (n == 4 && m[0] == 0x28 && m[1] == 0xb5 && m[2] == 0x2f && m[3] == 0xfd) return "zstd";

  return "wordlist";
}

static int generic_instance_open (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int from, const int to)
{
  generic_ctx_t        *generic_ctx        = &hashcat_ctx->generic_ctx[role];
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  generic_ctx->workc = (to - from) + 1;
  generic_ctx->workv = (char **) hcmalloc ((size_t) generic_ctx->workc * sizeof (char *));

  generic_ctx->workv[0] = (char *) (((role == GENERIC_ROLE_BASE) && ((to - from) == 1))
                                    ? generic_base_feed (user_options_extra->hc_workv[from])
                                    : "wordlist");

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
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  generic_instance_destroy (hashcat_ctx, generic_ctx);

  generic_ctx->workc = 2;
  generic_ctx->workv = (char **) hcmalloc (2 * sizeof (char *));

  // -a 9 splitting its own hash file has no file to name per round. Its rounds are the words one account
  // name becomes, so the source is which of those words this round is trying.

  generic_ctx->workv[0] = (char *) ((user_options_extra->association_autosplit == true) ? "association" : generic_base_feed (path));
  generic_ctx->workv[1] = (char *) path;

  generic_ctx->workv_owned = true;

  const int rc = generic_instance_init (hashcat_ctx, generic_ctx, false);

  return rc;
}

// Give the base word instance up before its round would normally replace it.
//
// An induction round reads a dictionary hashcat wrote itself and deletes it once it is consumed. The
// instance that read it is otherwise held until the next round opens over the top, and on Windows a
// file that is still open cannot be deleted, so the delete failed, the scan found the same file
// again, and the run never moved on. Closing here costs nothing anywhere else: the next round opens
// its own instance regardless.

void generic_ctx_base_close (hashcat_ctx_t *hashcat_ctx)
{
  generic_instance_destroy (hashcat_ctx, &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE]);
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

  // The third thread that reaches a feed. This is the main thread, before any device thread exists,
  // and the device is made current around the whole loop for the same reason it is made current
  // around the producer's: thread_next () may talk to it, and once per loop costs nothing.

  const bool bound = feed_device_bind_id (hashcat_ctx, device_id);

  for (u64 i = 0; i < count; i++)
  {
    const int out_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, device_id, out_buf, PW_MAX);

    if (out_len == GENERIC_RC_ERROR)
    {
      if (bound == true) feed_device_unbind_id (hashcat_ctx, device_id);

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

  if (bound == true) feed_device_unbind_id (hashcat_ctx, device_id);

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
  const user_options_t *user_options = hashcat_ctx->user_options;

  // The wordlist amplifies rather than being the base word source. That is a mask that ends in ?w
  // under a pure kernel, and a ?q, and base_source and hybrid_q are where those two were settled.

  if (user_options->attack_mode != ATTACK_MODE_HYBRID) return false;

  const bool inverted = (hashcat_ctx->user_options_extra->base_source == BASE_SOURCE_MASK);

  return inverted;
}

// -a 9 pairs word N with salt N, so the two counts have to agree exactly. Asked at init and again per
// round, because a scope that knows its keyspace at init should be refused before any device is brought
// up rather than after the self-test, and a scope that reads one dictionary per round can only be asked
// once that round's dictionary has been counted.
//
// A hash-mode with no salt is the common way to arrive here: every one of its hashes shares the single
// salt, so there is one salt to pair with however many words there are. Naming the file the words came
// out of is what makes that readable, and the autosplit form has no such file to name.

int generic_association_in_sync (hashcat_ctx_t *hashcat_ctx, const generic_ctx_t *generic_ctx)
{
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (generic_ctx->keyspace == hashes->salts_cnt) return 0;

  if (user_options_extra->association_autosplit == true)
  {
    event_log_error (hashcat_ctx, "Number of words split out of hash file '%s' is not in sync with number of unique salts", hashes->hashfile);
  }
  else
  {
    event_log_error (hashcat_ctx, "Number of words in wordlist '%s' is not in sync with number of unique salts", generic_ctx->workv[1]);
  }

  event_log_error (hashcat_ctx, "Words: %" PRIu64 ", salts: %d", generic_ctx->keyspace, hashes->salts_cnt);

  return -1;
}

// Whether any feed instance was asked to describe the attack rather than to run it. Both roles are
// asked, because -a 1 counts its two dictionaries as two instances and either of them can be the one
// that was handed the question.

bool generic_ctx_described (const hashcat_ctx_t *hashcat_ctx)
{
  for (int role = 0; role < GENERIC_ROLE_CNT; role++)
  {
    const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

    if (generic_ctx->enabled == false) continue;

    if (generic_ctx->global_ctx.described == true) return true;
  }

  return false;
}

// A word as the run would compare it, and whether the index it sits at moves on when the run throws
// it away.
//
// A feed hands back the line. The run does not compare against the line: pw_transform_apply () has
// had it first, and --hex-wordlist, $HEX[], the -j or -k rule, a mode that hashes in upper case and
// an encoding change all happen in there. Comparing against the line instead answers about a string
// the run never builds, which is worse than not answering: it reports a password the run does reach
// as absent, and hands out an offset for one it does not.
//
// The two roles book a refusal differently and both are deliberate. A base word keeps its position
// whatever happens to it, because --skip addresses that stream positionally and the dispatcher
// advances seek_pos before it tests anything. An amplifier word gives its slot up, because the fill
// packs what it accepted and everything after a refusal moves up.

static bool generic_word_transform (const pw_transform_t *transform, u8 *buf, const int out_len, const size_t buf_size, u32 *len_out)
{
  if (out_len > PW_MAX) return false;

  const int len = pw_transform_apply (transform, buf, out_len, (int) buf_size);

  if (len < 0) return false;

  *len_out = (u32) len;

  return true;
}

// Where a feed reaches a candidate: the index of the first word it produces that equals it, and how
// many more of them there are behind it.
//
// There is no index to consult and there is nowhere to put one. A feed is a stream; the only thing
// that knows what its Nth word is is the feed, and the nine functions it exports have no
// where-is-this-word among them. So the answer is found the way the run finds it, by reading forward
// from the start, and it costs one pass. That is what the run's own first pass costs and what
// grep -n costs, and there is no sublinear answer to pretend to.
//
// Read on thread slot 0, brought up and torn down here. No device thread is competing for it:
// --lookup borrows --keyspace, so the loop that would have initialised one slot per device never
// ran, and nothing else in the process is reading this feed. global_keyspace () borrows the same slot
// to count the file and gives it back, so it is free by the time this is called.
//
// The index is the answer in --skip units without conversion. A word the length filters will reject
// still advances it, and so does a duplicate, because the feed counts lines and nothing else - which
// is also what makes "grep -n minus one" a correct oracle for this.

int generic_ctx_word_index (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u8 *cand, const u32 cand_len, u64 *out_index, u64 *out_more, u64 *out_words)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  if (generic_ctx->enabled == false)
  {
    event_log_error (hashcat_ctx, "lookup: no feed instance is open for this role");

    return -1;
  }

  // A feed with a device engine builds device resources in thread_init (), and there is no device
  // here to build them on, so it is refused rather than initialised onto whatever was current. The
  // wordlist feed offers no device engine and builds nothing: it allocates its reader and opens no
  // file until it is told where to start.

  if (generic_ctx->dev_enable == true)
  {
    event_log_error (hashcat_ctx, "lookup: %s has a device engine and cannot be read without a device", generic_ctx->dynlib_filename);

    return -1;
  }

  // thread_init () and thread_term () are called without the device bind that wraps them everywhere
  // else. That bind makes one device current for a feed that builds resources on it, and this runs
  // with no devices at all: --lookup borrows --keyspace, so backend_ctx_init () returned before any
  // device was opened and there is nothing to make current. The test above is what makes that safe.

  if (generic_ctx->thread_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]) == false)
  {
    event_log_error (hashcat_ctx, "lookup: %s: %s", generic_ctx->dynlib_filename, generic_ctx->thread_ctx[0].error_msg);

    generic_ctx->thread_ctx[0].error = false;

    return -1;
  }

  // A feed opens nothing until it is told where to start, so the seek is not an optimisation here but
  // the thing that makes the first word exist.

  pw_transform_t transform;

  if (pw_transform_init (&transform, hashcat_ctx, role, (int) hashcat_ctx->user_options_extra->rule_len_base, hashcat_ctx->user_options_extra->rule_buf_base) == -1)
  {
    generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]);

    return -1;
  }

  int rc = -1;

  if (generic_thread_seek (hashcat_ctx, role, 0, 0) == GENERIC_RC_ERROR)
  {
    event_log_error (hashcat_ctx, "lookup: %s: seek to the first word failed", generic_ctx->dynlib_filename);
  }
  else
  {
    u8 buf[HCBUFSIZ_TINY];

    u64 index = 0;
    u64 first = 0;
    u64 more  = 0;

    bool found = false;

    rc = 0;

    while (true)
    {
      const int out_len = generic_thread_next (hashcat_ctx, role, 0, buf, sizeof (buf));

      if (out_len == GENERIC_RC_EOF) break;

      if (out_len == GENERIC_RC_ERROR)
      {
        rc = -1;

        break;
      }

      u32 len = 0;

      if (generic_word_transform (&transform, buf, out_len, sizeof (buf), &len) == true)
      {
        if ((len == cand_len) && (memcmp (buf, cand, cand_len) == 0))
        {
          if (found == false)
          {
            found = true;
            first = index;
          }
          else
          {
            more++;
          }
        }
      }

      index++;
    }

    if (rc == 0)
    {
      *out_words = index;

      if (found == true)
      {
        *out_index = first;
        *out_more  = more;

        rc = 1;
      }
    }
  }

  pw_transform_term (&transform);

  generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]);

  generic_ctx->thread_ctx[0].error = false;

  return rc;
}

// The first index at which a feed produces each of a family of words, in one pass.
//
// A -a 12 candidate is mask, base word, mask, ?q word, mask, and only the two word lengths are free.
// That does not make the words independent: whatever the split, the base word is a prefix of what
// follows the mask in front of it and the ?q word is a suffix of what precedes the mask behind it. So
// every length can be tested with one comparison per feed word, and every length at once with one
// pass, rather than one pass per split.
//
// anchor is the candidate byte the family is measured from. Going forward, a word of length L must
// equal anchor[0..L). Going backward, it must equal anchor[-L..0), which is the ?q case: the ?q word
// ends where the mask behind it begins, and that end is fixed while its start is not.
//
// out_index[L - min_len] is the first index of a word of length L, or GENERIC_KEYSPACE_UNKNOWN when
// no word of that length matched.

int generic_ctx_word_family (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u8 *anchor, const u32 min_len, const u32 max_len, const bool backward, u64 *out_index, u64 *out_words)
{
  generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  if (generic_ctx->enabled == false) return -1;

  if (generic_ctx->dev_enable == true) return -1;

  if (min_len > max_len) return -1;

  for (u32 i = 0; i <= (max_len - min_len); i++) out_index[i] = GENERIC_KEYSPACE_UNKNOWN;

  if (generic_ctx->thread_init (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]) == false)
  {
    event_log_error (hashcat_ctx, "lookup: %s: %s", generic_ctx->dynlib_filename, generic_ctx->thread_ctx[0].error_msg);

    generic_ctx->thread_ctx[0].error = false;

    return -1;
  }

  // The base word keeps its position when the run throws it away and the amplifier word does not, so
  // the index only always moves on for the base. See generic_word_transform () above.

  const bool advance_on_reject = (role == GENERIC_ROLE_BASE);

  const int   rule_len = (int) ((role == GENERIC_ROLE_BASE) ? hashcat_ctx->user_options_extra->rule_len_base : hashcat_ctx->user_options_extra->rule_len_amp);
  const char *rule_buf =        (role == GENERIC_ROLE_BASE) ? hashcat_ctx->user_options_extra->rule_buf_base : hashcat_ctx->user_options_extra->rule_buf_amp;

  pw_transform_t transform;

  if (pw_transform_init (&transform, hashcat_ctx, role, rule_len, rule_buf) == -1)
  {
    generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]);

    return -1;
  }

  int rc = -1;

  if (generic_thread_seek (hashcat_ctx, role, 0, 0) != GENERIC_RC_ERROR)
  {
    u8 buf[HCBUFSIZ_TINY];

    u64 index = 0;

    rc = 0;

    while (true)
    {
      const int out_len = generic_thread_next (hashcat_ctx, role, 0, buf, sizeof (buf));

      if (out_len == GENERIC_RC_EOF) break;

      if (out_len == GENERIC_RC_ERROR)
      {
        rc = -1;

        break;
      }

      u32 len = 0;

      if (generic_word_transform (&transform, buf, out_len, sizeof (buf), &len) == false)
      {
        if (advance_on_reject == true) index++;

        continue;
      }

      if ((len >= min_len) && (len <= max_len))
      {
        const u8 *want = (backward == true) ? (anchor - len) : anchor;

        if (memcmp (buf, want, len) == 0)
        {
          if (out_index[len - min_len] == GENERIC_KEYSPACE_UNKNOWN) out_index[len - min_len] = index;
        }
      }

      index++;
    }

    if (rc == 0) *out_words = index;
  }

  pw_transform_term (&transform);

  generic_ctx->thread_term (&generic_ctx->global_ctx, &generic_ctx->thread_ctx[0]);

  generic_ctx->thread_ctx[0].error = false;

  return rc;
}

// Which of a feed's sources a word index lands in, for a base that is several dictionaries or a
// folder laid end to end. The feed publishes the two arrays in global_keyspace (); a feed that
// publishes none is one source and has nothing to say.

const char *generic_ctx_segment_of (const hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u64 index)
{
  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[role];

  const generic_global_ctx_t *global_ctx = &generic_ctx->global_ctx;

  if (global_ctx->segments_cnt < 2) return NULL;

  const char *name = NULL;

  for (u64 i = 0; i < global_ctx->segments_cnt; i++)
  {
    if (global_ctx->segment_first[i] > index) break;

    name = global_ctx->segment_names[i];
  }

  return name;
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

  if (generic_amp_is_wordlist (hashcat_ctx) == true)
  {
    // -a 7 under the pure kernel names its mask first and its dictionary second, and so does -a 12

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
    //
    // -a 12 writes the mask first and then its wordlists, one of them or two, and which is which is
    // its position and nothing else. Nothing here opens a file to find out what it looks like.

    int from = 0;
    int to   = user_options_extra->hc_workc;

    const bool hybrid_q = user_options_extra->hybrid_q;

    if (user_options->attack_mode == ATTACK_MODE_HYBRID)
    {
      from = 1;
      to   = user_options_extra->hc_workc - ((hybrid_q == true) ? 1 : 0);
    }

    if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_BASE, from, to) == -1) return -1;

    if (hybrid_q == true)
    {
      // the second wordlist is read by one instance from start to end, so unlike the base it cannot
      // be a folder

      if (hc_path_is_file (user_options_extra->hc_workv[to]) == false)
      {
        event_log_error (hashcat_ctx, "%s: Not a regular file.", user_options_extra->hc_workv[to]);

        return -1;
      }

      if (generic_instance_open (hashcat_ctx, GENERIC_ROLE_AMP, to, to + 1) == -1) return -1;
    }
  }

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    if (generic_association_in_sync (hashcat_ctx, generic_ctx) == -1) return -1;
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
