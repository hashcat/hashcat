/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "logfile.h"
#include "interface.h"
#include "shared.h"
#include "path.h"
#include "filehandling.h"
#include "usage.h"
#include "backend.h"
#include "user_options.h"
#include "outfile.h"
#include "rp.h"
#include "rp_cpu.h"

#include "feed_ctx.h"
#include "mpsp.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

#ifdef WITH_BRAIN
static const char *const short_options = "hHVvm:a:r:j:k:g:o:t:d:D:n:u:T:p:s:l:1:2:3:4:5:6:7:8:iIbw:OMSY:R:z";
#else
static const char *const short_options = "hHVvm:a:r:j:k:g:o:t:d:D:n:u:T:p:s:l:1:2:3:4:5:6:7:8:iIbw:OMSY:R:";
#endif

static char *const SEPARATOR = ":";

static const struct option long_options[] =
{
  {"advice-disable",            no_argument,       NULL, IDX_ADVICE_DISABLE},
  {"attack-mode",               required_argument, NULL, IDX_ATTACK_MODE},
  {"backend-devices",           required_argument, NULL, IDX_BACKEND_DEVICES},
  {"backend-devices-virtmulti", required_argument, NULL, IDX_BACKEND_DEVICES_VIRTMULTI},
  {"backend-devices-virthost",  required_argument, NULL, IDX_BACKEND_DEVICES_VIRTHOST},
  {"backend-ignore-cuda",       no_argument,       NULL, IDX_BACKEND_IGNORE_CUDA},
  {"backend-ignore-hip",        no_argument,       NULL, IDX_BACKEND_IGNORE_HIP},
  #if defined (__APPLE__)
  {"backend-ignore-metal",      no_argument,       NULL, IDX_BACKEND_IGNORE_METAL},
  #endif
  {"backend-ignore-opencl",     no_argument,       NULL, IDX_BACKEND_IGNORE_OPENCL},
  {"backend-info",              no_argument,       NULL, IDX_BACKEND_INFO},
  {"backend-vector-width",      required_argument, NULL, IDX_BACKEND_VECTOR_WIDTH},
  {"bypass-delay",              required_argument, NULL, IDX_BYPASS_DELAY},
  {"bypass-threshold",          required_argument, NULL, IDX_BYPASS_THRESHOLD},
  {"benchmark-all",             no_argument,       NULL, IDX_BENCHMARK_ALL},
  {"benchmark-max",             required_argument, NULL, IDX_BENCHMARK_MAX},
  {"benchmark-min",             required_argument, NULL, IDX_BENCHMARK_MIN},
  {"benchmark",                 no_argument,       NULL, IDX_BENCHMARK},
  {"bitmap-max",                required_argument, NULL, IDX_BITMAP_MAX},
  {"bitmap-min",                required_argument, NULL, IDX_BITMAP_MIN},
  {"bridge-parameter1",         required_argument, NULL, IDX_BRIDGE_PARAMETER1},
  {"bridge-parameter2",         required_argument, NULL, IDX_BRIDGE_PARAMETER2},
  {"bridge-parameter3",         required_argument, NULL, IDX_BRIDGE_PARAMETER3},
  {"bridge-parameter4",         required_argument, NULL, IDX_BRIDGE_PARAMETER4},
  {"cpu-affinity",              required_argument, NULL, IDX_CPU_AFFINITY},
  {"custom-charset1",           required_argument, NULL, IDX_CUSTOM_CHARSET_1},
  {"custom-charset2",           required_argument, NULL, IDX_CUSTOM_CHARSET_2},
  {"custom-charset3",           required_argument, NULL, IDX_CUSTOM_CHARSET_3},
  {"custom-charset4",           required_argument, NULL, IDX_CUSTOM_CHARSET_4},
  {"custom-charset5",           required_argument, NULL, IDX_CUSTOM_CHARSET_5},
  {"custom-charset6",           required_argument, NULL, IDX_CUSTOM_CHARSET_6},
  {"custom-charset7",           required_argument, NULL, IDX_CUSTOM_CHARSET_7},
  {"custom-charset8",           required_argument, NULL, IDX_CUSTOM_CHARSET_8},
  {"debug-file",                required_argument, NULL, IDX_DEBUG_FILE},
  {"debug-mode",                required_argument, NULL, IDX_DEBUG_MODE},
  {"deprecated-check-disable",  no_argument,       NULL, IDX_DEPRECATED_CHECK_DISABLE},
  {"dynamic-x",                 no_argument,       NULL, IDX_DYNAMIC_X},
  {"encoding-from",             required_argument, NULL, IDX_ENCODING_FROM},
  {"encoding-to",               required_argument, NULL, IDX_ENCODING_TO},
  {"example-hashes",            no_argument,       NULL, IDX_HASH_INFO}, // alias of hash-info
  {"force",                     no_argument,       NULL, IDX_FORCE},
  {"generate-rules-func-max",   required_argument, NULL, IDX_RP_GEN_FUNC_MAX},
  {"generate-rules-func-min",   required_argument, NULL, IDX_RP_GEN_FUNC_MIN},
  {"generate-rules-func-sel",   required_argument, NULL, IDX_RP_GEN_FUNC_SEL},
  {"generate-rules",            required_argument, NULL, IDX_RP_GEN},
  {"generate-rules-seed",       required_argument, NULL, IDX_RP_GEN_SEED},
  {"hwmon-disable",             no_argument,       NULL, IDX_HWMON_DISABLE},
  {"hwmon-temp-abort",          required_argument, NULL, IDX_HWMON_TEMP_ABORT},
  {"hash-copy",                 no_argument,       NULL, IDX_HASH_COPY},
  {"hash-info",                 no_argument,       NULL, IDX_HASH_INFO},
  {"hash-type",                 required_argument, NULL, IDX_HASH_MODE},
  {"hccapx-message-pair",       required_argument, NULL, IDX_HCCAPX_MESSAGE_PAIR},
  {"help",                      no_argument,       NULL, IDX_HELP},
  {"hex-charset",               no_argument,       NULL, IDX_HEX_CHARSET},
  {"hex-salt",                  no_argument,       NULL, IDX_HEX_SALT},
  {"hex-wordlist",              no_argument,       NULL, IDX_HEX_WORDLIST},
  {"hook-threads",              required_argument, NULL, IDX_HOOK_THREADS},
  {"identify",                  no_argument,       NULL, IDX_IDENTIFY},
  {"increment-max",             required_argument, NULL, IDX_INCREMENT_MAX},
  {"increment-min",             required_argument, NULL, IDX_INCREMENT_MIN},
  {"increment",                 no_argument,       NULL, IDX_INCREMENT},
  {"increment-inverse",         no_argument,       NULL, IDX_INCREMENT_INVERSE},
  {"induction-dir",             required_argument, NULL, IDX_INDUCTION_DIR},
  {"keep-guessing",             no_argument,       NULL, IDX_KEEP_GUESSING},
  {"kernel-accel",              required_argument, NULL, IDX_KERNEL_ACCEL},
  {"kernel-loops",              required_argument, NULL, IDX_KERNEL_LOOPS},
  {"kernel-threads",            required_argument, NULL, IDX_KERNEL_THREADS},
  {"keyboard-layout-mapping",   required_argument, NULL, IDX_KEYBOARD_LAYOUT_MAPPING},
  {"keyspace",                  no_argument,       NULL, IDX_KEYSPACE},
  {"total-candidates",          no_argument,       NULL, IDX_TOTAL_CANDIDATES},
  {"left",                      no_argument,       NULL, IDX_LEFT},
  {"limit",                     required_argument, NULL, IDX_LIMIT},
  {"logfile-disable",           no_argument,       NULL, IDX_LOGFILE_DISABLE},
  {"lookup",                    required_argument, NULL, IDX_LOOKUP},
  {"loopback",                  no_argument,       NULL, IDX_LOOPBACK},
  {"machine-readable",          no_argument,       NULL, IDX_MACHINE_READABLE},
  {"markov-classic",            no_argument,       NULL, IDX_MARKOV_CLASSIC},
  {"markov-disable",            no_argument,       NULL, IDX_MARKOV_DISABLE},
  {"markov-hcstat2",            required_argument, NULL, IDX_MARKOV_HCSTAT2},
  {"markov-inverse",            no_argument,       NULL, IDX_MARKOV_INVERSE},
  {"markov-threshold",          required_argument, NULL, IDX_MARKOV_THRESHOLD},
  {"metal-compiler-runtime",    required_argument, NULL, IDX_METAL_COMPILER_RUNTIME},
  {"nonce-error-corrections",   required_argument, NULL, IDX_NONCE_ERROR_CORRECTIONS},
  {"opencl-device-types",       required_argument, NULL, IDX_OPENCL_DEVICE_TYPES},
  {"optimized-kernel-enable",   no_argument,       NULL, IDX_OPTIMIZED_KERNEL_ENABLE},
  {"multiply-accel-disable",    no_argument,       NULL, IDX_MULTIPLY_ACCEL_DISABLE},
  {"outfile-autohex-disable",   no_argument,       NULL, IDX_OUTFILE_AUTOHEX_DISABLE},
  {"outfile-check-dir",         required_argument, NULL, IDX_OUTFILE_CHECK_DIR},
  {"outfile-check-timer",       required_argument, NULL, IDX_OUTFILE_CHECK_TIMER},
  {"outfile-format",            required_argument, NULL, IDX_OUTFILE_FORMAT},
  {"outfile-json",              no_argument,       NULL, IDX_OUTFILE_JSON},
  {"outfile",                   required_argument, NULL, IDX_OUTFILE},
  {"potfile-disable",           no_argument,       NULL, IDX_POTFILE_DISABLE},
  {"potfile-path",              required_argument, NULL, IDX_POTFILE_PATH},
  {"progress-only",             no_argument,       NULL, IDX_PROGRESS_ONLY},
  {"quiet",                     no_argument,       NULL, IDX_QUIET},
  {"remove",                    no_argument,       NULL, IDX_REMOVE},
  {"remove-timer",              required_argument, NULL, IDX_REMOVE_TIMER},
  {"restore-disable",           no_argument,       NULL, IDX_RESTORE_DISABLE},
  {"restore-file-path",         required_argument, NULL, IDX_RESTORE_FILE_PATH},
  {"restore-position",          no_argument,       NULL, IDX_RESTORE_POSITION},
  {"restore",                   no_argument,       NULL, IDX_RESTORE},
  {"rule-left",                 required_argument, NULL, IDX_RULE_BUF_L},
  {"rule-right",                required_argument, NULL, IDX_RULE_BUF_R},
  {"rules-file",                required_argument, NULL, IDX_RP_FILE},
  {"runtime",                   required_argument, NULL, IDX_RUNTIME},
  {"scrypt-tmto",               required_argument, NULL, IDX_SCRYPT_TMTO},
  {"seekdb-path",               required_argument, NULL, IDX_SEEKDB_PATH},
  {"self-test-disable",         no_argument,       NULL, IDX_SELF_TEST_DISABLE},
  {"separator",                 required_argument, NULL, IDX_SEPARATOR},
  {"seperator",                 required_argument, NULL, IDX_SEPARATOR},
  {"session",                   required_argument, NULL, IDX_SESSION},
  {"show",                      no_argument,       NULL, IDX_SHOW},
  {"skip",                      required_argument, NULL, IDX_SKIP},
  {"slow-candidates",           no_argument,       NULL, IDX_SLOW_CANDIDATES},
  {"speed-only",                no_argument,       NULL, IDX_SPEED_ONLY},
  {"spin-damp",                 required_argument, NULL, IDX_SPIN_DAMP},
  {"status",                    no_argument,       NULL, IDX_STATUS},
  {"status-json",               no_argument,       NULL, IDX_STATUS_JSON},
  {"pipeline-stats",            no_argument,       NULL, IDX_PIPELINE_STATS},
  {"task-time-breakdown",       no_argument,       NULL, IDX_TASK_TIME_BREAKDOWN},
  {"status-timer",              required_argument, NULL, IDX_STATUS_TIMER},
  {"stdout",                    no_argument,       NULL, IDX_STDOUT_FLAG},
  {"stdin-timeout-abort",       required_argument, NULL, IDX_STDIN_TIMEOUT_ABORT},
  {"truecrypt-keyfiles",        required_argument, NULL, IDX_TRUECRYPT_KEYFILES},
  {"username",                  no_argument,       NULL, IDX_USERNAME},
  {"veracrypt-keyfiles",        required_argument, NULL, IDX_VERACRYPT_KEYFILES},
  {"veracrypt-pim-start",       required_argument, NULL, IDX_VERACRYPT_PIM_START},
  {"veracrypt-pim-stop",        required_argument, NULL, IDX_VERACRYPT_PIM_STOP},
  {"version",                   no_argument,       NULL, IDX_VERSION},
  {"wordlist-autohex-disable",  no_argument,       NULL, IDX_WORDLIST_AUTOHEX_DISABLE},
  {"workload-profile",          required_argument, NULL, IDX_WORKLOAD_PROFILE},
  #ifdef WITH_BRAIN
  {"brain-client",              no_argument,       NULL, IDX_BRAIN_CLIENT},
  {"brain-feed",                no_argument,       NULL, IDX_BRAIN_FEED},
  {"brain-client-features",     required_argument, NULL, IDX_BRAIN_CLIENT_FEATURES},
  {"brain-server",              no_argument,       NULL, IDX_BRAIN_SERVER},
  {"brain-server-timer",        required_argument, NULL, IDX_BRAIN_SERVER_TIMER},
  {"brain-host",                required_argument, NULL, IDX_BRAIN_HOST},
  {"brain-port",                required_argument, NULL, IDX_BRAIN_PORT},
  {"brain-password",            required_argument, NULL, IDX_BRAIN_PASSWORD},
  {"brain-session",             required_argument, NULL, IDX_BRAIN_SESSION},
  {"brain-session-whitelist",   required_argument, NULL, IDX_BRAIN_SESSION_WHITELIST},
  #endif
  {"color-cracked",             no_argument,       NULL, IDX_COLOR_CRACKED},
  {"encrypt-with-pubkey",       required_argument, NULL, IDX_ENCRYPT_WITH_PUBKEY},
  {NULL,                        0,                 NULL, 0 }
};

static const char *const ENCODING_FROM = "utf-8";
static const char *const ENCODING_TO   = "utf-8";

static const char *const RULE_BUF_R = ":";
static const char *const RULE_BUF_L = ":";

static const char *const DEF_MASK_CS_1 = "?l?d?u";
static const char *const DEF_MASK_CS_2 = "?l?d";
static const char *const DEF_MASK_CS_3 = "?l?d*!$@_";

int user_options_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  user_options->advice                    = ADVICE;
  user_options->attack_mode               = ATTACK_MODE;
  user_options->autodetect                = AUTODETECT;
  user_options->backend_devices           = NULL;
  user_options->backend_devices_virtmulti = BACKEND_DEVICES_VIRTMULTI;
  user_options->backend_devices_virthost  = BACKEND_DEVICES_VIRTHOST;
  user_options->backend_ignore_cuda       = BACKEND_IGNORE_CUDA;
  user_options->backend_ignore_hip        = BACKEND_IGNORE_HIP;
  #if defined (__APPLE__)
  user_options->backend_ignore_metal      = BACKEND_IGNORE_METAL;
  #endif
  user_options->backend_ignore_opencl     = BACKEND_IGNORE_OPENCL;
  user_options->backend_info              = BACKEND_INFO;
  user_options->backend_vector_width      = BACKEND_VECTOR_WIDTH;
  user_options->benchmark_all             = BENCHMARK_ALL;
  user_options->benchmark_max             = BENCHMARK_MAX;
  user_options->benchmark_min             = BENCHMARK_MIN;
  user_options->benchmark                 = BENCHMARK;
  user_options->bitmap_max                = BITMAP_MAX;
  user_options->bitmap_min                = BITMAP_MIN;
  #ifdef WITH_BRAIN
  user_options->brain_client              = BRAIN_CLIENT;
  user_options->brain_feed                = false;
  user_options->brain_client_features      = BRAIN_CLIENT_FEATURES;
  user_options->brain_client_features_chgd = false;
  user_options->brain_host                = NULL;
  user_options->brain_port                = BRAIN_PORT;
  user_options->brain_server              = BRAIN_SERVER;
  user_options->brain_server_timer        = BRAIN_SERVER_TIMER;
  user_options->brain_session             = BRAIN_SESSION;
  user_options->brain_session_whitelist   = NULL;
  #endif
  user_options->color_cracked             = COLOR_CRACKED;
  user_options->bridge_parameter1         = NULL;
  user_options->bridge_parameter2         = NULL;
  user_options->bridge_parameter3         = NULL;
  user_options->bridge_parameter4         = NULL;
  user_options->cpu_affinity              = NULL;
  user_options->custom_charset_1          = NULL;
  user_options->custom_charset_2          = NULL;
  user_options->custom_charset_3          = NULL;
  user_options->custom_charset_4          = NULL;
  user_options->custom_charset_5          = NULL;
  user_options->custom_charset_6          = NULL;
  user_options->custom_charset_7          = NULL;
  user_options->custom_charset_8          = NULL;
  user_options->debug_file                = NULL;
  user_options->debug_mode                = DEBUG_MODE;
  user_options->deprecated_check          = DEPRECATED_CHECK;
  user_options->dynamic_x                 = DYNAMIC_X;
  user_options->encoding_from             = ENCODING_FROM;
  user_options->encoding_to               = ENCODING_TO;
  user_options->encrypt_with_pubkey       = NULL;
  user_options->force                     = FORCE;
  user_options->hash_copy                 = HASH_COPY;
  user_options->hwmon                     = HWMON;
  user_options->hwmon_temp_abort          = HWMON_TEMP_ABORT;
  user_options->hash_info                 = HASH_INFO;
  user_options->hash_mode                 = HASH_MODE;
  user_options->hccapx_message_pair       = HCCAPX_MESSAGE_PAIR;
  user_options->hex_charset               = HEX_CHARSET;
  user_options->hex_salt                  = HEX_SALT;
  user_options->hex_wordlist              = HEX_WORDLIST;
  user_options->hook_threads              = HOOK_THREADS;
  user_options->identify                  = IDENTIFY;
  user_options->increment                 = (increment_t) INCREMENT;
  user_options->increment_max             = INCREMENT_MAX;
  user_options->increment_min             = INCREMENT_MIN;
  user_options->induction_dir             = NULL;
  user_options->keep_guessing             = KEEP_GUESSING;
  user_options->kernel_accel              = KERNEL_ACCEL;
  user_options->kernel_loops              = KERNEL_LOOPS;
  user_options->kernel_threads            = KERNEL_THREADS;
  user_options->keyboard_layout_mapping   = NULL;
  user_options->keyspace                  = KEYSPACE;
  user_options->total_candidates          = TOTAL_CANDIDATES;
  user_options->left                      = LEFT;
  user_options->limit                     = LIMIT;
  user_options->logfile                   = LOGFILE;
  user_options->lookup                    = NULL;
  user_options->lookup_alias              = NULL;
  user_options->loopback                  = LOOPBACK;
  user_options->machine_readable          = MACHINE_READABLE;
  user_options->markov_classic            = MARKOV_CLASSIC;
  user_options->markov                    = MARKOV;
  user_options->markov_hcstat2            = NULL;
  user_options->markov_inverse            = MARKOV_INVERSE;
  user_options->markov_threshold          = MARKOV_THRESHOLD;
  user_options->metal_compiler_runtime    = METAL_COMPILER_RUNTIME;
  user_options->nonce_error_corrections   = NONCE_ERROR_CORRECTIONS;
  user_options->opencl_device_types       = NULL;
  user_options->optimized_kernel          = OPTIMIZED_KERNEL;
  user_options->multiply_accel            = MULTIPLY_ACCEL;
  user_options->outfile_autohex           = OUTFILE_AUTOHEX;
  user_options->outfile_check_dir         = NULL;
  user_options->outfile_check_timer       = OUTFILE_CHECK_TIMER;
  user_options->outfile_format            = OUTFILE_FORMAT;
  user_options->outfile_json              = OUTFILE_JSON;
  user_options->outfile                   = NULL;
  user_options->potfile                   = POTFILE;
  user_options->potfile_path              = NULL;
  user_options->progress_only             = PROGRESS_ONLY;
  user_options->quiet                     = QUIET;
  user_options->remove                    = REMOVE;
  user_options->remove_timer              = REMOVE_TIMER;
  user_options->restore_enable            = RESTORE_ENABLE;
  user_options->restore_file_path         = NULL;
  user_options->restore                   = RESTORE;
  user_options->restore_position          = RESTORE_POSITION;
  user_options->restore_timer             = RESTORE_TIMER;
  user_options->rp_gen_func_max           = RP_GEN_FUNC_MAX;
  user_options->rp_gen_func_min           = RP_GEN_FUNC_MIN;
  user_options->rp_gen_func_sel           = NULL;
  user_options->rp_gen                    = RP_GEN;
  user_options->rp_gen_seed               = RP_GEN_SEED;
  user_options->rule_buf_l                = RULE_BUF_L;
  user_options->rule_buf_r                = RULE_BUF_R;
  user_options->runtime                   = RUNTIME;
  user_options->scrypt_tmto               = SCRYPT_TMTO;
  user_options->seekdb_path               = NULL;
  user_options->self_test                 = SELF_TEST;
  user_options->separator                 = SEPARATOR;
  user_options->session                   = PROGNAME;
  user_options->show                      = SHOW;
  user_options->skip                      = SKIP;
  user_options->slow_candidates           = SLOW_CANDIDATES;
  user_options->speed_only                = SPEED_ONLY;
  user_options->spin_damp                 = SPIN_DAMP;
  user_options->status                    = STATUS;
  user_options->status_json               = STATUS_JSON;
  user_options->pipeline_stats            = PIPELINE_STATS;
  user_options->task_time_breakdown       = TASK_TIME_BREAKDOWN;
  user_options->status_timer              = STATUS_TIMER;
  user_options->stdin_timeout_abort       = STDIN_TIMEOUT_ABORT;
  user_options->stdout_flag               = STDOUT_FLAG;
  user_options->truecrypt_keyfiles        = NULL;
  user_options->usage                     = USAGE;
  user_options->username                  = USERNAME;
  user_options->veracrypt_keyfiles        = NULL;
  user_options->veracrypt_pim_start       = VERACRYPT_PIM_START;
  user_options->veracrypt_pim_stop        = VERACRYPT_PIM_STOP;
  user_options->version                   = VERSION;
  user_options->wordlist_autohex          = WORDLIST_AUTOHEX;
  user_options->workload_profile          = WORKLOAD_PROFILE;
  user_options->rp_files_cnt              = 0;
  user_options->rp_files                  = (char **) hccalloc (256, sizeof (char *));
  user_options->hc_bin                    = PROGNAME;
  user_options->hc_argc                   = 0;
  user_options->hc_argv                   = NULL;

  return 0;
}

void user_options_destroy (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  hcfree (user_options->rp_files);

  hcfree (user_options->hc_argv_alias);

  hcfree (user_options->lookup_alias);

  if (user_options->backend_info > 0)
  {
    hcfree (user_options->opencl_device_types);
  }

  //do not reset this, it might be used from main.c
  //memset (user_options, 0, sizeof (user_options_t));
}

int user_options_getopt (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  int c = -1;

  int option_index;

  // Which arguments are options is hashcat's decision and not the environment's. getopt reorders the
  // command line so that an option is an option wherever it stands, and every example hashcat gives
  // relies on that: "hashcat -m 0 hash.txt wordlist -r rules/best64.rule" has an option after two
  // work arguments. POSIXLY_CORRECT turns the reordering off, and then everything from the first
  // work argument on is handed to the attack instead of being parsed, silently. "-a 8 --stdout feed
  // --limit 2" prints two candidates normally and runs to exhaustion with the variable set.
  //
  // It is removed rather than read, because getopt only asks whether the name exists and a value of
  // "0" or "" would still mean yes. This changes nothing outside hashcat's own process.

  #if defined (_WIN)
  _putenv_s ("POSIXLY_CORRECT", "");
  #else
  unsetenv ("POSIXLY_CORRECT");
  #endif

  optind = 1;
  optopt = 0;

  option_index = 0;

  while ((c = getopt_long (argc, argv, short_options, long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_REMOVE_TIMER:
      case IDX_DEBUG_MODE:
      case IDX_SKIP:
      case IDX_LIMIT:
      case IDX_STATUS_TIMER:
      case IDX_HASH_MODE:
      case IDX_RUNTIME:
      case IDX_METAL_COMPILER_RUNTIME:
      case IDX_ATTACK_MODE:
      case IDX_RP_GEN:
      case IDX_RP_GEN_FUNC_MIN:
      case IDX_RP_GEN_FUNC_MAX:
      case IDX_RP_GEN_SEED:
      case IDX_MARKOV_THRESHOLD:
      case IDX_OUTFILE_CHECK_TIMER:
      case IDX_BACKEND_VECTOR_WIDTH:
      case IDX_BYPASS_DELAY:
      case IDX_BYPASS_THRESHOLD:
      case IDX_WORKLOAD_PROFILE:
      case IDX_KERNEL_ACCEL:
      case IDX_KERNEL_LOOPS:
      case IDX_KERNEL_THREADS:
      case IDX_SPIN_DAMP:
      case IDX_HWMON_TEMP_ABORT:
      case IDX_HCCAPX_MESSAGE_PAIR:
      case IDX_NONCE_ERROR_CORRECTIONS:
      case IDX_VERACRYPT_PIM_START:
      case IDX_VERACRYPT_PIM_STOP:
      case IDX_SCRYPT_TMTO:
      case IDX_BITMAP_MIN:
      case IDX_BITMAP_MAX:
      case IDX_INCREMENT_MIN:
      case IDX_INCREMENT_MAX:
      case IDX_HOOK_THREADS:
      case IDX_BACKEND_DEVICES_VIRTMULTI:
      case IDX_BACKEND_DEVICES_VIRTHOST:
      case IDX_BENCHMARK_MAX:
      case IDX_BENCHMARK_MIN:
      #ifdef WITH_BRAIN
      case IDX_BRAIN_PORT:
      #endif

      if (hc_string_is_digit (optarg) == false)
      {
        event_log_error (hashcat_ctx, "The specified parameter cannot use '%s' as a value - must be a number.", optarg);

        return -1;
      }

      break;

      case '?':
      {
        event_log_error (hashcat_ctx, "Invalid argument specified.");

        return -1;
      }
    }
  }

  optind = 1;
  optopt = 0;

  option_index = 0;

  while ((c = getopt_long (argc, argv, short_options, long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_HELP:                      user_options->usage++;                                                     break;
      case IDX_VERSION:                   user_options->version                   = true;                            break;
      case IDX_RESTORE:                   user_options->restore                   = true;                            break;
      case IDX_RESTORE_POSITION:          user_options->restore_position          = true;                            break;
      case IDX_QUIET:                     user_options->quiet                     = true;                            break;
      case IDX_SHOW:                      user_options->show                      = true;                            break;
      case IDX_DEPRECATED_CHECK_DISABLE:  user_options->deprecated_check          = false;                           break;
      case IDX_LEFT:                      user_options->left                      = true;                            break;
      case IDX_ADVICE_DISABLE:            user_options->advice                    = false;                           break;
      case IDX_USERNAME:                  user_options->username                  = true;                            break;
      case IDX_DYNAMIC_X:                 user_options->dynamic_x                 = true;                            break;
      case IDX_REMOVE:                    user_options->remove                    = true;                            break;
      case IDX_REMOVE_TIMER:              user_options->remove_timer              = hc_strtoul (optarg, NULL, 10);
                                          user_options->remove_timer_chgd         = true;                            break;
      case IDX_POTFILE_DISABLE:           user_options->potfile                   = false;                           break;
      case IDX_POTFILE_PATH:              user_options->potfile_path              = optarg;                          break;
      case IDX_DEBUG_MODE:                user_options->debug_mode                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_DEBUG_FILE:                user_options->debug_file                = optarg;                          break;
      case IDX_ENCODING_FROM:             user_options->encoding_from             = optarg;                          break;
      case IDX_ENCODING_TO:               user_options->encoding_to               = optarg;                          break;
      case IDX_INDUCTION_DIR:             user_options->induction_dir             = optarg;                          break;
      case IDX_OUTFILE_CHECK_DIR:         user_options->outfile_check_dir         = optarg;                          break;
      case IDX_HASH_INFO:                 user_options->hash_info++;                                                 break;
      case IDX_FORCE:                     user_options->force                     = true;                            break;
      case IDX_SELF_TEST_DISABLE:         user_options->self_test                 = false;                           break;
      case IDX_SKIP:                      user_options->skip                      = hc_strtoull (optarg, NULL, 10);
                                          user_options->skip_chgd                 = true;                            break;
      case IDX_LIMIT:                     user_options->limit                     = hc_strtoull (optarg, NULL, 10);
                                          user_options->limit_chgd                = true;                            break;
      case IDX_KEEP_GUESSING:             user_options->keep_guessing             = true;                            break;
      case IDX_KEYSPACE:                  user_options->keyspace                  = true;                            break;
      case IDX_TOTAL_CANDIDATES:          user_options->total_candidates          = true;                            break;
      case IDX_BENCHMARK:                 user_options->benchmark                 = true;                            break;
      case IDX_BENCHMARK_ALL:             user_options->benchmark_all             = true;                            break;
      case IDX_BENCHMARK_MAX:             user_options->benchmark_max             = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BENCHMARK_MIN:             user_options->benchmark_min             = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_STDOUT_FLAG:               user_options->stdout_flag               = true;                            break;
      case IDX_STDIN_TIMEOUT_ABORT:       user_options->stdin_timeout_abort       = hc_strtoul (optarg, NULL, 10);
                                          user_options->stdin_timeout_abort_chgd  = true;                            break;
      case IDX_IDENTIFY:                  user_options->identify                  = true;                            break;
      case IDX_SPEED_ONLY:                user_options->speed_only                = true;                            break;
      case IDX_PROGRESS_ONLY:             user_options->progress_only             = true;                            break;
      case IDX_RESTORE_DISABLE:           user_options->restore_enable            = false;                           break;
      case IDX_RESTORE_FILE_PATH:         user_options->restore_file_path         = optarg;                          break;
      case IDX_SEEKDB_PATH:               user_options->seekdb_path               = optarg;                          break;
      case IDX_STATUS:                    user_options->status                    = true;                            break;
      case IDX_STATUS_JSON:               user_options->status_json               = true;                            break;
      case IDX_PIPELINE_STATS:            user_options->pipeline_stats            = true;                            break;
      case IDX_TASK_TIME_BREAKDOWN:       user_options->task_time_breakdown       = true;                            break;
      case IDX_STATUS_TIMER:              user_options->status_timer              = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_MACHINE_READABLE:          user_options->machine_readable          = true;                            break;
      case IDX_LOOKUP:                    user_options->lookup                    = optarg;                          break;
      case IDX_LOOPBACK:                  user_options->loopback                  = true;                            break;
      case IDX_SESSION:                   user_options->session                   = optarg;
                                          user_options->session_chgd              = true;                            break;
      case IDX_HASH_MODE:                 user_options->hash_mode                 = hc_strtoul (optarg, NULL, 10);
                                          user_options->hash_mode_chgd            = true;                            break;
      case IDX_RUNTIME:                   user_options->runtime                   = hc_strtoul (optarg, NULL, 10);
                                          user_options->runtime_chgd              = true;                            break;
      case IDX_METAL_COMPILER_RUNTIME:    user_options->metal_compiler_runtime    = hc_strtoul (optarg, NULL, 10);
                                          user_options->metal_compiler_runtime_chgd = true;                          break;
      case IDX_ATTACK_MODE:               user_options->attack_mode               = hc_strtoul (optarg, NULL, 10);
                                          user_options->attack_mode_chgd          = true;                            break;
      case IDX_RP_FILE:                   user_options->rp_files[user_options->rp_files_cnt++] = optarg;             break;
      case IDX_RP_GEN:                    user_options->rp_gen                    = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_FUNC_MIN:           user_options->rp_gen_func_min           = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_FUNC_MAX:           user_options->rp_gen_func_max           = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_FUNC_SEL:           user_options->rp_gen_func_sel           = optarg;                          break;
      case IDX_RP_GEN_SEED:               user_options->rp_gen_seed               = hc_strtoul (optarg, NULL, 10);
                                          user_options->rp_gen_seed_chgd          = true;                            break;
      case IDX_RULE_BUF_L:                user_options->rule_buf_l                = optarg;
                                          user_options->rule_buf_l_chgd           = true;                            break;
      case IDX_RULE_BUF_R:                user_options->rule_buf_r                = optarg;
                                          user_options->rule_buf_r_chgd           = true;                            break;
      case IDX_MARKOV_DISABLE:            user_options->markov                    = false;                           break;
      case IDX_MARKOV_CLASSIC:            user_options->markov_classic            = true;                            break;
      case IDX_MARKOV_INVERSE:            user_options->markov_inverse            = true;                            break;
      case IDX_MARKOV_THRESHOLD:          user_options->markov_threshold          = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_MARKOV_HCSTAT2:            user_options->markov_hcstat2            = optarg;                          break;
      case IDX_OUTFILE:                   user_options->outfile                   = optarg;
                                          user_options->outfile_chgd              = true;                            break;
      case IDX_OUTFILE_FORMAT:            user_options->outfile_format            = outfile_format_parse (optarg);
                                          user_options->outfile_format_chgd       = true;                            break;
      case IDX_OUTFILE_JSON:              user_options->outfile_json              = true;                            break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:   user_options->outfile_autohex           = false;                           break;
      case IDX_OUTFILE_CHECK_TIMER:       user_options->outfile_check_timer       = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_WORDLIST_AUTOHEX_DISABLE:  user_options->wordlist_autohex          = false;                           break;
      case IDX_HEX_CHARSET:               user_options->hex_charset               = true;                            break;
      case IDX_HEX_SALT:                  user_options->hex_salt                  = true;                            break;
      case IDX_HEX_WORDLIST:              user_options->hex_wordlist              = true;                            break;
      case IDX_BRIDGE_PARAMETER1:         user_options->bridge_parameter1         = optarg;                          break;
      case IDX_BRIDGE_PARAMETER2:         user_options->bridge_parameter2         = optarg;                          break;
      case IDX_BRIDGE_PARAMETER3:         user_options->bridge_parameter3         = optarg;                          break;
      case IDX_BRIDGE_PARAMETER4:         user_options->bridge_parameter4         = optarg;                          break;
      case IDX_CPU_AFFINITY:              user_options->cpu_affinity              = optarg;                          break;
      case IDX_BACKEND_IGNORE_CUDA:       user_options->backend_ignore_cuda       = true;                            break;
      case IDX_BACKEND_IGNORE_HIP:        user_options->backend_ignore_hip        = true;                            break;
      #if defined (__APPLE__)
      case IDX_BACKEND_IGNORE_METAL:      user_options->backend_ignore_metal      = true;                            break;
      #endif
      case IDX_BACKEND_IGNORE_OPENCL:     user_options->backend_ignore_opencl     = true;                            break;
      case IDX_BACKEND_INFO:              user_options->backend_info++;                                              break;
      case IDX_BACKEND_DEVICES:           user_options->backend_devices           = optarg;                          break;
      case IDX_BACKEND_DEVICES_VIRTMULTI: user_options->backend_devices_virtmulti = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BACKEND_DEVICES_VIRTHOST:  user_options->backend_devices_virthost  = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BACKEND_VECTOR_WIDTH:      user_options->backend_vector_width      = hc_strtoul (optarg, NULL, 10);
                                          user_options->backend_vector_width_chgd = true;                            break;
      case IDX_BYPASS_DELAY:              user_options->bypass_delay              = hc_strtoul (optarg, NULL, 10);
                                          user_options->bypass_delay_chgd         = true;                            break;
      case IDX_BYPASS_THRESHOLD:          user_options->bypass_threshold          = hc_strtoul (optarg, NULL, 10);
                                          user_options->bypass_threshold_chgd     = true;                            break;
      case IDX_OPENCL_DEVICE_TYPES:       user_options->opencl_device_types       = optarg;                          break;
      case IDX_OPTIMIZED_KERNEL_ENABLE:   user_options->optimized_kernel          = true;                            break;
      case IDX_MULTIPLY_ACCEL_DISABLE:    user_options->multiply_accel            = false;                           break;
      case IDX_WORKLOAD_PROFILE:          user_options->workload_profile          = hc_strtoul (optarg, NULL, 10);
                                          user_options->workload_profile_chgd     = true;                            break;
      case IDX_KERNEL_ACCEL:              user_options->kernel_accel              = hc_strtoul (optarg, NULL, 10);
                                          user_options->kernel_accel_chgd         = true;                            break;
      case IDX_KERNEL_LOOPS:              user_options->kernel_loops              = hc_strtoul (optarg, NULL, 10);
                                          user_options->kernel_loops_chgd         = true;                            break;
      case IDX_KERNEL_THREADS:            user_options->kernel_threads            = hc_strtoul (optarg, NULL, 10);
                                          user_options->kernel_threads_chgd       = true;                            break;
      case IDX_SPIN_DAMP:                 user_options->spin_damp                 = hc_strtoul (optarg, NULL, 10);
                                          user_options->spin_damp_chgd            = true;                            break;
      case IDX_HWMON_DISABLE:             user_options->hwmon                     = false;                           break;
      case IDX_HWMON_TEMP_ABORT:          user_options->hwmon_temp_abort          = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_LOGFILE_DISABLE:           user_options->logfile                   = false;                           break;
      case IDX_HCCAPX_MESSAGE_PAIR:       user_options->hccapx_message_pair       = hc_strtoul (optarg, NULL, 10);
                                          user_options->hccapx_message_pair_chgd  = true;                            break;
      case IDX_NONCE_ERROR_CORRECTIONS:   user_options->nonce_error_corrections   = hc_strtoul (optarg, NULL, 10);
                                          user_options->nonce_error_corrections_chgd = true;                         break;
      case IDX_KEYBOARD_LAYOUT_MAPPING:   user_options->keyboard_layout_mapping   = optarg;                          break;
      case IDX_TRUECRYPT_KEYFILES:        user_options->truecrypt_keyfiles        = optarg;                          break;
      case IDX_VERACRYPT_KEYFILES:        user_options->veracrypt_keyfiles        = optarg;                          break;
      case IDX_VERACRYPT_PIM_START:       user_options->veracrypt_pim_start       = hc_strtoul (optarg, NULL, 10);
                                          user_options->veracrypt_pim_start_chgd  = true;                            break;
      case IDX_VERACRYPT_PIM_STOP:        user_options->veracrypt_pim_stop        = hc_strtoul (optarg, NULL, 10);
                                          user_options->veracrypt_pim_stop_chgd   = true;                            break;
      case IDX_SCRYPT_TMTO:               user_options->scrypt_tmto               = hc_strtoul (optarg, NULL, 10);
                                          user_options->scrypt_tmto_chgd          = true;                            break;
      case IDX_SEPARATOR:                 user_options->separator                 = optarg;
                                          user_options->separator_chgd            = true;                            break;
      case IDX_BITMAP_MIN:                user_options->bitmap_min                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BITMAP_MAX:                user_options->bitmap_max                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_HOOK_THREADS:              user_options->hook_threads              = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_INCREMENT:                 user_options->increment++;                                                 break;
      case IDX_INCREMENT_INVERSE:         user_options->increment                 = INCREMENT_INVERSED;              break;
      case IDX_INCREMENT_MIN:             user_options->increment_min             = hc_strtoul (optarg, NULL, 10);
                                          user_options->increment_min_chgd        = true;                            break;
      case IDX_INCREMENT_MAX:             user_options->increment_max             = hc_strtoul (optarg, NULL, 10);
                                          user_options->increment_max_chgd        = true;                            break;
      case IDX_CUSTOM_CHARSET_1:          user_options->custom_charset_1          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_2:          user_options->custom_charset_2          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_3:          user_options->custom_charset_3          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_4:          user_options->custom_charset_4          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_5:          user_options->custom_charset_5          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_6:          user_options->custom_charset_6          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_7:          user_options->custom_charset_7          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_8:          user_options->custom_charset_8          = optarg;                          break;
      case IDX_SLOW_CANDIDATES:           user_options->slow_candidates           = true;                            break;
      #ifdef WITH_BRAIN
      case IDX_BRAIN_CLIENT:              user_options->brain_client              = true;                            break;
      case IDX_BRAIN_FEED:                user_options->brain_feed                = true;                            break;
      case IDX_BRAIN_CLIENT_FEATURES:     user_options->brain_client_features     = hc_strtoul (optarg, NULL, 10);
                                          user_options->brain_client_features_chgd = true;                           break;
      case IDX_BRAIN_SERVER:              user_options->brain_server              = true;                            break;
      case IDX_BRAIN_SERVER_TIMER:        user_options->brain_server_timer        = hc_strtoul (optarg, NULL, 10);
                                          user_options->brain_server_timer_chgd   = true;                            break;
      case IDX_BRAIN_PASSWORD:            user_options->brain_password            = optarg;
                                          user_options->brain_password_chgd       = true;                            break;
      case IDX_BRAIN_HOST:                user_options->brain_host                = optarg;
                                          user_options->brain_host_chgd           = true;                            break;
      case IDX_BRAIN_PORT:                user_options->brain_port                = hc_strtoul (optarg, NULL, 10);
                                          user_options->brain_port_chgd           = true;                            break;
      case IDX_BRAIN_SESSION:             user_options->brain_session             = hc_strtoul (optarg, NULL, 16);   break;
      case IDX_BRAIN_SESSION_WHITELIST:   user_options->brain_session_whitelist   = optarg;                          break;
      #endif
      case IDX_COLOR_CRACKED:             user_options->color_cracked             = true;                            break;
      case IDX_HASH_COPY:                 user_options->hash_copy                 = true;                            break;
      case IDX_ENCRYPT_WITH_PUBKEY:       user_options->encrypt_with_pubkey       = optarg;                          break;
    }
  }

  // The restore file records how far the run got, which is the same thing the status display
  // withholds under --encrypt-with-pubkey, so it is turned off the same way --restore-disable does
  // it. This has to happen here and not in user_options_preprocess, because restore_ctx_init runs
  // before preprocess and would already have set the file up.

  if (user_options->encrypt_with_pubkey != NULL)
  {
    user_options->restore_enable = false;
  }

  user_options->hc_bin = argv[0];

  user_options->hc_argc = argc - optind;
  user_options->hc_argv = argv + optind;

  return 0;
}

int user_options_sanity (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->hc_argc < 0)
  {
    event_log_error (hashcat_ctx, "hc_argc %d is invalid.", user_options->hc_argc);

    return -1;
  }

  if (user_options->hc_argv == NULL)
  {
    event_log_error (hashcat_ctx, "hc_argv is NULL.");

    return -1;
  }

  if (user_options->usage > 2)
  {
    event_log_error (hashcat_ctx, "Invalid --help/-h value, must have a value greater or equal to 0 and lower than 3.");

    return -1;
  }

  // --encrypt-with-pubkey exists so that a recovered password never appears in the clear on the
  // machine doing the cracking. The options below would each write it out in the clear somewhere
  // else, so combining them is refused rather than silently half-honoured.

  if (user_options->encrypt_with_pubkey != NULL)
  {
    if (user_options->loopback == true)
    {
      event_log_error (hashcat_ctx, "Mixing --encrypt-with-pubkey with --loopback is not allowed.");

      event_log_warning (hashcat_ctx, "The loopback file would receive the encrypted plains and feed them back as candidates.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    if (user_options->debug_file != NULL)
    {
      event_log_error (hashcat_ctx, "Mixing --encrypt-with-pubkey with --debug-file is not allowed.");

      event_log_warning (hashcat_ctx, "The debug file records the originating word in the clear.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    if (user_options->debug_mode > 0)
    {
      event_log_error (hashcat_ctx, "Mixing --encrypt-with-pubkey with --debug-mode is not allowed.");

      event_log_warning (hashcat_ctx, "The debug output records the originating word in the clear.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    // A protected run writes no restore file, so there is nothing to resume from. The restore file
    // is turned off in user_options_preprocess, which runs after this, so --restore has to be
    // refused on its own name here.

    if ((user_options->restore == true) || (user_options->restore_position == true))
    {
      event_log_error (hashcat_ctx, "Mixing --encrypt-with-pubkey with --restore is not allowed.");

      event_log_warning (hashcat_ctx, "A protected run writes no restore file, because it would record how far the run got.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }
  }

  #ifdef WITH_BRAIN
  // The feeder is a mode of its own: it reads stdin and exits, so it takes neither the client's nor
  // the server's other arguments. The session cannot be computed here because there is no hash list,
  // so it has to be given, and hashcat prints it on the status line of any brain run.

  if (user_options->brain_feed == true)
  {
    if (user_options->brain_client == true)
    {
      event_log_error (hashcat_ctx, "Combining --brain-feed with --brain-client is not allowed.");

      return -1;
    }

    if (user_options->brain_server == true)
    {
      event_log_error (hashcat_ctx, "Combining --brain-feed with --brain-server is not allowed.");

      return -1;
    }

    if (user_options->brain_password == NULL)
    {
      event_log_error (hashcat_ctx, "Using --brain-feed requires --brain-password.");

      return -1;
    }

    if (user_options->brain_session == 0)
    {
      event_log_error (hashcat_ctx, "Using --brain-feed requires --brain-session.");
      event_log_warning (hashcat_ctx, "The session says which brain database the candidates belong in. It is normally");
      event_log_warning (hashcat_ctx, "computed from the hash list, which a feeder does not have. Any brain run prints");
      event_log_warning (hashcat_ctx, "it on the status line as Brain Session/Attack.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }
  }

  if ((user_options->brain_client == true) && (user_options->brain_server == true))
  {
    event_log_error (hashcat_ctx, "Can not have --brain-client and --brain-server at the same time.");

    return -1;
  }

  if ((user_options->brain_client_features < 1) || (user_options->brain_client_features > 3))
  {
    event_log_error (hashcat_ctx, "Invalid --brain-client-feature argument.");

    return -1;
  }

  if (user_options->brain_port > 65535)
  {
    event_log_error (hashcat_ctx, "Invalid brain port specified (greater than 65535).");

    return -1;
  }

  if ((user_options->brain_client == true) && (user_options->brain_password_chgd == false))
  {
    event_log_error (hashcat_ctx, "Brain clients must specify --brain-password.");

    return -1;
  }

  if (user_options->brain_server_timer_chgd)
  {
    if (user_options->brain_server == false)
    {
      event_log_error (hashcat_ctx, "The --brain-server-timer flag requires --brain-server.");

      return -1;
    }

    if (user_options->brain_server_timer != 0) // special case (no intermediate dumps)
    {
      if (user_options->brain_server_timer < 60)
      {
        event_log_error (hashcat_ctx, "Brain server backup timer must be at least 60 seconds.");

        return -1;
      }
    }
  }
  #endif

  if (user_options->separator_chgd == true)
  {
    bool error = false;

    if ((strlen (user_options->separator) != 1) && (strlen (user_options->separator) != 4))
    {
        error = true;
    }

    if (strlen (user_options->separator) == 4)
    {
      if ((user_options->separator[0] == '0') && (user_options->separator[1] == 'x'))
      {
        if (is_valid_hex_string ((u8 *) (&(user_options->separator[2])), 2))
        {
          u8 sep = hex_to_u8 ((u8 *) (&(user_options->separator[2])));

          user_options->separator[0] = sep;
          user_options->separator[1] = 0;
        }
        else
        {
          error = true;
        }
      }
      else
      {
        error = true;
      }
    }

    if (error)
    {
      event_log_error (hashcat_ctx, "Separator length has to be exactly 1 byte (single char or hex format e.g. 0x09 for TAB)");

      return -1;
    }
  }

  if (user_options->slow_candidates == true)
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT)
     && (user_options->attack_mode != ATTACK_MODE_COMBI)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID2)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID)
     && (user_options->attack_mode != ATTACK_MODE_BF)
     && (user_options->attack_mode != ATTACK_MODE_PCFG)
     && (user_options->attack_mode != ATTACK_MODE_GENERIC))
    {
      event_log_error (hashcat_ctx, "Invalid attack mode (-a) value specified in slow-candidates mode.");

      return -1;
    }
  }
  #ifdef WITH_BRAIN
  else if (user_options->brain_client == true)
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT)
     && (user_options->attack_mode != ATTACK_MODE_COMBI)
     && (user_options->attack_mode != ATTACK_MODE_BF)
     && (user_options->attack_mode != ATTACK_MODE_PCFG)
     && (user_options->attack_mode != ATTACK_MODE_GENERIC))
    {
      event_log_error (hashcat_ctx, "Invalid attack mode (-a) value specified in brain-client mode.");

      return -1;
    }
  }
  #endif
  else
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT)
     && (user_options->attack_mode != ATTACK_MODE_COMBI)
     && (user_options->attack_mode != ATTACK_MODE_BF)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID2)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID)
     && (user_options->attack_mode != ATTACK_MODE_PCFG)
     && (user_options->attack_mode != ATTACK_MODE_GENERIC)
     && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION)
     && (user_options->attack_mode != ATTACK_MODE_NONE))
    {
      event_log_error (hashcat_ctx, "Invalid attack mode (-a) value specified.");

      return -1;
    }
  }

  if (user_options->hccapx_message_pair_chgd == true)
  {
    if (user_options->remove == true)
    {
      event_log_error (hashcat_ctx, "Combining --remove with --hccapx-message-pair is not allowed.");

      return -1;
    }

    if (user_options->hccapx_message_pair >= 6)
    {
      event_log_error (hashcat_ctx, "Invalid --hccapx-message-pair value specified.");

      return -1;
    }
  }

  /*
  if (user_options->skip_chgd == true && user_options->skip == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --skip value specified.");

    return -1;
  }
  */

  if (user_options->limit_chgd == true && user_options->limit == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --limit value specified.");

    return -1;
  }

  if (user_options->runtime_chgd == true && user_options->runtime == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --runtime value specified.");

    return -1;
  }

  // --metal-compiler-runtime is really used only on Apple

  if (user_options->metal_compiler_runtime_chgd == true && user_options->metal_compiler_runtime == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --metal-compiler-runtime value specified (must be > 0).");

    return -1;
  }

  if (user_options->limit_chgd == true && user_options->loopback == true)
  {
    event_log_error (hashcat_ctx, "Combining --limit with --loopback is not allowed.");

    return -1;
  }

  if (user_options->hash_mode >= MODULE_HASH_MODES_MAXIMUM)
  {
    event_log_error (hashcat_ctx, "Invalid -m (hash type) value specified.");

    return -1;
  }

  if (user_options->backend_devices_virtmulti == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --backend-devices-virtmulti value specified.");

    return -1;
  }

  if (user_options->backend_devices_virthost == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --backend-devices-virthost value specified.");

    return -1;
  }


  if (user_options->outfile_format == 0)
  {
    event_log_error (hashcat_ctx, "Invalid --outfile-format value specified.");

    return -1;
  }

  if (user_options->left == true)
  {
    if (user_options->outfile_format_chgd == true)
    {
      if (user_options->outfile_format > 1)
      {
        event_log_error (hashcat_ctx, "Combining --outfile-format > 1 with --left is not allowed.");

        return -1;
      }
    }
  }

  if (user_options->show == true)
  {
    if (user_options->outfile_format_chgd == true)
    {
      if (user_options->outfile_format & OUTFILE_FMT_CRACKPOS)
      {
        event_log_error (hashcat_ctx, "Using crack_pos in --outfile-format for --show is not allowed.");

        return -1;
      }

      if (user_options->outfile_format & OUTFILE_FMT_TIME_ABS)
      {
        event_log_error (hashcat_ctx, "Using the absolute timestamp in --outfile-format for --show is not allowed.");

        return -1;
      }

      if (user_options->outfile_format & OUTFILE_FMT_TIME_REL)
      {
        event_log_error (hashcat_ctx, "Using the relative timestamp in --outfile-format for --show is not allowed.");

        return -1;
      }
    }
  }

  if (user_options->increment_min < INCREMENT_MIN)
  {
    event_log_error (hashcat_ctx, "Invalid --increment-min value specified.");

    return -1;
  }

  if (user_options->increment_max > INCREMENT_MAX)
  {
    event_log_error (hashcat_ctx, "Invalid --increment-max value specified.");

    return -1;
  }

  if ((user_options->veracrypt_pim_start_chgd == true) && (user_options->veracrypt_pim_stop_chgd == false))
  {
    event_log_error (hashcat_ctx, "The--veracrypt-pim-start option requires --veracrypt-pim-stop as well.");

    return -1;
  }

  if ((user_options->veracrypt_pim_start_chgd == false) && (user_options->veracrypt_pim_stop_chgd == true))
  {
    event_log_error (hashcat_ctx, "The --veracrypt-pim-stop option requires --veracrypt-pim-start as well.");

    return -1;
  }

  if (user_options->veracrypt_pim_start > user_options->veracrypt_pim_stop)
  {
    event_log_error (hashcat_ctx, "Invalid --veracrypt-pim-start value specified.");

    return -1;
  }

  if (user_options->increment_min > user_options->increment_max)
  {
    event_log_error (hashcat_ctx, "Invalid --increment-min value specified - must be >= --increment-max.");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->progress_only == true))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in combination with --progress-only.");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->speed_only == true))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in combination with --speed-only.");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->attack_mode == ATTACK_MODE_STRAIGHT))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in attack mode 0 (straight).");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->attack_mode == ATTACK_MODE_PCFG))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in attack mode 4 (pcfg).");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->attack_mode == ATTACK_MODE_GENERIC))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in attack mode 8 (generic).");

    return -1;
  }

  if ((user_options->increment != INCREMENT_NONE) && (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in attack mode 9 (association).");

    return -1;
  }

  if ((user_options->remove == true) && (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    event_log_error (hashcat_ctx, "Remove is not allowed in attack mode 9 (association).");

    return -1;
  }

  if ((user_options->increment == INCREMENT_NONE) && (user_options->increment_min_chgd == true))
  {
    event_log_error (hashcat_ctx, "Increment-min is only supported when combined with -i/--increment.");

    return -1;
  }

  if ((user_options->increment == INCREMENT_NONE) && (user_options->increment_max_chgd == true))
  {
    event_log_error (hashcat_ctx, "Increment-max is only supported combined with -i/--increment.");

    return -1;
  }

  // In case the user uses -iii, escaping enum bounds
  if (user_options->increment > INCREMENT_INVERSED)
  {
    event_log_error (hashcat_ctx, "Invalid -i/--increment value.");

    return -1;
  }

  // Incrementing cuts the mask down to its first N positions, which throws the ?w away for every
  // length shorter than the position it sits at. There is no obvious right answer to what a shorter
  // mask should do with a marker that is not a charset, so it is refused rather than guessed at.

  if ((user_options->increment != INCREMENT_NONE) && (user_options->attack_mode == ATTACK_MODE_HYBRID))
  {
    event_log_error (hashcat_ctx, "Attack-mode 12 does not support -i/--increment. The ?w marker has a fixed position in the mask, and a shorter mask has nowhere to put it.");

    return -1;
  }

  if ((user_options->rp_files_cnt > 0) && (user_options->rp_gen > 0))
  {
    event_log_error (hashcat_ctx, "Combining -r/--rules-file and -g/--rules-generate is not supported.");

    return -1;
  }

  if ((user_options->rp_files_cnt > 0) || (user_options->rp_gen > 0))
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT) && (user_options->attack_mode != ATTACK_MODE_PCFG) && (user_options->attack_mode != ATTACK_MODE_GENERIC) && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION))
    {
      event_log_error (hashcat_ctx, "Use of -r/--rules-file and -g/--rules-generate requires attack mode 0, 4, 8 or 9.");

      return -1;
    }
  }

  if (user_options->bitmap_min > user_options->bitmap_max)
  {
    event_log_error (hashcat_ctx, "Invalid --bitmap-min value specified.");

    return -1;
  }

  if (user_options->bitmap_max > 28)
  {
    event_log_error (hashcat_ctx, "Invalid --bitmap-max value specified - must not be higher than 28.");

    return -1;
  }

  if (user_options->rp_gen_func_min > user_options->rp_gen_func_max)
  {
    event_log_error (hashcat_ctx, "Invalid --rp-gen-func-min value specified.");

    return -1;
  }

  if (user_options->kernel_accel_chgd == true)
  {
    if (user_options->force == false)
    {
      event_log_error (hashcat_ctx, "The manual use of the -n option (or --kernel-accel) is outdated.");

      event_log_warning (hashcat_ctx, "Please consider using the -w option instead.");
      event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    if (user_options->kernel_accel < 1)
    {
      event_log_error (hashcat_ctx, "Invalid --kernel-accel value specified - must be greater than 0.");

      return -1;
    }

    // This runs long before hashconfig_init, so whether the selected mode is an assimilation bridge
    // is not knowable yet. Only the looser of the two ceilings can be applied here. The tighter
    // KERNEL_ACCEL_MAX is enforced in backend.c for a non-bridge mode, where the mode IS known.
    //
    // A non-bridge mode still refuses exactly the values it refused before, with the same message and
    // the same exit. What did change is WHEN: the refusal now comes during backend startup rather
    // than during argument parsing, so devices are enumerated first. That is the price of the mode
    // not being known here, and it is only paid on a command line that was going to be rejected.

    if (user_options->kernel_accel > KERNEL_ACCEL_MAX_BRIDGE)
    {
      event_log_error (hashcat_ctx, "Invalid --kernel-accel value specified - must be <= %d.", KERNEL_ACCEL_MAX_BRIDGE);

      return -1;
    }
  }

  if (user_options->kernel_loops_chgd == true)
  {
    if (user_options->force == false)
    {
      event_log_error (hashcat_ctx, "The manual use of the -u option (or --kernel-loops) is outdated.");

      event_log_warning (hashcat_ctx, "Please consider using the -w option instead.");
      event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    if (user_options->kernel_loops < 1)
    {
      event_log_error (hashcat_ctx, "Invalid kernel-loops specified.");

      return -1;
    }

    // no upper bound is checked here. KERNEL_LOOPS_MAX is only the default ceiling, and a module
    // is free to raise its own through module_kernel_loops_max. Several do, up to 131072. This
    // runs before hashconfig_init, so the real ceiling is not known yet. backend_session_begin
    // holds the value against the module's range and warns if it has to drop it.
  }

  if (user_options->kernel_threads_chgd == true)
  {
    if (user_options->force == false)
    {
      event_log_error (hashcat_ctx, "The manual use of the -T option (or --kernel-threads) is outdated.");

      event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    if (user_options->kernel_threads < 1)
    {
      event_log_error (hashcat_ctx, "Invalid kernel-threads specified.");

      return -1;
    }

    if (user_options->kernel_threads > 1024)
    {
      event_log_error (hashcat_ctx, "Invalid kernel-threads specified.");

      return -1;
    }
  }

  if ((user_options->workload_profile < 1) || (user_options->workload_profile > 4))
  {
    event_log_error (hashcat_ctx, "workload-profile %u is not available.", user_options->workload_profile);

    return -1;
  }

  if (user_options->backend_vector_width_chgd == true)
  {
    if (is_power_of_2 (user_options->backend_vector_width) == false || user_options->backend_vector_width > 16)
    {
      event_log_error (hashcat_ctx, "backend-vector-width %u is not allowed.", user_options->backend_vector_width);

      return -1;
    }
  }

  if (user_options->stdout_flag == true && user_options->slow_candidates == true)
  {
    event_log_error (hashcat_ctx, "Slow candidates (-S) is not allowed in stdout mode.");

    return -1;
  }

  if (user_options->show == true && (user_options->restore == true || user_options->restore_position == true))
  {
    event_log_error (hashcat_ctx, "Mixing --show and --restore is not allowed.");

    return -1;
  }

  if (user_options->show == true || user_options->left == true)
  {
    if (user_options->remove == true)
    {
      event_log_error (hashcat_ctx, "Mixing --remove not allowed with --show or --left.");

      return -1;
    }

    if (user_options->potfile == false)
    {
      event_log_error (hashcat_ctx, "Mixing --potfile-disable is not allowed with --show or --left.");

      return -1;
    }
  }

  if (user_options->show == true)
  {
    if (user_options->outfile_autohex == false)
    {
      event_log_error (hashcat_ctx, "Mixing --outfile-autohex-disable is not allowed with --show.");

      return -1;
    }

    if (user_options->outfile_json == true)
    {
      event_log_error (hashcat_ctx, "Mixing --outfile-json is not allowed with --show.");

      return -1;
    }
  }

  if (user_options->keyspace == true)
  {
    if (user_options->show == true)
    {
      event_log_error (hashcat_ctx, "Combining --show with --keyspace is not allowed.");

      return -1;
    }

   if (user_options->left == true)
    {
      event_log_error (hashcat_ctx, "Combining --left with --keyspace is not allowed.");

      return -1;
    }

    // An association attack has no keyspace of its own. It pairs one candidate with each hash, so what
    // it would count is a property of the hash file, and --keyspace never reads a hash file: every
    // argument it is given is work. Without this the hash file is opened as a wordlist and the run ends
    // on a line count that does not match a salt count of one, which reads like a broken hash file.

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      event_log_error (hashcat_ctx, "Combining -a 9 with --keyspace is not allowed.");

      event_log_warning (hashcat_ctx, "An association attack takes its keyspace from the hash file, which --keyspace does not read.");

      return -1;
    }
  }

  // --lookup asks where a run reaches one candidate and answers from the tables that run would
  // enumerate, so it sizes every round exactly as --keyspace does and then reports instead of
  // summing. It is refused everywhere --keyspace is, on its own name, because it only turns into
  // --keyspace in user_options_preprocess and that runs after this.

  if (user_options->lookup != NULL)
  {
    if (strlen (user_options->lookup) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --lookup value - must not be empty.");

      return -1;
    }

    // A candidate is bytes, and a ?b mask reaches bytes no shell can pass. $HEX[...] is the spelling
    // the potfile and --show already use for exactly that, so it is accepted here as well and the
    // length that has to fit a mask is the decoded one.

    if (is_hexify ((const u8 *) user_options->lookup, strlen (user_options->lookup)) == false)
    {
      if (strlen (user_options->lookup) > PW_MAX)
      {
        event_log_error (hashcat_ctx, "Invalid --lookup value - must not be longer than %d characters.", PW_MAX);

        return -1;
      }
    }
    else
    {
      if (((strlen (user_options->lookup) - 6) / 2) > PW_MAX)
      {
        event_log_error (hashcat_ctx, "Invalid --lookup value - must not decode to more than %d bytes.", PW_MAX);

        return -1;
      }
    }

    if (user_options->show == true)
    {
      event_log_error (hashcat_ctx, "Combining --show with --lookup is not allowed.");

      return -1;
    }

    if (user_options->left == true)
    {
      event_log_error (hashcat_ctx, "Combining --left with --lookup is not allowed.");

      return -1;
    }

    if (user_options->keyspace == true)
    {
      event_log_error (hashcat_ctx, "Combining --keyspace with --lookup is not allowed.");

      return -1;
    }

    if (user_options->total_candidates == true)
    {
      event_log_error (hashcat_ctx, "Combining --total-candidates with --lookup is not allowed.");

      return -1;
    }

    if (user_options->stdout_flag == true)
    {
      event_log_error (hashcat_ctx, "Combining --stdout with --lookup is not allowed.");

      return -1;
    }

    if (user_options->benchmark == true)
    {
      event_log_error (hashcat_ctx, "Combining --benchmark with --lookup is not allowed.");

      return -1;
    }

    if (user_options->speed_only == true)
    {
      event_log_error (hashcat_ctx, "Combining --speed-only with --lookup is not allowed.");

      return -1;
    }

    if (user_options->progress_only == true)
    {
      event_log_error (hashcat_ctx, "Combining --progress-only with --lookup is not allowed.");

      return -1;
    }

    // -a 4 answers this question already, from tables only its feed has, so --lookup is carried to it
    // as the setting it already understands rather than reimplemented beside it. That happens in
    // user_options_alias_attack_mode (), which is where -a 4's command line is rewritten anyway.
    //
    // Every other mode is refused, and refused for a reason worth stating: not because there is
    // nowhere to hang the answer, but because nothing has been written that can invert it yet. A run
    // that quietly answered nothing would be worse than one that says so.

    if ((user_options->attack_mode != ATTACK_MODE_BF)
     && (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
     && (user_options->attack_mode != ATTACK_MODE_COMBI)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID2)
     && (user_options->attack_mode != ATTACK_MODE_HYBRID)
     && (user_options->attack_mode != ATTACK_MODE_PCFG))
    {
      event_log_error (hashcat_ctx, "--lookup is supported in attack-modes 0, 1, 3, 4, 6, 7 and 12 only.");

      event_log_warning (hashcat_ctx, "The other attack modes have no inversion yet, so there is no offset to give rather than a wrong one.");

      return -1;
    }

    // A restored session is handed its command line by the restore file and its position in the
    // queue by the restore data, and --lookup reads neither: it walks the queue from the front to
    // number it. Left alone the two produce an answer against the default mask rather than against
    // the attack that was restored, which is a wrong answer rather than an error.

    if ((user_options->restore == true) || (user_options->restore_position == true))
    {
      event_log_error (hashcat_ctx, "Combining --restore with --lookup is not allowed.");

      event_log_warning (hashcat_ctx, "Give --lookup the command line of the run instead. It answers about the attack, not about how far a session got.");

      return -1;
    }

    // The most natural command line for this option is the run the user has just done with --lookup
    // added to it, and that one has a hash file in front of the mask. It cannot be taken. --lookup
    // reads no hashes, exactly as --keyspace reads none, so every argument is work and a hash file
    // would be opened as the mask. Saying that beats the usage banner the argument count check at
    // the end of this function would otherwise print.

    // Only the two modes whose command line is one work argument are checked here. The rest take two
    // or three, and the count table at the end of this function is what knows which.

    if ((user_options->attack_mode == ATTACK_MODE_BF) || (user_options->attack_mode == ATTACK_MODE_STRAIGHT))
    {
      const char *want = (user_options->attack_mode == ATTACK_MODE_BF) ? "mask" : "wordlist";

      if (user_options->hc_argc > 1)
      {
        event_log_error (hashcat_ctx, "--lookup takes the %s on its own, with no hash file, exactly as --keyspace does.", want);

        event_log_warning (hashcat_ctx, "It answers about the attack and reads no hashes, so the hash file would be read as the %s.", want);

        return -1;
      }

      if (user_options->hc_argc == 0)
      {
        event_log_error (hashcat_ctx, "--lookup needs a %s to look in.", want);

        return -1;
      }
    }
  }

  if (user_options->total_candidates == true)
  {
    if (user_options->show == true)
    {
      event_log_error (hashcat_ctx, "Combining --show with --total-candidates is not allowed.");

      return -1;
    }

   if (user_options->left == true)
    {
      event_log_error (hashcat_ctx, "Combining --left with --total-candidates is not allowed.");

      return -1;
    }

    // Same reason as the --keyspace case above. --total-candidates turns into --keyspace in
    // user_options_preprocess, which runs after this, so it has to be refused on its own name here.

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      event_log_error (hashcat_ctx, "Combining -a 9 with --total-candidates is not allowed.");

      event_log_warning (hashcat_ctx, "An association attack takes its keyspace from the hash file, which --total-candidates does not read.");

      return -1;
    }
  }

  if (user_options->machine_readable == true)
  {
    if (user_options->status_json == true)
    {
      event_log_error (hashcat_ctx, "The --status-json flag can not be used with --machine-readable.");

      return -1;
    }
  }

  if (user_options->remove_timer_chgd == true)
  {
    if (user_options->remove == false)
    {
      event_log_error (hashcat_ctx, "The --remove-timer flag requires --remove.");

      return -1;
    }

    if (user_options->remove_timer < 1)
    {
      event_log_error (hashcat_ctx, "The --remove-timer parameter must have a value greater than or equal to 1.");

      return -1;
    }
  }

  if (user_options->loopback == true)
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
      {
        event_log_error (hashcat_ctx, "Parameter --loopback requires either -r/--rules-file or -g/--rules-generate.");

        return -1;
      }
    }
    else
    {
      event_log_error (hashcat_ctx, "Parameter --loopback is only allowed in attack mode 0 (straight).");

      return -1;
    }
  }

  if (user_options->debug_mode > 0)
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT) && (user_options->attack_mode != ATTACK_MODE_PCFG) && (user_options->attack_mode != ATTACK_MODE_GENERIC) && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION))
    {
      event_log_error (hashcat_ctx, "Parameter --debug-mode option is only allowed in attack mode 0 (straight), 4 (pcfg), 8 (generic) or 9 (association).");

      return -1;
    }

    if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
    {
      event_log_error (hashcat_ctx, "Use of --debug-mode requires -r/--rules-file or -g/--rules-generate.");

      return -1;
    }
  }

  if (user_options->debug_mode > 5)
  {
    event_log_error (hashcat_ctx, "Invalid --debug-mode value specified.");

    return -1;
  }

  if (user_options->induction_dir != NULL)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      event_log_error (hashcat_ctx, "Use of --induction-dir is not allowed in attack mode 3 (brute-force).");

      return -1;
    }

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      event_log_error (hashcat_ctx, "Use of --induction-dir is not allowed in attack mode 9 (association).");

      return -1;
    }
  }

  if (user_options->spin_damp > 100)
  {
    event_log_error (hashcat_ctx, "Values of --spin-damp must be between 0 and 100 (inclusive).");

    return -1;
  }

  if (user_options->identify == true)
  {
    if (user_options->hash_mode_chgd == true)
    {
      event_log_error (hashcat_ctx, "Can't change --hash-type (-m) in identify mode.");

      return -1;
    }
  }

  if (user_options->benchmark_all == true)
  {
    user_options->benchmark = true;
  }

  if (user_options->benchmark == true)
  {
    // sanity checks based on automatically overwritten configuration variables by
    // benchmark mode section in user_options_preprocess()

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      event_log_error (hashcat_ctx, "Brain client (-z) is not allowed in benchmark mode.");

      return -1;
    }

    if (user_options->brain_server == true)
    {
      event_log_error (hashcat_ctx, "Brain server is not allowed in benchmark mode.");

      return -1;
    }
    #endif

    if (user_options->benchmark_max > BENCHMARK_MAX)
    {
      event_log_error (hashcat_ctx, "Invalid --benchmark-max value specified (cannot be greater than 99999).");

      return -1;
    }

    if (user_options->benchmark_max < user_options->benchmark_min)
    {
      event_log_error (hashcat_ctx, "Invalid --benchmark-min/max values specified (max cannot be lower than min).");

      return -1;
    }

    if (user_options->benchmark_min != BENCHMARK_MIN || user_options->benchmark_max != BENCHMARK_MAX)
    {
      // forces benchmark-all to be enabled if benchmark-min and benchmark_max are also set
      user_options->benchmark_all = true;
    }

    if (user_options->attack_mode_chgd == true)
    {
      event_log_error (hashcat_ctx, "Can't change --attack-mode (-a) in benchmark mode.");

      return -1;
    }

    if (user_options->bitmap_min != BITMAP_MIN)
    {
      event_log_error (hashcat_ctx, "Can't change --bitmap-min in benchmark mode.");

      return -1;
    }

    if (user_options->bitmap_max != BITMAP_MAX)
    {
      event_log_error (hashcat_ctx, "Can't change --bitmap-max in benchmark mode.");

      return -1;
    }

    if (user_options->hwmon_temp_abort != HWMON_TEMP_ABORT)
    {
      event_log_error (hashcat_ctx, "Can't change --hwmon-temp-abort in benchmark mode.");

      return -1;
    }

    if (user_options->left == true)
    {
      event_log_error (hashcat_ctx, "Can't change --left in benchmark mode.");

      return -1;
    }

    if (user_options->show == true)
    {
      event_log_error (hashcat_ctx, "Can't change --show in benchmark mode.");

      return -1;
    }

    if (user_options->speed_only == true)
    {
      event_log_error (hashcat_ctx, "Can't change --speed-only in benchmark mode.");

      return -1;
    }

    if (user_options->progress_only == true)
    {
      event_log_error (hashcat_ctx, "Can't change --progress-only in benchmark mode.");

      return -1;
    }

    if (user_options->slow_candidates == true)
    {
      event_log_error (hashcat_ctx, "Use of --slow-candidates (-S) is not allowed in benchmark mode.");

      return -1;
    }

    if (user_options->hash_info > 0)
    {
      event_log_error (hashcat_ctx, "Use of --hash-info is not allowed in benchmark mode.");

      return -1;
    }

    if (user_options->increment == INCREMENT_NORMAL)
    {
      event_log_error (hashcat_ctx, "Can't change --increment (-i) in benchmark mode.");

      return -1;
    }

    if (user_options->increment == INCREMENT_INVERSED)
    {
      event_log_error (hashcat_ctx, "Can't change --increment-inverse in benchmark mode.");

      return -1;
    }

    if (user_options->restore == true)
    {
      event_log_error (hashcat_ctx, "Can't change --restore in benchmark mode.");

      return -1;
    }

    if (user_options->status == true)
    {
      event_log_error (hashcat_ctx, "Can't change --status in benchmark mode.");

      return -1;
    }

    if (user_options->backend_info > 0)
    {
      event_log_error (hashcat_ctx, "Use of --backend-info is not allowed in benchmark mode.");

      return -1;
    }

    if (user_options->spin_damp_chgd == true)
    {
      event_log_error (hashcat_ctx, "Can't change --spin-damp in benchmark mode.");

      return -1;
    }

    if ((user_options->custom_charset_1 != NULL)
     || (user_options->custom_charset_2 != NULL)
     || (user_options->custom_charset_3 != NULL)
     || (user_options->custom_charset_4 != NULL)
     || (user_options->custom_charset_5 != NULL)
     || (user_options->custom_charset_6 != NULL)
     || (user_options->custom_charset_7 != NULL)
     || (user_options->custom_charset_8 != NULL))
    {
      if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
      {
        event_log_error (hashcat_ctx, "Custom charsets are not supported in benchmark mode.");

        return -1;
      }
    }
  }

  if (user_options->markov_hcstat2 != NULL)
  {
    if (strlen (user_options->markov_hcstat2) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --markov-hcstat2 value - must not be empty.");

      return -1;
    }
  }

  if (user_options->markov_threshold != 0) // is 0 by default
  {
    if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_COMBI) || (user_options->attack_mode == ATTACK_MODE_PCFG) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
    {
      event_log_error (hashcat_ctx, "Option --markov-threshold is not allowed in combination with --attack mode %d", user_options->attack_mode);

      return -1;
    }
  }

  // --restore prints the command line the restore file holds and stops. --restore-position is what
  // that printed command line carries, and it takes only the position out of the file. The two are
  // the two halves of one resume and cannot be given together.

  if ((user_options->restore == true) && (user_options->restore_position == true))
  {
    event_log_error (hashcat_ctx, "Mixing --restore and --restore-position is not allowed.");

    event_log_warning (hashcat_ctx, "--restore prints the command line to run. --restore-position belongs to that printed command line.");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  if (user_options->restore_file_path != NULL)
  {
    if (strlen (user_options->restore_file_path) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --restore-file-path value - must not be empty.");

      return -1;
    }
  }

  if (user_options->seekdb_path != NULL)
  {
    if (strlen (user_options->seekdb_path) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --seekdb-path value - must not be empty.");

      return -1;
    }

    // A directory that is not there is worth stopping for, because the alternative is a run that
    // quietly rebuilds its seek database every time and never says why. Not being able to write to
    // one is fine and deliberately not checked: a read only share is a normal way to use this.

    if (hc_path_is_directory (user_options->seekdb_path) == false)
    {
      event_log_error (hashcat_ctx, "Invalid --seekdb-path value - must be an existing directory.");

      return -1;
    }
  }

  if (user_options->outfile != NULL)
  {
    if (strlen (user_options->outfile) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --outfile value - must not be empty.");

      return -1;
    }
  }

  if (user_options->debug_file != NULL)
  {
    if (strlen (user_options->debug_file) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --debug-file value - must not be empty.");

      return -1;
    }
  }

  if (user_options->session != NULL)
  {
    if (strlen (user_options->session) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --session value - must not be empty.");

      return -1;
    }
  }

  #if defined (_WIN)
  char invalid_characters[] = "/<>:\"\\|?*";
  #else
  char invalid_characters[] = "/";
  #endif

  for (size_t i = 0; strlen (user_options->session) > i; i++)
  {
    if (strchr (invalid_characters, user_options->session[i]) != NULL)
    {
      event_log_error (hashcat_ctx, "Invalid --session value - must not contain invalid characters.");

      return -1;
    }
  }

  if (user_options->cpu_affinity != NULL)
  {
    if (strlen (user_options->cpu_affinity) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --cpu-affinity value - must not be empty.");

      return -1;
    }
  }

  if (user_options->backend_devices != NULL)
  {
    if (strlen (user_options->backend_devices) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --backend-devices value - must not be empty.");

      return -1;
    }
  }

  if (user_options->opencl_device_types != NULL)
  {
    if (strlen (user_options->opencl_device_types) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --opencl-device-types value - must not be empty.");

      return -1;
    }
  }

  if (user_options->stdin_timeout_abort_chgd == true)
  {
    if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
    {
      event_log_error (hashcat_ctx, "Use of --stdin-timeout-abort is only allowed in attack mode 0 (straight).");

      return -1;
    }

    // --stdin-timeout-abort can only be used in stdin mode

    int hc_argc_expected = 1; // our hash file (note: hc_argc only counts hash files and dicts)

    if (user_options->stdout_flag == true) hc_argc_expected = 0; // special case: no hash file

    if (user_options->hc_argc != hc_argc_expected)
    {
      event_log_error (hashcat_ctx, "Use of --stdin-timeout-abort is only allowed in stdin mode (pipe).");

      return -1;
    }
  }

  if (user_options->backend_info > 2)
  {
    event_log_error (hashcat_ctx, "Invalid --backend-info/-I value, must have a value greater or equal to 0 and lower than 3.");

    return -1;
  }

  if (user_options->hash_info > 2)
  {
    event_log_error (hashcat_ctx, "Invalid --hash-info/-H value, must have a value greater or equal to 0 and lower than 3.");

    return -1;
  }

  #ifdef WITH_BRAIN
  if ((user_options->brain_client == true) && (user_options->remove == true))
  {
    event_log_error (hashcat_ctx, "Using --remove is not allowed if --brain-client is used.");

    return -1;
  }

  if ((user_options->brain_client == true) && (user_options->potfile == false))
  {
    event_log_error (hashcat_ctx, "Using --potfile-disable is not allowed if --brain-client is used.");

    return -1;
  }
  #endif

  // custom charset checks

  if ((user_options->custom_charset_1 != NULL)
   || (user_options->custom_charset_2 != NULL)
   || (user_options->custom_charset_3 != NULL)
   || (user_options->custom_charset_4 != NULL)
   || (user_options->custom_charset_5 != NULL)
   || (user_options->custom_charset_6 != NULL)
   || (user_options->custom_charset_7 != NULL)
   || (user_options->custom_charset_8 != NULL))
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      event_log_error (hashcat_ctx, "Custom charsets are not supported in attack mode 0 (straight).");

      return -1;
    }

    if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      event_log_error (hashcat_ctx, "Custom charsets are not supported in attack mode 1 (combination).");

      return -1;
    }

    if (user_options->attack_mode == ATTACK_MODE_PCFG)
    {
      event_log_error (hashcat_ctx, "Custom charsets are not supported in attack mode 4 (pcfg).");

      return -1;
    }

    if (user_options->attack_mode == ATTACK_MODE_GENERIC)
    {
      event_log_error (hashcat_ctx, "Custom charsets are not supported in attack mode 8 (generic).");

      return -1;
    }

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      event_log_error (hashcat_ctx, "Custom charsets are not supported in attack mode 9 (association).");

      return -1;
    }

    // detect if mask was specified:

    bool mask_is_missing = true;

    if (user_options->keyspace == true || user_options->total_candidates == true || user_options->lookup != NULL) // special case if --keyspace was used: we need the mask but no hash file
    {
      if (user_options->hc_argc > 0) mask_is_missing = false;
    }
    else if (user_options->stdout_flag == true) // special case if --stdout was used: we need the mask but no hash file
    {
      if (user_options->hc_argc > 0) mask_is_missing = false;
    }
    else
    {
      if (user_options->hc_argc > 1) mask_is_missing = false;
    }

    if (mask_is_missing == true)
    {
      event_log_error (hashcat_ctx, "If you specify a custom charset, you must also specify a mask.");

      return -1;
    }
  }

  if ((user_options->bypass_delay_chgd && !user_options->bypass_threshold_chgd) || (!user_options->bypass_delay_chgd && user_options->bypass_threshold_chgd))
  {
    event_log_error (hashcat_ctx, "You must specify --bypass-delay and --bypass-threshold together.");

    return -1;
  }

  if (user_options->rule_buf_l_chgd == true)
  {
    char rule_buf_in[RP_PASSWORD_SIZE]  = { 0 };
    char rule_buf_out[RP_PASSWORD_SIZE] = { 0 };

    const int rc = _old_apply_rule (user_options->rule_buf_l, strlen (user_options->rule_buf_l), rule_buf_in, 0, rule_buf_out);

    if (rc == RULE_RC_SYNTAX_ERROR)
    {
      event_log_error (hashcat_ctx, "Invalid or unsupported rule specified -j/--rule-left: %s", user_options->rule_buf_l);

      return -1;
    }
  }

  if (user_options->rule_buf_r_chgd == true)
  {
    char rule_buf_in[RP_PASSWORD_SIZE]  = { 0 };
    char rule_buf_out[RP_PASSWORD_SIZE] = { 0 };

    const int rc = _old_apply_rule (user_options->rule_buf_r, strlen (user_options->rule_buf_r), rule_buf_in, 0, rule_buf_out);

    if (rc == RULE_RC_SYNTAX_ERROR)
    {
      event_log_error (hashcat_ctx, "Invalid or unsupported rule specified -k/--rule-right: %s", user_options->rule_buf_r);

      return -1;
    }
  }

  // argc / argv checks

  bool show_error = true;

  if (user_options->version == true)
  {
    show_error = false;
  }
  else if (user_options->usage > 0)
  {
    show_error = false;
  }
  #ifdef WITH_BRAIN
  else if (user_options->brain_feed == true)
  {
    // reads stdin and exits, so it takes no hash file and no attack arguments

    show_error = false;
  }
  else if (user_options->brain_server == true)
  {
    show_error = false;
  }
  #endif
  else if (user_options->benchmark == true)
  {
    if (user_options->hc_argc == 0)
    {
      show_error = false;
    }
  }
  else if (user_options->hash_info > 0)
  {
    if (user_options->hc_argc == 0)
    {
      show_error = false;
    }
  }
  else if (user_options->backend_info > 0)
  {
    if (user_options->hc_argc == 0)
    {
      show_error = false;
    }
  }
  else if (user_options->restore == true)
  {
    if (user_options->hc_argc == 0)
    {
      show_error = false;
    }
  }
  else if (user_options->keyspace == true || user_options->total_candidates == true || user_options->lookup != NULL)
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      // Several wordlists are one keyspace, so sizing a run has to accept as many of them as running it
      // does. One argument is still the minimum: no argument at all is stdin, which has no keyspace.

      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      if (user_options->hc_argc == 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (user_options->hc_argc == 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_PCFG)
    {
      // Nothing is required. No ruleset runs the pair hashcat ships, and anything given is a ruleset
      // or a setting, which is what the feed reads either way.

      show_error = false;
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      // at least one wordlist, and the mask

      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
    {
      // a ?q in the mask names a second wordlist, so -a 12 takes one argument more than -a 6 does

      if ((user_options->hc_argc == 2) || (user_options->hc_argc == 3))
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      // the mask, and at least one wordlist

      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
    {
      // a feed takes as many arguments as it wants, and the wordlist feed takes one per source

      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      if (user_options->hc_argc == 1)
      {
        show_error = false;
      }
    }
  }
  else if (user_options->stdout_flag == true)
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      // all argc possible because of stdin mode

      show_error = false;
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      if (user_options->hc_argc == 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_PCFG)
    {
      // Nothing is required. No ruleset runs the pair hashcat ships, and anything given is a ruleset
      // or a setting, which is what the feed reads either way.

      show_error = false;
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      // at least one wordlist, and the mask

      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
    {
      // the mask, the wordlist the ?w names, and the wordlist the ?q names when the mask has one

      if ((user_options->hc_argc == 2) || (user_options->hc_argc == 3))
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      // the mask, and at least one wordlist

      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
  }
  else
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }

      if (user_options->hc_argc == 1)
      {
        // stdin mode

        #ifdef WITH_BRAIN
        if (user_options->brain_client == true)
        {
          event_log_error (hashcat_ctx, "Use of --brain-client is not possible in stdin mode.");

          return -1;
        }
        #endif

        if (user_options->slow_candidates == true)
        {
          event_log_error (hashcat_ctx, "Use of --slow-candidates is not possible in stdin mode.");

          return -1;
        }
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      if (user_options->hc_argc == 3)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_PCFG)
    {
      // The hash file, and after it nothing at all, a ruleset, or several rulesets and settings.
      // Nothing after it runs the pair hashcat ships.

      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      // the hash file, at least one wordlist, and the mask

      if (user_options->hc_argc >= 3)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
    {
      // the hash file, the mask, the wordlist the ?w names, and the wordlist the ?q names when the
      // mask has one

      if ((user_options->hc_argc == 3) || (user_options->hc_argc == 4))
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      // the hash file, the mask, and at least one wordlist

      if (user_options->hc_argc >= 3)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
    {
      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // The hash file on its own is the shorter form, where the words are the hash file's own first
      // fields. A wordlist after it is the older form, where the two files are lined up by line number.

      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
  }

  if (show_error == true)
  {
    usage_mini_print (user_options->hc_bin);

    return -1;
  }

  return 0;
}

void user_options_session_auto (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (strcmp (user_options->session, PROGNAME) == 0)
  {
    if (user_options->benchmark == true)
    {
      user_options->session = "benchmark";
    }

    if (user_options->hash_info > 0)
    {
      user_options->session = "hash_info";
    }

    if (user_options->usage > 0)
    {
      user_options->session = "usage";
    }

    if (user_options->speed_only == true)
    {
      user_options->session = "speed_only";
    }

    if (user_options->progress_only == true)
    {
      user_options->session = "progress_only";
    }

    if (user_options->total_candidates == true)
    {
      user_options->session = "candidates";
    }

    if (user_options->keyspace == true)
    {
      user_options->session = "keyspace";
    }

    if (user_options->lookup != NULL)
    {
      user_options->session = "lookup";
    }

    if (user_options->stdout_flag == true)
    {
      user_options->session = "stdout";
    }

    if (user_options->backend_info > 0)
    {
      user_options->session = "backend_info";
    }

    if (user_options->show == true)
    {
      user_options->session = "show";
    }

    if (user_options->left == true)
    {
      user_options->session = "left";
    }

    if (user_options->identify == true)
    {
      user_options->session = "identify";
    }
  }
}

// -a 1, -a 6 and -a 7 are -a 12 masks with the ?w in a fixed place, and -a 4 is -a 8 with the feed
// name already known, so all four are rewritten into the mode that runs them here and everything
// below this sees only -a 12 or -a 8. The options stay on the command line because every tutorial,
// script and wiki page in the world uses them.
//
//   -a 1 hash d1 d2      ->  -a 12 hash '?w?q' d1 d2
//   -a 6 hash dict mask  ->  -a 12 hash '?w' + mask dict
//   -a 7 hash mask dict  ->  -a 12 hash mask + '?w' dict
//   -a 4 hash ruleset    ->  -a 8 hash pcfg ruleset
//
// Only the mode and the order of the arguments are settled here. The ?w itself goes on in
// mask_append_final (), once per mask, which is what lets a mask file get it per line and
// --increment get it per length.
//
// -a 7 already writes its mask first, so it moves nothing. -a 6 writes its mask last and its two
// swap. -a 1 has no mask at all and gains one. -a 4 moves nothing either and gains the feed name.
//
// hc_argv is argv + optind and the restore file is written from those same pointers, so the rewrite
// allocates its own vector rather than writing through that one. Writing through it would put the
// rewritten text in the restore file next to the untouched -a 6, and the next resume would alias it
// a second time.

static void user_options_alias_attack_mode (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  const u32 attack_mode = user_options->attack_mode;

  if ((attack_mode != ATTACK_MODE_COMBI) && (attack_mode != ATTACK_MODE_HYBRID1) && (attack_mode != ATTACK_MODE_HYBRID2) && (attack_mode != ATTACK_MODE_PCFG)) return;

  // The argument count was checked against the mode the user typed, so anything that did not pass
  // that check is left alone for the error to be reported the way it always was.

  const int hc_argc = user_options->hc_argc;

  // -a 4 alone is a whole command line, because the ruleset is optional, so it has to reach the
  // rewrite with nothing after it. Every other mode here needs at least one argument.

  if ((hc_argc < 1) && (attack_mode != ATTACK_MODE_PCFG)) return;

  // Two spare slots for the feed name and the terminator, and a third for the setting --lookup is
  // carried in as. Only the -a 4 branch below uses the third.

  char **hc_argv = (char **) hccalloc (hc_argc + 3, sizeof (char *));

  int hc_argc_new = 0;

  // the hash file, or the first work argument when there is no hash file

  const bool has_hash_file = (user_options->benchmark == false) && (user_options->hash_info == 0) && (user_options->backend_info == 0) && (user_options->keyspace == false) && (user_options->total_candidates == false) && (user_options->lookup == NULL) && (user_options->stdout_flag == false);

  int work_from = 0;

  if (has_hash_file == true)
  {
    hc_argv[hc_argc_new] = user_options->hc_argv[0];

    hc_argc_new++;

    work_from = 1;
  }

  const int work_cnt = hc_argc - work_from;

  if (attack_mode == ATTACK_MODE_COMBI)
  {
    if (work_cnt != 2) { hcfree (hc_argv); return; }

    hc_argv[hc_argc_new + 0] = "?w?q";
    hc_argv[hc_argc_new + 1] = user_options->hc_argv[work_from + 0];
    hc_argv[hc_argc_new + 2] = user_options->hc_argv[work_from + 1];

    hc_argc_new += 3;

    user_options->marker_policy = MARKER_POLICY_NONE;

    user_options->attack_mode = ATTACK_MODE_HYBRID;
  }
  else if (attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (work_cnt < 2) { hcfree (hc_argv); return; }

    hc_argv[hc_argc_new] = user_options->hc_argv[hc_argc - 1];

    hc_argc_new++;

    for (int i = work_from; i < (hc_argc - 1); i++)
    {
      hc_argv[hc_argc_new] = user_options->hc_argv[i];

      hc_argc_new++;
    }

    user_options->marker_policy = MARKER_POLICY_PREFIX_W;

    user_options->attack_mode = ATTACK_MODE_HYBRID;
  }
  else if (attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (work_cnt < 2) { hcfree (hc_argv); return; }

    for (int i = work_from; i < hc_argc; i++)
    {
      hc_argv[hc_argc_new] = user_options->hc_argv[i];

      hc_argc_new++;
    }

    user_options->marker_policy = MARKER_POLICY_SUFFIX_W;

    user_options->attack_mode = ATTACK_MODE_HYBRID;
  }
  else
  {
    // -a 4 is a feed attack whose feed is already known, so the whole rewrite is the feed name in
    // front of the work arguments. A ruleset directory is the first of them, and everything after it
    // is a second ruleset or a setting, which is what the feed reads either way.

    hc_argv[hc_argc_new] = "pcfg";

    hc_argc_new++;

    for (int i = work_from; i < hc_argc; i++)
    {
      hc_argv[hc_argc_new] = user_options->hc_argv[i];

      hc_argc_new++;
    }

    // --lookup is the one spelling of the question, and this is the mode that already answers it. The
    // answer is the feed's to give: it depends on which engine the run got and on device-tuned sizing,
    // and neither leaves the feed. So the option is carried in as the setting the feed already reads,
    // rather than reimplemented next to it out of tables the core does not have.
    //
    // Appended last, so a lookup= the user typed themselves is the one further to the left and this
    // one wins, which is what a command line option should do against a positional setting.

    if (user_options->lookup != NULL)
    {
      hc_asprintf (&user_options->lookup_alias, "lookup=%s", user_options->lookup);

      hc_argv[hc_argc_new] = user_options->lookup_alias;

      hc_argc_new++;
    }

    user_options->attack_mode = ATTACK_MODE_GENERIC;
  }

  user_options->hc_argv_alias = hc_argv;

  user_options->hc_argv = hc_argv;
  user_options->hc_argc = hc_argc_new;
}

void user_options_preprocess (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // What the user asked for, before anything below rewrites it. Everything that has to answer for the
  // command line rather than for the attack that runs reads this.

  user_options->attack_mode_typed = user_options->attack_mode;

  user_options_alias_attack_mode (hashcat_ctx);

  // some options can influence or overwrite other options

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    user_options->slow_candidates = true;
  }
    #endif

  if (user_options->hwmon == false)
  {
    // some algorithm, such as SCRYPT and Argon2, depend on accurate free memory values
    // the only way to get them is through low-level APIs such as nvml via hwmon
    // we have --backend-keep-free message now

    //user_options->hwmon = true;
  }

  if (user_options->stdout_flag)
  {
    user_options->hwmon               = false;
    user_options->left                = false;
    user_options->logfile             = false;
    user_options->spin_damp           = 0;
    user_options->outfile_check_timer = 0;
    user_options->potfile             = false;
    user_options->restore_enable      = false;
    user_options->restore             = false;
    user_options->restore_position    = false;
    user_options->restore_timer       = 0;
    user_options->show                = false;
    user_options->status              = false;
    user_options->status_timer        = 0;
    user_options->bitmap_min          = 1;
    user_options->bitmap_max          = 1;
  }

  if (user_options->keyspace         == true
   || user_options->total_candidates == true
   || user_options->lookup           != NULL
   || user_options->speed_only       == true
   || user_options->progress_only    == true
   || user_options->identify         == true
   || user_options->usage             > 0
   || user_options->hash_info         > 0
   || user_options->backend_info      > 0)
  {
    //user_options->hwmon               = false;
    user_options->left                = false;
    user_options->logfile             = false;
    user_options->spin_damp           = 0;
    user_options->outfile_check_timer = 0;
    user_options->potfile             = false;
    user_options->restore_enable      = false;
    user_options->restore             = false;
    user_options->restore_position    = false;
    user_options->restore_timer       = 0;
    user_options->show                = false;
    user_options->status              = false;
    user_options->status_timer        = 0;
    // A measuring run has to build the bitmap the real attack would build. Without it every
    // candidate falls through to the hash table search and the measurement describes an attack
    // nobody is going to launch. progress_only is only promoted to speed_only further down, so
    // testing speed_only alone leaves it clamped.

    if ((user_options->speed_only == false) && (user_options->progress_only == false))
    {
      user_options->bitmap_min          = 1;
      user_options->bitmap_max          = 1;
    }
    #ifdef WITH_BRAIN
    user_options->brain_client        = false;
    #endif
  }

  if (user_options->benchmark == true)
  {
    user_options->attack_mode         = ATTACK_MODE_BF;
    user_options->hwmon_temp_abort    = 0;
    user_options->increment           = INCREMENT_NONE;
    user_options->left                = false;
    user_options->logfile             = false;
    user_options->spin_damp           = 0;
    user_options->potfile             = false;
    user_options->progress_only       = false;
    user_options->restore_enable      = false;
    user_options->restore             = false;
    user_options->restore_position    = false;
    user_options->restore_timer       = 0;
    user_options->show                = false;
    user_options->speed_only          = true;
    user_options->status              = false;
    user_options->status_timer        = 0;
    user_options->bitmap_min          = 1;
    user_options->bitmap_max          = 1;
    #ifdef WITH_BRAIN
    user_options->brain_client        = false;
    #endif

    if (user_options->workload_profile_chgd == false)
    {
      user_options->optimized_kernel  = true;
      user_options->workload_profile  = 3;
    }
  }

  if (user_options->hash_info > 0)
  {
    user_options->quiet = true;
  }

  if (user_options->usage > 0)
  {
    user_options->quiet = true;
  }

  if (user_options->progress_only == true)
  {
    user_options->speed_only = true;
  }

  if (user_options->total_candidates == true)
  {
    user_options->quiet = true;
  }

  if (user_options->lookup != NULL)
  {
    user_options->quiet = true;
  }

  if (user_options->keyspace == true)
  {
    user_options->quiet = true;
  }

  if (user_options->slow_candidates == true)
  {
    user_options->backend_vector_width = 1;
  }

  if (user_options->total_candidates == true)
  {
    user_options->keyspace = true;
  }

  // Every mode, -a 4 included, and there is no exception to it: --lookup never takes a hash file.
  // The feed's answer depends on which engine the run gets and on device-tuned sizing, and none of
  // that comes from a device -- the engine follows from -m and -S, and the sizing is a plugin call
  // with no device in it. Verified by asking the same question both ways and getting the same -s.
  //
  // --lookup sizes every round of the queue and then reports where one candidate falls in it, which
  // is what --keyspace already does minus the reporting. Borrowing it rather than repeating it is
  // also what keeps the two answers in the same units: a --lookup that named an offset --keyspace
  // did not count would send the user somewhere the run never goes.

  if (user_options->lookup != NULL)
  {
    user_options->keyspace = true;
  }

  if (user_options->stdout_flag == true)
  {
    user_options->force                 = true;
    user_options->hash_mode             = 2000;
    user_options->kernel_accel          = 1024;
    user_options->backend_vector_width  = 1;
    user_options->outfile_format        = OUTFILE_FMT_PLAIN;
    user_options->quiet                 = true;

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      user_options->kernel_loops = KERNEL_RULES;
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      user_options->kernel_loops = KERNEL_COMBS;
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      user_options->kernel_loops = KERNEL_BFS;
    }
    else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID))
    {
      user_options->kernel_loops = KERNEL_COMBS;
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      user_options->kernel_loops = KERNEL_COMBS;
    }
    else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
    {
      user_options->kernel_loops = KERNEL_RULES;
    }
    else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      user_options->kernel_loops = KERNEL_RULES;
    }
  }

  if (user_options->backend_info > 0)
  {
    user_options->backend_devices     = NULL;
    user_options->opencl_device_types = hcstrdup ("1,2");
    user_options->quiet               = true;
  }

  if (user_options->left == true)
  {
    user_options->outfile_format = OUTFILE_FMT_HASH;
  }

  if (user_options->show == true || user_options->left == true)
  {
    user_options->attack_mode = ATTACK_MODE_NONE;
    user_options->quiet       = true;
  }

  // this allows the user to use --show and --left while cracking (i.e. while another instance of hashcat is running)
  if (user_options->show == true || user_options->left == true)
  {
    user_options->restore_enable = false;

    user_options->restore = false;

    user_options->restore_position = false;
  }

  if (user_options->skip != 0 && user_options->limit != 0)
  {
    user_options->limit += user_options->skip;
  }

  if (user_options->markov_threshold == 0)
  {
    user_options->markov_threshold = 0x100;
  }

  #if !defined (WITH_HWMON)
  user_options->hwmon = false;
  #endif // WITH_HWMON

  if (user_options->hwmon == false)
  {
    user_options->hwmon_temp_abort = 0;
  }

  // default mask

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->hash_info > 0)
    {

    }
    else if (user_options->backend_info > 0)
    {

    }
    else if (user_options->speed_only == true)
    {

    }
    else if (user_options->keyspace == true)
    {
      if (user_options->hc_argc == 0)
      {
        user_options->custom_charset_1 = DEF_MASK_CS_1;
        user_options->custom_charset_2 = DEF_MASK_CS_2;
        user_options->custom_charset_3 = DEF_MASK_CS_3;

        user_options->increment = INCREMENT_NORMAL;
      }
    }
    else if (user_options->stdout_flag == true)
    {
      if (user_options->hc_argc == 0)
      {
        user_options->custom_charset_1 = DEF_MASK_CS_1;
        user_options->custom_charset_2 = DEF_MASK_CS_2;
        user_options->custom_charset_3 = DEF_MASK_CS_3;

        user_options->increment = INCREMENT_NORMAL;
      }
    }
    else
    {
      if (user_options->hc_argc == 1)
      {
        user_options->custom_charset_1 = DEF_MASK_CS_1;
        user_options->custom_charset_2 = DEF_MASK_CS_2;
        user_options->custom_charset_3 = DEF_MASK_CS_3;

        user_options->increment = INCREMENT_NORMAL;
      }
    }
  }

  // association limitations

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    user_options->potfile = false;
  }

  if (user_options->stdout_flag == false && user_options->benchmark == false && user_options->keyspace == false)
  {
    if (user_options->hash_mode == 0 && user_options->hash_mode_chgd == false)
    {
      user_options->autodetect = true;
    }
  }
}

void user_options_postprocess (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // automatic status

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    user_options->status = true;

    // A pipe is restorable, and --skip works on it, as long as it is fed the same candidates in the
    // same order. "cat wordlist.txt | hashcat --skip 1000" is a thing people run and a thing an
    // overlay hands out, so it is the user's job to feed the same stream again and hashcat's job to
    // start where it was asked to. It reaches a position by reading and throwing away everything
    // before it, in generic_ctx_base_discard (), because a stream cannot be seeked.
    //
    // Reading stdin through a feed is what made this work at all. The old producer never advanced the
    // restore point, so a restore file was written saying zero and restoring re-read the new pipe
    // from the start whatever it was told.
  }

  // Splitting the hash file is what --username already does, so it is turned on rather than reinvented.
  // The hash side is then the text after the first separator, which is what the hash parser has to see,
  // and the username side is kept per hash, which is where the feed picks the words up. Saying
  // --username as well is not a contradiction and not an error, it asks for the half of this that it
  // has always asked for.

  if (user_options_extra->association_autosplit == true)
  {
    user_options->username = true;
  }
}

void user_options_info (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  if (user_options->benchmark == false) return;

  if (user_options->machine_readable == false)
  {
    event_log_info (hashcat_ctx, "Benchmark relevant options:");
    event_log_info (hashcat_ctx, "===========================");

    if (user_options->benchmark_all == true)
    {
      event_log_info (hashcat_ctx, "* --benchmark-all");
    }

    if (user_options->hash_mode_chgd == false)
    {
      if (user_options->benchmark_max != BENCHMARK_MAX)
      {
        event_log_info (hashcat_ctx, "* --benchmark-max=%u", user_options->benchmark_max);
      }

      if (user_options->benchmark_min != BENCHMARK_MIN)
      {
        event_log_info (hashcat_ctx, "* --benchmark-min=%u", user_options->benchmark_min);
      }
    }

    if (user_options->force == true)
    {
      event_log_info (hashcat_ctx, "* --force");
    }

    if (user_options->backend_devices)
    {
      event_log_info (hashcat_ctx, "* --backend-devices=%s", user_options->backend_devices);
    }

    if (user_options->backend_devices_virtmulti)
    {
      event_log_info (hashcat_ctx, "* --backend-devices-virtmulti=%u", user_options->backend_devices_virtmulti);
    }

    if (user_options->backend_devices_virthost)
    {
      event_log_info (hashcat_ctx, "* --backend-devices-virthost=%u", user_options->backend_devices_virthost);
    }

    if (user_options->opencl_device_types)
    {
      event_log_info (hashcat_ctx, "* --opencl-device-types=%s", user_options->opencl_device_types);
    }

    if (user_options->optimized_kernel == true)
    {
      event_log_info (hashcat_ctx, "* --optimized-kernel-enable");
    }

    if (user_options->multiply_accel == false)
    {
      event_log_info (hashcat_ctx, "* --multiply-accel-disable");
    }

    if (user_options->backend_vector_width_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --backend-vector-width=%u", user_options->backend_vector_width);
    }

    if (user_options->kernel_accel_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-accel=%u", user_options->kernel_accel);
    }

    if (user_options->kernel_loops_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-loops=%u", user_options->kernel_loops);
    }

    if (user_options->kernel_threads_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-threads=%u", user_options->kernel_threads);
    }

    if (user_options->workload_profile_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --workload-profile=%u", user_options->workload_profile);
    }

    event_log_info (hashcat_ctx, NULL);
  }
  else
  {
    if (user_options->benchmark_all == true)
    {
      event_log_info (hashcat_ctx, "# option: --benchmark-all");
    }

    if (user_options->benchmark_max != BENCHMARK_MAX)
    {
      event_log_info (hashcat_ctx, "# option: --benchmark-max=%u", user_options->benchmark_max);
    }

    if (user_options->benchmark_min != BENCHMARK_MIN)
    {
      event_log_info (hashcat_ctx, "# option: --benchmark-min=%u", user_options->benchmark_min);
    }

    if (user_options->force == true)
    {
      event_log_info (hashcat_ctx, "# option: --force");
    }

    if (user_options->backend_devices)
    {
      event_log_info (hashcat_ctx, "# option: --backend-devices=%s", user_options->backend_devices);
    }

    if (user_options->backend_devices_virtmulti)
    {
      event_log_info (hashcat_ctx, "# option: --backend-devices-virtmulti=%u", user_options->backend_devices_virtmulti);
    }

    if (user_options->backend_devices_virthost)
    {
      event_log_info (hashcat_ctx, "# option: --backend-devices-virthost=%u", user_options->backend_devices_virthost);
    }

    if (user_options->opencl_device_types)
    {
      event_log_info (hashcat_ctx, "# option: --opencl-device-types=%s", user_options->opencl_device_types);
    }

    if (user_options->optimized_kernel == true)
    {
      event_log_info (hashcat_ctx, "# option: --optimized-kernel-enable");
    }

    if (user_options->multiply_accel == false)
    {
      event_log_info (hashcat_ctx, "# option: --multiply-accel-disable");
    }

    if (user_options->backend_vector_width_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --backend-vector-width=%u", user_options->backend_vector_width);
    }

    if (user_options->kernel_accel_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-accel=%u", user_options->kernel_accel);
    }

    if (user_options->kernel_loops_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-loops=%u", user_options->kernel_loops);
    }

    if (user_options->kernel_threads_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-threads=%u", user_options->kernel_threads);
    }

    if (user_options->workload_profile_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --workload-profile=%u", user_options->workload_profile);
    }
  }
}

// Which producer fills a batch of base words for this run. The attack mode is not the answer: it says
// what the user asked for and goes on saying it, and several modes can take their base words from more
// than one place.
//
// A wordlist reaches the generic feed wherever the feed can express what the mode was asked to do. The
// feed seeks, so a device jumps straight to its own range instead of reading and discarding every word
// another device already took. It also lays several dictionaries end to end into one keyspace, which is
// what makes --skip and --limit work across all of them.
//
// Two things are excluded, and both are the same reason rather than an oversight. Reading candidates
// from stdin has no feed equivalent. Neither has an induction round: a feed is handed its sources once,
// in global_init (), which runs before the first round, so a second round would re-read the original
// wordlist instead of the words --loopback or --induction-dir just produced. Those runs take the
// wordlist reader, which is correct and only slower.
//
// HASHCAT_A0_LEGACY_READER=1 puts the wordlist reader back. It is there because this is a large change
// to the most used attack modes, not because either path is expected to be wrong.

// How much of the attack one instance covers. Everything is one keyspace unless the run is really a
// queue of attacks, and only two things are: an induction round, whose dictionary does not exist
// until the round before it is read, and -a 9 over more than one dictionary, where each one is its
// own attack over the same salts.

static u32 user_options_extra_base_scope (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->loopback      == true) return BASE_SCOPE_PER_ROUND;
  if (user_options->induction_dir != NULL) return BASE_SCOPE_PER_ROUND;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    // An account name becomes several words, and each of them is a round over the same hashes. Asked
    // before the argument count, because that count is zero here.

    if (user_options_extra->association_autosplit == true) return BASE_SCOPE_PER_ROUND;

    if (user_options_extra->hc_workc != 1) return BASE_SCOPE_PER_ROUND;

    if (hc_path_is_directory (user_options_extra->hc_workv[0]) == true) return BASE_SCOPE_PER_ROUND;
  }

  return BASE_SCOPE_ALL_SOURCES;
}

static u32 user_options_extra_base_source (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  const u32 attack_mode = user_options->attack_mode;

  if (attack_mode == ATTACK_MODE_BF)      return BASE_SOURCE_MASK;
  if (attack_mode == ATTACK_MODE_GENERIC) return BASE_SOURCE_FEED;

  const bool reads_words = (attack_mode == ATTACK_MODE_STRAIGHT) || (attack_mode == ATTACK_MODE_COMBI) || (attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2) || (attack_mode == ATTACK_MODE_HYBRID) || (attack_mode == ATTACK_MODE_ASSOCIATION);

  if (reads_words == false) return BASE_SOURCE_NONE;

  // -a 7 is the one mode whose base words are not settled here. The optimized kernel builds mask plus
  // word and takes its base from the dictionary; the pure kernel builds word plus mask and takes its
  // base from the mask. Which kernel it will be is decided inside hashconfig_init, which has not run,
  // so the answer given here is the pure one and user_options_extra_init_late () upgrades it once the
  // kernel type is known.

  if (attack_mode == ATTACK_MODE_HYBRID2) return BASE_SOURCE_MASK;

  return BASE_SOURCE_FEED;
}

// Finish base_source once the hash mode is known. Two attack modes have something left to decide and
// both of them need to know which kernel it will be, and OPTI_TYPE_OPTIMIZED_KERNEL is written inside
// hashconfig_init and by nothing after it, so this is the earliest the question can be answered.
//
// Every reader of base_source runs later than this. induct_ctx_init only ever looks at -a 0 and -a 9,
// user_options_check_files works from the attack mode alone, the one early reader of wordlist_mode
// tests for stdin which neither of these can be, and straight_ctx_init, combinator_ctx_init,
// mask_ctx_init and generic_ctx_init are all further down outer_loop.

void user_options_extra_init_late (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig         = hashcat_ctx->hashconfig;
  const user_options_t *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;

  // -a 7 builds mask plus word. The optimized kernel can put the amplifier in front of the base word,
  // so it takes its base from the dictionary; the pure kernel can only append, so the mask has to be
  // the base and the dictionary the amplifier.

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (user_options_extra->base_source != BASE_SOURCE_MASK) return;

    if (optimized_kernel == false) return;

    user_options_extra->base_source   = BASE_SOURCE_FEED;
    user_options_extra->wordlist_mode = WL_MODE_GENERIC;

    return;
  }

  // -a 12 is the same question asked of the mask rather than of the attack mode. A mask that ends in
  // ?w builds mask plus word, which is what -a 7 builds, so under a pure kernel it wants the same
  // answer: the mask is the base and the wordlist is the amplifier. A prefix in front of the base
  // word cannot be precomputed into the hash context and would be fed again for every candidate.
  //
  // A ?q is out, because a second word behind the first one leaves the mask no longer at the end. It
  // is out by the argument count rather than by looking, since a ?q is what the third argument is for.
  //
  // The mask is the first work argument and it is read here rather than asked of mask_ctx, which has
  // not parsed it yet. Reading it is not guessing: its position is what says it is the mask.

  if (user_options->attack_mode != ATTACK_MODE_HYBRID) return;

  if (optimized_kernel == true) return;

  // --slow-candidates picks its producer by base_source too and has no mask producer

  if (user_options->slow_candidates == true) return;

  // an induction round reads a dictionary that did not exist at init, so the base word source is a
  // queue of feeds and cannot be the mask

  if (user_options_extra->base_scope != BASE_SCOPE_ALL_SOURCES) return;

  if (user_options_extra->hc_workc != 2) return;

  // the wordlist becomes the amplifier, and an amplifier is one instance read from start to end and
  // rewound per chunk, so unlike a base word source it cannot be a folder

  if (hc_path_is_file (user_options_extra->hc_workv[1]) == false) return;

  // Whether every mask this run will use ends in ?w. A mask the user typed has to be read to find
  // out, and a mask that was rewritten from another attack mode has not been given its ?w yet, so
  // there the policy that will put it there is the answer.

  bool ends_with_w = false;

  if      (user_options->marker_policy == MARKER_POLICY_SUFFIX_W) ends_with_w = true;
  else if (user_options->marker_policy == MARKER_POLICY_PREFIX_W) ends_with_w = false;
  else                                                            ends_with_w = mask_arg_ends_with_marker (user_options_extra->hc_workv[0], 'w');

  if (ends_with_w == false) return;

  user_options_extra->base_source   = BASE_SOURCE_MASK;
  user_options_extra->wordlist_mode = WL_MODE_MASK;

  // The wordlist has moved from the base loop to the amplifier loop and every producer picks its rule
  // by role, so the rule that named the word has to move with it. -j named it before and names it
  // still.

  user_options_extra->rule_buf_amp = user_options->rule_buf_l;
  user_options_extra->rule_len_amp = user_options_extra->rule_len_l;
}

void user_options_extra_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // separator

  if (user_options->separator)
  {
    user_options_extra->separator = user_options->separator[0];
  }

  // attack-kern

  user_options_extra->attack_kern = ATTACK_KERN_NONE;

  switch (user_options->attack_mode)
  {
    case ATTACK_MODE_STRAIGHT:      user_options_extra->attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_COMBI:         user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_BF:            user_options_extra->attack_kern = ATTACK_KERN_BF;       break;
    case ATTACK_MODE_HYBRID1:       user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID2:       user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID:        user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_GENERIC:       user_options_extra->attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_ASSOCIATION:   user_options_extra->attack_kern = ATTACK_KERN_STRAIGHT; break;
  }

  // rules

  user_options_extra->rule_len_l = (int) strlen (user_options->rule_buf_l);
  user_options_extra->rule_len_r = (int) strlen (user_options->rule_buf_r);

  // The base word is the left hand side of a candidate, so -j is its rule and -k the amplifier's.

  user_options_extra->rule_buf_base = user_options->rule_buf_l;
  user_options_extra->rule_len_base = user_options_extra->rule_len_l;

  user_options_extra->rule_buf_amp  = user_options->rule_buf_r;
  user_options_extra->rule_len_amp  = user_options_extra->rule_len_r;

  // -a 7 appends a word to a mask, so its word is the right hand side and -k is the rule for it. That
  // holds whichever loop the word ends up in: the optimized kernel makes it the base and the pure
  // kernel makes it the amplifier, and -k applies either way. Which means this one does not have to
  // wait for the kernel type, and it must not: the pure kernel counts that dictionary twice, once in
  // combinator_ctx_init and once per round in straight_ctx_update_loop, and the two counts divide into
  // each other. They have to be made with the same rule.
  //
  // The mask is the other side and nothing applies a rule to a mask, so both fields naming -k is right
  // rather than merely harmless.

  if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    user_options_extra->rule_buf_base = user_options->rule_buf_r;
    user_options_extra->rule_len_base = user_options_extra->rule_len_r;
  }

  // --dynamic-x

  user_options_extra->dynamicx_num = -1;

  // hc_hash and hc_work*

  user_options_extra->hc_hash  = NULL;
  user_options_extra->hc_workv = NULL;
  user_options_extra->hc_workc = 0;

  if (user_options->benchmark == true)
  {

  }
  else if (user_options->hash_info > 0)
  {

  }
  else if (user_options->backend_info > 0)
  {

  }
  else if (user_options->keyspace == true)
  {
    user_options_extra->hc_workc = user_options->hc_argc;
    user_options_extra->hc_workv = user_options->hc_argv;
  }
  else if (user_options->stdout_flag == true)
  {
    user_options_extra->hc_workc = user_options->hc_argc;
    user_options_extra->hc_workv = user_options->hc_argv;
  }
  else
  {
    user_options_extra->hc_hash  = user_options->hc_argv[0];
    user_options_extra->hc_workc = user_options->hc_argc - 1;
    user_options_extra->hc_workv = user_options->hc_argv + 1;
  }

  // -a 9 with a hash file and nothing else takes its words out of that file. One argument means nothing
  // to -a 9 today, it is a usage error, so no flag is needed to ask for this and nothing changes meaning.
  //
  // --keyspace and --stdout have no hash file at all, and their single argument is the wordlist, which
  // is why hc_hash rather than the argument count is what this asks.

  user_options_extra->association_autosplit = false;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    if (user_options_extra->hc_hash != NULL)
    {
      if (user_options_extra->hc_workc == 0) user_options_extra->association_autosplit = true;
    }
  }

  // base_source, and how much of the attack one instance of it covers

  user_options_extra->base_source = user_options_extra_base_source (hashcat_ctx);
  user_options_extra->base_scope  = user_options_extra_base_scope  (hashcat_ctx);

  // Whether the last work argument belongs to the ?q rather than to the base word. Settled once here
  // so that the argument split, the file checks and the wordlist list cannot answer it differently.

  user_options_extra->hybrid_q = false;

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    if (user_options->attack_mode_typed == ATTACK_MODE_COMBI)
    {
      user_options_extra->hybrid_q = true;
    }
    else if (user_options->attack_mode_typed == ATTACK_MODE_HYBRID)
    {
      user_options_extra->hybrid_q = (user_options_extra->hc_workc == 3);
    }
  }

  // wordlist_mode says the same thing base_source does and is kept because a lot of code reads it. It
  // is derived here rather than worked out a second time.

  user_options_extra->wordlist_mode = WL_MODE_NONE;

  switch (user_options_extra->base_source)
  {
    case BASE_SOURCE_MASK: user_options_extra->wordlist_mode = WL_MODE_MASK;    break;
    case BASE_SOURCE_FEED: user_options_extra->wordlist_mode = WL_MODE_GENERIC; break;
  }

  // -a 0 with no wordlist reads its candidates from a pipe, and that is a feed like any other. It is
  // the one whose plugin hashcat picks rather than the user, so base_source cannot tell it apart from
  // a wordlist and this is where the difference is kept: which plugin to open, whether to print the
  // stdin prompt, and that the run is not restorable.

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) && (user_options_extra->hc_workc == 0))
  {
    user_options_extra->wordlist_mode = WL_MODE_STDIN;
  }
}

void user_options_extra_destroy (hashcat_ctx_t *hashcat_ctx)
{
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  memset (user_options_extra, 0, sizeof (user_options_extra_t));
}

// Settle which rule belongs to the base word and which to the amplifier, once the attack mode has
// finished deciding what its base word is.
//
// Finish the base and amplifier rules for -a 1, which is the only mode that cannot answer earlier.
//
// It takes the larger of its two dictionaries as the base so that the base loop is the long one, and
// that choice is made by counting both, in combinator_ctx_init. The rule follows the dictionary rather
// than the loop, so a base-right attack reads its base words with -k and its amplifier words with -j.
//
// Everything that reads either side runs after this: the producers, the counters in
// straight_ctx_update_loop and the amplifier readers are all inside the attack loop. The two counts
// combinator_ctx_init itself makes are the ones that pick the base, and they are deliberately made
// before the choice exists, both with -j, which is what they were made with before this existed.

void user_options_extra_init_rules (hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const user_options_t   *user_options       = hashcat_ctx->user_options;
  user_options_extra_t   *user_options_extra = hashcat_ctx->user_options_extra;

  // What the user typed, because -a 1 is rewritten into a -a 12 mask and this is about which of the
  // two wordlists they named first.

  if (user_options->attack_mode_typed != ATTACK_MODE_COMBI) return;

  if (combinator_ctx->roles_swapped == false) return;

  user_options_extra->rule_buf_base = user_options->rule_buf_r;
  user_options_extra->rule_len_base = user_options_extra->rule_len_r;

  user_options_extra->rule_buf_amp  = user_options->rule_buf_l;
  user_options_extra->rule_len_amp  = user_options_extra->rule_len_l;
}

// Which of the hash mode's length bounds a base word is judged against. See base_length_t for why the
// three cases are what they are.

u32 user_options_extra_base_length (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION) return BASE_LENGTH_NONE;

  if (user_options_extra->attack_kern == ATTACK_KERN_COMBI) return BASE_LENGTH_MAX;

  return BASE_LENGTH_BOTH;
}

u64 user_options_extra_amplifier (hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  const straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->slow_candidates == true)
  {
    return 1;
  }

  if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
  {
    if (straight_ctx->kernel_rules_cnt)
    {
      return straight_ctx->kernel_rules_cnt;
    }
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
  {
    if (combinator_ctx->combs_cnt)
    {
      return combinator_ctx->combs_cnt;
    }
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    if (mask_ctx->bfs_cnt)
    {
      return mask_ctx->bfs_cnt;
    }
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_PCFG)
  {
    // An amplifying feed expands one base word into a cell of candidates on the device, the same way
    // rules expand a word, so the work item --skip and --limit count is the base word and the
    // device engine has to divide out of the keyspace here as every other one does.
    //
    // Without this the count is left in candidates while thread_seek () is handed a base word index.
    // The two differ by the mean cell, which on a rockyou grammar is 5434, so --keyspace answers
    // 1.3e15 for a stream that ends at 2.4e11 and every --skip past that exits Exhausted having done
    // no work at all. It also left the rejected counters short by the same factor, since both of the
    // other callers multiply a base word count by this to reach candidates.

    if (hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE].dev_avg)
    {
      return hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE].dev_avg;
    }
  }

  return 1;
}

int user_options_check_files (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t      *folder_config      = hashcat_ctx->folder_config;
  logfile_ctx_t        *logfile_ctx        = hashcat_ctx->logfile_ctx;
  outcheck_ctx_t       *outcheck_ctx       = hashcat_ctx->outcheck_ctx;
  outfile_ctx_t        *outfile_ctx        = hashcat_ctx->outfile_ctx;
  pidfile_ctx_t        *pidfile_ctx        = hashcat_ctx->pidfile_ctx;
  potfile_ctx_t        *potfile_ctx        = hashcat_ctx->potfile_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  // public key

  if (user_options->encrypt_with_pubkey != NULL)
  {
    if (hc_path_read (user_options->encrypt_with_pubkey) == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", user_options->encrypt_with_pubkey, strerror (errno));

      return -1;
    }
  }

  // brain

  #ifdef WITH_BRAIN
  if (user_options->brain_host)
  {
    struct addrinfo hints;

    memset (&hints, 0, sizeof (hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *address_info = NULL;

    const int rc_getaddrinfo = getaddrinfo (user_options->brain_host, NULL, &hints, &address_info);

    if (rc_getaddrinfo != 0)
    {
      fprintf (stderr, "%s: %s\n", user_options->brain_host, gai_strerror (rc_getaddrinfo));

      return -1;
    }

    freeaddrinfo (address_info);
  }
  #endif

  // common folders

  #if defined (_WIN)
  if (hc_path_read (".") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", ".", strerror (errno));

    return -1;
  }
  #else
  if (hc_path_read (folder_config->cwd) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->cwd, strerror (errno));

    return -1;
  }
  #endif

  if (hc_path_read (folder_config->install_dir) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->install_dir, strerror (errno));

    return -1;
  }

  if (hc_path_read (folder_config->profile_dir) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->profile_dir, strerror (errno));

    return -1;
  }

  if (hc_path_write (folder_config->session_dir) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->session_dir, strerror (errno));

    return -1;
  }

  if (hc_path_read (folder_config->shared_dir) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->shared_dir, strerror (errno));

    return -1;
  }

  if (hc_path_read (folder_config->cpath_real) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->cpath_real, strerror (errno));

    return -1;
  }

  // hashfile - can be NULL

  if (user_options_extra->hc_hash != NULL)
  {
    if (hc_path_exist (user_options_extra->hc_hash) == true)
    {
      if (hc_path_is_directory (user_options_extra->hc_hash) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a hashfile argument.", user_options_extra->hc_hash);

        return -1;
      }

      if (hc_path_read (user_options_extra->hc_hash) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", user_options_extra->hc_hash, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (user_options_extra->hc_hash) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", user_options_extra->hc_hash);

        //return -1;
      }
    }
  }

  // arguments - checks must depend on attack_mode

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    for (int i = 0; i < user_options_extra->hc_workc; i++)
    {
      char *wlfile = user_options_extra->hc_workv[i];

      if (hc_path_exist (wlfile) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", wlfile, strerror (errno));

        return -1;
      }
    }

    for (int i = 0; i < (int) user_options->rp_files_cnt; i++)
    {
      char *rp_file = user_options->rp_files[i];

      if (hc_path_exist (rp_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", rp_file, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (rp_file) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a rulefile argument.", rp_file);

        return -1;
      }

      if (hc_path_read (rp_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", rp_file, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (rp_file) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", rp_file);

        //return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    // mode easy mode here because both files must exist and readable

    if (user_options_extra->hc_workc == 2)
    {
      char *dictfile1 = user_options_extra->hc_workv[0];
      char *dictfile2 = user_options_extra->hc_workv[1];

      if (hc_path_exist (dictfile1) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile1, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (dictfile1) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a wordlist argument.", dictfile1);

        return -1;
      }

      if (hc_path_read (dictfile1) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile1, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (dictfile1) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dictfile1);

        //return -1;
      }

      if (hc_path_exist (dictfile2) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (dictfile2) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a wordlist argument.", dictfile2);

        return -1;
      }

      if (hc_path_read (dictfile2) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (dictfile2) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dictfile2);

        //return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    // if the file exist it's a maskfile and then it must be readable

    if (user_options_extra->hc_workc == 1)
    {
      char *maskfile = user_options_extra->hc_workv[0];

      if (hc_path_exist (maskfile) == true)
      {
        if (hc_path_is_directory (maskfile) == true)
        {
          event_log_error (hashcat_ctx, "%s: A directory cannot be used as a maskfile argument.", maskfile);

          return -1;
        }

        if (hc_path_read (maskfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", maskfile, strerror (errno));

          return -1;
        }

        if (hc_path_has_bom (maskfile) == true)
        {
          event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

          //return -1;
        }

        if ((user_options->custom_charset_1)
         || (user_options->custom_charset_2)
         || (user_options->custom_charset_3)
         || (user_options->custom_charset_4)
         || (user_options->custom_charset_5)
         || (user_options->custom_charset_6)
         || (user_options->custom_charset_7)
         || (user_options->custom_charset_8))
        {
          event_log_error (hashcat_ctx, "Using --custom-charsetX with mask files is misleading. Put custom charsets in the mask file instead.");

          return -1;
        }
      }
    }
  }
  else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID))
  {
    // -a 6 names its wordlist first and its mask last, and -a 12 names its mask first and then its
    // wordlists. What -a 12 adds is a second wordlist when the mask carries a ?q. That one is read by
    // a single feed instance rather than a wordlist reader, so unlike the base it cannot be a folder.

    const bool hybrid = (user_options->attack_mode == ATTACK_MODE_HYBRID);

    const bool has_second_dict = (hybrid == true) && (user_options_extra->hybrid_q == true);

    if (has_second_dict == true)
    {
      char *dictfile2 = user_options_extra->hc_workv[user_options_extra->hc_workc - 1];

      if (hc_path_exist (dictfile2) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (dictfile2) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a wordlist argument.", dictfile2);

        return -1;
      }

      if (hc_path_read (dictfile2) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (dictfile2) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dictfile2);
      }
    }

    if ((user_options_extra->hc_workc >= 2) || (has_second_dict == true))
    {
      char *wlfile = user_options_extra->hc_workv[(hybrid == true) ? 1 : 0];

      char *maskfile = user_options_extra->hc_workv[(hybrid == true) ? 0 : (user_options_extra->hc_workc - 1)];

      // for wordlist: can be folder

      if (hc_path_exist (wlfile) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", wlfile, strerror (errno));

        return -1;
      }

      // for mask: if the file exist it's a maskfile and then it must be readable

      if (hc_path_exist (maskfile) == true)
      {
        if (hc_path_is_directory (maskfile) == true)
        {
          event_log_error (hashcat_ctx, "%s: A directory cannot be used as a maskfile argument.", maskfile);

          return -1;
        }

        if (hc_path_read (maskfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", maskfile, strerror (errno));

          return -1;
        }

        if (hc_path_has_bom (maskfile) == true)
        {
          event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

          //return -1;
        }

        if ((user_options->custom_charset_1)
         || (user_options->custom_charset_2)
         || (user_options->custom_charset_3)
         || (user_options->custom_charset_4)
         || (user_options->custom_charset_5)
         || (user_options->custom_charset_6)
         || (user_options->custom_charset_7)
         || (user_options->custom_charset_8))
        {
          event_log_error (hashcat_ctx, "Using --custom-charsetX with mask files is misleading. Put custom charsets in the mask file instead.");

          return -1;
        }
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (user_options_extra->hc_workc == 2)
    {
      char *wlfile = user_options_extra->hc_workv[1];

      char *maskfile = user_options_extra->hc_workv[0];

      // for wordlist: can be folder

      if (hc_path_exist (wlfile) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", wlfile, strerror (errno));

        return -1;
      }

      // for mask: if the file exist it's a maskfile and then it must be readable

      if (hc_path_exist (maskfile) == true)
      {
        if (hc_path_is_directory (maskfile) == true)
        {
          event_log_error (hashcat_ctx, "%s: A directory cannot be used as a maskfile argument.", maskfile);

          return -1;
        }

        if (hc_path_read (maskfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", maskfile, strerror (errno));

          return -1;
        }

        if (hc_path_has_bom (maskfile) == true)
        {
          event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

          //return -1;
        }

        if ((user_options->custom_charset_1)
         || (user_options->custom_charset_2)
         || (user_options->custom_charset_3)
         || (user_options->custom_charset_4)
         || (user_options->custom_charset_5)
         || (user_options->custom_charset_6)
         || (user_options->custom_charset_7)
         || (user_options->custom_charset_8))
        {
          event_log_error (hashcat_ctx, "Using --custom-charsetX with mask files is misleading. Put custom charsets in the mask file instead.");

          return -1;
        }
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
  {
    // The first argument is a plugin name and only falls back to being a path, so it is checked
    // against the shipped feeds first. A name that matches neither is reported as the path it would
    // have been, because that is the form the user typed.
    //
    // There may be no argument at all. --backend-info and --hash-info answer without running an
    // attack, so they leave hc_workv null whatever else is on the command line, and reading
    // hc_workv[0] read through it. --benchmark leaves it null for the same reason but refuses -a
    // before reaching here, so it cannot get this far today.

    if (user_options_extra->hc_workc > 0)
    {
      char *plugin_name = user_options_extra->hc_workv[0];

      bool by_name = false;

      char *library_filename = generic_resolve (folder_config, plugin_name, &by_name);

      hcfree (library_filename);

      if (by_name == false)
      {
        if (hc_path_exist (plugin_name) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", plugin_name, strerror (errno));

          return -1;
        }

        if (hc_path_is_directory (plugin_name) == true)
        {
          event_log_error (hashcat_ctx, "%s: A directory cannot be used as first plugin argument.", plugin_name);

          return -1;
        }

        if (hc_path_read (plugin_name) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", plugin_name, strerror (errno));

          return -1;
        }
      }
    }

    for (int i = 0; i < (int) user_options->rp_files_cnt; i++)
    {
      char *rp_file = user_options->rp_files[i];

      if (hc_path_exist (rp_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", rp_file, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (rp_file) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a rulefile argument.", rp_file);

        return -1;
      }

      if (hc_path_read (rp_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", rp_file, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (rp_file) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", rp_file);

        //return -1;
      }
    }
  }

  // logfile

  if (logfile_ctx->enabled == true)
  {
    if (hc_path_exist (logfile_ctx->logfile) == true)
    {
      if (hc_path_is_directory (logfile_ctx->logfile) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a logfile argument.", logfile_ctx->logfile);

        return -1;
      }

      if (hc_path_write (logfile_ctx->logfile) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", logfile_ctx->logfile, strerror (errno));

        return -1;
      }
    }
    else
    {
      if (hc_path_create (logfile_ctx->logfile) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", logfile_ctx->logfile, strerror (errno));

        return -1;
      }
    }
  }

  // outfile_check

  if (outcheck_ctx->enabled == true)
  {
    if (hc_path_exist (outcheck_ctx->root_directory) == true)
    {
      if (hc_path_is_directory (outcheck_ctx->root_directory) == false)
      {
        event_log_error (hashcat_ctx, "Directory specified in outfile-check '%s' is not a directory.", outcheck_ctx->root_directory);

        return -1;
      }
    }
  }

  // outfile - can be NULL

  if (outfile_ctx->filename != NULL)
  {
    if (hc_path_exist (outfile_ctx->filename) == true)
    {
      if (hc_path_is_directory (outfile_ctx->filename) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as an outfile.", outfile_ctx->filename);

        return -1;
      }

      if (hc_path_write (outfile_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", outfile_ctx->filename, strerror (errno));

        return -1;
      }
    }
    else
    {
      if (hc_path_create (outfile_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", outfile_ctx->filename, strerror (errno));

        return -1;
      }
    }
  }

  // check for outfile vs. hashfile

  if (hc_same_files (outfile_ctx->filename, user_options_extra->hc_hash) == true)
  {
    event_log_error (hashcat_ctx, "Outfile and hashfile cannot point to the same file.");

    return -1;
  }

  // check for outfile vs. cached wordlists

  if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    for (int i = 0; i < user_options_extra->hc_workc; i++)
    {
      char *wlfile = user_options_extra->hc_workv[i];

      if (hc_same_files (outfile_ctx->filename, wlfile) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    if (user_options_extra->hc_workc == 2)
    {
      char *dictfile1 = user_options_extra->hc_workv[0];
      char *dictfile2 = user_options_extra->hc_workv[1];

      if (hc_same_files (outfile_ctx->filename, dictfile1) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }

      if (hc_same_files (outfile_ctx->filename, dictfile2) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (user_options_extra->hc_workc == 2)
    {
      char *wlfile = user_options_extra->hc_workv[0];

      if (hc_same_files (outfile_ctx->filename, wlfile) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // The mask is the first work argument and everything behind it is a wordlist: one of them, or two
    // when the mask carries a ?q.

    for (int i = 1; i < user_options_extra->hc_workc; i++)
    {
      char *wlfile = user_options_extra->hc_workv[i];

      if (hc_same_files (outfile_ctx->filename, wlfile) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (user_options_extra->hc_workc == 2)
    {
      char *wlfile = user_options_extra->hc_workv[1];

      if (hc_same_files (outfile_ctx->filename, wlfile) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and wordlist cannot point to the same file.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_GENERIC)
  {
    for (int i = 0; i < user_options_extra->hc_workc; i++)
    {
      char *plugin = user_options_extra->hc_workv[i];

      if (hc_same_files (outfile_ctx->filename, plugin) == true)
      {
        event_log_error (hashcat_ctx, "Outfile and plugin cannot point to the same file.");

        return -1;
      }
    }
  }
  // pidfile

  if (hc_path_exist (pidfile_ctx->filename) == true)
  {
    if (hc_path_is_directory (pidfile_ctx->filename) == true)
    {
      event_log_error (hashcat_ctx, "%s: A directory cannot be used as a pidfile argument.", pidfile_ctx->filename);

      return -1;
    }

    if (hc_path_write (pidfile_ctx->filename) == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", pidfile_ctx->filename, strerror (errno));

      return -1;
    }
  }
  else
  {
    if (hc_path_create (pidfile_ctx->filename) == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", pidfile_ctx->filename, strerror (errno));

      return -1;
    }
  }

  // potfile

  if (potfile_ctx->enabled == true)
  {
    if (hc_path_exist (potfile_ctx->filename) == true)
    {
      if (hc_path_is_directory (potfile_ctx->filename) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a potfile argument.", potfile_ctx->filename);

        return -1;
      }

      if (hc_path_write (potfile_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", potfile_ctx->filename, strerror (errno));

        return -1;
      }
    }
    else
    {
      if (hc_path_create (potfile_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", potfile_ctx->filename, strerror (errno));

        return -1;
      }
    }
  }

  // single kernel and module existence check to detect "7z e" errors

  char *modulefile = (char *) hcmalloc (HCBUFSIZ_TINY);

  module_filename (folder_config, 0, modulefile, HCBUFSIZ_TINY);

  if (hc_path_exist (modulefile) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", modulefile, strerror (errno));

    event_log_warning (hashcat_ctx, "If you are using the hashcat binary package, this may be an extraction issue.");
    event_log_warning (hashcat_ctx, "For example, using \"7z e\" instead of using \"7z x\".");
    event_log_warning (hashcat_ctx, NULL);

    hcfree (modulefile);

    return -1;
  }

  hcfree (modulefile);

  const bool quiet_save = user_options->quiet;

  user_options->quiet = true;

  const int rc = hashconfig_init (hashcat_ctx);

  user_options->quiet = quiet_save;

  if (rc == -1) return -1;

  hashconfig_destroy (hashcat_ctx);

  // same check but for an backend kernel

  char *kernelfile = (char *) hcmalloc (HCBUFSIZ_TINY);

  generate_source_kernel_filename (false, ATTACK_EXEC_OUTSIDE_KERNEL, ATTACK_KERN_STRAIGHT, 400, 0, folder_config->shared_dir, kernelfile);

  if (hc_path_read (kernelfile) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", kernelfile, strerror (errno));

    event_log_warning (hashcat_ctx, "If you are using the hashcat binary package, this may be an extraction issue.");
    event_log_warning (hashcat_ctx, "For example, using \"7z e\" instead of using \"7z x\".");
    event_log_warning (hashcat_ctx, NULL);

    hcfree (kernelfile);

    return -1;
  }

  hcfree (kernelfile);

  // loopback - can't check at this point

  // tuning file check already done

  // debugfile check already done

  if (user_options->keyboard_layout_mapping != NULL)
  {
    if (hc_path_exist (user_options->keyboard_layout_mapping) == true)
    {
      if (hc_path_read (user_options->keyboard_layout_mapping) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", user_options->keyboard_layout_mapping, strerror (errno));

        return -1;
      }
    }
    else
    {
      event_log_error (hashcat_ctx, "%s: %s", user_options->keyboard_layout_mapping, strerror (errno));

      return -1;
    }
  }

  if (user_options->veracrypt_keyfiles != NULL)
  {
    char *keyfiles = hcstrdup (user_options->veracrypt_keyfiles);

    char *saveptr = NULL;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    while (keyfile)
    {
      if (hc_path_exist (keyfile) == true)
      {
        if (hc_path_read (keyfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", keyfile, strerror (errno));

          return -1;
        }
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: %s", keyfile, strerror (errno));

        return -1;
      }

      keyfile = strtok_r ((char *) NULL, ",", &saveptr);
    }

    hcfree (keyfiles);
  }

  if (user_options->truecrypt_keyfiles != NULL)
  {
    char *keyfiles = hcstrdup (user_options->truecrypt_keyfiles);

    char *saveptr = NULL;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    while (keyfile)
    {
      if (hc_path_exist (keyfile) == true)
      {
        if (hc_path_read (keyfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", keyfile, strerror (errno));

          return -1;
        }
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: %s", keyfile, strerror (errno));

        return -1;
      }

      keyfile = strtok_r ((char *) NULL, ",", &saveptr);
    }

    hcfree (keyfiles);
  }

  /**
   * default building options
   */

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (chdir (folder_config->cpath_real) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->cpath_real, strerror (errno));

    return -1;
  }
  */

  // include check
  // this test needs to be done manually because of macOS opencl runtime
  // if there's a problem with permission, its not reporting back and erroring out silently

  const char *files_names[] =
  {
    "inc_cipher_aes.cl",
    "inc_cipher_serpent.cl",
    "inc_cipher_twofish.cl",
    "inc_common.cl",
    "inc_comp_multi_bs.cl",
    "inc_comp_multi.cl",
    "inc_comp_single_bs.cl",
    "inc_comp_single.cl",
    "inc_rp_optimized.cl",
    "inc_rp_optimized.h",
    "inc_simd.cl",
    "inc_scalar.cl",
    "inc_types.h",
    "inc_vendor.h",
    NULL
  };

  for (int i = 0; files_names[i] != NULL; i++)
  {
    char *temp_filename = NULL;

    hc_asprintf (&temp_filename, "%s/%s", folder_config->cpath_real, files_names[i]);

    if (hc_path_read (temp_filename) == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", temp_filename, strerror (errno));

      hcfree (temp_filename);

      return -1;
    }

    hcfree (temp_filename);
  }

  // return back to the folder we came from initially (workaround)

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  #if defined (_WIN)
  if (chdir ("..") == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", "..", strerror (errno));

    return -1;
  }
  #else
  if (chdir (folder_config->cwd) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", folder_config->cwd, strerror (errno));

    return -1;
  }
  #endif
  */

  return 0;
}

void user_options_logger (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;

  #ifdef WITH_BRAIN
  logfile_top_string (user_options->brain_session_whitelist);
  #endif
  logfile_top_string (user_options->encrypt_with_pubkey);
  logfile_top_string (user_options->bridge_parameter1);
  logfile_top_string (user_options->bridge_parameter2);
  logfile_top_string (user_options->bridge_parameter3);
  logfile_top_string (user_options->bridge_parameter4);
  logfile_top_string (user_options->cpu_affinity);
  logfile_top_string (user_options->custom_charset_1);
  logfile_top_string (user_options->custom_charset_2);
  logfile_top_string (user_options->custom_charset_3);
  logfile_top_string (user_options->custom_charset_4);
  logfile_top_string (user_options->custom_charset_5);
  logfile_top_string (user_options->custom_charset_6);
  logfile_top_string (user_options->custom_charset_7);
  logfile_top_string (user_options->custom_charset_8);
  logfile_top_string (user_options->debug_file);
  logfile_top_string (user_options->encoding_from);
  logfile_top_string (user_options->encoding_to);
  logfile_top_string (user_options->induction_dir);
  logfile_top_string (user_options->keyboard_layout_mapping);
  logfile_top_string (user_options->markov_hcstat2);
  logfile_top_string (user_options->backend_devices);
  logfile_top_string (user_options->opencl_device_types);
  logfile_top_string (user_options->outfile);
  logfile_top_string (user_options->outfile_check_dir);
  logfile_top_string (user_options->potfile_path);
  logfile_top_string (user_options->restore_file_path);
  logfile_top_string (user_options->rp_files[0]);
  logfile_top_string (user_options->rp_gen_func_sel);
  logfile_top_string (user_options->rule_buf_l);
  logfile_top_string (user_options->rule_buf_r);
  logfile_top_string (user_options->session);
  logfile_top_string (user_options->separator);
  logfile_top_string (user_options->truecrypt_keyfiles);
  logfile_top_string (user_options->veracrypt_keyfiles);
  #ifdef WITH_BRAIN
  logfile_top_string (user_options->brain_host);
  #endif
  logfile_top_uint64 (user_options->limit);
  logfile_top_uint64 (user_options->skip);
  logfile_top_uint   (user_options->attack_mode);
  logfile_top_uint   (user_options->backend_devices_virtmulti);
  logfile_top_uint   (user_options->backend_devices_virthost);
  logfile_top_uint   (user_options->benchmark);
  logfile_top_uint   (user_options->benchmark_all);
  logfile_top_uint   (user_options->benchmark_max);
  logfile_top_uint   (user_options->benchmark_min);
  logfile_top_uint   (user_options->bitmap_max);
  logfile_top_uint   (user_options->bitmap_min);
  logfile_top_uint   (user_options->debug_mode);
  logfile_top_uint   (user_options->dynamic_x);
  logfile_top_uint   (user_options->hash_info);
  logfile_top_uint   (user_options->force);
  logfile_top_uint   (user_options->hwmon);
  logfile_top_uint   (user_options->hwmon_temp_abort);
  logfile_top_uint   (user_options->hash_mode);
  logfile_top_uint   (user_options->hex_charset);
  logfile_top_uint   (user_options->hex_salt);
  logfile_top_uint   (user_options->hex_wordlist);
  logfile_top_uint   (user_options->hook_threads);
  logfile_top_uint   (user_options->identify);
  logfile_top_uint   (user_options->increment);
  logfile_top_uint   (user_options->increment_max);
  logfile_top_uint   (user_options->increment_min);
  logfile_top_uint   (user_options->keep_guessing);
  logfile_top_uint   (user_options->kernel_accel);
  logfile_top_uint   (user_options->kernel_loops);
  logfile_top_uint   (user_options->kernel_threads);
  logfile_top_uint   (user_options->keyspace);
  logfile_top_uint   (user_options->total_candidates);
  logfile_top_uint   (user_options->left);
  logfile_top_uint   (user_options->logfile);
  logfile_top_uint   (user_options->loopback);
  logfile_top_uint   (user_options->machine_readable);
  logfile_top_uint   (user_options->markov_classic);
  logfile_top_uint   (user_options->markov);
  logfile_top_uint   (user_options->markov_inverse);
  logfile_top_uint   (user_options->markov_threshold);
  logfile_top_uint   (user_options->metal_compiler_runtime);
  logfile_top_uint   (user_options->multiply_accel);
  logfile_top_uint   (user_options->backend_info);
  logfile_top_uint   (user_options->backend_vector_width);
  logfile_top_uint   (user_options->optimized_kernel);
  logfile_top_uint   (user_options->outfile_autohex);
  logfile_top_uint   (user_options->outfile_check_timer);
  logfile_top_uint   (user_options->outfile_format);
  logfile_top_uint   (user_options->outfile_json);
  logfile_top_uint   (user_options->wordlist_autohex);
  logfile_top_uint   (user_options->potfile);
  logfile_top_uint   (user_options->progress_only);
  logfile_top_uint   (user_options->quiet);
  logfile_top_uint   (user_options->remove);
  logfile_top_uint   (user_options->remove_timer);
  logfile_top_uint   (user_options->restore);
  logfile_top_uint   (user_options->restore_enable);
  logfile_top_uint   (user_options->restore_position);
  logfile_top_uint   (user_options->restore_timer);
  logfile_top_uint   (user_options->rp_files_cnt);
  logfile_top_uint   (user_options->rp_gen);
  logfile_top_uint   (user_options->rp_gen_func_max);
  logfile_top_uint   (user_options->rp_gen_func_min);
  logfile_top_uint   (user_options->rp_gen_seed);
  logfile_top_uint   (user_options->runtime);
  logfile_top_uint   (user_options->scrypt_tmto);
  logfile_top_string (user_options->seekdb_path);
  logfile_top_uint   (user_options->self_test);
  logfile_top_uint   (user_options->slow_candidates);
  logfile_top_uint   (user_options->show);
  logfile_top_uint   (user_options->speed_only);
  logfile_top_uint   (user_options->spin_damp);
  logfile_top_uint   (user_options->status);
  logfile_top_uint   (user_options->status_json);
  logfile_top_uint   (user_options->status_timer);
  logfile_top_uint   (user_options->stdout_flag);
  logfile_top_uint   (user_options->usage);
  logfile_top_uint   (user_options->username);
  logfile_top_uint   (user_options->veracrypt_pim_start);
  logfile_top_uint   (user_options->veracrypt_pim_stop);
  logfile_top_uint   (user_options->version);
  logfile_top_uint   (user_options->workload_profile);
  #ifdef WITH_BRAIN
  logfile_top_uint   (user_options->brain_client);
  logfile_top_uint   (user_options->brain_client_features);
  logfile_top_uint   (user_options->brain_server);
  logfile_top_uint   (user_options->brain_server_timer);
  logfile_top_uint   (user_options->brain_port);
  logfile_top_uint   (user_options->brain_session);
  #endif
}
