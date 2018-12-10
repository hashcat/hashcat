/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "logfile.h"
#include "interface.h"
#include "shared.h"
#include "usage.h"
#include "outfile.h"
#include "user_options.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

#ifdef WITH_BRAIN
static const char *short_options = "hVvm:a:r:j:k:g:o:t:d:D:n:u:T:c:p:s:l:1:2:3:4:iIbw:OSz";
#else
static const char *short_options = "hVvm:a:r:j:k:g:o:t:d:D:n:u:T:c:p:s:l:1:2:3:4:iIbw:OS";
#endif

static const struct option long_options[] =
{
  {"advice-disable",            no_argument,       NULL, IDX_ADVICE_DISABLE},
  {"attack-mode",               required_argument, NULL, IDX_ATTACK_MODE},
  {"benchmark-all",             no_argument,       NULL, IDX_BENCHMARK_ALL},
  {"benchmark",                 no_argument,       NULL, IDX_BENCHMARK},
  {"bitmap-max",                required_argument, NULL, IDX_BITMAP_MAX},
  {"bitmap-min",                required_argument, NULL, IDX_BITMAP_MIN},
  {"cpu-affinity",              required_argument, NULL, IDX_CPU_AFFINITY},
  {"custom-charset1",           required_argument, NULL, IDX_CUSTOM_CHARSET_1},
  {"custom-charset2",           required_argument, NULL, IDX_CUSTOM_CHARSET_2},
  {"custom-charset3",           required_argument, NULL, IDX_CUSTOM_CHARSET_3},
  {"custom-charset4",           required_argument, NULL, IDX_CUSTOM_CHARSET_4},
  {"debug-file",                required_argument, NULL, IDX_DEBUG_FILE},
  {"debug-mode",                required_argument, NULL, IDX_DEBUG_MODE},
  {"encoding-from",             required_argument, NULL, IDX_ENCODING_FROM},
  {"encoding-to",               required_argument, NULL, IDX_ENCODING_TO},
  {"example-hashes",            no_argument,       NULL, IDX_EXAMPLE_HASHES},
  {"force",                     no_argument,       NULL, IDX_FORCE},
  {"generate-rules-func-max",   required_argument, NULL, IDX_RP_GEN_FUNC_MAX},
  {"generate-rules-func-min",   required_argument, NULL, IDX_RP_GEN_FUNC_MIN},
  {"generate-rules",            required_argument, NULL, IDX_RP_GEN},
  {"generate-rules-seed",       required_argument, NULL, IDX_RP_GEN_SEED},
  {"hwmon-disable",             no_argument,       NULL, IDX_HWMON_DISABLE},
  {"hwmon-temp-abort",          required_argument, NULL, IDX_HWMON_TEMP_ABORT},
  {"hash-type",                 required_argument, NULL, IDX_HASH_MODE},
  {"hccapx-message-pair",       required_argument, NULL, IDX_HCCAPX_MESSAGE_PAIR},
  {"help",                      no_argument,       NULL, IDX_HELP},
  {"hex-charset",               no_argument,       NULL, IDX_HEX_CHARSET},
  {"hex-salt",                  no_argument,       NULL, IDX_HEX_SALT},
  {"hex-wordlist",              no_argument,       NULL, IDX_HEX_WORDLIST},
  {"increment-max",             required_argument, NULL, IDX_INCREMENT_MAX},
  {"increment-min",             required_argument, NULL, IDX_INCREMENT_MIN},
  {"increment",                 no_argument,       NULL, IDX_INCREMENT},
  {"induction-dir",             required_argument, NULL, IDX_INDUCTION_DIR},
  {"keep-guessing",             no_argument,       NULL, IDX_KEEP_GUESSING},
  {"kernel-accel",              required_argument, NULL, IDX_KERNEL_ACCEL},
  {"kernel-loops",              required_argument, NULL, IDX_KERNEL_LOOPS},
  {"kernel-threads",            required_argument, NULL, IDX_KERNEL_THREADS},
  {"keyboard-layout-mapping",   required_argument, NULL, IDX_KEYBOARD_LAYOUT_MAPPING},
  {"keyspace",                  no_argument,       NULL, IDX_KEYSPACE},
  {"left",                      no_argument,       NULL, IDX_LEFT},
  {"limit",                     required_argument, NULL, IDX_LIMIT},
  {"logfile-disable",           no_argument,       NULL, IDX_LOGFILE_DISABLE},
  {"loopback",                  no_argument,       NULL, IDX_LOOPBACK},
  {"machine-readable",          no_argument,       NULL, IDX_MACHINE_READABLE},
  {"markov-classic",            no_argument,       NULL, IDX_MARKOV_CLASSIC},
  {"markov-disable",            no_argument,       NULL, IDX_MARKOV_DISABLE},
  {"markov-hcstat2",            required_argument, NULL, IDX_MARKOV_HCSTAT2},
  {"markov-threshold",          required_argument, NULL, IDX_MARKOV_THRESHOLD},
  {"nonce-error-corrections",   required_argument, NULL, IDX_NONCE_ERROR_CORRECTIONS},
  {"opencl-devices",            required_argument, NULL, IDX_OPENCL_DEVICES},
  {"opencl-device-types",       required_argument, NULL, IDX_OPENCL_DEVICE_TYPES},
  {"opencl-info",               no_argument,       NULL, IDX_OPENCL_INFO},
  {"opencl-platforms",          required_argument, NULL, IDX_OPENCL_PLATFORMS},
  {"opencl-vector-width",       required_argument, NULL, IDX_OPENCL_VECTOR_WIDTH},
  {"optimized-kernel-enable",   no_argument,       NULL, IDX_OPTIMIZED_KERNEL_ENABLE},
  {"outfile-autohex-disable",   no_argument,       NULL, IDX_OUTFILE_AUTOHEX_DISABLE},
  {"outfile-check-dir",         required_argument, NULL, IDX_OUTFILE_CHECK_DIR},
  {"outfile-check-timer",       required_argument, NULL, IDX_OUTFILE_CHECK_TIMER},
  {"outfile-format",            required_argument, NULL, IDX_OUTFILE_FORMAT},
  {"outfile",                   required_argument, NULL, IDX_OUTFILE},
  {"potfile-disable",           no_argument,       NULL, IDX_POTFILE_DISABLE},
  {"potfile-path",              required_argument, NULL, IDX_POTFILE_PATH},
  {"progress-only",             no_argument,       NULL, IDX_PROGRESS_ONLY},
  {"quiet",                     no_argument,       NULL, IDX_QUIET},
  {"remove",                    no_argument,       NULL, IDX_REMOVE},
  {"remove-timer",              required_argument, NULL, IDX_REMOVE_TIMER},
  {"restore-disable",           no_argument,       NULL, IDX_RESTORE_DISABLE},
  {"restore-file-path",         required_argument, NULL, IDX_RESTORE_FILE_PATH},
  {"restore",                   no_argument,       NULL, IDX_RESTORE},
  {"rule-left",                 required_argument, NULL, IDX_RULE_BUF_L},
  {"rule-right",                required_argument, NULL, IDX_RULE_BUF_R},
  {"rules-file",                required_argument, NULL, IDX_RP_FILE},
  {"runtime",                   required_argument, NULL, IDX_RUNTIME},
  {"scrypt-tmto",               required_argument, NULL, IDX_SCRYPT_TMTO},
  {"segment-size",              required_argument, NULL, IDX_SEGMENT_SIZE},
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
  {"status-timer",              required_argument, NULL, IDX_STATUS_TIMER},
  {"stdout",                    no_argument,       NULL, IDX_STDOUT_FLAG},
  {"stdin-timeout-abort",       required_argument, NULL, IDX_STDIN_TIMEOUT_ABORT},
  {"truecrypt-keyfiles",        required_argument, NULL, IDX_TRUECRYPT_KEYFILES},
  {"username",                  no_argument,       NULL, IDX_USERNAME},
  {"veracrypt-keyfiles",        required_argument, NULL, IDX_VERACRYPT_KEYFILES},
  {"veracrypt-pim",             required_argument, NULL, IDX_VERACRYPT_PIM},
  {"version",                   no_argument,       NULL, IDX_VERSION},
  {"wordlist-autohex-disable",  no_argument,       NULL, IDX_WORDLIST_AUTOHEX_DISABLE},
  {"workload-profile",          required_argument, NULL, IDX_WORKLOAD_PROFILE},
  #ifdef WITH_BRAIN
  {"brain-client",              no_argument,       NULL, IDX_BRAIN_CLIENT},
  {"brain-client-features",     required_argument, NULL, IDX_BRAIN_CLIENT_FEATURES},
  {"brain-server",              no_argument,       NULL, IDX_BRAIN_SERVER},
  {"brain-host",                required_argument, NULL, IDX_BRAIN_HOST},
  {"brain-port",                required_argument, NULL, IDX_BRAIN_PORT},
  {"brain-password",            required_argument, NULL, IDX_BRAIN_PASSWORD},
  {"brain-session",             required_argument, NULL, IDX_BRAIN_SESSION},
  {"brain-session-whitelist",   required_argument, NULL, IDX_BRAIN_SESSION_WHITELIST},
  #endif
  {NULL,                        0,                 NULL, 0 }
};

static const char *ENCODING_FROM = "utf-8";
static const char *ENCODING_TO   = "utf-8";

static const char *RULE_BUF_R = ":";
static const char *RULE_BUF_L = ":";

static const char *DEF_MASK_CS_1 = "?l?d?u";
static const char *DEF_MASK_CS_2 = "?l?d";
static const char *DEF_MASK_CS_3 = "?l?d*!$@_";

int user_options_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  user_options->advice_disable            = ADVICE_DISABLE;
  user_options->attack_mode               = ATTACK_MODE;
  user_options->benchmark_all             = BENCHMARK_ALL;
  user_options->benchmark                 = BENCHMARK;
  user_options->bitmap_max                = BITMAP_MAX;
  user_options->bitmap_min                = BITMAP_MIN;
  #ifdef WITH_BRAIN
  user_options->brain_client              = BRAIN_CLIENT;
  user_options->brain_client_features     = BRAIN_CLIENT_FEATURES;
  user_options->brain_host                = NULL;
  user_options->brain_port                = BRAIN_PORT;
  user_options->brain_server              = BRAIN_SERVER;
  user_options->brain_session             = BRAIN_SESSION;
  user_options->brain_session_whitelist   = NULL;
  #endif
  user_options->cpu_affinity              = NULL;
  user_options->custom_charset_1          = NULL;
  user_options->custom_charset_2          = NULL;
  user_options->custom_charset_3          = NULL;
  user_options->custom_charset_4          = NULL;
  user_options->debug_file                = NULL;
  user_options->debug_mode                = DEBUG_MODE;
  user_options->encoding_from             = ENCODING_FROM;
  user_options->encoding_to               = ENCODING_TO;
  user_options->example_hashes            = EXAMPLE_HASHES;
  user_options->force                     = FORCE;
  user_options->hwmon_disable             = HWMON_DISABLE;
  user_options->hwmon_temp_abort          = HWMON_TEMP_ABORT;
  user_options->hash_mode                 = HASH_MODE;
  user_options->hccapx_message_pair       = HCCAPX_MESSAGE_PAIR;
  user_options->hex_charset               = HEX_CHARSET;
  user_options->hex_salt                  = HEX_SALT;
  user_options->hex_wordlist              = HEX_WORDLIST;
  user_options->increment                 = INCREMENT;
  user_options->increment_max             = INCREMENT_MAX;
  user_options->increment_min             = INCREMENT_MIN;
  user_options->induction_dir             = NULL;
  user_options->keep_guessing             = KEEP_GUESSING;
  user_options->kernel_accel              = KERNEL_ACCEL;
  user_options->kernel_loops              = KERNEL_LOOPS;
  user_options->kernel_threads            = KERNEL_THREADS;
  user_options->keyboard_layout_mapping   = NULL;
  user_options->keyspace                  = KEYSPACE;
  user_options->left                      = LEFT;
  user_options->limit                     = LIMIT;
  user_options->logfile_disable           = LOGFILE_DISABLE;
  user_options->loopback                  = LOOPBACK;
  user_options->machine_readable          = MACHINE_READABLE;
  user_options->markov_classic            = MARKOV_CLASSIC;
  user_options->markov_disable            = MARKOV_DISABLE;
  user_options->markov_hcstat2            = NULL;
  user_options->markov_threshold          = MARKOV_THRESHOLD;
  user_options->nonce_error_corrections   = NONCE_ERROR_CORRECTIONS;
  user_options->opencl_devices            = NULL;
  user_options->opencl_device_types       = NULL;
  user_options->opencl_info               = OPENCL_INFO;
  user_options->opencl_platforms          = NULL;
  user_options->opencl_vector_width       = OPENCL_VECTOR_WIDTH;
  user_options->optimized_kernel_enable   = OPTIMIZED_KERNEL_ENABLE;
  user_options->outfile_autohex           = OUTFILE_AUTOHEX;
  user_options->outfile_check_dir         = NULL;
  user_options->outfile_check_timer       = OUTFILE_CHECK_TIMER;
  user_options->outfile_format            = OUTFILE_FORMAT;
  user_options->outfile                   = NULL;
  user_options->potfile_disable           = POTFILE_DISABLE;
  user_options->potfile_path              = NULL;
  user_options->progress_only             = PROGRESS_ONLY;
  user_options->quiet                     = QUIET;
  user_options->remove                    = REMOVE;
  user_options->remove_timer              = REMOVE_TIMER;
  user_options->restore_disable           = RESTORE_DISABLE;
  user_options->restore_file_path         = NULL;
  user_options->restore                   = RESTORE;
  user_options->restore_timer             = RESTORE_TIMER;
  user_options->rp_gen_func_max           = RP_GEN_FUNC_MAX;
  user_options->rp_gen_func_min           = RP_GEN_FUNC_MIN;
  user_options->rp_gen                    = RP_GEN;
  user_options->rp_gen_seed               = RP_GEN_SEED;
  user_options->rule_buf_l                = RULE_BUF_L;
  user_options->rule_buf_r                = RULE_BUF_R;
  user_options->runtime                   = RUNTIME;
  user_options->scrypt_tmto               = SCRYPT_TMTO;
  user_options->segment_size              = SEGMENT_SIZE;
  user_options->self_test_disable         = SELF_TEST_DISABLE;
  user_options->separator                 = SEPARATOR;
  user_options->session                   = PROGNAME;
  user_options->show                      = SHOW;
  user_options->skip                      = SKIP;
  user_options->slow_candidates           = SLOW_CANDIDATES;
  user_options->speed_only                = SPEED_ONLY;
  user_options->spin_damp                 = SPIN_DAMP;
  user_options->status                    = STATUS;
  user_options->status_timer              = STATUS_TIMER;
  user_options->stdin_timeout_abort       = STDIN_TIMEOUT_ABORT;
  user_options->stdout_flag               = STDOUT_FLAG;
  user_options->truecrypt_keyfiles        = NULL;
  user_options->usage                     = USAGE;
  user_options->username                  = USERNAME;
  user_options->veracrypt_keyfiles        = NULL;
  user_options->veracrypt_pim             = 0;
  user_options->version                   = VERSION;
  user_options->wordlist_autohex_disable  = WORDLIST_AUTOHEX_DISABLE;
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

  //do not reset this, it might be used from main.c
  //memset (user_options, 0, sizeof (user_options_t));
}

int user_options_getopt (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  int c = -1;

  int option_index;

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
      case IDX_ATTACK_MODE:
      case IDX_RP_GEN:
      case IDX_RP_GEN_FUNC_MIN:
      case IDX_RP_GEN_FUNC_MAX:
      case IDX_RP_GEN_SEED:
      case IDX_MARKOV_THRESHOLD:
      case IDX_OUTFILE_FORMAT:
      case IDX_OUTFILE_CHECK_TIMER:
      case IDX_OPENCL_VECTOR_WIDTH:
      case IDX_WORKLOAD_PROFILE:
      case IDX_KERNEL_ACCEL:
      case IDX_KERNEL_LOOPS:
      case IDX_KERNEL_THREADS:
      case IDX_SPIN_DAMP:
      case IDX_HWMON_TEMP_ABORT:
      case IDX_HCCAPX_MESSAGE_PAIR:
      case IDX_NONCE_ERROR_CORRECTIONS:
      case IDX_VERACRYPT_PIM:
      case IDX_SEGMENT_SIZE:
      case IDX_SCRYPT_TMTO:
      case IDX_BITMAP_MIN:
      case IDX_BITMAP_MAX:
      case IDX_INCREMENT_MIN:
      case IDX_INCREMENT_MAX:
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
      case IDX_HELP:                      user_options->usage                     = true;                            break;
      case IDX_VERSION:                   user_options->version                   = true;                            break;
      case IDX_RESTORE:                   user_options->restore                   = true;                            break;
      case IDX_QUIET:                     user_options->quiet                     = true;                            break;
      case IDX_SHOW:                      user_options->show                      = true;                            break;
      case IDX_LEFT:                      user_options->left                      = true;                            break;
      case IDX_ADVICE_DISABLE:            user_options->advice_disable            = true;                            break;
      case IDX_USERNAME:                  user_options->username                  = true;                            break;
      case IDX_REMOVE:                    user_options->remove                    = true;                            break;
      case IDX_REMOVE_TIMER:              user_options->remove_timer              = hc_strtoul (optarg, NULL, 10);
                                          user_options->remove_timer_chgd         = true;                            break;
      case IDX_POTFILE_DISABLE:           user_options->potfile_disable           = true;                            break;
      case IDX_POTFILE_PATH:              user_options->potfile_path              = optarg;                          break;
      case IDX_DEBUG_MODE:                user_options->debug_mode                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_DEBUG_FILE:                user_options->debug_file                = optarg;                          break;
      case IDX_ENCODING_FROM:             user_options->encoding_from             = optarg;                          break;
      case IDX_ENCODING_TO:               user_options->encoding_to               = optarg;                          break;
      case IDX_INDUCTION_DIR:             user_options->induction_dir             = optarg;                          break;
      case IDX_OUTFILE_CHECK_DIR:         user_options->outfile_check_dir         = optarg;                          break;
      case IDX_EXAMPLE_HASHES:            user_options->example_hashes            = true;                            break;
      case IDX_FORCE:                     user_options->force                     = true;                            break;
      case IDX_SELF_TEST_DISABLE:         user_options->self_test_disable         = true;                            break;
      case IDX_SKIP:                      user_options->skip                      = hc_strtoull (optarg, NULL, 10);
                                          user_options->skip_chgd                 = true;                            break;
      case IDX_LIMIT:                     user_options->limit                     = hc_strtoull (optarg, NULL, 10);
                                          user_options->limit_chgd                = true;                            break;
      case IDX_KEEP_GUESSING:             user_options->keep_guessing             = true;                            break;
      case IDX_KEYSPACE:                  user_options->keyspace                  = true;                            break;
      case IDX_BENCHMARK:                 user_options->benchmark                 = true;                            break;
      case IDX_BENCHMARK_ALL:             user_options->benchmark_all             = true;                            break;
      case IDX_STDOUT_FLAG:               user_options->stdout_flag               = true;                            break;
      case IDX_STDIN_TIMEOUT_ABORT:       user_options->stdin_timeout_abort       = hc_strtoul (optarg, NULL, 10);
                                          user_options->stdin_timeout_abort_chgd  = true;                            break;
      case IDX_SPEED_ONLY:                user_options->speed_only                = true;                            break;
      case IDX_PROGRESS_ONLY:             user_options->progress_only             = true;                            break;
      case IDX_RESTORE_DISABLE:           user_options->restore_disable           = true;                            break;
      case IDX_RESTORE_FILE_PATH:         user_options->restore_file_path         = optarg;                          break;
      case IDX_STATUS:                    user_options->status                    = true;                            break;
      case IDX_STATUS_TIMER:              user_options->status_timer              = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_MACHINE_READABLE:          user_options->machine_readable          = true;                            break;
      case IDX_LOOPBACK:                  user_options->loopback                  = true;                            break;
      case IDX_SESSION:                   user_options->session                   = optarg;                          break;
      case IDX_HASH_MODE:                 user_options->hash_mode                 = hc_strtoul (optarg, NULL, 10);
                                          user_options->hash_mode_chgd            = true;                            break;
      case IDX_RUNTIME:                   user_options->runtime                   = hc_strtoul (optarg, NULL, 10);
                                          user_options->runtime_chgd              = true;                            break;
      case IDX_ATTACK_MODE:               user_options->attack_mode               = hc_strtoul (optarg, NULL, 10);
                                          user_options->attack_mode_chgd          = true;                            break;
      case IDX_RP_FILE:                   user_options->rp_files[user_options->rp_files_cnt++] = optarg;             break;
      case IDX_RP_GEN:                    user_options->rp_gen                    = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_FUNC_MIN:           user_options->rp_gen_func_min           = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_FUNC_MAX:           user_options->rp_gen_func_max           = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_RP_GEN_SEED:               user_options->rp_gen_seed               = hc_strtoul (optarg, NULL, 10);
                                          user_options->rp_gen_seed_chgd          = true;                            break;
      case IDX_RULE_BUF_L:                user_options->rule_buf_l                = optarg;                          break;
      case IDX_RULE_BUF_R:                user_options->rule_buf_r                = optarg;                          break;
      case IDX_MARKOV_DISABLE:            user_options->markov_disable            = true;                            break;
      case IDX_MARKOV_CLASSIC:            user_options->markov_classic            = true;                            break;
      case IDX_MARKOV_THRESHOLD:          user_options->markov_threshold          = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_MARKOV_HCSTAT2:            user_options->markov_hcstat2            = optarg;                          break;
      case IDX_OUTFILE:                   user_options->outfile                   = optarg;                          break;
      case IDX_OUTFILE_FORMAT:            user_options->outfile_format            = hc_strtoul (optarg, NULL, 10);
                                          user_options->outfile_format_chgd       = true;                            break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:   user_options->outfile_autohex           = false;                           break;
      case IDX_OUTFILE_CHECK_TIMER:       user_options->outfile_check_timer       = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_WORDLIST_AUTOHEX_DISABLE:  user_options->wordlist_autohex_disable  = true;                            break;
      case IDX_HEX_CHARSET:               user_options->hex_charset               = true;                            break;
      case IDX_HEX_SALT:                  user_options->hex_salt                  = true;                            break;
      case IDX_HEX_WORDLIST:              user_options->hex_wordlist              = true;                            break;
      case IDX_CPU_AFFINITY:              user_options->cpu_affinity              = optarg;                          break;
      case IDX_OPENCL_INFO:               user_options->opencl_info               = true;                            break;
      case IDX_OPENCL_DEVICES:            user_options->opencl_devices            = optarg;                          break;
      case IDX_OPENCL_PLATFORMS:          user_options->opencl_platforms          = optarg;                          break;
      case IDX_OPENCL_DEVICE_TYPES:       user_options->opencl_device_types       = optarg;                          break;
      case IDX_OPENCL_VECTOR_WIDTH:       user_options->opencl_vector_width       = hc_strtoul (optarg, NULL, 10);
                                          user_options->opencl_vector_width_chgd  = true;                            break;
      case IDX_OPTIMIZED_KERNEL_ENABLE:   user_options->optimized_kernel_enable   = true;                            break;
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
      case IDX_HWMON_DISABLE:             user_options->hwmon_disable             = true;                            break;
      case IDX_HWMON_TEMP_ABORT:          user_options->hwmon_temp_abort          = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_LOGFILE_DISABLE:           user_options->logfile_disable           = true;                            break;
      case IDX_HCCAPX_MESSAGE_PAIR:       user_options->hccapx_message_pair       = hc_strtoul (optarg, NULL, 10);
                                          user_options->hccapx_message_pair_chgd  = true;                            break;
      case IDX_NONCE_ERROR_CORRECTIONS:   user_options->nonce_error_corrections   = hc_strtoul (optarg, NULL, 10);
                                          user_options->nonce_error_corrections_chgd = true;                         break;
      case IDX_KEYBOARD_LAYOUT_MAPPING:   user_options->keyboard_layout_mapping   = optarg;                          break;
      case IDX_TRUECRYPT_KEYFILES:        user_options->truecrypt_keyfiles        = optarg;                          break;
      case IDX_VERACRYPT_KEYFILES:        user_options->veracrypt_keyfiles        = optarg;                          break;
      case IDX_VERACRYPT_PIM:             user_options->veracrypt_pim             = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_SEGMENT_SIZE:              user_options->segment_size              = hc_strtoul (optarg, NULL, 10);
                                          user_options->segment_size_chgd         = true;                            break;
      case IDX_SCRYPT_TMTO:               user_options->scrypt_tmto               = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_SEPARATOR:                 user_options->separator                 = optarg[0];                       break;
      case IDX_BITMAP_MIN:                user_options->bitmap_min                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BITMAP_MAX:                user_options->bitmap_max                = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_INCREMENT:                 user_options->increment                 = true;                            break;
      case IDX_INCREMENT_MIN:             user_options->increment_min             = hc_strtoul (optarg, NULL, 10);
                                          user_options->increment_min_chgd        = true;                            break;
      case IDX_INCREMENT_MAX:             user_options->increment_max             = hc_strtoul (optarg, NULL, 10);
                                          user_options->increment_max_chgd        = true;                            break;
      case IDX_CUSTOM_CHARSET_1:          user_options->custom_charset_1          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_2:          user_options->custom_charset_2          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_3:          user_options->custom_charset_3          = optarg;                          break;
      case IDX_CUSTOM_CHARSET_4:          user_options->custom_charset_4          = optarg;                          break;
      case IDX_SLOW_CANDIDATES:           user_options->slow_candidates           = true;                            break;
      #ifdef WITH_BRAIN
      case IDX_BRAIN_CLIENT:              user_options->brain_client              = true;                            break;
      case IDX_BRAIN_CLIENT_FEATURES:     user_options->brain_client_features     = hc_strtoul (optarg, NULL, 10);   break;
      case IDX_BRAIN_SERVER:              user_options->brain_server              = true;                            break;
      case IDX_BRAIN_PASSWORD:            user_options->brain_password            = optarg;
                                          user_options->brain_password_chgd       = true;                            break;
      case IDX_BRAIN_HOST:                user_options->brain_host                = optarg;
                                          user_options->brain_host_chgd           = true;                            break;
      case IDX_BRAIN_PORT:                user_options->brain_port                = hc_strtoul (optarg, NULL, 10);
                                          user_options->brain_port_chgd           = true;                            break;
      case IDX_BRAIN_SESSION:             user_options->brain_session             = hc_strtoul (optarg, NULL, 16);   break;
      case IDX_BRAIN_SESSION_WHITELIST:   user_options->brain_session_whitelist   = optarg;                          break;
      #endif
    }
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

  #ifdef WITH_BRAIN
  if ((user_options->brain_client == true) && (user_options->brain_server == true))
  {
    event_log_error (hashcat_ctx, "Can not have --brain-client and --brain-server at the same time");

    return -1;
  }

  if ((user_options->brain_client_features < 1) || (user_options->brain_client_features > 3))
  {
    event_log_error (hashcat_ctx, "Invalid --brain-client-feature argument");

    return -1;
  }

  if ((user_options->brain_client == true) && (user_options->brain_password_chgd == false))
  {
    event_log_error (hashcat_ctx, "Brain clients need to set --brain-password");

    return -1;
  }
  #endif

  if (user_options->slow_candidates == true)
  {
    if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT)
     && (user_options->attack_mode != ATTACK_MODE_COMBI)
     && (user_options->attack_mode != ATTACK_MODE_BF))
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
     && (user_options->attack_mode != ATTACK_MODE_BF))
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

  if (user_options->runtime_chgd == true && user_options->loopback == true)
  {
    event_log_error (hashcat_ctx, "Combining --limit with --loopback is not allowed.");

    return -1;
  }

  if (user_options->hash_mode > 99999)
  {
    event_log_error (hashcat_ctx, "Invalid -m (hash type) value specified.");

    return -1;
  }

  if (user_options->username == true)
  {
    if  ((user_options->hash_mode ==  2500)
     ||  (user_options->hash_mode ==  2501)
     ||  (user_options->hash_mode ==  5200)
     || ((user_options->hash_mode >=  6200) && (user_options->hash_mode <=  6299))
     || ((user_options->hash_mode >= 13700) && (user_options->hash_mode <= 13799))
     ||  (user_options->hash_mode ==  9000))
    {
      event_log_error (hashcat_ctx, "Combining --username with hashes of type %s is not supported.", strhashtype (user_options->hash_mode));

      return -1;
    }
  }

  if (user_options->outfile_format > 16)
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
      if (user_options->outfile_format > 7)
      {
        event_log_error (hashcat_ctx, "Combining --outfile-format > 7 with --show is not allowed.");

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

  if (user_options->increment_min > user_options->increment_max)
  {
    event_log_error (hashcat_ctx, "Invalid --increment-min value specified - must be >= --increment-max.");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->progress_only == true))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in combination with --progress-only.");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->speed_only == true))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in combination with --speed-only.");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->attack_mode == ATTACK_MODE_STRAIGHT))
  {
    event_log_error (hashcat_ctx, "Increment is not allowed in attack mode 0 (straight).");

    return -1;
  }

  if ((user_options->increment == false) && (user_options->increment_min_chgd == true))
  {
    event_log_error (hashcat_ctx, "Increment-min is only supported when combined with -i/--increment.");

    return -1;
  }

  if ((user_options->increment == false) && (user_options->increment_max_chgd == true))
  {
    event_log_error (hashcat_ctx, "Increment-max is only supported combined with -i/--increment.");

    return -1;
  }

  if ((user_options->rp_files_cnt > 0) && (user_options->rp_gen > 0))
  {
    event_log_error (hashcat_ctx, "Combining -r/--rules-file and -g/--rules-generate is not supported.");

    return -1;
  }

  if ((user_options->rp_files_cnt > 0) || (user_options->rp_gen > 0))
  {
    if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
    {
      event_log_error (hashcat_ctx, "Use of -r/--rules-file and -g/--rules-generate only allowed in attack mode 0.");

      return -1;
    }
  }

  if (user_options->bitmap_min > user_options->bitmap_max)
  {
    event_log_error (hashcat_ctx, "Invalid --bitmap-min value specified.");

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

    if (user_options->kernel_accel > 1024)
    {
      event_log_error (hashcat_ctx, "Invalid --kernel-accel value specified - must be <= 1024.");

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

    if (user_options->kernel_loops > 1024)
    {
      event_log_error (hashcat_ctx, "Invalid kernel-loops specified.");

      return -1;
    }
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

  if (user_options->opencl_vector_width_chgd == true)
  {
    if (is_power_of_2 (user_options->opencl_vector_width) == false || user_options->opencl_vector_width > 16)
    {
      event_log_error (hashcat_ctx, "opencl-vector-width %u is not allowed.", user_options->opencl_vector_width);

      return -1;
    }
  }

  if (user_options->show == true || user_options->left == true)
  {
    if (user_options->remove == true)
    {
      event_log_error (hashcat_ctx, "Mixing --remove not allowed with --show or --left.");

      return -1;
    }

    if (user_options->potfile_disable == true)
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
  }

  if (user_options->remove_timer_chgd == true)
  {
    if (user_options->remove == false)
    {
      event_log_error (hashcat_ctx, "The --remove-timer requires --remove.");

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
        event_log_error (hashcat_ctx, "Parameter --loopback not allowed without -r/--rules-file or -g/--rules-generate.");

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
    if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
    {
      event_log_error (hashcat_ctx, "Parameter --debug-mode option is only allowed in attack mode 0 (straight).");

      return -1;
    }

    if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
    {
      event_log_error (hashcat_ctx, "Use of --debug-mode requires -r/--rules-file or -g/--rules-generate.");

      return -1;
    }
  }

  if (user_options->debug_mode > 4)
  {
    event_log_error (hashcat_ctx, "Invalid --debug-mode value specified.");

    return -1;
  }

  if (user_options->debug_file != NULL)
  {
    if (user_options->debug_mode < 1)
    {
      event_log_error (hashcat_ctx, "Parameter --debug-file requires --debug-mode.");

      return -1;
    }
  }

  if (user_options->induction_dir != NULL)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      event_log_error (hashcat_ctx, "Use of --induction-dir is not allowed in attack mode 3 (brute-force).");

      return -1;
    }
  }

  if (user_options->spin_damp > 100)
  {
    event_log_error (hashcat_ctx, "Values of --spin-damp must be between 0 and 100 (inclusive).");

    return -1;
  }

  if ((user_options->spin_damp_chgd == true) && (user_options->benchmark == true))
  {
    event_log_error (hashcat_ctx, "Values of --spin-damp cannot be used in combination with --benchmark.");

    return -1;
  }

  if (user_options->benchmark == true)
  {
    if (user_options->attack_mode_chgd == true)
    {
      if (user_options->attack_mode != ATTACK_MODE_BF)
      {
        event_log_error (hashcat_ctx, "Benchmark mode is only allowed in attack mode 3 (brute-force).");

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

  if (user_options->restore_file_path != NULL)
  {
    if (strlen (user_options->restore_file_path) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --restore-file-path value - must not be empty.");

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

  if (user_options->cpu_affinity != NULL)
  {
    if (strlen (user_options->cpu_affinity) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --cpu-affinity value - must not be empty.");

      return -1;
    }
  }

  if (user_options->opencl_platforms != NULL)
  {
    if (strlen (user_options->opencl_platforms) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --opencl-platforms value - must not be empty.");

      return -1;
    }
  }

  if (user_options->opencl_devices != NULL)
  {
    if (strlen (user_options->opencl_devices) == 0)
    {
      event_log_error (hashcat_ctx, "Invalid --opencl-devices value - must not be empty.");

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

    if (user_options->hc_argc != 1)
    {
      event_log_error (hashcat_ctx, "Use of --stdin-timeout-abort is only allowed in stdin mode (pipe).");

      return -1;
    }
  }

  #ifdef WITH_BRAIN
  if ((user_options->brain_client == true) && (user_options->remove == true))
  {
    event_log_error (hashcat_ctx, "Using --remove is not allowed if --brain-client is used.");

    return -1;
  }

  if ((user_options->brain_client == true) && (user_options->potfile_disable == true))
  {
    event_log_error (hashcat_ctx, "Using --potfile-disable is not allowed if --brain-client is used.");

    return -1;
  }
  #endif

  // custom charset checks

  if ((user_options->custom_charset_1 != NULL)
   || (user_options->custom_charset_2 != NULL)
   || (user_options->custom_charset_3 != NULL)
   || (user_options->custom_charset_4 != NULL))
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

    // detect if mask was specified:

    bool mask_is_missing = true;

    if (user_options->keyspace == true) // special case if --keyspace was used: we need the mask but no hash file
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

  // argc / argv checks

  bool show_error = true;

  if (user_options->version == true)
  {
    show_error = false;
  }
  else if (user_options->usage == true)
  {
    show_error = false;
  }
  #ifdef WITH_BRAIN
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
  else if (user_options->example_hashes == true)
  {
    if (user_options->hc_argc == 0)
    {
      show_error = false;
    }
  }
  else if (user_options->opencl_info == true)
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
  else if (user_options->keyspace == true)
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options->hc_argc == 1)
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
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      if (user_options->hc_argc == 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (user_options->hc_argc == 2)
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
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      if (user_options->hc_argc >= 1)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
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
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      if (user_options->hc_argc >= 2)
      {
        show_error = false;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (user_options->hc_argc >= 2)
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

    if (user_options->example_hashes == true)
    {
      user_options->session = "example_hashes";
    }

    if (user_options->speed_only == true)
    {
      user_options->session = "speed_only";
    }

    if (user_options->progress_only == true)
    {
      user_options->session = "progress_only";
    }

    if (user_options->keyspace == true)
    {
      user_options->session = "keyspace";
    }

    if (user_options->stdout_flag == true)
    {
      user_options->session = "stdout";
    }

    if (user_options->opencl_info == true)
    {
      user_options->session = "opencl_info";
    }

    if (user_options->show == true)
    {
      user_options->session = "show";
    }

    if (user_options->left == true)
    {
      user_options->session = "left";
    }
  }
}

void user_options_preprocess (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // some options can influence or overwrite other options

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    user_options->slow_candidates = true;
  }
  #endif

  if (user_options->stdout_flag)
  {
    user_options->hwmon_disable       = true;
    user_options->left                = false;
    user_options->logfile_disable     = true;
    user_options->spin_damp           = 0;
    user_options->outfile_check_timer = 0;
    user_options->potfile_disable     = true;
    user_options->restore_disable     = true;
    user_options->restore             = false;
    user_options->restore_timer       = 0;
    user_options->show                = false;
    user_options->status              = false;
    user_options->status_timer        = 0;
    user_options->bitmap_min          = 1;
    user_options->bitmap_max          = 1;
  }

  if (user_options->example_hashes  == true
   || user_options->opencl_info     == true
   || user_options->keyspace        == true
   || user_options->speed_only      == true
   || user_options->progress_only   == true)
  {
    user_options->hwmon_disable       = true;
    user_options->left                = false;
    user_options->logfile_disable     = true;
    user_options->spin_damp           = 0;
    user_options->outfile_check_timer = 0;
    user_options->potfile_disable     = true;
    user_options->restore_disable     = true;
    user_options->restore             = false;
    user_options->restore_timer       = 0;
    user_options->show                = false;
    user_options->status              = false;
    user_options->status_timer        = 0;
    user_options->bitmap_min          = 1;
    user_options->bitmap_max          = 1;
    #ifdef WITH_BRAIN
    user_options->brain_client        = false;
    #endif
  }

  if (user_options->benchmark == true)
  {
    user_options->attack_mode         = ATTACK_MODE_BF;
    user_options->hwmon_temp_abort    = 0;
    user_options->increment           = false;
    user_options->left                = false;
    user_options->logfile_disable     = true;
    user_options->spin_damp           = 0;
    user_options->potfile_disable     = true;
    user_options->progress_only       = false;
    user_options->restore_disable     = true;
    user_options->restore             = false;
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
      user_options->optimized_kernel_enable = true;
      user_options->workload_profile        = 3;
    }
  }

  if (user_options->example_hashes == true)
  {
    user_options->quiet = true;
  }

  if (user_options->progress_only == true)
  {
    user_options->speed_only = true;
  }

  if (user_options->keyspace == true)
  {
    user_options->quiet = true;
  }

  if (user_options->slow_candidates == true)
  {
    user_options->opencl_vector_width = 1;
  }

  if (user_options->stdout_flag == true)
  {
    user_options->force               = true;
    user_options->hash_mode           = 2000;
    user_options->kernel_accel        = 1024;
    user_options->opencl_vector_width = 1;
    user_options->outfile_format      = OUTFILE_FMT_PLAIN;
    user_options->quiet               = true;

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
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      user_options->kernel_loops = KERNEL_COMBS;
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      user_options->kernel_loops = KERNEL_COMBS;
    }
  }

  if (user_options->opencl_info == true)
  {
    user_options->opencl_devices      = NULL;
    user_options->opencl_device_types = hcstrdup ("1,2,3");
    user_options->opencl_platforms    = NULL;
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
    user_options->restore_disable = true;

    user_options->restore = false;
  }

  if (user_options->skip != 0 && user_options->limit != 0)
  {
    user_options->limit += user_options->skip;
  }

  if (user_options->hash_mode == 9710)
  {
    user_options->outfile_format      = 5;
    user_options->outfile_format_chgd = 1;
  }

  if (user_options->hash_mode == 9810)
  {
    user_options->outfile_format      = 5;
    user_options->outfile_format_chgd = 1;
  }

  if (user_options->hash_mode == 10410)
  {
    user_options->outfile_format      = 5;
    user_options->outfile_format_chgd = 1;
  }

  if (user_options->markov_threshold == 0)
  {
    user_options->markov_threshold = 0x100;
  }

  if (user_options->segment_size_chgd == true)
  {
    user_options->segment_size *= (1024 * 1024);
  }

  #if !defined (WITH_HWMON)
  user_options->hwmon_disable = true;
  #endif // WITH_HWMON

  if (user_options->hwmon_disable == true)
  {
    user_options->hwmon_temp_abort = 0;
  }

  // default mask

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->example_hashes == true)
    {

    }
    else if (user_options->opencl_info == true)
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

        user_options->increment = true;
      }
    }
    else if (user_options->stdout_flag == true)
    {
      if (user_options->hc_argc == 0)
      {
        user_options->custom_charset_1 = DEF_MASK_CS_1;
        user_options->custom_charset_2 = DEF_MASK_CS_2;
        user_options->custom_charset_3 = DEF_MASK_CS_3;

        user_options->increment = true;
      }
    }
    else
    {
      if (user_options->hc_argc == 1)
      {
        user_options->custom_charset_1 = DEF_MASK_CS_1;
        user_options->custom_charset_2 = DEF_MASK_CS_2;
        user_options->custom_charset_3 = DEF_MASK_CS_3;

        user_options->increment = true;
      }
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

    if (user_options->force == true)
    {
      event_log_info (hashcat_ctx, "* --force");
    }

    if (user_options->opencl_devices)
    {
      event_log_info (hashcat_ctx, "* --opencl-devices=%s", user_options->opencl_devices);
    }

    if (user_options->opencl_device_types)
    {
      event_log_info (hashcat_ctx, "* --opencl-device-types=%s", user_options->opencl_device_types);
    }

    if (user_options->opencl_platforms)
    {
      event_log_info (hashcat_ctx, "* --opencl-platforms=%s", user_options->opencl_platforms);
    }

    if (user_options->optimized_kernel_enable == true)
    {
      event_log_info (hashcat_ctx, "* --optimized-kernel-enable");
    }

    if (user_options->opencl_vector_width_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --opencl-vector-width=%u", user_options->opencl_vector_width);
    }

    if (user_options->kernel_accel_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-accel=%u", user_options->kernel_accel);
    }
    else if (user_options->kernel_loops_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-loops=%u", user_options->kernel_loops);
    }
    else if (user_options->kernel_threads_chgd == true)
    {
      event_log_info (hashcat_ctx, "* --kernel-threads=%u", user_options->kernel_threads);
    }
    else
    {
      if (user_options->workload_profile_chgd == true)
      {
        event_log_info (hashcat_ctx, "* --workload-profile=%u", user_options->workload_profile);
      }
    }

    event_log_info (hashcat_ctx, NULL);
  }
  else
  {
    if (user_options->benchmark_all == true)
    {
      event_log_info (hashcat_ctx, "# option: --benchmark-all");
    }

    if (user_options->force == true)
    {
      event_log_info (hashcat_ctx, "# option: --force");
    }

    if (user_options->opencl_devices)
    {
      event_log_info (hashcat_ctx, "# option: --opencl-devices=%s", user_options->opencl_devices);
    }

    if (user_options->opencl_device_types)
    {
      event_log_info (hashcat_ctx, "# option: --opencl-device-types=%s", user_options->opencl_device_types);
    }

    if (user_options->opencl_platforms)
    {
      event_log_info (hashcat_ctx, "* option: --opencl-platforms=%s", user_options->opencl_platforms);
    }

    if (user_options->optimized_kernel_enable == true)
    {
      event_log_info (hashcat_ctx, "# option: --optimized-kernel-enable");
    }

    if (user_options->opencl_vector_width_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --opencl-vector-width=%u", user_options->opencl_vector_width);
    }

    if (user_options->kernel_accel_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-accel=%u", user_options->kernel_accel);
    }
    else if (user_options->kernel_loops_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-loops=%u", user_options->kernel_loops);
    }
    else if (user_options->kernel_threads_chgd == true)
    {
      event_log_info (hashcat_ctx, "# option: --kernel-threads=%u", user_options->kernel_threads);
    }
    else
    {
      if (user_options->workload_profile_chgd == true)
      {
        event_log_info (hashcat_ctx, "# option: --workload-profile=%u", user_options->workload_profile);
      }
    }
  }
}

void user_options_extra_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // attack-kern

  user_options_extra->attack_kern = ATTACK_KERN_NONE;

  switch (user_options->attack_mode)
  {
    case ATTACK_MODE_STRAIGHT: user_options_extra->attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_COMBI:    user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_BF:       user_options_extra->attack_kern = ATTACK_KERN_BF;       break;
    case ATTACK_MODE_HYBRID1:  user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID2:  user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
  }

  // rules

  user_options_extra->rule_len_l = (int) strlen (user_options->rule_buf_l);
  user_options_extra->rule_len_r = (int) strlen (user_options->rule_buf_r);

  // hc_hash and hc_work*

  user_options_extra->hc_hash  = NULL;
  user_options_extra->hc_workv = NULL;
  user_options_extra->hc_workc = 0;

  if (user_options->benchmark == true)
  {

  }
  else if (user_options->example_hashes == true)
  {

  }
  else if (user_options->opencl_info == true)
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

  // wordlist_mode

  user_options_extra->wordlist_mode = WL_MODE_NONE;

  if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
  {
    user_options_extra->wordlist_mode = (user_options_extra->hc_workc >= 1) ? WL_MODE_FILE : WL_MODE_STDIN;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
  {
    user_options_extra->wordlist_mode = WL_MODE_FILE;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    user_options_extra->wordlist_mode = WL_MODE_MASK;
  }
}

void user_options_extra_destroy (hashcat_ctx_t *hashcat_ctx)
{
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  memset (user_options_extra, 0, sizeof (user_options_extra_t));
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
  else
  {
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
  }

  return 1;
}

int user_options_check_files (hashcat_ctx_t *hashcat_ctx)
{
  dictstat_ctx_t       *dictstat_ctx       = hashcat_ctx->dictstat_ctx;
  folder_config_t      *folder_config      = hashcat_ctx->folder_config;
  logfile_ctx_t        *logfile_ctx        = hashcat_ctx->logfile_ctx;
  outcheck_ctx_t       *outcheck_ctx       = hashcat_ctx->outcheck_ctx;
  outfile_ctx_t        *outfile_ctx        = hashcat_ctx->outfile_ctx;
  pidfile_ctx_t        *pidfile_ctx        = hashcat_ctx->pidfile_ctx;
  potfile_ctx_t        *potfile_ctx        = hashcat_ctx->potfile_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

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
        event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", user_options_extra->hc_hash);

        return -1;
      }
    }
  }

  // arguments - checks must depend on attack_mode

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
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
        event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", rp_file);

        return -1;
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
        event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dictfile1);

        return -1;
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
        event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dictfile2);

        return -1;
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
          event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

          return -1;
        }
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (user_options_extra->hc_workc == 2)
    {
      char *wlfile = user_options_extra->hc_workv[0];

      char *maskfile = user_options_extra->hc_workv[1];

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
          event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

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
          event_log_error (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", maskfile);

          return -1;
        }
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

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
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

  // dictstat

  if (dictstat_ctx->enabled == true)
  {
    if (hc_path_exist (dictstat_ctx->filename) == true)
    {
      if (hc_path_is_directory (dictstat_ctx->filename) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a dictstat argument.", dictstat_ctx->filename);

        return -1;
      }

      if (hc_path_write (dictstat_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictstat_ctx->filename, strerror (errno));

        return -1;
      }
    }
    else
    {
      if (hc_path_create (dictstat_ctx->filename) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictstat_ctx->filename, strerror (errno));

        return -1;
      }
    }
  }

  // loopback - can't check at this point

  // tuning file check already done

  // debugfile check already done

  // dictstat

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

  return 0;
}

void user_options_logger (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;

  logfile_top_char   (user_options->separator);
  #ifdef WITH_BRAIN
  logfile_top_string (user_options->brain_session_whitelist);
  #endif
  logfile_top_string (user_options->cpu_affinity);
  logfile_top_string (user_options->custom_charset_1);
  logfile_top_string (user_options->custom_charset_2);
  logfile_top_string (user_options->custom_charset_3);
  logfile_top_string (user_options->custom_charset_4);
  logfile_top_string (user_options->debug_file);
  logfile_top_string (user_options->encoding_from);
  logfile_top_string (user_options->encoding_to);
  logfile_top_string (user_options->induction_dir);
  logfile_top_string (user_options->keyboard_layout_mapping);
  logfile_top_string (user_options->markov_hcstat2);
  logfile_top_string (user_options->opencl_devices);
  logfile_top_string (user_options->opencl_device_types);
  logfile_top_string (user_options->opencl_platforms);
  logfile_top_string (user_options->outfile);
  logfile_top_string (user_options->outfile_check_dir);
  logfile_top_string (user_options->potfile_path);
  logfile_top_string (user_options->restore_file_path);
  logfile_top_string (user_options->rp_files[0]);
  logfile_top_string (user_options->rule_buf_l);
  logfile_top_string (user_options->rule_buf_r);
  logfile_top_string (user_options->session);
  logfile_top_string (user_options->truecrypt_keyfiles);
  logfile_top_string (user_options->veracrypt_keyfiles);
  #ifdef WITH_BRAIN
  logfile_top_string (user_options->brain_host);
  #endif
  logfile_top_uint64 (user_options->limit);
  logfile_top_uint64 (user_options->skip);
  logfile_top_uint   (user_options->attack_mode);
  logfile_top_uint   (user_options->benchmark);
  logfile_top_uint   (user_options->benchmark_all);
  logfile_top_uint   (user_options->bitmap_max);
  logfile_top_uint   (user_options->bitmap_min);
  logfile_top_uint   (user_options->debug_mode);
  logfile_top_uint   (user_options->example_hashes);
  logfile_top_uint   (user_options->force);
  logfile_top_uint   (user_options->hwmon_disable);
  logfile_top_uint   (user_options->hwmon_temp_abort);
  logfile_top_uint   (user_options->hash_mode);
  logfile_top_uint   (user_options->hex_charset);
  logfile_top_uint   (user_options->hex_salt);
  logfile_top_uint   (user_options->hex_wordlist);
  logfile_top_uint   (user_options->increment);
  logfile_top_uint   (user_options->increment_max);
  logfile_top_uint   (user_options->increment_min);
  logfile_top_uint   (user_options->keep_guessing);
  logfile_top_uint   (user_options->kernel_accel);
  logfile_top_uint   (user_options->kernel_loops);
  logfile_top_uint   (user_options->kernel_threads);
  logfile_top_uint   (user_options->keyspace);
  logfile_top_uint   (user_options->left);
  logfile_top_uint   (user_options->logfile_disable);
  logfile_top_uint   (user_options->loopback);
  logfile_top_uint   (user_options->machine_readable);
  logfile_top_uint   (user_options->markov_classic);
  logfile_top_uint   (user_options->markov_disable);
  logfile_top_uint   (user_options->markov_threshold);
  logfile_top_uint   (user_options->opencl_info);
  logfile_top_uint   (user_options->opencl_vector_width);
  logfile_top_uint   (user_options->optimized_kernel_enable);
  logfile_top_uint   (user_options->outfile_autohex);
  logfile_top_uint   (user_options->outfile_check_timer);
  logfile_top_uint   (user_options->outfile_format);
  logfile_top_uint   (user_options->wordlist_autohex_disable);
  logfile_top_uint   (user_options->potfile_disable);
  logfile_top_uint   (user_options->progress_only);
  logfile_top_uint   (user_options->quiet);
  logfile_top_uint   (user_options->remove);
  logfile_top_uint   (user_options->remove_timer);
  logfile_top_uint   (user_options->restore);
  logfile_top_uint   (user_options->restore_disable);
  logfile_top_uint   (user_options->restore_timer);
  logfile_top_uint   (user_options->rp_files_cnt);
  logfile_top_uint   (user_options->rp_gen);
  logfile_top_uint   (user_options->rp_gen_func_max);
  logfile_top_uint   (user_options->rp_gen_func_min);
  logfile_top_uint   (user_options->rp_gen_seed);
  logfile_top_uint   (user_options->runtime);
  logfile_top_uint   (user_options->scrypt_tmto);
  logfile_top_uint   (user_options->segment_size);
  logfile_top_uint   (user_options->self_test_disable);
  logfile_top_uint   (user_options->slow_candidates);
  logfile_top_uint   (user_options->show);
  logfile_top_uint   (user_options->speed_only);
  logfile_top_uint   (user_options->spin_damp);
  logfile_top_uint   (user_options->status);
  logfile_top_uint   (user_options->status_timer);
  logfile_top_uint   (user_options->stdout_flag);
  logfile_top_uint   (user_options->usage);
  logfile_top_uint   (user_options->username);
  logfile_top_uint   (user_options->veracrypt_pim);
  logfile_top_uint   (user_options->version);
  logfile_top_uint   (user_options->workload_profile);
  #ifdef WITH_BRAIN
  logfile_top_uint   (user_options->brain_client);
  logfile_top_uint   (user_options->brain_client_features);
  logfile_top_uint   (user_options->brain_server);
  logfile_top_uint   (user_options->brain_port);
  logfile_top_uint   (user_options->brain_session);
  #endif
}
