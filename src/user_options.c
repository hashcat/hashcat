/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "interface.h"
#include "user_options.h"

void user_options_init (user_options_t *user_options)
{
  user_options->attack_mode               = ATTACK_MODE;
  user_options->benchmark                 = BENCHMARK;
  user_options->bitmap_max                = BITMAP_MAX;
  user_options->bitmap_min                = BITMAP_MIN;
  user_options->cpu_affinity              = NULL;
  user_options->custom_charset_1          = NULL;
  user_options->custom_charset_2          = NULL;
  user_options->custom_charset_3          = NULL;
  user_options->custom_charset_4          = NULL;
  user_options->debug_file                = NULL;
  user_options->debug_mode                = DEBUG_MODE;
  user_options->force                     = FORCE;
  user_options->gpu_temp_abort            = GPU_TEMP_ABORT;
  user_options->gpu_temp_disable          = GPU_TEMP_DISABLE;
  user_options->gpu_temp_retain           = GPU_TEMP_RETAIN;
  user_options->hash_mode                 = HASH_MODE;
  user_options->hex_charset               = HEX_CHARSET;
  user_options->hex_salt                  = HEX_SALT;
  user_options->hex_wordlist              = HEX_WORDLIST;
  user_options->increment                 = INCREMENT;
  user_options->increment_max             = INCREMENT_MAX;
  user_options->increment_min             = INCREMENT_MIN;
  user_options->induction_dir             = NULL;
  user_options->kernel_accel              = KERNEL_ACCEL;
  user_options->kernel_loops              = KERNEL_LOOPS;
  user_options->keyspace                  = KEYSPACE;
  user_options->left                      = LEFT;
  user_options->limit                     = LIMIT;
  user_options->logfile_disable           = LOGFILE_DISABLE;
  user_options->loopback                  = LOOPBACK;
  user_options->machine_readable          = MACHINE_READABLE;
  user_options->markov_classic            = MARKOV_CLASSIC;
  user_options->markov_disable            = MARKOV_DISABLE;
  user_options->markov_hcstat             = NULL;
  user_options->markov_threshold          = MARKOV_THRESHOLD;
  user_options->nvidia_spin_damp          = NVIDIA_SPIN_DAMP;
  user_options->opencl_devices            = NULL;
  user_options->opencl_device_types       = NULL;
  user_options->opencl_info               = 0;
  user_options->opencl_platforms          = NULL;
  user_options->opencl_vector_width       = OPENCL_VECTOR_WIDTH;
  user_options->outfile_autohex           = OUTFILE_AUTOHEX;
  user_options->outfile_check_dir         = NULL;
  user_options->outfile_check_timer       = OUTFILE_CHECK_TIMER;
  user_options->outfile_format            = OUTFILE_FORMAT;
  user_options->outfile                   = NULL;
  user_options->potfile_disable           = POTFILE_DISABLE;
  user_options->potfile_path              = NULL;
  user_options->powertune_enable          = POWERTUNE_ENABLE;
  user_options->quiet                     = QUIET;
  user_options->remove                    = REMOVE;
  user_options->remove_timer              = REMOVE_TIMER;
  user_options->restore_disable           = RESTORE_DISABLE;
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
  user_options->separator                 = SEPARATOR;
  user_options->session                   = NULL;
  user_options->show                      = SHOW;
  user_options->skip                      = SKIP;
  user_options->status                    = STATUS;
  user_options->status_timer              = STATUS_TIMER;
  user_options->stdout_flag               = STDOUT_FLAG;
  user_options->truecrypt_keyfiles        = NULL;
  user_options->usage                     = USAGE;
  user_options->username                  = USERNAME;
  user_options->veracrypt_keyfiles        = NULL;
  user_options->veracrypt_pim             = 0;
  user_options->version                   = VERSION;
  user_options->weak_hash_threshold       = WEAK_HASH_THRESHOLD;
  user_options->workload_profile          = WORKLOAD_PROFILE;
}

void user_options_destroy (user_options_t *user_options)
{
  myfree (user_options);
}
