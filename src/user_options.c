/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "interface.h"
#include "shared.h"
#include "usage.h"
#include "outfile.h"
#include "user_options.h"

static char RULE_BUF_R[] = ":";
static char RULE_BUF_L[] = ":";

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
  user_options->rp_files_cnt              = 0;
  user_options->rp_files                  = NULL;
}

void user_options_destroy (user_options_t *user_options)
{
  myfree (user_options->rp_files);

  myfree (user_options);
}

int user_options_parse (user_options_t *user_options, int myargc, char **myargv)
{
  int c = -1;

  optind = 1;
  optopt = 0;

  int option_index = 0;

  while (((c = getopt_long (myargc, myargv, short_options, long_options, &option_index)) != -1) && optopt == 0)
  {
    switch (c)
    {
      case IDX_HELP:                      user_options->usage                     = true;           break;
      case IDX_VERSION:                   user_options->version                   = true;           break;
      case IDX_RESTORE:                   user_options->restore                   = true;           break;
      case IDX_QUIET:                     user_options->quiet                     = true;           break;
      case IDX_SHOW:                      user_options->show                      = true;           break;
      case IDX_LEFT:                      user_options->left                      = true;           break;
      case IDX_USERNAME:                  user_options->username                  = true;           break;
      case IDX_REMOVE:                    user_options->remove                    = true;           break;
      case IDX_REMOVE_TIMER:              user_options->remove_timer              = atoi (optarg);
                                          user_options->remove_timer_chgd         = true;           break;
      case IDX_POTFILE_DISABLE:           user_options->potfile_disable           = true;           break;
      case IDX_POTFILE_PATH:              user_options->potfile_path              = optarg;         break;
      case IDX_DEBUG_MODE:                user_options->debug_mode                = atoi (optarg);  break;
      case IDX_DEBUG_FILE:                user_options->debug_file                = optarg;         break;
      case IDX_INDUCTION_DIR:             user_options->induction_dir             = optarg;         break;
      case IDX_OUTFILE_CHECK_DIR:         user_options->outfile_check_dir         = optarg;         break;
      case IDX_FORCE:                     user_options->force                     = true;           break;
      case IDX_SKIP:                      user_options->skip                      = atoll (optarg); break;
      case IDX_LIMIT:                     user_options->limit                     = atoll (optarg); break;
      case IDX_KEYSPACE:                  user_options->keyspace                  = true;           break;
      case IDX_BENCHMARK:                 user_options->benchmark                 = true;           break;
      case IDX_STDOUT_FLAG:               user_options->stdout_flag               = true;           break;
      case IDX_RESTORE_DISABLE:           user_options->restore_disable           = true;           break;
      case IDX_STATUS:                    user_options->status                    = true;           break;
      case IDX_STATUS_TIMER:              user_options->status_timer              = atoi (optarg);  break;
      case IDX_MACHINE_READABLE:          user_options->machine_readable          = true;           break;
      case IDX_LOOPBACK:                  user_options->loopback                  = true;           break;
      case IDX_WEAK_HASH_THRESHOLD:       user_options->weak_hash_threshold       = atoi (optarg);  break;
      case IDX_SESSION:                   user_options->session                   = optarg;         break;
      case IDX_HASH_MODE:                 user_options->hash_mode                 = atoi (optarg);
                                          user_options->hash_mode_chgd            = true;           break;
      case IDX_RUNTIME:                   user_options->runtime                   = atoi (optarg);
                                          user_options->runtime_chgd              = true;           break;
      case IDX_ATTACK_MODE:               user_options->attack_mode               = atoi (optarg);
                                          user_options->attack_mode_chgd          = true;           break;
      case IDX_RP_FILE:                   user_options->rp_files[user_options->rp_files_cnt++]
                                                                                  = optarg;         break;
      case IDX_RP_GEN:                    user_options->rp_gen                    = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MIN:           user_options->rp_gen_func_min           = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MAX:           user_options->rp_gen_func_max           = atoi (optarg);  break;
      case IDX_RP_GEN_SEED:               user_options->rp_gen_seed               = atoi (optarg);
                                          user_options->rp_gen_seed_chgd          = true;           break;
      case IDX_RULE_BUF_L:                user_options->rule_buf_l                = optarg;         break;
      case IDX_RULE_BUF_R:                user_options->rule_buf_r                = optarg;         break;
      case IDX_MARKOV_DISABLE:            user_options->markov_disable            = true;           break;
      case IDX_MARKOV_CLASSIC:            user_options->markov_classic            = true;           break;
      case IDX_MARKOV_THRESHOLD:          user_options->markov_threshold          = atoi (optarg);  break;
      case IDX_MARKOV_HCSTAT:             user_options->markov_hcstat             = optarg;         break;
      case IDX_OUTFILE:                   user_options->outfile                   = optarg;         break;
      case IDX_OUTFILE_FORMAT:            user_options->outfile_format            = atoi (optarg);
                                          user_options->outfile_format_chgd       = true;           break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:   user_options->outfile_autohex           = 0;              break;
      case IDX_OUTFILE_CHECK_TIMER:       user_options->outfile_check_timer       = atoi (optarg);  break;
      case IDX_HEX_CHARSET:               user_options->hex_charset               = true;           break;
      case IDX_HEX_SALT:                  user_options->hex_salt                  = true;           break;
      case IDX_HEX_WORDLIST:              user_options->hex_wordlist              = true;           break;
      case IDX_CPU_AFFINITY:              user_options->cpu_affinity              = optarg;         break;
      case IDX_OPENCL_INFO:               user_options->opencl_info               = true;           break;
      case IDX_OPENCL_DEVICES:            user_options->opencl_devices            = optarg;         break;
      case IDX_OPENCL_PLATFORMS:          user_options->opencl_platforms          = optarg;         break;
      case IDX_OPENCL_DEVICE_TYPES:       user_options->opencl_device_types       = optarg;         break;
      case IDX_OPENCL_VECTOR_WIDTH:       user_options->opencl_vector_width       = atoi (optarg);
                                          user_options->opencl_vector_width_chgd  = true;           break;
      case IDX_WORKLOAD_PROFILE:          user_options->workload_profile          = atoi (optarg);
                                          user_options->workload_profile_chgd     = true;           break;
      case IDX_KERNEL_ACCEL:              user_options->kernel_accel              = atoi (optarg);
                                          user_options->kernel_accel_chgd         = true;           break;
      case IDX_KERNEL_LOOPS:              user_options->kernel_loops              = atoi (optarg);
                                          user_options->kernel_loops_chgd         = true;           break;
      case IDX_NVIDIA_SPIN_DAMP:          user_options->nvidia_spin_damp          = atoi (optarg);
                                          user_options->nvidia_spin_damp_chgd     = true;           break;
      case IDX_GPU_TEMP_DISABLE:          user_options->gpu_temp_disable          = true;           break;
      #if defined (HAVE_HWMON)
      case IDX_GPU_TEMP_ABORT:            user_options->gpu_temp_abort            = atoi (optarg);  break;
      case IDX_GPU_TEMP_RETAIN:           user_options->gpu_temp_retain           = atoi (optarg);  break;
      case IDX_POWERTUNE_ENABLE:          user_options->powertune_enable          = true;           break;
      #endif // HAVE_HWMON
      case IDX_LOGFILE_DISABLE:           user_options->logfile_disable           = true;           break;
      case IDX_TRUECRYPT_KEYFILES:        user_options->truecrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_KEYFILES:        user_options->veracrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_PIM:             user_options->veracrypt_pim             = atoi (optarg);  break;
      case IDX_SEGMENT_SIZE:              user_options->segment_size              = atoi (optarg);  break;
      case IDX_SCRYPT_TMTO:               user_options->scrypt_tmto               = atoi (optarg);  break;
      case IDX_SEPARATOR:                 user_options->separator                 = optarg[0];      break;
      case IDX_BITMAP_MIN:                user_options->bitmap_min                = atoi (optarg);  break;
      case IDX_BITMAP_MAX:                user_options->bitmap_max                = atoi (optarg);  break;
      case IDX_INCREMENT:                 user_options->increment                 = true;           break;
      case IDX_INCREMENT_MIN:             user_options->increment_min             = atoi (optarg);
                                          user_options->increment_min_chgd        = true;           break;
      case IDX_INCREMENT_MAX:             user_options->increment_max             = atoi (optarg);
                                          user_options->increment_max_chgd        = true;           break;
      case IDX_CUSTOM_CHARSET_1:          user_options->custom_charset_1          = optarg;         break;
      case IDX_CUSTOM_CHARSET_2:          user_options->custom_charset_2          = optarg;         break;
      case IDX_CUSTOM_CHARSET_3:          user_options->custom_charset_3          = optarg;         break;
      case IDX_CUSTOM_CHARSET_4:          user_options->custom_charset_4          = optarg;         break;

      default:
      {
        log_error ("ERROR: Invalid argument specified");

        return -1;
      }
    }
  }

  if (optopt != 0)
  {
    log_error ("ERROR: Invalid argument specified");

    return -1;
  }

  // some options can influence or overwrite other options

  if (user_options->opencl_info == true
   || user_options->keyspace    == true
   || user_options->benchmark   == true
   || user_options->stdout_flag == true)
  {
    user_options->show                = false;
    user_options->left                = false;
    user_options->gpu_temp_disable    = true;
    user_options->potfile_disable     = true;
    user_options->powertune_enable    = false;
    user_options->restore             = false;
    user_options->restore_disable     = true;
    user_options->restore_timer       = 0;
    user_options->markov_disable      = true;
    user_options->logfile_disable     = true;
    user_options->weak_hash_threshold = 0;
    user_options->nvidia_spin_damp    = 0;
    user_options->status              = false;
    user_options->status_timer        = 0;
    user_options->outfile_check_timer = 0;
  }

  if (user_options->benchmark == true)
  {
    user_options->attack_mode         = ATTACK_MODE_BF;
    user_options->session             = "benchmark";

    if (user_options->workload_profile_chgd == false)
    {
      user_options->workload_profile = 3;
    }

    #if defined (HAVE_HWMON)
    if (user_options->powertune_enable == true)
    {
      user_options->gpu_temp_disable = false;
    }
    #endif
  }

  if (user_options->keyspace == true)
  {
    user_options->session             = "keyspace";
    user_options->quiet               = true;
  }

  if (user_options->stdout_flag == true)
  {
    user_options->session             = "stdout";
    user_options->quiet               = true;
    user_options->hash_mode           = 2000;
    user_options->outfile_format      = OUTFILE_FMT_PLAIN;
    user_options->force               = true;
    user_options->kernel_accel        = 1024;
    user_options->kernel_loops        = 1024;
    user_options->opencl_vector_width = 1;
  }

  if (user_options->opencl_info == true)
  {
    user_options->session             = "opencl_info";
    user_options->quiet               = true;
    user_options->opencl_platforms    = NULL;
    user_options->opencl_devices      = NULL;
    user_options->opencl_device_types = mystrdup ("1,2,3");
  }

  if (user_options->left == true)
  {
    user_options->outfile_format = OUTFILE_FMT_HASH;
  }

  if (user_options->show == true || user_options->left == true)
  {
    user_options->attack_mode = ATTACK_MODE_NONE;
  }

  if (user_options->skip != 0 && user_options->limit != 0)
  {
    user_options->limit += user_options->skip;
  }

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
  {
    user_options->weak_hash_threshold = 0;
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

  if (user_options->session == NULL)
  {
    user_options->session = (char *) PROGNAME;
  }

  return 0;
}

int user_options_sanity (user_options_t *user_options, int myargc, char **myargv, user_options_extra_t *user_options_extra)
{
  if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT)
   && (user_options->attack_mode != ATTACK_MODE_COMBI)
   && (user_options->attack_mode != ATTACK_MODE_BF)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID2)
   && (user_options->attack_mode != ATTACK_MODE_NONE))
  {
    log_error ("ERROR: Invalid attack-mode specified");

    return -1;
  }

  if (user_options->runtime_chgd == true && user_options->runtime == 0)
  {
    log_error ("ERROR: Invalid runtime specified");

    return -1;
  }

  if (user_options->hash_mode > 14100)
  {
    log_error ("ERROR: Invalid hash-type specified");

    return -1;
  }

  if (user_options->username == true)
  {
    if  ((user_options->hash_mode == 2500)
     ||  (user_options->hash_mode == 5200)
     || ((user_options->hash_mode >= 6200)  && (user_options->hash_mode <= 6299))
     || ((user_options->hash_mode >= 13700) && (user_options->hash_mode <= 13799)))
    {
      log_error ("ERROR: Mixing support for user names and hashes of type %s is not supported", strhashtype (user_options->hash_mode));

      return -1;
    }
  }

  if (user_options->outfile_format > 16)
  {
    log_error ("ERROR: Invalid outfile-format specified");

    return -1;
  }

  if (user_options->left == true)
  {
    if (user_options->outfile_format_chgd == true)
    {
      log_error ("ERROR: Mixing outfile-format > 1 with left parameter is not allowed");

      return -1;
    }
  }

  if (user_options->show == true)
  {
    if (user_options->outfile_format_chgd == true)
    {
      log_error ("ERROR: Mixing outfile-format > 7 with show parameter is not allowed");

      return -1;
    }
  }

  if (user_options->increment_min < INCREMENT_MIN)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if (user_options->increment_max > INCREMENT_MAX)
  {
    log_error ("ERROR: Invalid increment-max specified");

    return -1;
  }

  if (user_options->increment_min > user_options->increment_max)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->attack_mode == ATTACK_MODE_STRAIGHT))
  {
    log_error ("ERROR: Increment is not allowed in attack-mode 0");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->increment_min_chgd == true))
  {
    log_error ("ERROR: Increment-min is only supported combined with increment switch");

    return -1;
  }

  if ((user_options->increment == true) && (user_options->increment_max_chgd == true))
  {
    log_error ("ERROR: Increment-max is only supported combined with increment switch");

    return -1;
  }

  if (user_options->rp_files_cnt > 0 && user_options->rp_gen == true)
  {
    log_error ("ERROR: Use of both rules-file and rules-generate is not supported");

    return -1;
  }

  if (user_options->rp_files_cnt > 0 || user_options->rp_gen == true)
  {
    if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Use of rules-file or rules-generate only allowed in attack-mode 0");

      return -1;
    }
  }

  if (user_options->rp_gen_func_min > user_options->rp_gen_func_max)
  {
    log_error ("ERROR: Invalid rp-gen-func-min specified");

    return -1;
  }

  if (user_options->kernel_accel_chgd == true)
  {
    if (user_options->force == false)
    {
      log_info ("The manual use of the -n option (or --kernel-accel) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (user_options->kernel_accel < 1)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }

    if (user_options->kernel_accel > 1024)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }
  }

  if (user_options->kernel_loops_chgd == true)
  {
    if (user_options->force == false)
    {
      log_info ("The manual use of the -u option (or --kernel-loops) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (user_options->kernel_loops < 1)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }

    if (user_options->kernel_loops > 1024)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }
  }

  if ((user_options->workload_profile < 1) || (user_options->workload_profile > 4))
  {
    log_error ("ERROR: workload-profile %i not available", user_options->workload_profile);

    return -1;
  }

  if (user_options->opencl_vector_width_chgd == true)
  {
    if (is_power_of_2 (user_options->opencl_vector_width) == false || user_options->opencl_vector_width > 16)
    {
      log_error ("ERROR: opencl-vector-width %i not allowed", user_options->opencl_vector_width);

      return -1;
    }
  }

  if (user_options->show == true || user_options->left == true)
  {
    if (user_options->remove == true)
    {
      log_error ("ERROR: Mixing remove parameter not allowed with show parameter or left parameter");

      return -1;
    }

    if (user_options->potfile_disable == true)
    {
      log_error ("ERROR: Mixing potfile-disable parameter not allowed with show parameter or left parameter");

      return -1;
    }
  }

  if (user_options->show == true)
  {
    if (user_options->outfile_autohex == false)
    {
      log_error ("ERROR: Mixing outfile-autohex-disable parameter not allowed with show parameter");

      return -1;
    }
  }

  if (user_options->keyspace == true)
  {
    if (user_options->show == true)
    {
      log_error ("ERROR: Combining show parameter with keyspace parameter is not allowed");

      return -1;
    }
    else if (user_options->left == true)
    {
      log_error ("ERROR: Combining left parameter with keyspace parameter is not allowed");

      return -1;
    }
  }

  if (user_options->remove_timer_chgd == true)
  {
    if (user_options->remove == false)
    {
      log_error ("ERROR: Parameter remove-timer require parameter remove enabled");

      return -1;
    }

    if (user_options->remove_timer < 1)
    {
      log_error ("ERROR: Parameter remove-timer must have a value greater than or equal to 1");

      return -1;
    }
  }

  if (user_options->loopback == true)
  {
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
      {
        log_error ("ERROR: Parameter loopback not allowed without rules-file or rules-generate");

        return -1;
      }
    }
    else
    {
      log_error ("ERROR: Parameter loopback allowed in attack-mode 0 only");

      return -1;
    }
  }


  if (user_options->debug_mode > 0)
  {
    if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Parameter debug-mode option is only available with attack-mode 0");

      return -1;
    }

    if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
    {
      log_error ("ERROR: Parameter debug-mode not allowed without rules-file or rules-generate");

      return -1;
    }
  }

  if (user_options->debug_mode > 4)
  {
    log_error ("ERROR: Invalid debug-mode specified");

    return -1;
  }

  if (user_options->debug_file != NULL)
  {
    if (user_options->debug_mode < 1)
    {
      log_error ("ERROR: Parameter debug-file requires parameter debug-mode to be set");

      return -1;
    }
  }

  if (user_options->induction_dir != NULL)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      log_error ("ERROR: Parameter induction-dir not allowed with brute-force attacks");

      return -1;
    }
  }

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
  {
    if ((user_options->weak_hash_threshold != WEAK_HASH_THRESHOLD) && (user_options->weak_hash_threshold != 0))
    {
      log_error ("ERROR: setting --weak-hash-threshold allowed only in straight-attack mode");

      return -1;
    }
  }

  if (user_options->nvidia_spin_damp > 100)
  {
    log_error ("ERROR: setting --nvidia-spin-damp must be between 0 and 100 (inclusive)");

    return -1;
  }

  if (user_options->benchmark == true)
  {
    if (myargv[optind] != NULL)
    {
      log_error ("ERROR: Invalid argument for benchmark mode specified");

      return -1;
    }

    if (user_options->attack_mode_chgd == true)
    {
      if (user_options->attack_mode != ATTACK_MODE_BF)
      {
        log_error ("ERROR: Only attack-mode 3 allowed in benchmark mode");

        return -1;
      }
    }
  }
  else if (user_options->opencl_info == true)
  {
    if (user_options_extra->optind != myargc)
    {
      usage_mini_print (myargv[0]);

      return -1;
    }
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_NONE)
    {
      if ((user_options_extra->optind + 1) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if ((user_options_extra->optind + 1) > myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      if ((user_options_extra->optind + 3) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      if ((user_options_extra->optind + 1) > myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else
    {
      usage_mini_print (myargv[0]);

      return -1;
    }
  }

  return 0;
}

int user_options_extra_init (user_options_t *user_options, int myargc, char **myargv, user_options_extra_t *user_options_extra)
{
  user_options_extra->attack_kern = ATTACK_KERN_NONE;

  switch (user_options->attack_mode)
  {
    case ATTACK_MODE_STRAIGHT: user_options_extra->attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_COMBI:    user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_BF:       user_options_extra->attack_kern = ATTACK_KERN_BF;       break;
    case ATTACK_MODE_HYBRID1:  user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID2:  user_options_extra->attack_kern = ATTACK_KERN_COMBI;    break;
  }

  user_options_extra->optind = optind;

  if (user_options->benchmark == true)
  {

  }
  else
  {
    if (user_options->stdout_flag == true) // no hash here
    {
      user_options_extra->optind--;
    }

    if (user_options->keyspace == true)
    {
      int num_additional_params = 1;

      if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        num_additional_params = 2;
      }

      int keyspace_wordlist_specified = myargc - user_options_extra->optind - num_additional_params;

      if (keyspace_wordlist_specified == 0) user_options_extra->optind--;
    }
  }

  user_options_extra->rule_len_l = (int) strlen (user_options->rule_buf_l);
  user_options_extra->rule_len_r = (int) strlen (user_options->rule_buf_r);

  user_options_extra->wordlist_mode = ((user_options_extra->optind + 1) < myargc) ? WL_MODE_FILE : WL_MODE_STDIN;

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    user_options_extra->wordlist_mode = WL_MODE_MASK;
  }

  /* still needed?
  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    // enable status (in stdin mode) whenever we do not use --stdout together with an outfile

    if      (user_options->stdout_flag == true) user_options->status = true;
    else if (user_options->outfile)             user_options->status = true;
  }
  */

  return 0;
}
