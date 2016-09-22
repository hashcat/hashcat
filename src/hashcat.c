/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif // __APPLE__

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>
#include <inttypes.h>
#include <signal.h>

#if defined (_POSIX)
#include <pthread.h>
#include <pwd.h>
#endif // _POSIX

#include "types.h"
#include "interface.h"
#include "timer.h"
#include "bitops.h"
#include "memory.h"
#include "folder.h"
#include "convert.h"
#include "logging.h"
#include "logfile.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "cpu_aes.h"
#include "cpu_crc32.h"
#include "cpu_des.h"
#include "cpu_md5.h"
#include "cpu_sha1.h"
#include "cpu_sha256.h"
#include "filehandling.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "locking.h"
#include "rp_cpu.h"
#include "rp_kernel_on_cpu.h"
#include "terminal.h"
#include "inc_hash_constants.h"
#include "shared.h"
#include "mpsp.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "affinity.h"
#include "bitmap.h"
#include "usage.h"
#include "status.h"
#include "hlfmt.h"
#include "filenames.h"
#include "stdout.h"
#include "dictstat.h"
#include "wordlist.h"
#include "version.h"
#include "benchmark.h"
#include "outfile_check.h"
#include "weak_hash.h"
#include "remove.h"
#include "debugfile.h"
#include "runtime.h"
#include "attack_mode.h"
#include "powertune.h"
#include "autotune.h"
#include "induct.h"
#include "dispatch.h"
#include "monitor.h"
#include "session.h"
#include "user_options.h"

extern hc_global_data_t data;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_hwmon;
extern hc_thread_mutex_t mux_display;

extern void (*get_next_word_func) (char *, u32, u32 *, u32 *);

extern const unsigned int full01;
extern const unsigned int full80;

extern const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[];

const int comptime = COMPTIME;

int main (int argc, char **argv)
{
  #if defined (_WIN)
  SetConsoleWindowSize (132);
  #endif

  /**
   * To help users a bit
   */

  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    static char display[100];

    snprintf (display, sizeof (display) - 1, "DISPLAY=%s", compute);

    putenv (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  if (getenv ("GPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("CPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("GPU_USE_SYNC_OBJECTS") == NULL)
    putenv ((char *) "GPU_USE_SYNC_OBJECTS=1");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");

  umask (077);

  /**
   * Real init
   */

  memset (&data, 0, sizeof (hc_global_data_t));

  time_t proc_start;

  time (&proc_start);

  data.proc_start = proc_start;

  time_t prepare_start;

  time (&prepare_start);

  hc_thread_mutex_init (mux_display);
  hc_thread_mutex_init (mux_hwmon);

  /**
   * folder
   */

  folder_config_t *folder_config = (folder_config_t *) mymalloc (sizeof (folder_config_t));

  char *install_folder = NULL;
  char *shared_folder  = NULL;

  #if defined (INSTALL_FOLDER)
  install_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  shared_folder = SHARED_FOLDER;
  #endif

  folder_config_init (folder_config, install_folder, shared_folder);

  data.install_dir = folder_config->install_dir;
  data.profile_dir = folder_config->profile_dir;
  data.session_dir = folder_config->session_dir;
  data.shared_dir  = folder_config->shared_dir;

  /**
   * commandline parameters
   */

  user_options_t *user_options = (user_options_t *) mymalloc (sizeof (user_options_t));

  user_options_init (user_options, argc, argv);

  const int rc_user_options_parse1 = user_options_parse (user_options, argc, argv);

  if (rc_user_options_parse1 == -1) return -1;

  /**
   * session
   */

  data.session         = user_options->session;
  data.restore_disable = user_options->restore_disable;

  char *eff_restore_file = (char *) mymalloc (HCBUFSIZ_TINY);
  char *new_restore_file = (char *) mymalloc (HCBUFSIZ_TINY);

  snprintf (eff_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore",     data.session_dir, user_options->session);
  snprintf (new_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore.new", data.session_dir, user_options->session);

  data.eff_restore_file = eff_restore_file;
  data.new_restore_file = new_restore_file;

  restore_data_t *rd = init_restore (argc, argv);

  data.rd = rd;

  /**
   * restore file
   */

  int    myargc = argc;
  char **myargv = argv;

  if (user_options->restore == true)
  {
    read_restore (eff_restore_file, rd);

    if (rd->version < RESTORE_VERSION_MIN)
    {
      log_error ("ERROR: Incompatible restore-file version");

      return -1;
    }

    myargc = rd->argc;
    myargv = rd->argv;

    #if defined (_POSIX)
    rd->pid = getpid ();
    #elif defined (_WIN)
    rd->pid = GetCurrentProcessId ();
    #endif
  }

  const int rc_user_options_parse2 = user_options_parse (user_options, myargc, myargv);

  if (rc_user_options_parse2 == -1) return -1;

  user_options_extra_t *user_options_extra = (user_options_extra_t *) mymalloc (sizeof (user_options_extra_t));

  const int rc_user_options_extra_init = user_options_extra_init (user_options, myargc, myargv, user_options_extra);

  if (rc_user_options_extra_init == -1) return -1;

  const int rc_user_options_sanity = user_options_sanity (user_options, myargc, myargv, user_options_extra);

  if (rc_user_options_sanity == -1) return -1;

  // temporarily start

  if (1)
  {
    data.attack_mode = user_options->attack_mode;
    data.benchmark = user_options->benchmark;
    data.custom_charset_1 = user_options->custom_charset_1;
    data.custom_charset_2 = user_options->custom_charset_2;
    data.custom_charset_3 = user_options->custom_charset_3;
    data.custom_charset_4 = user_options->custom_charset_4;
    data.force = user_options->force;
    data.gpu_temp_abort = user_options->gpu_temp_abort;
    data.gpu_temp_disable = user_options->gpu_temp_disable;
    data.gpu_temp_retain = user_options->gpu_temp_retain;
    data.hex_charset = user_options->hex_charset;
    data.hex_salt = user_options->hex_salt;
    data.hex_wordlist = user_options->hex_wordlist;
    data.limit = user_options->limit;
    data.logfile_disable = user_options->logfile_disable;
    data.loopback = user_options->loopback;
    data.machine_readable = user_options->machine_readable;
    data.outfile_check_timer = user_options->outfile_check_timer;
    data.powertune_enable = user_options->powertune_enable;
    data.quiet = user_options->quiet;
    data.remove = user_options->remove;
    data.remove_timer = user_options->remove_timer;
    data.restore = user_options->restore;
    data.restore_disable = user_options->restore_disable;
    data.restore_timer = user_options->restore_timer;
    data.rp_files = user_options->rp_files;
    data.rp_files_cnt = user_options->rp_files_cnt;
    data.rp_gen = user_options->rp_gen;
    data.rp_gen_seed = user_options->rp_gen_seed;
    data.rule_buf_l = user_options->rule_buf_l;
    data.rule_buf_r = user_options->rule_buf_r;
    data.runtime = user_options->runtime;
    data.scrypt_tmto = user_options->scrypt_tmto;
    data.segment_size = user_options->segment_size;
    data.session = user_options->session;
    data.skip = user_options->skip;
    data.status = user_options->status;
    data.status_timer = user_options->status_timer;
    data.truecrypt_keyfiles = user_options->truecrypt_keyfiles;
    data.username = user_options->username;
    data.veracrypt_keyfiles = user_options->veracrypt_keyfiles;
    data.veracrypt_pim = user_options->veracrypt_pim;

    data.rule_len_l = user_options_extra->rule_len_l;
    data.rule_len_r = user_options_extra->rule_len_r;
    data.wordlist_mode = user_options_extra->wordlist_mode;
    data.attack_kern = user_options_extra->attack_kern;
  }

  if (user_options->version)
  {
    log_info ("%s", VERSION_TAG);

    return 0;
  }

  if (user_options->usage)
  {
    usage_big_print (PROGNAME);

    return 0;
  }

  /**
   * Inform user things getting started,
   * - this is giving us a visual header before preparations start, so we do not need to clear them afterwards
   * - we do not need to check algorithm_pos
   */

  if (user_options->quiet == false)
  {
    if (user_options->benchmark == true)
    {
      if (user_options->machine_readable == false)
      {
        log_info ("%s (%s) starting in benchmark-mode...", PROGNAME, VERSION_TAG);
        log_info ("");
      }
      else
      {
        log_info ("# %s (%s) %s", PROGNAME, VERSION_TAG, ctime (&proc_start));
      }
    }
    else if (user_options->restore == true)
    {
      log_info ("%s (%s) starting in restore-mode...", PROGNAME, VERSION_TAG);
      log_info ("");
    }
    else if (user_options->stdout_flag == true)
    {
      // do nothing
    }
    else if (user_options->keyspace == true)
    {
      // do nothing
    }
    else
    {
      if ((user_options->show == true) || (user_options->left == true))
      {
        // do nothing
      }
      else
      {
        log_info ("%s (%s) starting...", PROGNAME, VERSION_TAG);
        log_info ("");
      }
    }
  }

  /**
   * induction directory
   */

  char *induction_directory = NULL;

  if (user_options->attack_mode != ATTACK_MODE_BF)
  {
    if ((user_options->keyspace == false) && (user_options->benchmark == false) && (user_options->opencl_info == false))
    {
      if (user_options->induction_dir == NULL)
      {
        induction_directory = (char *) mymalloc (HCBUFSIZ_TINY);

        snprintf (induction_directory, HCBUFSIZ_TINY - 1, "%s/%s.%s", folder_config->session_dir, user_options->session, INDUCT_DIR);

        // create induction folder if it does not already exist

        if (user_options->keyspace == false)
        {
          if (rmdir (induction_directory) == -1)
          {
            if (errno == ENOENT)
            {
              // good, we can ignore
            }
            else if (errno == ENOTEMPTY)
            {
              char *induction_directory_mv = (char *) mymalloc (HCBUFSIZ_TINY);

              snprintf (induction_directory_mv, HCBUFSIZ_TINY - 1, "%s/%s.induct.%d", folder_config->session_dir, user_options->session, (int) proc_start);

              if (rename (induction_directory, induction_directory_mv) != 0)
              {
                log_error ("ERROR: Rename directory %s to %s: %s", induction_directory, induction_directory_mv, strerror (errno));

                return -1;
              }
            }
            else
            {
              log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

              return -1;
            }
          }

          if (mkdir (induction_directory, 0700) == -1)
          {
            log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

            return -1;
          }
        }
      }
      else
      {
        induction_directory = user_options->induction_dir;
      }
    }
  }

  data.induction_directory = induction_directory;

  /**
   * tuning db
   */

  char tuning_db_file[256] = { 0 };

  snprintf (tuning_db_file, sizeof (tuning_db_file) - 1, "%s/%s", folder_config->shared_dir, TUNING_DB_FILE);

  tuning_db_t *tuning_db = tuning_db_init (tuning_db_file);

  /**
   * outfile-check directory
   */

  char *outfile_check_directory = NULL;

  if ((user_options->keyspace == false) && (user_options->benchmark == false) && (user_options->opencl_info == false))
  {
    if (user_options->outfile_check_dir == NULL)
    {
      outfile_check_directory = (char *) mymalloc (HCBUFSIZ_TINY);

      snprintf (outfile_check_directory, HCBUFSIZ_TINY - 1, "%s/%s.%s", folder_config->session_dir, user_options->session, OUTFILES_DIR);
    }
    else
    {
      outfile_check_directory = user_options->outfile_check_dir;
    }

    struct stat outfile_check_stat;

    if (stat (outfile_check_directory, &outfile_check_stat) == 0)
    {
      uint is_dir = S_ISDIR (outfile_check_stat.st_mode);

      if (is_dir == 0)
      {
        log_error ("ERROR: Directory specified in outfile-check '%s' is not a valid directory", outfile_check_directory);

        return -1;
      }
    }
    else if (user_options->outfile_check_dir == NULL)
    {
      if (mkdir (outfile_check_directory, 0700) == -1)
      {
        log_error ("ERROR: %s: %s", outfile_check_directory, strerror (errno));

        return -1;
      }
    }
  }

  data.outfile_check_directory = outfile_check_directory;

  /**
   * cpu affinity
   */

  if (user_options->cpu_affinity)
  {
    set_cpu_affinity (user_options->cpu_affinity);
  }

  if (user_options->rp_gen_seed_chgd == false)
  {
    srand (user_options->rp_gen_seed);
  }
  else
  {
    srand (proc_start);
  }

  /**
   * logfile init
   */

  if (user_options->logfile_disable == 0)
  {
    char *logfile = (char *) mymalloc (HCBUFSIZ_TINY);

    snprintf (logfile, HCBUFSIZ_TINY - 1, "%s/%s.log", folder_config->session_dir, user_options->session);

    data.logfile = logfile;

    char *topid = logfile_generate_topid ();

    data.topid = topid;
  }

  logfile_top_msg ("START");

  logfile_top_uint   (user_options->attack_mode);
  logfile_top_uint   (user_options->benchmark);
  logfile_top_uint   (user_options->stdout_flag);
  logfile_top_uint   (user_options->bitmap_min);
  logfile_top_uint   (user_options->bitmap_max);
  logfile_top_uint   (user_options->debug_mode);
  logfile_top_uint   (user_options->force);
  logfile_top_uint   (user_options->kernel_accel);
  logfile_top_uint   (user_options->kernel_loops);
  logfile_top_uint   (user_options->nvidia_spin_damp);
  logfile_top_uint   (user_options->hash_mode);
  logfile_top_uint   (user_options->hex_charset);
  logfile_top_uint   (user_options->hex_salt);
  logfile_top_uint   (user_options->hex_wordlist);
  logfile_top_uint   (user_options->increment);
  logfile_top_uint   (user_options->increment_max);
  logfile_top_uint   (user_options->increment_min);
  logfile_top_uint   (user_options->keyspace);
  logfile_top_uint   (user_options->left);
  logfile_top_uint   (user_options->logfile_disable);
  logfile_top_uint   (user_options->loopback);
  logfile_top_uint   (user_options->markov_classic);
  logfile_top_uint   (user_options->markov_disable);
  logfile_top_uint   (user_options->markov_threshold);
  logfile_top_uint   (user_options->outfile_autohex);
  logfile_top_uint   (user_options->outfile_check_timer);
  logfile_top_uint   (user_options->outfile_format);
  logfile_top_uint   (user_options->potfile_disable);
  logfile_top_string (user_options->potfile_path);
  logfile_top_uint   (user_options->powertune_enable);
  logfile_top_uint   (user_options->scrypt_tmto);
  logfile_top_uint   (user_options->quiet);
  logfile_top_uint   (user_options->remove);
  logfile_top_uint   (user_options->remove_timer);
  logfile_top_uint   (user_options->restore);
  logfile_top_uint   (user_options->restore_disable);
  logfile_top_uint   (user_options->restore_timer);
  logfile_top_uint   (user_options->rp_gen);
  logfile_top_uint   (user_options->rp_gen_func_max);
  logfile_top_uint   (user_options->rp_gen_func_min);
  logfile_top_uint   (user_options->rp_gen_seed);
  logfile_top_uint   (user_options->runtime);
  logfile_top_uint   (user_options->segment_size);
  logfile_top_uint   (user_options->show);
  logfile_top_uint   (user_options->status);
  logfile_top_uint   (user_options->machine_readable);
  logfile_top_uint   (user_options->status_timer);
  logfile_top_uint   (user_options->usage);
  logfile_top_uint   (user_options->username);
  logfile_top_uint   (user_options->version);
  logfile_top_uint   (user_options->weak_hash_threshold);
  logfile_top_uint   (user_options->workload_profile);
  logfile_top_uint64 (user_options->limit);
  logfile_top_uint64 (user_options->skip);
  logfile_top_char   (user_options->separator);
  logfile_top_string (user_options->cpu_affinity);
  logfile_top_string (user_options->custom_charset_1);
  logfile_top_string (user_options->custom_charset_2);
  logfile_top_string (user_options->custom_charset_3);
  logfile_top_string (user_options->custom_charset_4);
  logfile_top_string (user_options->debug_file);
  logfile_top_string (user_options->opencl_devices);
  logfile_top_string (user_options->opencl_platforms);
  logfile_top_string (user_options->opencl_device_types);
  logfile_top_uint   (user_options->opencl_vector_width);
  logfile_top_string (user_options->induction_dir);
  logfile_top_string (user_options->markov_hcstat);
  logfile_top_string (user_options->outfile);
  logfile_top_string (user_options->outfile_check_dir);
  logfile_top_string (user_options->rule_buf_l);
  logfile_top_string (user_options->rule_buf_r);
  logfile_top_string (user_options->session);
  logfile_top_string (user_options->truecrypt_keyfiles);
  logfile_top_string (user_options->veracrypt_keyfiles);
  logfile_top_uint   (user_options->veracrypt_pim);

  /**
   * Init OpenCL library loader
   */

  opencl_ctx_t *opencl_ctx = (opencl_ctx_t *) mymalloc (sizeof (opencl_ctx_t));

  data.opencl_ctx = opencl_ctx;

  const int rc_opencl_init = opencl_ctx_init (opencl_ctx, user_options);

  if (rc_opencl_init == -1)
  {
    log_error ("ERROR: opencl_ctx_init() failed");

    return -1;
  }

  /**
   * status, monitor and outfile remove threads
   */

  uint outer_threads_cnt = 0;

  hc_thread_t *outer_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  data.shutdown_outer = 0;

  if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      hc_thread_create (outer_threads[outer_threads_cnt], thread_keypress, NULL);

      outer_threads_cnt++;
    }
  }

  /**
   * config
   */

  hashconfig_t *hashconfig = (hashconfig_t *) mymalloc (sizeof (hashconfig_t));

  data.hashconfig = hashconfig;

  uint algorithm_pos = 0;
  uint algorithm_max = 1;

  const int *algorithms = DEFAULT_BENCHMARK_ALGORITHMS_BUF;

  if (user_options->benchmark == true && user_options->hash_mode_chgd == false) algorithm_max = DEFAULT_BENCHMARK_ALGORITHMS_CNT;

  for (algorithm_pos = 0; algorithm_pos < algorithm_max; algorithm_pos++)
  {
    opencl_ctx->devices_status = STATUS_INIT;

    //opencl_ctx->run_main_level1   = true;
    opencl_ctx->run_main_level2   = true;
    opencl_ctx->run_main_level3   = true;
    opencl_ctx->run_thread_level1 = true;
    opencl_ctx->run_thread_level2 = true;

    /*
     * We need to reset 'rd' in benchmark mode otherwise when the user hits 'bypass'
     * the following algos are skipped entirely
     */

    if (algorithm_pos > 0)
    {
      local_free (rd);

      rd = init_restore (argc, argv);

      data.rd = rd;
    }

    /**
     * update hash_mode in case of multihash benchmark
     */

    if (user_options->benchmark == true)
    {
      if (user_options->hash_mode_chgd == false)
      {
        user_options->hash_mode = algorithms[algorithm_pos];
      }

      user_options->quiet = true;
    }

    /**
     * setup variables and buffers depending on hash_mode
     */

    const int rc_hashconfig = hashconfig_init (hashconfig, user_options);

    if (rc_hashconfig == -1) return -1;

    /**
     * outfile
     */

    outfile_ctx_t *outfile_ctx = mymalloc (sizeof (outfile_ctx_t));

    data.outfile_ctx = outfile_ctx;

    outfile_init (outfile_ctx, user_options);

    /**
     * Sanity check for hashfile vs outfile (should not point to the same physical file)
     */

    const int rc_outfile_and_hashfile = outfile_and_hashfile (outfile_ctx, myargv[user_options_extra->optind]);

    if (rc_outfile_and_hashfile == -1) return -1;

    /**
     * potfile
     */

    potfile_ctx_t *potfile_ctx = mymalloc (sizeof (potfile_ctx_t));

    data.potfile_ctx = potfile_ctx;

    potfile_init (potfile_ctx, folder_config->profile_dir, user_options->potfile_path, user_options->potfile_disable);

    if (user_options->show == true || user_options->left == true)
    {
      outfile_write_open (outfile_ctx);

      SUPPRESS_OUTPUT = 1;

      potfile_read_open  (potfile_ctx);

      potfile_read_parse (potfile_ctx, hashconfig);

      potfile_read_close (potfile_ctx);

      SUPPRESS_OUTPUT = 0;
    }

    /**
     * load hashes, stage 1
     */

    hashes_t *hashes = (hashes_t *) mymalloc (sizeof (hashes_t));

    data.hashes = hashes;

    const int rc_hashes_init_stage1 = hashes_init_stage1 (hashes, hashconfig, potfile_ctx, outfile_ctx, user_options, myargv[user_options_extra->optind]);

    if (rc_hashes_init_stage1 == -1) return -1;

    logfile_top_var_string ("hashfile", hashes->hashfile);

    logfile_top_uint (hashes->hashlist_mode);
    logfile_top_uint (hashes->hashlist_format);

    if ((user_options->keyspace == false) && (user_options->stdout_flag == false) && (user_options->opencl_info == false))
    {
      if (hashes->hashes_cnt == 0)
      {
        log_error ("ERROR: No hashes loaded");

        return -1;
      }
    }

    if (user_options->show == true || user_options->left == true)
    {
      outfile_write_close (outfile_ctx);

      potfile_hash_free (potfile_ctx, hashconfig);

      if (user_options->quiet == false) log_info_nn ("");

      return 0;
    }

    /**
     * Potfile removes
     */

    int potfile_remove_cracks = 0;

    if (user_options->potfile_disable == 0)
    {
      if (user_options->quiet == false) log_info_nn ("Comparing hashes with potfile entries...");

      potfile_remove_cracks = potfile_remove_parse (potfile_ctx, hashconfig, hashes);
    }

    /**
     * load hashes, stage 2
     */

    uint hashes_cnt_orig = hashes->hashes_cnt;

    const int rc_hashes_init_stage2 = hashes_init_stage2 (hashes, hashconfig, opencl_ctx, user_options);

    if (rc_hashes_init_stage2 == -1) return -1;

    /**
     * Automatic Optimizers
     */

    hashconfig_general_defaults (hashconfig, hashes, user_options);

    if (hashes->salts_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_SALT;

    if (hashes->digests_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_HASH;

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      hashconfig->opti_type |= OPTI_TYPE_NOT_ITERATED;

    if (user_options->attack_mode == ATTACK_MODE_BF)
      hashconfig->opti_type |= OPTI_TYPE_BRUTE_FORCE;

    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADD80;
          }

          if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS14)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS14;
          }

          if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS15)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS15;
          }
        }
      }
    }

    /**
     * choose dictionary parser
     */

    get_next_word_func = get_next_word_std;

    if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
    {
      get_next_word_func = get_next_word_uc;
    }

    if (hashconfig->hash_type == HASH_TYPE_LM) // yes that's fine that way
    {
      get_next_word_func = get_next_word_lm;
    }

    /**
     * dictstat
     */

    dictstat_ctx_t *dictstat_ctx = mymalloc (sizeof (dictstat_ctx_t));

    dictstat_init (dictstat_ctx, folder_config->profile_dir);

    if (user_options->keyspace == false)
    {
      dictstat_read (dictstat_ctx);
    }

    /**
     * loopback
     */

    loopback_ctx_t *loopback_ctx = mymalloc (sizeof (loopback_ctx_t));

    data.loopback_ctx = loopback_ctx;

    loopback_init (loopback_ctx);

    /**
     * debugfile
     */

    debugfile_ctx_t *debugfile_ctx = mymalloc (sizeof (debugfile_ctx_t));

    data.debugfile_ctx = debugfile_ctx;

    debugfile_init (debugfile_ctx, user_options->debug_mode, user_options->debug_file);

    /**
     * word len
     */

    uint pw_min = hashconfig_general_pw_min (hashconfig);
    uint pw_max = hashconfig_general_pw_max (hashconfig);

    /**
     * charsets : keep them together for more easy maintainnce
     */

    cs_t mp_sys[6] = { { { 0 }, 0 } };
    cs_t mp_usr[4] = { { { 0 }, 0 } };

    mp_setup_sys (mp_sys);

    if (user_options->custom_charset_1) mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_1, 0, hashconfig);
    if (user_options->custom_charset_2) mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_2, 1, hashconfig);
    if (user_options->custom_charset_3) mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_3, 2, hashconfig);
    if (user_options->custom_charset_4) mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_4, 3, hashconfig);

    /**
     * Some algorithm, like descrypt, can benefit from JIT compilation
     */

    opencl_ctx->force_jit_compilation = -1;

    if (hashconfig->hash_mode == 8900)
    {
      opencl_ctx->force_jit_compilation = 8900;
    }
    else if (hashconfig->hash_mode == 9300)
    {
      opencl_ctx->force_jit_compilation = 8900;
    }
    else if (hashconfig->hash_mode == 1500 && user_options->attack_mode == ATTACK_MODE_BF && hashes->salts_cnt == 1)
    {
      opencl_ctx->force_jit_compilation = 1500;
    }

    /**
     * generate bitmap tables
     */

    const uint bitmap_shift1 = 5;
    const uint bitmap_shift2 = 13;

    if (user_options->bitmap_max < user_options->bitmap_min) user_options->bitmap_max = user_options->bitmap_min;

    uint *bitmap_s1_a = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s1_b = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s1_c = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s1_d = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s2_a = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s2_b = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s2_c = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));
    uint *bitmap_s2_d = (uint *) mymalloc ((1u << user_options->bitmap_max) * sizeof (uint));

    uint bitmap_bits;
    uint bitmap_nums;
    uint bitmap_mask;
    uint bitmap_size;

    for (bitmap_bits = user_options->bitmap_min; bitmap_bits < user_options->bitmap_max; bitmap_bits++)
    {
      if (user_options->quiet == false) log_info_nn ("Generating bitmap tables with %u bits...", bitmap_bits);

      bitmap_nums = 1u << bitmap_bits;

      bitmap_mask = bitmap_nums - 1;

      bitmap_size = bitmap_nums * sizeof (uint);

      if ((hashes->digests_cnt & bitmap_mask) == hashes->digests_cnt) break;

      if (generate_bitmaps (hashes->digests_cnt, hashconfig->dgst_size, bitmap_shift1, (char *) hashes->digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, hashes->digests_cnt / 2) == 0x7fffffff) continue;
      if (generate_bitmaps (hashes->digests_cnt, hashconfig->dgst_size, bitmap_shift2, (char *) hashes->digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, hashes->digests_cnt / 2) == 0x7fffffff) continue;

      break;
    }

    bitmap_nums = 1u << bitmap_bits;

    bitmap_mask = bitmap_nums - 1;

    bitmap_size = bitmap_nums * sizeof (uint);

    generate_bitmaps (hashes->digests_cnt, hashconfig->dgst_size, bitmap_shift1, (char *) hashes->digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, -1ul);
    generate_bitmaps (hashes->digests_cnt, hashconfig->dgst_size, bitmap_shift2, (char *) hashes->digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s2_a, bitmap_s2_b, bitmap_s2_c, bitmap_s2_d, -1ul);

    /**
     * load rules
     */

    uint *all_kernel_rules_cnt = NULL;

    kernel_rule_t **all_kernel_rules_buf = NULL;

    if (user_options->rp_files_cnt)
    {
      all_kernel_rules_cnt = (uint *) mycalloc (user_options->rp_files_cnt, sizeof (uint));

      all_kernel_rules_buf = (kernel_rule_t **) mycalloc (user_options->rp_files_cnt, sizeof (kernel_rule_t *));
    }

    char *rule_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

    int rule_len = 0;

    for (uint i = 0; i < user_options->rp_files_cnt; i++)
    {
      uint kernel_rules_avail = 0;

      uint kernel_rules_cnt = 0;

      kernel_rule_t *kernel_rules_buf = NULL;

      char *rp_file = user_options->rp_files[i];

      char in[BLOCK_SIZE]  = { 0 };
      char out[BLOCK_SIZE] = { 0 };

      FILE *fp = NULL;

      uint rule_line = 0;

      if ((fp = fopen (rp_file, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", rp_file, strerror (errno));

        return -1;
      }

      while (!feof (fp))
      {
        memset (rule_buf, 0, HCBUFSIZ_LARGE);

        rule_len = fgetl (fp, rule_buf);

        rule_line++;

        if (rule_len == 0) continue;

        if (rule_buf[0] == '#') continue;

        if (kernel_rules_avail == kernel_rules_cnt)
        {
          kernel_rules_buf = (kernel_rule_t *) myrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

          kernel_rules_avail += INCR_RULES;
        }

        memset (in,  0, BLOCK_SIZE);
        memset (out, 0, BLOCK_SIZE);

        int result = _old_apply_rule (rule_buf, rule_len, in, 1, out);

        if (result == -1)
        {
          log_info ("WARNING: Skipping invalid or unsupported rule in file %s on line %u: %s", rp_file, rule_line, rule_buf);

          continue;
        }

        if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1)
        {
          log_info ("WARNING: Cannot convert rule for use on OpenCL device in file %s on line %u: %s", rp_file, rule_line, rule_buf);

          memset (&kernel_rules_buf[kernel_rules_cnt], 0, sizeof (kernel_rule_t)); // needs to be cleared otherwise we could have some remaining data

          continue;
        }

        kernel_rules_cnt++;
      }

      fclose (fp);

      all_kernel_rules_cnt[i] = kernel_rules_cnt;

      all_kernel_rules_buf[i] = kernel_rules_buf;
    }

    /**
     * merge rules or automatic rule generator
     */

    uint kernel_rules_cnt = 0;

    kernel_rule_t *kernel_rules_buf = NULL;

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options->rp_files_cnt)
      {
        kernel_rules_cnt = 1;

        uint *repeats = (uint *) mycalloc (user_options->rp_files_cnt + 1, sizeof (uint));

        repeats[0] = kernel_rules_cnt;

        for (uint i = 0; i < user_options->rp_files_cnt; i++)
        {
          kernel_rules_cnt *= all_kernel_rules_cnt[i];

          repeats[i + 1] = kernel_rules_cnt;
        }

        kernel_rules_buf = (kernel_rule_t *) mycalloc (kernel_rules_cnt, sizeof (kernel_rule_t));

        memset (kernel_rules_buf, 0, kernel_rules_cnt * sizeof (kernel_rule_t));

        for (uint i = 0; i < kernel_rules_cnt; i++)
        {
          uint out_pos = 0;

          kernel_rule_t *out = &kernel_rules_buf[i];

          for (uint j = 0; j < user_options->rp_files_cnt; j++)
          {
            uint in_off = (i / repeats[j]) % all_kernel_rules_cnt[j];
            uint in_pos;

            kernel_rule_t *in = &all_kernel_rules_buf[j][in_off];

            for (in_pos = 0; in->cmds[in_pos]; in_pos++, out_pos++)
            {
              if (out_pos == RULES_MAX - 1)
              {
                // log_info ("WARNING: Truncating chaining of rule %d and rule %d as maximum number of function calls per rule exceeded", i, in_off);

                break;
              }

              out->cmds[out_pos] = in->cmds[in_pos];
            }
          }
        }

        local_free (repeats);
      }
      else if (user_options->rp_gen)
      {
        uint kernel_rules_avail = 0;

        while (kernel_rules_cnt < user_options->rp_gen)
        {
          if (kernel_rules_avail == kernel_rules_cnt)
          {
            kernel_rules_buf = (kernel_rule_t *) myrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

            kernel_rules_avail += INCR_RULES;
          }

          memset (rule_buf, 0, HCBUFSIZ_LARGE);

          rule_len = (int) generate_random_rule (rule_buf, user_options->rp_gen_func_min, user_options->rp_gen_func_max);

          if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1) continue;

          kernel_rules_cnt++;
        }
      }
    }

    myfree (rule_buf);

    /**
     * generate NOP rules
     */

    if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
    {
      kernel_rules_buf = (kernel_rule_t *) mymalloc (sizeof (kernel_rule_t));

      kernel_rules_buf[kernel_rules_cnt].cmds[0] = RULE_OP_MANGLE_NOOP;

      kernel_rules_cnt++;
    }

    data.kernel_rules_cnt = kernel_rules_cnt;
    data.kernel_rules_buf = kernel_rules_buf;

    if (kernel_rules_cnt == 0)
    {
      log_error ("ERROR: No valid rules left");

      return -1;
    }

    /**
     * If we have a NOOP rule then we can process words from wordlists > length 32 for slow hashes
     */

    int has_noop = 0;

    for (uint kernel_rules_pos = 0; kernel_rules_pos < kernel_rules_cnt; kernel_rules_pos++)
    {
      if (kernel_rules_buf[kernel_rules_pos].cmds[0] != RULE_OP_MANGLE_NOOP) continue;
      if (kernel_rules_buf[kernel_rules_pos].cmds[1] != 0)                   continue;

      has_noop = 1;
    }

    if (has_noop == 0)
    {
      switch (user_options_extra->attack_kern)
      {
        case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
        case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
      }
    }
    else
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        switch (user_options_extra->attack_kern)
        {
          case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                      break;
          case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                      break;
        }
      }
      else
      {
        // in this case we can process > 32
      }
    }

    const int rc_devices_init = opencl_ctx_devices_init (opencl_ctx, hashconfig, tuning_db, user_options, algorithm_pos);

    if (rc_devices_init == -1)
    {
      log_error ("ERROR: opencl_ctx_devices_init() failed");

      return -1;
    }

    /**
     * HM devices: init
     */

    hm_attrs_t hm_adapters_adl[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvapi[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvml[DEVICES_MAX];
    hm_attrs_t hm_adapters_xnvctrl[DEVICES_MAX];

    memset (hm_adapters_adl,     0, sizeof (hm_adapters_adl));
    memset (hm_adapters_nvapi,   0, sizeof (hm_adapters_nvapi));
    memset (hm_adapters_nvml,    0, sizeof (hm_adapters_nvml));
    memset (hm_adapters_xnvctrl, 0, sizeof (hm_adapters_xnvctrl));

    if (user_options->gpu_temp_disable == false)
    {
      ADL_PTR     *adl     = (ADL_PTR *)     mymalloc (sizeof (ADL_PTR));
      NVAPI_PTR   *nvapi   = (NVAPI_PTR *)   mymalloc (sizeof (NVAPI_PTR));
      NVML_PTR    *nvml    = (NVML_PTR *)    mymalloc (sizeof (NVML_PTR));
      XNVCTRL_PTR *xnvctrl = (XNVCTRL_PTR *) mymalloc (sizeof (XNVCTRL_PTR));

      data.hm_adl     = NULL;
      data.hm_nvapi   = NULL;
      data.hm_nvml    = NULL;
      data.hm_xnvctrl = NULL;

      if ((opencl_ctx->need_nvml == 1) && (nvml_init (nvml) == 0))
      {
        data.hm_nvml = nvml;
      }

      if (data.hm_nvml)
      {
        if (hm_NVML_nvmlInit (data.hm_nvml) == NVML_SUCCESS)
        {
          HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX] = { 0 };

          int tmp_in = hm_get_adapter_index_nvml (nvmlGPUHandle);

          int tmp_out = 0;

          for (int i = 0; i < tmp_in; i++)
          {
            hm_adapters_nvml[tmp_out++].nvml = nvmlGPUHandle[i];
          }

          for (int i = 0; i < tmp_out; i++)
          {
            unsigned int speed;

            if (hm_NVML_nvmlDeviceGetFanSpeed (data.hm_nvml, 0, hm_adapters_nvml[i].nvml, &speed) == NVML_SUCCESS) hm_adapters_nvml[i].fan_get_supported = 1;

            // doesn't seem to create any advantages
            //hm_NVML_nvmlDeviceSetComputeMode (data.hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_COMPUTEMODE_EXCLUSIVE_PROCESS);
            //hm_NVML_nvmlDeviceSetGpuOperationMode (data.hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_GOM_ALL_ON);
          }
        }
      }

      if ((opencl_ctx->need_nvapi == 1) && (nvapi_init (nvapi) == 0))
      {
        data.hm_nvapi = nvapi;
      }

      if (data.hm_nvapi)
      {
        if (hm_NvAPI_Initialize (data.hm_nvapi) == NVAPI_OK)
        {
          HM_ADAPTER_NVAPI nvGPUHandle[DEVICES_MAX] = { 0 };

          int tmp_in = hm_get_adapter_index_nvapi (nvGPUHandle);

          int tmp_out = 0;

          for (int i = 0; i < tmp_in; i++)
          {
            hm_adapters_nvapi[tmp_out++].nvapi = nvGPUHandle[i];
          }
        }
      }

      if ((opencl_ctx->need_xnvctrl == 1) && (xnvctrl_init (xnvctrl) == 0))
      {
        data.hm_xnvctrl = xnvctrl;
      }

      if (data.hm_xnvctrl)
      {
        if (hm_XNVCTRL_XOpenDisplay (data.hm_xnvctrl) == 0)
        {
          for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

            if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

            hm_adapters_xnvctrl[device_id].xnvctrl = device_id;

            int speed = 0;

            if (get_fan_speed_current (data.hm_xnvctrl, device_id, &speed) == 0) hm_adapters_xnvctrl[device_id].fan_get_supported = 1;
          }
        }
      }

      if ((opencl_ctx->need_adl == 1) && (adl_init (adl) == 0))
      {
        data.hm_adl = adl;
      }

      if (data.hm_adl)
      {
        if (hm_ADL_Main_Control_Create (data.hm_adl, ADL_Main_Memory_Alloc, 0) == ADL_OK)
        {
          // total number of adapters

          int hm_adapters_num;

          if (get_adapters_num_adl (data.hm_adl, &hm_adapters_num) != 0) return -1;

          // adapter info

          LPAdapterInfo lpAdapterInfo = hm_get_adapter_info_adl (data.hm_adl, hm_adapters_num);

          if (lpAdapterInfo == NULL) return -1;

          // get a list (of ids of) valid/usable adapters

          int num_adl_adapters = 0;

          u32 *valid_adl_device_list = hm_get_list_valid_adl_adapters (hm_adapters_num, &num_adl_adapters, lpAdapterInfo);

          if (num_adl_adapters > 0)
          {
            hc_thread_mutex_lock (mux_hwmon);

            // hm_get_opencl_busid_devid (hm_adapters_adl, devices_all_cnt, devices_all);

            hm_get_adapter_index_adl (hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

            hm_get_overdrive_version  (data.hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);
            hm_check_fanspeed_control (data.hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

            hc_thread_mutex_unlock (mux_hwmon);
          }

          myfree (valid_adl_device_list);
          myfree (lpAdapterInfo);
        }
      }

      if (data.hm_adl == NULL && data.hm_nvml == NULL && data.hm_xnvctrl == NULL)
      {
        user_options->gpu_temp_disable = true;
      }
    }

    /**
     * OpenCL devices: allocate buffer for device specific information
     */

    ADLOD6MemClockState *od_clock_mem_status = (ADLOD6MemClockState *) mycalloc (opencl_ctx->devices_cnt, sizeof (ADLOD6MemClockState));

    int *od_power_control_status = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));

    unsigned int *nvml_power_limit = (unsigned int *) mycalloc (opencl_ctx->devices_cnt, sizeof (unsigned int));

    /**
     * User-defined GPU temp handling
     */

    if (user_options->gpu_temp_disable == true)
    {
      user_options->gpu_temp_abort  = 0;
      user_options->gpu_temp_retain = 0;
    }

    data.gpu_temp_disable = user_options->gpu_temp_disable;
    data.gpu_temp_abort   = user_options->gpu_temp_abort;
    data.gpu_temp_retain  = user_options->gpu_temp_retain;

    /**
     * enable custom signal handler(s)
     */

    if (user_options->benchmark == false)
    {
      hc_signal (sigHandler_default);
    }
    else
    {
      hc_signal (sigHandler_benchmark);
    }

    /**
     * inform the user
     */

    if (user_options->quiet == false)
    {
      log_info ("Hashes: %u digests; %u unique digests, %u unique salts", hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);

      log_info ("Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_bits, bitmap_nums, bitmap_mask, bitmap_size, bitmap_shift1, bitmap_shift2);

      if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
      {
        log_info ("Rules: %u", kernel_rules_cnt);
      }

      if (hashconfig->opti_type)
      {
        log_info ("Applicable Optimizers:");

        for (uint i = 0; i < 32; i++)
        {
          const uint opti_bit = 1u << i;

          if (hashconfig->opti_type & opti_bit) log_info ("* %s", stroptitype (opti_bit));
        }
      }

      /**
       * Watchdog and Temperature balance
       */

      if (user_options->gpu_temp_disable == false && data.hm_adl == NULL && data.hm_nvml == NULL && data.hm_xnvctrl == NULL)
      {
        log_info ("Watchdog: Hardware Monitoring Interface not found on your system");
      }

      if (user_options->gpu_temp_abort == 0)
      {
        log_info ("Watchdog: Temperature abort trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature abort trigger set to %uc", user_options->gpu_temp_abort);
      }

      if (user_options->gpu_temp_retain == 0)
      {
        log_info ("Watchdog: Temperature retain trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature retain trigger set to %uc", user_options->gpu_temp_retain);
      }

      if (user_options->quiet == false) log_info ("");
    }

    /**
     * HM devices: copy
     */

    if (user_options->gpu_temp_disable == false)
    {
      for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->skipped) continue;

        const uint platform_devices_id = device_param->platform_devices_id;

        if (device_param->device_vendor_id == VENDOR_ID_AMD)
        {
          data.hm_device[device_id].adl               = hm_adapters_adl[platform_devices_id].adl;
          data.hm_device[device_id].nvapi             = 0;
          data.hm_device[device_id].nvml              = 0;
          data.hm_device[device_id].xnvctrl           = 0;
          data.hm_device[device_id].od_version        = hm_adapters_adl[platform_devices_id].od_version;
          data.hm_device[device_id].fan_get_supported = hm_adapters_adl[platform_devices_id].fan_get_supported;
          data.hm_device[device_id].fan_set_supported = 0;
        }

        if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          data.hm_device[device_id].adl               = 0;
          data.hm_device[device_id].nvapi             = hm_adapters_nvapi[platform_devices_id].nvapi;
          data.hm_device[device_id].nvml              = hm_adapters_nvml[platform_devices_id].nvml;
          data.hm_device[device_id].xnvctrl           = hm_adapters_xnvctrl[platform_devices_id].xnvctrl;
          data.hm_device[device_id].od_version        = 0;
          data.hm_device[device_id].fan_get_supported = hm_adapters_nvml[platform_devices_id].fan_get_supported;
          data.hm_device[device_id].fan_set_supported = 0;
        }
      }
    }

    /**
     * powertune on user request
     */

    if (user_options->powertune_enable == true)
    {
      hc_thread_mutex_lock (mux_hwmon);

      for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped) continue;

        if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
        {
          /**
           * Temporary fix:
           * with AMD r9 295x cards it seems that we need to set the powertune value just AFTER the ocl init stuff
           * otherwise after hc_clCreateContext () etc, powertune value was set back to "normal" and cards unfortunately
           * were not working @ full speed (setting hm_ADL_Overdrive_PowerControl_Set () here seems to fix the problem)
           * Driver / ADL bug?
           */

          if (data.hm_device[device_id].od_version == 6)
          {
            int ADL_rc;

            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            if ((ADL_rc = hm_ADL_Overdrive6_PowerControl_Caps (data.hm_adl, data.hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
            {
              log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

              return -1;
            }

            // first backup current value, we will restore it later

            if (powertune_supported != 0)
            {
              // powercontrol settings

              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (data.hm_adl, data.hm_device[device_id].adl, &powertune)) == ADL_OK)
              {
                ADL_rc = hm_ADL_Overdrive_PowerControl_Get (data.hm_adl, data.hm_device[device_id].adl, &od_power_control_status[device_id]);
              }

              if (ADL_rc != ADL_OK)
              {
                log_error ("ERROR: Failed to get current ADL PowerControl settings");

                return -1;
              }

              if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
              {
                log_error ("ERROR: Failed to set new ADL PowerControl values");

                return -1;
              }

              // clocks

              memset (&od_clock_mem_status[device_id], 0, sizeof (ADLOD6MemClockState));

              od_clock_mem_status[device_id].state.iNumberOfPerformanceLevels = 2;

              if ((ADL_rc = hm_ADL_Overdrive_StateInfo_Get (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE, &od_clock_mem_status[device_id])) != ADL_OK)
              {
                log_error ("ERROR: Failed to get ADL memory and engine clock frequency");

                return -1;
              }

              // Query capabilities only to see if profiles were not "damaged", if so output a warning but do accept the users profile settings

              ADLOD6Capabilities caps = {0, 0, 0, {0, 0, 0}, {0, 0, 0}, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_Capabilities_Get (data.hm_adl, data.hm_device[device_id].adl, &caps)) != ADL_OK)
              {
                log_error ("ERROR: Failed to get ADL device capabilities");

                return -1;
              }

              int engine_clock_max =       (int) (0.6666 * caps.sEngineClockRange.iMax);
              int memory_clock_max =       (int) (0.6250 * caps.sMemoryClockRange.iMax);

              int warning_trigger_engine = (int) (0.25   * engine_clock_max);
              int warning_trigger_memory = (int) (0.25   * memory_clock_max);

              int engine_clock_profile_max = od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              int memory_clock_profile_max = od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              // warning if profile has too low max values

              if ((engine_clock_max - engine_clock_profile_max) > warning_trigger_engine)
              {
                log_info ("WARN: The custom profile seems to have too low maximum engine clock values. You therefore may not reach full performance");
              }

              if ((memory_clock_max - memory_clock_profile_max) > warning_trigger_memory)
              {
                log_info ("WARN: The custom profile seems to have too low maximum memory clock values. You therefore may not reach full performance");
              }

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[1].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[0].iMemoryClock = memory_clock_profile_max;
              performance_state->aLevels[1].iMemoryClock = memory_clock_profile_max;

              if ((ADL_rc = hm_ADL_Overdrive_State_Set (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
              {
                log_info ("ERROR: Failed to set ADL performance state");

                return -1;
              }

              local_free (performance_state);
            }

            // set powertune value only

            if (powertune_supported != 0)
            {
              // powertune set
              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (data.hm_adl, data.hm_device[device_id].adl, &powertune)) != ADL_OK)
              {
                log_error ("ERROR: Failed to get current ADL PowerControl settings");

                return -1;
              }

              if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
              {
                log_error ("ERROR: Failed to set new ADL PowerControl values");

                return -1;
              }
            }
          }
        }

        if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
        {
          // first backup current value, we will restore it later

          unsigned int limit;

          int powertune_supported = 0;

          if (hm_NVML_nvmlDeviceGetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, &limit) == NVML_SUCCESS)
          {
            powertune_supported = 1;
          }

          // if backup worked, activate the maximum allowed

          if (powertune_supported != 0)
          {
            unsigned int minLimit;
            unsigned int maxLimit;

            if (hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (data.hm_nvml, 0, data.hm_device[device_id].nvml, &minLimit, &maxLimit) == NVML_SUCCESS)
            {
              if (maxLimit > 0)
              {
                if (hm_NVML_nvmlDeviceSetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, maxLimit) == NVML_SUCCESS)
                {
                  // now we can be sure we need to reset later

                  nvml_power_limit[device_id] = limit;
                }
              }
            }
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    #if defined (DEBUG)
    if (user_options->benchmark == true) log_info ("Hashmode: %d", hashconfig->hash_mode);
    #endif

    if (user_options->quiet == false) log_info_nn ("Initializing device kernels and memory...");

    session_ctx_t *session_ctx = (session_ctx_t *) mymalloc (sizeof (session_ctx_t));

    data.session_ctx = session_ctx;

    session_ctx_init (session_ctx, kernel_rules_cnt, kernel_rules_buf, bitmap_size, bitmap_mask, bitmap_shift1, bitmap_shift2, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, bitmap_s2_a, bitmap_s2_b, bitmap_s2_c, bitmap_s2_d);

    opencl_session_begin (opencl_ctx, hashconfig, hashes, session_ctx, user_options, user_options_extra, folder_config);

    if (user_options->quiet == false) log_info_nn ("");

    /**
     * Store initial fanspeed if gpu_temp_retain is enabled
     */

    if (user_options->gpu_temp_disable == false)
    {
      if (user_options->gpu_temp_retain)
      {
        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (device_param->skipped) continue;

          hc_thread_mutex_lock (mux_hwmon);

          if (data.hm_device[device_id].fan_get_supported == 1)
          {
            const int fanspeed  = hm_get_fanspeed_with_device_id  (opencl_ctx, device_id);
            const int fanpolicy = hm_get_fanpolicy_with_device_id (opencl_ctx, device_id);

            // we also set it to tell the OS we take control over the fan and it's automatic controller
            // if it was set to automatic. we do not control user-defined fanspeeds.

            if (fanpolicy == 1)
            {
              data.hm_device[device_id].fan_set_supported = 1;

              int rc = -1;

              if (device_param->device_vendor_id == VENDOR_ID_AMD)
              {
                rc = hm_set_fanspeed_with_device_id_adl (device_id, fanspeed, 1);
              }
              else if (device_param->device_vendor_id == VENDOR_ID_NV)
              {
                #if defined (__linux__)
                rc = set_fan_control (data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE);
                #endif

                #if defined (_WIN)
                rc = hm_set_fanspeed_with_device_id_nvapi (device_id, fanspeed, 1);
                #endif
              }

              if (rc == 0)
              {
                data.hm_device[device_id].fan_set_supported = 1;
              }
              else
              {
                log_info ("WARNING: Failed to set initial fan speed for device #%u", device_id + 1);

                data.hm_device[device_id].fan_set_supported = 0;
              }
            }
            else
            {
              data.hm_device[device_id].fan_set_supported = 0;
            }
          }

          hc_thread_mutex_unlock (mux_hwmon);
        }
      }
    }

    /**
     * In benchmark-mode, inform user which algorithm is checked
     */

    if (user_options->benchmark == true)
    {
      if (user_options->machine_readable == false)
      {
        //quiet = 0;

        //user_options->quiet = quiet;

        char *hash_type = strhashtype (hashconfig->hash_mode); // not a bug

        log_info ("Hashtype: %s", hash_type);
        log_info ("");
      }
    }

    /**
     * keep track of the progress
     */

    data.words_progress_done     = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
    data.words_progress_rejected = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
    data.words_progress_restored = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));

    /**
     * open filehandles
     */

    #if defined (_WIN)
    if (_setmode (_fileno (stdin), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stdin", strerror (errno));

      return -1;
    }

    if (_setmode (_fileno (stdout), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stdout", strerror (errno));

      return -1;
    }

    if (_setmode (_fileno (stderr), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stderr", strerror (errno));

      return -1;
    }
    #endif

    /**
     * dictionary pad
     */

    wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

    wl_data->buf   = (char *) mymalloc (user_options->segment_size);
    wl_data->avail = user_options->segment_size;
    wl_data->incr  = user_options->segment_size;
    wl_data->cnt   = 0;
    wl_data->pos   = 0;

    cs_t  *css_buf   = NULL;
    uint   css_cnt   = 0;
    uint   dictcnt   = 0;
    uint   maskcnt   = 1;
    char **masks     = NULL;
    char **dictfiles = NULL;

    uint   mask_from_file = 0;

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options_extra->wordlist_mode == WL_MODE_FILE)
      {
        int wls_left = myargc - (user_options_extra->optind + 1);

        for (int i = 0; i < wls_left; i++)
        {
          char *l0_filename = myargv[user_options_extra->optind + 1 + i];

          struct stat l0_stat;

          if (stat (l0_filename, &l0_stat) == -1)
          {
            log_error ("ERROR: %s: %s", l0_filename, strerror (errno));

            return -1;
          }

          uint is_dir = S_ISDIR (l0_stat.st_mode);

          if (is_dir == 0)
          {
            dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

            dictcnt++;

            dictfiles[dictcnt - 1] = l0_filename;
          }
          else
          {
            // do not allow --keyspace w/ a directory

            if (user_options->keyspace == true)
            {
              log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

              return -1;
            }

            char **dictionary_files = NULL;

            dictionary_files = scan_directory (l0_filename);

            if (dictionary_files != NULL)
            {
              qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

              for (int d = 0; dictionary_files[d] != NULL; d++)
              {
                char *l1_filename = dictionary_files[d];

                struct stat l1_stat;

                if (stat (l1_filename, &l1_stat) == -1)
                {
                  log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                  return -1;
                }

                if (S_ISREG (l1_stat.st_mode))
                {
                  dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                  dictcnt++;

                  dictfiles[dictcnt - 1] = mystrdup (l1_filename);
                }
              }
            }

            local_free (dictionary_files);
          }
        }

        if (dictcnt < 1)
        {
          log_error ("ERROR: No usable dictionary file found.");

          return -1;
        }
      }
      else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
      {
        dictcnt = 1;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      // display

      char *dictfile1 = myargv[user_options_extra->optind + 1 + 0];
      char *dictfile2 = myargv[user_options_extra->optind + 1 + 1];

      // find the bigger dictionary and use as base

      FILE *fp1 = NULL;
      FILE *fp2 = NULL;

      struct stat tmp_stat;

      if ((fp1 = fopen (dictfile1, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

        return -1;
      }

      if (stat (dictfile1, &tmp_stat) == -1)
      {
        log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if (S_ISDIR (tmp_stat.st_mode))
      {
        log_error ("ERROR: %s must be a regular file", dictfile1, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if ((fp2 = fopen (dictfile2, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if (stat (dictfile2, &tmp_stat) == -1)
      {
        log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      if (S_ISDIR (tmp_stat.st_mode))
      {
        log_error ("ERROR: %s must be a regular file", dictfile2, strerror (errno));

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      data.combs_cnt = 1;

      //user_options->quiet = 1;

      const u64 words1_cnt = count_words (wl_data, fp1, dictfile1, dictstat_ctx);

      //user_options->quiet = quiet;

      if (words1_cnt == 0)
      {
        log_error ("ERROR: %s: empty file", dictfile1);

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      data.combs_cnt = 1;

      //user_options->quiet = 1;

      const u64 words2_cnt = count_words (wl_data, fp2, dictfile2, dictstat_ctx);

      //user_options->quiet = quiet;

      if (words2_cnt == 0)
      {
        log_error ("ERROR: %s: empty file", dictfile2);

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      fclose (fp1);
      fclose (fp2);

      data.dictfile  = dictfile1;
      data.dictfile2 = dictfile2;

      if (words1_cnt >= words2_cnt)
      {
        data.combs_cnt  = words2_cnt;
        data.combs_mode = COMBINATOR_MODE_BASE_LEFT;

        dictfiles = &data.dictfile;

        dictcnt = 1;
      }
      else
      {
        data.combs_cnt  = words1_cnt;
        data.combs_mode = COMBINATOR_MODE_BASE_RIGHT;

        dictfiles = &data.dictfile2;

        dictcnt = 1;

        // we also have to switch wordlist related rules!

        char *tmpc = data.rule_buf_l;

        data.rule_buf_l = data.rule_buf_r;
        data.rule_buf_r = tmpc;

        int   tmpi = data.rule_len_l;

        data.rule_len_l = data.rule_len_r;
        data.rule_len_r = tmpi;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      char *mask = NULL;

      maskcnt = 0;

      if (user_options->benchmark == false)
      {
        mask = myargv[user_options_extra->optind + 1];

        masks = (char **) mymalloc (INCR_MASKS * sizeof (char *));

        if ((user_options_extra->optind + 2) <= myargc)
        {
          struct stat file_stat;

          if (stat (mask, &file_stat) == -1)
          {
            maskcnt = 1;

            masks[maskcnt - 1] = mystrdup (mask);
          }
          else
          {
            int wls_left = myargc - (user_options_extra->optind + 1);

            uint masks_avail = INCR_MASKS;

            for (int i = 0; i < wls_left; i++)
            {
              if (i != 0)
              {
                mask = myargv[user_options_extra->optind + 1 + i];

                if (stat (mask, &file_stat) == -1)
                {
                  log_error ("ERROR: %s: %s", mask, strerror (errno));

                  return -1;
                }
              }

              uint is_file = S_ISREG (file_stat.st_mode);

              if (is_file == 1)
              {
                FILE *mask_fp;

                if ((mask_fp = fopen (mask, "r")) == NULL)
                {
                  log_error ("ERROR: %s: %s", mask, strerror (errno));

                  return -1;
                }

                char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

                while (!feof (mask_fp))
                {
                  memset (line_buf, 0, HCBUFSIZ_LARGE);

                  int line_len = fgetl (mask_fp, line_buf);

                  if (line_len == 0) continue;

                  if (line_buf[0] == '#') continue;

                  if (masks_avail == maskcnt)
                  {
                    masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

                    masks_avail += INCR_MASKS;
                  }

                  masks[maskcnt] = mystrdup (line_buf);

                  maskcnt++;
                }

                myfree (line_buf);

                fclose (mask_fp);
              }
              else
              {
                log_error ("ERROR: %s: unsupported file-type", mask);

                return -1;
              }
            }

            mask_from_file = 1;
          }
        }
        else
        {
          user_options->custom_charset_1 = (char *) "?l?d?u";
          user_options->custom_charset_2 = (char *) "?l?d";
          user_options->custom_charset_3 = (char *) "?l?d*!$@_";

          mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_1, 0, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_2, 1, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_3, 2, hashconfig);

          maskcnt = 1;

          masks[maskcnt - 1] = mystrdup ("?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d");

          user_options->increment = true;
        }
      }
      else
      {
        /**
         * generate full masks and charsets
         */

        mask = hashconfig_benchmark_mask (hashconfig);

        pw_min = mp_get_length (mask);
        pw_max = pw_min;

        masks = (char **) mymalloc (sizeof (char *));

        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);

        user_options->increment = true;
      }

      dictfiles = (char **) mycalloc (pw_max, sizeof (char *));

      if (user_options->increment == true)
      {
        if (user_options->increment_min > pw_min) pw_min = user_options->increment_min;
        if (user_options->increment_max < pw_max) pw_max = user_options->increment_max;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
    {
      data.combs_mode = COMBINATOR_MODE_BASE_LEFT;

      // display

      char *mask = myargv[myargc - 1];

      maskcnt = 0;

      masks = (char **) mymalloc (1 * sizeof (char *));

      // mod

      struct stat file_stat;

      if (stat (mask, &file_stat) == -1)
      {
        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);
      }
      else
      {
        uint is_file = S_ISREG (file_stat.st_mode);

        if (is_file == 1)
        {
          FILE *mask_fp;

          if ((mask_fp = fopen (mask, "r")) == NULL)
          {
            log_error ("ERROR: %s: %s", mask, strerror (errno));

            return -1;
          }

          char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

          uint masks_avail = 1;

          while (!feof (mask_fp))
          {
            memset (line_buf, 0, HCBUFSIZ_LARGE);

            int line_len = fgetl (mask_fp, line_buf);

            if (line_len == 0) continue;

            if (line_buf[0] == '#') continue;

            if (masks_avail == maskcnt)
            {
              masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

              masks_avail += INCR_MASKS;
            }

            masks[maskcnt] = mystrdup (line_buf);

            maskcnt++;
          }

          myfree (line_buf);

          fclose (mask_fp);

          mask_from_file = 1;
        }
        else
        {
          maskcnt = 1;

          masks[maskcnt - 1] = mystrdup (mask);
        }
      }

      // base

      int wls_left = myargc - (user_options_extra->optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[user_options_extra->optind + 1 + i];

        struct stat file_stat;

        if (stat (filename, &file_stat) == -1)
        {
          log_error ("ERROR: %s: %s", filename, strerror (errno));

          return -1;
        }

        uint is_dir = S_ISDIR (file_stat.st_mode);

        if (is_dir == 0)
        {
          dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

          dictcnt++;

          dictfiles[dictcnt - 1] = filename;
        }
        else
        {
          // do not allow --keyspace w/ a directory

          if (user_options->keyspace == true)
          {
            log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

            return -1;
          }

          char **dictionary_files = NULL;

          dictionary_files = scan_directory (filename);

          if (dictionary_files != NULL)
          {
            qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

            for (int d = 0; dictionary_files[d] != NULL; d++)
            {
              char *l1_filename = dictionary_files[d];

              struct stat l1_stat;

              if (stat (l1_filename, &l1_stat) == -1)
              {
                log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                return -1;
              }

              if (S_ISREG (l1_stat.st_mode))
              {
                dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                dictcnt++;

                dictfiles[dictcnt - 1] = mystrdup (l1_filename);
              }
            }
          }

          local_free (dictionary_files);
        }
      }

      if (dictcnt < 1)
      {
        log_error ("ERROR: No usable dictionary file found.");

        return -1;
      }

      if (user_options->increment == true)
      {
        maskcnt = 0;

        uint mask_min = user_options->increment_min; // we can't reject smaller masks here
        uint mask_max = (user_options->increment_max < pw_max) ? user_options->increment_max : pw_max;

        for (uint mask_cur = mask_min; mask_cur <= mask_max; mask_cur++)
        {
          char *cur_mask = mp_get_truncated_mask (mask, strlen (mask), mask_cur);

          if (cur_mask == NULL) break;

          masks[maskcnt] = cur_mask;

          maskcnt++;

          masks = (char **) myrealloc (masks, maskcnt * sizeof (char *), sizeof (char *));
        }
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      data.combs_mode = COMBINATOR_MODE_BASE_RIGHT;

      // display

      char *mask = myargv[user_options_extra->optind + 1 + 0];

      maskcnt = 0;

      masks = (char **) mymalloc (1 * sizeof (char *));

      // mod

      struct stat file_stat;

      if (stat (mask, &file_stat) == -1)
      {
        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);
      }
      else
      {
        uint is_file = S_ISREG (file_stat.st_mode);

        if (is_file == 1)
        {
          FILE *mask_fp;

          if ((mask_fp = fopen (mask, "r")) == NULL)
          {
            log_error ("ERROR: %s: %s", mask, strerror (errno));

            return -1;
          }

          char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

          uint masks_avail = 1;

          while (!feof (mask_fp))
          {
            memset (line_buf, 0, HCBUFSIZ_LARGE);

            int line_len = fgetl (mask_fp, line_buf);

            if (line_len == 0) continue;

            if (line_buf[0] == '#') continue;

            if (masks_avail == maskcnt)
            {
              masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

              masks_avail += INCR_MASKS;
            }

            masks[maskcnt] = mystrdup (line_buf);

            maskcnt++;
          }

          myfree (line_buf);

          fclose (mask_fp);

          mask_from_file = 1;
        }
        else
        {
          maskcnt = 1;

          masks[maskcnt - 1] = mystrdup (mask);
        }
      }

      // base

      int wls_left = myargc - (user_options_extra->optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[user_options_extra->optind + 2 + i];

        struct stat file_stat;

        if (stat (filename, &file_stat) == -1)
        {
          log_error ("ERROR: %s: %s", filename, strerror (errno));

          return -1;
        }

        uint is_dir = S_ISDIR (file_stat.st_mode);

        if (is_dir == 0)
        {
          dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

          dictcnt++;

          dictfiles[dictcnt - 1] = filename;
        }
        else
        {
          // do not allow --keyspace w/ a directory

          if (user_options->keyspace == true)
          {
            log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

            return -1;
          }

          char **dictionary_files = NULL;

          dictionary_files = scan_directory (filename);

          if (dictionary_files != NULL)
          {
            qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

            for (int d = 0; dictionary_files[d] != NULL; d++)
            {
              char *l1_filename = dictionary_files[d];

              struct stat l1_stat;

              if (stat (l1_filename, &l1_stat) == -1)
              {
                log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                return -1;
              }

              if (S_ISREG (l1_stat.st_mode))
              {
                dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                dictcnt++;

                dictfiles[dictcnt - 1] = mystrdup (l1_filename);
              }
            }
          }

          local_free (dictionary_files);
        }
      }

      if (dictcnt < 1)
      {
        log_error ("ERROR: No usable dictionary file found.");

        return -1;
      }

      if (user_options->increment == true)
      {
        maskcnt = 0;

        uint mask_min = user_options->increment_min; // we can't reject smaller masks here
        uint mask_max = (user_options->increment_max < pw_max) ? user_options->increment_max : pw_max;

        for (uint mask_cur = mask_min; mask_cur <= mask_max; mask_cur++)
        {
          char *cur_mask = mp_get_truncated_mask (mask, strlen (mask), mask_cur);

          if (cur_mask == NULL) break;

          masks[maskcnt] = cur_mask;

          maskcnt++;

          masks = (char **) myrealloc (masks, maskcnt * sizeof (char *), sizeof (char *));
        }
      }
    }

    data.pw_min = pw_min;
    data.pw_max = pw_max;

    /**
     * weak hash check
     */

    potfile_write_open (potfile_ctx);

    /**
     * weak hash check
     */

    if (user_options->weak_hash_threshold >= hashes->salts_cnt)
    {
      hc_device_param_t *device_param = NULL;

      for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped) continue;

        break;
      }

      if (user_options->quiet == false) log_info_nn ("Checking for weak hashes...");

      for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        weak_hash_check (opencl_ctx, device_param, hashconfig, hashes, salt_pos);
      }

      // Display hack, guarantee that there is at least one \r before real start

      //if (user_options->quiet == false) log_info ("");
    }

    /**
     * status and monitor threads
     */

    uint inner_threads_cnt = 0;

    hc_thread_t *inner_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

    data.shutdown_inner = 0;

    /**
      * Outfile remove
      */

    if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, NULL);

      inner_threads_cnt++;

      if (user_options->outfile_check_timer != 0)
      {
        if (data.outfile_check_directory != NULL)
        {
          if ((hashconfig->hash_mode !=  5200) &&
            !((hashconfig->hash_mode >=  6200) && (hashconfig->hash_mode <=  6299)) &&
            !((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799)) &&
              (hashconfig->hash_mode != 9000))
          {
            hc_thread_create (inner_threads[inner_threads_cnt], thread_outfile_remove, NULL);

            inner_threads_cnt++;
          }
          else
          {
            user_options->outfile_check_timer = 0;
          }
        }
        else
        {
          user_options->outfile_check_timer = 0;
        }
      }
    }

    data.outfile_check_timer = user_options->outfile_check_timer;

    /**
     * main loop
     */

    if (user_options->quiet == false)
    {
      if (potfile_remove_cracks > 0)
      {
        if (potfile_remove_cracks == 1) log_info ("INFO: Removed 1 hash found in potfile\n");
        else                            log_info ("INFO: Removed %d hashes found in potfile\n", potfile_remove_cracks);
      }
    }

    char **induction_dictionaries = NULL;

    int induction_dictionaries_cnt = 0;

    hcstat_table_t *root_table_buf   = NULL;
    hcstat_table_t *markov_table_buf = NULL;

    uint initial_restore_done = 0;

    data.maskcnt = maskcnt;

    for (uint maskpos = rd->maskpos; maskpos < maskcnt; maskpos++)
    {
      //opencl_ctx->run_main_level1   = true;
      //opencl_ctx->run_main_level2   = true;
      opencl_ctx->run_main_level3   = true;
      opencl_ctx->run_thread_level1 = true;
      opencl_ctx->run_thread_level2 = true;

      if (maskpos > rd->maskpos)
      {
        rd->dictpos = 0;
      }

      rd->maskpos  = maskpos;
      data.maskpos = maskpos;

      if (user_options->attack_mode == ATTACK_MODE_HYBRID1 || user_options->attack_mode == ATTACK_MODE_HYBRID2 || user_options->attack_mode == ATTACK_MODE_BF)
      {
        char *mask = masks[maskpos];

        if (mask_from_file == 1)
        {
          if (mask[0] == '\\' && mask[1] == '#') mask++; // escaped comment sign (sharp) "\#"

          char *str_ptr;
          uint  str_pos;

          uint mask_offset = 0;

          uint separator_cnt;

          for (separator_cnt = 0; separator_cnt < 4; separator_cnt++)
          {
            str_ptr = strstr (mask + mask_offset, ",");

            if (str_ptr == NULL) break;

            str_pos = str_ptr - mask;

            // escaped separator, i.e. "\,"

            if (str_pos > 0)
            {
              if (mask[str_pos - 1] == '\\')
              {
                separator_cnt --;

                mask_offset = str_pos + 1;

                continue;
              }
            }

            // reset the offset

            mask_offset = 0;

            mask[str_pos] = '\0';

            switch (separator_cnt)
            {
              case 0:
                mp_reset_usr (mp_usr, 0);

                user_options->custom_charset_1 = mask;
                mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_1, 0, hashconfig);
                break;

              case 1:
                mp_reset_usr (mp_usr, 1);

                user_options->custom_charset_2 = mask;
                mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_2, 1, hashconfig);
                break;

              case 2:
                mp_reset_usr (mp_usr, 2);

                user_options->custom_charset_3 = mask;
                mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_3, 2, hashconfig);
                break;

              case 3:
                mp_reset_usr (mp_usr, 3);

                user_options->custom_charset_4 = mask;
                mp_setup_usr (mp_sys, mp_usr, user_options->custom_charset_4, 3, hashconfig);
                break;
            }

            mask = mask + str_pos + 1;
          }

          /**
           * What follows is a very special case where "\," is within the mask field of a line in a .hcmask file only because otherwise (without the "\")
           * it would be interpreted as a custom charset definition.
           *
           * We need to replace all "\," with just "," within the mask (but allow the special case "\\," which means "\" followed by ",")
           * Note: "\\" is not needed to replace all "\" within the mask! The meaning of "\\" within a line containing the string "\\," is just to allow "\" followed by ","
           */

          uint mask_len_cur = strlen (mask);

          uint mask_out_pos = 0;
          char mask_prev = 0;

          for (uint mask_iter = 0; mask_iter < mask_len_cur; mask_iter++, mask_out_pos++)
          {
            if (mask[mask_iter] == ',')
            {
              if (mask_prev == '\\')
              {
                mask_out_pos -= 1; // this means: skip the previous "\"
              }
            }

            mask_prev = mask[mask_iter];

            mask[mask_out_pos] = mask[mask_iter];
          }

          mask[mask_out_pos] = '\0';
        }

        if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (maskpos > 0)
          {
            local_free (css_buf);
            local_free (data.root_css_buf);
            local_free (data.markov_css_buf);

            local_free (masks[maskpos - 1]);
          }

          css_buf = mp_gen_css (mask, strlen (mask), mp_sys, mp_usr, &css_cnt, hashconfig);

          data.mask = mask;
          data.css_cnt = css_cnt;
          data.css_buf = css_buf;

          uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

          mp_css_to_uniq_tbl (css_cnt, css_buf, uniq_tbls);

          if (root_table_buf   == NULL) root_table_buf   = (hcstat_table_t *) mycalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
          if (markov_table_buf == NULL) markov_table_buf = (hcstat_table_t *) mycalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

          sp_setup_tbl (folder_config->shared_dir, user_options->markov_hcstat, user_options->markov_disable, user_options->markov_classic, root_table_buf, markov_table_buf);

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, user_options->markov_threshold, uniq_tbls);

          data.combs_cnt = sp_get_sum (0, css_cnt, root_css_buf);

          local_free (root_table_buf);
          local_free (markov_table_buf);

          // args

          for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

            if (device_param->skipped) continue;

            device_param->kernel_params_mp[0] = &device_param->d_combs;
            device_param->kernel_params_mp[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_buf64[3] = 0;
            device_param->kernel_params_mp_buf32[4] = css_cnt;
            device_param->kernel_params_mp_buf32[5] = 0;
            device_param->kernel_params_mp_buf32[6] = 0;
            device_param->kernel_params_mp_buf32[7] = 0;

            if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_buf32[5] = full01;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_buf32[5] = full80;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_buf32[6] = 1;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_buf32[7] = 1;
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
            {
              device_param->kernel_params_mp_buf32[5] = 0;
              device_param->kernel_params_mp_buf32[6] = 0;
              device_param->kernel_params_mp_buf32[7] = 0;
            }

            cl_int CL_err = CL_SUCCESS;

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp[i]);
            for (uint i = 4; i < 8; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp[i]);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err |= hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   root_css_buf,   0, NULL, NULL);
            CL_err |= hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, markov_css_buf, 0, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          dictcnt = 0;  // number of "sub-masks", i.e. when using incremental mode

          if (user_options->increment == true)
          {
            for (uint i = 0; i < dictcnt; i++)
            {
              local_free (dictfiles[i]);
            }

            for (uint pw_len = MAX (1, pw_min); pw_len <= pw_max; pw_len++)
            {
              char *l1_filename = mp_get_truncated_mask (mask, strlen (mask), pw_len);

              if (l1_filename == NULL) break;

              dictcnt++;

              dictfiles[dictcnt - 1] = l1_filename;
            }
          }
          else
          {
            dictcnt++;

            dictfiles[dictcnt - 1] = mask;
          }

          if (dictcnt == 0)
          {
            log_error ("ERROR: Mask is too small");

            return -1;
          }
        }
      }

      free (induction_dictionaries);

      // induction_dictionaries_cnt = 0; // implied

      if (user_options->attack_mode != ATTACK_MODE_BF)
      {
        if ((user_options->keyspace == false) && (user_options->benchmark == false) && (user_options->opencl_info == false))
        {
          induction_dictionaries = scan_directory (induction_directory);

          induction_dictionaries_cnt = count_dictionaries (induction_dictionaries);
        }
      }

      if (induction_dictionaries_cnt)
      {
        qsort (induction_dictionaries, induction_dictionaries_cnt, sizeof (char *), sort_by_mtime);
      }

      /**
       * prevent the user from using --skip/--limit together w/ maskfile and or dictfile
       */

      if (user_options->skip != 0 || user_options->limit != 0)
      {
        if ((maskcnt > 1) || (dictcnt > 1))
        {
          log_error ("ERROR: --skip/--limit are not supported with --increment or mask files");

          return -1;
        }
      }

      /**
       * prevent the user from using --keyspace together w/ maskfile and or dictfile
       */

      if (user_options->keyspace == true)
      {
        if ((maskcnt > 1) || (dictcnt > 1))
        {
          log_error ("ERROR: --keyspace is not supported with --increment or mask files");

          return -1;
        }
      }

      for (uint dictpos = rd->dictpos; dictpos < dictcnt; dictpos++)
      {
        if (opencl_ctx->run_main_level3 == false) break;

        //opencl_ctx->run_main_level1   = true;
        //opencl_ctx->run_main_level2   = true;
        //opencl_ctx->run_main_level3   = true;
        opencl_ctx->run_thread_level1 = true;
        opencl_ctx->run_thread_level2 = true;

        rd->dictpos = dictpos;

        char *subid = logfile_generate_subid ();

        data.subid = subid;

        logfile_sub_msg ("START");

        memset (data.words_progress_done,     0, hashes->salts_cnt * sizeof (u64));
        memset (data.words_progress_rejected, 0, hashes->salts_cnt * sizeof (u64));
        memset (data.words_progress_restored, 0, hashes->salts_cnt * sizeof (u64));

        memset (data.cpt_buf, 0, CPT_BUF * sizeof (cpt_t));

        data.cpt_pos = 0;

        data.cpt_start = time (NULL);

        data.cpt_total = 0;

        if (data.restore == false)
        {
          rd->words_cur = user_options->skip;

          user_options->skip = 0;

          data.skip = 0;
        }

        data.ms_paused = 0;

        data.kernel_power_final = 0;

        data.words_cur = rd->words_cur;

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (device_param->skipped) continue;

          device_param->speed_pos = 0;

          memset (device_param->speed_cnt, 0, SPEED_CACHE * sizeof (u64));
          memset (device_param->speed_ms,  0, SPEED_CACHE * sizeof (double));

          device_param->exec_pos = 0;

          memset (device_param->exec_ms, 0, EXEC_CACHE * sizeof (double));

          device_param->outerloop_pos  = 0;
          device_param->outerloop_left = 0;
          device_param->innerloop_pos  = 0;
          device_param->innerloop_left = 0;

          // some more resets:

          if (device_param->pws_buf) memset (device_param->pws_buf, 0, device_param->size_pws);

          device_param->pws_cnt = 0;

          device_param->words_off  = 0;
          device_param->words_done = 0;
        }

        // figure out some workload

        if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
        {
          if (user_options_extra->wordlist_mode == WL_MODE_FILE)
          {
            char *dictfile = NULL;

            if (induction_dictionaries_cnt)
            {
              dictfile = induction_dictionaries[0];
            }
            else
            {
              dictfile = dictfiles[dictpos];
            }

            data.dictfile = dictfile;

            logfile_sub_string (dictfile);

            for (uint i = 0; i < user_options->rp_files_cnt; i++)
            {
              logfile_sub_var_string ("rulefile", user_options->rp_files[i]);
            }

            FILE *fd2 = fopen (dictfile, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

            fclose (fd2);

            if (data.words_cnt == 0)
            {
              logfile_sub_msg ("STOP");

              continue;
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_COMBI)
        {
          char *dictfile  = data.dictfile;
          char *dictfile2 = data.dictfile2;

          logfile_sub_string (dictfile);
          logfile_sub_string (dictfile2);

          if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
          {
            FILE *fd2 = fopen (dictfile, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

            fclose (fd2);
          }
          else if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
          {
            FILE *fd2 = fopen (dictfile2, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile2, dictstat_ctx);

            fclose (fd2);
          }

          if (data.words_cnt == 0)
          {
            logfile_sub_msg ("STOP");

            continue;
          }
        }
        else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          char *dictfile = NULL;

          if (induction_dictionaries_cnt)
          {
            dictfile = induction_dictionaries[0];
          }
          else
          {
            dictfile = dictfiles[dictpos];
          }

          data.dictfile = dictfile;

          char *mask = data.mask;

          logfile_sub_string (dictfile);
          logfile_sub_string (mask);

          FILE *fd2 = fopen (dictfile, "rb");

          if (fd2 == NULL)
          {
            log_error ("ERROR: %s: %s", dictfile, strerror (errno));

            return -1;
          }

          data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

          fclose (fd2);

          if (data.words_cnt == 0)
          {
            logfile_sub_msg ("STOP");

            continue;
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          local_free (css_buf);
          local_free (data.root_css_buf);
          local_free (data.markov_css_buf);

          char *mask = dictfiles[dictpos];

          logfile_sub_string (mask);

          // base

          css_buf = mp_gen_css (mask, strlen (mask), mp_sys, mp_usr, &css_cnt, hashconfig);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
          {
            uint css_cnt_unicode = css_cnt * 2;

            cs_t *css_buf_unicode = (cs_t *) mycalloc (css_cnt_unicode, sizeof (cs_t));

            for (uint i = 0, j = 0; i < css_cnt; i += 1, j += 2)
            {
              memcpy (&css_buf_unicode[j + 0], &css_buf[i], sizeof (cs_t));

              css_buf_unicode[j + 1].cs_buf[0] = 0;
              css_buf_unicode[j + 1].cs_len    = 1;
            }

            free (css_buf);

            css_buf = css_buf_unicode;
            css_cnt = css_cnt_unicode;
          }

          // check if mask is not too large or too small for pw_min/pw_max  (*2 if unicode)

          uint mask_min = pw_min;
          uint mask_max = pw_max;

          if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
          {
            mask_min *= 2;
            mask_max *= 2;
          }

          if ((css_cnt < mask_min) || (css_cnt > mask_max))
          {
            if (css_cnt < mask_min)
            {
              log_info ("WARNING: Skipping mask '%s' because it is smaller than the minimum password length", mask);
            }

            if (css_cnt > mask_max)
            {
              log_info ("WARNING: Skipping mask '%s' because it is larger than the maximum password length", mask);
            }

            // skip to next mask

            logfile_sub_msg ("STOP");

            continue;
          }

          uint save_css_cnt = css_cnt;

          if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
          {
            if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
            {
              uint  salt_len = (uint)   hashes->salts_buf[0].salt_len;
              char *salt_buf = (char *) hashes->salts_buf[0].salt_buf;

              uint css_cnt_salt = css_cnt + salt_len;

              cs_t *css_buf_salt = (cs_t *) mycalloc (css_cnt_salt, sizeof (cs_t));

              memcpy (css_buf_salt, css_buf, css_cnt * sizeof (cs_t));

              for (uint i = 0, j = css_cnt; i < salt_len; i++, j++)
              {
                css_buf_salt[j].cs_buf[0] = salt_buf[i];
                css_buf_salt[j].cs_len    = 1;
              }

              free (css_buf);

              css_buf = css_buf_salt;
              css_cnt = css_cnt_salt;
            }
          }

          data.mask = mask;
          data.css_cnt = css_cnt;
          data.css_buf = css_buf;

          if (maskpos > 0 && dictpos == 0) free (masks[maskpos - 1]);

          uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

          mp_css_to_uniq_tbl (css_cnt, css_buf, uniq_tbls);

          if (root_table_buf   == NULL) root_table_buf   = (hcstat_table_t *) mycalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
          if (markov_table_buf == NULL) markov_table_buf = (hcstat_table_t *) mycalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

          sp_setup_tbl (folder_config->shared_dir, user_options->markov_hcstat, user_options->markov_disable, user_options->markov_classic, root_table_buf, markov_table_buf);

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, user_options->markov_threshold, uniq_tbls);

          data.words_cnt = sp_get_sum (0, css_cnt, root_css_buf);

          local_free (root_table_buf);
          local_free (markov_table_buf);

          // copy + args

          uint css_cnt_l = css_cnt;
          uint css_cnt_r;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            if (save_css_cnt < 6)
            {
              css_cnt_r = 1;
            }
            else if (save_css_cnt == 6)
            {
              css_cnt_r = 2;
            }
            else
            {
              if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
              {
                if (save_css_cnt == 8 || save_css_cnt == 10)
                {
                  css_cnt_r = 2;
                }
                else
                {
                  css_cnt_r = 4;
                }
              }
              else
              {
                if ((css_buf[0].cs_len * css_buf[1].cs_len * css_buf[2].cs_len) > 256)
                {
                  css_cnt_r = 3;
                }
                else
                {
                  css_cnt_r = 4;
                }
              }
            }
          }
          else
          {
            css_cnt_r = 1;

            /* unfinished code?
            int sum = css_buf[css_cnt_r - 1].cs_len;

            for (uint i = 1; i < 4 && i < css_cnt; i++)
            {
              if (sum > 1) break; // we really don't need alot of amplifier them for slow hashes

              css_cnt_r++;

              sum *= css_buf[css_cnt_r - 1].cs_len;
            }
            */
          }

          css_cnt_l -= css_cnt_r;

          data.bfs_cnt = sp_get_sum (0, css_cnt_r, root_css_buf);

          for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

            if (device_param->skipped) continue;

            device_param->kernel_params_mp_l[0] = &device_param->d_pws_buf;
            device_param->kernel_params_mp_l[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp_l[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_l_buf64[3] = 0;
            device_param->kernel_params_mp_l_buf32[4] = css_cnt_l;
            device_param->kernel_params_mp_l_buf32[5] = css_cnt_r;
            device_param->kernel_params_mp_l_buf32[6] = 0;
            device_param->kernel_params_mp_l_buf32[7] = 0;
            device_param->kernel_params_mp_l_buf32[8] = 0;

            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_l_buf32[6] = full01;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_l_buf32[6] = full80;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_l_buf32[7] = 1;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_l_buf32[8] = 1;

            device_param->kernel_params_mp_r[0] = &device_param->d_bfs;
            device_param->kernel_params_mp_r[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp_r[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_r_buf64[3] = 0;
            device_param->kernel_params_mp_r_buf32[4] = css_cnt_r;
            device_param->kernel_params_mp_r_buf32[5] = 0;
            device_param->kernel_params_mp_r_buf32[6] = 0;
            device_param->kernel_params_mp_r_buf32[7] = 0;

            cl_int CL_err = CL_SUCCESS;

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_l, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp_l[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_l, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp_l[i]);
            for (uint i = 4; i < 9; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_l, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp_l[i]);

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_r, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp_r[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_r, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp_r[i]);
            for (uint i = 4; i < 8; i++) CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, device_param->kernel_mp_r, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp_r[i]);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err |= hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   root_css_buf,   0, NULL, NULL);
            CL_err |= hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, markov_css_buf, 0, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }

        u64 words_base = data.words_cnt;

        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (data.kernel_rules_cnt)
          {
            words_base /= data.kernel_rules_cnt;
          }
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (data.combs_cnt)
          {
            words_base /= data.combs_cnt;
          }
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (data.bfs_cnt)
          {
            words_base /= data.bfs_cnt;
          }
        }

        data.words_base = words_base;

        if (user_options->keyspace == true)
        {
          log_info ("%" PRIu64 "", words_base);

          return 0;
        }

        if (data.words_cur > data.words_base)
        {
          log_error ("ERROR: Restore value greater keyspace");

          return -1;
        }

        if (data.words_cur)
        {
          if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
          {
            for (uint i = 0; i < hashes->salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.kernel_rules_cnt;
            }
          }
          else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
          {
            for (uint i = 0; i < hashes->salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.combs_cnt;
            }
          }
          else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
          {
            for (uint i = 0; i < hashes->salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.bfs_cnt;
            }
          }
        }

        /*
         * Update dictionary statistic
         */

        if (user_options->keyspace == false)
        {
          dictstat_write (dictstat_ctx);
        }

        /**
         * Update loopback file
         */

        if (user_options->loopback == true)
        {
          loopback_write_open (loopback_ctx, induction_directory);
        }

        /**
         * some algorithms have a maximum kernel-loops count
         */

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (device_param->skipped) continue;

          if (device_param->kernel_loops_min < device_param->kernel_loops_max)
          {
            u32 innerloop_cnt = 0;

            if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
            {
              if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = data.kernel_rules_cnt;
              else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = data.combs_cnt;
              else if (user_options_extra->attack_kern == ATTACK_KERN_BF)        innerloop_cnt = data.bfs_cnt;
            }
            else
            {
              innerloop_cnt = hashes->salts_buf[0].salt_iter;
            }

            if ((innerloop_cnt >= device_param->kernel_loops_min) &&
                (innerloop_cnt <= device_param->kernel_loops_max))
            {
              device_param->kernel_loops_max = innerloop_cnt;
            }
          }
        }

        /**
         * create autotune threads
         */

        hc_thread_t *c_threads = (hc_thread_t *) mycalloc (opencl_ctx->devices_cnt, sizeof (hc_thread_t));

        opencl_ctx->devices_status = STATUS_AUTOTUNE;

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          hc_thread_create (c_threads[device_id], thread_autotune, device_param);
        }

        hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

        /*
         * Inform user about possible slow speeds
         */

        uint hardware_power_all = 0;

        uint kernel_power_all = 0;

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          hardware_power_all += device_param->hardware_power;

          kernel_power_all += device_param->kernel_power;
        }

        data.hardware_power_all = hardware_power_all; // hardware_power_all is the same as kernel_power_all but without the influence of kernel_accel on the devices

        data.kernel_power_all = kernel_power_all;

        if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
        {
          if (data.words_base < kernel_power_all)
          {
            if (user_options->quiet == false)
            {
              clear_prompt ();

              log_info ("ATTENTION!");
              log_info ("  The wordlist or mask you are using is too small.");
              log_info ("  Therefore, hashcat is unable to utilize the full parallelization power of your device(s).");
              log_info ("  The cracking speed will drop.");
              log_info ("  Workaround: https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_to_create_more_work_for_full_speed");
              log_info ("");
            }
          }
        }

        /**
         * create cracker threads
         */

        opencl_ctx->devices_status = STATUS_RUNNING;

        if (initial_restore_done == 0)
        {
          if (data.restore_disable == 0) cycle_restore (opencl_ctx);

          initial_restore_done = 1;
        }

        hc_timer_set (&data.timer_running);

        if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
        {
          if ((user_options->quiet == false) && (user_options->status == false) && (user_options->benchmark == false))
          {
            if (user_options->quiet == false) send_prompt ();
          }
        }
        else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
        {
          if (user_options->quiet == false) log_info ("Starting attack in stdin mode...");
          if (user_options->quiet == false) log_info ("");
        }

        time_t runtime_start;

        time (&runtime_start);

        data.runtime_start = runtime_start;

        data.prepare_time += runtime_start - prepare_start;

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
          {
            hc_thread_create (c_threads[device_id], thread_calc_stdin, device_param);
          }
          else
          {
            hc_thread_create (c_threads[device_id], thread_calc, device_param);
          }
        }

        hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

        local_free (c_threads);

        if ((opencl_ctx->devices_status != STATUS_CRACKED)
         && (opencl_ctx->devices_status != STATUS_ABORTED)
         && (opencl_ctx->devices_status != STATUS_QUIT)
         && (opencl_ctx->devices_status != STATUS_BYPASS))
        {
          opencl_ctx->devices_status = STATUS_EXHAUSTED;
        }

        logfile_sub_var_uint ("status-after-work", opencl_ctx->devices_status);

        data.restore = 0;

        if (induction_dictionaries_cnt)
        {
          unlink (induction_dictionaries[0]);
        }

        free (induction_dictionaries);

        if (user_options->attack_mode != ATTACK_MODE_BF)
        {
          if ((user_options->keyspace == false) && (user_options->benchmark == false) && (user_options->opencl_info == false))
          {
            induction_dictionaries = scan_directory (induction_directory);

            induction_dictionaries_cnt = count_dictionaries (induction_dictionaries);
          }
        }

        if (user_options->benchmark == true)
        {
          status_benchmark (opencl_ctx, hashconfig);

          if (user_options->machine_readable == false)
          {
            log_info ("");
          }
        }
        else
        {
          if (user_options->quiet == false)
          {
            clear_prompt ();

            log_info ("");

            status_display (opencl_ctx, hashconfig, hashes);

            log_info ("");
          }
          else
          {
            if (user_options->status == true)
            {
              status_display (opencl_ctx, hashconfig, hashes);
            }
          }
        }

        if (induction_dictionaries_cnt)
        {
          qsort (induction_dictionaries, induction_dictionaries_cnt, sizeof (char *), sort_by_mtime);

          // yeah, this next statement is a little hack to make sure that --loopback runs correctly (because with it we guarantee that the loop iterates one more time)

          dictpos--;
        }

        /**
         * Update loopback file
         */

        if (user_options->loopback == true)
        {
          loopback_write_close (loopback_ctx);
        }

        time_t runtime_stop;

        time (&runtime_stop);

        data.runtime_stop = runtime_stop;

        logfile_sub_uint (runtime_start);
        logfile_sub_uint (runtime_stop);

        time (&prepare_start);

        logfile_sub_msg ("STOP");

        global_free (subid);

        // finalize task

        if (opencl_ctx->run_main_level3 == false) break;
      }

      if (opencl_ctx->run_main_level2 == false) break;
    }

    // problems could occur if already at startup everything was cracked (because of .pot file reading etc), we must set some variables here to avoid NULL pointers
    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options_extra->wordlist_mode == WL_MODE_FILE)
      {
        if (data.dictfile == NULL)
        {
          if (dictfiles != NULL)
          {
            data.dictfile = dictfiles[0];

            hc_timer_set (&data.timer_running);
          }
        }
      }
    }
    // NOTE: combi is okay because it is already set beforehand
    else if (user_options->attack_mode == ATTACK_MODE_HYBRID1 || user_options->attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (data.dictfile == NULL)
      {
        if (dictfiles != NULL)
        {
          hc_timer_set (&data.timer_running);

          data.dictfile = dictfiles[0];
        }
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (data.mask == NULL)
      {
        hc_timer_set (&data.timer_running);

        data.mask = masks[0];
      }
    }

    // if cracked / aborted remove last induction dictionary

    for (int file_pos = 0; file_pos < induction_dictionaries_cnt; file_pos++)
    {
      struct stat induct_stat;

      if (stat (induction_dictionaries[file_pos], &induct_stat) == 0)
      {
        unlink (induction_dictionaries[file_pos]);
      }
    }

    // wait for inner threads

    data.shutdown_inner = 1;

    for (uint thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
    {
      hc_thread_wait (1, &inner_threads[thread_idx]);
    }

    local_free (inner_threads);

    // we dont need restore file anymore
    if (data.restore_disable == 0)
    {
      if ((opencl_ctx->devices_status == STATUS_EXHAUSTED) || (opencl_ctx->devices_status == STATUS_CRACKED))
      {
        unlink (eff_restore_file);
        unlink (new_restore_file);
      }
      else
      {
        cycle_restore (opencl_ctx);
      }
    }

    // finally save left hashes

    if ((hashes->hashlist_mode == HL_MODE_FILE) && (user_options->remove == 1) && (hashes->digests_saved != hashes->digests_done))
    {
      save_hash (opencl_ctx);
    }

    /**
     * Clean up
     */

    // reset default fan speed

    if (user_options->gpu_temp_disable == false)
    {
      if (user_options->gpu_temp_retain)
      {
        hc_thread_mutex_lock (mux_hwmon);

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (device_param->skipped) continue;

          if (data.hm_device[device_id].fan_set_supported == 1)
          {
            int rc = -1;

            if (device_param->device_vendor_id == VENDOR_ID_AMD)
            {
              rc = hm_set_fanspeed_with_device_id_adl (device_id, 100, 0);
            }
            else if (device_param->device_vendor_id == VENDOR_ID_NV)
            {
              #if defined (__linux__)
              rc = set_fan_control (data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE);
              #endif

              #if defined (_WIN)
              rc = hm_set_fanspeed_with_device_id_nvapi (device_id, 100, 0);
              #endif
            }

            if (rc == -1) log_info ("WARNING: Failed to restore default fan speed and policy for device #%", device_id + 1);
          }
        }

        hc_thread_mutex_unlock (mux_hwmon);
      }
    }

    // reset power tuning

    if (user_options->powertune_enable == true)
    {
      hc_thread_mutex_lock (mux_hwmon);

      for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped) continue;

        if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
        {
          if (data.hm_device[device_id].od_version == 6)
          {
            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            if ((hm_ADL_Overdrive6_PowerControl_Caps (data.hm_adl, data.hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
            {
              log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

              return -1;
            }

            if (powertune_supported != 0)
            {
              // powercontrol settings

              if ((hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, od_power_control_status[device_id])) != ADL_OK)
              {
                log_info ("ERROR: Failed to restore the ADL PowerControl values");

                return -1;
              }

              // clocks

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = od_clock_mem_status[device_id].state.aLevels[0].iEngineClock;
              performance_state->aLevels[1].iEngineClock = od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              performance_state->aLevels[0].iMemoryClock = od_clock_mem_status[device_id].state.aLevels[0].iMemoryClock;
              performance_state->aLevels[1].iMemoryClock = od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              if ((hm_ADL_Overdrive_State_Set (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
              {
                log_info ("ERROR: Failed to restore ADL performance state");

                return -1;
              }

              local_free (performance_state);
            }
          }
        }

        if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
        {
          unsigned int power_limit = nvml_power_limit[device_id];

          if (power_limit > 0)
          {
            hm_NVML_nvmlDeviceSetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, power_limit);
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    if (user_options->gpu_temp_disable == false)
    {
      if (data.hm_nvml)
      {
        hm_NVML_nvmlShutdown (data.hm_nvml);

        nvml_close (data.hm_nvml);

        data.hm_nvml = NULL;
      }

      if (data.hm_nvapi)
      {
        hm_NvAPI_Unload (data.hm_nvapi);

        nvapi_close (data.hm_nvapi);

        data.hm_nvapi = NULL;
      }

      if (data.hm_xnvctrl)
      {
        hm_XNVCTRL_XCloseDisplay (data.hm_xnvctrl);

        xnvctrl_close (data.hm_xnvctrl);

        data.hm_xnvctrl = NULL;
      }

      if (data.hm_adl)
      {
        hm_ADL_Main_Control_Destroy (data.hm_adl);

        adl_close (data.hm_adl);

        data.hm_adl = NULL;
      }
    }

    if (opencl_ctx->run_main_level1 == false) break;

    // free memory

    opencl_session_destroy (opencl_ctx);

    opencl_ctx_devices_destroy (opencl_ctx);

    local_free (masks);

    debugfile_destroy (debugfile_ctx);

    outfile_destroy (outfile_ctx);

    potfile_write_close (potfile_ctx);

    potfile_destroy (potfile_ctx);

    dictstat_destroy (dictstat_ctx);

    loopback_destroy (loopback_ctx);

    local_free (all_kernel_rules_cnt);
    local_free (all_kernel_rules_buf);

    local_free (wl_data->buf);
    local_free (wl_data);

    local_free (bitmap_s1_a);
    local_free (bitmap_s1_b);
    local_free (bitmap_s1_c);
    local_free (bitmap_s1_d);
    local_free (bitmap_s2_a);
    local_free (bitmap_s2_b);
    local_free (bitmap_s2_c);
    local_free (bitmap_s2_d);

    local_free (od_clock_mem_status);
    local_free (od_power_control_status);
    local_free (nvml_power_limit);

    global_free (kernel_rules_buf);

    global_free (root_css_buf);
    global_free (markov_css_buf);

    hashes_destroy (hashes);

    global_free (words_progress_done);
    global_free (words_progress_rejected);
    global_free (words_progress_restored);
  }

  // wait for outer threads

  data.shutdown_outer = 1;

  for (uint thread_idx = 0; thread_idx < outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &outer_threads[thread_idx]);
  }

  local_free (outer_threads);

  // destroy others mutex

  hc_thread_mutex_delete (mux_display);
  hc_thread_mutex_delete (mux_hwmon);

  // free memory

  local_free (hashconfig);

  local_free (eff_restore_file);
  local_free (new_restore_file);

  local_free (rd);

  // tuning db

  tuning_db_destroy (tuning_db);

  // induction directory

  if (induction_directory != NULL)
  {
    if (rmdir (induction_directory) == -1)
    {
      if (errno == ENOENT)
      {
        // good, we can ignore
      }
      else if (errno == ENOTEMPTY)
      {
        // good, we can ignore
      }
      else
      {
        log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

        return -1;
      }
    }

    local_free (induction_directory);
  }

  // outfile-check directory

  if (outfile_check_directory != NULL)
  {
    if (rmdir (outfile_check_directory) == -1)
    {
      if (errno == ENOENT)
      {
        // good, we can ignore
      }
      else if (errno == ENOTEMPTY)
      {
        // good, we can ignore
      }
      else
      {
        log_error ("ERROR: %s: %s", outfile_check_directory, strerror (errno));

        return -1;
      }
    }

    local_free (outfile_check_directory);
  }

  time_t proc_stop;

  time (&proc_stop);

  logfile_top_uint (proc_start);
  logfile_top_uint (proc_stop);

  logfile_top_msg ("STOP");

  if (user_options->quiet == false) log_info_nn ("Started: %s", ctime (&proc_start));
  if (user_options->quiet == false) log_info_nn ("Stopped: %s", ctime (&proc_stop));

  u32 rc_final = -1;

  if (opencl_ctx->devices_status == STATUS_ABORTED)   rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_QUIT)      rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_EXHAUSTED) rc_final = 1;
  if (opencl_ctx->devices_status == STATUS_CRACKED)   rc_final = 0;

  opencl_ctx_destroy (opencl_ctx);

  folder_config_destroy (folder_config);

  return rc_final;
}
