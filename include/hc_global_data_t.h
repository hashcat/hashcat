#pragma once
#include "config.h"
#include "common.h"
#include "types.h"
#include "shared.h"
#include "consts/devices_statuses.h"
#include "consts/hash_options.h"
#include "consts/optimizer_options.h"
#include "consts/hash_types.h"
#include "consts/salt_types.h"
#include "consts/kernel_types.h"
#include "consts/hashcat_modes.h"
#include "hc_device_param_t.h"
#include "hc_concurrency.h"
#include "ext_OpenCL.h"
#include "hwmon.h"

typedef struct hc_global_data_t_
{
  /**
  * threads
  */

  DEVICES_STATUS    devices_status;
  uint    devices_cnt;
  uint    devices_active;

  hc_device_param_t *devices_param;

  uint    shutdown_inner;
  uint    shutdown_outer;

  /**
  * workload specific
  */

  uint    hardware_power_all;
  uint    kernel_power_all;
  u64     kernel_power_final; // we save that so that all divisions are done from the same base

                              /**
                              * attack specific
                              */

  WL_MODE    wordlist_mode;
  HL_MODE    hashlist_mode;
  HLFMT    hashlist_format;

  ATTACK_MODE    attack_mode;
  ATTACK_KERN    attack_kern;
  uint    attack_exec;

  uint    kernel_rules_cnt;

  kernel_rule_t *kernel_rules_buf;

  uint    combs_mode;
  uint    combs_cnt;

  uint    bfs_cnt;

  uint    css_cnt;
  cs_t   *css_buf;

  cs_t   *root_css_buf;
  cs_t   *markov_css_buf;

  char   *rule_buf_l;
  char   *rule_buf_r;
  int     rule_len_l;
  int     rule_len_r;

  /**
  * opencl library stuff
  */

  OCL_PTR   *ocl;

  /**
  * hardware watchdog
  */

#ifdef WITH_HWMON
  ADL_PTR      *hm_adl;
  NVML_PTR      *hm_nvml;
  NVAPI_PTR      *hm_nvapi;
  XNVCTRL_PTR      *hm_xnvctrl;
  hm_attrs_t hm_device[DEVICES_MAX];
#endif

  /**
  * hashes
  */


  uint    digests_cnt;
  uint    digests_done;
  uint    digests_saved;

  void   *digests_buf;
  uint   *digests_shown;
  uint   *digests_shown_tmp;

  uint    salts_cnt;
  uint    salts_done;

  salt_t *salts_buf;
  uint   *salts_shown;

  void   *esalts_buf;

  uint    scrypt_tmp_size;
  uint    scrypt_tmto_final;

  /**
  * logging
  */

  uint    logfile_disable;
  char   *logfile;
  char   *topid;
  char   *subid;

  /**
  * crack-per-time
  */

  cpt_t   cpt_buf[CPT_BUF];
  int     cpt_pos;
  time_t  cpt_start;
  u64     cpt_total;

  /**
  * user
  */

  char   *dictfile;
  char   *dictfile2;
  char   *mask;
  uint    maskcnt;
  uint    maskpos;
  char   *session;
  char    separator;
  char   *hashfile;
  char   *homedir;
  char   *install_dir;
  char   *profile_dir;
  char   *session_dir;
  char   *shared_dir;
  char   *outfile;
  uint    outfile_format;
  uint    outfile_autohex;
  uint    outfile_check_timer;
  char   *eff_restore_file;
  char   *new_restore_file;
  char   *induction_directory;
  char   *outfile_check_directory;
  uint    loopback;
  char   *loopback_file;
  uint    restore;
  uint    restore_timer;
  uint    restore_disable;
  uint    status;
  uint    status_timer;
  uint    machine_readable;
  uint    quiet;
  uint    force;
  uint    benchmark;
  uint    runtime;
  uint    remove;
  uint    remove_timer;
  uint    debug_mode;
  char   *debug_file;
  uint    hex_charset;
  uint    hex_salt;
  uint    hex_wordlist;
  uint    pw_min;
  uint    pw_max;
  uint    powertune_enable;
  uint    scrypt_tmto;
  uint    segment_size;
  char   *truecrypt_keyfiles;
  char   *veracrypt_keyfiles;
  uint    veracrypt_pim;
  uint    workload_profile;
  char   *custom_charset_1;
  char   *custom_charset_2;
  char   *custom_charset_3;
  char   *custom_charset_4;

  uint    hash_mode;
  HASH_TYPE    hash_type;
  KERN_TYPE    kern_type;
  OPTS_TYPE    opts_type;
  SALT_TYPE    salt_type;
  uint    esalt_size;
  uint    isSalted;
  uint    dgst_size;
  OPTI_TYPE    opti_type;
  uint    dgst_pos0;
  uint    dgst_pos1;
  uint    dgst_pos2;
  uint    dgst_pos3;

#ifdef WITH_HWMON
  uint    gpu_temp_disable;
  uint    gpu_temp_abort;
  uint    gpu_temp_retain;
#endif

  char  **rp_files;
  uint    rp_files_cnt;
  uint    rp_gen;
  uint    rp_gen_seed;

  FILE   *pot_fp;

  /**
  * used for restore
  */

  u64     skip;
  u64     limit;

  restore_data_t *rd;

  u64     checkpoint_cur_words;     // used for the "stop at next checkpoint" feature

                                    /**
                                    * status, timer
                                    */

  time_t  runtime_start;
  time_t  runtime_stop;

  time_t  prepare_time;

  time_t  proc_start;
  time_t  proc_stop;

  u64     words_cnt;
  u64     words_cur;
  u64     words_base;

  u64    *words_progress_done;      // progress number of words done     per salt
  u64    *words_progress_rejected;  // progress number of words rejected per salt
  u64    *words_progress_restored;  // progress number of words restored per salt

  hc_timer_t timer_running;         // timer on current dict
  hc_timer_t timer_paused;          // timer on current dict

  double  ms_paused;                // timer on current dict

                                    /**
                                    * hash_info and username
                                    */

  hashinfo_t **hash_info;
  uint    username;

  int(*sort_by_digest) (const void *, const void *);

  int(*parse_func)     (char *, uint, hash_t *);

} hc_global_data_t;
