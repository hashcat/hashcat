/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TYPES_H
#define _TYPES_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#if defined (_WIN)
#include <windows.h>
#if defined (_BASETSD_H)
#else
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
#endif
#endif // _WIN

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint32_t uint; // we need to get rid of this sooner or later, for consistency

#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"

// timer

#if defined (_WIN)
typedef LARGE_INTEGER     hc_timer_t;
#elif defined (_POSIX)
typedef struct timeval    hc_timer_t;
#endif

// thread

#if defined (_WIN)
typedef HANDLE            hc_thread_t;
typedef CRITICAL_SECTION  hc_thread_mutex_t;
#elif defined (_POSIX)
typedef pthread_t         hc_thread_t;
typedef pthread_mutex_t   hc_thread_mutex_t;
#endif

// enums

typedef enum wl_mode
{
  WL_MODE_STDIN = 1,
  WL_MODE_FILE  = 2,
  WL_MODE_MASK  = 3

} wl_mode_t;

typedef enum hl_mode
{
  HL_MODE_FILE  = 4,
  HL_MODE_ARG   = 5

} hl_mode_t;

typedef struct
{
  char   *file_name;
  long   seek;
  time_t ctime;

} outfile_data_t;

typedef enum attack_mode
{
  ATTACK_MODE_STRAIGHT  = 0,
  ATTACK_MODE_COMBI     = 1,
  ATTACK_MODE_TOGGLE    = 2,
  ATTACK_MODE_BF        = 3,
  ATTACK_MODE_PERM      = 4,
  ATTACK_MODE_TABLE     = 5,
  ATTACK_MODE_HYBRID1   = 6,
  ATTACK_MODE_HYBRID2   = 7,
  ATTACK_MODE_NONE      = 100

} attack_mode_t;

typedef enum attack_kern
{
  ATTACK_KERN_STRAIGHT  = 0,
  ATTACK_KERN_COMBI     = 1,
  ATTACK_KERN_BF        = 3,
  ATTACK_KERN_NONE      = 100

} attack_kern_t;

typedef enum combinator_mode
{
  COMBINATOR_MODE_BASE_LEFT  = 10001,
  COMBINATOR_MODE_BASE_RIGHT = 10002

} combinator_mode_t;

typedef enum kern_run
{
  KERN_RUN_1    = 1000,
  KERN_RUN_12   = 1500,
  KERN_RUN_2    = 2000,
  KERN_RUN_23   = 2500,
  KERN_RUN_3    = 3000

} kern_run_t;

typedef enum kern_run_mp
{
  KERN_RUN_MP   = 101,
  KERN_RUN_MP_L = 102,
  KERN_RUN_MP_R = 103

} kern_run_mp_t;



/**
 * structs
 */

typedef struct
{
  u32  salt_buf[16];
  u32  salt_buf_pc[8];

  u32  salt_len;
  u32  salt_iter;
  u32  salt_sign[2];

  u32  keccak_mdlen;
  u32  truecrypt_mdlen;

  u32  digests_cnt;
  u32  digests_done;

  u32  digests_offset;

  u32  scrypt_N;
  u32  scrypt_r;
  u32  scrypt_p;

} salt_t;

typedef struct
{
  char *user_name;
  u32   user_len;

} user_t;

typedef struct
{
  user_t *user;
  char   *orighash;

} hashinfo_t;

typedef struct
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  int         cracked;
  hashinfo_t *hash_info;

} hash_t;

typedef struct
{
  char   *hashfile;

  u32     hashlist_mode;
  u32     hashlist_format;

  u32     digests_cnt;
  u32     digests_done;
  u32     digests_saved;

  void   *digests_buf;
  u32    *digests_shown;
  u32    *digests_shown_tmp;

  u32     salts_cnt;
  u32     salts_done;

  salt_t *salts_buf;
  u32    *salts_shown;

  void   *esalts_buf;

  u32     hashes_cnt;
  hash_t *hashes_buf;

  hashinfo_t  **hash_info;

} hashes_t;

struct _hashconfig
{
  char  separator;

  u32   hash_mode;
  u32   hash_type;
  u32   salt_type;
  u32   attack_exec;
  u32   opts_type;
  u32   kern_type;
  u32   dgst_size;
  u32   esalt_size;
  u32   opti_type;
  u32   is_salted;
  u32   dgst_pos0;
  u32   dgst_pos1;
  u32   dgst_pos2;
  u32   dgst_pos3;

  int (*parse_func) (char *, u32, hash_t *, const struct _hashconfig *);
};

typedef struct _hashconfig hashconfig_t;

typedef struct
{
  u32 i[16];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct
{
  u32  i;

} bf_t;

typedef struct
{
  u32  b[32];

} bs_word_t;

typedef struct
{
  u32  i[8];

  u32  pw_len;

} comb_t;

#define CPT_BUF 0x20000

typedef struct
{
  u32    cracked;
  time_t timestamp;

} cpt_t;

typedef struct
{
  u32  salt_pos;
  u32  digest_pos;
  u32  hash_pos;
  u32  gidvid;
  u32  il_pos;

} plain_t;

typedef struct
{
  u32  word_buf[16];

} wordl_t;

typedef struct
{
  u32  word_buf[1];

} wordr_t;

#define PARAMCNT 64

typedef struct __hc_device_param hc_device_param_t;

struct __hc_device_param
{
  cl_device_id      device;
  cl_device_type    device_type;

  u32     device_id;
  u32     platform_devices_id;   // for mapping with hms devices

  bool    skipped;

  u32     sm_major;
  u32     sm_minor;
  u32     kernel_exec_timeout;

  u32     device_processors;
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;

  u32     vector_width;

  u32     kernel_threads;
  u32     kernel_loops;
  u32     kernel_accel;
  u32     kernel_loops_min;
  u32     kernel_loops_max;
  u32     kernel_accel_min;
  u32     kernel_accel_max;
  u32     kernel_power;
  u32     hardware_power;

  size_t  size_pws;
  size_t  size_tmps;
  size_t  size_hooks;
  size_t  size_bfs;
  size_t  size_combs;
  size_t  size_rules;
  size_t  size_rules_c;
  size_t  size_root_css;
  size_t  size_markov_css;
  size_t  size_digests;
  size_t  size_salts;
  size_t  size_shown;
  size_t  size_results;
  size_t  size_plains;

  FILE   *combs_fp;
  comb_t *combs_buf;

  void   *hooks_buf;

  pw_t   *pws_buf;
  u32     pws_cnt;

  u64     words_off;
  u64     words_done;

  u32     outerloop_pos;
  u32     outerloop_left;

  u32     innerloop_pos;
  u32     innerloop_left;

  u32     exec_pos;
  double  exec_ms[EXEC_CACHE];

  // workaround cpu spinning

  double  exec_us_prev1[EXPECTED_ITERATIONS];
  double  exec_us_prev2[EXPECTED_ITERATIONS];
  double  exec_us_prev3[EXPECTED_ITERATIONS];

  // this is "current" speed

  u32     speed_pos;
  u64     speed_cnt[SPEED_CACHE];
  double  speed_ms[SPEED_CACHE];

  hc_timer_t timer_speed;

  // device specific attributes starting

  char   *device_name;
  char   *device_vendor;
  char   *device_name_chksum;
  char   *device_version;
  char   *driver_version;

  bool    opencl_v12;

  double  nvidia_spin_damp;

  cl_platform_id platform;

  cl_uint  device_vendor_id;
  cl_uint  platform_vendor_id;

  cl_kernel  kernel1;
  cl_kernel  kernel12;
  cl_kernel  kernel2;
  cl_kernel  kernel23;
  cl_kernel  kernel3;
  cl_kernel  kernel_mp;
  cl_kernel  kernel_mp_l;
  cl_kernel  kernel_mp_r;
  cl_kernel  kernel_amp;
  cl_kernel  kernel_tm;
  cl_kernel  kernel_weak;
  cl_kernel  kernel_memset;

  cl_context context;

  cl_program program;
  cl_program program_mp;
  cl_program program_amp;

  cl_command_queue command_queue;

  cl_mem  d_pws_buf;
  cl_mem  d_pws_amp_buf;
  cl_mem  d_words_buf_l;
  cl_mem  d_words_buf_r;
  cl_mem  d_rules;
  cl_mem  d_rules_c;
  cl_mem  d_combs;
  cl_mem  d_combs_c;
  cl_mem  d_bfs;
  cl_mem  d_bfs_c;
  cl_mem  d_tm_c;
  cl_mem  d_bitmap_s1_a;
  cl_mem  d_bitmap_s1_b;
  cl_mem  d_bitmap_s1_c;
  cl_mem  d_bitmap_s1_d;
  cl_mem  d_bitmap_s2_a;
  cl_mem  d_bitmap_s2_b;
  cl_mem  d_bitmap_s2_c;
  cl_mem  d_bitmap_s2_d;
  cl_mem  d_plain_bufs;
  cl_mem  d_digests_buf;
  cl_mem  d_digests_shown;
  cl_mem  d_salt_bufs;
  cl_mem  d_esalt_bufs;
  cl_mem  d_bcrypt_bufs;
  cl_mem  d_tmps;
  cl_mem  d_hooks;
  cl_mem  d_result;
  cl_mem  d_scryptV0_buf;
  cl_mem  d_scryptV1_buf;
  cl_mem  d_scryptV2_buf;
  cl_mem  d_scryptV3_buf;
  cl_mem  d_root_css_buf;
  cl_mem  d_markov_css_buf;

  void   *kernel_params[PARAMCNT];
  void   *kernel_params_mp[PARAMCNT];
  void   *kernel_params_mp_r[PARAMCNT];
  void   *kernel_params_mp_l[PARAMCNT];
  void   *kernel_params_amp[PARAMCNT];
  void   *kernel_params_tm[PARAMCNT];
  void   *kernel_params_memset[PARAMCNT];

  u32     kernel_params_buf32[PARAMCNT];

  u32     kernel_params_mp_buf32[PARAMCNT];
  u64     kernel_params_mp_buf64[PARAMCNT];

  u32     kernel_params_mp_r_buf32[PARAMCNT];
  u64     kernel_params_mp_r_buf64[PARAMCNT];

  u32     kernel_params_mp_l_buf32[PARAMCNT];
  u64     kernel_params_mp_l_buf64[PARAMCNT];

  u32     kernel_params_amp_buf32[PARAMCNT];
  u32     kernel_params_memset_buf32[PARAMCNT];
};

typedef struct
{
  int                 disable;

  void               *ocl;

  cl_uint             platforms_cnt;
  cl_platform_id     *platforms;

  cl_uint             platform_devices_cnt;
  cl_device_id       *platform_devices;

  u32                 devices_cnt;
  u32                 devices_active;

  hc_device_param_t  *devices_param;

  bool                run_main_level1;
  bool                run_main_level2;
  bool                run_main_level3;
  bool                run_thread_level1;
  bool                run_thread_level2;

  u32                 devices_status;

  u32                 opencl_platforms_filter;
  u32                 devices_filter;
  cl_device_type      device_types_filter;

  double              target_ms;

  int                 need_adl;
  int                 need_nvml;
  int                 need_nvapi;
  int                 need_xnvctrl;

  int                 force_jit_compilation;

  hc_thread_mutex_t   mux_dispatcher;
  hc_thread_mutex_t   mux_counter;

} opencl_ctx_t;

#if defined (__APPLE__)
typedef struct cpu_set
{
  u32 count;

} cpu_set_t;
#endif

typedef struct
{
  u32 bitmap_shift;
  u32 collisions;

} bitmap_result_t;

/* AES context.  */
typedef struct aes_context
{
  u32 bits;

  u32 rek[60];
  u32 rdk[60];

} aes_context_t;

typedef aes_context_t aes_ctx;

typedef struct
{
  FILE *fp;
  char *filename;
  u32   mode;

} debugfile_ctx_t;

typedef struct
{
  u64 cnt;

  #if defined (_POSIX)
  struct stat stat;
  #endif

  #if defined (_WIN)
  struct __stat64 stat;
  #endif

} dictstat_t;

typedef struct
{
  char *filename;

  dictstat_t *base;

  #if defined (_POSIX)
  size_t cnt;
  #else
  u32    cnt;
  #endif

} dictstat_ctx_t;

typedef struct
{
  HM_ADAPTER_ADL     adl;
  HM_ADAPTER_NVML    nvml;
  HM_ADAPTER_NVAPI   nvapi;
  HM_ADAPTER_XNVCTRL xnvctrl;

  int od_version;

  int fan_get_supported;
  int fan_set_supported;

} hm_attrs_t;

typedef struct
{
  FILE *fp;
  char *filename;

} loopback_ctx_t;

typedef struct
{
  u32  cs_buf[0x100];
  u32  cs_len;

} cs_t;

typedef struct
{
  u32  key;
  u64  val;

} hcstat_table_t;

typedef struct
{
  char *filename;

  FILE *fp;

  u32   outfile_format;
  u32   outfile_autohex;

} outfile_ctx_t;

typedef struct
{
  char     plain_buf[HCBUFSIZ_TINY];
  int      plain_len;

  hash_t   hash;

} pot_t;

typedef struct
{
  int      disable;

  FILE    *fp;
  char    *filename;

  pot_t   *pot;

  u32      pot_cnt;
  u32      pot_avail;
  u32      pot_hashes_avail;

} potfile_ctx_t;

typedef struct
{
  int  version;
  char cwd[256];
  u32  pid;

  u32  dictpos;
  u32  maskpos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

typedef struct
{
  u32  len;

  char buf[0x100];

} cpu_rule_t;

typedef struct
{
  u32  cmds[0x100];

} kernel_rule_t;

typedef struct
{
  FILE *fp;

  char  buf[BUFSIZ];
  int   len;

} out_t;

typedef struct
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct
{
  char *device_name;
  int   attack_mode;
  int   hash_type;
  int   workload_profile;
  int   vector_width;
  int   kernel_accel;
  int   kernel_loops;

} tuning_db_entry_t;

typedef struct
{
  tuning_db_alias_t *alias_buf;
  int                alias_cnt;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;

} tuning_db_t;

typedef struct
{
  char *buf;
  u32  incr;
  u32  avail;
  u32  cnt;
  u32  pos;

  void (*func) (char *, u32, u32 *, u32 *);

} wl_data_t;

typedef struct
{
  bool   usage;
  bool   version;
  bool   quiet;
  bool   benchmark;
  bool   stdout_flag;
  bool   show;
  bool   left;
  bool   username;
  bool   remove;
  u32    remove_timer;
  u64    skip;
  u64    limit;
  bool   force;
  bool   keyspace;
  bool   potfile_disable;
  char  *potfile_path;
  u32    debug_mode;
  char  *debug_file;
  char  *induction_dir;
  char  *outfile_check_dir;
  u32    runtime;
  u32    hash_mode;
  u32    attack_mode;
  char  *outfile;
  u32    outfile_format;
  bool   outfile_autohex;
  u32    outfile_check_timer;
  bool   restore;
  u32    restore_timer;
  bool   restore_disable;
  bool   status;
  u32    status_timer;
  bool   machine_readable;
  bool   loopback;
  u32    weak_hash_threshold;
  char  *session;
  bool   hex_charset;
  bool   hex_salt;
  bool   hex_wordlist;
  u32    rp_gen;
  u32    rp_gen_func_min;
  u32    rp_gen_func_max;
  u32    rp_gen_seed;
  char  *rule_buf_l;
  char  *rule_buf_r;
  bool   increment;
  u32    increment_min;
  u32    increment_max;
  char  *cpu_affinity;
  bool   opencl_info;
  char  *opencl_devices;
  char  *opencl_platforms;
  char  *opencl_device_types;
  u32    opencl_vector_width;
  char  *truecrypt_keyfiles;
  char  *veracrypt_keyfiles;
  u32    veracrypt_pim;
  u32    workload_profile;
  u32    kernel_accel;
  u32    kernel_loops;
  u32    nvidia_spin_damp;
  bool   gpu_temp_disable;
  u32    gpu_temp_abort;
  u32    gpu_temp_retain;
  bool   powertune_enable;
  bool   logfile_disable;
  u32    segment_size;
  u32    scrypt_tmto;
  char   separator;
  u32    bitmap_min;
  u32    bitmap_max;
  bool   markov_disable;
  bool   markov_classic;
  u32    markov_threshold;
  char  *markov_hcstat;
  char  *custom_charset_1;
  char  *custom_charset_2;
  char  *custom_charset_3;
  char  *custom_charset_4;
  u32    rp_files_cnt;
  char **rp_files;

  bool   attack_mode_chgd;
  bool   hash_mode_chgd;
  bool   increment_max_chgd;
  bool   increment_min_chgd;
  bool   kernel_accel_chgd;
  bool   kernel_loops_chgd;
  bool   nvidia_spin_damp_chgd;
  bool   opencl_vector_width_chgd;
  bool   outfile_format_chgd;
  bool   remove_timer_chgd;
  bool   rp_gen_seed_chgd;
  bool   runtime_chgd;
  bool   workload_profile_chgd;
  bool   segment_size_chgd;

} user_options_t;


typedef struct
{
  u32 attack_kern;

  u32 rule_len_r;
  u32 rule_len_l;

  u32 wordlist_mode;

  int optind;

} user_options_extra_t;

typedef struct
{
  u32             kernel_rules_cnt;
  kernel_rule_t  *kernel_rules_buf;

  u32             bitmap_size;
  u32             bitmap_mask;
  u32             bitmap_shift1;
  u32             bitmap_shift2;

  u32            *bitmap_s1_a;
  u32            *bitmap_s1_b;
  u32            *bitmap_s1_c;
  u32            *bitmap_s1_d;
  u32            *bitmap_s2_a;
  u32            *bitmap_s2_b;
  u32            *bitmap_s2_c;
  u32            *bitmap_s2_d;

} session_ctx_t;

typedef struct
{
  char *cwd;
  char *install_dir;
  char *profile_dir;
  char *session_dir;
  char *shared_dir;
  char *cpath_real;

} folder_config_t;

typedef struct
{
  /**
   * threads
   */

  u32     shutdown_inner;
  u32     shutdown_outer;

  /**
   * workload specific
   */

  u32     hardware_power_all;
  u32     kernel_power_all;
  u64     kernel_power_final; // we save that so that all divisions are done from the same base

  /**
   * attack specific
   */

  u32            kernel_rules_cnt;
  kernel_rule_t *kernel_rules_buf;

  u32     combs_mode;
  u32     combs_cnt;

  u32     bfs_cnt;

  u32     css_cnt;
  cs_t   *css_buf;

  cs_t   *root_css_buf;
  cs_t   *markov_css_buf;

  /**
   * hardware watchdog
   */

  void      *hm_adl;
  void      *hm_nvml;
  void      *hm_nvapi;
  void      *hm_xnvctrl;
  hm_attrs_t hm_device[DEVICES_MAX];

  /**
   * logging
   */

  u32     logfile_disable;
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
  u32     maskcnt;
  u32     maskpos;
  u32     wordlist_mode;
  char   *eff_restore_file;
  char   *new_restore_file;
  char   *induction_directory;
  char   *outfile_check_directory;



  u32     attack_mode;
  u32     attack_kern;
  u32     quiet;
  u32     force;
  u32     benchmark;
  u32     runtime;
  u32     hex_charset;
  u32     hex_salt;
  u32     hex_wordlist;
  u32     pw_min;
  u32     pw_max;
  u32     powertune_enable;
  u32     scrypt_tmto;
  u32     segment_size;
  char   *truecrypt_keyfiles;
  char   *veracrypt_keyfiles;
  u32     veracrypt_pim;

  opencl_ctx_t          *opencl_ctx;
  hashconfig_t          *hashconfig;
  hashes_t              *hashes;
  user_options_t        *user_options;
  user_options_extra_t  *user_options_extra;
  outfile_ctx_t         *outfile_ctx;
  potfile_ctx_t         *potfile_ctx;
  loopback_ctx_t        *loopback_ctx;
  debugfile_ctx_t       *debugfile_ctx;
  session_ctx_t         *session_ctx;

  /**
   * used for restore
   */

  restore_data_t *rd;

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

} hc_global_data_t;

#define RULES_MAX   256
#define PW_DICTMAX  31
#define PW_DICTMAX1 (PW_DICTMAX + 1)

#endif // _TYPES_H
