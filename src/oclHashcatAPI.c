/* 
 * 
 * 
 * Proposed oclhashcat API prototype
 * 
 * compile with:
 * 
 * make
 * 
 * or
 * 
 * make win32API win64API
 * 
 * 
 * Author: Rich Kelley
 * 
 * Derived from oclhashcat.c
 * 
 * Last Update: 21 March 2016
 * 
 */



#include <common.h>
#include <unistd.h>
#include <shared.h>
#ifndef WIN
#include <pthread.h>
#endif

#ifdef DEBUG
#define debug_print(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)
#define debug_prints(fmt, args...) fprintf(stderr, fmt, ##args) // simple debug print
#else
#define debug_print(fmt, args...) // Don't do anything in release builds 
#define debug_prints(fmt, args...)
#endif

#define HM_STR_BUF_SIZE 255

typedef unsigned int uint;

typedef struct hcapi_thread_args
{
  int c;
  char **v;

} thread_args;

typedef struct hcapi_options
{

  char *hash_input;
  uint version;
  uint quiet;
  uint benchmark;
  uint show;
  uint left;
  uint username;
  uint remove;
  uint remove_timer;
  uint64_t skip;
  uint64_t limit;
  uint keyspace;
  uint potfile_disable;
  char *potfile_path;
  uint debug_mode;
  char *debug_file;
  char *induction_dir;
  char *outfile_check_dir;
  uint force;
  uint runtime;
  uint hash_mode;
  uint attack_mode;
  uint markov_disable;
  uint markov_classic;
  uint markov_threshold;
  char *markov_hcstat;
  char *outfile;
  uint outfile_format;
  uint outfile_autohex;
  uint outfile_check_timer;
  uint restore;
  uint restore_timer;
  uint restore_disable;
  uint status;
  uint status_timer;
  uint status_automat;
  uint loopback;
  uint weak_hash_threshold;
  char *session;
  uint hex_charset;
  uint hex_salt;
  uint hex_wordlist;
  uint rp_gen;
  uint rp_gen_func_min;
  uint rp_gen_func_max;
  uint rp_gen_seed;
  char *rule_buf_l;
  char *rule_buf_r;
  uint increment;
  uint increment_min;
  uint increment_max;
  char *cpu_affinity;
  char *opencl_devices;
  char *opencl_platform;
  char *opencl_device_types;
  char *truecrypt_keyfiles;
  uint workload_profile;
  uint kernel_accel;
  uint kernel_loops;
  uint gpu_temp_disable;
  uint gpu_temp_abort;
  uint gpu_temp_retain;
  uint powertune_enable;
  uint logfile_disable;
  uint segment_size;
  uint scrypt_tmto;
  char separator;
  uint bitmap_min;
  uint bitmap_max;
  char *custom_charset_1;
  char *custom_charset_2;
  char *custom_charset_3;
  char *custom_charset_4;

  char *rp_files;
  void (*append_rules) (struct hcapi_options * options, char *new_file_path);

  char *dictmaskdir;
  void (*append_dictmaskdir) (struct hcapi_options * options, char *new_file_path);

} hcapi_options;

typedef struct hcapi_control
{

  int (*start) (int argc, char **argvv);

#ifdef WIN
    HANDLE (*start_thread) (int argc, char **argvv);
#else
  int (*start_thread) (int argc, char **argvv);
#endif

  int (*stop) (void);
  void (*generate_commandline) (hcapi_options options, int *c, char ***v);
  hc_global_data_t *(*get_data_ptr) (void);
  void (*status_data) (void);

  hcapi_options options;

} hcapi_con;

typedef struct hcapi_data_time_start {
    
    char *start;
    char *display_run;


} hcapi_data_time_started;


typedef struct hcapi_data_time_estimated {
    
    char * etc;
    char *display_etc;

} hcapi_data_time_estimated;

typedef struct hcapi_data_speed_dev {
    

    int device_id;
    char display_dev_cur[16];
    double exec_all_ms[DEVICES_MAX];
    char display_all_cur[16];

} hcapi_data_speed_dev;

typedef struct hcapi_data_recovered {
    
    float digests_percent;
    float salts_percent;

} hcapi_data_recovered;


typedef struct hcapi_data_recovered_time {
    
    int cpt_cur_min;
    int cpt_cur_hour;
    int cpt_cur_day;

    float ms_real;

    float cpt_avg_min;
    float cpt_avg_hour;
    float cpt_avg_day;

} hcapi_data_recovered_time;

typedef struct hcapi_data_progress {
    
    u64 progress_cur_relative_skip;
    u64 progress_end_relative_skip;
    float percent_finished;
    float percent_rejected;
    u64 all_rejected;

} hcapi_data_progress;


typedef struct hcapi_data_restore_point {
    
    u64 restore_total;
    u64 restore_point;
    float percent_restore;

} hcapi_data_restore_point;


typedef struct hcapi_data_hwmon_gpu {
    
    int device_id;
    char utilization[HM_STR_BUF_SIZE];
    char temperature[HM_STR_BUF_SIZE];

} hcapi_data_hwmon_gpu;

typedef struct hcapi_global_data_t {
    
  /**
   * threads
   */
  uint    devices_status;
  uint    devices_cnt;
  uint    devices_active;


  /**
   * attack specific
   */

  uint    wordlist_mode;
  uint    attack_mode;
  uint    attack_kern;
  uint    kernel_rules_cnt;
  uint    combs_cnt;
  uint    bfs_cnt;
  uint    css_cnt;



  /**
   * hashes
   */

  uint    digests_cnt;
  uint    digests_done;
  uint    salts_cnt;
  uint    salts_done;
  salt_t *salts_buf;
  uint   *salts_shown;
  void   *esalts_buf;

 

  /**
   * crack-per-time
   */

  cpt_t   cpt_buf[CPT_BUF];
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
  char   *hashfile;
  uint    restore_disable;
  uint    hash_mode;
  uint    hash_type;
  uint    opts_type;


  #ifdef HAVE_HWMON
  uint    gpu_temp_disable;
  #endif

  char  **rp_files;
  uint    rp_files_cnt;
  uint    rp_gen;
  uint    rp_gen_seed;


  /**
   * used for restore
   */

  u64     skip;
  u64     limit;


  /**
   * status, timer
   */

  time_t  proc_start;
  u64     words_cnt;
  u64     words_base;
  u64    *words_progress_done;      // progress number of words done     per salt
  u64    *words_progress_rejected;  // progress number of words rejected per salt
  u64    *words_progress_restored;  // progress number of words restored per salt

  hc_timer_t timer_running;         // timer on current dict
  hc_timer_t timer_paused;          // timer on current dict

  float   ms_paused;                // timer on current dict

  /**
   * Calculated values
   */

   char *status;
   char *hash_target;
   char *hash_type_str;

   hcapi_data_time_started time_started;
   hcapi_data_time_estimated time_estimated;

   hcapi_data_speed_dev *speed_dev;
   hcapi_data_recovered recovered;
   hcapi_data_recovered_time recovered_time;
   hcapi_data_progress progress;
   hcapi_data_restore_point restore_point;
   hcapi_data_hwmon_gpu hwmon_gpu;

} hcapi_global_data_t;

// Storage for runtime status data
hcapi_global_data_t hcapi_data;



/**
 * Function prototypes
 */

struct hcapi_control oclhashcat_init (void);
int hcapi_main (int, char **);
int hcapi_start (int, char **);
int hcapi_stop (void);
void hcapi_append_rules (struct hcapi_options *options, char *add);
void hcapi_append_dictmaskdir (struct hcapi_options *options, char *add);
void hcapi_generate_commandline (struct hcapi_options, int *, char ***);

#ifdef WIN
HANDLE hcapi_start_thread (int, char **);
#else
int hcapi_start_thread (int, char **);
#endif

void check_argv_array (char ***, size_t *, size_t *, int *);
char *strcat_ls (char *, char *);


/**
 * Utility/helper Functions 
 */

char *strcat_ls (char *dst, char *src)
{

  size_t dst_len = snprintf (0, 0, "%s", dst);
  size_t src_len = snprintf (0, 0, "%s", src);
  size_t total_len = dst_len + src_len + 2;


  char *tmp = (char *) calloc (total_len, sizeof (char));

  if (tmp == NULL)
  {

    printf ("ERROR: Allocating Memory");
    exit (1);
  }

  snprintf (tmp, total_len, "%s%s", dst, src);

  dst = tmp;

  tmp = NULL;
  free (tmp);
  return dst;
}

void check_argv_array (char ***apiargv, size_t * apiargv_size, size_t * apiargv_grow_by, int *apiargc)
{

  // Check if the argv array is full
  if (*apiargc == (int) *apiargv_size - 1)
  {

    *apiargv = realloc (*apiargv, (*apiargv_size + *apiargv_grow_by) * sizeof (char *));

    // Something went wrong Free memory for apiargv
    if (*apiargv == NULL)
    {

      for (size_t i = 0; i < (size_t) * apiargc; i++)
      {
        // Free individual args
        free (*apiargv[i]);
      }

      free (*apiargv);

      printf ("ERROR: Expanding Array!\n");
      exit (1);
    }

  }
}

// From oclHashcat.c used in hcapi_status_data()
static double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries)
{
  int exec_pos = (int) device_param->exec_pos - last_num_entries;

  if (exec_pos < 0) exec_pos += EXEC_CACHE;

  double exec_ms_sum = 0;

  int exec_ms_cnt = 0;

  for (int i = 0; i < last_num_entries; i++)
  {
    double exec_ms = device_param->exec_ms[(exec_pos + i) % EXEC_CACHE];

    if (exec_ms)
    {
      exec_ms_sum += exec_ms;

      exec_ms_cnt++;
    }
  }

  if (exec_ms_cnt == 0) return 0;

  return exec_ms_sum / exec_ms_cnt;
}




/**
 * oclHashcat API Functions 
 */

void hcapi_generate_commandline (struct hcapi_options options, int *c, char ***v)
{

  /* 
   * 
   * Not sure if the build order matters. Might need to account for positional args by building in the following order - options - hash|hashfile|hccapfile - dictionary|mask|directory
   * 
   */

  debug_print ("Building commandline\n");
  size_t apiargv_size = 1;
  size_t apiargv_grow_by = 1;
  char **apiargv = (char **) calloc (apiargv_size, sizeof (char *));
  int apiargc = 0;

  if (apiargv == NULL)
  {
    printf ("ERROR: Memory allocation failure ARGV!\n");
    exit (1);
  }

  // Account for program call
  apiargv[apiargc] = (char *) calloc (11, sizeof (char));
  apiargv[apiargc] = "oclHashcat";
  apiargc++;


  if (options.version != VERSION)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (3, sizeof (char));
    apiargv[apiargc] = "-V";
    apiargc++;

  }

  /* The --quiet option is always defaulted to 1 for API calls. 
   * The developer may override this option by setting it to 0 manually, but it's not recommended
   *
   */ 
  if (options.quiet != QUIET)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (8, sizeof (char));
    apiargv[apiargc] = "--quiet";
    apiargc++;

  }


  if (options.benchmark != BENCHMARK)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (3, sizeof (char));
    apiargv[apiargc] = "-b";
    apiargc++;

  }


  if (options.show != SHOW)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (7, sizeof (char));
    apiargv[apiargc] = "--show";
    apiargc++;

  }

  if (options.left != LEFT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (7, sizeof (char));
    apiargv[apiargc] = "--left";
    apiargc++;

  }

  if (options.username != USERNAME)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (11, sizeof (char));
    apiargv[apiargc] = "--username";
    apiargc++;

  }

  if (options.remove != REMOVE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (9, sizeof (char));
    apiargv[apiargc] = "--remove";
    apiargc++;

  }

  if (options.remove_timer != REMOVE_TIMER)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.remove_timer))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.remove_timer);

    apiargv[apiargc] = strcat_ls ("--remove-timer=", user_input);
    apiargc++;
    free (user_input);
  }

  if (options.skip != SKIP)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    int rounds = 0;
    uint64_t _result = options.skip;

    while (_result > 0)
    {

      rounds++;
      _result = _result / 10;

    }

    size_t input_size = (uint64_t) rounds + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%" PRIu64, options.skip);

    apiargv[apiargc] = strcat_ls ("--skip=", user_input);
    apiargc++;
  }

  if (options.limit != LIMIT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    int rounds = 0;
    uint64_t _result = options.limit;

    while (_result > 0)
    {

      rounds++;
      _result = _result / 10;

    }


    size_t input_size = (uint64_t) rounds + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%" PRIu64, options.limit);

    apiargv[apiargc] = strcat_ls ("--limit=", user_input);
    apiargc++;

  }

  if (options.keyspace != KEYSPACE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (11, sizeof (char));
    apiargv[apiargc] = "--keyspace";
    apiargc++;

  }

  if (options.potfile_disable != POTFILE_DISABLE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (18, sizeof (char));
    apiargv[apiargc] = "--potfile-disable";
    apiargc++;

  }

  // str
  if (options.potfile_path != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.potfile_path) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.potfile_path);

    apiargv[apiargc] = strcat_ls ("--potfile-path=", user_input);
    apiargc++;

  }

  

  if (options.debug_mode != DEBUG_MODE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.debug_mode))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.debug_mode);

    apiargv[apiargc] = strcat_ls ("--debug-mode=", user_input);
    apiargc++;

  }


  if (options.debug_file != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.debug_file) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.debug_file);

    apiargv[apiargc] = strcat_ls ("--debug-file=", user_input);
    apiargc++;

  }

  // str
  if (options.induction_dir != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.induction_dir) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.induction_dir);

    apiargv[apiargc] = strcat_ls ("--induction-dir=", user_input);
    apiargc++;

  }

  // str
  if (options.outfile_check_dir != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.outfile_check_dir) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.outfile_check_dir);

    apiargv[apiargc] = strcat_ls ("--output-check-dir=", user_input);
    apiargc++;

  }

  if (options.force != FORCE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (8, sizeof (char));
    apiargv[apiargc] = "--force";
    apiargc++;

  }

  if (options.runtime != RUNTIME)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.runtime))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.runtime);

    apiargv[apiargc] = strcat_ls ("--runtime=", user_input);
    apiargc++;

  }

  if (options.hash_mode != HASH_MODE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.hash_mode))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.hash_mode);

    apiargv[apiargc] = strcat_ls ("-m ", user_input);
    apiargc++;


  }

  if (options.attack_mode != ATTACK_MODE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.attack_mode))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.attack_mode);

    apiargv[apiargc] = strcat_ls ("-a ", user_input);
    apiargc++;

  }

  if (options.markov_disable != MARKOV_DISABLE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (17, sizeof (char));
    apiargv[apiargc] = "--markov-disable";
    apiargc++;
  }

  if (options.markov_classic != MARKOV_CLASSIC)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (17, sizeof (char));
    apiargv[apiargc] = "--markov-classic";
    apiargc++;

  }

  if (options.markov_threshold != MARKOV_THRESHOLD)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.markov_threshold))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.markov_threshold);

    apiargv[apiargc] = strcat_ls ("-t ", user_input);
    apiargc++;

  }

  // str
  if (options.markov_hcstat != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.markov_hcstat) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.markov_hcstat);

    apiargv[apiargc] = strcat_ls ("--markov-hcstat=", user_input);
    apiargc++;

  }

  // str
  if (options.outfile != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = strlen (options.outfile) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.outfile);

    apiargv[apiargc] = strcat_ls ("-o ", user_input);
    apiargc++;

  }

  if (options.outfile_format != OUTFILE_FORMAT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    size_t input_size = (int) ((ceil (log10 (options.outfile_format))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.outfile_format);

    apiargv[apiargc] = strcat_ls ("--output-format=", user_input);
    apiargc++;

  }

  if (options.outfile_autohex != OUTFILE_AUTOHEX)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (26, sizeof (char));
    apiargv[apiargc] = "--outfile-autohex-disable";
    apiargc++;

  }

  if (options.outfile_check_timer != OUTFILE_CHECK_TIMER)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.outfile_check_timer))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.outfile_check_timer);

    apiargv[apiargc] = strcat_ls ("--outfile-check-timer=", user_input);
    apiargc++;

  }

  if (options.restore != RESTORE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (10, sizeof (char));
    apiargv[apiargc] = "--restore";
    apiargc++;

  }


  if (options.restore_disable != RESTORE_DISABLE)
  {


    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (18, sizeof (char));
    apiargv[apiargc] = "--restore-disable";
    apiargc++;

  }

  if (options.status != STATUS)
  {


    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (9, sizeof (char));
    apiargv[apiargc] = "--status";
    apiargc++;

  }

  if (options.status_timer != STATUS_TIMER)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.status_timer))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.status_timer);

    apiargv[apiargc] = strcat_ls ("--status-timer=", user_input);
    apiargc++;

  }

  if (options.status_automat != STATUS_AUTOMAT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (17, sizeof (char));
    apiargv[apiargc] = "--status-automat";
    apiargc++;
  }

  if (options.loopback != LOOPBACK)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (11, sizeof (char));
    apiargv[apiargc] = "--loopback";
    apiargc++;
  }

  if (options.weak_hash_threshold != WEAK_HASH_THRESHOLD)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.weak_hash_threshold))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.weak_hash_threshold);

    apiargv[apiargc] = strcat_ls ("--weak-hash-threshold=", user_input);
    apiargc++;

  }

  // str
  if (options.session != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.session) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.session);

    apiargv[apiargc] = strcat_ls ("--session=", user_input);
    apiargc++;

  }

  if (options.hex_charset != HEX_CHARSET)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (14, sizeof (char));
    apiargv[apiargc] = "--hex-charset";
    apiargc++;

  }

  if (options.hex_salt != HEX_SALT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (11, sizeof (char));
    apiargv[apiargc] = "--hex-salt";
    apiargc++;

  }

  if (options.hex_wordlist != HEX_WORDLIST)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (15, sizeof (char));
    apiargv[apiargc] = "--hex-wordlist";
    apiargc++;

  }

  if (options.rp_gen != RP_GEN)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.rp_gen))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.rp_gen);

    apiargv[apiargc] = strcat_ls ("-g ", user_input);
    apiargc++;

  }

  if (options.rp_gen_func_min != RP_GEN_FUNC_MIN)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.rp_gen_func_min))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.rp_gen_func_min);

    apiargv[apiargc] = strcat_ls ("--generate-rules-func-min=", user_input);
    apiargc++;

  }

  if (options.rp_gen_func_max != RP_GEN_FUNC_MAX)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.rp_gen_func_max))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.rp_gen_func_max);

    apiargv[apiargc] = strcat_ls ("--generate-rules-func-max=", user_input);
    apiargc++;

  }

  if (options.rp_gen_seed != RP_GEN_SEED)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.rp_gen_seed))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.rp_gen_seed);

    apiargv[apiargc] = strcat_ls ("--generate-rules-seed=", user_input);
    apiargc++;

  }

  // str
  if (options.rule_buf_l != (char *) RULE_BUF_L)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.rule_buf_l) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.rule_buf_l);

    apiargv[apiargc] = strcat_ls ("-j ", user_input);
    apiargc++;

  }

  // str
  if (options.rule_buf_r != (char *) RULE_BUF_R)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.rule_buf_r) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.rule_buf_r);

    apiargv[apiargc] = strcat_ls ("-k ", user_input);
    apiargc++;

  }

  if (options.increment != INCREMENT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (2, sizeof (char));
    apiargv[apiargc] = "-i";
    apiargc++;

  }

  if (options.increment_min != INCREMENT_MIN)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.increment_min))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.increment_min);

    apiargv[apiargc] = strcat_ls ("--increment-min=", user_input);
    apiargc++;

  }

  if (options.increment_max != INCREMENT_MAX)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.increment_max))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.increment_max);

    apiargv[apiargc] = strcat_ls ("--increment-max=", user_input);
    apiargc++;

  }

  // str
  if (options.cpu_affinity != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.cpu_affinity) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.cpu_affinity);

    apiargv[apiargc] = strcat_ls ("--cpu-affinity=", user_input);
    apiargc++;

  }

  // str
  if (options.opencl_devices != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.opencl_devices) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.opencl_devices);

    apiargv[apiargc] = strcat_ls ("-d ", user_input);
    apiargc++;

  }


  // str
  if (options.opencl_platform != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.opencl_platform) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.opencl_platform);

    apiargv[apiargc] = strcat_ls ("--opencl-platform=", user_input);
    apiargc++;

  }

  if (options.opencl_device_types != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.opencl_device_types) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.opencl_device_types);

    apiargv[apiargc] = strcat_ls ("--opencl-device-types=", user_input);
    apiargc++;

  }



  // str
  if (options.truecrypt_keyfiles != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.truecrypt_keyfiles) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.truecrypt_keyfiles);

    apiargv[apiargc] = strcat_ls ("--truecrypt-keyfiles=", user_input);
    apiargc++;

  }

  if (options.workload_profile != WORKLOAD_PROFILE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.workload_profile))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.workload_profile);

    apiargv[apiargc] = strcat_ls ("--workload-profile=", user_input);
    apiargc++;

  }

  if (options.kernel_accel != KERNEL_ACCEL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.kernel_accel))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.kernel_accel);

    apiargv[apiargc] = strcat_ls ("-n ", user_input);
    apiargc++;

  }

  if (options.kernel_loops != KERNEL_LOOPS)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.kernel_loops))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.kernel_loops);

    apiargv[apiargc] = strcat_ls ("-u ", user_input);
    apiargc++;

  }

  if (options.gpu_temp_disable != GPU_TEMP_DISABLE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (19, sizeof (char));
    apiargv[apiargc] = "--gpu-temp-disable";
    apiargc++;

  }

  if (options.gpu_temp_abort != GPU_TEMP_ABORT)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.gpu_temp_abort))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.gpu_temp_abort);

    apiargv[apiargc] = strcat_ls ("--gpu-temp-abort=", user_input);
    apiargc++;

  }

  if (options.gpu_temp_retain != GPU_TEMP_RETAIN)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.gpu_temp_retain))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.gpu_temp_retain);

    apiargv[apiargc] = strcat_ls ("--gpu-temp-retain=", user_input);
    apiargc++;

  }

  if (options.powertune_enable != POWERTUNE_ENABLE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (19, sizeof (char));
    apiargv[apiargc] = "--powertune-enable";
    apiargc++;

  }

  if (options.logfile_disable != LOGFILE_DISABLE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
    apiargv[apiargc] = (char *) calloc (18, sizeof (char));
    apiargv[apiargc] = "--logfile-disable";
    apiargc++;
  }

  if (options.segment_size != SEGMENT_SIZE)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.segment_size))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.segment_size);

    apiargv[apiargc] = strcat_ls ("-c ", user_input);
    apiargc++;

  }

  if (options.scrypt_tmto != SCRYPT_TMTO)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.scrypt_tmto))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.scrypt_tmto);

    apiargv[apiargc] = strcat_ls ("-c ", user_input);
    apiargc++;

  }

  // char
  if (options.separator != SEPARATOR)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%c", options.separator);

    apiargv[apiargc] = strcat_ls ("-p ", user_input);
    apiargc++;

  }

  if (options.bitmap_min != BITMAP_MIN)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.bitmap_min))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.bitmap_min);

    apiargv[apiargc] = strcat_ls ("--bitmap-min=", user_input);
    apiargc++;

  }

  if (options.bitmap_max != BITMAP_MAX)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = (int) ((ceil (log10 (options.bitmap_max))) * sizeof (char)) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%d", options.bitmap_max);

    apiargv[apiargc] = strcat_ls ("--bitmap-max=", user_input);
    apiargc++;

  }

  // str
  if (options.custom_charset_1 != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.custom_charset_1) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.custom_charset_1);

    apiargv[apiargc] = strcat_ls ("-1 ", user_input);
    apiargc++;
  }


  // str
  if (options.custom_charset_2 != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.custom_charset_2) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.custom_charset_2);

    apiargv[apiargc] = strcat_ls ("-2 ", user_input);
    apiargc++;
  }


  // str
  if (options.custom_charset_3 != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    // Account for num of digits plus null
    size_t input_size = strlen (options.custom_charset_3) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.custom_charset_3);

    apiargv[apiargc] = strcat_ls ("-3 ", user_input);
    apiargc++;

  }


  // str
  if (options.custom_charset_4 != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    
    size_t input_size = strlen (options.custom_charset_4) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.custom_charset_4);

    apiargv[apiargc] = strcat_ls ("-4 ", user_input);
    apiargc++;

  }

  // This is a positional parameter
  if (options.hash_input != NULL)
  {

    check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

    
    size_t input_size = strlen (options.hash_input) + 2;

    char *user_input = (char *) calloc (input_size, sizeof (char));

    snprintf (user_input, input_size, "%s", options.hash_input);

    apiargv[apiargc] = strcat_ls ("", user_input);
    apiargc++;

  }


  if (options.dictmaskdir != NULL)
  {

    char seps[] = ",";
    char *token;

    char *dictmaskdir = strcat_ls ("", options.dictmaskdir);

    /**
			WARNING: strtok() is considered unsafe. Would normally us strtok_r or strtok_s,
				 but they are not standard in C99. Other options are we could roll our own, make options.dictmaskdir an char *array[] and dynamically grow for each rule, compile with 
				 -std=C11 which has strtok_r
		*/
    token = strtok (dictmaskdir, seps);

    if (token != NULL)
    {
      while (token != NULL)
      {

        check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
        size_t input_size = strlen (token) + 2;

        char *user_input = (char *) calloc (input_size, sizeof (char));

        snprintf (user_input, input_size, "%s", token);

        apiargv[apiargc] = strcat_ls ("", user_input);
        apiargc++;
        token = strtok (NULL, seps);
      }
    }
    else
    {

      check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
      size_t input_size = strlen (dictmaskdir) + 2;

      char *user_input = (char *) calloc (input_size, sizeof (char));

      snprintf (user_input, input_size, "%s", dictmaskdir);

      apiargv[apiargc] = strcat_ls ("", user_input);
      apiargc++;

    }

  }

  if (options.rp_files != NULL)
  {

    char seps[] = ",";
    char *token;

    char *rule_files = strcat_ls ("", options.rp_files);

    /**
			WARNING: strtok() is considered unsafe. Would normally us strtok_r or strtok_s,
				 but they are not standard in C99. Other options are we could roll our own, make options.rp_files an char *array[] and dynamically grow for each rule, compile with 
				 -std=C11 which has strtok_r
		*/
    token = strtok (rule_files, seps);

    if (token != NULL)
    {
      while (token != NULL)
      {

        check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
        size_t input_size = strlen (token) + 2;

        char *user_input = (char *) calloc (input_size, sizeof (char));

        snprintf (user_input, input_size, "%s", token);

        /* 
         * For some reason if I use "-r " (with a space) below, getopt doesn't recognize that the file path/name applies to the -r switch. No idea why. I'm sure it has to do with the way I'm building apiargv. Null somewhere? Any thoughts?
         * 
         * In the mean time, going without the space seems to work in my tests. */

        apiargv[apiargc] = strcat_ls ("-r", user_input);
        apiargc++;
        token = strtok (NULL, seps);
      }
    }
    else
    {

      check_argv_array (&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
      size_t input_size = strlen (rule_files) + 2;

      char *user_input = (char *) calloc (input_size, sizeof (char));

      snprintf (user_input, input_size, "%s", rule_files);

      /* 
       * For some reason if I use "-r " (with a space) below, getopt doesn't recognize that the file path/name applies to the -r switch. No idea why. I'm sure it has to do with the way I'm building apiargv. Null somewhere? Any thoughts?
       * 
       * In the mean time, going without the space seems to work in my tests. */
      apiargv[apiargc] = strcat_ls ("-r", user_input);
      apiargc++;

    }

  }


  *c = apiargc;
  *v = apiargv;

  debug_print ("Commandline build complete\n");
  return;
}

int hcapi_start (int argc, char **argv)
{

  debug_print ("Start Called \n");
  debug_print ("argc = %d\n", argc);
  debug_prints ("argv = ");

  for (int i = 0; i < argc; i++)
  {
    debug_prints ("%s ", argv[i]);
  }

  int rtcode = hcapi_main (argc, argv);

  return rtcode;
}

#ifdef WIN
unsigned __stdcall start_hc_thread (void *params)
{

  thread_args *args = (thread_args *) params;

  int argc = args->c;
  char **argv = args->v;

  debug_print ("argc = %d\n", argc);
  debug_print ("argv = ");

  for (int i = 0; i < argc; i++)
  {
    debug_prints ("%s ", argv[i]);
  }

  debug_prints ("\n");
  debug_print ("hcapi_main called from Thread: %lu \n", GetCurrentThreadId ());

  hcapi_main (argc, argv);


  return 0;
}

HANDLE hcapi_start_thread (int argc, char **argv)
{

  HANDLE hThread;
  unsigned int threadID;

  thread_args args;

  args.c = argc;
  args.v = argv;


  debug_print ("Attempting to start background thread, calling  _beginthreadex\n");
  hThread = (HANDLE) _beginthreadex (0, 0, &start_hc_thread, &args, 0, &threadID);
  
  // Give the worker thread a chance to initialize
  int sleep_time = 5;
  debug_print ("oclHashcat Spinning Up! Main thread sleeping for %d\n", sleep_time);
  sleep (sleep_time);

  return hThread;
}
#else

void *start_hc_thread (void *params)
{

  thread_args *args = (thread_args *) params;

  int argc = args->c;
  char **argv = args->v;

  debug_print ("argc = %d\n", argc);
  debug_print ("argv = ");

  for (int i = 0; i < argc; i++)
  {
    debug_prints ("%s ", argv[i]);
  }

  debug_prints ("\n");

  pthread_t self;

  self = pthread_self ();

  debug_print ("hcapi_main called from Thread: %d \n", (int) self);
  hcapi_main (argc, argv);


  return NULL;
}

int hcapi_start_thread (int argc, char **argv)
{

  int err;
  pthread_t hThread;
  thread_args args;

  args.c = argc;
  args.v = argv;

  debug_print ("Attempting to start background thread, calling pthread_create\n");
  err = pthread_create (&hThread, NULL, &start_hc_thread, &args);
  
  // Give the worker thread a chance to initialize
  int sleep_time = 5;
  debug_print ("Main thread sleeping for %d\n", sleep_time);
  sleep (sleep_time);

  debug_print ("pthread_create err = %d \n", err);
  return err;

}
#endif


int hcapi_stop (void)
{

  debug_print ("Stop Called\n");

  hc_thread_mutex_lock (mux_display);
  myabort ();
  hc_thread_mutex_unlock (mux_display);

  debug_print ("myabort() completed\n");

  return 0;
}

void hcapi_append_rules (struct hcapi_options *options, char *new_file_path)
{

  debug_print ("Called Append Rules.\n");

  if (options->rp_files != NULL)
  {

    options->rp_files = strcat_ls (options->rp_files, ",");
    options->rp_files = strcat_ls (options->rp_files, new_file_path);

  }
  else
  {
    options->rp_files = new_file_path;
  }


  return;
}

void hcapi_append_dictmaskdir (struct hcapi_options *options, char *new_file_path)
{

  debug_print ("Called Append Dict, Mask, or Dir.\n");

  if (options->dictmaskdir != NULL)
  {

    options->dictmaskdir = strcat_ls (options->dictmaskdir, ",");
    options->dictmaskdir = strcat_ls (options->dictmaskdir, new_file_path);

  }
  else
  {
    options->dictmaskdir = new_file_path;
  }


  return;
}

void hcapi_status_data ()
{

  
  hc_thread_mutex_lock (mux_display);

  if (data.devices_status == STATUS_INIT)     return;
  if (data.devices_status == STATUS_STARTING) return;
  if (data.devices_status == STATUS_BYPASS)   return;

  extern hc_thread_mutex_t mux_adl;

  char tmp_buf[1000] = { 0 };

  uint tmp_len = 0;

  log_info ("Session.Name...: %s", data.session);

  char *status_type = strstatus (data.devices_status);

  uint hash_mode = data.hash_mode;

  char *hash_type = strhashtype (hash_mode); // not a bug

  log_info ("Status.........: %s", status_type);
 
  /**
   * show rules
   */

  if (data.rp_files_cnt)
  {
    uint i;

    for (i = 0, tmp_len = 0; i < data.rp_files_cnt - 1 && tmp_len < sizeof (tmp_buf); i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s), ", data.rp_files[i]);
    }

    snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s)", data.rp_files[i]);

    log_info ("Rules.Type.....: %s", tmp_buf);

    tmp_len = 0;
  }

  if (data.rp_gen)
  {
    log_info ("Rules.Type.....: Generated (%u)", data.rp_gen);

    if (data.rp_gen_seed)
    {
      log_info ("Rules.Seed.....: %u", data.rp_gen_seed);
    }
  }

  /**
   * show input
   */

  if (data.attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (data.wordlist_mode == WL_MODE_FILE)
    {
      if (data.dictfile != NULL) log_info ("Input.Mode.....: File (%s)", data.dictfile);
    }
    else if (data.wordlist_mode == WL_MODE_STDIN)
    {
      log_info ("Input.Mode.....: Pipe");
    }
  }
  else if (data.attack_mode == ATTACK_MODE_COMBI)
  {
    if (data.dictfile  != NULL) log_info ("Input.Left.....: File (%s)", data.dictfile);
    if (data.dictfile2 != NULL) log_info ("Input.Right....: File (%s)", data.dictfile2);
  }
  else if (data.attack_mode == ATTACK_MODE_BF)
  {
    char *mask = data.mask;

    if (mask != NULL)
    {
      uint mask_len = data.css_cnt;

      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "Mask (%s)", mask);

      if (mask_len > 0)
      {
        if (data.opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (data.opti_type & OPTI_TYPE_APPENDED_SALT)
          {
            mask_len -= data.salts_buf[0].salt_len;
          }
        }

        if (data.opts_type & OPTS_TYPE_PT_UNICODE) mask_len /= 2;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " [%i]", mask_len);
      }

      if (data.maskcnt > 1)
      {
        float mask_percentage = (float) data.maskpos / (float) data.maskcnt;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " (%.02f%%)", mask_percentage * 100);
      }

      log_info ("Input.Mode.....: %s", tmp_buf);
    }

    tmp_len = 0;
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (data.dictfile != NULL) log_info ("Input.Left.....: File (%s)", data.dictfile);
    if (data.mask     != NULL) log_info ("Input.Right....: Mask (%s) [%i]", data.mask, data.css_cnt);
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (data.mask     != NULL) log_info ("Input.Left.....: Mask (%s) [%i]", data.mask, data.css_cnt);
    if (data.dictfile != NULL) log_info ("Input.Right....: File (%s)", data.dictfile);
  }

  if (data.digests_cnt == 1)
  {
    if (data.hash_mode == 2500)
    {
      wpa_t *wpa = (wpa_t *) data.esalts_buf;

      log_info ("Hash.Target....: %s (%02x:%02x:%02x:%02x:%02x:%02x <-> %02x:%02x:%02x:%02x:%02x:%02x)",
                (char *) data.salts_buf[0].salt_buf,
                wpa->orig_mac1[0],
                wpa->orig_mac1[1],
                wpa->orig_mac1[2],
                wpa->orig_mac1[3],
                wpa->orig_mac1[4],
                wpa->orig_mac1[5],
                wpa->orig_mac2[0],
                wpa->orig_mac2[1],
                wpa->orig_mac2[2],
                wpa->orig_mac2[3],
                wpa->orig_mac2[4],
                wpa->orig_mac2[5]);
    }
    else if (data.hash_mode == 5200)
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else if (data.hash_mode == 9000)
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else if ((data.hash_mode >= 6200) && (data.hash_mode <= 6299))
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else
    {
      char out_buf[HCBUFSIZ] = { 0 };

      ascii_digest (out_buf, 0, 0);

      // limit length
      if (strlen (out_buf) > 40)
      {
        out_buf[41] = '.';
        out_buf[42] = '.';
        out_buf[43] = '.';
        out_buf[44] = 0;
      }

      log_info ("Hash.Target....: %s", out_buf);
    }
  }
  else
  {
    if (data.hash_mode == 3000)
    {
      char out_buf1[32] = { 0 };
      char out_buf2[32] = { 0 };

      ascii_digest (out_buf1, 0, 0);
      ascii_digest (out_buf2, 0, 1);

      log_info ("Hash.Target....: %s, %s", out_buf1, out_buf2);
    }
    else
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
  }

  log_info ("Hash.Type......: %s", hash_type);

  /**
   * speed new
   */

  u64   speed_cnt[DEVICES_MAX] = { 0 };
  float speed_ms[DEVICES_MAX]  = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    // we need to clear values (set to 0) because in case the device does
    // not get new candidates it idles around but speed display would
    // show it as working.
    // if we instantly set it to 0 after reading it happens that the
    // speed can be shown as zero if the users refreshes too fast.
    // therefore, we add a timestamp when a stat was recorded and if its
    // too old we will not use it

    speed_cnt[device_id] = 0;
    speed_ms[device_id]  = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      float rec_ms;

      hc_timer_get (device_param->speed_rec[i], rec_ms);

      if (rec_ms > SPEED_MAXAGE) continue;

      speed_cnt[device_id] += device_param->speed_cnt[i];
      speed_ms[device_id]  += device_param->speed_ms[i];
    }

    speed_cnt[device_id] /= SPEED_CACHE;
    speed_ms[device_id]  /= SPEED_CACHE;
  }

  float hashes_all_ms = 0;

  float hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id])
    {
      hashes_dev_ms[device_id] = speed_cnt[device_id] / speed_ms[device_id];

      hashes_all_ms += hashes_dev_ms[device_id];
    }
  }

  /**
   * exec time
   */

  double exec_all_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  /**
   * timers
   */

  float ms_running = 0;

  hc_timer_get (data.timer_running, ms_running);

  float ms_paused = data.ms_paused;

  if (data.devices_status == STATUS_PAUSED)
  {
    float ms_paused_tmp = 0;

    hc_timer_get (data.timer_paused, ms_paused_tmp);

    ms_paused += ms_paused_tmp;
  }

  #ifdef WIN

  __time64_t sec_run = ms_running / 1000;

  #else

  time_t sec_run = ms_running / 1000;

  #endif

  if (sec_run)
  {
    char display_run[32] = { 0 };

    struct tm tm_run;

    struct tm *tmp = NULL;

    #ifdef WIN

    tmp = _gmtime64 (&sec_run);

    #else

    tmp = gmtime (&sec_run);

    #endif

    if (tmp != NULL)
    {
      memset (&tm_run, 0, sizeof (tm_run));

      memcpy (&tm_run, tmp, sizeof (tm_run));

      format_timer_display (&tm_run, display_run, sizeof (tm_run));

      char *start = ctime (&data.proc_start);

      size_t start_len = strlen (start);

      if (start[start_len - 1] == '\n') start[start_len - 1] = 0;
      if (start[start_len - 2] == '\r') start[start_len - 2] = 0;

      log_info ("Time.Started...: %s (%s)", start, display_run);
    }
  }
  else
  {
    log_info ("Time.Started...: 0 secs");
  }

  /**
   * counters
   */

  u64 progress_total = data.words_cnt * data.salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  u64 progress_noneed = 0;

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    all_done     += data.words_progress_done[salt_pos];
    all_rejected += data.words_progress_rejected[salt_pos];
    all_restored += data.words_progress_restored[salt_pos];

    // Important for ETA only

    if (data.salts_shown[salt_pos] == 1)
    {
      const u64 all = data.words_progress_done[salt_pos]
                    + data.words_progress_rejected[salt_pos]
                    + data.words_progress_restored[salt_pos];

      const u64 left = data.words_cnt - all;

      progress_noneed += left;
    }
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (data.skip)
  {
    progress_skip = MIN (data.skip, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_skip *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_skip *= data.bfs_cnt;
  }

  if (data.limit)
  {
    progress_end = MIN (data.limit, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_end  *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_end  *= data.bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
  {
    if (data.devices_status != STATUS_CRACKED)
    {
      #ifdef WIN
      __time64_t sec_etc = 0;
      #else
      time_t sec_etc = 0;
      #endif

      if (hashes_all_ms)
      {
        u64 progress_left_relative_skip = progress_end_relative_skip - progress_cur_relative_skip;

        u64 ms_left = (progress_left_relative_skip - progress_noneed) / hashes_all_ms;

        sec_etc = ms_left / 1000;
      }

      if (sec_etc == 0)
      {
        //log_info ("Time.Estimated.: 0 secs");
      }
      else if ((u64) sec_etc > ETC_MAX)
      {
        log_info ("Time.Estimated.: > 10 Years");
      }
      else
      {
        char display_etc[32] = { 0 };

        struct tm tm_etc;

        struct tm *tmp = NULL;

        #ifdef WIN

        tmp = _gmtime64 (&sec_etc);

        #else

        tmp = gmtime (&sec_etc);

        #endif

        if (tmp != NULL)
        {
          memset (&tm_etc, 0, sizeof (tm_etc));

          memcpy (&tm_etc, tmp, sizeof (tm_etc));

          format_timer_display (&tm_etc, display_etc, sizeof (display_etc));

          time_t now;

          time (&now);

          now += sec_etc;

          char *etc = ctime (&now);

          size_t etc_len = strlen (etc);

          if (etc[etc_len - 1] == '\n') etc[etc_len - 1] = 0;
          if (etc[etc_len - 2] == '\r') etc[etc_len - 2] = 0;

          log_info ("Time.Estimated.: %s (%s)", etc, display_etc);
        }
      }
    }
  }

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display (hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    log_info ("Speed.Dev.#%d...: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
  }

  char display_all_cur[16] = { 0 };

  strncpy (display_all_cur, "0.00", 4);

  format_speed_display (hashes_all_ms * 1000, display_all_cur, sizeof (display_all_cur));

  if (data.devices_active > 1) log_info ("Speed.Dev.#*...: %9sH/s", display_all_cur);

  const float digests_percent = (float) data.digests_done / data.digests_cnt;
  const float salts_percent   = (float) data.salts_done   / data.salts_cnt;

  log_info ("Recovered......: %u/%u (%.2f%%) Digests, %u/%u (%.2f%%) Salts", data.digests_done, data.digests_cnt, digests_percent * 100, data.salts_done, data.salts_cnt, salts_percent * 100);

  // crack-per-time

  if (data.digests_cnt > 100)
  {
    time_t now = time (NULL);

    int cpt_cur_min  = 0;
    int cpt_cur_hour = 0;
    int cpt_cur_day  = 0;

    for (int i = 0; i < CPT_BUF; i++)
    {
      const uint   cracked   = data.cpt_buf[i].cracked;
      const time_t timestamp = data.cpt_buf[i].timestamp;

      if ((timestamp + 60) > now)
      {
        cpt_cur_min  += cracked;
      }

      if ((timestamp + 3600) > now)
      {
        cpt_cur_hour += cracked;
      }

      if ((timestamp + 86400) > now)
      {
        cpt_cur_day  += cracked;
      }
    }

    float ms_real = ms_running - ms_paused;

    float cpt_avg_min  = (float) data.cpt_total / ((ms_real / 1000) / 60);
    float cpt_avg_hour = (float) data.cpt_total / ((ms_real / 1000) / 3600);
    float cpt_avg_day  = (float) data.cpt_total / ((ms_real / 1000) / 86400);

    if ((data.cpt_start + 86400) < now)
    {
      log_info ("Recovered/Time.: CUR:%llu,%llu,%llu AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_cur_day,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 3600) < now)
    {
      log_info ("Recovered/Time.: CUR:%llu,%llu,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 60) < now)
    {
      log_info ("Recovered/Time.: CUR:%llu,N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else
    {
      log_info ("Recovered/Time.: CUR:N/A,N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
  }

  // Restore point

  u64 restore_point = get_lowest_words_done ();

  u64 restore_total = data.words_base;

  float percent_restore = 0;

  if (restore_total != 0) percent_restore = (float) restore_point / (float) restore_total;

  if (progress_end_relative_skip)
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      float percent_finished = (float) progress_cur_relative_skip / (float) progress_end_relative_skip;
      float percent_rejected = 0.0;

      if (progress_cur)
      {
        percent_rejected = (float) (all_rejected) / (float) progress_cur;
      }

      log_info ("Progress.......: %llu/%llu (%.02f%%)", (unsigned long long int) progress_cur_relative_skip, (unsigned long long int) progress_end_relative_skip, percent_finished * 100);
      log_info ("Rejected.......: %llu/%llu (%.02f%%)", (unsigned long long int) all_rejected,               (unsigned long long int) progress_cur_relative_skip, percent_rejected * 100);

      if (data.restore_disable == 0)
      {
        if (percent_finished != 1)
        {
          log_info ("Restore.Point..: %llu/%llu (%.02f%%)", (unsigned long long int) restore_point, (unsigned long long int) restore_total, percent_restore * 100);
        }
      }
    }
  }
  else
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      log_info ("Progress.......: %llu/%llu (%.02f%%)", (u64) 0, (u64) 0, (float) 100);
      log_info ("Rejected.......: %llu/%llu (%.02f%%)", (u64) 0, (u64) 0, (float) 100);

      if (data.restore_disable == 0)
      {
        log_info ("Restore.Point..: %llu/%llu (%.02f%%)", (u64) 0, (u64) 0, (float) 100);
      }
    }
    else
    {
      log_info ("Progress.......: %llu", (unsigned long long int) progress_cur_relative_skip);
      log_info ("Rejected.......: %llu", (unsigned long long int) all_rejected);

      
    }
  }

  #ifdef HAVE_HWMON
  if (data.gpu_temp_disable == 0)
  {
    hc_thread_mutex_lock (mux_adl);

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      #define HM_STR_BUF_SIZE 255

      if (data.hm_device[device_id].fan_supported == 1)
      {
        char utilization[HM_STR_BUF_SIZE] = { 0 };
        char temperature[HM_STR_BUF_SIZE] = { 0 };
        char fanspeed[HM_STR_BUF_SIZE] = { 0 };

        hm_device_val_to_str ((char *) utilization, HM_STR_BUF_SIZE, "%", hm_get_utilization_with_device_id (device_id));
        hm_device_val_to_str ((char *) temperature, HM_STR_BUF_SIZE, "c", hm_get_temperature_with_device_id (device_id));

        if (device_param->vendor_id == VENDOR_ID_AMD)
        {
          hm_device_val_to_str ((char *) fanspeed, HM_STR_BUF_SIZE, "%", hm_get_fanspeed_with_device_id (device_id));
        }
        else if (device_param->vendor_id == VENDOR_ID_NV)
        {
          hm_device_val_to_str ((char *) fanspeed, HM_STR_BUF_SIZE, "%", hm_get_fanspeed_with_device_id (device_id));
        }

        log_info ("HWMon.GPU.#%d...: %s Util, %s Temp, %s Fan", device_id + 1, utilization, temperature, fanspeed);
      }
      else
      {
        char utilization[HM_STR_BUF_SIZE] = { 0 };
        char temperature[HM_STR_BUF_SIZE] = { 0 };

        hm_device_val_to_str ((char *) utilization, HM_STR_BUF_SIZE, "%", hm_get_utilization_with_device_id (device_id));
        hm_device_val_to_str ((char *) temperature, HM_STR_BUF_SIZE, "c", hm_get_temperature_with_device_id (device_id));

        log_info ("HWMon.GPU.#%d...: %s Util, %s Temp, N/A Fan", device_id + 1, utilization, temperature);
      }
    }

    hc_thread_mutex_unlock (mux_adl);
  }
  #endif // HAVE_HWMON

  hc_thread_mutex_unlock (mux_display);
}

hcapi_con oclhashcat_init (void)
{

  debug_print ("Intializing options\n");

  hcapi_con control;

  control.options.hash_input = NULL;      // positional param --> hash|hashfile|hccapfile
  control.options.dictmaskdir = NULL;     // positional param --> [dictionary|mask|directory]
  control.options.version = VERSION;
  control.options.quiet = 1;              // Changed from default of QUIET == 0;
  control.options.benchmark = BENCHMARK;
  control.options.show = SHOW;
  control.options.left = LEFT;
  control.options.username = USERNAME;
  control.options.remove = REMOVE;
  control.options.remove_timer = REMOVE_TIMER;
  control.options.skip = SKIP;
  control.options.limit = LIMIT;
  control.options.keyspace = KEYSPACE;
  control.options.potfile_disable = POTFILE_DISABLE;
  control.options.potfile_path = NULL;
  control.options.debug_mode = DEBUG_MODE;
  control.options.debug_file = NULL;
  control.options.induction_dir = NULL;
  control.options.outfile_check_dir = NULL;
  control.options.force = FORCE;
  control.options.runtime = RUNTIME;
  control.options.hash_mode = HASH_MODE;
  control.options.attack_mode = ATTACK_MODE;
  control.options.markov_disable = MARKOV_DISABLE;
  control.options.markov_classic = MARKOV_CLASSIC;
  control.options.markov_threshold = MARKOV_THRESHOLD;
  control.options.markov_hcstat = NULL;
  control.options.outfile = NULL;
  control.options.outfile_format = OUTFILE_FORMAT;
  control.options.outfile_autohex = OUTFILE_AUTOHEX;
  control.options.outfile_check_timer = OUTFILE_CHECK_TIMER;
  control.options.restore = RESTORE;
  control.options.restore_timer = RESTORE_TIMER;
  control.options.restore_disable = RESTORE_DISABLE;
  control.options.status = STATUS;
  control.options.status_timer = STATUS_TIMER;
  control.options.status_automat = STATUS_AUTOMAT;
  control.options.loopback = LOOPBACK;
  control.options.weak_hash_threshold = WEAK_HASH_THRESHOLD;
  control.options.session = NULL;
  control.options.hex_charset = HEX_CHARSET;
  control.options.hex_salt = HEX_SALT;
  control.options.hex_wordlist = HEX_WORDLIST;
  control.options.rp_gen = RP_GEN;
  control.options.rp_gen_func_min = RP_GEN_FUNC_MIN;
  control.options.rp_gen_func_max = RP_GEN_FUNC_MAX;
  control.options.rp_gen_seed = RP_GEN_SEED;
  control.options.rule_buf_l = (char *) RULE_BUF_L;
  control.options.rule_buf_r = (char *) RULE_BUF_R;
  control.options.increment = INCREMENT;
  control.options.increment_min = INCREMENT_MIN;
  control.options.increment_max = INCREMENT_MAX;
  control.options.cpu_affinity = NULL;
  control.options.opencl_devices = NULL;
  control.options.opencl_platform = NULL;
  control.options.opencl_device_types = NULL;
  control.options.truecrypt_keyfiles = NULL;
  control.options.workload_profile = WORKLOAD_PROFILE;
  control.options.kernel_accel = KERNEL_ACCEL;
  control.options.kernel_loops = KERNEL_LOOPS;
  control.options.gpu_temp_disable = GPU_TEMP_DISABLE;
  control.options.gpu_temp_abort = GPU_TEMP_ABORT;
  control.options.gpu_temp_retain = GPU_TEMP_RETAIN;
  control.options.powertune_enable = POWERTUNE_ENABLE;
  control.options.logfile_disable = LOGFILE_DISABLE;
  control.options.segment_size = SEGMENT_SIZE;
  control.options.scrypt_tmto = SCRYPT_TMTO;
  control.options.separator = SEPARATOR;
  control.options.bitmap_min = BITMAP_MIN;
  control.options.bitmap_max = BITMAP_MAX;
  control.options.custom_charset_1 = NULL;
  control.options.custom_charset_2 = NULL;
  control.options.custom_charset_3 = NULL;
  control.options.custom_charset_4 = NULL;
  control.options.append_rules = hcapi_append_rules;
  control.options.append_dictmaskdir = hcapi_append_dictmaskdir;
  control.options.rp_files = NULL;

  control.start = hcapi_start;
  control.start_thread = hcapi_start_thread;
  control.stop = hcapi_stop;
  control.generate_commandline = hcapi_generate_commandline;
  control.status_data = hcapi_status_data;


  debug_print ("Intializing data output structure\n");



  return control;

}


/* 
 * API Test Main
 *
 */
int main ()
{

  printf ("[*] Starting API Test.\n");

  hcapi_con hc = oclhashcat_init ();


  hc.options.attack_mode = 0;
  hc.options.hash_mode = 1000;
  hc.options.hash_input = "C:\\Users\\auser\\Desktop\\hashes.txt";
  hc.options.append_dictmaskdir(&hc.options, "C:\\Users\\auser\\Desktop\\Dicts\\dictionary.txt");
  hc.options.append_rules(&hc.options, "C:\\Users\\auser\\Desktop\\Rules\\somerulse.rule");
  hc.options.append_rules(&hc.options, "rules\\best64.rule");

  /*




        IN PROGRESS THIS IS NOT A WORKING COMMIT


  */

  int c;
  char **v;

  hc.generate_commandline (hc.options, &c, &v);

  hc.start_thread (c, v);

  char quit = 'r';


  while (1)
  {

    
    hc.status_data ();

    quit = getchar ();
    if (quit == 'q')
    {

      hc.stop ();
      break;
    }

  }


  // Lots of prints for testing. To be deleted upon release
  printf ("[!] BACK IN MAIN");

  getchar ();


  return 0;
}
