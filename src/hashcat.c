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
#include <getopt.h>
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
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "thread.h"
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

extern hc_global_data_t data;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_hwmon;
extern hc_thread_mutex_t mux_display;
extern hc_thread_mutex_t mux_counter;
extern hc_thread_mutex_t mux_dispatcher;

extern void (*get_next_word_func) (char *, u32, u32 *, u32 *);

extern const unsigned int full01;
extern const unsigned int full80;

extern const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[];

static const char PROGNAME[] = "hashcat";

const int comptime = COMPTIME;

#define FORCE 0

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
   * There's some buggy OpenCL runtime that do not support -I.
   * A workaround is to chdir() to the OpenCL folder,
   * then compile the kernels,
   * then chdir() back to where we came from so we need to save it first
   */

  char cwd[1024];

  if (getcwd (cwd, sizeof (cwd) - 1) == NULL)
  {
    log_error ("ERROR: getcwd(): %s", strerror (errno));

    return -1;
  }

  /**
   * Real init
   */

  memset (&data, 0, sizeof (hc_global_data_t));

  time_t proc_start;

  time (&proc_start);

  data.proc_start = proc_start;

  time_t prepare_start;

  time (&prepare_start);

  int    myargc = argc;
  char **myargv = argv;

  hc_thread_mutex_init (mux_dispatcher);
  hc_thread_mutex_init (mux_counter);
  hc_thread_mutex_init (mux_display);
  hc_thread_mutex_init (mux_hwmon);

  /**
   * commandline parameters
   */

  uint  usage                     = USAGE;
  uint  version                   = VERSION;
  uint  quiet                     = QUIET;
  uint  benchmark                 = BENCHMARK;
  uint  stdout_flag               = STDOUT_FLAG;
  uint  show                      = SHOW;
  uint  left                      = LEFT;
  uint  username                  = USERNAME;
  uint  remove                    = REMOVE;
  uint  remove_timer              = REMOVE_TIMER;
  u64   skip                      = SKIP;
  u64   limit                     = LIMIT;
  uint  keyspace                  = KEYSPACE;
  uint  potfile_disable           = POTFILE_DISABLE;
  char *potfile_path              = NULL;
  uint  debug_mode                = DEBUG_MODE;
  char *debug_file                = NULL;
  char *induction_dir             = NULL;
  char *outfile_check_dir         = NULL;
  uint  force                     = FORCE;
  uint  runtime                   = RUNTIME;
  uint  hash_mode                 = HASH_MODE;
  uint  attack_mode               = ATTACK_MODE;
  uint  markov_disable            = MARKOV_DISABLE;
  uint  markov_classic            = MARKOV_CLASSIC;
  uint  markov_threshold          = MARKOV_THRESHOLD;
  char *markov_hcstat             = NULL;
  char *outfile                   = NULL;
  uint  outfile_format            = OUTFILE_FORMAT;
  uint  outfile_autohex           = OUTFILE_AUTOHEX;
  uint  outfile_check_timer       = OUTFILE_CHECK_TIMER;
  uint  restore                   = RESTORE;
  uint  restore_timer             = RESTORE_TIMER;
  uint  restore_disable           = RESTORE_DISABLE;
  uint  status                    = STATUS;
  uint  status_timer              = STATUS_TIMER;
  uint  machine_readable          = MACHINE_READABLE;
  uint  loopback                  = LOOPBACK;
  uint  weak_hash_threshold       = WEAK_HASH_THRESHOLD;
  char *session                   = NULL;
  uint  hex_charset               = HEX_CHARSET;
  uint  hex_salt                  = HEX_SALT;
  uint  hex_wordlist              = HEX_WORDLIST;
  uint  rp_gen                    = RP_GEN;
  uint  rp_gen_func_min           = RP_GEN_FUNC_MIN;
  uint  rp_gen_func_max           = RP_GEN_FUNC_MAX;
  uint  rp_gen_seed               = RP_GEN_SEED;
  char *rule_buf_l                = (char *) RULE_BUF_L;
  char *rule_buf_r                = (char *) RULE_BUF_R;
  uint  increment                 = INCREMENT;
  uint  increment_min             = INCREMENT_MIN;
  uint  increment_max             = INCREMENT_MAX;
  char *cpu_affinity              = NULL;
  bool  opencl_info               = 0;
  char *opencl_devices            = NULL;
  char *opencl_platforms          = NULL;
  char *opencl_device_types       = NULL;
  uint  opencl_vector_width       = OPENCL_VECTOR_WIDTH;
  char *truecrypt_keyfiles        = NULL;
  char *veracrypt_keyfiles        = NULL;
  uint  veracrypt_pim             = 0;
  uint  workload_profile          = WORKLOAD_PROFILE;
  uint  kernel_accel              = KERNEL_ACCEL;
  uint  kernel_loops              = KERNEL_LOOPS;
  uint  nvidia_spin_damp          = NVIDIA_SPIN_DAMP;
  uint  gpu_temp_disable          = GPU_TEMP_DISABLE;
  #if defined (HAVE_HWMON)
  uint  gpu_temp_abort            = GPU_TEMP_ABORT;
  uint  gpu_temp_retain           = GPU_TEMP_RETAIN;
  uint  powertune_enable          = POWERTUNE_ENABLE;
  #endif
  uint  logfile_disable           = LOGFILE_DISABLE;
  uint  segment_size              = SEGMENT_SIZE;
  uint  scrypt_tmto               = SCRYPT_TMTO;
  char  separator                 = SEPARATOR;
  uint  bitmap_min                = BITMAP_MIN;
  uint  bitmap_max                = BITMAP_MAX;
  char *custom_charset_1          = NULL;
  char *custom_charset_2          = NULL;
  char *custom_charset_3          = NULL;
  char *custom_charset_4          = NULL;

  #define IDX_HELP                      'h'
  #define IDX_VERSION                   'V'
  #define IDX_VERSION_LOWER             'v'
  #define IDX_QUIET                     0xff02
  #define IDX_SHOW                      0xff03
  #define IDX_LEFT                      0xff04
  #define IDX_REMOVE                    0xff05
  #define IDX_REMOVE_TIMER              0xff37
  #define IDX_SKIP                      's'
  #define IDX_LIMIT                     'l'
  #define IDX_KEYSPACE                  0xff35
  #define IDX_POTFILE_DISABLE           0xff06
  #define IDX_POTFILE_PATH              0xffe0
  #define IDX_DEBUG_MODE                0xff43
  #define IDX_DEBUG_FILE                0xff44
  #define IDX_INDUCTION_DIR             0xff46
  #define IDX_OUTFILE_CHECK_DIR         0xff47
  #define IDX_USERNAME                  0xff07
  #define IDX_FORCE                     0xff08
  #define IDX_RUNTIME                   0xff09
  #define IDX_BENCHMARK                 'b'
  #define IDX_STDOUT_FLAG               0xff77
  #define IDX_HASH_MODE                 'm'
  #define IDX_ATTACK_MODE               'a'
  #define IDX_RP_FILE                   'r'
  #define IDX_RP_GEN                    'g'
  #define IDX_RP_GEN_FUNC_MIN           0xff10
  #define IDX_RP_GEN_FUNC_MAX           0xff11
  #define IDX_RP_GEN_SEED               0xff34
  #define IDX_RULE_BUF_L                'j'
  #define IDX_RULE_BUF_R                'k'
  #define IDX_INCREMENT                 'i'
  #define IDX_INCREMENT_MIN             0xff12
  #define IDX_INCREMENT_MAX             0xff13
  #define IDX_OUTFILE                   'o'
  #define IDX_OUTFILE_FORMAT            0xff14
  #define IDX_OUTFILE_AUTOHEX_DISABLE   0xff39
  #define IDX_OUTFILE_CHECK_TIMER       0xff45
  #define IDX_RESTORE                   0xff15
  #define IDX_RESTORE_DISABLE           0xff27
  #define IDX_STATUS                    0xff17
  #define IDX_STATUS_TIMER              0xff18
  #define IDX_MACHINE_READABLE          0xff50
  #define IDX_LOOPBACK                  0xff38
  #define IDX_WEAK_HASH_THRESHOLD       0xff42
  #define IDX_SESSION                   0xff19
  #define IDX_HEX_CHARSET               0xff20
  #define IDX_HEX_SALT                  0xff21
  #define IDX_HEX_WORDLIST              0xff40
  #define IDX_MARKOV_DISABLE            0xff22
  #define IDX_MARKOV_CLASSIC            0xff23
  #define IDX_MARKOV_THRESHOLD          't'
  #define IDX_MARKOV_HCSTAT             0xff24
  #define IDX_CPU_AFFINITY              0xff25
  #define IDX_OPENCL_INFO               'I'
  #define IDX_OPENCL_DEVICES            'd'
  #define IDX_OPENCL_PLATFORMS          0xff72
  #define IDX_OPENCL_DEVICE_TYPES       'D'
  #define IDX_OPENCL_VECTOR_WIDTH       0xff74
  #define IDX_WORKLOAD_PROFILE          'w'
  #define IDX_KERNEL_ACCEL              'n'
  #define IDX_KERNEL_LOOPS              'u'
  #define IDX_NVIDIA_SPIN_DAMP          0xff79
  #define IDX_GPU_TEMP_DISABLE          0xff29
  #define IDX_GPU_TEMP_ABORT            0xff30
  #define IDX_GPU_TEMP_RETAIN           0xff31
  #define IDX_POWERTUNE_ENABLE          0xff41
  #define IDX_LOGFILE_DISABLE           0xff51
  #define IDX_TRUECRYPT_KEYFILES        0xff52
  #define IDX_VERACRYPT_KEYFILES        0xff53
  #define IDX_VERACRYPT_PIM             0xff54
  #define IDX_SCRYPT_TMTO               0xff61
  #define IDX_SEGMENT_SIZE              'c'
  #define IDX_SEPARATOR                 'p'
  #define IDX_BITMAP_MIN                0xff70
  #define IDX_BITMAP_MAX                0xff71
  #define IDX_CUSTOM_CHARSET_1          '1'
  #define IDX_CUSTOM_CHARSET_2          '2'
  #define IDX_CUSTOM_CHARSET_3          '3'
  #define IDX_CUSTOM_CHARSET_4          '4'

  char short_options[] = "hVvm:a:r:j:k:g:o:t:d:D:n:u:c:p:s:l:1:2:3:4:iIbw:";

  struct option long_options[] =
  {
    {"help",                      no_argument,       0, IDX_HELP},
    {"version",                   no_argument,       0, IDX_VERSION},
    {"quiet",                     no_argument,       0, IDX_QUIET},
    {"show",                      no_argument,       0, IDX_SHOW},
    {"left",                      no_argument,       0, IDX_LEFT},
    {"username",                  no_argument,       0, IDX_USERNAME},
    {"remove",                    no_argument,       0, IDX_REMOVE},
    {"remove-timer",              required_argument, 0, IDX_REMOVE_TIMER},
    {"skip",                      required_argument, 0, IDX_SKIP},
    {"limit",                     required_argument, 0, IDX_LIMIT},
    {"keyspace",                  no_argument,       0, IDX_KEYSPACE},
    {"potfile-disable",           no_argument,       0, IDX_POTFILE_DISABLE},
    {"potfile-path",              required_argument, 0, IDX_POTFILE_PATH},
    {"debug-mode",                required_argument, 0, IDX_DEBUG_MODE},
    {"debug-file",                required_argument, 0, IDX_DEBUG_FILE},
    {"induction-dir",             required_argument, 0, IDX_INDUCTION_DIR},
    {"outfile-check-dir",         required_argument, 0, IDX_OUTFILE_CHECK_DIR},
    {"force",                     no_argument,       0, IDX_FORCE},
    {"benchmark",                 no_argument,       0, IDX_BENCHMARK},
    {"stdout",                    no_argument,       0, IDX_STDOUT_FLAG},
    {"restore",                   no_argument,       0, IDX_RESTORE},
    {"restore-disable",           no_argument,       0, IDX_RESTORE_DISABLE},
    {"status",                    no_argument,       0, IDX_STATUS},
    {"status-timer",              required_argument, 0, IDX_STATUS_TIMER},
    {"machine-readable",          no_argument,       0, IDX_MACHINE_READABLE},
    {"loopback",                  no_argument,       0, IDX_LOOPBACK},
    {"weak-hash-threshold",       required_argument, 0, IDX_WEAK_HASH_THRESHOLD},
    {"session",                   required_argument, 0, IDX_SESSION},
    {"runtime",                   required_argument, 0, IDX_RUNTIME},
    {"generate-rules",            required_argument, 0, IDX_RP_GEN},
    {"generate-rules-func-min",   required_argument, 0, IDX_RP_GEN_FUNC_MIN},
    {"generate-rules-func-max",   required_argument, 0, IDX_RP_GEN_FUNC_MAX},
    {"generate-rules-seed",       required_argument, 0, IDX_RP_GEN_SEED},
    {"rule-left",                 required_argument, 0, IDX_RULE_BUF_L},
    {"rule-right",                required_argument, 0, IDX_RULE_BUF_R},
    {"hash-type",                 required_argument, 0, IDX_HASH_MODE},
    {"attack-mode",               required_argument, 0, IDX_ATTACK_MODE},
    {"rules-file",                required_argument, 0, IDX_RP_FILE},
    {"outfile",                   required_argument, 0, IDX_OUTFILE},
    {"outfile-format",            required_argument, 0, IDX_OUTFILE_FORMAT},
    {"outfile-autohex-disable",   no_argument,       0, IDX_OUTFILE_AUTOHEX_DISABLE},
    {"outfile-check-timer",       required_argument, 0, IDX_OUTFILE_CHECK_TIMER},
    {"hex-charset",               no_argument,       0, IDX_HEX_CHARSET},
    {"hex-salt",                  no_argument,       0, IDX_HEX_SALT},
    {"hex-wordlist",              no_argument,       0, IDX_HEX_WORDLIST},
    {"markov-disable",            no_argument,       0, IDX_MARKOV_DISABLE},
    {"markov-classic",            no_argument,       0, IDX_MARKOV_CLASSIC},
    {"markov-threshold",          required_argument, 0, IDX_MARKOV_THRESHOLD},
    {"markov-hcstat",             required_argument, 0, IDX_MARKOV_HCSTAT},
    {"cpu-affinity",              required_argument, 0, IDX_CPU_AFFINITY},
    {"opencl-info",               no_argument,       0, IDX_OPENCL_INFO},
    {"opencl-devices",            required_argument, 0, IDX_OPENCL_DEVICES},
    {"opencl-platforms",          required_argument, 0, IDX_OPENCL_PLATFORMS},
    {"opencl-device-types",       required_argument, 0, IDX_OPENCL_DEVICE_TYPES},
    {"opencl-vector-width",       required_argument, 0, IDX_OPENCL_VECTOR_WIDTH},
    {"workload-profile",          required_argument, 0, IDX_WORKLOAD_PROFILE},
    {"kernel-accel",              required_argument, 0, IDX_KERNEL_ACCEL},
    {"kernel-loops",              required_argument, 0, IDX_KERNEL_LOOPS},
    {"nvidia-spin-damp",          required_argument, 0, IDX_NVIDIA_SPIN_DAMP},
    {"gpu-temp-disable",          no_argument,       0, IDX_GPU_TEMP_DISABLE},
    #if defined (HAVE_HWMON)
    {"gpu-temp-abort",            required_argument, 0, IDX_GPU_TEMP_ABORT},
    {"gpu-temp-retain",           required_argument, 0, IDX_GPU_TEMP_RETAIN},
    {"powertune-enable",          no_argument,       0, IDX_POWERTUNE_ENABLE},
    #endif // HAVE_HWMON
    {"logfile-disable",           no_argument,       0, IDX_LOGFILE_DISABLE},
    {"truecrypt-keyfiles",        required_argument, 0, IDX_TRUECRYPT_KEYFILES},
    {"veracrypt-keyfiles",        required_argument, 0, IDX_VERACRYPT_KEYFILES},
    {"veracrypt-pim",             required_argument, 0, IDX_VERACRYPT_PIM},
    {"segment-size",              required_argument, 0, IDX_SEGMENT_SIZE},
    {"scrypt-tmto",               required_argument, 0, IDX_SCRYPT_TMTO},
    {"seperator",                 required_argument, 0, IDX_SEPARATOR},
    {"separator",                 required_argument, 0, IDX_SEPARATOR},
    {"bitmap-min",                required_argument, 0, IDX_BITMAP_MIN},
    {"bitmap-max",                required_argument, 0, IDX_BITMAP_MAX},
    {"increment",                 no_argument,       0, IDX_INCREMENT},
    {"increment-min",             required_argument, 0, IDX_INCREMENT_MIN},
    {"increment-max",             required_argument, 0, IDX_INCREMENT_MAX},
    {"custom-charset1",           required_argument, 0, IDX_CUSTOM_CHARSET_1},
    {"custom-charset2",           required_argument, 0, IDX_CUSTOM_CHARSET_2},
    {"custom-charset3",           required_argument, 0, IDX_CUSTOM_CHARSET_3},
    {"custom-charset4",           required_argument, 0, IDX_CUSTOM_CHARSET_4},
    {0, 0, 0, 0}
  };

  uint rp_files_cnt = 0;

  char **rp_files = (char **) mycalloc (argc, sizeof (char *));

  int option_index = 0;
  int c = -1;

  optind = 1;
  optopt = 0;

  while (((c = getopt_long (argc, argv, short_options, long_options, &option_index)) != -1) && optopt == 0)
  {
    switch (c)
    {
      case IDX_HELP:          usage   = 1;      break;
      case IDX_VERSION:
      case IDX_VERSION_LOWER: version = 1;      break;
      case IDX_RESTORE:       restore = 1;      break;
      case IDX_SESSION:       session = optarg; break;
      case IDX_SHOW:          show    = 1;      break;
      case IDX_LEFT:          left    = 1;      break;
      case '?':               return -1;
    }
  }

  if (optopt != 0)
  {
    log_error ("ERROR: Invalid argument specified");

    return -1;
  }

  /**
   * exit functions
   */

  if (version)
  {
    log_info ("%s", VERSION_TAG);

    return 0;
  }

  if (usage)
  {
    usage_big_print (PROGNAME);

    return 0;
  }

  /**
   * session needs to be set, always!
   */

  if (session == NULL) session = (char *) PROGNAME;

  /**
   * folders, as discussed on https://github.com/hashcat/hashcat/issues/20
   */

  char *exec_path = get_exec_path ();


  #if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)

  char *resolved_install_folder = realpath (INSTALL_FOLDER, NULL);
  char *resolved_exec_path      = realpath (exec_path, NULL);

  if (resolved_install_folder == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_install_folder, strerror (errno));

    return -1;
  }

  if (resolved_exec_path == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_exec_path, strerror (errno));

    return -1;
  }

  char *install_dir = get_install_dir (resolved_exec_path);
  char *profile_dir = NULL;
  char *session_dir = NULL;
  char *shared_dir  = NULL;

  if (strcmp (install_dir, resolved_install_folder) == 0)
  {
    struct passwd *pw = getpwuid (getuid ());

    const char *homedir = pw->pw_dir;

    profile_dir = get_profile_dir (homedir);
    session_dir = get_session_dir (profile_dir);
    shared_dir  = mystrdup (SHARED_FOLDER);

    mkdir (profile_dir, 0700);
    mkdir (session_dir, 0700);
  }
  else
  {
    profile_dir = install_dir;
    session_dir = install_dir;
    shared_dir  = install_dir;
  }

  myfree (resolved_install_folder);
  myfree (resolved_exec_path);

  #else

  char *install_dir = get_install_dir (exec_path);
  char *profile_dir = install_dir;
  char *session_dir = install_dir;
  char *shared_dir  = install_dir;

  #endif

  data.install_dir = install_dir;
  data.profile_dir = profile_dir;
  data.session_dir = session_dir;
  data.shared_dir  = shared_dir;

  myfree (exec_path);

  /**
   * There's alot of problem related to bad support -I parameters when building the kernel.
   * Each OpenCL runtime handles it slightly different.
   * The most problematic is with new AMD drivers on Windows, which can not handle quote characters!
   * The best workaround found so far is to modify the TMP variable (only inside hashcat process) before the runtime is load
   */

  char cpath[1024] = { 0 };

  #if defined (_WIN)

  snprintf (cpath, sizeof (cpath) - 1, "%s\\OpenCL\\", shared_dir);

  char *cpath_real = mymalloc (MAX_PATH);

  if (GetFullPathName (cpath, MAX_PATH, cpath_real, NULL) == 0)
  {
    log_error ("ERROR: %s: %s", cpath, "GetFullPathName()");

    return -1;
  }

  #else

  snprintf (cpath, sizeof (cpath) - 1, "%s/OpenCL/", shared_dir);

  char *cpath_real = mymalloc (PATH_MAX);

  if (realpath (cpath, cpath_real) == NULL)
  {
    log_error ("ERROR: %s: %s", cpath, strerror (errno));

    return -1;
  }

  #endif

  //if (getenv ("TMP") == NULL)
  if (1)
  {
    char tmp[1000];

    snprintf (tmp, sizeof (tmp) - 1, "TMP=%s", cpath_real);

    putenv (tmp);
  }

  #if defined (_WIN)

  naive_replace (cpath_real, '\\', '/');

  // not escaping here, windows using quotes later
  // naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #else

  naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #endif

  /**
   * kernel cache, we need to make sure folder exist
   */

  int kernels_folder_size = strlen (profile_dir) + 1 + 7 + 1 + 1;

  char *kernels_folder = (char *) mymalloc (kernels_folder_size);

  snprintf (kernels_folder, kernels_folder_size - 1, "%s/kernels", profile_dir);

  mkdir (kernels_folder, 0700);

  myfree (kernels_folder);

  /**
   * session
   */

  size_t session_size = strlen (session_dir) + 1 + strlen (session) + 32;

  data.session = session;

  char *eff_restore_file = (char *) mymalloc (session_size);
  char *new_restore_file = (char *) mymalloc (session_size);

  snprintf (eff_restore_file, session_size - 1, "%s/%s.restore",     data.session_dir, session);
  snprintf (new_restore_file, session_size - 1, "%s/%s.restore.new", data.session_dir, session);

  data.eff_restore_file = eff_restore_file;
  data.new_restore_file = new_restore_file;

  if (((show == 1) || (left == 1)) && (restore == 1))
  {
    if (show == 1) log_error ("ERROR: Mixing --restore parameter and --show is not supported");
    else           log_error ("ERROR: Mixing --restore parameter and --left is not supported");

    return -1;
  }

  // this allows the user to use --show and --left while cracking (i.e. while another instance of hashcat is running)
  if ((show == 1) || (left == 1))
  {
    restore_disable = 1;

    restore = 0;
  }

  data.restore_disable = restore_disable;

  restore_data_t *rd = init_restore (argc, argv);

  data.rd = rd;

  /**
   * restore file
   */

  if (restore == 1)
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

  uint hash_mode_chgd           = 0;
  uint runtime_chgd             = 0;
  uint kernel_loops_chgd        = 0;
  uint kernel_accel_chgd        = 0;
  uint nvidia_spin_damp_chgd    = 0;
  uint attack_mode_chgd         = 0;
  uint outfile_format_chgd      = 0;
  uint rp_gen_seed_chgd         = 0;
  uint remove_timer_chgd        = 0;
  uint increment_min_chgd       = 0;
  uint increment_max_chgd       = 0;
  uint workload_profile_chgd    = 0;
  uint opencl_vector_width_chgd = 0;

  optind = 1;
  optopt = 0;
  option_index = 0;

  while (((c = getopt_long (myargc, myargv, short_options, long_options, &option_index)) != -1) && optopt == 0)
  {
    switch (c)
    {
    //case IDX_HELP:                      usage                     = 1;              break;
    //case IDX_VERSION:                   version                   = 1;              break;
    //case IDX_RESTORE:                   restore                   = 1;              break;
      case IDX_QUIET:                     quiet                     = 1;              break;
    //case IDX_SHOW:                      show                      = 1;              break;
      case IDX_SHOW:                                                                  break;
    //case IDX_LEFT:                      left                      = 1;              break;
      case IDX_LEFT:                                                                  break;
      case IDX_USERNAME:                  username                  = 1;              break;
      case IDX_REMOVE:                    remove                    = 1;              break;
      case IDX_REMOVE_TIMER:              remove_timer              = atoi (optarg);
                                          remove_timer_chgd         = 1;              break;
      case IDX_POTFILE_DISABLE:           potfile_disable           = 1;              break;
      case IDX_POTFILE_PATH:              potfile_path              = optarg;         break;
      case IDX_DEBUG_MODE:                debug_mode                = atoi (optarg);  break;
      case IDX_DEBUG_FILE:                debug_file                = optarg;         break;
      case IDX_INDUCTION_DIR:             induction_dir             = optarg;         break;
      case IDX_OUTFILE_CHECK_DIR:         outfile_check_dir         = optarg;         break;
      case IDX_FORCE:                     force                     = 1;              break;
      case IDX_SKIP:                      skip                      = atoll (optarg); break;
      case IDX_LIMIT:                     limit                     = atoll (optarg); break;
      case IDX_KEYSPACE:                  keyspace                  = 1;              break;
      case IDX_BENCHMARK:                 benchmark                 = 1;              break;
      case IDX_STDOUT_FLAG:               stdout_flag               = 1;              break;
      case IDX_RESTORE:                                                               break;
      case IDX_RESTORE_DISABLE:           restore_disable           = 1;              break;
      case IDX_STATUS:                    status                    = 1;              break;
      case IDX_STATUS_TIMER:              status_timer              = atoi (optarg);  break;
      case IDX_MACHINE_READABLE:          machine_readable          = 1;              break;
      case IDX_LOOPBACK:                  loopback                  = 1;              break;
      case IDX_WEAK_HASH_THRESHOLD:       weak_hash_threshold       = atoi (optarg);  break;
    //case IDX_SESSION:                   session                   = optarg;         break;
      case IDX_SESSION:                                                               break;
      case IDX_HASH_MODE:                 hash_mode                 = atoi (optarg);
                                          hash_mode_chgd            = 1;              break;
      case IDX_RUNTIME:                   runtime                   = atoi (optarg);
                                          runtime_chgd              = 1;              break;
      case IDX_ATTACK_MODE:               attack_mode               = atoi (optarg);
                                          attack_mode_chgd          = 1;              break;
      case IDX_RP_FILE:                   rp_files[rp_files_cnt++]  = optarg;         break;
      case IDX_RP_GEN:                    rp_gen                    = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MIN:           rp_gen_func_min           = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MAX:           rp_gen_func_max           = atoi (optarg);  break;
      case IDX_RP_GEN_SEED:               rp_gen_seed               = atoi (optarg);
                                          rp_gen_seed_chgd          = 1;              break;
      case IDX_RULE_BUF_L:                rule_buf_l                = optarg;         break;
      case IDX_RULE_BUF_R:                rule_buf_r                = optarg;         break;
      case IDX_MARKOV_DISABLE:            markov_disable            = 1;              break;
      case IDX_MARKOV_CLASSIC:            markov_classic            = 1;              break;
      case IDX_MARKOV_THRESHOLD:          markov_threshold          = atoi (optarg);  break;
      case IDX_MARKOV_HCSTAT:             markov_hcstat             = optarg;         break;
      case IDX_OUTFILE:                   outfile                   = optarg;         break;
      case IDX_OUTFILE_FORMAT:            outfile_format            = atoi (optarg);
                                          outfile_format_chgd       = 1;              break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:   outfile_autohex           = 0;              break;
      case IDX_OUTFILE_CHECK_TIMER:       outfile_check_timer       = atoi (optarg);  break;
      case IDX_HEX_CHARSET:               hex_charset               = 1;              break;
      case IDX_HEX_SALT:                  hex_salt                  = 1;              break;
      case IDX_HEX_WORDLIST:              hex_wordlist              = 1;              break;
      case IDX_CPU_AFFINITY:              cpu_affinity              = optarg;         break;
      case IDX_OPENCL_INFO:               opencl_info               = 1;              break;
      case IDX_OPENCL_DEVICES:            opencl_devices            = optarg;         break;
      case IDX_OPENCL_PLATFORMS:          opencl_platforms          = optarg;         break;
      case IDX_OPENCL_DEVICE_TYPES:       opencl_device_types       = optarg;         break;
      case IDX_OPENCL_VECTOR_WIDTH:       opencl_vector_width       = atoi (optarg);
                                          opencl_vector_width_chgd  = 1;              break;
      case IDX_WORKLOAD_PROFILE:          workload_profile          = atoi (optarg);
                                          workload_profile_chgd     = 1;              break;
      case IDX_KERNEL_ACCEL:              kernel_accel              = atoi (optarg);
                                          kernel_accel_chgd         = 1;              break;
      case IDX_KERNEL_LOOPS:              kernel_loops              = atoi (optarg);
                                          kernel_loops_chgd         = 1;              break;
      case IDX_NVIDIA_SPIN_DAMP:          nvidia_spin_damp          = atoi (optarg);
                                          nvidia_spin_damp_chgd     = 1;              break;
      case IDX_GPU_TEMP_DISABLE:          gpu_temp_disable          = 1;              break;
      #if defined (HAVE_HWMON)
      case IDX_GPU_TEMP_ABORT:            gpu_temp_abort            = atoi (optarg);  break;
      case IDX_GPU_TEMP_RETAIN:           gpu_temp_retain           = atoi (optarg);  break;
      case IDX_POWERTUNE_ENABLE:          powertune_enable          = 1;              break;
      #endif // HAVE_HWMON
      case IDX_LOGFILE_DISABLE:           logfile_disable           = 1;              break;
      case IDX_TRUECRYPT_KEYFILES:        truecrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_KEYFILES:        veracrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_PIM:             veracrypt_pim             = atoi (optarg);  break;
      case IDX_SEGMENT_SIZE:              segment_size              = atoi (optarg);  break;
      case IDX_SCRYPT_TMTO:               scrypt_tmto               = atoi (optarg);  break;
      case IDX_SEPARATOR:                 separator                 = optarg[0];      break;
      case IDX_BITMAP_MIN:                bitmap_min                = atoi (optarg);  break;
      case IDX_BITMAP_MAX:                bitmap_max                = atoi (optarg);  break;
      case IDX_INCREMENT:                 increment                 = 1;              break;
      case IDX_INCREMENT_MIN:             increment_min             = atoi (optarg);
                                          increment_min_chgd        = 1;              break;
      case IDX_INCREMENT_MAX:             increment_max             = atoi (optarg);
                                          increment_max_chgd        = 1;              break;
      case IDX_CUSTOM_CHARSET_1:          custom_charset_1          = optarg;         break;
      case IDX_CUSTOM_CHARSET_2:          custom_charset_2          = optarg;         break;
      case IDX_CUSTOM_CHARSET_3:          custom_charset_3          = optarg;         break;
      case IDX_CUSTOM_CHARSET_4:          custom_charset_4          = optarg;         break;

      default:
        log_error ("ERROR: Invalid argument specified");
        return -1;
    }
  }

  if (optopt != 0)
  {
    log_error ("ERROR: Invalid argument specified");

    return -1;
  }

  if (opencl_info)
  {
    quiet             = 1;
    gpu_temp_disable  = 1;
    potfile_disable   = 1;
    restore_disable   = 1;
    markov_disable    = 1;
    logfile_disable   = 1;
    //stdout_flag       = 1;
  }

  /**
   * Inform user things getting started,
   * - this is giving us a visual header before preparations start, so we do not need to clear them afterwards
   * - we do not need to check algorithm_pos
   */

  if (quiet == 0)
  {
    if (benchmark == 1)
    {
      if (machine_readable == 0)
      {
        log_info ("%s (%s) starting in benchmark-mode...", PROGNAME, VERSION_TAG);
        log_info ("");
      }
      else
      {
        log_info ("# %s (%s) %s", PROGNAME, VERSION_TAG, ctime (&proc_start));
      }
    }
    else if (restore == 1)
    {
      log_info ("%s (%s) starting in restore-mode...", PROGNAME, VERSION_TAG);
      log_info ("");
    }
    else if (stdout_flag == 1)
    {
      // do nothing
    }
    else if (keyspace == 1)
    {
      // do nothing
    }
    else
    {
      if ((show == 1) || (left == 1))
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
   * sanity check
   */

  if (attack_mode > 7)
  {
    log_error ("ERROR: Invalid attack-mode specified");

    return -1;
  }

  if (runtime_chgd && runtime == 0) // just added to remove compiler warnings for runtime_chgd
  {
    log_error ("ERROR: Invalid runtime specified");

    return -1;
  }

  if (hash_mode_chgd && hash_mode > 14100) // just added to remove compiler warnings for hash_mode_chgd
  {
    log_error ("ERROR: Invalid hash-type specified");

    return -1;
  }

  // renamed hash modes

  if (hash_mode_chgd)
  {
    int n = -1;

    switch (hash_mode)
    {
      case 123: n = 124;
                break;
    }

    if (n >= 0)
    {
      log_error ("Old -m specified, use -m %d instead", n);

      return -1;
    }
  }

  if (username == 1)
  {
    if ((hash_mode == 2500) || (hash_mode == 5200) || ((hash_mode >= 6200) && (hash_mode <= 6299)) || ((hash_mode >= 13700) && (hash_mode <= 13799)))
    {
      log_error ("ERROR: Mixing support for user names and hashes of type %s is not supported", strhashtype (hash_mode));

      return -1;
    }
  }

  if (outfile_format > 16)
  {
    log_error ("ERROR: Invalid outfile-format specified");

    return -1;
  }

  if (left == 1)
  {
    if (outfile_format_chgd == 1)
    {
      if (outfile_format > 1)
      {
        log_error ("ERROR: Mixing outfile-format > 1 with left parameter is not allowed");

        return -1;
      }
    }
    else
    {
      outfile_format = OUTFILE_FMT_HASH;
    }
  }

  if (show == 1)
  {
    if (outfile_format_chgd == 1)
    {
      if ((outfile_format > 7) && (outfile_format < 16))
      {
        log_error ("ERROR: Mixing outfile-format > 7 with show parameter is not allowed");

        return -1;
      }
    }
  }

  if (increment_min < INCREMENT_MIN)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if (increment_max > INCREMENT_MAX)
  {
    log_error ("ERROR: Invalid increment-max specified");

    return -1;
  }

  if (increment_min > increment_max)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if ((increment == 1) && (attack_mode == ATTACK_MODE_STRAIGHT))
  {
    log_error ("ERROR: Increment is not allowed in attack-mode 0");

    return -1;
  }

  if ((increment == 0) && (increment_min_chgd == 1))
  {
    log_error ("ERROR: Increment-min is only supported combined with increment switch");

    return -1;
  }

  if ((increment == 0) && (increment_max_chgd == 1))
  {
    log_error ("ERROR: Increment-max is only supported combined with increment switch");

    return -1;
  }

  if (rp_files_cnt && rp_gen)
  {
    log_error ("ERROR: Use of both rules-file and rules-generate is not supported");

    return -1;
  }

  if (rp_files_cnt || rp_gen)
  {
    if (attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Use of rules-file or rules-generate only allowed in attack-mode 0");

      return -1;
    }
  }

  if (rp_gen_func_min > rp_gen_func_max)
  {
    log_error ("ERROR: Invalid rp-gen-func-min specified");

    return -1;
  }

  if (kernel_accel_chgd == 1)
  {
    if (force == 0)
    {
      log_info ("The manual use of the -n option (or --kernel-accel) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (kernel_accel < 1)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }

    if (kernel_accel > 1024)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }
  }

  if (kernel_loops_chgd == 1)
  {
    if (force == 0)
    {
      log_info ("The manual use of the -u option (or --kernel-loops) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (kernel_loops < 1)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }

    if (kernel_loops > 1024)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }
  }

  if ((workload_profile < 1) || (workload_profile > 4))
  {
    log_error ("ERROR: workload-profile %i not available", workload_profile);

    return -1;
  }

  if (opencl_vector_width_chgd && (!is_power_of_2(opencl_vector_width) || opencl_vector_width > 16))
  {
    log_error ("ERROR: opencl-vector-width %i not allowed", opencl_vector_width);

    return -1;
  }

  if (show == 1 || left == 1)
  {
    attack_mode = ATTACK_MODE_NONE;

    if (remove == 1)
    {
      log_error ("ERROR: Mixing remove parameter not allowed with show parameter or left parameter");

      return -1;
    }

    if (potfile_disable == 1)
    {
      log_error ("ERROR: Mixing potfile-disable parameter not allowed with show parameter or left parameter");

      return -1;
    }
  }

  if (show == 1)
  {
    if (outfile_autohex == 0)
    {
      log_error ("ERROR: Mixing outfile-autohex-disable parameter not allowed with show parameter");

      return -1;
    }
  }

  uint attack_kern = ATTACK_KERN_NONE;

  switch (attack_mode)
  {
    case ATTACK_MODE_STRAIGHT: attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_COMBI:    attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_BF:       attack_kern = ATTACK_KERN_BF;       break;
    case ATTACK_MODE_HYBRID1:  attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID2:  attack_kern = ATTACK_KERN_COMBI;    break;
  }

  if (benchmark == 1)
  {
    if (myargv[optind] != 0)
    {
      log_error ("ERROR: Invalid argument for benchmark mode specified");

      return -1;
    }

    if (attack_mode_chgd == 1)
    {
      if (attack_mode != ATTACK_MODE_BF)
      {
        log_error ("ERROR: Only attack-mode 3 allowed in benchmark mode");

        return -1;
      }
    }
  }
  else
  {
    if (stdout_flag == 1) // no hash here
    {
      optind--;
    }

    if (keyspace == 1)
    {
      int num_additional_params = 1;

      if (attack_kern == ATTACK_KERN_COMBI)
      {
        num_additional_params = 2;
      }

      int keyspace_wordlist_specified = myargc - optind - num_additional_params;

      if (keyspace_wordlist_specified == 0) optind--;
    }

    if (attack_kern == ATTACK_KERN_NONE)
    {
      if ((optind + 1) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if ((optind + 1) > myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_COMBI)
    {
      if ((optind + 3) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_BF)
    {
      if ((optind + 1) > myargc)
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

  if (skip != 0 && limit != 0)
  {
    limit += skip;
  }

  if (keyspace == 1)
  {
    if (show == 1)
    {
      log_error ("ERROR: Combining show parameter with keyspace parameter is not allowed");

      return -1;
    }
    else if (left == 1)
    {
      log_error ("ERROR: Combining left parameter with keyspace parameter is not allowed");

      return -1;
    }

    potfile_disable = 1;

    restore_disable = 1;

    restore = 0;

    weak_hash_threshold = 0;

    quiet = 1;
  }

  if (stdout_flag == 1)
  {
    status_timer          = 0;
    restore_timer         = 0;
    restore_disable       = 1;
    restore               = 0;
    potfile_disable       = 1;
    weak_hash_threshold   = 0;
    gpu_temp_disable      = 1;
    hash_mode             = 2000;
    quiet                 = 1;
    outfile_format        = OUTFILE_FMT_PLAIN;
    kernel_accel          = 1024;
    kernel_loops          = 1024;
    force                 = 1;
    outfile_check_timer   = 0;
    session               = "stdout";
    opencl_vector_width   = 1;
  }

  if (opencl_info == true)
  {
    opencl_platforms    = NULL;
    opencl_devices      = NULL;
    opencl_device_types = mystrdup ("1,2,3");
  }

  if (remove_timer_chgd == 1)
  {
    if (remove == 0)
    {
      log_error ("ERROR: Parameter remove-timer require parameter remove enabled");

      return -1;
    }

    if (remove_timer < 1)
    {
      log_error ("ERROR: Parameter remove-timer must have a value greater than or equal to 1");

      return -1;
    }
  }

  if (loopback == 1)
  {
    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if ((rp_files_cnt == 0) && (rp_gen == 0))
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

  if (debug_mode > 0)
  {
    if (attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Parameter debug-mode option is only available with attack-mode 0");

      return -1;
    }

    if ((rp_files_cnt == 0) && (rp_gen == 0))
    {
      log_error ("ERROR: Parameter debug-mode not allowed without rules-file or rules-generate");

      return -1;
    }
  }

  if (debug_mode > 4)
  {
    log_error ("ERROR: Invalid debug-mode specified");

    return -1;
  }

  if (debug_file != NULL)
  {
    if (debug_mode < 1)
    {
      log_error ("ERROR: Parameter debug-file requires parameter debug-mode to be set");

      return -1;
    }
  }

  if (induction_dir != NULL)
  {
    if (attack_mode == ATTACK_MODE_BF)
    {
      log_error ("ERROR: Parameter induction-dir not allowed with brute-force attacks");

      return -1;
    }
  }

  if (attack_mode != ATTACK_MODE_STRAIGHT)
  {
    if ((weak_hash_threshold != WEAK_HASH_THRESHOLD) && (weak_hash_threshold != 0))
    {
      log_error ("ERROR: setting --weak-hash-threshold allowed only in straight-attack mode");

      return -1;
    }

    weak_hash_threshold = 0;
  }

  if (nvidia_spin_damp > 100)
  {
    log_error ("ERROR: setting --nvidia-spin-damp must be between 0 and 100 (inclusive)");

    return -1;
  }


  /**
   * induction directory
   */

  char *induction_directory = NULL;

  if (attack_mode != ATTACK_MODE_BF)
  {
    if (induction_dir == NULL)
    {
      induction_directory = (char *) mymalloc (session_size);

      snprintf (induction_directory, session_size - 1, "%s/%s.%s", session_dir, session, INDUCT_DIR);

      // create induction folder if it does not already exist

      if (keyspace == 0)
      {
        if (rmdir (induction_directory) == -1)
        {
          if (errno == ENOENT)
          {
            // good, we can ignore
          }
          else if (errno == ENOTEMPTY)
          {
            char *induction_directory_mv = (char *) mymalloc (session_size);

            snprintf (induction_directory_mv, session_size - 1, "%s/%s.induct.%d", session_dir, session, (int) proc_start);

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
      induction_directory = induction_dir;
    }
  }

  data.induction_directory = induction_directory;

  /**
   * tuning db
   */

  char tuning_db_file[256] = { 0 };

  snprintf (tuning_db_file, sizeof (tuning_db_file) - 1, "%s/%s", shared_dir, TUNING_DB_FILE);

  tuning_db_t *tuning_db = tuning_db_init (tuning_db_file);

  /**
   * outfile-check directory
   */

  char *outfile_check_directory = NULL;

  if (outfile_check_dir == NULL)
  {
    outfile_check_directory = (char *) mymalloc (session_size);

    snprintf (outfile_check_directory, session_size - 1, "%s/%s.%s", session_dir, session, OUTFILES_DIR);
  }
  else
  {
    outfile_check_directory = outfile_check_dir;
  }

  data.outfile_check_directory = outfile_check_directory;

  if (keyspace == 0)
  {
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
    else if (outfile_check_dir == NULL)
    {
      if (mkdir (outfile_check_directory, 0700) == -1)
      {
        log_error ("ERROR: %s: %s", outfile_check_directory, strerror (errno));

        return -1;
      }
    }
  }

  /**
   * special other stuff
   */

  if (hash_mode == 9710)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  if (hash_mode == 9810)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  if (hash_mode == 10410)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  /**
   * store stuff
   */

  data.restore                 = restore;
  data.restore_timer           = restore_timer;
  data.restore_disable         = restore_disable;
  data.status                  = status;
  data.status_timer            = status_timer;
  data.machine_readable        = machine_readable;
  data.loopback                = loopback;
  data.runtime                 = runtime;
  data.remove                  = remove;
  data.remove_timer            = remove_timer;

  data.username                = username;
  data.quiet                   = quiet;

  data.hex_charset             = hex_charset;
  data.hex_salt                = hex_salt;
  data.hex_wordlist            = hex_wordlist;
  data.rp_files                = rp_files;
  data.rp_files_cnt            = rp_files_cnt;
  data.rp_gen                  = rp_gen;
  data.rp_gen_seed             = rp_gen_seed;
  data.force                   = force;
  data.benchmark               = benchmark;
  data.skip                    = skip;
  data.limit                   = limit;
  data.custom_charset_1        = custom_charset_1;
  data.custom_charset_2        = custom_charset_2;
  data.custom_charset_3        = custom_charset_3;
  data.custom_charset_4        = custom_charset_4;
  #if defined (HAVE_HWMONO)
  data.powertune_enable        = powertune_enable;
  #endif
  data.logfile_disable         = logfile_disable;
  data.truecrypt_keyfiles      = truecrypt_keyfiles;
  data.veracrypt_keyfiles      = veracrypt_keyfiles;
  data.veracrypt_pim           = veracrypt_pim;
  data.scrypt_tmto             = scrypt_tmto;

  /**
   * cpu affinity
   */

  if (cpu_affinity)
  {
    set_cpu_affinity (cpu_affinity);
  }

  if (rp_gen_seed_chgd == 0)
  {
    srand (proc_start);
  }
  else
  {
    srand (rp_gen_seed);
  }

  /**
   * logfile init
   */

  if (logfile_disable == 0)
  {
    size_t logfile_size = strlen (session_dir) + 1 + strlen (session) + 32;

    char *logfile = (char *) mymalloc (logfile_size);

    snprintf (logfile, logfile_size - 1, "%s/%s.log", session_dir, session);

    data.logfile = logfile;

    char *topid = logfile_generate_topid ();

    data.topid = topid;
  }

  logfile_top_msg ("START");

  logfile_top_uint   (attack_mode);
  logfile_top_uint   (attack_kern);
  logfile_top_uint   (benchmark);
  logfile_top_uint   (stdout_flag);
  logfile_top_uint   (bitmap_min);
  logfile_top_uint   (bitmap_max);
  logfile_top_uint   (debug_mode);
  logfile_top_uint   (force);
  logfile_top_uint   (kernel_accel);
  logfile_top_uint   (kernel_loops);
  logfile_top_uint   (nvidia_spin_damp);
  logfile_top_uint   (gpu_temp_disable);
  #if defined (HAVE_HWMON)
  logfile_top_uint   (gpu_temp_abort);
  logfile_top_uint   (gpu_temp_retain);
  #endif
  logfile_top_uint   (hash_mode);
  logfile_top_uint   (hex_charset);
  logfile_top_uint   (hex_salt);
  logfile_top_uint   (hex_wordlist);
  logfile_top_uint   (increment);
  logfile_top_uint   (increment_max);
  logfile_top_uint   (increment_min);
  logfile_top_uint   (keyspace);
  logfile_top_uint   (left);
  logfile_top_uint   (logfile_disable);
  logfile_top_uint   (loopback);
  logfile_top_uint   (markov_classic);
  logfile_top_uint   (markov_disable);
  logfile_top_uint   (markov_threshold);
  logfile_top_uint   (outfile_autohex);
  logfile_top_uint   (outfile_check_timer);
  logfile_top_uint   (outfile_format);
  logfile_top_uint   (potfile_disable);
  logfile_top_string (potfile_path);
  #if defined(HAVE_HWMON)
  logfile_top_uint   (powertune_enable);
  #endif
  logfile_top_uint   (scrypt_tmto);
  logfile_top_uint   (quiet);
  logfile_top_uint   (remove);
  logfile_top_uint   (remove_timer);
  logfile_top_uint   (restore);
  logfile_top_uint   (restore_disable);
  logfile_top_uint   (restore_timer);
  logfile_top_uint   (rp_gen);
  logfile_top_uint   (rp_gen_func_max);
  logfile_top_uint   (rp_gen_func_min);
  logfile_top_uint   (rp_gen_seed);
  logfile_top_uint   (runtime);
  logfile_top_uint   (segment_size);
  logfile_top_uint   (show);
  logfile_top_uint   (status);
  logfile_top_uint   (machine_readable);
  logfile_top_uint   (status_timer);
  logfile_top_uint   (usage);
  logfile_top_uint   (username);
  logfile_top_uint   (version);
  logfile_top_uint   (weak_hash_threshold);
  logfile_top_uint   (workload_profile);
  logfile_top_uint64 (limit);
  logfile_top_uint64 (skip);
  logfile_top_char   (separator);
  logfile_top_string (cpu_affinity);
  logfile_top_string (custom_charset_1);
  logfile_top_string (custom_charset_2);
  logfile_top_string (custom_charset_3);
  logfile_top_string (custom_charset_4);
  logfile_top_string (debug_file);
  logfile_top_string (opencl_devices);
  logfile_top_string (opencl_platforms);
  logfile_top_string (opencl_device_types);
  logfile_top_uint   (opencl_vector_width);
  logfile_top_string (induction_dir);
  logfile_top_string (markov_hcstat);
  logfile_top_string (outfile);
  logfile_top_string (outfile_check_dir);
  logfile_top_string (rule_buf_l);
  logfile_top_string (rule_buf_r);
  logfile_top_string (session);
  logfile_top_string (truecrypt_keyfiles);
  logfile_top_string (veracrypt_keyfiles);
  logfile_top_uint   (veracrypt_pim);

  /**
   * Init OpenCL library loader
   */

  opencl_ctx_t *opencl_ctx = (opencl_ctx_t *) mymalloc (sizeof (opencl_ctx_t));

  data.opencl_ctx = opencl_ctx;

  const int rc_opencl_init = opencl_ctx_init (opencl_ctx, opencl_platforms, opencl_devices, opencl_device_types, opencl_vector_width, opencl_vector_width_chgd, nvidia_spin_damp, nvidia_spin_damp_chgd, workload_profile, kernel_accel, kernel_accel_chgd, kernel_loops, kernel_loops_chgd, keyspace, stdout_flag);

  if (rc_opencl_init == -1)
  {
    log_error ("ERROR: opencl_ctx_init() failed");

    return -1;
  }

  /**
   * benchmark
   */

  if (benchmark == 1)
  {
    /**
     * disable useless stuff for benchmark
     */

    status_timer          = 0;
    restore_timer         = 0;
    restore_disable       = 1;
    potfile_disable       = 1;
    weak_hash_threshold   = 0;
    nvidia_spin_damp      = 0;
    gpu_temp_disable      = 1;
    outfile_check_timer   = 0;

    #if defined (HAVE_HWMON)
    if (powertune_enable == 1)
    {
      gpu_temp_disable = 0;
    }
    #endif

    data.status_timer         = status_timer;
    data.restore_timer        = restore_timer;
    data.restore_disable      = restore_disable;
    data.outfile_check_timer  = outfile_check_timer;

    /**
     * force attack mode to be bruteforce
     */

    attack_mode = ATTACK_MODE_BF;
    attack_kern = ATTACK_KERN_BF;

    if (workload_profile_chgd == 0)
    {
      workload_profile = 3;

      opencl_ctx->workload_profile = workload_profile;
    }
  }

  data.attack_mode = attack_mode;
  data.attack_kern = attack_kern;

  /**
   * status, monitor and outfile remove threads
   */

  uint wordlist_mode = ((optind + 1) < myargc) ? WL_MODE_FILE : WL_MODE_STDIN;

  data.wordlist_mode = wordlist_mode;

  if (wordlist_mode == WL_MODE_STDIN)
  {
    // enable status (in stdin mode) whenever we do not use --stdout together with an outfile

    if      (stdout_flag == 0) status = 1;
    else if (outfile != NULL)  status = 1;

    data.status = status;
  }

  uint outer_threads_cnt = 0;

  hc_thread_t *outer_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  data.shutdown_outer = 0;

  if (keyspace == 0 && benchmark == 0 && stdout_flag == 0)
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
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

  if (benchmark == 1 && hash_mode_chgd == 0) algorithm_max = DEFAULT_BENCHMARK_ALGORITHMS_CNT;

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

    if (benchmark == 1)
    {
      if (hash_mode_chgd == 0)
      {
        hash_mode = algorithms[algorithm_pos];
      }

      quiet = 1;

      data.quiet = quiet;
    }

    /**
     * setup variables and buffers depending on hash_mode
     */

    const int rc_hashconfig = hashconfig_init (hashconfig, hash_mode, separator, hex_salt);

    if (rc_hashconfig == -1) return -1;

    /**
     * outfile
     */

    outfile_ctx_t *outfile_ctx = mymalloc (sizeof (outfile_ctx_t));

    data.outfile_ctx = outfile_ctx;

    outfile_init (outfile_ctx, outfile, outfile_format, outfile_autohex);

    /**
     * Sanity check for hashfile vs outfile (should not point to the same physical file)
     */

    const int rc_outfile_and_hashfile = outfile_and_hashfile (outfile_ctx, myargv[optind]);

    if (rc_outfile_and_hashfile == -1) return -1;

    /**
     * potfile
     */

    potfile_ctx_t *potfile_ctx = mymalloc (sizeof (potfile_ctx_t));

    data.potfile_ctx = potfile_ctx;

    potfile_init (potfile_ctx, profile_dir, potfile_path, potfile_disable);

    if (show == 1 || left == 1)
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

    const int rc_hashes_init_stage1 = hashes_init_stage1 (hashes, hashconfig, potfile_ctx, outfile_ctx, myargv[optind], keyspace, quiet, benchmark, opencl_info, stdout_flag, username, remove, show, left);

    if (rc_hashes_init_stage1 == -1) return -1;

    logfile_top_var_string ("hashfile", hashes->hashfile);

    logfile_top_uint (hashes->hashlist_mode);
    logfile_top_uint (hashes->hashlist_format);

    if ((keyspace == 0) && (stdout_flag == 0))
    {
      if (hashes->hashes_cnt == 0)
      {
        log_error ("ERROR: No hashes loaded");

        return -1;
      }
    }

    if (show == 1 || left == 1)
    {
      outfile_write_close (outfile_ctx);

      potfile_hash_free (potfile_ctx, hashconfig);

      if (data.quiet == 0) log_info_nn ("");

      return 0;
    }

    /**
     * Potfile removes
     */

    int potfile_remove_cracks = 0;

    if (potfile_disable == 0)
    {
      if (data.quiet == 0) log_info_nn ("Comparing hashes with potfile entries...");

      potfile_remove_cracks = potfile_remove_parse (potfile_ctx, hashconfig, hashes);
    }

    /**
     * load hashes, stage 2
     */

    uint hashes_cnt_orig = hashes->hashes_cnt;

    const int rc_hashes_init_stage2 = hashes_init_stage2 (hashes, hashconfig, opencl_ctx, username, remove, show);

    if (rc_hashes_init_stage2 == -1) return -1;

    /**
     * Automatic Optimizers
     */

    char *optional_param1 = NULL;

    if (truecrypt_keyfiles) optional_param1 = truecrypt_keyfiles;
    if (veracrypt_keyfiles) optional_param1 = veracrypt_keyfiles;

    hashconfig_general_defaults (hashconfig, hashes, optional_param1);

    if (hashes->salts_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_SALT;

    if (hashes->digests_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_HASH;

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      hashconfig->opti_type |= OPTI_TYPE_NOT_ITERATED;

    if (attack_mode == ATTACK_MODE_BF)
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

    dictstat_init (dictstat_ctx, profile_dir);

    if (keyspace == 0)
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

    debugfile_init (debugfile_ctx, debug_mode, debug_file);

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

    if (custom_charset_1) mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
    if (custom_charset_2) mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
    if (custom_charset_3) mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);
    if (custom_charset_4) mp_setup_usr (mp_sys, mp_usr, custom_charset_4, 3, hashconfig);

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
    else if (hashconfig->hash_mode == 1500 && attack_mode == ATTACK_MODE_BF && hashes->salts_cnt == 1)
    {
      opencl_ctx->force_jit_compilation = 1500;
    }

    /**
     * generate bitmap tables
     */

    const uint bitmap_shift1 = 5;
    const uint bitmap_shift2 = 13;

    if (bitmap_max < bitmap_min) bitmap_max = bitmap_min;

    uint *bitmap_s1_a = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_b = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_c = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_d = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_a = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_b = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_c = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_d = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));

    uint bitmap_bits;
    uint bitmap_nums;
    uint bitmap_mask;
    uint bitmap_size;

    for (bitmap_bits = bitmap_min; bitmap_bits < bitmap_max; bitmap_bits++)
    {
      if (data.quiet == 0) log_info_nn ("Generating bitmap tables with %u bits...", bitmap_bits);

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
     * prepare quick rule
     */

    data.rule_buf_l = rule_buf_l;
    data.rule_buf_r = rule_buf_r;

    int rule_len_l = (int) strlen (rule_buf_l);
    int rule_len_r = (int) strlen (rule_buf_r);

    data.rule_len_l = rule_len_l;
    data.rule_len_r = rule_len_r;

    /**
     * load rules
     */

    uint *all_kernel_rules_cnt = NULL;

    kernel_rule_t **all_kernel_rules_buf = NULL;

    if (rp_files_cnt)
    {
      all_kernel_rules_cnt = (uint *) mycalloc (rp_files_cnt, sizeof (uint));

      all_kernel_rules_buf = (kernel_rule_t **) mycalloc (rp_files_cnt, sizeof (kernel_rule_t *));
    }

    char *rule_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

    int rule_len = 0;

    for (uint i = 0; i < rp_files_cnt; i++)
    {
      uint kernel_rules_avail = 0;

      uint kernel_rules_cnt = 0;

      kernel_rule_t *kernel_rules_buf = NULL;

      char *rp_file = rp_files[i];

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

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (rp_files_cnt)
      {
        kernel_rules_cnt = 1;

        uint *repeats = (uint *) mycalloc (rp_files_cnt + 1, sizeof (uint));

        repeats[0] = kernel_rules_cnt;

        for (uint i = 0; i < rp_files_cnt; i++)
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

          for (uint j = 0; j < rp_files_cnt; j++)
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
      else if (rp_gen)
      {
        uint kernel_rules_avail = 0;

        while (kernel_rules_cnt < rp_gen)
        {
          if (kernel_rules_avail == kernel_rules_cnt)
          {
            kernel_rules_buf = (kernel_rule_t *) myrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

            kernel_rules_avail += INCR_RULES;
          }

          memset (rule_buf, 0, HCBUFSIZ_LARGE);

          rule_len = (int) generate_random_rule (rule_buf, rp_gen_func_min, rp_gen_func_max);

          if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1) continue;

          kernel_rules_cnt++;
        }
      }
    }

    myfree (rule_buf);

    /**
     * generate NOP rules
     */

    if ((rp_files_cnt == 0) && (rp_gen == 0))
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
      switch (attack_kern)
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
        switch (attack_kern)
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

    if (opencl_ctx_devices_init (opencl_ctx, hashconfig, tuning_db, attack_mode, quiet, force, benchmark, opencl_info, machine_readable, algorithm_pos) != 0)
    {
      log_error ("ERROR: opencl_ctx_devices_init() failed.");
      return -1;
    }

    /**
     * HM devices: init
     */

    #if defined (HAVE_HWMON)
    hm_attrs_t hm_adapters_adl[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvapi[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvml[DEVICES_MAX];
    hm_attrs_t hm_adapters_xnvctrl[DEVICES_MAX];

    memset (hm_adapters_adl,     0, sizeof (hm_adapters_adl));
    memset (hm_adapters_nvapi,   0, sizeof (hm_adapters_nvapi));
    memset (hm_adapters_nvml,    0, sizeof (hm_adapters_nvml));
    memset (hm_adapters_xnvctrl, 0, sizeof (hm_adapters_xnvctrl));

    if (gpu_temp_disable == 0)
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
        gpu_temp_disable = 1;
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

    if (gpu_temp_disable == 1)
    {
      gpu_temp_abort  = 0;
      gpu_temp_retain = 0;
    }

    if ((gpu_temp_abort != 0) && (gpu_temp_retain != 0))
    {
      if (gpu_temp_abort < gpu_temp_retain)
      {
        log_error ("ERROR: Invalid values for gpu-temp-abort. Parameter gpu-temp-abort is less than gpu-temp-retain.");

        return -1;
      }
    }

    data.gpu_temp_disable = gpu_temp_disable;
    data.gpu_temp_abort   = gpu_temp_abort;
    data.gpu_temp_retain  = gpu_temp_retain;
    #endif

    /**
     * enable custom signal handler(s)
     */

    if (benchmark == 0)
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

    if (data.quiet == 0)
    {
      log_info ("Hashes: %u digests; %u unique digests, %u unique salts", hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);

      log_info ("Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_bits, bitmap_nums, bitmap_mask, bitmap_size, bitmap_shift1, bitmap_shift2);

      if (attack_mode == ATTACK_MODE_STRAIGHT)
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

      #if defined (HAVE_HWMON)
      if (gpu_temp_disable == 0 && data.hm_adl == NULL && data.hm_nvml == NULL && data.hm_xnvctrl == NULL)
      {
        log_info ("Watchdog: Hardware Monitoring Interface not found on your system");
      }

      if (gpu_temp_abort == 0)
      {
        log_info ("Watchdog: Temperature abort trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature abort trigger set to %uc", gpu_temp_abort);
      }

      if (gpu_temp_retain == 0)
      {
        log_info ("Watchdog: Temperature retain trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature retain trigger set to %uc", gpu_temp_retain);
      }

      if (data.quiet == 0) log_info ("");
      #endif
    }

    #if defined (HAVE_HWMON)

    /**
     * HM devices: copy
     */

    if (gpu_temp_disable == 0)
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

    if (powertune_enable == 1)
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

    #endif // HAVE_HWMON

    #if defined (DEBUG)
    if (benchmark == 1) log_info ("Hashmode: %d", hashconfig->hash_mode);
    #endif

    if (data.quiet == 0) log_info_nn ("Initializing device kernels and memory...");

    session_ctx_t *session_ctx = (session_ctx_t *) mymalloc (sizeof (session_ctx_t));

    data.session_ctx = session_ctx;

    session_ctx_init (session_ctx, quiet, force, benchmark, scrypt_tmto, cwd, install_dir, profile_dir, session_dir, shared_dir, cpath_real, wordlist_mode, rule_buf_l, rule_buf_r, rule_len_l, rule_len_r, kernel_rules_cnt, kernel_rules_buf, attack_mode, attack_kern, bitmap_size, bitmap_mask, bitmap_shift1, bitmap_shift2, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, bitmap_s2_a, bitmap_s2_b, bitmap_s2_c, bitmap_s2_d);

    opencl_session_begin (opencl_ctx, hashconfig, hashes, session_ctx);

    if (data.quiet == 0) log_info_nn ("");

    /**
     * Store initial fanspeed if gpu_temp_retain is enabled
     */

    #if defined(HAVE_HWMON)

    for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (gpu_temp_disable == 1) continue;

      if (gpu_temp_retain == 0) continue;

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

    #endif // HAVE_HWMON

    /**
     * In benchmark-mode, inform user which algorithm is checked
     */

    if (benchmark == 1)
    {
      if (machine_readable == 0)
      {
        quiet = 0;

        data.quiet = quiet;

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

    segment_size *= (1024 * 1024);

    data.segment_size = segment_size;

    wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

    wl_data->buf   = (char *) mymalloc (segment_size);
    wl_data->avail = segment_size;
    wl_data->incr  = segment_size;
    wl_data->cnt   = 0;
    wl_data->pos   = 0;

    cs_t  *css_buf   = NULL;
    uint   css_cnt   = 0;
    uint   dictcnt   = 0;
    uint   maskcnt   = 1;
    char **masks     = NULL;
    char **dictfiles = NULL;

    uint   mask_from_file = 0;

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (wordlist_mode == WL_MODE_FILE)
      {
        int wls_left = myargc - (optind + 1);

        for (int i = 0; i < wls_left; i++)
        {
          char *l0_filename = myargv[optind + 1 + i];

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

            if (keyspace == 1)
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
      else if (wordlist_mode == WL_MODE_STDIN)
      {
        dictcnt = 1;
      }
    }
    else if (attack_mode == ATTACK_MODE_COMBI)
    {
      // display

      char *dictfile1 = myargv[optind + 1 + 0];
      char *dictfile2 = myargv[optind + 1 + 1];

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

      data.quiet = 1;

      const u64 words1_cnt = count_words (wl_data, fp1, dictfile1, dictstat_ctx);

      data.quiet = quiet;

      if (words1_cnt == 0)
      {
        log_error ("ERROR: %s: empty file", dictfile1);

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      data.combs_cnt = 1;

      data.quiet = 1;

      const u64 words2_cnt = count_words (wl_data, fp2, dictfile2, dictstat_ctx);

      data.quiet = quiet;

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
    else if (attack_mode == ATTACK_MODE_BF)
    {
      char *mask = NULL;

      maskcnt = 0;

      if (benchmark == 0)
      {
        mask = myargv[optind + 1];

        masks = (char **) mymalloc (INCR_MASKS * sizeof (char *));

        if ((optind + 2) <= myargc)
        {
          struct stat file_stat;

          if (stat (mask, &file_stat) == -1)
          {
            maskcnt = 1;

            masks[maskcnt - 1] = mystrdup (mask);
          }
          else
          {
            int wls_left = myargc - (optind + 1);

            uint masks_avail = INCR_MASKS;

            for (int i = 0; i < wls_left; i++)
            {
              if (i != 0)
              {
                mask = myargv[optind + 1 + i];

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
          custom_charset_1 = (char *) "?l?d?u";
          custom_charset_2 = (char *) "?l?d";
          custom_charset_3 = (char *) "?l?d*!$@_";

          mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);

          masks[maskcnt] = mystrdup ("?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d");

          wordlist_mode = WL_MODE_MASK;

          data.wordlist_mode = wordlist_mode;

          increment = 1;

          maskcnt = 1;
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

        wordlist_mode = WL_MODE_MASK;

        data.wordlist_mode = wordlist_mode;

        increment = 1;
      }

      dictfiles = (char **) mycalloc (pw_max, sizeof (char *));

      if (increment)
      {
        if (increment_min > pw_min) pw_min = increment_min;

        if (increment_max < pw_max) pw_max = increment_max;
      }
    }
    else if (attack_mode == ATTACK_MODE_HYBRID1)
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

      int wls_left = myargc - (optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[optind + 1 + i];

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

          if (keyspace == 1)
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

      if (increment)
      {
        maskcnt = 0;

        uint mask_min = increment_min; // we can't reject smaller masks here
        uint mask_max = (increment_max < pw_max) ? increment_max : pw_max;

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
    else if (attack_mode == ATTACK_MODE_HYBRID2)
    {
      data.combs_mode = COMBINATOR_MODE_BASE_RIGHT;

      // display

      char *mask = myargv[optind + 1 + 0];

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

      int wls_left = myargc - (optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[optind + 2 + i];

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

          if (keyspace == 1)
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

      if (increment)
      {
        maskcnt = 0;

        uint mask_min = increment_min; // we can't reject smaller masks here
        uint mask_max = (increment_max < pw_max) ? increment_max : pw_max;

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

    if (weak_hash_threshold >= hashes->salts_cnt)
    {
      hc_device_param_t *device_param = NULL;

      for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped) continue;

        break;
      }

      if (data.quiet == 0) log_info_nn ("Checking for weak hashes...");

      for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        weak_hash_check (opencl_ctx, device_param, hashconfig, hashes, salt_pos);
      }

      // Display hack, guarantee that there is at least one \r before real start

      //if (data.quiet == 0) log_info ("");
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

    if (keyspace == 0 && benchmark == 0 && stdout_flag == 0)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, NULL);

      inner_threads_cnt++;

      if (outfile_check_timer != 0)
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
            outfile_check_timer = 0;
          }
        }
        else
        {
          outfile_check_timer = 0;
        }
      }
    }

    data.outfile_check_timer = outfile_check_timer;

    /**
     * main loop
     */

    if (data.quiet == 0)
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

      if (attack_mode == ATTACK_MODE_HYBRID1 || attack_mode == ATTACK_MODE_HYBRID2 || attack_mode == ATTACK_MODE_BF)
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

                custom_charset_1 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
                break;

              case 1:
                mp_reset_usr (mp_usr, 1);

                custom_charset_2 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
                break;

              case 2:
                mp_reset_usr (mp_usr, 2);

                custom_charset_3 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);
                break;

              case 3:
                mp_reset_usr (mp_usr, 3);

                custom_charset_4 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_4, 3, hashconfig);
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

        if ((attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2))
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

          sp_setup_tbl (shared_dir, markov_hcstat, markov_disable, markov_classic, root_table_buf, markov_table_buf);

          markov_threshold = (markov_threshold != 0) ? markov_threshold : CHARSIZ;

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, markov_threshold, uniq_tbls);

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

            if (attack_mode == ATTACK_MODE_HYBRID1)
            {
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_buf32[5] = full01;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_buf32[5] = full80;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_buf32[6] = 1;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_buf32[7] = 1;
            }
            else if (attack_mode == ATTACK_MODE_HYBRID2)
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
        else if (attack_mode == ATTACK_MODE_BF)
        {
          dictcnt = 0;  // number of "sub-masks", i.e. when using incremental mode

          if (increment)
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

      if (attack_mode != ATTACK_MODE_BF)
      {
        if (keyspace == 0)
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

      if (skip != 0 || limit != 0)
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

      if (keyspace == 1)
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

        if (data.restore == 0)
        {
          rd->words_cur = skip;

          skip = 0;

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

        if (attack_mode == ATTACK_MODE_STRAIGHT)
        {
          if (data.wordlist_mode == WL_MODE_FILE)
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

            for (uint i = 0; i < rp_files_cnt; i++)
            {
              logfile_sub_var_string ("rulefile", rp_files[i]);
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
        else if (attack_mode == ATTACK_MODE_COMBI)
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
        else if ((attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2))
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
        else if (attack_mode == ATTACK_MODE_BF)
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

          sp_setup_tbl (shared_dir, markov_hcstat, markov_disable, markov_classic, root_table_buf, markov_table_buf);

          markov_threshold = (markov_threshold != 0) ? markov_threshold : CHARSIZ;

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, markov_threshold, uniq_tbls);

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

        if (data.attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (data.kernel_rules_cnt)
          {
            words_base /= data.kernel_rules_cnt;
          }
        }
        else if (data.attack_kern == ATTACK_KERN_COMBI)
        {
          if (data.combs_cnt)
          {
            words_base /= data.combs_cnt;
          }
        }
        else if (data.attack_kern == ATTACK_KERN_BF)
        {
          if (data.bfs_cnt)
          {
            words_base /= data.bfs_cnt;
          }
        }

        data.words_base = words_base;

        if (keyspace == 1)
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
          if (data.attack_kern == ATTACK_KERN_STRAIGHT)
          {
            for (uint i = 0; i < hashes->salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.kernel_rules_cnt;
            }
          }
          else if (data.attack_kern == ATTACK_KERN_COMBI)
          {
            for (uint i = 0; i < hashes->salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.combs_cnt;
            }
          }
          else if (data.attack_kern == ATTACK_KERN_BF)
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

        if (keyspace == 0)
        {
          dictstat_write (dictstat_ctx);
        }

        /**
         * Update loopback file
         */

        if (loopback == 1)
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
              if      (session_ctx->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = data.kernel_rules_cnt;
              else if (session_ctx->attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = data.combs_cnt;
              else if (session_ctx->attack_kern == ATTACK_KERN_BF)        innerloop_cnt = data.bfs_cnt;
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

        if ((wordlist_mode == WL_MODE_FILE) || (wordlist_mode == WL_MODE_MASK))
        {
          if (data.words_base < kernel_power_all)
          {
            if (quiet == 0)
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

        if ((wordlist_mode == WL_MODE_FILE) || (wordlist_mode == WL_MODE_MASK))
        {
          if ((quiet == 0) && (status == 0) && (benchmark == 0))
          {
            if (quiet == 0) send_prompt ();
          }
        }
        else if (wordlist_mode == WL_MODE_STDIN)
        {
          if (data.quiet == 0) log_info ("Starting attack in stdin mode...");
          if (data.quiet == 0) log_info ("");
        }

        time_t runtime_start;

        time (&runtime_start);

        data.runtime_start = runtime_start;

        data.prepare_time += runtime_start - prepare_start;

        for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

          if (wordlist_mode == WL_MODE_STDIN)
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

        if (attack_mode != ATTACK_MODE_BF)
        {
          induction_dictionaries = scan_directory (induction_directory);

          induction_dictionaries_cnt = count_dictionaries (induction_dictionaries);
        }

        if (benchmark == 1)
        {
          status_benchmark (opencl_ctx, hashconfig);

          if (machine_readable == 0)
          {
            log_info ("");
          }
        }
        else
        {
          if (quiet == 0)
          {
            clear_prompt ();

            log_info ("");

            status_display (opencl_ctx, hashconfig, hashes);

            log_info ("");
          }
          else
          {
            if (status == 1)
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

        if (loopback == 1)
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
    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (data.wordlist_mode == WL_MODE_FILE)
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
    else if (attack_mode == ATTACK_MODE_HYBRID1 || attack_mode == ATTACK_MODE_HYBRID2)
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
    else if (attack_mode == ATTACK_MODE_BF)
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

    if ((hashes->hashlist_mode == HL_MODE_FILE) && (remove == 1) && (hashes->digests_saved != hashes->digests_done))
    {
      save_hash (opencl_ctx);
    }

    /**
     * Clean up
     */

    // reset default fan speed

    #if defined (HAVE_HWMON)
    if (gpu_temp_disable == 0)
    {
      if (gpu_temp_retain != 0)
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

    if (powertune_enable == 1)
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
          unsigned int limit = nvml_power_limit[device_id];

          if (limit > 0)
          {
            hm_NVML_nvmlDeviceSetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, limit);
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    if (gpu_temp_disable == 0)
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
    #endif // HAVE_HWMON

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

    #if defined (HAVE_HWMON)
    local_free (od_clock_mem_status);
    local_free (od_power_control_status);
    local_free (nvml_power_limit);
    #endif

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

  hc_thread_mutex_delete (mux_dispatcher);
  hc_thread_mutex_delete (mux_counter);
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

  if (induction_dir == NULL)
  {
    if (attack_mode != ATTACK_MODE_BF)
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
  }

  // outfile-check directory

  if (outfile_check_dir == NULL)
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

  if (quiet == 0) log_info_nn ("Started: %s", ctime (&proc_start));
  if (quiet == 0) log_info_nn ("Stopped: %s", ctime (&proc_stop));

  u32 rc_final = -1;

  if (opencl_ctx->devices_status == STATUS_ABORTED)   rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_QUIT)      rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_EXHAUSTED) rc_final = 1;
  if (opencl_ctx->devices_status == STATUS_CRACKED)   rc_final = 0;

  opencl_ctx_destroy (opencl_ctx);

  return rc_final;
}
