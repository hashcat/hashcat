/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TYPES_H
#define _TYPES_H

#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

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

// timer

#if defined (_WIN)
typedef LARGE_INTEGER     hc_timer_t;
#elif defined (_POSIX)
typedef struct timeval    hc_timer_t;
#endif

// thread

#if defined (_POSIX)
#include <pthread.h>
#endif

#if defined (_WIN)
typedef HANDLE            hc_thread_t;
typedef CRITICAL_SECTION  hc_thread_mutex_t;
#elif defined (_POSIX)
typedef pthread_t         hc_thread_t;
typedef pthread_mutex_t   hc_thread_mutex_t;
#endif

// stat

#if defined (_POSIX)
typedef struct stat hc_stat_t;
#endif

#if defined (_WIN)
typedef struct _stat64 hc_stat_t;
#endif

// enums

typedef enum loglevel
{
  LOGLEVEL_INFO    = 0,
  LOGLEVEL_WARNING = 1,
  LOGLEVEL_ERROR   = 2,

} loglevel_t;

typedef enum event_identifier
{
  EVENT_AUTOTUNE_FINISHED         = 0x00000000,
  EVENT_AUTOTUNE_STARTING         = 0x00000001,
  EVENT_BITMAP_INIT_POST          = 0x00000010,
  EVENT_BITMAP_INIT_PRE           = 0x00000011,
  EVENT_CALCULATED_WORDS_BASE     = 0x00000020,
  EVENT_CRACKER_FINISHED          = 0x00000030,
  EVENT_CRACKER_HASH_CRACKED      = 0x00000031,
  EVENT_CRACKER_STARTING          = 0x00000032,
  EVENT_HASHLIST_COUNT_LINES_POST = 0x00000040,
  EVENT_HASHLIST_COUNT_LINES_PRE  = 0x00000041,
  EVENT_HASHLIST_PARSE_HASH       = 0x00000042,
  EVENT_HASHLIST_SORT_HASH_POST   = 0x00000043,
  EVENT_HASHLIST_SORT_HASH_PRE    = 0x00000044,
  EVENT_HASHLIST_SORT_SALT_POST   = 0x00000045,
  EVENT_HASHLIST_SORT_SALT_PRE    = 0x00000046,
  EVENT_HASHLIST_UNIQUE_HASH_POST = 0x00000047,
  EVENT_HASHLIST_UNIQUE_HASH_PRE  = 0x00000048,
  EVENT_INNERLOOP1_FINISHED       = 0x00000050,
  EVENT_INNERLOOP1_STARTING       = 0x00000051,
  EVENT_INNERLOOP2_FINISHED       = 0x00000060,
  EVENT_INNERLOOP2_STARTING       = 0x00000061,
  EVENT_LOG_ERROR                 = 0x00000070,
  EVENT_LOG_INFO                  = 0x00000071,
  EVENT_LOG_WARNING               = 0x00000072,
  EVENT_MONITOR_RUNTIME_LIMIT     = 0x00000080,
  EVENT_MONITOR_STATUS_REFRESH    = 0x00000081,
  EVENT_MONITOR_TEMP_ABORT        = 0x00000082,
  EVENT_MONITOR_THROTTLE1         = 0x00000083,
  EVENT_MONITOR_THROTTLE2         = 0x00000084,
  EVENT_MONITOR_THROTTLE3         = 0x00000085,
  EVENT_MONITOR_PERFORMANCE_HINT  = 0x00000086,
  EVENT_OPENCL_SESSION_POST       = 0x00000090,
  EVENT_OPENCL_SESSION_PRE        = 0x00000091,
  EVENT_OUTERLOOP_FINISHED        = 0x000000a0,
  EVENT_OUTERLOOP_MAINSCREEN      = 0x000000a1,
  EVENT_OUTERLOOP_STARTING        = 0x000000a2,
  EVENT_POTFILE_ALL_CRACKED       = 0x000000b0,
  EVENT_POTFILE_HASH_LEFT         = 0x000000b1,
  EVENT_POTFILE_HASH_SHOW         = 0x000000b2,
  EVENT_POTFILE_NUM_CRACKED       = 0x000000b3,
  EVENT_POTFILE_REMOVE_PARSE_POST = 0x000000b4,
  EVENT_POTFILE_REMOVE_PARSE_PRE  = 0x000000b5,
  EVENT_SET_KERNEL_POWER_FINAL    = 0x000000c0,
  EVENT_WEAK_HASH_POST            = 0x000000d0,
  EVENT_WEAK_HASH_PRE             = 0x000000d1,
  EVENT_WORDLIST_CACHE_GENERATE   = 0x000000e0,
  EVENT_WORDLIST_CACHE_HIT        = 0x000000e1,

  // there will be much more event types soon

} event_identifier_t;

typedef enum amplifier_count
{
  KERNEL_BFS              = 1024,
  KERNEL_COMBS            = 1024,
  KERNEL_RULES            = 1024,
  KERNEL_THREADS_MAX      = 256,
  KERNEL_THREADS_MAX_CPU  = 1

} amplifier_count_t;

typedef enum vendor_id
{
  VENDOR_ID_AMD           = (1 << 0),
  VENDOR_ID_APPLE         = (1 << 1),
  VENDOR_ID_INTEL_BEIGNET = (1 << 2),
  VENDOR_ID_INTEL_SDK     = (1 << 3),
  VENDOR_ID_MESA          = (1 << 4),
  VENDOR_ID_NV            = (1 << 5),
  VENDOR_ID_POCL          = (1 << 6),
  VENDOR_ID_AMD_USE_INTEL = (1 << 7),
  VENDOR_ID_GENERIC       = (1 << 31)

} vendor_id_t;

typedef enum status_rc
{
  STATUS_INIT            = 0,
  STATUS_AUTOTUNE        = 1,
  STATUS_RUNNING         = 2,
  STATUS_PAUSED          = 3,
  STATUS_EXHAUSTED       = 4,
  STATUS_CRACKED         = 5,
  STATUS_ABORTED         = 6,
  STATUS_QUIT            = 7,
  STATUS_BYPASS          = 8,

} status_rc_t;

typedef enum wl_mode
{
  WL_MODE_NONE  = 0,
  WL_MODE_STDIN = 1,
  WL_MODE_FILE  = 2,
  WL_MODE_MASK  = 3

} wl_mode_t;

typedef enum hl_mode
{
  HL_MODE_FILE  = 4,
  HL_MODE_ARG   = 5

} hl_mode_t;

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

typedef enum rule_functions
{
  RULE_OP_MANGLE_NOOP            = ':',
  RULE_OP_MANGLE_LREST           = 'l',
  RULE_OP_MANGLE_UREST           = 'u',
  RULE_OP_MANGLE_LREST_UFIRST    = 'c',
  RULE_OP_MANGLE_UREST_LFIRST    = 'C',
  RULE_OP_MANGLE_TREST           = 't',
  RULE_OP_MANGLE_TOGGLE_AT       = 'T',
  RULE_OP_MANGLE_REVERSE         = 'r',
  RULE_OP_MANGLE_DUPEWORD        = 'd',
  RULE_OP_MANGLE_DUPEWORD_TIMES  = 'p',
  RULE_OP_MANGLE_REFLECT         = 'f',
  RULE_OP_MANGLE_ROTATE_LEFT     = '{',
  RULE_OP_MANGLE_ROTATE_RIGHT    = '}',
  RULE_OP_MANGLE_APPEND          = '$',
  RULE_OP_MANGLE_PREPEND         = '^',
  RULE_OP_MANGLE_DELETE_FIRST    = '[',
  RULE_OP_MANGLE_DELETE_LAST     = ']',
  RULE_OP_MANGLE_DELETE_AT       = 'D',
  RULE_OP_MANGLE_EXTRACT         = 'x',
  RULE_OP_MANGLE_OMIT            = 'O',
  RULE_OP_MANGLE_INSERT          = 'i',
  RULE_OP_MANGLE_OVERSTRIKE      = 'o',
  RULE_OP_MANGLE_TRUNCATE_AT     = '\'',
  RULE_OP_MANGLE_REPLACE         = 's',
  RULE_OP_MANGLE_PURGECHAR       = '@',
  RULE_OP_MANGLE_TOGGLECASE_REC  = 'a',
  RULE_OP_MANGLE_DUPECHAR_FIRST  = 'z',
  RULE_OP_MANGLE_DUPECHAR_LAST   = 'Z',
  RULE_OP_MANGLE_DUPECHAR_ALL    = 'q',
  RULE_OP_MANGLE_EXTRACT_MEMORY  = 'X',
  RULE_OP_MANGLE_APPEND_MEMORY   = '4',
  RULE_OP_MANGLE_PREPEND_MEMORY  = '6',

  RULE_OP_MEMORIZE_WORD          = 'M',

  RULE_OP_REJECT_LESS            = '<',
  RULE_OP_REJECT_GREATER         = '>',
  RULE_OP_REJECT_CONTAIN         = '!',
  RULE_OP_REJECT_NOT_CONTAIN     = '/',
  RULE_OP_REJECT_EQUAL_FIRST     = '(',
  RULE_OP_REJECT_EQUAL_LAST      = ')',
  RULE_OP_REJECT_EQUAL_AT        = '=',
  RULE_OP_REJECT_CONTAINS        = '%',
  RULE_OP_REJECT_MEMORY          = 'Q',

  RULE_OP_MANGLE_SWITCH_FIRST    = 'k',
  RULE_OP_MANGLE_SWITCH_LAST     = 'K',
  RULE_OP_MANGLE_SWITCH_AT       = '*',
  RULE_OP_MANGLE_CHR_SHIFTL      = 'L',
  RULE_OP_MANGLE_CHR_SHIFTR      = 'R',
  RULE_OP_MANGLE_CHR_INCR        = '+',
  RULE_OP_MANGLE_CHR_DECR        = '-',
  RULE_OP_MANGLE_REPLACE_NP1     = '.',
  RULE_OP_MANGLE_REPLACE_NM1     = ',',
  RULE_OP_MANGLE_DUPEBLOCK_FIRST = 'y',
  RULE_OP_MANGLE_DUPEBLOCK_LAST  = 'Y',
  RULE_OP_MANGLE_TITLE           = 'E',

} rule_functions_t;

typedef enum salt_type
{
  SALT_TYPE_NONE     = 1,
  SALT_TYPE_EMBEDDED = 2,
  SALT_TYPE_INTERN   = 3,
  SALT_TYPE_EXTERN   = 4,
  SALT_TYPE_VIRTUAL  = 5

} salt_type_t;

typedef enum opti_type
{
  OPTI_TYPE_ZERO_BYTE         = (1 <<  1),
  OPTI_TYPE_PRECOMPUTE_INIT   = (1 <<  2),
  OPTI_TYPE_PRECOMPUTE_MERKLE = (1 <<  3),
  OPTI_TYPE_PRECOMPUTE_PERMUT = (1 <<  4),
  OPTI_TYPE_MEET_IN_MIDDLE    = (1 <<  5),
  OPTI_TYPE_EARLY_SKIP        = (1 <<  6),
  OPTI_TYPE_NOT_SALTED        = (1 <<  7),
  OPTI_TYPE_NOT_ITERATED      = (1 <<  8),
  OPTI_TYPE_PREPENDED_SALT    = (1 <<  9),
  OPTI_TYPE_APPENDED_SALT     = (1 << 10),
  OPTI_TYPE_SINGLE_HASH       = (1 << 11),
  OPTI_TYPE_SINGLE_SALT       = (1 << 12),
  OPTI_TYPE_BRUTE_FORCE       = (1 << 13),
  OPTI_TYPE_RAW_HASH          = (1 << 14),
  OPTI_TYPE_SLOW_HASH_SIMD    = (1 << 15),
  OPTI_TYPE_USES_BITS_8       = (1 << 16),
  OPTI_TYPE_USES_BITS_16      = (1 << 17),
  OPTI_TYPE_USES_BITS_32      = (1 << 18),
  OPTI_TYPE_USES_BITS_64      = (1 << 19)

} opti_type_t;

typedef enum opts_type
{
  OPTS_TYPE_PT_UNICODE        = (1 <<  0),
  OPTS_TYPE_PT_UPPER          = (1 <<  1),
  OPTS_TYPE_PT_LOWER          = (1 <<  2),
  OPTS_TYPE_PT_ADD01          = (1 <<  3),
  OPTS_TYPE_PT_ADD02          = (1 <<  4),
  OPTS_TYPE_PT_ADD80          = (1 <<  5),
  OPTS_TYPE_PT_ADDBITS14      = (1 <<  6),
  OPTS_TYPE_PT_ADDBITS15      = (1 <<  7),
  OPTS_TYPE_PT_GENERATE_LE    = (1 <<  8),
  OPTS_TYPE_PT_GENERATE_BE    = (1 <<  9),
  OPTS_TYPE_PT_NEVERCRACK     = (1 << 10), // if we want all possible results
  OPTS_TYPE_PT_BITSLICE       = (1 << 11),
  OPTS_TYPE_PT_ALWAYS_ASCII   = (1 << 12),
  OPTS_TYPE_ST_UNICODE        = (1 << 13),
  OPTS_TYPE_ST_UPPER          = (1 << 14),
  OPTS_TYPE_ST_LOWER          = (1 << 15),
  OPTS_TYPE_ST_ADD01          = (1 << 16),
  OPTS_TYPE_ST_ADD02          = (1 << 17),
  OPTS_TYPE_ST_ADD80          = (1 << 18),
  OPTS_TYPE_ST_ADDBITS14      = (1 << 19),
  OPTS_TYPE_ST_ADDBITS15      = (1 << 20),
  OPTS_TYPE_ST_GENERATE_LE    = (1 << 21),
  OPTS_TYPE_ST_GENERATE_BE    = (1 << 22),
  OPTS_TYPE_ST_HEX            = (1 << 23),
  OPTS_TYPE_ST_BASE64         = (1 << 24),
  OPTS_TYPE_HASH_COPY         = (1 << 25),
  OPTS_TYPE_HOOK12            = (1 << 26),
  OPTS_TYPE_HOOK23            = (1 << 27),
  OPTS_TYPE_BINARY_HASHFILE   = (1 << 28),

} opts_type_t;

typedef enum dgst_size
{
  DGST_SIZE_4_2  = (2  * sizeof (u32)), // 8
  DGST_SIZE_4_4  = (4  * sizeof (u32)), // 16
  DGST_SIZE_4_5  = (5  * sizeof (u32)), // 20
  DGST_SIZE_4_6  = (6  * sizeof (u32)), // 24
  DGST_SIZE_4_8  = (8  * sizeof (u32)), // 32
  DGST_SIZE_4_16 = (16 * sizeof (u32)), // 64 !!!
  DGST_SIZE_4_32 = (32 * sizeof (u32)), // 128 !!!
  DGST_SIZE_4_64 = (64 * sizeof (u32)), // 256
  DGST_SIZE_8_8  = (8  * sizeof (u64)), // 64 !!!
  DGST_SIZE_8_16 = (16 * sizeof (u64)), // 128 !!!
  DGST_SIZE_8_25 = (25 * sizeof (u64))  // 200

} dgst_size_t;

typedef enum attack_exec
{
  ATTACK_EXEC_OUTSIDE_KERNEL = 10,
  ATTACK_EXEC_INSIDE_KERNEL  = 11

} attack_exec_t;

typedef enum hlfmt_name
{
  HLFMT_HASHCAT  = 0,
  HLFMT_PWDUMP   = 1,
  HLFMT_PASSWD   = 2,
  HLFMT_SHADOW   = 3,
  HLFMT_DCC      = 4,
  HLFMT_DCC2     = 5,
  HLFMT_NETNTLM1 = 7,
  HLFMT_NETNTLM2 = 8,
  HLFMT_NSLDAP   = 9,
  HLFMT_NSLDAPS  = 10

} hlfmt_name_t;

typedef enum outfile_fmt
{
  OUTFILE_FMT_HASH      = (1 << 0),
  OUTFILE_FMT_PLAIN     = (1 << 1),
  OUTFILE_FMT_HEXPLAIN  = (1 << 2),
  OUTFILE_FMT_CRACKPOS  = (1 << 3)

} outfile_fmt_t;

typedef enum parser_rc
{
  PARSER_OK                  = 0,
  PARSER_COMMENT             = -1,
  PARSER_GLOBAL_ZERO         = -2,
  PARSER_GLOBAL_LENGTH       = -3,
  PARSER_HASH_LENGTH         = -4,
  PARSER_HASH_VALUE          = -5,
  PARSER_SALT_LENGTH         = -6,
  PARSER_SALT_VALUE          = -7,
  PARSER_SALT_ITERATION      = -8,
  PARSER_SEPARATOR_UNMATCHED = -9,
  PARSER_SIGNATURE_UNMATCHED = -10,
  PARSER_HCCAP_FILE_SIZE     = -11,
  PARSER_HCCAP_EAPOL_SIZE    = -12,
  PARSER_PSAFE2_FILE_SIZE    = -13,
  PARSER_PSAFE3_FILE_SIZE    = -14,
  PARSER_TC_FILE_SIZE        = -15,
  PARSER_VC_FILE_SIZE        = -16,
  PARSER_SIP_AUTH_DIRECTIVE  = -17,
  PARSER_HASH_FILE           = -18,
  PARSER_UNKNOWN_ERROR       = -255

} parser_rc_t;

typedef enum input_mode
{
  INPUT_MODE_NONE                       = 0,
  INPUT_MODE_STRAIGHT_FILE              = 1,
  INPUT_MODE_STRAIGHT_FILE_RULES_FILE   = 2,
  INPUT_MODE_STRAIGHT_FILE_RULES_GEN    = 3,
  INPUT_MODE_STRAIGHT_STDIN             = 4,
  INPUT_MODE_STRAIGHT_STDIN_RULES_FILE  = 5,
  INPUT_MODE_STRAIGHT_STDIN_RULES_GEN   = 6,
  INPUT_MODE_COMBINATOR_BASE_LEFT       = 7,
  INPUT_MODE_COMBINATOR_BASE_RIGHT      = 8,
  INPUT_MODE_MASK                       = 9,
  INPUT_MODE_MASK_CS                    = 10,
  INPUT_MODE_HYBRID1                    = 11,
  INPUT_MODE_HYBRID1_CS                 = 12,
  INPUT_MODE_HYBRID2                    = 13,
  INPUT_MODE_HYBRID2_CS                 = 14,

} input_mode_t;

typedef enum progress_mode
{
  PROGRESS_MODE_NONE              = 0,
  PROGRESS_MODE_KEYSPACE_KNOWN    = 1,
  PROGRESS_MODE_KEYSPACE_UNKNOWN  = 2,

} progress_mode_t;

typedef enum user_options_defaults
{
  ATTACK_MODE             = ATTACK_MODE_STRAIGHT,
  BENCHMARK               = false,
  BITMAP_MAX              = 24,
  BITMAP_MIN              = 16,
  DEBUG_MODE              = 0,
  FORCE                   = false,
  GPU_TEMP_ABORT          = 90,
  GPU_TEMP_DISABLE        = false,
  GPU_TEMP_RETAIN         = 75,
  HASH_MODE               = 0,
  HEX_CHARSET             = false,
  HEX_SALT                = false,
  HEX_WORDLIST            = false,
  INCREMENT               = false,
  INCREMENT_MAX           = PW_MAX,
  INCREMENT_MIN           = 1,
  KEEP_GUESSING           = false,
  KERNEL_ACCEL            = 0,
  KERNEL_LOOPS            = 0,
  KEYSPACE                = false,
  LEFT                    = false,
  LIMIT                   = 0,
  LOGFILE_DISABLE         = false,
  LOOPBACK                = false,
  MACHINE_READABLE        = false,
  MARKOV_CLASSIC          = false,
  MARKOV_DISABLE          = false,
  MARKOV_THRESHOLD        = 0,
  NVIDIA_SPIN_DAMP        = 100,
  OPENCL_VECTOR_WIDTH     = 0,
  OUTFILE_AUTOHEX         = true,
  OUTFILE_CHECK_TIMER     = 5,
  OUTFILE_FORMAT          = 3,
  POTFILE_DISABLE         = false,
  POWERTUNE_ENABLE        = false,
  QUIET                   = false,
  REMOVE                  = false,
  REMOVE_TIMER            = 60,
  RESTORE                 = false,
  RESTORE_DISABLE         = false,
  RESTORE_TIMER           = 60,
  RP_GEN                  = 0,
  RP_GEN_FUNC_MAX         = 4,
  RP_GEN_FUNC_MIN         = 1,
  RP_GEN_SEED             = 0,
  RUNTIME                 = 0,
  SCRYPT_TMTO             = 0,
  SEGMENT_SIZE            = 33554432,
  SEPARATOR               = ':',
  SHOW                    = false,
  SKIP                    = 0,
  STATUS                  = false,
  STATUS_TIMER            = 10,
  STDOUT_FLAG             = false,
  SPEED_ONLY              = false,
  USAGE                   = false,
  USERNAME                = false,
  VERSION                 = false,
  WEAK_HASH_THRESHOLD     = 100,
  WORKLOAD_PROFILE        = 2,

} user_options_defaults_t;

typedef enum user_options_map
{
  IDX_ATTACK_MODE              = 'a',
  IDX_BENCHMARK                = 'b',
  IDX_BITMAP_MAX               = 0xff00,
  IDX_BITMAP_MIN               = 0xff01,
  IDX_CPU_AFFINITY             = 0xff02,
  IDX_CUSTOM_CHARSET_1         = '1',
  IDX_CUSTOM_CHARSET_2         = '2',
  IDX_CUSTOM_CHARSET_3         = '3',
  IDX_CUSTOM_CHARSET_4         = '4',
  IDX_DEBUG_FILE               = 0xff03,
  IDX_DEBUG_MODE               = 0xff04,
  IDX_FORCE                    = 0xff05,
  IDX_GPU_TEMP_ABORT           = 0xff06,
  IDX_GPU_TEMP_DISABLE         = 0xff07,
  IDX_GPU_TEMP_RETAIN          = 0xff08,
  IDX_HASH_MODE                = 'm',
  IDX_HELP                     = 'h',
  IDX_HEX_CHARSET              = 0xff09,
  IDX_HEX_SALT                 = 0xff0a,
  IDX_HEX_WORDLIST             = 0xff0b,
  IDX_INCREMENT                = 'i',
  IDX_INCREMENT_MAX            = 0xff0c,
  IDX_INCREMENT_MIN            = 0xff0d,
  IDX_INDUCTION_DIR            = 0xff0e,
  IDX_KEEP_GUESSING            = 0xff0f,
  IDX_KERNEL_ACCEL             = 'n',
  IDX_KERNEL_LOOPS             = 'u',
  IDX_KEYSPACE                 = 0xff10,
  IDX_LEFT                     = 0xff11,
  IDX_LIMIT                    = 'l',
  IDX_LOGFILE_DISABLE          = 0xff12,
  IDX_LOOPBACK                 = 0xff13,
  IDX_MACHINE_READABLE         = 0xff14,
  IDX_MARKOV_CLASSIC           = 0xff15,
  IDX_MARKOV_DISABLE           = 0xff16,
  IDX_MARKOV_HCSTAT            = 0xff17,
  IDX_MARKOV_THRESHOLD         = 't',
  IDX_NVIDIA_SPIN_DAMP         = 0xff18,
  IDX_OPENCL_DEVICES           = 'd',
  IDX_OPENCL_DEVICE_TYPES      = 'D',
  IDX_OPENCL_INFO              = 'I',
  IDX_OPENCL_PLATFORMS         = 0xff19,
  IDX_OPENCL_VECTOR_WIDTH      = 0xff1a,
  IDX_OUTFILE_AUTOHEX_DISABLE  = 0xff1b,
  IDX_OUTFILE_CHECK_DIR        = 0xff1c,
  IDX_OUTFILE_CHECK_TIMER      = 0xff1d,
  IDX_OUTFILE_FORMAT           = 0xff1e,
  IDX_OUTFILE                  = 'o',
  IDX_POTFILE_DISABLE          = 0xff1f,
  IDX_POTFILE_PATH             = 0xff20,
  IDX_POWERTUNE_ENABLE         = 0xff21,
  IDX_QUIET                    = 0xff22,
  IDX_REMOVE                   = 0xff23,
  IDX_REMOVE_TIMER             = 0xff24,
  IDX_RESTORE                  = 0xff25,
  IDX_RESTORE_DISABLE          = 0xff26,
  IDX_RESTORE_FILE_PATH        = 0xff27,
  IDX_RP_FILE                  = 'r',
  IDX_RP_GEN_FUNC_MAX          = 0xff28,
  IDX_RP_GEN_FUNC_MIN          = 0xff29,
  IDX_RP_GEN                   = 'g',
  IDX_RP_GEN_SEED              = 0xff2a,
  IDX_RULE_BUF_L               = 'j',
  IDX_RULE_BUF_R               = 'k',
  IDX_RUNTIME                  = 0xff2b,
  IDX_SCRYPT_TMTO              = 0xff2c,
  IDX_SEGMENT_SIZE             = 'c',
  IDX_SEPARATOR                = 'p',
  IDX_SESSION                  = 0xff2d,
  IDX_SHOW                     = 0xff2e,
  IDX_SKIP                     = 's',
  IDX_STATUS                   = 0xff2f,
  IDX_STATUS_TIMER             = 0xff30,
  IDX_STDOUT_FLAG              = 0xff31,
  IDX_SPEED_ONLY               = 0xff32,
  IDX_TRUECRYPT_KEYFILES       = 0xff33,
  IDX_USERNAME                 = 0xff34,
  IDX_VERACRYPT_KEYFILES       = 0xff35,
  IDX_VERACRYPT_PIM            = 0xff36,
  IDX_VERSION_LOWER            = 'v',
  IDX_VERSION                  = 'V',
  IDX_WEAK_HASH_THRESHOLD      = 0xff37,
  IDX_WORKLOAD_PROFILE         = 'w'

} user_options_map_t;

/**
 * structs
 */

typedef struct salt
{
  u32  salt_buf[16];
  u32  salt_buf_pc[8];

  u32  salt_len;
  u32  salt_iter;
  u32  salt_sign[2];

  u32  keccak_mdlen;

  u32  digests_cnt;
  u32  digests_done;

  u32  digests_offset;

  u32  scrypt_N;
  u32  scrypt_r;
  u32  scrypt_p;

} salt_t;

typedef struct user
{
  char *user_name;
  u32   user_len;

} user_t;

typedef struct hashinfo
{
  user_t *user;
  char   *orighash;

} hashinfo_t;

typedef struct hash
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  int         cracked;
  hashinfo_t *hash_info;
  char       *pw_buf;
  int         pw_len;

} hash_t;

typedef struct outfile_data
{
  char   *file_name;
  off_t   seek;
  time_t ctime;

} outfile_data_t;

typedef struct logfile_ctx
{
  bool  enabled;

  char *logfile;
  char *topid;
  char *subid;

} logfile_ctx_t;

typedef struct hashes
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

  u32     hashes_cnt_orig;
  u32     hashes_cnt;
  hash_t *hashes_buf;

  hashinfo_t  **hash_info;

  u8      *out_buf; // allocates [HCBUFSIZ_LARGE];
  u8      *tmp_buf; // allocates [HCBUFSIZ_LARGE];

} hashes_t;

struct hashconfig
{
  char  separator;

  u32   hash_mode;
  u32   hash_type;
  u32   salt_type;
  u32   attack_exec;
  u32   opts_type;
  u32   kern_type;
  u32   dgst_size;
  u32   opti_type;
  u32   dgst_pos0;
  u32   dgst_pos1;
  u32   dgst_pos2;
  u32   dgst_pos3;

  u32   is_salted;
  u32   esalt_size;
  u32   tmp_size;
  u32   hook_size;

  u32   pw_min;
  u32   pw_max;

  int (*parse_func) (u8 *, u32, hash_t *, const struct hashconfig *);
};

typedef struct hashconfig hashconfig_t;

typedef struct pw
{
  u32 i[16];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct bf
{
  u32  i;

} bf_t;

typedef struct bs_word
{
  u32  b[32];

} bs_word_t;

typedef struct comb
{
  u32  i[8];

  u32  pw_len;

} comb_t;

typedef struct cpt
{
  u32    cracked;
  time_t timestamp;

} cpt_t;

typedef struct plain
{
  u32  salt_pos;
  u32  digest_pos;
  u32  hash_pos;
  u32  gidvid;
  u32  il_pos;

} plain_t;

typedef struct wordl
{
  u32  word_buf[16];

} wordl_t;

typedef struct wordr
{
  u32  word_buf[1];

} wordr_t;

#include "ext_OpenCL.h"

typedef struct hc_device_param
{
  cl_device_id    device;
  cl_device_type  device_type;

  u32     device_id;
  u32     platform_devices_id;   // for mapping with hms devices

  bool    skipped;
  bool    skipped_temp;

  u32     sm_major;
  u32     sm_minor;

  u8      pcie_bus;
  u8      pcie_device;
  u8      pcie_function;

  u32     device_processors;
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;

  u32     vector_width;

  u32     kernel_threads_by_user;

  u32     kernel_threads_by_wgs_kernel1;
  u32     kernel_threads_by_wgs_kernel12;
  u32     kernel_threads_by_wgs_kernel2;
  u32     kernel_threads_by_wgs_kernel23;
  u32     kernel_threads_by_wgs_kernel3;
  u32     kernel_threads_by_wgs_kernel_mp;
  u32     kernel_threads_by_wgs_kernel_mp_l;
  u32     kernel_threads_by_wgs_kernel_mp_r;
  u32     kernel_threads_by_wgs_kernel_amp;
  u32     kernel_threads_by_wgs_kernel_tm;
  u32     kernel_threads_by_wgs_kernel_memset;

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
  double  exec_msec[EXEC_CACHE];

  // workaround cpu spinning

  double  exec_us_prev1[EXPECTED_ITERATIONS];
  double  exec_us_prev2[EXPECTED_ITERATIONS];
  double  exec_us_prev3[EXPECTED_ITERATIONS];

  // this is "current" speed

  u32     speed_pos;
  u64     speed_cnt[SPEED_CACHE];
  double  speed_msec[SPEED_CACHE];

  hc_timer_t timer_speed;

  // device specific attributes starting

  char   *device_name;
  char   *device_vendor;
  char   *device_name_chksum;
  char   *device_version;
  char   *driver_version;
  char   *device_opencl_version;

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

} hc_device_param_t;

typedef struct opencl_ctx
{
  bool                enabled;

  void               *ocl;

  cl_uint             platforms_cnt;
  cl_platform_id     *platforms;
  char              **platforms_vendor;
  char              **platforms_name;
  char              **platforms_version;
  bool               *platforms_skipped;

  cl_uint             platform_devices_cnt;
  cl_device_id       *platform_devices;

  u32                 devices_cnt;
  u32                 devices_active;

  hc_device_param_t  *devices_param;

  u32                 hardware_power_all;

  u32                 kernel_power_all;
  u64                 kernel_power_final; // we save that so that all divisions are done from the same base

  u32                 opencl_platforms_filter;
  u32                 devices_filter;
  cl_device_type      device_types_filter;

  double              target_msec;

  bool                need_adl;
  bool                need_nvml;
  bool                need_nvapi;
  bool                need_xnvctrl;
  bool                need_sysfs;

  int                 force_jit_compilation;

} opencl_ctx_t;

#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "ext_sysfs.h"

typedef struct hm_attrs
{
  HM_ADAPTER_ADL     adl;
  HM_ADAPTER_NVML    nvml;
  HM_ADAPTER_NVAPI   nvapi;
  HM_ADAPTER_XNVCTRL xnvctrl;
  HM_ADAPTER_SYSFS   sysfs;

  int od_version;

  bool buslanes_get_supported;
  bool corespeed_get_supported;
  bool fanspeed_get_supported;
  bool fanspeed_set_supported;
  bool fanpolicy_get_supported;
  bool fanpolicy_set_supported;
  bool memoryspeed_get_supported;
  bool temperature_get_supported;
  bool threshold_shutdown_get_supported;
  bool threshold_slowdown_get_supported;
  bool throttle_get_supported;
  bool utilization_get_supported;

} hm_attrs_t;

typedef struct hwmon_ctx
{
  bool  enabled;

  void *hm_adl;
  void *hm_nvml;
  void *hm_nvapi;
  void *hm_xnvctrl;
  void *hm_sysfs;

  hm_attrs_t *hm_device;

  ADLOD6MemClockState *od_clock_mem_status;
  int                 *od_power_control_status;
  unsigned int        *nvml_power_limit;

} hwmon_ctx_t;

#if defined (__APPLE__)
typedef struct cpu_set
{
  u32 count;

} cpu_set_t;
#endif

/* AES context.  */
typedef struct aes_context
{
  int bits;

  u32 rek[60];
  u32 rdk[60];

} aes_context_t;

typedef aes_context_t aes_ctx;

typedef struct debugfile_ctx
{
  bool enabled;

  FILE *fp;
  char *filename;
  u32   mode;

} debugfile_ctx_t;

typedef struct dictstat
{
  u64 cnt;

  hc_stat_t stat;

} dictstat_t;

typedef struct dictstat_ctx
{
  bool enabled;

  char *filename;

  dictstat_t *base;

  #if defined (_POSIX)
  size_t cnt;
  #else
  u32    cnt;
  #endif

} dictstat_ctx_t;

typedef struct loopback_ctx
{
  bool enabled;
  bool unused;

  FILE *fp;
  char *filename;

} loopback_ctx_t;

typedef struct cs
{
  u32  cs_buf[0x100];
  u32  cs_len;

} cs_t;

typedef struct mf
{
  char mf_buf[0x100];
  int  mf_len;

} mf_t;

typedef struct hcstat_table
{
  u32  key;
  u64  val;

} hcstat_table_t;

typedef struct outfile_ctx
{
  char *filename;

  FILE *fp;

  u32   outfile_format;
  bool  outfile_autohex;

} outfile_ctx_t;

typedef struct pot
{
  char     plain_buf[HCBUFSIZ_TINY];
  int      plain_len;

  hash_t   hash;

} pot_t;

typedef struct potfile_ctx
{
  bool     enabled;

  FILE    *fp;
  char    *filename;

  u8      *out_buf; // allocates [HCBUFSIZ_LARGE];
  u8      *tmp_buf; // allocates [HCBUFSIZ_LARGE];

} potfile_ctx_t;

typedef struct restore_data
{
  int  version;
  char cwd[256];
  u32  pid;

  u32  dicts_pos;
  u32  masks_pos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

typedef struct restore_ctx
{
  bool    enabled;

  int     argc;
  char  **argv;

  char   *eff_restore_file;
  char   *new_restore_file;

  restore_data_t *rd;

} restore_ctx_t;

typedef struct kernel_rule
{
  u32  cmds[32];

} kernel_rule_t;

typedef struct out
{
  FILE *fp;

  char  buf[BUFSIZ];
  int   len;

} out_t;

typedef struct tuning_db_alias
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct tuning_db_entry
{
  char *device_name;
  int   attack_mode;
  int   hash_type;
  int   workload_profile;
  int   vector_width;
  int   kernel_accel;
  int   kernel_loops;

} tuning_db_entry_t;

typedef struct tuning_db
{
  bool enabled;

  tuning_db_alias_t *alias_buf;
  int                alias_cnt;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;

} tuning_db_t;

typedef struct wl_data
{
  bool enabled;

  char *buf;
  u64  incr;
  u64  avail;
  u64  cnt;
  u64  pos;

  void (*func) (char *, u64, u64 *, u64 *);

} wl_data_t;

typedef struct user_options
{
  char  *hc_bin;

  int    hc_argc;
  char **hc_argv;

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

  bool   benchmark;
  bool   force;
  bool   gpu_temp_disable;
  bool   hex_charset;
  bool   hex_salt;
  bool   hex_wordlist;
  bool   increment;
  bool   keep_guessing;
  bool   keyspace;
  bool   left;
  bool   logfile_disable;
  bool   loopback;
  bool   machine_readable;
  bool   markov_classic;
  bool   markov_disable;
  bool   opencl_info;
  bool   outfile_autohex;
  bool   potfile_disable;
  bool   powertune_enable;
  bool   quiet;
  bool   remove;
  bool   restore;
  bool   restore_disable;
  bool   show;
  bool   status;
  bool   stdout_flag;
  bool   speed_only;
  bool   usage;
  bool   username;
  bool   version;
  char  *cpu_affinity;
  char  *custom_charset_1;
  char  *custom_charset_2;
  char  *custom_charset_3;
  char  *custom_charset_4;
  char  *debug_file;
  char  *induction_dir;
  char  *markov_hcstat;
  char  *opencl_devices;
  char  *opencl_device_types;
  char  *opencl_platforms;
  char  *outfile;
  char  *outfile_check_dir;
  char  *potfile_path;
  char  *restore_file_path;
  char **rp_files;
  char  *rule_buf_l;
  char  *rule_buf_r;
  char   separator;
  char  *session;
  char  *truecrypt_keyfiles;
  char  *veracrypt_keyfiles;
  u32    attack_mode;
  u32    bitmap_max;
  u32    bitmap_min;
  u32    debug_mode;
  u32    gpu_temp_abort;
  u32    gpu_temp_retain;
  u32    hash_mode;
  u32    increment_max;
  u32    increment_min;
  u32    kernel_accel;
  u32    kernel_loops;
  u32    markov_threshold;
  u32    nvidia_spin_damp;
  u32    opencl_vector_width;
  u32    outfile_check_timer;
  u32    outfile_format;
  u32    remove_timer;
  u32    restore_timer;
  u32    rp_files_cnt;
  u32    rp_gen;
  u32    rp_gen_func_max;
  u32    rp_gen_func_min;
  u32    rp_gen_seed;
  u32    runtime;
  u32    scrypt_tmto;
  u32    segment_size;
  u32    status_timer;
  u32    veracrypt_pim;
  u32    weak_hash_threshold;
  u32    workload_profile;
  u64    limit;
  u64    skip;

} user_options_t;

typedef struct user_options_extra
{
  u32 attack_kern;

  u32 rule_len_r;
  u32 rule_len_l;

  u32 wordlist_mode;

  char  *hc_hash;   // can be filename or string

  int    hc_workc;  // can be 0 in bf-mode = default mask
  char **hc_workv;

} user_options_extra_t;

typedef struct bitmap_ctx
{
  bool enabled;

  u32   bitmap_bits;
  u32   bitmap_nums;
  u32   bitmap_size;
  u32   bitmap_mask;
  u32   bitmap_shift1;
  u32   bitmap_shift2;

  u32  *bitmap_s1_a;
  u32  *bitmap_s1_b;
  u32  *bitmap_s1_c;
  u32  *bitmap_s1_d;
  u32  *bitmap_s2_a;
  u32  *bitmap_s2_b;
  u32  *bitmap_s2_c;
  u32  *bitmap_s2_d;

} bitmap_ctx_t;

typedef struct folder_config
{
  char *cwd;
  char *install_dir;
  char *profile_dir;
  char *session_dir;
  char *shared_dir;
  char *cpath_real;

} folder_config_t;

typedef struct induct_ctx
{
  bool enabled;

  char *root_directory;

  char **induction_dictionaries;
  int    induction_dictionaries_cnt;
  int    induction_dictionaries_pos;

} induct_ctx_t;

typedef struct outcheck_ctx
{
  bool enabled;

  char *root_directory;

} outcheck_ctx_t;

typedef struct straight_ctx
{
  bool enabled;

  u32             kernel_rules_cnt;
  kernel_rule_t  *kernel_rules_buf;

  char **dicts;
  u32    dicts_pos;
  u32    dicts_cnt;
  u32    dicts_avail;

  char *dict;

} straight_ctx_t;

typedef struct combinator_ctx
{
  bool enabled;

  char *scratch_buf;

  char *dict1;
  char *dict2;

  u32 combs_mode;
  u32 combs_cnt;

} combinator_ctx_t;

typedef struct mask_ctx
{
  bool   enabled;

  cs_t   mp_sys[8];
  cs_t   mp_usr[4];

  u64    bfs_cnt;

  cs_t  *css_buf;
  u32    css_cnt;

  hcstat_table_t *root_table_buf;
  hcstat_table_t *markov_table_buf;

  cs_t  *root_css_buf;
  cs_t  *markov_css_buf;

  bool   mask_from_file;

  char **masks;
  u32    masks_pos;
  u32    masks_cnt;
  u32    masks_avail;

  char *mask;

  mf_t  *mfs;

} mask_ctx_t;

typedef struct cpt_ctx
{
  bool enabled;

  cpt_t  *cpt_buf;
  int     cpt_pos;
  time_t  cpt_start;
  u64     cpt_total;

} cpt_ctx_t;

typedef struct
{
  bool    skipped_dev;
  double  hashes_msec_dev;
  double  hashes_msec_dev_benchmark;
  double  exec_msec_dev;
  char   *speed_sec_dev;
  char   *input_candidates_dev;
  char   *hwmon_dev;
  int     corespeed_dev;
  int     memoryspeed_dev;

} device_info_t;

typedef struct
{
  char   *hash_target;
  char   *hash_type;
  int     input_mode;
  char   *input_base;
  int     input_base_offset;
  int     input_base_count;
  double  input_base_percent;
  char   *input_mod;
  int     input_mod_offset;
  int     input_mod_count;
  double  input_mod_percent;
  char   *input_charset;
  int     input_mask_length;
  char   *session;
  char   *status_string;
  int     status_number;
  char   *time_estimated_absolute;
  char   *time_estimated_relative;
  char   *time_started_absolute;
  char   *time_started_relative;
  double  msec_paused;
  double  msec_running;
  double  msec_real;
  int     digests_cnt;
  int     digests_done;
  double  digests_percent;
  int     salts_cnt;
  int     salts_done;
  double  salts_percent;
  int     progress_mode;
  double  progress_finished_percent;
  u64     progress_cur;
  u64     progress_cur_relative_skip;
  u64     progress_done;
  u64     progress_end;
  u64     progress_end_relative_skip;
  u64     progress_ignore;
  u64     progress_rejected;
  double  progress_rejected_percent;
  u64     progress_restored;
  u64     progress_skip;
  u64     restore_point;
  u64     restore_total;
  double  restore_percent;
  int     cpt_cur_min;
  int     cpt_cur_hour;
  int     cpt_cur_day;
  double  cpt_avg_min;
  double  cpt_avg_hour;
  double  cpt_avg_day;
  char   *cpt;

  device_info_t device_info_buf[DEVICES_MAX];
  int           device_info_cnt;
  int           device_info_active;

  double  hashes_msec_all;
  double  exec_msec_all;
  char   *speed_sec_all;

} hashcat_status_t;

typedef struct status_ctx
{
  /**
   * main status
   */

  bool accessible;

  u32  devices_status;

  /**
   * full (final) status snapshot
   */

  hashcat_status_t *hashcat_status_final;

  /**
   * thread control
   */

  bool run_main_level1;
  bool run_main_level2;
  bool run_main_level3;
  bool run_thread_level1;
  bool run_thread_level2;

  bool shutdown_inner;
  bool shutdown_outer;

  bool checkpoint_shutdown;

  hc_thread_mutex_t mux_dispatcher;
  hc_thread_mutex_t mux_counter;
  hc_thread_mutex_t mux_hwmon;
  hc_thread_mutex_t mux_display;

  /**
   * workload
   */

  u64  words_off;               // used by dispatcher; get_work () as offset; attention: needs to be redone on in restore case!
  u64  words_cur;               // used by dispatcher; the different to words_cur_next is that this counter guarantees that the work from zero to this counter has been actually computed
                                // has been finished actually, can be used for restore point therefore
  u64  words_base;              // the unamplified max keyspace
  u64  words_cnt;               // the amplified max keyspace

  /**
   * progress
   */

  u64 *words_progress_done;     // progress number of words done     per salt
  u64 *words_progress_rejected; // progress number of words rejected per salt
  u64 *words_progress_restored; // progress number of words restored per salt

  /**
   * timer
   */

  time_t  runtime_start;
  time_t  runtime_stop;

  time_t  prepare_start;
  time_t  prepare_time;

  hc_timer_t timer_running;     // timer on current dict
  hc_timer_t timer_paused;      // timer on current dict

  double  msec_paused;          // timer on current dict

} status_ctx_t;

typedef struct hashcat_user
{
  // use this for context specific data
  // see main.c as how this example is used

  int          outer_threads_cnt;
  hc_thread_t *outer_threads;

} hashcat_user_t;

typedef struct cache_hit
{
  char *dictfile;

  hc_stat_t stat;

  u64 cached_cnt;
  u64 keyspace;

} cache_hit_t;

typedef struct cache_generate
{
  char *dictfile;

  double percent;

  u64 comp;
  u64 cnt;
  u64 cnt2;

} cache_generate_t;

typedef struct hashlist_parse
{
  u32 hashes_cnt;
  u32 hashes_avail;

} hashlist_parse_t;

#define MAX_OLD_EVENTS 10

typedef struct event_ctx
{
  char old_buf[MAX_OLD_EVENTS][HCBUFSIZ_TINY];
  int  old_len[MAX_OLD_EVENTS];
  int  old_cnt;

  char msg_buf[HCBUFSIZ_TINY];
  int  msg_len;
  bool msg_newline;

  int  prev_len;

  hc_thread_mutex_t mux_event;

} event_ctx_t;

typedef struct hashcat_ctx
{
  bitmap_ctx_t          *bitmap_ctx;
  combinator_ctx_t      *combinator_ctx;
  cpt_ctx_t             *cpt_ctx;
  debugfile_ctx_t       *debugfile_ctx;
  dictstat_ctx_t        *dictstat_ctx;
  event_ctx_t           *event_ctx;
  folder_config_t       *folder_config;
  hashcat_user_t        *hashcat_user;
  hashconfig_t          *hashconfig;
  hashes_t              *hashes;
  hwmon_ctx_t           *hwmon_ctx;
  induct_ctx_t          *induct_ctx;
  logfile_ctx_t         *logfile_ctx;
  loopback_ctx_t        *loopback_ctx;
  mask_ctx_t            *mask_ctx;
  opencl_ctx_t          *opencl_ctx;
  outcheck_ctx_t        *outcheck_ctx;
  outfile_ctx_t         *outfile_ctx;
  potfile_ctx_t         *potfile_ctx;
  restore_ctx_t         *restore_ctx;
  status_ctx_t          *status_ctx;
  straight_ctx_t        *straight_ctx;
  tuning_db_t           *tuning_db;
  user_options_extra_t  *user_options_extra;
  user_options_t        *user_options;
  wl_data_t             *wl_data;

  void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t);

} hashcat_ctx_t;

typedef struct thread_param
{
  u32 tid;

  hashcat_ctx_t *hashcat_ctx;

} thread_param_t;

#endif // _TYPES_H
