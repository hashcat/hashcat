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
#include <math.h>

// workaround to get the rid of "redefinition of typedef 'Byte'" build warning
#if !defined (__APPLE__)
#include "zlib.h"
#endif

#if !defined(__MACTYPES__)
#define __MACTYPES__
#include "ext_lzma.h"
#undef __MACTYPES__
#endif
// end of workaround

#if defined (_WIN)
#define WINICONV_CONST
#endif

#include <iconv.h>

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

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#include "inc_types.h"

// there's no such thing in plain C, therefore all vector operation cannot work in this emu
// which is why VECT_SIZE is set to 1

typedef uint32_t uint4;

// timer

#if defined (_WIN)
typedef LARGE_INTEGER     hc_timer_t;
#elif defined(__APPLE__) && defined(MISSING_CLOCK_GETTIME)
typedef struct timeval    hc_timer_t;
#else
typedef struct timespec   hc_timer_t;
#endif

// thread

#if defined (_POSIX)
#include <pthread.h>
#include <semaphore.h>
#endif

#if defined (_WIN)
typedef HANDLE           hc_thread_t;
typedef CRITICAL_SECTION hc_thread_mutex_t;
typedef HANDLE           hc_thread_semaphore_t;
#else
typedef pthread_t        hc_thread_t;
typedef pthread_mutex_t  hc_thread_mutex_t;
typedef sem_t            hc_thread_semaphore_t;
#endif

// enums

typedef enum loglevel
{
  LOGLEVEL_INFO    = 0,
  LOGLEVEL_WARNING = 1,
  LOGLEVEL_ERROR   = 2,
  LOGLEVEL_ADVICE  = 3,

} loglevel_t;

typedef enum event_identifier
{
  EVENT_AUTODETECT_FINISHED       = 0x00000100,
  EVENT_AUTODETECT_STARTING       = 0x00000101,
  EVENT_AUTOTUNE_FINISHED         = 0x00000000,
  EVENT_AUTOTUNE_STARTING         = 0x00000001,
  EVENT_BITMAP_INIT_POST          = 0x00000010,
  EVENT_BITMAP_INIT_PRE           = 0x00000011,
  EVENT_BITMAP_FINAL_OVERFLOW     = 0x00000012,
  EVENT_CALCULATED_WORDS_BASE     = 0x00000020,
  EVENT_CRACKER_FINISHED          = 0x00000030,
  EVENT_CRACKER_HASH_CRACKED      = 0x00000031,
  EVENT_CRACKER_STARTING          = 0x00000032,
  EVENT_HASHCONFIG_PRE            = 0x00000040,
  EVENT_HASHCONFIG_POST           = 0x00000041,
  EVENT_HASHLIST_COUNT_LINES_POST = 0x00000050,
  EVENT_HASHLIST_COUNT_LINES_PRE  = 0x00000051,
  EVENT_HASHLIST_PARSE_HASH       = 0x00000052,
  EVENT_HASHLIST_SORT_HASH_POST   = 0x00000053,
  EVENT_HASHLIST_SORT_HASH_PRE    = 0x00000054,
  EVENT_HASHLIST_SORT_SALT_POST   = 0x00000055,
  EVENT_HASHLIST_SORT_SALT_PRE    = 0x00000056,
  EVENT_HASHLIST_UNIQUE_HASH_POST = 0x00000057,
  EVENT_HASHLIST_UNIQUE_HASH_PRE  = 0x00000058,
  EVENT_INNERLOOP1_FINISHED       = 0x00000060,
  EVENT_INNERLOOP1_STARTING       = 0x00000061,
  EVENT_INNERLOOP2_FINISHED       = 0x00000070,
  EVENT_INNERLOOP2_STARTING       = 0x00000071,
  EVENT_LOG_ERROR                 = 0x00000080,
  EVENT_LOG_INFO                  = 0x00000081,
  EVENT_LOG_WARNING               = 0x00000082,
  EVENT_LOG_ADVICE                = 0x00000083,
  EVENT_MONITOR_RUNTIME_LIMIT     = 0x00000090,
  EVENT_MONITOR_STATUS_REFRESH    = 0x00000091,
  EVENT_MONITOR_TEMP_ABORT        = 0x00000092,
  EVENT_MONITOR_THROTTLE1         = 0x00000093,
  EVENT_MONITOR_THROTTLE2         = 0x00000094,
  EVENT_MONITOR_THROTTLE3         = 0x00000095,
  EVENT_MONITOR_PERFORMANCE_HINT  = 0x00000096,
  EVENT_MONITOR_NOINPUT_HINT      = 0x00000097,
  EVENT_MONITOR_NOINPUT_ABORT     = 0x00000098,
  EVENT_BACKEND_SESSION_POST      = 0x000000a0,
  EVENT_BACKEND_SESSION_PRE       = 0x000000a1,
  EVENT_BACKEND_SESSION_HOSTMEM   = 0x000000a2,
  EVENT_BACKEND_DEVICE_INIT_POST  = 0x000000a3,
  EVENT_BACKEND_DEVICE_INIT_PRE   = 0x000000a4,
  EVENT_OUTERLOOP_FINISHED        = 0x000000b0,
  EVENT_OUTERLOOP_MAINSCREEN      = 0x000000b1,
  EVENT_OUTERLOOP_STARTING        = 0x000000b2,
  EVENT_POTFILE_ALL_CRACKED       = 0x000000c0,
  EVENT_POTFILE_HASH_LEFT         = 0x000000c1,
  EVENT_POTFILE_HASH_SHOW         = 0x000000c2,
  EVENT_POTFILE_NUM_CRACKED       = 0x000000c3,
  EVENT_POTFILE_REMOVE_PARSE_POST = 0x000000c4,
  EVENT_POTFILE_REMOVE_PARSE_PRE  = 0x000000c5,
  EVENT_SELFTEST_FINISHED         = 0x000000d0,
  EVENT_SELFTEST_STARTING         = 0x000000d1,
  EVENT_SET_KERNEL_POWER_FINAL    = 0x000000e0,
  EVENT_WORDLIST_CACHE_GENERATE   = 0x000000f0,
  EVENT_WORDLIST_CACHE_HIT        = 0x000000f1,

  // there will be much more event types soon

} event_identifier_t;

typedef enum amplifier_count
{
  KERNEL_BFS                        = 1024,
  KERNEL_COMBS                      = 1024,
  KERNEL_RULES                      = 256,

} amplifier_count_t;

typedef enum vendor_id
{
  VENDOR_ID_AMD           = (1U << 0),
  VENDOR_ID_APPLE         = (1U << 1),
  VENDOR_ID_INTEL_BEIGNET = (1U << 2),
  VENDOR_ID_INTEL_SDK     = (1U << 3),
  VENDOR_ID_MESA          = (1U << 4),
  VENDOR_ID_NV            = (1U << 5),
  VENDOR_ID_POCL          = (1U << 6),
  VENDOR_ID_AMD_USE_INTEL = (1U << 7),
  VENDOR_ID_AMD_USE_HIP   = (1U << 8),
  VENDOR_ID_GENERIC       = (1U << 31)

} vendor_id_t;

typedef enum st_status_rc
{
  ST_STATUS_PASSED        = 0,
  ST_STATUS_FAILED        = 1,
  ST_STATUS_IGNORED       = 2,

} st_status_t;

typedef enum at_status_rc
{
  AT_STATUS_PASSED        = 0,
  AT_STATUS_FAILED        = 1,

} at_status_t;

typedef enum status_rc
{
  STATUS_INIT               = 0,
  STATUS_AUTOTUNE           = 1,
  STATUS_SELFTEST           = 2,
  STATUS_RUNNING            = 3,
  STATUS_PAUSED             = 4,
  STATUS_EXHAUSTED          = 5,
  STATUS_CRACKED            = 6,
  STATUS_ABORTED            = 7,
  STATUS_QUIT               = 8,
  STATUS_BYPASS             = 9,
  STATUS_ABORTED_CHECKPOINT = 10,
  STATUS_ABORTED_RUNTIME    = 11,
  STATUS_ERROR              = 13,
  STATUS_ABORTED_FINISH     = 14,
  STATUS_AUTODETECT         = 16,

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
  HL_MODE_ARG         = 2,
  HL_MODE_FILE_PLAIN  = 5,
  HL_MODE_FILE_BINARY = 6,

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
  ATTACK_MODE_ASSOCIATION   = 9,
  ATTACK_MODE_NONE      = 100

} attack_mode_t;

typedef enum attack_kern
{
  ATTACK_KERN_STRAIGHT  = 0,
  ATTACK_KERN_COMBI     = 1,
  ATTACK_KERN_BF        = 3,
  ATTACK_KERN_NONE      = 100

} attack_kern_t;

typedef enum kern_run
{
  KERN_RUN_1      = 1000,
  KERN_RUN_12     = 1500,
  KERN_RUN_2P     = 1999,
  KERN_RUN_2      = 2000,
  KERN_RUN_2E     = 2001,
  KERN_RUN_23     = 2500,
  KERN_RUN_3      = 3000,
  KERN_RUN_4      = 4000,
  KERN_RUN_INIT2  = 5000,
  KERN_RUN_LOOP2P = 5999,
  KERN_RUN_LOOP2  = 6000,
  KERN_RUN_AUX1   = 7001,
  KERN_RUN_AUX2   = 7002,
  KERN_RUN_AUX3   = 7003,
  KERN_RUN_AUX4   = 7004,

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
  RULE_OP_MANGLE_TOGGLE_AT_SEP   = '3',
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
  RULE_OP_MANGLE_TITLE_SEP       = 'e',

  RULE_OP_MEMORIZE_WORD          = 'M',

  RULE_OP_REJECT_LESS            = '<',
  RULE_OP_REJECT_GREATER         = '>',
  RULE_OP_REJECT_EQUAL           = '_',
  RULE_OP_REJECT_CONTAIN         = '!',
  RULE_OP_REJECT_NOT_CONTAIN     = '/',
  RULE_OP_REJECT_EQUAL_FIRST     = '(',
  RULE_OP_REJECT_EQUAL_LAST      = ')',
  RULE_OP_REJECT_EQUAL_AT        = '=',
  RULE_OP_REJECT_CONTAINS        = '%',
  RULE_OP_REJECT_MEMORY          = 'Q',
  RULE_LAST_REJECTED_SAVED_POS   = 'p',

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
  SALT_TYPE_GENERIC  = 3,
  SALT_TYPE_VIRTUAL  = 5

} salt_type_t;

typedef enum opti_type
{
  OPTI_TYPE_OPTIMIZED_KERNEL      = (1 <<  0),
  OPTI_TYPE_ZERO_BYTE             = (1 <<  1),
  OPTI_TYPE_PRECOMPUTE_INIT       = (1 <<  2),
  OPTI_TYPE_MEET_IN_MIDDLE        = (1 <<  3),
  OPTI_TYPE_EARLY_SKIP            = (1 <<  4),
  OPTI_TYPE_NOT_SALTED            = (1 <<  5),
  OPTI_TYPE_NOT_ITERATED          = (1 <<  6),
  OPTI_TYPE_PREPENDED_SALT        = (1 <<  7),
  OPTI_TYPE_APPENDED_SALT         = (1 <<  8),
  OPTI_TYPE_SINGLE_HASH           = (1 <<  9),
  OPTI_TYPE_SINGLE_SALT           = (1 << 10),
  OPTI_TYPE_BRUTE_FORCE           = (1 << 11),
  OPTI_TYPE_RAW_HASH              = (1 << 12),
  OPTI_TYPE_SLOW_HASH_SIMD_INIT   = (1 << 13),
  OPTI_TYPE_SLOW_HASH_SIMD_LOOP   = (1 << 14),
  OPTI_TYPE_SLOW_HASH_SIMD_COMP   = (1 << 15),
  OPTI_TYPE_USES_BITS_8           = (1 << 16),
  OPTI_TYPE_USES_BITS_16          = (1 << 17),
  OPTI_TYPE_USES_BITS_32          = (1 << 18),
  OPTI_TYPE_USES_BITS_64          = (1 << 19),
  OPTI_TYPE_REGISTER_LIMIT        = (1 << 20), // We'll limit the register count to 128
  OPTI_TYPE_SLOW_HASH_SIMD_INIT2  = (1 << 21),
  OPTI_TYPE_SLOW_HASH_SIMD_LOOP2  = (1 << 22),

} opti_type_t;

typedef enum opts_type
{
  OPTS_TYPE_PT_UTF16LE        = (1ULL <<  0),
  OPTS_TYPE_PT_UTF16BE        = (1ULL <<  1),
  OPTS_TYPE_PT_UPPER          = (1ULL <<  2),
  OPTS_TYPE_PT_LOWER          = (1ULL <<  3),
  OPTS_TYPE_PT_ADD01          = (1ULL <<  4),
  OPTS_TYPE_PT_ADD02          = (1ULL <<  5),
  OPTS_TYPE_PT_ADD80          = (1ULL <<  6),
  OPTS_TYPE_PT_ADDBITS14      = (1ULL <<  7),
  OPTS_TYPE_PT_ADDBITS15      = (1ULL <<  8),
  OPTS_TYPE_PT_GENERATE_LE    = (1ULL <<  9),
  OPTS_TYPE_PT_GENERATE_BE    = (1ULL << 10),
  OPTS_TYPE_PT_NEVERCRACK     = (1ULL << 11), // if we want all possible results
  OPTS_TYPE_PT_ALWAYS_ASCII   = (1ULL << 12),
  OPTS_TYPE_PT_ALWAYS_HEXIFY  = (1ULL << 13),
  OPTS_TYPE_PT_LM             = (1ULL << 14), // special handling: all lower, 7 max, ...
  OPTS_TYPE_PT_HEX            = (1ULL << 15), // input wordlist (and masks!) are always in hex
  OPTS_TYPE_ST_UTF16LE        = (1ULL << 16),
  OPTS_TYPE_ST_UTF16BE        = (1ULL << 17),
  OPTS_TYPE_ST_UPPER          = (1ULL << 18),
  OPTS_TYPE_ST_LOWER          = (1ULL << 19),
  OPTS_TYPE_ST_ADD01          = (1ULL << 20),
  OPTS_TYPE_ST_ADD02          = (1ULL << 21),
  OPTS_TYPE_ST_ADD80          = (1ULL << 22),
  OPTS_TYPE_ST_ADDBITS14      = (1ULL << 23),
  OPTS_TYPE_ST_ADDBITS15      = (1ULL << 24),
  OPTS_TYPE_ST_HEX            = (1ULL << 25),
  OPTS_TYPE_ST_BASE64         = (1ULL << 26),
  OPTS_TYPE_HASH_COPY         = (1ULL << 28),
  OPTS_TYPE_HASH_SPLIT        = (1ULL << 29),
  OPTS_TYPE_LOOP_PREPARE      = (1ULL << 30), // a kernel which is called each time before _loop kernel started.
                                              // like a hook12 kernel but without extra buffers.
  OPTS_TYPE_LOOP_EXTENDED     = (1ULL << 31), // a kernel which is called each time normal _loop kernel finished.
                                              // but unlike a hook kernel this kernel is called for every _loop iteration offset
  OPTS_TYPE_HOOK12            = (1ULL << 32),
  OPTS_TYPE_HOOK23            = (1ULL << 33),
  OPTS_TYPE_INIT2             = (1ULL << 34),
  OPTS_TYPE_LOOP2_PREPARE     = (1ULL << 35), // same as OPTS_TYPE_LOOP_PREPARE but for loop2 kernel
  OPTS_TYPE_LOOP2             = (1ULL << 36),
  OPTS_TYPE_AUX1              = (1ULL << 37),
  OPTS_TYPE_AUX2              = (1ULL << 38),
  OPTS_TYPE_AUX3              = (1ULL << 39),
  OPTS_TYPE_AUX4              = (1ULL << 40),
  OPTS_TYPE_BINARY_HASHFILE   = (1ULL << 41),
  OPTS_TYPE_BINARY_HASHFILE_OPTIONAL
                              = (1ULL << 42), // this allows us to not enforce the use of a binary file. requires OPTS_TYPE_BINARY_HASHFILE set to be effective.
  OPTS_TYPE_PT_ADD06          = (1ULL << 43),
  OPTS_TYPE_KEYBOARD_MAPPING  = (1ULL << 44),
  OPTS_TYPE_DEEP_COMP_KERNEL  = (1ULL << 45), // if we have to iterate through each hash inside the comp kernel, for example if each hash has to be decrypted separately
  OPTS_TYPE_TM_KERNEL         = (1ULL << 46),
  OPTS_TYPE_SUGGEST_KG        = (1ULL << 47), // suggest keep guessing for modules the user maybe wants to use --keep-guessing
  OPTS_TYPE_COPY_TMPS         = (1ULL << 48), // if we want to use data from tmps buffer (for example get the PMK in WPA)
  OPTS_TYPE_POTFILE_NOPASS    = (1ULL << 49), // sometimes the password should not be printed to potfile
  OPTS_TYPE_DYNAMIC_SHARED    = (1ULL << 50), // use dynamic shared memory (note: needs special kernel changes)
  OPTS_TYPE_SELF_TEST_DISABLE = (1ULL << 51), // some algos use JiT in combinations with a salt or create too much startup time
  OPTS_TYPE_MP_MULTI_DISABLE  = (1ULL << 52), // do not multiply the kernel-accel with the multiprocessor count per device to allow more fine-tuned workload settings
  OPTS_TYPE_NATIVE_THREADS    = (1ULL << 53), // forces "native" thread count: CPU=1, GPU-Intel=8, GPU-AMD=64 (wavefront), GPU-NV=32 (warps)
  OPTS_TYPE_MAXIMUM_THREADS   = (1ULL << 54), // disable else branch in pre-compilation thread count optimization setting
  OPTS_TYPE_POST_AMP_UTF16LE  = (1ULL << 55), // run the utf8 to utf16le conversion kernel after they have been processed from amplifiers
  OPTS_TYPE_AUTODETECT_DISABLE
                              = (1ULL << 56), // skip autodetect engine
  OPTS_TYPE_STOCK_MODULE      = (1ULL << 57), // module included with hashcat default distribution

} opts_type_t;

typedef enum dgst_size
{
  DGST_SIZE_4_2  = (2  * sizeof (u32)), // 8
  DGST_SIZE_4_4  = (4  * sizeof (u32)), // 16 !!!
  DGST_SIZE_4_5  = (5  * sizeof (u32)), // 20
  DGST_SIZE_4_6  = (6  * sizeof (u32)), // 24
  DGST_SIZE_4_7  = (7  * sizeof (u32)), // 28
  DGST_SIZE_4_8  = (8  * sizeof (u32)), // 32
  DGST_SIZE_4_16 = (16 * sizeof (u32)), // 64 !!!
  DGST_SIZE_4_32 = (32 * sizeof (u32)), // 128 !!!
  DGST_SIZE_4_64 = (64 * sizeof (u32)), // 256
  DGST_SIZE_8_2  = (2  * sizeof (u64)), // 16 !!!
  DGST_SIZE_8_4  = (4  * sizeof (u64)), // 32 !!!
  DGST_SIZE_8_6  = (6  * sizeof (u64)), // 48 !!!
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

typedef enum pwdump_column
{
  PWDUMP_COLUMN_INVALID   = -1,
  PWDUMP_COLUMN_USERNAME  = 0,
  PWDUMP_COLUMN_UID       = 1,
  PWDUMP_COLUMN_LM_HASH   = 2,
  PWDUMP_COLUMN_NTLM_HASH = 3,
  PWDUMP_COLUMN_COMMENT   = 4,
  PWDUMP_COLUMN_HOMEDIR   = 5,

} pwdump_column_t;

typedef enum outfile_fmt
{
  OUTFILE_FMT_HASH      = (1 << 0),
  OUTFILE_FMT_PLAIN     = (1 << 1),
  OUTFILE_FMT_HEXPLAIN  = (1 << 2),
  OUTFILE_FMT_CRACKPOS  = (1 << 3),
  OUTFILE_FMT_TIME_ABS  = (1 << 4),
  OUTFILE_FMT_TIME_REL  = (1 << 5)

} outfile_fmt_t;

typedef enum parser_rc
{
  PARSER_OK                   = 0,
  PARSER_COMMENT              = -1,
  PARSER_GLOBAL_ZERO          = -2,
  PARSER_GLOBAL_LENGTH        = -3,
  PARSER_HASH_LENGTH          = -4,
  PARSER_HASH_VALUE           = -5,
  PARSER_SALT_LENGTH          = -6,
  PARSER_SALT_VALUE           = -7,
  PARSER_SALT_ITERATION       = -8,
  PARSER_SEPARATOR_UNMATCHED  = -9,
  PARSER_SIGNATURE_UNMATCHED  = -10,
  PARSER_HCCAPX_FILE_SIZE     = -11,
  PARSER_HCCAPX_EAPOL_LEN     = -12,
  PARSER_PSAFE2_FILE_SIZE     = -13,
  PARSER_PSAFE3_FILE_SIZE     = -14,
  PARSER_TC_FILE_SIZE         = -15,
  PARSER_VC_FILE_SIZE         = -16,
  PARSER_SIP_AUTH_DIRECTIVE   = -17,
  PARSER_HASH_FILE            = -18,
  PARSER_HASH_ENCODING        = -19,
  PARSER_SALT_ENCODING        = -20,
  PARSER_LUKS_FILE_SIZE       = -21,
  PARSER_LUKS_MAGIC           = -22,
  PARSER_LUKS_VERSION         = -23,
  PARSER_LUKS_CIPHER_TYPE     = -24,
  PARSER_LUKS_CIPHER_MODE     = -25,
  PARSER_LUKS_HASH_TYPE       = -26,
  PARSER_LUKS_KEY_SIZE        = -27,
  PARSER_LUKS_KEY_DISABLED    = -28,
  PARSER_LUKS_KEY_STRIPES     = -29,
  PARSER_LUKS_HASH_CIPHER     = -30,
  PARSER_HCCAPX_SIGNATURE     = -31,
  PARSER_HCCAPX_VERSION       = -32,
  PARSER_HCCAPX_MESSAGE_PAIR  = -33,
  PARSER_TOKEN_ENCODING       = -34,
  PARSER_TOKEN_LENGTH         = -35,
  PARSER_INSUFFICIENT_ENTROPY = -36,
  PARSER_PKZIP_CT_UNMATCHED   = -37,
  PARSER_KEY_SIZE             = -38,
  PARSER_BLOCK_SIZE           = -39,
  PARSER_CIPHER               = -40,
  PARSER_FILE_SIZE            = -41,
  PARSER_IV_LENGTH            = -42,
  PARSER_CT_LENGTH            = -43,
  PARSER_CRYPTOAPI_KERNELTYPE = -44,
  PARSER_CRYPTOAPI_KEYSIZE    = -45,
  PARSER_HAVE_ERRNO           = -100,
  PARSER_UNKNOWN_ERROR        = -255

} parser_rc_t;

typedef enum guess_mode
{
  GUESS_MODE_NONE                       = 0,
  GUESS_MODE_STRAIGHT_FILE              = 1,
  GUESS_MODE_STRAIGHT_FILE_RULES_FILE   = 2,
  GUESS_MODE_STRAIGHT_FILE_RULES_GEN    = 3,
  GUESS_MODE_STRAIGHT_STDIN             = 4,
  GUESS_MODE_STRAIGHT_STDIN_RULES_FILE  = 5,
  GUESS_MODE_STRAIGHT_STDIN_RULES_GEN   = 6,
  GUESS_MODE_COMBINATOR_BASE_LEFT       = 7,
  GUESS_MODE_COMBINATOR_BASE_RIGHT      = 8,
  GUESS_MODE_MASK                       = 9,
  GUESS_MODE_MASK_CS                    = 10,
  GUESS_MODE_HYBRID1                    = 11,
  GUESS_MODE_HYBRID1_CS                 = 12,
  GUESS_MODE_HYBRID2                    = 13,
  GUESS_MODE_HYBRID2_CS                 = 14,

} guess_mode_t;

typedef enum progress_mode
{
  PROGRESS_MODE_NONE              = 0,
  PROGRESS_MODE_KEYSPACE_KNOWN    = 1,
  PROGRESS_MODE_KEYSPACE_UNKNOWN  = 2,

} progress_mode_t;

typedef enum user_options_defaults
{
  ADVICE_DISABLE           = false,
  ATTACK_MODE              = ATTACK_MODE_STRAIGHT,
  AUTODETECT               = false,
  BENCHMARK_ALL            = false,
  BENCHMARK                = false,
  BITMAP_MAX               = 18,
  BITMAP_MIN               = 16,
  #ifdef WITH_BRAIN
  BRAIN_CLIENT             = false,
  BRAIN_CLIENT_FEATURES    = 2,
  BRAIN_PORT               = 6863,
  BRAIN_SERVER             = false,
  BRAIN_SESSION            = 0,
  #endif
  DEBUG_MODE               = 0,
  DEPRECATED_CHECK_DISABLE = false,
  FORCE                    = false,
  HWMON_DISABLE            = false,
  #if defined (__APPLE__)
  HWMON_TEMP_ABORT         = 100,
  #else
  HWMON_TEMP_ABORT         = 90,
  #endif
  HASH_INFO                = false,
  HASH_MODE                = 0,
  HCCAPX_MESSAGE_PAIR      = 0,
  HEX_CHARSET              = false,
  HEX_SALT                 = false,
  HEX_WORDLIST             = false,
  HOOK_THREADS             = 0,
  IDENTIFY                 = false,
  INCREMENT                = false,
  INCREMENT_MAX            = PW_MAX,
  INCREMENT_MIN            = 1,
  KEEP_GUESSING            = false,
  KERNEL_ACCEL             = 0,
  KERNEL_LOOPS             = 0,
  KERNEL_THREADS           = 0,
  KEYSPACE                 = false,
  LEFT                     = false,
  LIMIT                    = 0,
  LOGFILE_DISABLE          = false,
  LOOPBACK                 = false,
  MACHINE_READABLE         = false,
  MARKOV_CLASSIC           = false,
  MARKOV_DISABLE           = false,
  MARKOV_INVERSE           = false,
  MARKOV_THRESHOLD         = 0,
  NONCE_ERROR_CORRECTIONS  = 8,
  BACKEND_IGNORE_CUDA      = false,
  BACKEND_IGNORE_HIP       = false,
  #if defined (__APPLE__)
  BACKEND_IGNORE_METAL     = false,
  #endif
  BACKEND_IGNORE_OPENCL    = false,
  BACKEND_INFO             = 0,
  BACKEND_VECTOR_WIDTH     = 0,
  OPTIMIZED_KERNEL_ENABLE  = false,
  MULTIPLY_ACCEL_DISABLE   = false,
  OUTFILE_AUTOHEX          = true,
  OUTFILE_CHECK_TIMER      = 5,
  OUTFILE_FORMAT           = 3,
  POTFILE_DISABLE          = false,
  PROGRESS_ONLY            = false,
  QUIET                    = false,
  REMOVE                   = false,
  REMOVE_TIMER             = 60,
  RESTORE_DISABLE          = false,
  RESTORE                  = false,
  RESTORE_TIMER            = 1,
  RP_GEN                   = 0,
  RP_GEN_FUNC_MAX          = 4,
  RP_GEN_FUNC_MIN          = 1,
  RP_GEN_SEED              = 0,
  RUNTIME                  = 0,
  SCRYPT_TMTO              = 0,
  SEGMENT_SIZE             = 33554432,
  SELF_TEST_DISABLE        = false,
  SHOW                     = false,
  SKIP                     = 0,
  SLOW_CANDIDATES          = false,
  SPEED_ONLY               = false,
  SPIN_DAMP                = 0,
  STATUS                   = false,
  STATUS_JSON              = false,
  STATUS_TIMER             = 10,
  STDIN_TIMEOUT_ABORT      = 120,
  STDOUT_FLAG              = false,
  USAGE                    = false,
  USERNAME                 = false,
  VERSION                  = false,
  VERACRYPT_PIM_START      = 485,
  VERACRYPT_PIM_STOP       = 485,
  WORDLIST_AUTOHEX_DISABLE = false,
  WORKLOAD_PROFILE         = 2,

} user_options_defaults_t;

typedef enum user_options_map
{
  IDX_ADVICE_DISABLE            = 0xff00,
  IDX_ATTACK_MODE               = 'a',
  IDX_BACKEND_DEVICES           = 'd',
  IDX_BACKEND_IGNORE_CUDA       = 0xff01,
  IDX_BACKEND_IGNORE_HIP        = 0xff02,
  IDX_BACKEND_IGNORE_METAL      = 0xff03,
  IDX_BACKEND_IGNORE_OPENCL     = 0xff04,
  IDX_BACKEND_INFO              = 'I',
  IDX_BACKEND_VECTOR_WIDTH      = 0xff05,
  IDX_BENCHMARK_ALL             = 0xff06,
  IDX_BENCHMARK                 = 'b',
  IDX_BITMAP_MAX                = 0xff07,
  IDX_BITMAP_MIN                = 0xff08,
  #ifdef WITH_BRAIN
  IDX_BRAIN_CLIENT              = 'z',
  IDX_BRAIN_CLIENT_FEATURES     = 0xff09,
  IDX_BRAIN_HOST                = 0xff0a,
  IDX_BRAIN_PASSWORD            = 0xff0b,
  IDX_BRAIN_PORT                = 0xff0c,
  IDX_BRAIN_SERVER              = 0xff0d,
  IDX_BRAIN_SERVER_TIMER        = 0xff0e,
  IDX_BRAIN_SESSION             = 0xff0f,
  IDX_BRAIN_SESSION_WHITELIST   = 0xff10,
  #endif
  IDX_CPU_AFFINITY              = 0xff11,
  IDX_CUSTOM_CHARSET_1          = '1',
  IDX_CUSTOM_CHARSET_2          = '2',
  IDX_CUSTOM_CHARSET_3          = '3',
  IDX_CUSTOM_CHARSET_4          = '4',
  IDX_DEBUG_FILE                = 0xff12,
  IDX_DEBUG_MODE                = 0xff13,
  IDX_DEPRECATED_CHECK_DISABLE  = 0xff14,
  IDX_ENCODING_FROM             = 0xff15,
  IDX_ENCODING_TO               = 0xff16,
  IDX_HASH_INFO                 = 0xff17,
  IDX_FORCE                     = 0xff18,
  IDX_HWMON_DISABLE             = 0xff19,
  IDX_HWMON_TEMP_ABORT          = 0xff1a,
  IDX_HASH_MODE                 = 'm',
  IDX_HCCAPX_MESSAGE_PAIR       = 0xff1b,
  IDX_HELP                      = 'h',
  IDX_HEX_CHARSET               = 0xff1c,
  IDX_HEX_SALT                  = 0xff1d,
  IDX_HEX_WORDLIST              = 0xff1e,
  IDX_HOOK_THREADS              = 0xff1f,
  IDX_IDENTIFY                  = 0xff20,
  IDX_INCREMENT                 = 'i',
  IDX_INCREMENT_MAX             = 0xff21,
  IDX_INCREMENT_MIN             = 0xff22,
  IDX_INDUCTION_DIR             = 0xff23,
  IDX_KEEP_GUESSING             = 0xff24,
  IDX_KERNEL_ACCEL              = 'n',
  IDX_KERNEL_LOOPS              = 'u',
  IDX_KERNEL_THREADS            = 'T',
  IDX_KEYBOARD_LAYOUT_MAPPING   = 0xff25,
  IDX_KEYSPACE                  = 0xff26,
  IDX_LEFT                      = 0xff27,
  IDX_LIMIT                     = 'l',
  IDX_LOGFILE_DISABLE           = 0xff28,
  IDX_LOOPBACK                  = 0xff29,
  IDX_MACHINE_READABLE          = 0xff2a,
  IDX_MARKOV_CLASSIC            = 0xff2b,
  IDX_MARKOV_DISABLE            = 0xff2c,
  IDX_MARKOV_HCSTAT2            = 0xff2d,
  IDX_MARKOV_INVERSE            = 0xff2e,
  IDX_MARKOV_THRESHOLD          = 't',
  IDX_NONCE_ERROR_CORRECTIONS   = 0xff2f,
  IDX_OPENCL_DEVICE_TYPES       = 'D',
  IDX_OPTIMIZED_KERNEL_ENABLE   = 'O',
  IDX_MULTIPLY_ACCEL_DISABLE    = 'M',
  IDX_OUTFILE_AUTOHEX_DISABLE   = 0xff30,
  IDX_OUTFILE_CHECK_DIR         = 0xff31,
  IDX_OUTFILE_CHECK_TIMER       = 0xff32,
  IDX_OUTFILE_FORMAT            = 0xff33,
  IDX_OUTFILE                   = 'o',
  IDX_POTFILE_DISABLE           = 0xff34,
  IDX_POTFILE_PATH              = 0xff35,
  IDX_PROGRESS_ONLY             = 0xff36,
  IDX_QUIET                     = 0xff37,
  IDX_REMOVE                    = 0xff38,
  IDX_REMOVE_TIMER              = 0xff39,
  IDX_RESTORE                   = 0xff3a,
  IDX_RESTORE_DISABLE           = 0xff3b,
  IDX_RESTORE_FILE_PATH         = 0xff3c,
  IDX_RP_FILE                   = 'r',
  IDX_RP_GEN_FUNC_MAX           = 0xff3d,
  IDX_RP_GEN_FUNC_MIN           = 0xff3e,
  IDX_RP_GEN_FUNC_SEL           = 0xff3f,
  IDX_RP_GEN                    = 'g',
  IDX_RP_GEN_SEED               = 0xff40,
  IDX_RULE_BUF_L                = 'j',
  IDX_RULE_BUF_R                = 'k',
  IDX_RUNTIME                   = 0xff41,
  IDX_SCRYPT_TMTO               = 0xff42,
  IDX_SEGMENT_SIZE              = 'c',
  IDX_SELF_TEST_DISABLE         = 0xff43,
  IDX_SEPARATOR                 = 'p',
  IDX_SESSION                   = 0xff44,
  IDX_SHOW                      = 0xff45,
  IDX_SKIP                      = 's',
  IDX_SLOW_CANDIDATES           = 'S',
  IDX_SPEED_ONLY                = 0xff46,
  IDX_SPIN_DAMP                 = 0xff47,
  IDX_STATUS                    = 0xff48,
  IDX_STATUS_JSON               = 0xff49,
  IDX_STATUS_TIMER              = 0xff4a,
  IDX_STDOUT_FLAG               = 0xff4b,
  IDX_STDIN_TIMEOUT_ABORT       = 0xff4c,
  IDX_TRUECRYPT_KEYFILES        = 0xff4d,
  IDX_USERNAME                  = 0xff4e,
  IDX_VERACRYPT_KEYFILES        = 0xff4f,
  IDX_VERACRYPT_PIM_START       = 0xff50,
  IDX_VERACRYPT_PIM_STOP        = 0xff51,
  IDX_VERSION_LOWER             = 'v',
  IDX_VERSION                   = 'V',
  IDX_WORDLIST_AUTOHEX_DISABLE  = 0xff52,
  IDX_WORKLOAD_PROFILE          = 'w',

} user_options_map_t;

typedef enum token_attr
{
  TOKEN_ATTR_FIXED_LENGTH       = 1 <<  0,
  TOKEN_ATTR_SEPARATOR_FARTHEST = 1 <<  1,
  TOKEN_ATTR_OPTIONAL_ROUNDS    = 1 <<  2,
  TOKEN_ATTR_VERIFY_SIGNATURE   = 1 <<  3,
  TOKEN_ATTR_VERIFY_LENGTH      = 1 <<  4,
  TOKEN_ATTR_VERIFY_DIGIT       = 1 <<  5,
  TOKEN_ATTR_VERIFY_FLOAT       = 1 <<  6,
  TOKEN_ATTR_VERIFY_HEX         = 1 <<  7,
  TOKEN_ATTR_VERIFY_BASE64A     = 1 <<  8,
  TOKEN_ATTR_VERIFY_BASE64B     = 1 <<  9,
  TOKEN_ATTR_VERIFY_BASE64C     = 1 << 10,
  TOKEN_ATTR_VERIFY_BASE58      = 1 << 11,
  TOKEN_ATTR_VERIFY_BECH32      = 1 << 12,

} token_attr_t;

#ifdef WITH_BRAIN
typedef enum brain_link_status
{
  BRAIN_LINK_STATUS_CONNECTED   = 1 << 0,
  BRAIN_LINK_STATUS_RECEIVING   = 1 << 1,
  BRAIN_LINK_STATUS_SENDING     = 1 << 2,

} brain_link_status_t;
#endif

#ifdef _WIN
typedef HMODULE hc_dynlib_t;
typedef FARPROC hc_dynfunc_t;
#else
typedef void * hc_dynlib_t;
typedef void * hc_dynfunc_t;
#endif

/**
 * structs
 */

typedef struct user
{
  char *user_name;
  u32   user_len;

} user_t;

typedef enum split_origin
{
  SPLIT_ORIGIN_NONE   = 0,
  SPLIT_ORIGIN_LEFT   = 1,
  SPLIT_ORIGIN_RIGHT  = 2,

} split_origin_t;

typedef struct split
{
  // some hashes, like lm, are split. this id point to the other hash of the group

  int split_group;
  int split_neighbor;
  int split_origin;

} split_t;

typedef struct hashinfo
{
  user_t  *user;
  char    *orighash;
  split_t *split;

} hashinfo_t;

typedef struct hash
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  void       *hook_salt; // additional salt info only used by the hook (host)
  int         cracked;
  int         cracked_pot;
  int         cracked_zero;
  hashinfo_t *hash_info;
  char       *pw_buf;
  int         pw_len;
  u64         orig_line_pos;

} hash_t;

typedef struct outfile_data
{
  char      *file_name;
  off_t      seek;
  time_t     ctime;

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
  const char  *hashfile;

  u32          hashlist_mode;
  u32          hashlist_format;

  u32          digests_cnt;
  u32          digests_done;
  u32          digests_done_pot;
  u32          digests_done_zero;
  u32          digests_done_new;
  u32          digests_saved;

  void        *digests_buf;
  u32         *digests_shown;

  u32          salts_cnt;
  u32          salts_done;

  salt_t      *salts_buf;
  u32         *salts_shown;

  void        *esalts_buf;

  void        *hook_salts_buf;

  u32          hashes_cnt_orig;
  u32          hashes_cnt;
  hash_t      *hashes_buf;

  hashinfo_t **hash_info;

  u8          *out_buf; // allocates [HCBUFSIZ_LARGE];
  u8          *tmp_buf; // allocates [HCBUFSIZ_LARGE];

  // selftest buffers

  void        *st_digests_buf;
  salt_t      *st_salts_buf;
  void        *st_esalts_buf;
  void        *st_hook_salts_buf;

  int          parser_token_length_cnt;

} hashes_t;

typedef struct hashconfig
{
  char  separator;

  int   hash_mode;
  u32   salt_type;
  u32   attack_exec;
  u32   kern_type;
  u32   dgst_size;
  u32   opti_type;
  u64   opts_type;
  u32   dgst_pos0;
  u32   dgst_pos1;
  u32   dgst_pos2;
  u32   dgst_pos3;

  bool  is_salted;

  bool  has_pure_kernel;
  bool  has_optimized_kernel;

  // sizes have to be size_t

  u64   esalt_size;
  u64   hook_extra_param_size;
  u64   hook_salt_size;
  u64   tmp_size;
  u64   hook_size;

  // password length limit

  u32   pw_min;
  u32   pw_max;

  // salt length limit (generic hashes)

  u32   salt_min;
  u32   salt_max;

  // hash count limit

  u32   hashes_count_min;
  u32   hashes_count_max;

  //  int (*parse_func) (u8 *, u32, hash_t *, struct hashconfig *);

  const char *st_hash;
  const char *st_pass;

  u32         hash_category;
  const char *hash_name;

  const char *benchmark_mask;
  const char *benchmark_charset;

  u32 kernel_accel_min;
  u32 kernel_accel_max;
  u32 kernel_loops_min;
  u32 kernel_loops_max;
  u32 kernel_threads_min;
  u32 kernel_threads_max;

  u32 forced_outfile_format;

  bool dictstat_disable;
  bool hlfmt_disable;
  bool warmup_disable;
  bool outfile_check_disable;
  bool outfile_check_nocomp;
  bool potfile_disable;
  bool potfile_keep_all_hashes;
  bool forced_jit_compile;

  u32 pwdump_column;
} hashconfig_t;

typedef struct pw_pre
{
  u32 pw_buf[64];
  u32 pw_len;

  u32 base_buf[64];
  u32 base_len;

  u32 rule_idx;

} pw_pre_t;

typedef struct cpt
{
  u32       cracked;
  time_t    timestamp;

} cpt_t;

#define LINK_SPEED_COUNT 10000

typedef struct link_speed
{
  hc_timer_t timer[LINK_SPEED_COUNT];
  ssize_t    bytes[LINK_SPEED_COUNT];
  int        pos;

} link_speed_t;

// file handling

typedef struct xzfile xzfile_t;

typedef struct hc_fp
{
  int         fd;

  FILE       *pfp; // plain fp
  gzFile      gfp; //  gzip fp
  unzFile     ufp; //   zip fp
  xzfile_t   *xfp; //    xz fp

  int         bom_size;

  const char *mode;
  const char *path;

} HCFILE;

#include "ext_nvrtc.h"
#include "ext_hiprtc.h"

#include "ext_cuda.h"
#include "ext_hip.h"
#include "ext_OpenCL.h"
#include "ext_metal.h"

typedef struct hc_device_param
{
  int     device_id;

  // this occurs if the same device (pci address) is used by multiple backend API
  int     device_id_alias_cnt;
  int     device_id_alias_buf[DEVICES_MAX];

  u8      pcie_domain;
  u8      pcie_bus;
  u8      pcie_device;
  u8      pcie_function;

  bool    skipped;              // permanent
  bool    skipped_warning;      // iteration

  u32     device_processors;
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u64     device_available_mem;
  int     device_host_unified_memory;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;
  u64     device_local_mem_size;
  int     device_local_mem_type;
  char   *device_name;

  int     sm_major;
  int     sm_minor;
  u32     kernel_exec_timeout;

  u32     kernel_preferred_wgs_multiple;

  st_status_t st_status;        // selftest status

  at_status_t at_status;        // autotune status

  int     at_rc;                // autotune rc

  int     vector_width;

  u32     kernel_wgs1;
  u32     kernel_wgs12;
  u32     kernel_wgs2p;
  u32     kernel_wgs2;
  u32     kernel_wgs2e;
  u32     kernel_wgs23;
  u32     kernel_wgs3;
  u32     kernel_wgs4;
  u32     kernel_wgs_init2;
  u32     kernel_wgs_loop2p;
  u32     kernel_wgs_loop2;
  u32     kernel_wgs_mp;
  u32     kernel_wgs_mp_l;
  u32     kernel_wgs_mp_r;
  u32     kernel_wgs_amp;
  u32     kernel_wgs_tm;
  u32     kernel_wgs_memset;
  u32     kernel_wgs_bzero;
  u32     kernel_wgs_atinit;
  u32     kernel_wgs_utf8toutf16le;
  u32     kernel_wgs_decompress;
  u32     kernel_wgs_aux1;
  u32     kernel_wgs_aux2;
  u32     kernel_wgs_aux3;
  u32     kernel_wgs_aux4;

  u32     kernel_preferred_wgs_multiple1;
  u32     kernel_preferred_wgs_multiple12;
  u32     kernel_preferred_wgs_multiple2p;
  u32     kernel_preferred_wgs_multiple2;
  u32     kernel_preferred_wgs_multiple2e;
  u32     kernel_preferred_wgs_multiple23;
  u32     kernel_preferred_wgs_multiple3;
  u32     kernel_preferred_wgs_multiple4;
  u32     kernel_preferred_wgs_multiple_init2;
  u32     kernel_preferred_wgs_multiple_loop2p;
  u32     kernel_preferred_wgs_multiple_loop2;
  u32     kernel_preferred_wgs_multiple_mp;
  u32     kernel_preferred_wgs_multiple_mp_l;
  u32     kernel_preferred_wgs_multiple_mp_r;
  u32     kernel_preferred_wgs_multiple_amp;
  u32     kernel_preferred_wgs_multiple_tm;
  u32     kernel_preferred_wgs_multiple_memset;
  u32     kernel_preferred_wgs_multiple_bzero;
  u32     kernel_preferred_wgs_multiple_atinit;
  u32     kernel_preferred_wgs_multiple_utf8toutf16le;
  u32     kernel_preferred_wgs_multiple_decompress;
  u32     kernel_preferred_wgs_multiple_aux1;
  u32     kernel_preferred_wgs_multiple_aux2;
  u32     kernel_preferred_wgs_multiple_aux3;
  u32     kernel_preferred_wgs_multiple_aux4;

  u64     kernel_local_mem_size1;
  u64     kernel_local_mem_size12;
  u64     kernel_local_mem_size2p;
  u64     kernel_local_mem_size2;
  u64     kernel_local_mem_size2e;
  u64     kernel_local_mem_size23;
  u64     kernel_local_mem_size3;
  u64     kernel_local_mem_size4;
  u64     kernel_local_mem_size_init2;
  u64     kernel_local_mem_size_loop2p;
  u64     kernel_local_mem_size_loop2;
  u64     kernel_local_mem_size_mp;
  u64     kernel_local_mem_size_mp_l;
  u64     kernel_local_mem_size_mp_r;
  u64     kernel_local_mem_size_amp;
  u64     kernel_local_mem_size_tm;
  u64     kernel_local_mem_size_memset;
  u64     kernel_local_mem_size_bzero;
  u64     kernel_local_mem_size_atinit;
  u64     kernel_local_mem_size_utf8toutf16le;
  u64     kernel_local_mem_size_decompress;
  u64     kernel_local_mem_size_aux1;
  u64     kernel_local_mem_size_aux2;
  u64     kernel_local_mem_size_aux3;
  u64     kernel_local_mem_size_aux4;

  u64     kernel_dynamic_local_mem_size1;
  u64     kernel_dynamic_local_mem_size12;
  u64     kernel_dynamic_local_mem_size2p;
  u64     kernel_dynamic_local_mem_size2;
  u64     kernel_dynamic_local_mem_size2e;
  u64     kernel_dynamic_local_mem_size23;
  u64     kernel_dynamic_local_mem_size3;
  u64     kernel_dynamic_local_mem_size4;
  u64     kernel_dynamic_local_mem_size_init2;
  u64     kernel_dynamic_local_mem_size_loop2p;
  u64     kernel_dynamic_local_mem_size_loop2;
  u64     kernel_dynamic_local_mem_size_mp;
  u64     kernel_dynamic_local_mem_size_mp_l;
  u64     kernel_dynamic_local_mem_size_mp_r;
  u64     kernel_dynamic_local_mem_size_amp;
  u64     kernel_dynamic_local_mem_size_tm;
  u64     kernel_dynamic_local_mem_size_memset;
  u64     kernel_dynamic_local_mem_size_bzero;
  u64     kernel_dynamic_local_mem_size_atinit;
  u64     kernel_dynamic_local_mem_size_utf8toutf16le;
  u64     kernel_dynamic_local_mem_size_decompress;
  u64     kernel_dynamic_local_mem_size_aux1;
  u64     kernel_dynamic_local_mem_size_aux2;
  u64     kernel_dynamic_local_mem_size_aux3;
  u64     kernel_dynamic_local_mem_size_aux4;

  u32     kernel_accel;
  u32     kernel_accel_prev;
  u32     kernel_accel_min;
  u32     kernel_accel_max;
  u32     kernel_loops;
  u32     kernel_loops_prev;
  u32     kernel_loops_min;
  u32     kernel_loops_max;
  u32     kernel_loops_min_sav; // the _sav are required because each -i iteration
  u32     kernel_loops_max_sav; // needs to recalculate the kernel_loops_min/max based on the current amplifier count
  u32     kernel_threads;
  u32     kernel_threads_prev;
  u32     kernel_threads_min;
  u32     kernel_threads_max;

  u64     kernel_power;
  u64     hardware_power;

  u64  size_pws;
  u64  size_pws_amp;
  u64  size_pws_comp;
  u64  size_pws_idx;
  u64  size_pws_pre;
  u64  size_pws_base;
  u64  size_tmps;
  u64  size_hooks;
  u64  size_bfs;
  u64  size_combs;
  u64  size_rules;
  u64  size_rules_c;
  u64  size_root_css;
  u64  size_markov_css;
  u64  size_digests;
  u64  size_salts;
  u64  size_esalts;
  u64  size_shown;
  u64  size_results;
  u64  size_plains;
  u64  size_st_digests;
  u64  size_st_salts;
  u64  size_st_esalts;
  u64  size_tm;
  u64  size_kernel_params;

  u64  extra_buffer_size;

  #ifdef WITH_BRAIN
  u64  size_brain_link_in;
  u64  size_brain_link_out;

  int           brain_link_client_fd;
  link_speed_t  brain_link_recv_speed;
  link_speed_t  brain_link_send_speed;
  bool          brain_link_recv_active;
  bool          brain_link_send_active;
  u64           brain_link_recv_bytes;
  u64           brain_link_send_bytes;
  u8           *brain_link_in_buf;
  u32          *brain_link_out_buf;
  #endif

  char     *scratch_buf;

  HCFILE    combs_fp;
  pw_t     *combs_buf;

  void     *hooks_buf;

  pw_idx_t *pws_idx;
  u32      *pws_comp;
  u64       pws_cnt;

  pw_pre_t *pws_pre_buf;  // for slow candidates
  u64       pws_pre_cnt;

  pw_pre_t *pws_base_buf; // for debug mode
  u64       pws_base_cnt;

  u64     words_off;
  u64     words_done;

  u64     outerloop_pos;
  u64     outerloop_left;
  double  outerloop_msec;
  double  outerloop_multi;

  u32     innerloop_pos;
  u32     innerloop_left;

  u32     exec_pos;
  double  exec_msec[EXEC_CACHE];

  // workaround cpu spinning

  double  exec_us_prev1[EXPECTED_ITERATIONS];
  double  exec_us_prev2p[EXPECTED_ITERATIONS];
  double  exec_us_prev2[EXPECTED_ITERATIONS];
  double  exec_us_prev2e[EXPECTED_ITERATIONS];
  double  exec_us_prev3[EXPECTED_ITERATIONS];
  double  exec_us_prev4[EXPECTED_ITERATIONS];
  double  exec_us_prev_init2[EXPECTED_ITERATIONS];
  double  exec_us_prev_loop2p[EXPECTED_ITERATIONS];
  double  exec_us_prev_loop2[EXPECTED_ITERATIONS];
  double  exec_us_prev_aux1[EXPECTED_ITERATIONS];
  double  exec_us_prev_aux2[EXPECTED_ITERATIONS];
  double  exec_us_prev_aux3[EXPECTED_ITERATIONS];
  double  exec_us_prev_aux4[EXPECTED_ITERATIONS];

  // this is "current" speed

  u32     speed_pos;
  u64     speed_cnt[SPEED_CACHE];
  double  speed_msec[SPEED_CACHE];
  bool    speed_only_finish;

  hc_timer_t timer_speed;

  // Some more attributes

  bool    use_opencl12;
  bool    use_opencl20;
  bool    use_opencl21;

  // AMD
  bool    has_vadd;
  bool    has_vaddc;
  bool    has_vadd_co;
  bool    has_vaddc_co;
  bool    has_vsub;
  bool    has_vsubb;
  bool    has_vsub_co;
  bool    has_vsubb_co;
  bool    has_vadd3;
  bool    has_vbfe;
  bool    has_vperm;

  // NV
  bool    has_add;
  bool    has_addc;
  bool    has_sub;
  bool    has_subc;
  bool    has_bfe;
  bool    has_lop3;
  bool    has_mov64;
  bool    has_prmt;

  double  spin_damp;

  void   *kernel_params[PARAMCNT];
  void   *kernel_params_mp[PARAMCNT];
  void   *kernel_params_mp_r[PARAMCNT];
  void   *kernel_params_mp_l[PARAMCNT];
  void   *kernel_params_amp[PARAMCNT];
  void   *kernel_params_tm[PARAMCNT];
  void   *kernel_params_memset[PARAMCNT];
  void   *kernel_params_bzero[PARAMCNT];
  void   *kernel_params_atinit[PARAMCNT];
  void   *kernel_params_utf8toutf16le[PARAMCNT];
  void   *kernel_params_decompress[PARAMCNT];

  u32     kernel_params_mp_buf32[PARAMCNT];
  u64     kernel_params_mp_buf64[PARAMCNT];

  u32     kernel_params_mp_r_buf32[PARAMCNT];
  u64     kernel_params_mp_r_buf64[PARAMCNT];

  u32     kernel_params_mp_l_buf32[PARAMCNT];
  u64     kernel_params_mp_l_buf64[PARAMCNT];

  u32     kernel_params_amp_buf32[PARAMCNT];
  u64     kernel_params_amp_buf64[PARAMCNT];

  u32     kernel_params_memset_buf32[PARAMCNT];
  u64     kernel_params_memset_buf64[PARAMCNT];

  u32     kernel_params_bzero_buf32[PARAMCNT];
  u64     kernel_params_bzero_buf64[PARAMCNT];

  u32     kernel_params_atinit_buf32[PARAMCNT];
  u64     kernel_params_atinit_buf64[PARAMCNT];

  u32     kernel_params_utf8toutf16le_buf32[PARAMCNT];
  u64     kernel_params_utf8toutf16le_buf64[PARAMCNT];

  u32     kernel_params_decompress_buf32[PARAMCNT];
  u64     kernel_params_decompress_buf64[PARAMCNT];

  kernel_param_t kernel_param;

  // API: cuda

  bool              is_cuda;

  int               cuda_warp_size;

  CUdevice          cuda_device;
  CUcontext         cuda_context;
  CUstream          cuda_stream;

  CUevent           cuda_event1;
  CUevent           cuda_event2;
  CUevent           cuda_event3;

  CUmodule          cuda_module;
  CUmodule          cuda_module_shared;
  CUmodule          cuda_module_mp;
  CUmodule          cuda_module_amp;

  CUfunction        cuda_function1;
  CUfunction        cuda_function12;
  CUfunction        cuda_function2p;
  CUfunction        cuda_function2;
  CUfunction        cuda_function2e;
  CUfunction        cuda_function23;
  CUfunction        cuda_function3;
  CUfunction        cuda_function4;
  CUfunction        cuda_function_init2;
  CUfunction        cuda_function_loop2p;
  CUfunction        cuda_function_loop2;
  CUfunction        cuda_function_mp;
  CUfunction        cuda_function_mp_l;
  CUfunction        cuda_function_mp_r;
  CUfunction        cuda_function_amp;
  CUfunction        cuda_function_tm;
  CUfunction        cuda_function_memset;
  CUfunction        cuda_function_bzero;
  CUfunction        cuda_function_atinit;
  CUfunction        cuda_function_utf8toutf16le;
  CUfunction        cuda_function_decompress;
  CUfunction        cuda_function_aux1;
  CUfunction        cuda_function_aux2;
  CUfunction        cuda_function_aux3;
  CUfunction        cuda_function_aux4;

  CUdeviceptr       cuda_d_pws_buf;
  CUdeviceptr       cuda_d_pws_amp_buf;
  CUdeviceptr       cuda_d_pws_comp_buf;
  CUdeviceptr       cuda_d_pws_idx;
  CUdeviceptr       cuda_d_rules;
  CUdeviceptr       cuda_d_rules_c;
  CUdeviceptr       cuda_d_combs;
  CUdeviceptr       cuda_d_combs_c;
  CUdeviceptr       cuda_d_bfs;
  CUdeviceptr       cuda_d_bfs_c;
  CUdeviceptr       cuda_d_tm_c;
  CUdeviceptr       cuda_d_bitmap_s1_a;
  CUdeviceptr       cuda_d_bitmap_s1_b;
  CUdeviceptr       cuda_d_bitmap_s1_c;
  CUdeviceptr       cuda_d_bitmap_s1_d;
  CUdeviceptr       cuda_d_bitmap_s2_a;
  CUdeviceptr       cuda_d_bitmap_s2_b;
  CUdeviceptr       cuda_d_bitmap_s2_c;
  CUdeviceptr       cuda_d_bitmap_s2_d;
  CUdeviceptr       cuda_d_plain_bufs;
  CUdeviceptr       cuda_d_digests_buf;
  CUdeviceptr       cuda_d_digests_shown;
  CUdeviceptr       cuda_d_salt_bufs;
  CUdeviceptr       cuda_d_esalt_bufs;
  CUdeviceptr       cuda_d_tmps;
  CUdeviceptr       cuda_d_hooks;
  CUdeviceptr       cuda_d_result;
  CUdeviceptr       cuda_d_extra0_buf;
  CUdeviceptr       cuda_d_extra1_buf;
  CUdeviceptr       cuda_d_extra2_buf;
  CUdeviceptr       cuda_d_extra3_buf;
  CUdeviceptr       cuda_d_root_css_buf;
  CUdeviceptr       cuda_d_markov_css_buf;
  CUdeviceptr       cuda_d_st_digests_buf;
  CUdeviceptr       cuda_d_st_salts_buf;
  CUdeviceptr       cuda_d_st_esalts_buf;
  CUdeviceptr       cuda_d_kernel_param;

  // API: hip

  bool              is_hip;

  int               hip_warp_size;

  hipDevice_t       hip_device;
  hipCtx_t          hip_context;
  hipStream_t       hip_stream;

  hipEvent_t        hip_event1;
  hipEvent_t        hip_event2;
  hipEvent_t        hip_event3;

  hipModule_t       hip_module;
  hipModule_t       hip_module_shared;
  hipModule_t       hip_module_mp;
  hipModule_t       hip_module_amp;

  hipFunction_t     hip_function1;
  hipFunction_t     hip_function12;
  hipFunction_t     hip_function2p;
  hipFunction_t     hip_function2;
  hipFunction_t     hip_function2e;
  hipFunction_t     hip_function23;
  hipFunction_t     hip_function3;
  hipFunction_t     hip_function4;
  hipFunction_t     hip_function_init2;
  hipFunction_t     hip_function_loop2p;
  hipFunction_t     hip_function_loop2;
  hipFunction_t     hip_function_mp;
  hipFunction_t     hip_function_mp_l;
  hipFunction_t     hip_function_mp_r;
  hipFunction_t     hip_function_amp;
  hipFunction_t     hip_function_tm;
  hipFunction_t     hip_function_memset;
  hipFunction_t     hip_function_bzero;
  hipFunction_t     hip_function_atinit;
  hipFunction_t     hip_function_utf8toutf16le;
  hipFunction_t     hip_function_decompress;
  hipFunction_t     hip_function_aux1;
  hipFunction_t     hip_function_aux2;
  hipFunction_t     hip_function_aux3;
  hipFunction_t     hip_function_aux4;

  hipDeviceptr_t    hip_d_pws_buf;
  hipDeviceptr_t    hip_d_pws_amp_buf;
  hipDeviceptr_t    hip_d_pws_comp_buf;
  hipDeviceptr_t    hip_d_pws_idx;
  hipDeviceptr_t    hip_d_rules;
  hipDeviceptr_t    hip_d_rules_c;
  hipDeviceptr_t    hip_d_combs;
  hipDeviceptr_t    hip_d_combs_c;
  hipDeviceptr_t    hip_d_bfs;
  hipDeviceptr_t    hip_d_bfs_c;
  hipDeviceptr_t    hip_d_tm_c;
  hipDeviceptr_t    hip_d_bitmap_s1_a;
  hipDeviceptr_t    hip_d_bitmap_s1_b;
  hipDeviceptr_t    hip_d_bitmap_s1_c;
  hipDeviceptr_t    hip_d_bitmap_s1_d;
  hipDeviceptr_t    hip_d_bitmap_s2_a;
  hipDeviceptr_t    hip_d_bitmap_s2_b;
  hipDeviceptr_t    hip_d_bitmap_s2_c;
  hipDeviceptr_t    hip_d_bitmap_s2_d;
  hipDeviceptr_t    hip_d_plain_bufs;
  hipDeviceptr_t    hip_d_digests_buf;
  hipDeviceptr_t    hip_d_digests_shown;
  hipDeviceptr_t    hip_d_salt_bufs;
  hipDeviceptr_t    hip_d_esalt_bufs;
  hipDeviceptr_t    hip_d_tmps;
  hipDeviceptr_t    hip_d_hooks;
  hipDeviceptr_t    hip_d_result;
  hipDeviceptr_t    hip_d_extra0_buf;
  hipDeviceptr_t    hip_d_extra1_buf;
  hipDeviceptr_t    hip_d_extra2_buf;
  hipDeviceptr_t    hip_d_extra3_buf;
  hipDeviceptr_t    hip_d_root_css_buf;
  hipDeviceptr_t    hip_d_markov_css_buf;
  hipDeviceptr_t    hip_d_st_digests_buf;
  hipDeviceptr_t    hip_d_st_salts_buf;
  hipDeviceptr_t    hip_d_st_esalts_buf;
  hipDeviceptr_t    hip_d_kernel_param;

  // API: opencl and metal

  bool              is_apple_silicon;

  // API: metal

  bool              is_metal;

  #if defined (__APPLE__)

  int               mtl_major;
  int               mtl_minor;

  int               device_physical_location;
  int               device_location_number;
  int               device_registryID;
  int               device_max_transfer_rate;
  int               device_is_headless;
  int               device_is_low_power;
  int               device_is_removable;

  int               metal_warp_size;

  mtl_device_id     metal_device;
  mtl_command_queue metal_command_queue;

  mtl_library       metal_library;
  mtl_library       metal_library_shared;
  mtl_library       metal_library_mp;
  mtl_library       metal_library_amp;

  mtl_function      metal_function1;
  mtl_function      metal_function12;
  mtl_function      metal_function2p;
  mtl_function      metal_function2;
  mtl_function      metal_function2e;
  mtl_function      metal_function23;
  mtl_function      metal_function3;
  mtl_function      metal_function4;
  mtl_function      metal_function_init2;
  mtl_function      metal_function_loop2p;
  mtl_function      metal_function_loop2;
  mtl_function      metal_function_mp;
  mtl_function      metal_function_mp_l;
  mtl_function      metal_function_mp_r;
  mtl_function      metal_function_amp;
  mtl_function      metal_function_tm;
  mtl_function      metal_function_memset;
  mtl_function      metal_function_bzero;
  mtl_function      metal_function_atinit;
  mtl_function      metal_function_utf8toutf16le;
  mtl_function      metal_function_decompress;
  mtl_function      metal_function_aux1;
  mtl_function      metal_function_aux2;
  mtl_function      metal_function_aux3;
  mtl_function      metal_function_aux4;

  mtl_pipeline      metal_pipeline1;
  mtl_pipeline      metal_pipeline12;
  mtl_pipeline      metal_pipeline2p;
  mtl_pipeline      metal_pipeline2;
  mtl_pipeline      metal_pipeline2e;
  mtl_pipeline      metal_pipeline23;
  mtl_pipeline      metal_pipeline3;
  mtl_pipeline      metal_pipeline4;
  mtl_pipeline      metal_pipeline_init2;
  mtl_pipeline      metal_pipeline_loop2p;
  mtl_pipeline      metal_pipeline_loop2;
  mtl_pipeline      metal_pipeline_mp;
  mtl_pipeline      metal_pipeline_mp_l;
  mtl_pipeline      metal_pipeline_mp_r;
  mtl_pipeline      metal_pipeline_amp;
  mtl_pipeline      metal_pipeline_tm;
  mtl_pipeline      metal_pipeline_memset;
  mtl_pipeline      metal_pipeline_bzero;
  mtl_pipeline      metal_pipeline_atinit;
  mtl_pipeline      metal_pipeline_utf8toutf16le;
  mtl_pipeline      metal_pipeline_decompress;
  mtl_pipeline      metal_pipeline_aux1;
  mtl_pipeline      metal_pipeline_aux2;
  mtl_pipeline      metal_pipeline_aux3;
  mtl_pipeline      metal_pipeline_aux4;

  mtl_mem           metal_d_pws_buf;
  mtl_mem           metal_d_pws_amp_buf;
  mtl_mem           metal_d_pws_comp_buf;
  mtl_mem           metal_d_pws_idx;
  mtl_mem           metal_d_rules;
  mtl_mem           metal_d_rules_c;
  mtl_mem           metal_d_combs;
  mtl_mem           metal_d_combs_c;
  mtl_mem           metal_d_bfs;
  mtl_mem           metal_d_bfs_c;
  mtl_mem           metal_d_tm_c;
  mtl_mem           metal_d_bitmap_s1_a;
  mtl_mem           metal_d_bitmap_s1_b;
  mtl_mem           metal_d_bitmap_s1_c;
  mtl_mem           metal_d_bitmap_s1_d;
  mtl_mem           metal_d_bitmap_s2_a;
  mtl_mem           metal_d_bitmap_s2_b;
  mtl_mem           metal_d_bitmap_s2_c;
  mtl_mem           metal_d_bitmap_s2_d;
  mtl_mem           metal_d_plain_bufs;
  mtl_mem           metal_d_digests_buf;
  mtl_mem           metal_d_digests_shown;
  mtl_mem           metal_d_salt_bufs;
  mtl_mem           metal_d_esalt_bufs;
  mtl_mem           metal_d_tmps;
  mtl_mem           metal_d_hooks;
  mtl_mem           metal_d_result;
  mtl_mem           metal_d_extra0_buf;
  mtl_mem           metal_d_extra1_buf;
  mtl_mem           metal_d_extra2_buf;
  mtl_mem           metal_d_extra3_buf;
  mtl_mem           metal_d_root_css_buf;
  mtl_mem           metal_d_markov_css_buf;
  mtl_mem           metal_d_st_digests_buf;
  mtl_mem           metal_d_st_salts_buf;
  mtl_mem           metal_d_st_esalts_buf;
  mtl_mem           metal_d_kernel_param;

  #endif // __APPLE__

  // API: opencl

  bool              is_opencl;

  char             *opencl_driver_version;
  char             *opencl_device_vendor;
  char             *opencl_device_version;
  char             *opencl_device_c_version;

  cl_device_type    opencl_device_type;
  cl_uint           opencl_device_vendor_id;
  u32               opencl_platform_id;
  cl_uint           opencl_platform_vendor_id;

  cl_device_id      opencl_device;
  cl_context        opencl_context;
  cl_command_queue  opencl_command_queue;

  cl_program        opencl_program;
  cl_program        opencl_program_shared;
  cl_program        opencl_program_mp;
  cl_program        opencl_program_amp;

  cl_kernel         opencl_kernel1;
  cl_kernel         opencl_kernel12;
  cl_kernel         opencl_kernel2p;
  cl_kernel         opencl_kernel2;
  cl_kernel         opencl_kernel2e;
  cl_kernel         opencl_kernel23;
  cl_kernel         opencl_kernel3;
  cl_kernel         opencl_kernel4;
  cl_kernel         opencl_kernel_init2;
  cl_kernel         opencl_kernel_loop2p;
  cl_kernel         opencl_kernel_loop2;
  cl_kernel         opencl_kernel_mp;
  cl_kernel         opencl_kernel_mp_l;
  cl_kernel         opencl_kernel_mp_r;
  cl_kernel         opencl_kernel_amp;
  cl_kernel         opencl_kernel_tm;
  cl_kernel         opencl_kernel_memset;
  cl_kernel         opencl_kernel_bzero;
  cl_kernel         opencl_kernel_atinit;
  cl_kernel         opencl_kernel_utf8toutf16le;
  cl_kernel         opencl_kernel_decompress;
  cl_kernel         opencl_kernel_aux1;
  cl_kernel         opencl_kernel_aux2;
  cl_kernel         opencl_kernel_aux3;
  cl_kernel         opencl_kernel_aux4;

  cl_mem            opencl_d_pws_buf;
  cl_mem            opencl_d_pws_amp_buf;
  cl_mem            opencl_d_pws_comp_buf;
  cl_mem            opencl_d_pws_idx;
  cl_mem            opencl_d_rules;
  cl_mem            opencl_d_rules_c;
  cl_mem            opencl_d_combs;
  cl_mem            opencl_d_combs_c;
  cl_mem            opencl_d_bfs;
  cl_mem            opencl_d_bfs_c;
  cl_mem            opencl_d_tm_c;
  cl_mem            opencl_d_bitmap_s1_a;
  cl_mem            opencl_d_bitmap_s1_b;
  cl_mem            opencl_d_bitmap_s1_c;
  cl_mem            opencl_d_bitmap_s1_d;
  cl_mem            opencl_d_bitmap_s2_a;
  cl_mem            opencl_d_bitmap_s2_b;
  cl_mem            opencl_d_bitmap_s2_c;
  cl_mem            opencl_d_bitmap_s2_d;
  cl_mem            opencl_d_plain_bufs;
  cl_mem            opencl_d_digests_buf;
  cl_mem            opencl_d_digests_shown;
  cl_mem            opencl_d_salt_bufs;
  cl_mem            opencl_d_esalt_bufs;
  cl_mem            opencl_d_tmps;
  cl_mem            opencl_d_hooks;
  cl_mem            opencl_d_result;
  cl_mem            opencl_d_extra0_buf;
  cl_mem            opencl_d_extra1_buf;
  cl_mem            opencl_d_extra2_buf;
  cl_mem            opencl_d_extra3_buf;
  cl_mem            opencl_d_root_css_buf;
  cl_mem            opencl_d_markov_css_buf;
  cl_mem            opencl_d_st_digests_buf;
  cl_mem            opencl_d_st_salts_buf;
  cl_mem            opencl_d_st_esalts_buf;
  cl_mem            opencl_d_kernel_param;

} hc_device_param_t;

typedef struct backend_ctx
{
  bool                enabled;

  // global rc

  bool                memory_hit_warning;
  bool                runtime_skip_warning;
  bool                kernel_build_warning;
  bool                kernel_create_warning;
  bool                kernel_accel_warnings;
  bool                extra_size_warning;
  bool                mixed_warnings;

  // generic

  void               *cuda;
  void               *hip;
  void               *mtl;
  void               *ocl;

  void               *nvrtc;
  void               *hiprtc;

  int                 backend_device_from_cuda[DEVICES_MAX];                              // from cuda device index to backend device index
  int                 backend_device_from_hip[DEVICES_MAX];                               // from hip device index to backend device index
  int                 backend_device_from_metal[DEVICES_MAX];                             // from metal device index to backend device index
  int                 backend_device_from_opencl[DEVICES_MAX];                            // from opencl device index to backend device index
  int                 backend_device_from_opencl_platform[CL_PLATFORMS_MAX][DEVICES_MAX]; // from opencl device index to backend device index (by platform)

  int                 backend_devices_cnt;
  int                 backend_devices_active;

  int                 cuda_devices_cnt;
  int                 cuda_devices_active;
  int                 hip_devices_cnt;
  int                 hip_devices_active;
  int                 metal_devices_cnt;
  int                 metal_devices_active;
  int                 opencl_devices_cnt;
  int                 opencl_devices_active;

  u64                 backend_devices_filter;

  hc_device_param_t  *devices_param;

  u32                 hardware_power_all;

  u64                 kernel_power_all;
  u64                 kernel_power_final; // we save that so that all divisions are done from the same base

  double              target_msec;

  bool                need_adl;
  bool                need_nvml;
  bool                need_nvapi;
  bool                need_sysfs_amdgpu;
  bool                need_sysfs_cpu;
  bool                need_iokit;

  int                 comptime;

  int                 force_jit_compilation;

  // cuda

  int                 rc_cuda_init;
  int                 rc_nvrtc_init;

  int                 nvrtc_driver_version;
  int                 cuda_driver_version;

  // hip

  int                 rc_hip_init;
  int                 rc_hiprtc_init;

  int                 hip_runtimeVersion;
  int                 hip_driverVersion;

  // metal

  int                 rc_metal_init;

  unsigned int        metal_runtimeVersion;
  char               *metal_runtimeVersionStr;

  // opencl

  cl_platform_id     *opencl_platforms;
  cl_uint             opencl_platforms_cnt;
  cl_device_id      **opencl_platforms_devices;
  cl_uint            *opencl_platforms_devices_cnt;
  char              **opencl_platforms_name;
  char              **opencl_platforms_vendor;
  cl_uint            *opencl_platforms_vendor_id;
  char              **opencl_platforms_version;

  cl_device_type      opencl_device_types_filter;

} backend_ctx_t;

typedef enum kernel_workload
{
  KERNEL_ACCEL_MIN   = 1,
  KERNEL_ACCEL_MAX   = 1024,
  KERNEL_LOOPS_MIN   = 1,
  KERNEL_LOOPS_MAX   = 1024,
  KERNEL_THREADS_MIN = 1,
  KERNEL_THREADS_MAX = 1024,

} kernel_workload_t;

#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_sysfs_amdgpu.h"
#include "ext_sysfs_cpu.h"
#include "ext_iokit.h"

typedef struct hm_attrs
{
  HM_ADAPTER_ADL          adl;
  HM_ADAPTER_NVML         nvml;
  HM_ADAPTER_NVAPI        nvapi;
  HM_ADAPTER_SYSFS_AMDGPU sysfs_amdgpu;
  HM_ADAPTER_SYSFS_CPU    sysfs_cpu;
  HM_ADAPTER_IOKIT        iokit;

  int od_version;

  bool buslanes_get_supported;
  bool corespeed_get_supported;
  bool fanspeed_get_supported;
  bool fanpolicy_get_supported;
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
  void *hm_sysfs_amdgpu;
  void *hm_sysfs_cpu;
  void *hm_iokit;

  hm_attrs_t *hm_device;

} hwmon_ctx_t;

#if defined (__APPLE__)
typedef struct cpu_set
{
  u32 count;

} cpu_set_t;
#endif

typedef struct
{
  char *buf;
  int   len;

} string_sized_t;

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
  HCFILE  fp;

  bool    enabled;

  char   *filename;
  u32     mode;

} debugfile_ctx_t;

typedef struct dictstat
{
  u64 cnt;

  struct stat stat;

  char encoding_from[64];
  char encoding_to[64];

  u8 hash_filename[16];

} dictstat_t;

typedef struct hashdump
{
  int version;

  hashes_t hashes;

} hashdump_t;

typedef struct dictstat_ctx
{
  bool enabled;

  char *filename;

  dictstat_t *base;

  #if defined (_WIN)
  u32    cnt;
  #else
  size_t cnt;
  #endif

} dictstat_ctx_t;

typedef struct loopback_ctx
{
  HCFILE  fp;

  bool    enabled;
  bool    unused;

  char   *filename;

} loopback_ctx_t;

typedef struct mf
{
  char mf_buf[0x400];
  int  mf_len;

} mf_t;

typedef struct outfile_ctx
{
  HCFILE  fp;

  u32     outfile_format;
  bool    outfile_autohex;

  char   *filename;

} outfile_ctx_t;

typedef struct pot
{
  char     plain_buf[HCBUFSIZ_SMALL];
  int      plain_len;

  hash_t   hash;

} pot_t;

typedef struct potfile_ctx
{
  HCFILE   fp;

  bool     enabled;

  char    *filename;

  u8      *out_buf; // allocates [HCBUFSIZ_LARGE];
  u8      *tmp_buf; // allocates [HCBUFSIZ_LARGE];

} potfile_ctx_t;

// this is a linked list structure of all the hashes with the same "key" (hash or hash + salt)

typedef struct pot_hash_node
{
  hash_t *hash_buf;

  struct pot_hash_node *next;

} pot_hash_node_t;

// Attention: this is only used when --show and --username are used together
// there could be multiple entries for each identical hash+salt combination
// (e.g. same hashes, but different user names... we want to print all of them!)
// that is why we use a linked list here

typedef struct pot_tree_entry
{
  pot_hash_node_t *nodes; // head of the linked list (under the field "hash_buf" it contains the sorting keys)

  // the hashconfig is required to distinguish between salted and non-salted hashes and to make sure
  // we compare the correct dgst_pos0...dgst_pos3

  hashconfig_t *hashconfig;

} pot_tree_entry_t;

typedef struct pot_orig_line_entry
{
  u8 *hash_buf;
  int hash_len;
  int line_pos;

} pot_orig_line_entry_t;

typedef struct restore_data
{
  int  version;
  char cwd[256];

  u32  dicts_pos;
  u32  masks_pos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

typedef struct pidfile_data
{
  u32 pid;

} pidfile_data_t;

typedef struct restore_ctx
{
  bool    enabled;

  bool    restore_execute;

  int     argc;
  char  **argv;

  char   *eff_restore_file;
  char   *new_restore_file;

  restore_data_t *rd;

  u32  dicts_pos_prev;
  u32  masks_pos_prev;
  u64  words_cur_prev;

} restore_ctx_t;

typedef struct pidfile_ctx
{
  u32   pid;
  char *filename;

  pidfile_data_t *pd;

  bool  pidfile_written;

} pidfile_ctx_t;

typedef struct out
{
  HCFILE fp;

  char   buf[HCBUFSIZ_SMALL];
  int    len;

} out_t;

typedef struct tuning_db_alias
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct tuning_db_entry
{
  const char *device_name;
  int         attack_mode;
  int         hash_mode;
  int         workload_profile;
  int         vector_width;
  int         kernel_accel;
  int         kernel_loops;

} tuning_db_entry_t;

typedef struct tuning_db
{
  bool enabled;

  tuning_db_alias_t *alias_buf;
  int                alias_cnt;
  int                alias_alloc;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;
  int                entry_alloc;

} tuning_db_t;

typedef struct wl_data
{
  bool enabled;

  char *buf;
  u64  incr;
  u64  avail;
  u64  cnt;
  u64  pos;

  bool    iconv_enabled;
  iconv_t iconv_ctx;
  char   *iconv_tmp;

  void (*func) (char *, u64, u64 *, u64 *);

} wl_data_t;

typedef struct user_options
{
  const char  *hc_bin;

  int          hc_argc;
  char       **hc_argv;

  bool         attack_mode_chgd;
  bool         autodetect;
  #ifdef WITH_BRAIN
  bool         brain_host_chgd;
  bool         brain_port_chgd;
  bool         brain_password_chgd;
  bool         brain_server_timer_chgd;
  #endif
  bool         hash_mode_chgd;
  bool         hccapx_message_pair_chgd;
  bool         identify;
  bool         increment_max_chgd;
  bool         increment_min_chgd;
  bool         kernel_accel_chgd;
  bool         kernel_loops_chgd;
  bool         kernel_threads_chgd;
  bool         nonce_error_corrections_chgd;
  bool         spin_damp_chgd;
  bool         backend_vector_width_chgd;
  bool         outfile_format_chgd;
  bool         remove_timer_chgd;
  bool         rp_gen_seed_chgd;
  bool         runtime_chgd;
  bool         segment_size_chgd;
  bool         workload_profile_chgd;
  bool         skip_chgd;
  bool         limit_chgd;
  bool         scrypt_tmto_chgd;
  bool         separator_chgd;

  bool         advice_disable;
  bool         benchmark;
  bool         benchmark_all;
  #ifdef WITH_BRAIN
  bool         brain_client;
  bool         brain_server;
  #endif
  bool         force;
  bool         deprecated_check_disable;
  bool         hwmon_disable;
  bool         hash_info;
  bool         hex_charset;
  bool         hex_salt;
  bool         hex_wordlist;
  bool         increment;
  bool         keep_guessing;
  bool         keyspace;
  bool         left;
  bool         logfile_disable;
  bool         loopback;
  bool         machine_readable;
  bool         markov_classic;
  bool         markov_disable;
  bool         markov_inverse;
  bool         backend_ignore_cuda;
  bool         backend_ignore_hip;
  bool         backend_ignore_metal;
  bool         backend_ignore_opencl;
  bool         optimized_kernel_enable;
  bool         multiply_accel_disable;
  bool         outfile_autohex;
  bool         potfile_disable;
  bool         progress_only;
  bool         quiet;
  bool         remove;
  bool         restore;
  bool         restore_disable;
  bool         self_test_disable;
  bool         show;
  bool         slow_candidates;
  bool         speed_only;
  bool         status;
  bool         status_json;
  bool         stdout_flag;
  bool         stdin_timeout_abort_chgd;
  bool         usage;
  bool         username;
  bool         veracrypt_pim_start_chgd;
  bool         veracrypt_pim_stop_chgd;
  bool         version;
  bool         wordlist_autohex_disable;
  #ifdef WITH_BRAIN
  char        *brain_host;
  char        *brain_password;
  char        *brain_session_whitelist;
  #endif
  char        *cpu_affinity;
  char        *custom_charset_4;
  char        *debug_file;
  char        *induction_dir;
  char        *keyboard_layout_mapping;
  char        *markov_hcstat2;
  char        *backend_devices;
  char        *opencl_device_types;
  char        *outfile;
  char        *outfile_check_dir;
  char        *potfile_path;
  char        *restore_file_path;
  char       **rp_files;
  char        *rp_gen_func_sel;
  char        *separator;
  char        *truecrypt_keyfiles;
  char        *veracrypt_keyfiles;
  const char  *custom_charset_1;
  const char  *custom_charset_2;
  const char  *custom_charset_3;
  const char  *encoding_from;
  const char  *encoding_to;
  const char  *rule_buf_l;
  const char  *rule_buf_r;
  const char  *session;
  u32          attack_mode;
  u32          backend_info;
  u32          bitmap_max;
  u32          bitmap_min;
  #ifdef WITH_BRAIN
  u32          brain_server_timer;
  u32          brain_client_features;
  u32          brain_port;
  u32          brain_session;
  u32          brain_attack;
  #endif
  u32          debug_mode;
  u32          hwmon_temp_abort;
  int          hash_mode;
  u32          hccapx_message_pair;
  u32          hook_threads;
  u32          increment_max;
  u32          increment_min;
  u32          kernel_accel;
  u32          kernel_loops;
  u32          kernel_threads;
  u32          markov_threshold;
  u32          nonce_error_corrections;
  u32          spin_damp;
  u32          backend_vector_width;
  u32          outfile_check_timer;
  u32          outfile_format;
  u32          remove_timer;
  u32          restore_timer;
  u32          rp_files_cnt;
  u32          rp_gen;
  u32          rp_gen_func_max;
  u32          rp_gen_func_min;
  u32          rp_gen_seed;
  u32          runtime;
  u32          scrypt_tmto;
  u32          segment_size;
  u32          status_timer;
  u32          stdin_timeout_abort;
  u32          veracrypt_pim_start;
  u32          veracrypt_pim_stop;
  u32          workload_profile;
  u64          limit;
  u64          skip;

} user_options_t;

typedef struct user_options_extra
{
  u32 attack_kern;

  u32 rule_len_r;
  u32 rule_len_l;

  u32 wordlist_mode;

  char   separator;

  char  *hc_hash;   // can be filename or string

  int    hc_workc;  // can be 0 in bf-mode = default mask
  char **hc_workv;

} user_options_extra_t;

typedef struct brain_ctx
{
  bool support;     // general brain support compiled in (server or client)
  bool enabled;     // brain support required by user request on command line

} brain_ctx_t;

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
  char *cache_dir;
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

  char *dict1;
  char *dict2;

  u32 combs_mode;
  u64 combs_cnt;

} combinator_ctx_t;

typedef struct mask_ctx
{
  bool   enabled;

  cs_t  *mp_sys;
  cs_t  *mp_usr;

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

  char  *mask;

  mf_t  *mfs;

} mask_ctx_t;

typedef struct cpt_ctx
{
  bool enabled;

  cpt_t     *cpt_buf;
  int        cpt_pos;
  time_t     cpt_start;
  u64        cpt_total;

} cpt_ctx_t;

typedef struct device_info
{
  bool    skipped_dev;
  bool    skipped_warning_dev;
  double  hashes_msec_dev;
  double  hashes_msec_dev_benchmark;
  double  exec_msec_dev;
  char   *speed_sec_dev;
  char   *guess_candidates_dev;
  #if defined(__APPLE__)
  char   *hwmon_fan_dev;
  #endif
  char   *hwmon_dev;
  int     corespeed_dev;
  int     memoryspeed_dev;
  double  runtime_msec_dev;
  u64     progress_dev;
  int     kernel_accel_dev;
  int     kernel_loops_dev;
  int     kernel_threads_dev;
  int     vector_width_dev;
  int     salt_pos_dev;
  int     innerloop_pos_dev;
  int     innerloop_left_dev;
  int     iteration_pos_dev;
  int     iteration_left_dev;
  char   *device_name;
  cl_device_type device_type;
  #ifdef WITH_BRAIN
  int     brain_link_client_id_dev;
  int     brain_link_status_dev;
  char   *brain_link_recv_bytes_dev;
  char   *brain_link_send_bytes_dev;
  char   *brain_link_recv_bytes_sec_dev;
  char   *brain_link_send_bytes_sec_dev;
  double  brain_link_time_recv_dev;
  double  brain_link_time_send_dev;
  #endif

} device_info_t;

typedef struct hashcat_status
{
  char       *hash_target;
  char       *hash_name;
  int         guess_mode;
  char       *guess_base;
  int         guess_base_offset;
  int         guess_base_count;
  double      guess_base_percent;
  char       *guess_mod;
  int         guess_mod_offset;
  int         guess_mod_count;
  double      guess_mod_percent;
  char       *guess_charset;
  int         guess_mask_length;
  char       *session;
  #ifdef WITH_BRAIN
  int         brain_session;
  int         brain_attack;
  char       *brain_rx_all;
  char       *brain_tx_all;
  #endif
  const char *status_string;
  int         status_number;
  char       *time_estimated_absolute;
  char       *time_estimated_relative;
  char       *time_started_absolute;
  char       *time_started_relative;
  double      msec_paused;
  double      msec_running;
  double      msec_real;
  int         digests_cnt;
  int         digests_done;
  int         digests_done_pot;
  int         digests_done_zero;
  int         digests_done_new;
  double      digests_percent;
  double      digests_percent_new;
  int         salts_cnt;
  int         salts_done;
  double      salts_percent;
  int         progress_mode;
  double      progress_finished_percent;
  u64         progress_cur;
  u64         progress_cur_relative_skip;
  u64         progress_done;
  u64         progress_end;
  u64         progress_end_relative_skip;
  u64         progress_ignore;
  u64         progress_rejected;
  double      progress_rejected_percent;
  u64         progress_restored;
  u64         progress_skip;
  u64         restore_point;
  u64         restore_total;
  double      restore_percent;
  int         cpt_cur_min;
  int         cpt_cur_hour;
  int         cpt_cur_day;
  double      cpt_avg_min;
  double      cpt_avg_hour;
  double      cpt_avg_day;
  char       *cpt;

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
  bool finish_shutdown;

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

  time_t runtime_start;
  time_t runtime_stop;

  hc_timer_t timer_running;     // timer on current dict
  hc_timer_t timer_paused;      // timer on current dict

  double  msec_paused;          // timer on current dict

  /**
   * read timeouts
   */

  u32  stdin_read_timeout_cnt;

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
  const char *dictfile;

  struct stat stat;

  u64 cached_cnt;
  u64 keyspace;

} cache_hit_t;

typedef struct cache_generate
{
  const char *dictfile;

  double percent;

  u64 comp;
  u64 cnt;
  u64 cnt2;

  time_t runtime;

} cache_generate_t;

typedef struct hashlist_parse
{
  u64 hashes_cnt;
  u64 hashes_avail;

} hashlist_parse_t;

#define MAX_OLD_EVENTS 10

typedef struct event_ctx
{
  char   old_buf[MAX_OLD_EVENTS][HCBUFSIZ_LARGE];
  size_t old_len[MAX_OLD_EVENTS];
  int    old_cnt;

  char   msg_buf[HCBUFSIZ_LARGE];
  size_t msg_len;
  bool   msg_newline;

  size_t prev_len;

  hc_thread_mutex_t mux_event;

} event_ctx_t;

#define MODULE_DEFAULT (void *) -1

typedef void (*MODULE_INIT) (void *);

typedef struct module_ctx
{
  size_t      module_context_size;
  int         module_interface_version;

  hc_dynlib_t module_handle;

  MODULE_INIT module_init;

  void      **hook_extra_params; // free for module to use (for instance: library handles)

  u32         (*module_attack_exec)             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  void       *(*module_benchmark_esalt)         (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  void       *(*module_benchmark_hook_salt)     (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_benchmark_mask)          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_benchmark_charset)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  salt_t     *(*module_benchmark_salt)          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_deprecated_notice)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos0)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos1)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos2)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos3)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_size)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_dictstat_disable)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_esalt_size)              (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_extra_tuningdb_block)    (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_forced_outfile_format)   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_hash_category)           (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_hash_name)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  int         (*module_hash_mode)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_hashes_count_min)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_hashes_count_max)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_hlfmt_disable)           (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_hook_salt_size)          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_hook_size)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_accel_min)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_accel_max)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_loops_min)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_loops_max)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_threads_min)      (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_kernel_threads_max)      (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_kern_type)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_opti_type)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_opts_type)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_outfile_check_disable)   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_outfile_check_nocomp)    (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_potfile_disable)         (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_potfile_keep_all_hashes) (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_pwdump_column)           (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_pw_min)                  (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_pw_max)                  (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_salt_min)                (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_salt_max)                (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_salt_type)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  char        (*module_separator)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_st_hash)                 (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_st_pass)                 (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_tmp_size)                (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_warmup_disable)          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);

  int         (*module_hash_binary_count)       (const hashes_t *);
  int         (*module_hash_binary_parse)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, hashes_t *);
  int         (*module_hash_binary_save)        (const hashes_t *, const u32, const u32, char **);

  int         (*module_hash_decode_postprocess) (const hashconfig_t *,       void *,       salt_t *,       void *,       void *,       hashinfo_t *, const user_options_t *, const user_options_extra_t *);
  int         (*module_hash_decode_potfile)     (const hashconfig_t *,       void *,       salt_t *,       void *,       void *,       hashinfo_t *, const char *, const int, void *);
  int         (*module_hash_decode_zero_hash)   (const hashconfig_t *,       void *,       salt_t *,       void *,       void *,       hashinfo_t *);
  int         (*module_hash_decode)             (const hashconfig_t *,       void *,       salt_t *,       void *,       void *,       hashinfo_t *, const char *, const int);
  int         (*module_hash_encode_potfile)     (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *,       char *,       int, const void *);
  int         (*module_hash_encode_status)      (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *,       char *,       int);
  int         (*module_hash_encode)             (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *,       char *,       int);

  u64         (*module_kern_type_dynamic)       (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *);
  u64         (*module_extra_buffer_size)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hashes_t *, const hc_device_param_t *);
  u64         (*module_extra_tmp_size)          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hashes_t *);
  char       *(*module_jit_build_options)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hashes_t *, const hc_device_param_t *);
  bool        (*module_jit_cache_disable)       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hashes_t *, const hc_device_param_t *);
  u32         (*module_deep_comp_kernel)        (const hashes_t *, const u32, const u32);
  int         (*module_hash_init_selftest)      (const hashconfig_t *, hash_t *);

  u64         (*module_hook_extra_param_size)   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  bool        (*module_hook_extra_param_init)   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const folder_config_t *, const backend_ctx_t *, void *);
  bool        (*module_hook_extra_param_term)   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const folder_config_t *, const backend_ctx_t *, void *);

  void        (*module_hook12)                  (hc_device_param_t *, const void *, const void *, const u32, const u64);
  void        (*module_hook23)                  (hc_device_param_t *, const void *, const void *, const u32, const u64);

  int         (*module_build_plain_postprocess) (const hashconfig_t *, const hashes_t *, const void *, const u32 *, const size_t, const int, u32 *, const size_t);

  bool        (*module_unstable_warning)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hc_device_param_t *);

  bool        (*module_potfile_custom_check)    (const hashconfig_t *, const hash_t *, const hash_t *, const void *);

} module_ctx_t;

typedef struct hashcat_ctx
{
  brain_ctx_t           *brain_ctx;
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
  module_ctx_t          *module_ctx;
  backend_ctx_t         *backend_ctx;
  outcheck_ctx_t        *outcheck_ctx;
  outfile_ctx_t         *outfile_ctx;
  pidfile_ctx_t         *pidfile_ctx;
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

typedef struct hook_thread_param
{
  int tid;
  int tsz;

  module_ctx_t *module_ctx;
  status_ctx_t *status_ctx;

  hc_device_param_t *device_param;

  void *hook_extra_param;
  void *hook_salts_buf;

  u32 salt_pos;
  u64 pws_cnt;

} hook_thread_param_t;

#define MAX_TOKENS     128
#define MAX_SIGNATURES 16

typedef struct hc_token
{
  int token_cnt;

  int signatures_cnt;
  const char *signatures_buf[MAX_SIGNATURES];

  int sep[MAX_TOKENS];

  const u8 *buf[MAX_TOKENS];
  int len[MAX_TOKENS];

  int len_min[MAX_TOKENS];
  int len_max[MAX_TOKENS];

  int attr[MAX_TOKENS];

  const u8 *opt_buf;
  int opt_len;

} hc_token_t;

/**
 * hash category is relevant in usage.c (--help screen)
 */

typedef enum hash_category
{
  HASH_CATEGORY_UNDEFINED               = 0,
  HASH_CATEGORY_RAW_HASH                = 1,
  HASH_CATEGORY_RAW_HASH_SALTED         = 2,
  HASH_CATEGORY_RAW_HASH_AUTHENTICATED  = 3,
  HASH_CATEGORY_RAW_CHECKSUM            = 4,
  HASH_CATEGORY_RAW_CIPHER_KPA          = 5,
  HASH_CATEGORY_GENERIC_KDF             = 6,
  HASH_CATEGORY_NETWORK_PROTOCOL        = 7,
  HASH_CATEGORY_OS                      = 8,
  HASH_CATEGORY_DATABASE_SERVER         = 9,
  HASH_CATEGORY_NETWORK_SERVER          = 10,
  HASH_CATEGORY_EAS                     = 11,
  HASH_CATEGORY_FDE                     = 12,
  HASH_CATEGORY_DOCUMENTS               = 13,
  HASH_CATEGORY_PASSWORD_MANAGER        = 14,
  HASH_CATEGORY_ARCHIVE                 = 15,
  HASH_CATEGORY_FORUM_SOFTWARE          = 16,
  HASH_CATEGORY_OTP                     = 17,
  HASH_CATEGORY_PLAIN                   = 18,
  HASH_CATEGORY_FRAMEWORK               = 19,
  HASH_CATEGORY_PRIVATE_KEY             = 20,
  HASH_CATEGORY_IMS                     = 21,
  HASH_CATEGORY_CRYPTOCURRENCY_WALLET   = 22,
  HASH_CATEGORY_FBE                     = 23
} hash_category_t;

// hash specific

typedef aes_ctx AES_KEY;

#endif // _TYPES_H
