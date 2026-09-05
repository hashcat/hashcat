/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_TYPES_H
#define HC_TYPES_H

#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>

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
#if defined (__APPLE__)
#include <dispatch/dispatch.h>
#else
#include <semaphore.h>
#endif // __APPLE__
#endif // _POSIX

#if defined (_WIN)
typedef HANDLE             hc_thread_t;
typedef CRITICAL_SECTION   hc_thread_mutex_t;
typedef CONDITION_VARIABLE hc_thread_cond_t;
typedef HANDLE             hc_thread_semaphore_t;
#else
typedef pthread_t          hc_thread_t;
typedef pthread_mutex_t    hc_thread_mutex_t;
typedef pthread_cond_t     hc_thread_cond_t;

#if defined (__APPLE__)
typedef dispatch_semaphore_t hc_thread_semaphore_t;
#else
typedef sem_t                hc_thread_semaphore_t;
#endif // __APPLE__
#endif // _WIN

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
  EVENT_BACKEND_RUNTIMES_INIT_POST = 0x00000130,
  EVENT_BACKEND_RUNTIMES_INIT_PRE  = 0x00000131,
  EVENT_BACKEND_DEVICES_INIT_POST = 0x00000132,
  EVENT_BACKEND_DEVICES_INIT_PRE  = 0x00000133,
  EVENT_BITMAP_INIT_POST          = 0x00000010,
  EVENT_BITMAP_INIT_PRE           = 0x00000011,
  EVENT_BITMAP_FINAL_OVERFLOW     = 0x00000012,
  EVENT_BRIDGES_INIT_POST         = 0x00000120,
  EVENT_BRIDGES_INIT_PRE          = 0x00000121,
  EVENT_CANDIDATE_SOURCE_POST     = 0x00000142,
  EVENT_CANDIDATE_SOURCE_PRE      = 0x00000143,
  EVENT_BRIDGES_SALT_POST         = 0x00000122,
  EVENT_BRIDGES_SALT_PRE          = 0x00000123,
  EVENT_CALCULATED_WORDS_BASE     = 0x00000020,
  EVENT_CALCULATED_WORDS_CNT      = 0x00000021,
  EVENT_CLEAR_EVENT_LINE          = 0x00001000,
  EVENT_CRACKER_FINISHED          = 0x00000030,
  EVENT_CRACKER_HASH_CRACKED      = 0x00000031,
  EVENT_CRACKER_STARTING          = 0x00000032,
  EVENT_GENERIC_INIT_POST         = 0x00000140,
  EVENT_GENERIC_INIT_PRE          = 0x00000141,
  EVENT_HASHCONFIG_PRE            = 0x00000040,
  EVENT_HASHCONFIG_POST           = 0x00000041,
  EVENT_HASHLIST_COUNT_LINES_POST = 0x00000050,
  EVENT_HASHLIST_COUNT_LINES_PRE  = 0x00000051,
  EVENT_HASHLIST_PARSE_HASH       = 0x00000052,
  EVENT_HASHLIST_PARSE_INPUT_POST = 0x00000059,
  EVENT_HASHLIST_PARSE_INPUT_PRE  = 0x0000005a,
  EVENT_KERNEL_BUILD_POST         = 0x00000144,
  EVENT_KERNEL_BUILD_PRE          = 0x00000145,
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
  EVENT_MONITOR_TEMP_ABORT_FEEDER = 0x00000099,
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
  EVENT_RULESFILES_PARSE_POST     = 0x000000d4,
  EVENT_RULESFILES_PARSE_PRE      = 0x000000d5,
  EVENT_SELFTEST_FINISHED         = 0x000000e0,
  EVENT_SELFTEST_STARTING         = 0x000000e1,
  EVENT_SET_KERNEL_POWER_FINAL    = 0x000000f0,
  EVENT_WORDLIST_CACHE_GENERATE   = 0x00000110,
  EVENT_WORDLIST_CACHE_HIT        = 0x00000111,

  // there will be much more event types soon

} event_identifier_t;

typedef enum amplifier_count
{
  KERNEL_BFS                        = 1024,
  KERNEL_COMBS                      = 1024,
  KERNEL_RULES                      = 256,

} amplifier_count_t;

// How many pieces one amplifier item is cut into. Every attack mode but -a 12 uses one, the single
// buffer that is appended to the base word. -a 12 uses four: the mask in front of the base word, the
// mask between the two words, the second word, and the mask behind the last word.

#define COMBS_PIECE_CNT 4

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
  VENDOR_ID_MICROSOFT     = (1U << 9),
  VENDOR_ID_GENERIC       = (1U << 31)

} vendor_id_t;

// Where device_available_mem came from. The difference that matters is whether it was measured or
// guessed: a guess has to be padded against desktop activity, a measurement must not be, because
// padding a good number throws away a third of the card for nothing.

// Private memory per work item beyond which a kernel is treated as spill-heavy and given the native
// thread count. Measured on an RTX 4090 across the 481 shipped modules that report a figure: 392 of
// them stay under 1024 bytes, and the largest that is not spill-heavy is BestCrypt v4 at 6336. Above
// the cut are yescrypt at 8800, gost-yescrypt at 10032, MD6 at 16400, Electrum salt-type 5 at 46696,
// and the 3 PKZIP inflate kernels at 77688. Nothing measures between 6336 and 8800, so the cut sits
// in an empty range and does not depend on where exactly it falls.
//
// The guard reaches 2 of those 7. The PKZIP modules ask for the native thread count themselves, and
// the 2 yescrypt modes pin a thread count the guard leaves alone.

#define SPILL_HEAVY_PRIVATE_BYTES 8192

typedef enum mem_source
{
  MEM_SOURCE_UNKNOWN   = 0,   // nothing asked; derived from the physical size
  MEM_SOURCE_RUNTIME   = 1,   // cuMemGetInfo () / hipMemGetInfo ()
  MEM_SOURCE_ALIAS     = 2,   // copied from the CUDA or HIP view of the same device
  MEM_SOURCE_EXTENSION = 3,   // CL_DEVICE_GLOBAL_FREE_MEMORY_AMD
  MEM_SOURCE_HWMON     = 4,   // the hardware monitor's used-memory reading
  MEM_SOURCE_PROBE     = 5,   // measured by allocating until it fails

} mem_source_t;

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

typedef enum rc_final
{
  RC_FINAL_ERROR            = -1,
  RC_FINAL_OK               = 0,
  RC_FINAL_EXHAUSTED        = 1,
  RC_FINAL_ABORT            = 2,
  RC_FINAL_ABORT_CHECKPOINT = 3,
  RC_FINAL_ABORT_RUNTIME    = 4,
  RC_FINAL_ABORT_FINISH     = 5,

} rc_final_t;

typedef enum wl_mode
{
  WL_MODE_NONE    = 0,
  WL_MODE_STDIN   = 1,
  WL_MODE_MASK    = 2,
  WL_MODE_GENERIC = 3,

} wl_mode_t;

// Where an attack takes its base words from. This is not the attack mode and must not be confused with
// it: the attack mode says what the user asked for, this says which producer fills a batch. The two
// disagree wherever the same mode can take its base words from more than one place. -a 7 is the
// clearest: under the optimized kernel the dictionary is the base and the mask is the amplifier, and
// under the pure kernel it is the other way round.
//
// The alternative was to rewrite the attack mode itself, which is what hashcat used to do. Every test
// on the attack mode that ran afterwards then silently meant something else, and --loopback stopped
// working with no message because of exactly that.

typedef enum base_source
{
  BASE_SOURCE_NONE = 0,
  BASE_SOURCE_MASK = 1,
  BASE_SOURCE_FEED = 2,

} base_source_t;

// Where the ?w marker goes on a mask that was not typed with one. -a 1, -a 6 and -a 7 are rewritten
// into -a 12 masks, and the marker is put on each mask as it is appended rather than on the argument,
// so that a mask file gets it per line and --increment gets it per length.

typedef enum marker_policy
{
  MARKER_POLICY_NONE     = 0,
  MARKER_POLICY_PREFIX_W = 1,
  MARKER_POLICY_SUFFIX_W = 2,

} marker_policy_t;

// How much of the attack one feed instance covers.
//
// Normally all of it: every dictionary is laid end to end into one keyspace, which is what makes
// --skip and --limit work across all of them and what -a 0 has done since the flip.
//
// Two things cannot be expressed that way, and both are a queue of attacks rather than one attack.
// An induction round produces its dictionary during the run, so it does not exist when the instance
// would have to be opened. -a 9 pairs word N with salt N, so several dictionaries are several
// attacks over the same salts and laying them end to end would change what the run means. Both get
// one instance per round over the one dictionary that round reads.

typedef enum base_scope
{
  BASE_SCOPE_ALL_SOURCES = 0,
  BASE_SCOPE_PER_ROUND   = 1,

} base_scope_t;

// Which lengths an attack will accept for a base word, and the whole of the difference between the
// attack modes on that question.
//
// -a 0 applies both of the hash mode's bounds, because a base word is already the whole candidate. The
// combinator kernels apply only the upper one: the base word is half a candidate and the other half has
// not been added yet, so a short one is not too short. -a 9 applies neither, and that is not a relaxation
// but a requirement. Word N belongs to salt N, so dropping one moves every later word onto the wrong
// hash.

typedef enum base_length
{
  BASE_LENGTH_BOTH = 0,
  BASE_LENGTH_MAX  = 1,
  BASE_LENGTH_NONE = 2,

} base_length_t;

typedef enum hl_mode
{
  HL_MODE_ARG         = 2,
  HL_MODE_FILE_PLAIN  = 5,
  HL_MODE_FILE_BINARY = 6,

} hl_mode_t;

typedef enum attack_mode
{
  ATTACK_MODE_STRAIGHT    = 0,
  ATTACK_MODE_COMBI       = 1,
  ATTACK_MODE_TOGGLE      = 2,
  ATTACK_MODE_BF          = 3,
  ATTACK_MODE_PCFG        = 4,
  ATTACK_MODE_TABLE       = 5,
  ATTACK_MODE_HYBRID1     = 6,
  ATTACK_MODE_HYBRID2     = 7,
  ATTACK_MODE_GENERIC     = 8,
  ATTACK_MODE_ASSOCIATION = 9,
  ATTACK_MODE_HYBRID      = 12,
  ATTACK_MODE_NONE        = 100

} attack_mode_t;

typedef enum attack_kern
{
  ATTACK_KERN_STRAIGHT  = 0,
  ATTACK_KERN_COMBI     = 1,
  ATTACK_KERN_PCFG      = 2,
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
  RULE_OP_MANGLE_NOOP              = ':',
  RULE_OP_MANGLE_LREST             = 'l',
  RULE_OP_MANGLE_UREST             = 'u',
  RULE_OP_MANGLE_LREST_UFIRST      = 'c',
  RULE_OP_MANGLE_UREST_LFIRST      = 'C',
  RULE_OP_MANGLE_TREST             = 't',
  RULE_OP_MANGLE_SHIFT_CASE        = 'S',
  RULE_OP_MANGLE_TOGGLE_AT         = 'T',
  RULE_OP_MANGLE_TOGGLE_AT_SEP     = '3',
  RULE_OP_MANGLE_REVERSE           = 'r',
  RULE_OP_MANGLE_DUPEWORD          = 'd',
  RULE_OP_MANGLE_DUPEWORD_TIMES    = 'p',
  RULE_OP_MANGLE_REFLECT           = 'f',
  RULE_OP_MANGLE_ROTATE_LEFT       = '{',
  RULE_OP_MANGLE_ROTATE_RIGHT      = '}',
  RULE_OP_MANGLE_APPEND            = '$',
  RULE_OP_MANGLE_PREPEND           = '^',
  RULE_OP_MANGLE_DELETE_FIRST      = '[',
  RULE_OP_MANGLE_DELETE_LAST       = ']',
  RULE_OP_MANGLE_DELETE_AT         = 'D',
  RULE_OP_MANGLE_EXTRACT           = 'x',
  RULE_OP_MANGLE_OMIT              = 'O',
  RULE_OP_MANGLE_INSERT            = 'i',
  RULE_OP_MANGLE_OVERSTRIKE        = 'o',
  RULE_OP_MANGLE_TRUNCATE_AT       = '\'',
  RULE_OP_MANGLE_REPLACE           = 's',
  RULE_OP_MANGLE_PURGECHAR         = '@',
  RULE_OP_MANGLE_TOGGLECASE_REC    = 'a',
  RULE_OP_MANGLE_DUPECHAR_FIRST    = 'z',
  RULE_OP_MANGLE_DUPECHAR_LAST     = 'Z',
  RULE_OP_MANGLE_DUPECHAR_ALL      = 'q',
  RULE_OP_MANGLE_EXTRACT_MEMORY    = 'X',
  RULE_OP_MANGLE_APPEND_MEMORY     = '4',
  RULE_OP_MANGLE_PREPEND_MEMORY    = '6',
  RULE_OP_MANGLE_TITLE_SEP         = 'e',

  RULE_OP_MEMORIZE_WORD            = 'M',

  RULE_OP_REJECT_LESS              = '<',
  RULE_OP_REJECT_GREATER           = '>',
  RULE_OP_REJECT_EQUAL             = '_',
  RULE_OP_REJECT_CONTAIN           = '!',
  RULE_OP_REJECT_NOT_CONTAIN       = '/',
  RULE_OP_REJECT_EQUAL_FIRST       = '(',
  RULE_OP_REJECT_EQUAL_LAST        = ')',
  RULE_OP_REJECT_EQUAL_AT          = '=',
  RULE_OP_REJECT_CONTAINS          = '%',
  RULE_OP_REJECT_MEMORY            = 'Q',
  RULE_LAST_REJECTED_SAVED_POS     = 'p',

  RULE_OP_MANGLE_SWITCH_FIRST      = 'k',
  RULE_OP_MANGLE_SWITCH_LAST       = 'K',
  RULE_OP_MANGLE_SWITCH_AT         = '*',
  RULE_OP_MANGLE_CHR_SHIFTL        = 'L',
  RULE_OP_MANGLE_CHR_SHIFTR        = 'R',
  RULE_OP_MANGLE_CHR_INCR          = '+',
  RULE_OP_MANGLE_CHR_DECR          = '-',
  RULE_OP_MANGLE_CHR_ADD           = 'B',
  RULE_OP_MANGLE_REPLACE_NP1       = '.',
  RULE_OP_MANGLE_REPLACE_NM1       = ',',
  RULE_OP_MANGLE_DUPEBLOCK_FIRST   = 'y',
  RULE_OP_MANGLE_DUPEBLOCK_LAST    = 'Y',
  RULE_OP_MANGLE_TITLE             = 'E',
  RULE_OP_MANGLE_TO_HEX_LOWER      = 'h',
  RULE_OP_MANGLE_TO_HEX_UPPER      = 'H',
  RULE_OP_MANGLE_INSERT_EVERY      = 'v',


  /* using character classes */
  RULE_OP_CLASS_BASED              = '~',
  RULE_OP_MANGLE_REPLACE_CLASS     = 0x01,
  RULE_OP_MANGLE_PURGECHAR_CLASS   = 0x02,
  RULE_OP_MANGLE_TITLE_SEP_CLASS   = 0x03,
  RULE_OP_REJECT_CONTAIN_CLASS     = 0x04,
  RULE_OP_REJECT_NOT_CONTAIN_CLASS = 0x05,
  RULE_OP_REJECT_EQUAL_FIRST_CLASS = 0x06,
  RULE_OP_REJECT_EQUAL_LAST_CLASS  = 0x07,
  RULE_OP_REJECT_EQUAL_AT_CLASS    = 0x08,
  RULE_OP_REJECT_CONTAINS_CLASS    = 0x09,

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
  OPTI_TYPE_SLOW_HASH_DIMY_INIT   = (1 << 23),
  OPTI_TYPE_SLOW_HASH_DIMY_LOOP   = (1 << 24),
  OPTI_TYPE_SLOW_HASH_DIMY_COMP   = (1 << 25),

} opti_type_t;

typedef enum opts_type
{
  OPTS_TYPE_PT_UTF16LE               = (1ULL <<  0),
  OPTS_TYPE_PT_UTF16BE               = (1ULL <<  1),
  OPTS_TYPE_PT_UPPER                 = (1ULL <<  2),
  OPTS_TYPE_PT_LOWER                 = (1ULL <<  3),
  OPTS_TYPE_PT_ADD01                 = (1ULL <<  4),
  OPTS_TYPE_PT_ADD02                 = (1ULL <<  5),
  OPTS_TYPE_PT_ADD80                 = (1ULL <<  6),
  OPTS_TYPE_PT_ADDBITS14             = (1ULL <<  7),
  OPTS_TYPE_PT_ADDBITS15             = (1ULL <<  8),
  OPTS_TYPE_PT_GENERATE_LE           = (1ULL <<  9),
  OPTS_TYPE_PT_GENERATE_BE           = (1ULL << 10),
  OPTS_TYPE_PT_NEVERCRACK            = (1ULL << 11), // if we want all possible results
  OPTS_TYPE_PT_ALWAYS_ASCII          = (1ULL << 12),
  OPTS_TYPE_PT_ALWAYS_HEXIFY         = (1ULL << 13),
  OPTS_TYPE_PT_LM                    = (1ULL << 14), // special handling: all lower, 7 max, ...
  OPTS_TYPE_PT_HEX                   = (1ULL << 15), // input wordlist is always in hex
  OPTS_TYPE_PT_BASE58                = (1ULL << 16), // only informative
  OPTS_TYPE_ST_UTF16LE               = (1ULL << 17),
  OPTS_TYPE_ST_UTF16BE               = (1ULL << 18),
  OPTS_TYPE_ST_UPPER                 = (1ULL << 19),
  OPTS_TYPE_ST_LOWER                 = (1ULL << 20),
  OPTS_TYPE_ST_ADD01                 = (1ULL << 21),
  OPTS_TYPE_ST_ADD02                 = (1ULL << 22),
  OPTS_TYPE_ST_ADD80                 = (1ULL << 23),
  OPTS_TYPE_ST_ADDBITS14             = (1ULL << 24),
  OPTS_TYPE_ST_ADDBITS15             = (1ULL << 25),
  OPTS_TYPE_ST_HEX                   = (1ULL << 26),
  OPTS_TYPE_ST_BASE64                = (1ULL << 27),
  OPTS_TYPE_MT_HEX                   = (1ULL << 28), // mask is always in hex
  OPTS_TYPE_HASH_COPY                = (1ULL << 29),
  OPTS_TYPE_HASH_SPLIT               = (1ULL << 30),
  OPTS_TYPE_INIT                     = (1ULL << 31), // Added v7, since bridge can fully replace these, but are set by default automatically
  OPTS_TYPE_LOOP                     = (1ULL << 32), // Added v7, since bridge can fully replace these, but are set by default automatically
  OPTS_TYPE_COMP                     = (1ULL << 33), // Added v7, since bridge can fully replace these, but are set by default automatically
  OPTS_TYPE_LOOP_PREPARE             = (1ULL << 34), // a kernel which is called each time before _loop kernel started.
                                                     // like a hook12 kernel but without extra buffers.
  OPTS_TYPE_LOOP_EXTENDED            = (1ULL << 35), // a kernel which is called each time normal _loop kernel finished.
                                                     // but unlike a hook kernel this kernel is called for every _loop iteration offset
  OPTS_TYPE_HOOK12                   = (1ULL << 36),
  OPTS_TYPE_HOOK23                   = (1ULL << 37),
  OPTS_TYPE_INIT2                    = (1ULL << 38),
  OPTS_TYPE_LOOP2_PREPARE            = (1ULL << 39), // same as OPTS_TYPE_LOOP_PREPARE but for loop2 kernel
  OPTS_TYPE_LOOP2                    = (1ULL << 40),
  OPTS_TYPE_AUX1                     = (1ULL << 41),
  OPTS_TYPE_AUX2                     = (1ULL << 42),
  OPTS_TYPE_AUX3                     = (1ULL << 43),
  OPTS_TYPE_AUX4                     = (1ULL << 44),
  OPTS_TYPE_BINARY_HASHFILE          = (1ULL << 45),
  OPTS_TYPE_BINARY_HASHFILE_OPTIONAL = (1ULL << 46), // this allows us to not enforce the use of a binary file. requires OPTS_TYPE_BINARY_HASHFILE set to be effective.
  OPTS_TYPE_PT_ADD06                 = (1ULL << 47),
  OPTS_TYPE_KEYBOARD_MAPPING         = (1ULL << 48),
  OPTS_TYPE_DEEP_COMP_KERNEL         = (1ULL << 49), // if we have to iterate through each hash inside the comp kernel, for example if each hash has to be decrypted separately
  OPTS_TYPE_TM_KERNEL                = (1ULL << 50),
  OPTS_TYPE_SUGGEST_KG               = (1ULL << 51), // suggest keep guessing for modules the user maybe wants to use --keep-guessing
  OPTS_TYPE_COPY_TMPS                = (1ULL << 52), // if we want to use data from tmps buffer (for example get the PMK in WPA)
  OPTS_TYPE_POTFILE_NOPASS           = (1ULL << 53), // sometimes the password should not be printed to potfile
  OPTS_TYPE_DYNAMIC_SHARED           = (1ULL << 54), // use dynamic shared memory (note: needs special kernel changes)
  OPTS_TYPE_SELF_TEST_DISABLE        = (1ULL << 55), // some algos use JiT in combinations with a salt or create too much startup time
  OPTS_TYPE_MP_MULTI_DISABLE         = (1ULL << 56), // do not multiply the kernel-accel with the multiprocessor count per device to allow more fine-tuned workload settings
  OPTS_TYPE_THREAD_MULTI_DISABLE     = (1ULL << 57), // do not multiply the kernel-power with the thread count per device for super slow algos
  OPTS_TYPE_NATIVE_THREADS           = (1ULL << 58), // forces "native" thread count: CPU=1, GPU-Intel=8, GPU-AMD=64 (wavefront), GPU-NV=32 (warps)
  OPTS_TYPE_MAXIMUM_THREADS          = (1ULL << 59), // disable else branch in pre-compilation thread count optimization setting
  OPTS_TYPE_POST_AMP_UTF16LE         = (1ULL << 60), // run the utf8 to utf16le conversion kernel after they have been processed from amplifiers
  OPTS_TYPE_AUTODETECT_DISABLE       = (1ULL << 61), // skip autodetect engine
  OPTS_TYPE_STOCK_MODULE             = (1ULL << 62), // module included with hashcat default distribution
  OPTS_TYPE_MULTIHASH_DESPITE_ESALT  = (1ULL << 63)  // overrule multihash cracking check same salt but not same esalt
//OPTS_TYPE_MAXIMUM_ACCEL            = (1ULL << 64)  // try to maximize kernel-accel during autotune

} opts_type_t;

typedef enum bridge_type
{
  BRIDGE_TYPE_NONE                   = 0,            // no bridge support
  BRIDGE_TYPE_UPDATE_SELFTEST        = (1ULL <<  2), // updates the selftest configured in the module. Can be useful for generic hash modes such as the python one

  // launch_loop() honours kernel_param.loop_pos and .loop_cnt, so hashcat may split the salt's
  // iteration space into chunks and call it once per chunk. Without this the bridge is handed the
  // whole range in a single call, which is what a one-shot implementation needs.

  BRIDGE_TYPE_LOOP_CHUNKED           = (1ULL <<  3),

  BRIDGE_TYPE_LAUNCH_INIT            = (1ULL << 10), // attention! not yet implemented
  BRIDGE_TYPE_LAUNCH_LOOP            = (1ULL << 11),
  BRIDGE_TYPE_LAUNCH_LOOP2           = (1ULL << 12),
  BRIDGE_TYPE_LAUNCH_COMP            = (1ULL << 13), // attention! not yet implemented

  // BRIDGE_TYPE_REPLACE_* is like
  // BRIDGE_TYPE_LAUNCH_*, but
  // deactivates KERN_RUN INIT/LOOP/COMP

  BRIDGE_TYPE_REPLACE_INIT           = (1ULL << 20), // attention! not yet implemented
  BRIDGE_TYPE_REPLACE_LOOP           = (1ULL << 21),
  BRIDGE_TYPE_REPLACE_LOOP2          = (1ULL << 22),
  BRIDGE_TYPE_REPLACE_COMP           = (1ULL << 23), // attention! not yet implemented

} bridge_type_t;

typedef enum dgst_size
{
  DGST_SIZE_4_2  = (2  * sizeof (u32)), // 8
  DGST_SIZE_4_4  = (4  * sizeof (u32)), // 16 !!!
  DGST_SIZE_4_5  = (5  * sizeof (u32)), // 20
  DGST_SIZE_4_6  = (6  * sizeof (u32)), // 24
  DGST_SIZE_4_7  = (7  * sizeof (u32)), // 28
  DGST_SIZE_4_8  = (8  * sizeof (u32)), // 32
  DGST_SIZE_4_10 = (10 * sizeof (u32)), // 40
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
  PARSER_PT_LENGTH            = -44,
  PARSER_PT_OFFSET            = -45,
  PARSER_CRYPTOAPI_KERNELTYPE = -46,
  PARSER_CRYPTOAPI_KEYSIZE    = -47,
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
  GUESS_MODE_GENERIC                    = 15,
  GUESS_MODE_GENERIC_RULES_FILE         = 16,
  GUESS_MODE_GENERIC_RULES_GEN          = 17,
  GUESS_MODE_HYBRID                     = 18,
  GUESS_MODE_HYBRID_CS                  = 19,
  GUESS_MODE_HYBRID_Q                   = 20,
  GUESS_MODE_HYBRID_Q_CS                = 21,

} guess_mode_t;

typedef enum progress_mode
{
  PROGRESS_MODE_NONE              = 0,
  PROGRESS_MODE_KEYSPACE_KNOWN    = 1,
  PROGRESS_MODE_KEYSPACE_UNKNOWN  = 2,

} progress_mode_t;

typedef enum increment {
  INCREMENT_NONE      = 0,
  INCREMENT_NORMAL    = 1,
  INCREMENT_INVERSED  = 2,
} increment_t;

typedef enum user_options_defaults
{
  ADVICE                   = true,
  ATTACK_MODE              = ATTACK_MODE_STRAIGHT,
  AUTODETECT               = false,
  BACKEND_DEVICES_VIRTMULTI = 1,
  BACKEND_DEVICES_VIRTHOST = 1,
  BENCHMARK_ALL            = false,
  BENCHMARK_MAX            = 99999,
  BENCHMARK_MIN            = 0,
  BENCHMARK                = false,
  BITMAP_MAX               = 24,
  BITMAP_MIN               = 10,
  #ifdef WITH_BRAIN
  BRAIN_CLIENT             = false,
  BRAIN_CLIENT_FEATURES    = 3,
  BRAIN_PORT               = 6863,
  BRAIN_SERVER             = false,
  BRAIN_SESSION            = 0,
  #endif
  COLOR_CRACKED            = false,
  DEBUG_MODE               = 0,
  DEPRECATED_CHECK         = true,
  DYNAMIC_X                = false,
  FORCE                    = false,
  HWMON                    = true,
  #if defined (__APPLE__)
  HWMON_TEMP_ABORT         = 100,
  #else
  HWMON_TEMP_ABORT         = 90,
  #endif
  HASH_COPY                = false,
  HASH_INFO                = 0,
  HASH_MODE                = 0,
  HCCAPX_MESSAGE_PAIR      = 0,
  HEX_CHARSET              = false,
  HEX_SALT                 = false,
  HEX_WORDLIST             = false,
  HOOK_THREADS             = 0,
  IDENTIFY                 = false,
  INCREMENT                = INCREMENT_NONE,
  INCREMENT_INVERSE        = false,
  INCREMENT_MAX            = PW_MAX,
  INCREMENT_MIN            = 1,
  KEEP_GUESSING            = false,
  KERNEL_ACCEL             = 0,
  KERNEL_LOOPS             = 0,
  KERNEL_THREADS           = 0,
  KEYSPACE                 = false,
  TOTAL_CANDIDATES         = false,
  LEFT                     = false,
  LIMIT                    = 0,
  LOGFILE                  = true,
  LOOPBACK                 = false,
  MACHINE_READABLE         = false,
  MARKOV_CLASSIC           = false,
  MARKOV                   = true,
  MARKOV_INVERSE           = false,
  MARKOV_THRESHOLD         = 0,
  METAL_COMPILER_RUNTIME   = 120,
  NONCE_ERROR_CORRECTIONS  = 8,
  BACKEND_IGNORE_CUDA      = false,
  BACKEND_IGNORE_HIP       = false,
  #if defined (__APPLE__)
  BACKEND_IGNORE_METAL     = false,
  #endif
  BACKEND_IGNORE_OPENCL    = false,
  BACKEND_INFO             = 0,
  BACKEND_VECTOR_WIDTH     = 0,
  OPTIMIZED_KERNEL         = false,
  MULTIPLY_ACCEL           = true,
  OUTFILE_AUTOHEX          = true,
  OUTFILE_CHECK_TIMER      = 5,
  OUTFILE_FORMAT           = 3,
  OUTFILE_JSON             = false,
  POTFILE                  = true,
  PROGRESS_ONLY            = false,
  QUIET                    = false,
  REMOVE                   = false,
  REMOVE_TIMER             = 60,
  RESTORE_ENABLE           = true,
  RESTORE                  = false,
  RESTORE_POSITION         = false,
  RESTORE_TIMER            = 1,
  RP_GEN                   = 0,
  RP_GEN_FUNC_MAX          = 4,
  RP_GEN_FUNC_MIN          = 1,
  RP_GEN_SEED              = 0,
  RUNTIME                  = 0,
  SCRYPT_TMTO              = 0,
  SELF_TEST                = true,
  SHOW                     = false,
  SKIP                     = 0,
  SLOW_CANDIDATES          = false,
  SPEED_ONLY               = false,
  SPIN_DAMP                = 0,
  STATUS                   = false,
  STATUS_JSON              = false,
  PIPELINE_STATS           = false,
  TASK_TIME_BREAKDOWN      = false,
  STATUS_TIMER             = 10,
  STDIN_TIMEOUT_ABORT      = 120,
  STDOUT_FLAG              = false,
  USAGE                    = 0,
  USERNAME                 = false,
  VERSION                  = false,
  VERACRYPT_PIM_START      = 485,
  VERACRYPT_PIM_STOP       = 485,
  WORDLIST_AUTOHEX         = true,
  WORKLOAD_PROFILE         = 2,

} user_options_defaults_t;

typedef enum user_options_map
{
  IDX_ADVICE_DISABLE            = 0xff00,
  IDX_ATTACK_MODE               = 'a',
  IDX_BACKEND_DEVICES           = 'd',
  IDX_BACKEND_DEVICES_VIRTMULTI = 'Y',
  IDX_BACKEND_DEVICES_VIRTHOST  = 'R',
  IDX_BACKEND_IGNORE_CUDA       = 0xff01,
  IDX_BACKEND_IGNORE_HIP        = 0xff02,
  IDX_BACKEND_IGNORE_METAL      = 0xff03,
  IDX_BACKEND_IGNORE_OPENCL     = 0xff04,
  IDX_BACKEND_INFO              = 'I',
  IDX_BACKEND_VECTOR_WIDTH      = 0xff05,
  IDX_BENCHMARK_ALL             = 0xff06,
  IDX_BENCHMARK_MAX             = 0xff56,
  IDX_BENCHMARK_MIN             = 0xff57,
  IDX_BENCHMARK                 = 'b',
  IDX_BITMAP_MAX                = 0xff07,
  IDX_BITMAP_MIN                = 0xff08,
  #ifdef WITH_BRAIN
  IDX_BRAIN_CLIENT              = 'z',
  IDX_BRAIN_CLIENT_FEATURES     = 0xff09,
  IDX_BRAIN_FEED                = 0xff17,
  IDX_BRAIN_HOST                = 0xff0a,
  IDX_BRAIN_PASSWORD            = 0xff0b,
  IDX_BRAIN_PORT                = 0xff0c,
  IDX_BRAIN_SERVER              = 0xff0d,
  IDX_BRAIN_SERVER_TIMER        = 0xff0e,
  IDX_BRAIN_SESSION             = 0xff0f,
  IDX_BRAIN_SESSION_WHITELIST   = 0xff10,
  #endif
  IDX_BYPASS_THRESHOLD          = 0xff84,
  IDX_BYPASS_DELAY              = 0xff85,
  IDX_COLOR_CRACKED             = 0xff59,
  IDX_BRIDGE_PARAMETER1         = 0xff80,
  IDX_BRIDGE_PARAMETER2         = 0xff81,
  IDX_BRIDGE_PARAMETER3         = 0xff82,
  IDX_BRIDGE_PARAMETER4         = 0xff83,
  IDX_CPU_AFFINITY              = 0xff11,
  IDX_CUSTOM_CHARSET_1          = '1',
  IDX_CUSTOM_CHARSET_2          = '2',
  IDX_CUSTOM_CHARSET_3          = '3',
  IDX_CUSTOM_CHARSET_4          = '4',
  IDX_CUSTOM_CHARSET_5          = '5',
  IDX_CUSTOM_CHARSET_6          = '6',
  IDX_CUSTOM_CHARSET_7          = '7',
  IDX_CUSTOM_CHARSET_8          = '8',
  IDX_DEBUG_FILE                = 0xff12,
  IDX_DEBUG_MODE                = 0xff13,
  IDX_DEPRECATED_CHECK_DISABLE  = 0xff14,
  IDX_DYNAMIC_X                 = 0xff55,
  IDX_ENCODING_FROM             = 0xff15,
  IDX_ENCODING_TO               = 0xff16,
  IDX_HASH_COPY                 = 0xff62,
  IDX_HASH_INFO                 = 'H', // 0xff17
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
  IDX_INCREMENT_INVERSE         = 0xff61,
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
  IDX_LOOKUP                    = 0xff89,
  IDX_PIPELINE_STATS            = 0xff8b,
  IDX_TASK_TIME_BREAKDOWN       = 0xff8a,
  IDX_LOOPBACK                  = 0xff29,
  IDX_MACHINE_READABLE          = 0xff2a,
  IDX_MARKOV_CLASSIC            = 0xff2b,
  IDX_MARKOV_DISABLE            = 0xff2c,
  IDX_MARKOV_HCSTAT2            = 0xff2d,
  IDX_MARKOV_INVERSE            = 0xff2e,
  IDX_MARKOV_THRESHOLD          = 't',
  IDX_METAL_COMPILER_RUNTIME    = 0xff2f,
  IDX_NONCE_ERROR_CORRECTIONS   = 0xff30,
  IDX_OPENCL_DEVICE_TYPES       = 'D',
  IDX_OPTIMIZED_KERNEL_ENABLE   = 'O',
  IDX_MULTIPLY_ACCEL_DISABLE    = 'M',
  IDX_OUTFILE_AUTOHEX_DISABLE   = 0xff31,
  IDX_OUTFILE_CHECK_DIR         = 0xff32,
  IDX_OUTFILE_CHECK_TIMER       = 0xff33,
  IDX_OUTFILE_FORMAT            = 0xff34,
  IDX_OUTFILE_JSON              = 0xff35,
  IDX_OUTFILE                   = 'o',
  IDX_POTFILE_DISABLE           = 0xff36,
  IDX_POTFILE_PATH              = 0xff37,
  IDX_PROGRESS_ONLY             = 0xff38,
  IDX_QUIET                     = 0xff39,
  IDX_REMOVE                    = 0xff3a,
  IDX_REMOVE_TIMER              = 0xff3b,
  IDX_RESTORE                   = 0xff3c,
  IDX_RESTORE_DISABLE           = 0xff3d,
  IDX_RESTORE_FILE_PATH         = 0xff3e,
  IDX_RESTORE_POSITION          = 0xff87,
  IDX_RP_FILE                   = 'r',
  IDX_RP_GEN_FUNC_MAX           = 0xff3f,
  IDX_RP_GEN_FUNC_MIN           = 0xff40,
  IDX_RP_GEN_FUNC_SEL           = 0xff41,
  IDX_RP_GEN                    = 'g',
  IDX_RP_GEN_SEED               = 0xff42,
  IDX_RULE_BUF_L                = 'j',
  IDX_RULE_BUF_R                = 'k',
  IDX_RUNTIME                   = 0xff43,
  IDX_SCRYPT_TMTO               = 0xff44,
  IDX_SEEKDB_PATH               = 0xff88,
  IDX_SELF_TEST_DISABLE         = 0xff45,
  IDX_SEPARATOR                 = 'p',
  IDX_SESSION                   = 0xff46,
  IDX_SHOW                      = 0xff47,
  IDX_SKIP                      = 's',
  IDX_SLOW_CANDIDATES           = 'S',
  IDX_SPEED_ONLY                = 0xff48,
  IDX_SPIN_DAMP                 = 0xff49,
  IDX_STATUS                    = 0xff4a,
  IDX_STATUS_JSON               = 0xff4b,
  IDX_STATUS_TIMER              = 0xff4c,
  IDX_STDOUT_FLAG               = 0xff4d,
  IDX_STDIN_TIMEOUT_ABORT       = 0xff4e,
  IDX_TOTAL_CANDIDATES          = 0xff58,
  IDX_TRUECRYPT_KEYFILES        = 0xff4f,
  IDX_USERNAME                  = 0xff50,
  IDX_VERACRYPT_KEYFILES        = 0xff51,
  IDX_VERACRYPT_PIM_START       = 0xff52,
  IDX_VERACRYPT_PIM_STOP        = 0xff53,
  IDX_VERSION_LOWER             = 'v',
  IDX_VERSION                   = 'V',
  IDX_WORDLIST_AUTOHEX_DISABLE  = 0xff54,
  IDX_WORKLOAD_PROFILE          = 'w',
  IDX_ENCRYPT_WITH_PUBKEY       = 0xff70,

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

typedef struct dynamicx
{
  char *dynamicx_buf;
  u32   dynamicx_len;

} dynamicx_t;

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
  dynamicx_t *dynamicx;
  user_t     *user;
  char       *orighash;
  split_t    *split;

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

  bool         radix_deduped;
  bool         radix_digests_reordered;

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

  bool hlfmt_disable;
  bool warmup_disable;
  bool outfile_check_disable;
  bool outfile_check_nocomp;
  bool potfile_disable;
  bool potfile_keep_all_hashes;
  bool forced_jit_compile;

  u32 pwdump_column;

  // bridge

  u64         bridge_type;
  const char *bridge_name;

} hashconfig_t;

typedef struct pw_pre
{
  u32 pw_buf[64];
  u32 pw_len;

  u32 base_buf[64];
  u32 base_len;

  u32 rule_idx;

} pw_pre_t;

// One prepared batch of candidates, and everything a launch needs to know about it. Building a batch
// is host work and running it is device work, so they are kept apart: the buffers belong to the batch
// rather than to the device, which is what lets the next batch be built while this one runs.

#define PW_PIPE_SLOTS 2

typedef struct pw_batch
{
  pw_idx_t *pws_idx;
  u32      *pws_comp;
  u64       pws_cnt;

  // The device engine's cells, one per candidate in this batch. They belong to the batch for the same
  // reason the candidates do: the next batch is built while this one runs.

  pcfg_cell_t *pcfg_cells;

  // and the wave map that goes with them: which cell each wave of the launch belongs to, and how many
  // waves that comes to. It is built here, one cell at a time as the cells are, because this runs on
  // the producer thread where the feed already runs for free. Building it on the launch thread instead
  // cost 411 ms of every launch on an RTX 4090, against 26 ms for the copy it sits in.

  u32 *pcfg_wmap;
  u64  pcfg_waves;

  // slow candidates keep the rule and the base word each candidate came from, so --debug-mode can
  // report them. That is read while the batch runs, so it belongs to the batch too.

  pw_pre_t *pws_base;
  u64       pws_base_cnt;

  // where this batch sits in the keyspace. The restore point may only advance past a batch that has
  // actually been launched, so the figures travel with the batch instead of with the device.

  u64 words_off;
  u64 words_fin;
  u64 words_extra;

  // A rejected word of a feed that amplifies cost a whole cell rather than one candidate, and this
  // holds what those cells came to, in candidates. The cell itself does not survive the rejection,
  // because pws_cnt does not advance over a refused word and the next one is written at the same
  // index, so the count is made where the word is refused rather than from a multiplier at the end.

  u64 words_extra_amp;

} pw_batch_t;

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

// A gzip and an xz reader. Both are declared here and defined in filehandling.c, so that this
// header says a handle exists without saying what a handle is. Every module, bridge and feed
// includes this file, and none of them opens a compressed file: naming the concrete types here
// would put the compression library's own headers on all 593 of their compile lines.

typedef struct gzfile gzfile_t;

typedef struct xzfile xzfile_t;

typedef struct zstdfile zstdfile_t;

// A file that is already in memory. It is opened over a buffer somebody else owns and holds no copy,
// so whatever produced the buffer has to outlive the handle. That is what lets one decompressed
// archive serve a reader per member without a copy apiece.

typedef struct memfile memfile_t;

// Where one frame of a compressed file ends and the next one begins.
//
// A container built out of independent frames can be read from any of those boundaries rather than
// only from the start, which is what lets a compressed wordlist be seeked into. Only the file layer
// knows where the boundaries of a given container are, so it reports them as they go past and a
// caller that wants to come back later writes them down.
//
// comp_off is where the next frame starts in the file on disk. uncomp_off is how many decompressed
// bytes came before it, so the two together say what a restart there would land on.

typedef void (*hc_frame_cb_t) (void *userdata, const u64 comp_off, const u64 uncomp_off);

typedef struct hc_fp
{
  int         fd;

  FILE       *pfp; // plain fp
  gzfile_t   *gfp; //  gzip fp
  xzfile_t   *xfp; //    xz fp
  zstdfile_t *zfp; //  zstd fp
  memfile_t  *mfp; //  memory fp

  int         bom_size;

  const char *mode;
  const char *path;

  off_t       uncompressed_size;

} HCFILE;

#include "ext_nvrtc.h"
#include "ext_hiprtc.h"

#include "ext_cuda.h"
#include "ext_hip.h"
#include "ext_OpenCL.h"
#include "ext_metal.h"

// Where a launch's wall clock goes, split by the stage that spent it. A launch is a chain of host
// steps around one device step, and the steps live in different files, so every stage books its time
// into the device it belongs to.

typedef enum pipe_slot
{
  PIPE_FEED   = 0,  // building the candidate batch on the host, off the critical path
  PIPE_COPY   = 1,  // uploading it and running the decompress kernel
  PIPE_INIT   = 2,  // amplifier, utf16 conversion and the init kernel
  PIPE_XFER   = 3,  // tmps out to the host and back
  PIPE_LAUNCH = 4,  // the loop itself, kernel or bridge
  PIPE_COMP   = 5,  // the comp kernel

  PIPE_SLOTS  = 6,

} pipe_slot_t;

typedef struct hc_device_param
{
  // Per device, because a device thread books only its own launches. These used to be one set of
  // globals written by every device thread at once, which added the devices together and raced
  // doing it.

  double    pipe_msec[PIPE_SLOTS];
  u64       pipe_launches;
  u64       pipe_cands;

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

  // Set on the other virtual devices sharing one physical device once any of them has been refused for
  // want of memory, so the rest are not set up at a cost that only deepens the shortage.

  bool    memory_hit_shared;

  u32     device_processors;
  u32     device_processor_threads;          // work items one processor holds resident, 0 if the runtime cannot report it
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u64     device_cache_size;                 // last level cache the device reports, 0 if it reports none
  u64     device_available_mem;
  int     device_host_unified_memory;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;
  u64     device_local_mem_size;
  int     device_local_mem_type;
  char   *device_name;

  int     sm_major;
  int     sm_minor;
  char   *gcnArchName;
  int     regsPerBlock;
  int     regsPerMultiprocessor;
  u32     kernel_exec_timeout;

  u32     kernel_preferred_wgs_multiple;

  int     bridge_link_device;

  // A copy of another device rather than a device of its own. Virtualisation makes one backend device
  // per bridge unit, all of them the same physical device, because a unit computes but does not feed
  // itself and needs something to generate its candidates.
  //
  // The first copy is left unmarked and stands for the physical device. The rest are marked here so
  // that -I can describe the machine rather than the work: a run with 33 bridge units otherwise lists
  // 33 identical CPUs, which reads as something being badly wrong.

  bool    is_virtual;

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

  bool    overtune_unfriendly;  // whatever sets this decide we operate in a mode that is not allowing to overtune threads_max or accel_max in autotuner

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
  u64  size_combs_c;

  // The device engine's two buffers. The cells are per work item and are rewritten every launch beside
  // pws_buf; the pool is the terminal bytes every cell indexes into and is uploaded once.

  u64  size_pcfg_cells;
  u64  size_pcfg_pool;
  u64  size_pcfg_wmap;
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
  bool          brain_link_reported;    // a failed link is retried per batch, so report an outage once
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

  pw_t     *combs_buf;

  pcfg_cell_t *pcfg_cells_buf;

  // Which cell each wave of the launch belongs to. A cell takes as many waves as its rectangle needs,
  // so a wave cannot work its own cell out from its id and this is the answer, one word a wave.

  u32 *pcfg_wmap_buf;

  // What the last layout of the PCFG launch came to: how many cells it covered, and how many work
  // items those cells ask for between them. A cell takes as many work items as its rectangle needs
  // rather than a fixed number, so the launch size cannot be worked out from the base word count and
  // has to be read back off the plan.

  u64 pcfg_lane_cnt;
  u64 pcfg_lane_total;

  // Whether combs_buf holds the amplifier chunk that is on the device. It does for every attack mode
  // that builds the amplifier on the host, and it does not for the one -a 12 shape whose mask the mask
  // processor produces on the device. Anything rebuilding a candidate has to know which, because in
  // the second case the buffer holds whatever was in it last.

  bool      combs_on_host;

  void     *hooks_buf;

  // the batch currently being launched. These point into one of the slots below, so everything
  // downstream of the launch reads them unchanged.

  pw_idx_t *pws_idx;
  u32      *pws_comp;
  u64       pws_cnt;

  pw_batch_t pws_slot[PW_PIPE_SLOTS];

  pw_pre_t *pws_pre_buf;  // for slow candidates
  u64       pws_pre_cnt;

  pw_pre_t *pws_base_buf; // for debug mode, a view of the batch being launched

  void    *h_tmps; // we need this only for bridges

  u64     words_off;

  // Where the batch being launched starts. words_off above belongs to the producer, which is filling
  // the next batch while this one runs, so by the time a crack is reported it has already moved on.
  // A crack is booked at a position in the keyspace, so that position has to come from the batch and
  // not from wherever the producer happens to have got to.

  u64     words_off_launch;

  u64     words_done;

  u64     outerloop_pos;
  u64     outerloop_left;
  double  outerloop_msec;
  double  outerloop_words;

  u64     innerloop_pos;
  u64     innerloop_left;

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
  bool    use_opencl30;

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
  bool    has_shfw;

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
  CUdeviceptr       cuda_d_pcfg_cells;
  CUdeviceptr       cuda_d_pcfg_pool;
  CUdeviceptr       cuda_d_pcfg_wmap;
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
  hipDeviceptr_t    hip_d_pcfg_cells;
  hipDeviceptr_t    hip_d_pcfg_pool;
  hipDeviceptr_t    hip_d_pcfg_wmap;
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

  //int               mtl_major;
  //int               mtl_minor;

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

  mtl_mem_t         metal_d_pws_buf;
  mtl_mem_t         metal_d_pws_amp_buf;
  mtl_mem_t         metal_d_pws_comp_buf;
  mtl_mem_t         metal_d_pws_idx;
  mtl_mem_t         metal_d_rules;
  mtl_mem_t         metal_d_rules_c;
  mtl_mem_t         metal_d_combs;
  mtl_mem_t         metal_d_combs_c;
  mtl_mem_t         metal_d_pcfg_cells;
  mtl_mem_t         metal_d_pcfg_pool;
  mtl_mem_t         metal_d_pcfg_wmap;
  mtl_mem_t         metal_d_bfs;
  mtl_mem_t         metal_d_bfs_c;
  mtl_mem_t         metal_d_tm_c;
  mtl_mem_t         metal_d_bitmap_s1_a;
  mtl_mem_t         metal_d_bitmap_s1_b;
  mtl_mem_t         metal_d_bitmap_s1_c;
  mtl_mem_t         metal_d_bitmap_s1_d;
  mtl_mem_t         metal_d_bitmap_s2_a;
  mtl_mem_t         metal_d_bitmap_s2_b;
  mtl_mem_t         metal_d_bitmap_s2_c;
  mtl_mem_t         metal_d_bitmap_s2_d;
  mtl_mem_t         metal_d_plain_bufs;
  mtl_mem_t         metal_d_digests_buf;
  mtl_mem_t         metal_d_digests_shown;
  mtl_mem_t         metal_d_salt_bufs;
  mtl_mem_t         metal_d_esalt_bufs;
  mtl_mem_t         metal_d_tmps;
  mtl_mem_t         metal_d_hooks;
  mtl_mem_t         metal_d_result;
  mtl_mem_t         metal_d_extra0_buf;
  mtl_mem_t         metal_d_extra1_buf;
  mtl_mem_t         metal_d_extra2_buf;
  mtl_mem_t         metal_d_extra3_buf;
  mtl_mem_t         metal_d_root_css_buf;
  mtl_mem_t         metal_d_markov_css_buf;
  mtl_mem_t         metal_d_st_digests_buf;
  mtl_mem_t         metal_d_st_salts_buf;
  mtl_mem_t         metal_d_st_esalts_buf;
  mtl_mem_t         metal_d_kernel_param;

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

  // Whether the device answers cl_amd_device_attribute_query, which is where the only OpenCL query
  // for free device memory lives. Recorded at enumeration because the extension string is not kept.
  // Vendor id is not a substitute: Mesa's rusticl reports VENDOR_ID_AMD and answers none of these.

  bool              has_amd_device_attribute_query;

  mem_source_t      device_available_mem_source;

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
  cl_mem            opencl_d_pcfg_cells;
  cl_mem            opencl_d_pcfg_pool;
  cl_mem            opencl_d_pcfg_wmap;
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

  // Which presentation group this device belongs to, as the device index of the group's first
  // member. A device that leads its own group carries its own index, which is what every device
  // outside a bridge does, so nothing about an ordinary run changes.
  //
  // Many devices can be ONE thing the user is looking at. Grouping is how those stay separate: work
  // is fed, tuned and failed per device, and reported per group. Without it sixty four devices of one
  // kind are sixty four status lines saying the same number.

  int               group_id;

  // Whether this device's context and programs came from an earlier clone of the same physical
  // device rather than being built here. A cl_program is what costs the host memory, and it belongs
  // to a context, so the two are shared or neither is.

  bool              opencl_context_is_clone;

  // What makes two builds interchangeable. hashcat already computes these to name the kernel cache
  // file, and a clone that agrees on both can use the program a previous clone built.

  char              opencl_chksum[24];
  char              opencl_chksum_amp_mp[24];

} hc_device_param_t;

// One entry per kernel binary a run has to produce. Devices that would build the same file are the
// same class, and the file name is the class: it already carries the device, the driver, the attack
// and a digest of the source, so two devices sharing a name would compile identical output.

// shared, main, mp and amp: the four kernel binaries a device can need

#define KERNEL_BUILDS_PER_DEVICE 4

typedef struct kernel_build
{
  char cached_file[256];

  bool done;
  bool failed;

} kernel_build_t;

typedef struct backend_ctx
{
  kernel_build_t     *kernel_builds;
  int                 kernel_builds_cnt;

  hc_thread_mutex_t   mux_kernel_build;
  hc_thread_cond_t    cond_kernel_build;

  bool                enabled;

  // global rc

  bool                memory_hit_warning;
  bool                runtime_skip_warning;
  bool                kernel_build_warning;
  bool                kernel_create_warning;
  bool                kernel_accel_warnings;
  bool                extra_size_warning;
  bool                mixed_warnings;
  bool                self_test_warnings;

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
  int                 backend_devices_virtmulti;
  int                 backend_devices_virthost;
  int                 backend_devices_active;

  // The machine as the runtimes reported it, recorded before virtualization rewrites the device list.
  // A virtualized run replaces that list with clones of one physical device, so the list can no longer
  // answer which hardware is present, which is exactly what a message about having no usable device
  // left has to describe. Indexed the way backend devices are numbered without virtualization, so
  // index 0 is device #1 and is also --backend-devices-virthost=1.

  int                 physical_devices_cnt;
  cl_device_type      physical_devices_type[DEVICES_MAX];

  int                 cuda_devices_cnt;
  int                 cuda_devices_active;
  int                 hip_devices_cnt;
  int                 hip_devices_active;
  int                 metal_devices_cnt;
  int                 metal_devices_active;
  int                 opencl_devices_cnt;
  int                 opencl_devices_active;

  // Whether virtual devices on one physical device share the compiled program instead of each
  // building their own. A program costs about 165 MiB of host memory on a runtime that compiles at
  // startup, and that is per virtual device, so a bridge with many units pays it many times over for
  // byte-identical builds.

  bool                opencl_program_share;

  int                 backend_devices_filter[DEVICES_MAX];

  hc_device_param_t  *devices_param;

  u32                 hardware_power_all;

  u64                 kernel_power_all;
  u64                 kernel_power_final; // we save that so that all divisions are done from the same base

  double              target_msec;

  bool                need_adl;
  bool                need_nvml;
  bool                need_nvapi;
  bool                need_sysfs_amdgpu;
  bool                need_sysfs_intelgpu;
  bool                need_sysfs_cpu;
  bool                need_iokit;

  int                 comptime;

  // digest of every kernel source that is shared by all kernels, read once because it does not depend
  // on the device or on the hash mode

  u64                 kernel_shared_chksum;

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

// KERNEL_ACCEL_MAX bounds a per-multiprocessor multiplier, which is what kernel_accel means for a
// compute kernel: the launch is hardware_power * kernel_accel, so 1024 is already an enormous grid.
//
// Under an assimilation bridge hardware_power is 1 and kernel_accel IS the candidate count in a
// launch, so the same number is a much smaller thing. A bridge whose unit is itself wide computes in
// waves of its own width and wants many whole waves per launch, which can put its useful range in the
// thousands, and 1024 would then express only the bottom few percent of it.

typedef enum kernel_workload
{
  KERNEL_ACCEL_MIN        = 1,
  KERNEL_ACCEL_MAX        = 1024,
  KERNEL_ACCEL_MAX_BRIDGE = 16384,
  KERNEL_LOOPS_MIN        = 1,
  KERNEL_LOOPS_MAX        = 1024,
  KERNEL_THREADS_MIN      = 1,
  KERNEL_THREADS_MAX      = 1024,

} kernel_workload_t;

#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_sysfs_amdgpu.h"
#include "ext_sysfs_intelgpu.h"
#include "ext_sysfs_cpu.h"
#include "ext_iokit.h"

typedef struct hm_attrs
{
  HM_ADAPTER_ADL            adl;
  HM_ADAPTER_NVML           nvml;
  HM_ADAPTER_NVAPI          nvapi;
  HM_ADAPTER_SYSFS_AMDGPU   sysfs_amdgpu;
  HM_ADAPTER_SYSFS_INTELGPU sysfs_intelgpu;
  HM_ADAPTER_SYSFS_CPU      sysfs_cpu;
  HM_ADAPTER_IOKIT          iokit;

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
  bool memoryused_get_supported;
  bool power_get_supported;

} hm_attrs_t;

typedef struct hwmon_ctx
{
  bool  enabled;

  void *hm_adl;
  void *hm_nvml;
  void *hm_nvapi;
  void *hm_sysfs_amdgpu;
  void *hm_sysfs_intelgpu;
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

typedef struct hashdump
{
  int version;

  hashes_t hashes;

} hashdump_t;

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

// State for --encrypt-with-pubkey. The library handle and the key are void pointers so that no
// OpenSSL header is needed to build hashcat; see ext_openssl.h.

typedef struct pubkey_ctx
{
  bool    enabled;

  void   *openssl;                    // hc_openssl_lib_t
  void   *pubkey;                     // EVP_PKEY

  int     key_bits;
  size_t  key_size;
  size_t  capacity;                   // key_size minus the OAEP overhead

  char    keyid[17];                  // 16 hex characters and a terminator

  u64     run_time;                   // stamped into every payload

} pubkey_ctx_t;

typedef struct outfile_ctx
{
  // How many batches are open. check_cracked () takes one for the whole of a launch's results, so
  // the file is opened and locked once instead of once per cracked hash. Zero means the old
  // behaviour, one open per write, which every other caller still gets.

  int batch_depth;

  HCFILE  fp;

  u32     outfile_format;
  bool    outfile_autohex;
  bool    outfile_json;
  bool    is_fifo;

  char   *filename;

  hc_thread_mutex_t mux_outfile;

} outfile_ctx_t;

typedef struct pot
{
  char     plain_buf[HCBUFSIZ_SMALL];
  int      plain_len;

  hash_t   hash;

} pot_t;

typedef struct potfile_ctx
{
  int batch_depth;

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

  // The password the potfile has for this hash+salt, kept here rather than pushed straight into the
  // linked list, because a potfile with the same hash on many lines would otherwise walk the whole
  // list once per line. It is handed to the nodes once, after the potfile has been read.

  char *pw_buf;
  int   pw_len;

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

  // Set when --restore has printed the command line the restore file holds and the run must stop
  // there. hashcat_session_init returns as soon as it sees this, before anything has opened a file
  // or created a directory on the strength of what the restore file said.

  bool    print_only;

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

// --stdout writes one syscall per full buffer, and at HCBUFSIZ_SMALL that is a write() every few
// hundred candidates. The buffer is a local in process_stdout (), so this stays a size a thread
// stack carries comfortably.

#define STDOUT_BUFSIZ 0x10000

typedef struct out
{
  HCFILE fp;

  char   buf[STDOUT_BUFSIZ];
  int    len;
  bool   write_failed;

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
  int         source; // 1 = dbfile, 2 = module

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

typedef struct user_options
{
  const char  *hc_bin;

  int          hc_argc;
  char       **hc_argv;

  // The vector the attack mode alias built, kept only so that it can be freed. hc_argv points at it
  // while the alias is in force and at argv otherwise, so it cannot be freed through hc_argv.

  char       **hc_argv_alias;

  bool         attack_mode_chgd;
  bool         autodetect;
  #ifdef WITH_BRAIN
  bool         brain_client_features_chgd;
  bool         brain_host_chgd;
  bool         brain_port_chgd;
  bool         brain_password_chgd;
  bool         brain_server_timer_chgd;
  #endif
  bool         bypass_delay_chgd;
  bool         bypass_threshold_chgd;
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
  bool         outfile_chgd;
  bool         outfile_format_chgd;
  bool         remove_timer_chgd;
  bool         rp_gen_seed_chgd;
  bool         runtime_chgd;
  bool         metal_compiler_runtime_chgd;
  bool         workload_profile_chgd;
  bool         skip_chgd;
  bool         limit_chgd;
  bool         scrypt_tmto_chgd;
  bool         separator_chgd;
  bool         rule_buf_l_chgd;
  bool         rule_buf_r_chgd;
  bool         session_chgd;

  bool         advice;
  bool         benchmark;
  bool         benchmark_all;
  #ifdef WITH_BRAIN
  bool         brain_client;
  bool         brain_feed;
  bool         brain_server;
  #endif
  bool         color_cracked;
  bool         force;
  bool         deprecated_check;
  bool         dynamic_x;
  bool         hwmon;
  bool         hex_charset;
  bool         hex_salt;
  bool         hex_wordlist;
  increment_t  increment;
  bool         keep_guessing;
  bool         keyspace;
  bool         total_candidates;
  bool         left;
  bool         logfile;
  bool         loopback;
  bool         machine_readable;
  bool         markov_classic;
  bool         markov;
  bool         markov_inverse;
  bool         backend_ignore_cuda;
  bool         backend_ignore_hip;
  bool         backend_ignore_metal;
  bool         backend_ignore_opencl;
  bool         optimized_kernel;
  bool         multiply_accel;
  bool         outfile_autohex;
  bool         outfile_json;
  bool         potfile;
  bool         progress_only;
  bool         quiet;
  bool         remove;
  bool         restore;
  bool         restore_enable;
  bool         restore_position;
  bool         self_test;
  bool         show;
  bool         slow_candidates;
  bool         speed_only;
  bool         status;
  bool         status_json;
  bool         pipeline_stats;
  bool         task_time_breakdown;
  bool         stdout_flag;
  bool         stdin_timeout_abort_chgd;
  bool         username;
  bool         veracrypt_pim_start_chgd;
  bool         veracrypt_pim_stop_chgd;
  bool         version;
  bool         wordlist_autohex;
  #ifdef WITH_BRAIN
  char        *brain_host;
  char        *brain_password;
  char        *brain_session_whitelist;
  #endif
  char        *bridge_parameter1;
  char        *bridge_parameter2;
  char        *bridge_parameter3;
  char        *bridge_parameter4;
  char        *cpu_affinity;
  char        *debug_file;
  char        *induction_dir;
  char        *keyboard_layout_mapping;
  char        *lookup;
  char        *lookup_alias;    // "lookup=" plus the above, when -a 4 is handed the question
  char        *markov_hcstat2;
  char        *backend_devices;
  char        *opencl_device_types;
  char        *outfile;
  char        *outfile_check_dir;
  char        *potfile_path;
  char        *restore_file_path;
  char       **rp_files;
  char        *rp_gen_func_sel;
  char        *seekdb_path;
  char        *separator;
  char        *truecrypt_keyfiles;
  char        *veracrypt_keyfiles;
  const char  *custom_charset_1;
  const char  *custom_charset_2;
  const char  *custom_charset_3;
  const char  *custom_charset_4;
  const char  *custom_charset_5;
  const char  *custom_charset_6;
  const char  *custom_charset_7;
  const char  *custom_charset_8;
  const char  *encoding_from;
  const char  *encoding_to;
  const char  *rule_buf_l;
  const char  *rule_buf_r;
  const char  *session;
  char        *encrypt_with_pubkey;
  u32          attack_mode;

  // The attack mode the user asked for, which is not always the one the run uses. -a 1, -a 6 and
  // -a 7 are rewritten into -a 12 masks at startup, so everything below the rewrite sees -a 12, and
  // the few things that have to answer for what was typed read this instead.

  u32          attack_mode_typed;

  // Where that rewrite puts the ?w marker on each mask. It is also what says a mask came from an
  // aliased mode rather than from the user.

  u32          marker_policy;

  u32          backend_devices_virtmulti;
  u32          backend_devices_virthost;
  u32          backend_info;
  u32          benchmark_max;
  u32          benchmark_min;
  u32          bitmap_max;
  u32          bitmap_min;
  #ifdef WITH_BRAIN
  u32          brain_server_timer;
  u32          brain_client_features;
  u32          brain_port;
  u32          brain_session;
  u32          brain_attack;
  #endif
  u32          bypass_delay;
  u32          bypass_threshold;
  u32          debug_mode;
  u32          hwmon_temp_abort;
  u32          hash_info;
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
  u32          metal_compiler_runtime;
  u32          scrypt_tmto;
  u32          status_timer;
  u32          stdin_timeout_abort;
  u32          usage;
  u32          veracrypt_pim_start;
  u32          veracrypt_pim_stop;
  u32          workload_profile;
  u64          limit;
  u64          skip;
  bool         hash_copy;

} user_options_t;

typedef struct user_options_extra
{
  u32 attack_kern;

  u32 rule_len_r;
  u32 rule_len_l;

  // Which of -j and -k applies to the base word and which to the amplifier. That is not the same
  // question as which flag the user typed. -j is the rule for the left hand side of a candidate and -k
  // for the right, but which side the base loop walks depends on the attack mode: -a 7 builds mask plus
  // word, so its word is the right hand side, and -a 1 takes whichever of its two dictionaries is
  // larger as the base.
  //
  // Resolving it once here is what lets combinator_ctx_init stop swapping the user's own options in
  // place, and what takes the -a 7 special case out of every producer that reads a base word.

  const char *rule_buf_base;
  const char *rule_buf_amp;

  u32 rule_len_base;
  u32 rule_len_amp;

  u32 base_source;
  u32 base_scope;
  u32 wordlist_mode;

  // Whether the last work argument is the wordlist a ?q names. A -a 12 the user typed says so with a
  // third argument, a -a 1 rewritten into one always has one, and a -a 6 rewritten into one never
  // does and may have any number of base wordlists, so the count alone cannot answer it.

  bool hybrid_q;

  char   separator;

  char  *hc_hash;   // can be filename or string

  // --dynamic-x: the number in the $dynamic_N$ tag of the first hash. One hash list is one -m, so
  // every other line has to carry the same number, and this is what they are compared against.

  int    dynamicx_num;

  int    hc_workc;  // can be 0 in bf-mode = default mask
  char **hc_workv;

  // -a 9 given nothing but a hash file splits that file itself: on each line the text before the first
  // separator is the candidate and the rest is the hash. That is the same pairing the two argument form
  // makes, with the wordlist taken out of the hash file instead of out of a second file.

  bool   association_autosplit;

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

  // Whether the two feed instances were swapped so that the bigger wordlist is the base word source.
  // Only a mask that is two wordlists and nothing else can be swapped, and the amplifier then goes in
  // front of the base word rather than behind it, so that the candidate is still the first wordlist's
  // word followed by the second's.

  bool roles_swapped;

  u32 combs_mode;
  u64 combs_cnt;

} combinator_ctx_t;

// Why a mask did not reach the candidate --lookup asked about. Which of the three it is decides what
// the user can do about it, so they are kept apart rather than reported as one refusal.

typedef enum mask_lookup_miss
{
  MASK_LOOKUP_MISS_NONE    = 0,
  MASK_LOOKUP_MISS_LENGTH  = 1,  // the mask is not the candidate's length, so no offset in it can be
  MASK_LOOKUP_MISS_CHARSET = 2,  // the mask does not allow that character at that position
  MASK_LOOKUP_MISS_MARKOV  = 3,  // the mask allows it, and --markov-threshold dropped it from the table

} mask_lookup_miss_t;

// Where the queue of masks reaches the candidate --lookup asked about, filled in one round at a time
// and read once the queue has been walked.
//
// word is a position in the whole queue and not in the round that found it, because that is what
// --skip addresses. A hit is kept and later rounds cannot displace it: the queue is walked in the
// order the run would walk it, so the first round that reaches the candidate is where the run does.
//
// The masks are copied rather than pointed at. A mask file's line is parsed into mask_ctx->mfs,
// which the next round overwrites, so a pointer would still be readable and would no longer say
// what it said when the answer was found.
//
// A miss is kept only until a nearer one turns up. Nearer means the mask was the right length when
// the one before it was not, and failing that means it got further along the candidate before
// refusing it. That is the mask the user most likely meant, and it is the one worth naming out of a
// queue that can hold fifty.

typedef struct mask_lookup
{
  bool  hit;
  bool  placed;     // whether word has been moved from this round's numbering to the queue's

  // A mode that hashes the candidate in upper case has every mask charset built in upper case, so
  // the candidate is folded the same way before it is looked for and the user is told it was. What
  // the run reaches is the folded spelling, and saying so is the difference between an answer and a
  // wrong one.

  bool  uppered;

  u32   round;      // masks_pos of the round that reached it
  char  mask[0x400]; // as wide as mf_t's, so no mask a maskfile can hold is truncated

  u64   word;       // the -s value, counted from the start of the queue
  u64   amp;        // where in that base word's cell the candidate sits
  u64   amp_cnt;    // how wide the cell is, which is 1 when -s counts candidates

  // Whether the engine this run did not get would have reached it, and whether that was asked at
  // all. The two engines differ: the run walks a mask in two pieces and -S walks it in one, and
  // under --markov-threshold that is not a reordering but a different set of candidates.
  //
  // Both directions are worth saying and both happen. A user told only that the mask does not
  // produce their password would change the mask, when what they needed was -S. And a user handed an
  // offset who then adds -S for a slow hash would lose the candidate without being told.

  bool  other_probed;
  bool  other;

  // Masks the run passed over for being outside the mode's password length. They are not part of the
  // attack and not part of the keyspace, so an answer that does not mention them can read as "no mask
  // was that long" when one was and the run declined it.

  u32   skipped;

  mask_lookup_miss_t miss;

  u32   round_miss;
  char  mask_miss[0x400];
  u32   miss_pos;   // the position that refused it, counted in characters and from 1
  u32   miss_chr;   // the character it refused

} mask_lookup_t;

// Where a hybrid queue reaches the candidate --lookup asked about. Separate from mask_lookup_t
// because the two answers are different shapes: -a 3 names one mask offset, and a hybrid names a
// word, a second word and a mask offset, plus the split of the candidate that produced them.

typedef struct combi_lookup
{
  bool  hit;
  bool  placed;

  // The mirror shape, where the mask is the base word and the dictionary amplifies it. It is a
  // different decomposition and this does not invert it, so it is reported as unanswered rather than
  // answered wrongly.

  bool  unsupported;

  u32   round;
  char  mask[0x400];

  u64   word;       // the -s value, counted from the start of the queue
  u64   amp;        // where in that base word's cell the candidate sits
  u64   amp_cnt;    // how wide the cell is

  bool  mask_base;  // the mask is the base word and the wordlist amplifies it

  u32   base_len;   // how the candidate was split between the two words
  u32   q_len;
  bool  has_q;

  mask_lookup_miss_t miss;

  char  mask_miss[0x400];
  u32   miss_pos;
  u32   miss_chr;

} combi_lookup_t;

typedef struct mask_ctx
{
  bool   enabled;

  cs_t  *mp_sys;
  cs_t  *mp_usr;

  u64    bfs_cnt;

  cs_t  *css_buf;
  u32    css_cnt;

  // Where the word markers sit in the mask, counted in css entries, which is the same as bytes because
  // every css entry produces exactly one character. css_buf holds the mask with the markers removed,
  // so the three mask pieces are the entries below pre_len, the mid_len entries after those, and
  // whatever is left. Every one of the three is allowed to be empty, and so is ?q.
  //
  //   ?d?w?d?q?d   pre_len 1, mid_len 1, has_q true,  one entry left over for the piece at the end
  //   ?w?d?d       pre_len 0, mid_len 0, has_q false, two entries left over
  //   ?w?q         pre_len 0, mid_len 0, has_q true,  nothing left over, which is -a 1

  bool   has_w;
  bool   has_q;
  u32    pre_len;
  u32    mid_len;

  hcstat_table_t *root_table_buf;
  hcstat_table_t *markov_table_buf;

  cs_t  *root_css_buf;
  cs_t  *markov_css_buf;

  bool   mask_from_file;

  // Whether any mask in this run puts the base word inside the amplifier rather than at one end of
  // it. The kernels compile the five piece assembly in only when it does, and it goes into the kernel
  // cache key, so two runs that build different source out of one file cannot share a cached result.

  bool   needs_middle;

  char **masks;
  u32    masks_pos;
  u32    masks_cnt;
  u32    masks_avail;

  char  *mask;

  mf_t  *mfs;

  // --lookup asks where this queue of masks reaches one candidate. It is answered while the queue is
  // sized rather than by a second walk of it, because a round's tables only exist between
  // mask_ctx_update_loop () building them and the next round overwriting them.

  mask_lookup_t lookup;

  combi_lookup_t lookup_combi;

} mask_ctx_t;

typedef struct generic_global_ctx
{
  bool   quiet;

  int    workc;
  char **workv;

  char  *profile_dir;
  char  *cache_dir;

  // Where seek databases live, when the user named a directory with --seekdb-path. NULL means the
  // feed picks its own place under cache_dir, which is what happens without the option.
  //
  // It is here because a database is described entirely by the wordlist it was built from, so one
  // built on any machine is usable on every machine that reads the same file, and pointing a whole
  // cluster at one shared directory turns a build per machine into a build for all of them. The
  // directory may be read only: a feed writes only when it did not find what it needed, and a write
  // that fails leaves it running from the database it just built in memory.

  char  *seekdb_dir;

  // Where hashcat keeps the files it ships. A feed that carries data of its own finds it here, the
  // same way the frontend finds the feed itself: shared_dir/feeds is what was searched to load this
  // plugin, so shared_dir/<something> is where anything shipped beside it lives.

  char  *shared_dir;

  // What the status display puts inside "Guess.Base.......: Feed (...)". A feed may write its own
  // during global_init (), because the plugin name alone says what is generating and not what it is
  // generating from: "Feed (rockyou.pcfg)" tells the user something that "Feed (pcfg)" does not.
  // Left empty, hashcat falls back to the plugin name.

  char   guess_base[256];

  // A feed built from several named sources laid end to end can publish where each one begins in the
  // keyspace, and then the status line says which source the run has reached rather than naming only
  // the first one. segment_first[i] is the offset source i starts at, ascending.
  //
  // hashcat reports the source holding the restore point, which is the contiguous prefix every device
  // has finished. Asking a device where it is would give a different answer per device and flicker
  // between them, because the whole point of the feed is that devices work separate ranges at once.
  //
  // A feed with nothing to segment leaves segments_cnt at zero and keeps guess_base as it is.

  u64          segments_cnt;
  const char **segment_names;
  const u64   *segment_first;

  // What this feed reads from, as one number, so that something which has to tell two runs apart can
  // do it without knowing what a source is. A path is not enough: the same path holds different words
  // on different days, and a run over the new contents is a different attack from a run over the old.
  //
  // The brain is what needs it. It keys its record of covered keyspace on the attack, so a feed whose
  // inputs changed has to look like a different attack or the second run is told the first one already
  // covered it.
  //
  // A feed that cannot say leaves it at zero, which is what a pipe does: there is nothing to identify
  // until it has been read, and by then it is too late to be worth saying.

  u64 source_ident;

  // How many candidates the device engine produces over the whole keyspace, where the feed can say.
  //
  // The keyspace a feed reports is base words, and the number of candidates is that times the mean
  // cell. The mean is an integer and the true one is not, so multiplying the two is short of the truth
  // by whatever the mean lost to rounding, and the total a run is measured against is short with it.
  // A feed that already knows the exact number says it here and the multiplication is not used.
  //
  // Zero means the feed did not say, and the mean stands.

  u64 dev_total;

  // Whether this instance's device engine is going to be used, settled before global_init () runs so that
  // a feed which can generate two different ways knows which one it is being loaded for.
  //
  // A feed that advertises GENERIC_PLUGIN_OPTIONS_DEVICE does not always get to amplify: an
  // outside-kernel hash mode has no attack kernel to put an inner loop in, and the device engine instance
  // of a combinator attack is a second word list rather than an device engine. hashcat settles all of that
  // in generic_instance_init (), and a feed reads the answer here instead of working it out again from
  // the hashconfig, which is what would let the two drift apart.
  //
  // It matters because the device engine is a constraint, not a feature. A feed may have parts of its
  // model that only a host loop can carry, and those parts change the keyspace, so it has to know
  // before it counts itself. false for every feed that never runs on the device.

  bool dev_enable;

  // Whether this feed was asked to describe the attack rather than to run it, which it says by
  // setting this from global_init () or global_dev_init (). A feed's settings can carry a question,
  // such as where in the keyspace this attack reaches a given candidate, and an answer to that is
  // only worth anything when it comes from the tables the run itself would enumerate, under the
  // engine the run itself was given. That is why such a question is answered from inside the feed
  // rather than by a second program that has to be kept in step with it.
  //
  // The feed has already said its piece by the time hashcat reads this, on its own account and in
  // its own words. Nothing will read a candidate from it afterwards: no device thread is started,
  // the queue of rounds is never entered, and the run ends as a success.
  //
  // A feed must not exit the process itself. It is a shared object inside a session that has a
  // potfile open and a restore file to unlink, and half of that is hashcat's to close.

  bool described;

  bool   error;
  char   error_msg[256];

  void  *gbldata; // super generic

} generic_global_ctx_t;

typedef struct generic_thread_ctx
{
  // A failure inside thread_init (), thread_term (), thread_next () or thread_seek () is reported
  // here and not in the global context, because those four run on one device thread each and a
  // shared flag would let one device's failure speak for all of them.

  bool   error;
  char   error_msg[256];

  // Which backend device this thread feeds. hashcat keeps one of these per device and hands each
  // device its own, so a feed that only produces candidates never needs to know. One that wants to
  // do work on the same device it feeds does: it is the index into backend_ctx->devices_param, and
  // with the hashcat_ctx a feed is given in global_init () that is enough to reach the device
  // itself. Set before thread_init () is called, and left alone afterwards.

  int    device_id;

  void  *thrdata; // super generic

} generic_thread_ctx_t;

typedef bool (*GENERIC_GLOBAL_INIT)     (generic_global_ctx_t *, generic_thread_ctx_t **, void *);
typedef void (*GENERIC_GLOBAL_TERM)     (generic_global_ctx_t *, generic_thread_ctx_t **, void *);
typedef u64  (*GENERIC_GLOBAL_KEYSPACE) (generic_global_ctx_t *, generic_thread_ctx_t **, void *);

typedef bool (*GENERIC_THREAD_INIT)     (generic_global_ctx_t *, generic_thread_ctx_t *);
typedef void (*GENERIC_THREAD_TERM)     (generic_global_ctx_t *, generic_thread_ctx_t *);
typedef int  (*GENERIC_THREAD_NEXT)     (generic_global_ctx_t *, generic_thread_ctx_t *, u8 *, const int);
typedef int  (*GENERIC_THREAD_NEXT_DEV) (generic_global_ctx_t *, generic_thread_ctx_t *, u8 *, const int, pcfg_cell_t *);
typedef bool (*GENERIC_THREAD_SEEK)     (generic_global_ctx_t *, generic_thread_ctx_t *, const u64);
typedef bool (*GENERIC_GLOBAL_DEV_INIT) (generic_global_ctx_t *, const u32 **, u64 *, u32 *, u32 *, u32 *, u32 *, u32 *, u32 *, pcfg_cell_t *);
typedef u64  (*GENERIC_GLOBAL_DEV_SPAN) (generic_global_ctx_t *, const u64, const u64);

// What a live feed instance is for. A run can hold one of each, and that is what lets -a 1 be
// expressed without a second reader: its amplifier is a wordlist too, so the number of amplifier
// words is a feed's keyspace like any other.
//
// The roles are slots and not identities. -a 1 cannot say which of its two dictionaries is the base
// until both have been counted, so the instances are created in the order the dictionaries were
// typed and combinator_ctx_init puts them in the right slots afterwards.

typedef enum generic_role
{
  GENERIC_ROLE_BASE = 0,
  GENERIC_ROLE_AMP  = 1,

  GENERIC_ROLE_CNT  = 2,

} generic_role_t;

typedef struct generic_ctx
{
  bool enabled;

  generic_global_ctx_t  global_ctx;
  generic_thread_ctx_t *thread_ctx;

  // what the user asked for, and the file that turned out to be

  char *plugin_name;
  char *dynlib_filename;

  // What the feed reads from. This is not the command line: -a 8 names its plugin as the first work
  // argument and the rest belong to the feed, while -a 0 names no plugin at all and every work
  // argument is a wordlist. Resolving it per attack mode is the only place that has to know, so the
  // work arguments themselves stay exactly as the user typed them.

  int    workc;
  char **workv;

  // -a 8 is handed the command line as it stands, so workv points into it. Every other mode needs a
  // plugin name put in front of its dictionaries and gets an array of its own, which is the only case
  // with anything to free.

  bool workv_owned;

  hc_dynlib_t lib;

  GENERIC_GLOBAL_INIT      global_init;
  GENERIC_GLOBAL_TERM      global_term;
  GENERIC_GLOBAL_KEYSPACE  global_keyspace;

  GENERIC_THREAD_INIT      thread_init;
  GENERIC_THREAD_TERM      thread_term;
  GENERIC_THREAD_NEXT      thread_next;
  GENERIC_THREAD_SEEK      thread_seek;

  // The device engine half of the interface, and it is optional. A feed that advertises
  // GENERIC_PLUGIN_OPTIONS_DEVICE can hand hashcat a base candidate plus the cell that says how the
  // device is to extend it, instead of one finished candidate per call. Everything else about the
  // feed is unchanged, because the device engine is a second consumer of the same generator rather than
  // a different generator.

  GENERIC_GLOBAL_DEV_INIT  global_dev_init;
  GENERIC_THREAD_NEXT_DEV  thread_next_dev;

  // Optional beside those two: how many candidates lie in a window of base words. A feed that does
  // not have it leaves this NULL, and a window is measured against the mean cell instead.

  GENERIC_GLOBAL_DEV_SPAN  global_dev_span;

  bool autohex_enable;
  bool iconv_enable;
  bool rules_enable;
  bool dev_enable;

  // What global_dev_init () handed over: the terminal pool every cell indexes into, and how wide the
  // device side inner loop is. The pool is read only and uploaded once per device.

  const u32 *dev_pool;
  u64        dev_pool_size;
  u32        dev_il_cnt;

  // How many words the kernel gives a candidate. The feed settles it from the ruleset and the backend
  // compiles the kernel with it, so the two cannot disagree unless a cached kernel is reused across
  // rulesets, which is why it is folded into the cache key.

  u32        dev_maxword;

  // Whether a bucket may hold entries of more than one byte length. Settled the same way and folded
  // into the same cache key, because it changes the kernel's source just as much.

  u32        dev_varlen;

  // A cell the feed really emitted, for the autotuner to probe the accel with. See global_dev_init ().

  pcfg_cell_t dev_probe;

  // The mean rectangle at the front of the stream, which is what the first launches carry and
  // therefore what the autotuner has to probe with. dev_avg is the average over the whole keyspace and
  // is what speed and progress are counted in; the two are not the same number.

  u32        dev_front;

  // What one step of the inner loop rewrites, in bytes. The autotuner's probe cell is one slot and this
  // is how wide to make it, so the probe pays for a step what a real cell pays.

  u32        dev_step;

  // the mean rectangle. What a base word is worth, as opposed to what the inner loop may reach.

  u32        dev_avg;

  // What the feed said its keyspace is, in base words, before any amplifier is applied. It cannot be
  // finished here: -a 6 and -a 7 amplify with the mask, and the mask is only sized once per round, in
  // mask_ctx_update_loop. So the number is kept and straight_ctx_update_loop finishes it.

  u64 keyspace;

} generic_ctx_t;

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

  // Which group reports for this device, as the index of the group's first member, and how many
  // devices that group holds. A device that leads its own group carries its own index and a size of
  // 1, which is every device outside a bridge.

  int     group_id_dev;
  int     group_size_dev;
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
  u64     kernel_power_dev;
  int     salt_pos_dev;
  u64     innerloop_pos_dev;
  u64     innerloop_left_dev;
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

  // The wordlist a ?q names. Guess.Mod is the mask for -a 12 and the mask does not say which wordlist
  // the ?q reads, so it is carried beside it rather than folded into it.

  char       *guess_mod_q;
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
  #ifdef WITH_BRAIN
  u64         brain_rejects_attacks;
  u64         brain_rejects_hashes;
  #endif
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

  // How many groups are actually running. The status view prints one line per group, so this is what
  // decides whether a total line underneath would say anything the lines above did not.

  int           group_info_active;

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

  // Set once a cracking thread has actually left its loop for the checkpoint. A thread that has gone
  // cannot be brought back, so from that point the checkpoint is happening whether or not the user
  // changes their mind, and the run has to be ended as a checkpoint rather than as an exhausted
  // round. Without this a cancel that lands too late cleared checkpoint_shutdown, the wait returned
  // with the status still RUNNING, and the round was booked as EXHAUSTED: the rest of the dictionary
  // was never dispatched and the restore file was deleted.

  bool checkpoint_taken;

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

  // What the producer of this round knows its unamplified keyspace to be.
  //
  // words_base is otherwise recovered by dividing words_cnt by the amplifier, which is exact only
  // while the product is. A base large enough that base times amplifier does not fit in 64 bits is
  // reachable from a feed that generates its base words rather than reading them, and there the
  // division recovers the wrong number from a saturated product. A producer that knows the base says
  // so here and the division is not consulted. Zero means it did not, which is every mask.

  u64  words_base_given;

  // -i and a mask file are a queue of rounds, and the queue is one keyspace. --skip and --limit
  // address the queue, so each round takes its own share of that window rather than applying the
  // whole of it again, which is what made --skip reach only the first round. These two are how far
  // into the queue the rounds before this one already got, unamplified and amplified, and --keyspace
  // is what they are for once the queue has been walked.

  u64  words_walk_base;
  u64  words_walk_cnt;

  // This round's share of the window, both positions in the round's own keyspace. words_limit is
  // zero when the round runs to its own end, which is what --limit not being given means.

  u64  words_skip;
  u64  words_limit;

  /**
   * progress
   */

  u64 *words_progress_done;     // progress number of words done     per salt
  u64 *words_progress_rejected; // progress number of words rejected per salt
  u64 *words_progress_restored; // progress number of words restored per salt

  #ifdef WITH_BRAIN
  // words_progress_rejected mixes every reason a candidate was dropped, so it cannot answer "how much
  // did the brain save". These two count only the brain, split by mechanism, because the mechanisms
  // are independent: ATTACKS skips a keyspace position another client already reserved, HASHES drops
  // a candidate the brain has seen before whatever position it came from.

  u64 brain_rejects_attacks;
  u64 brain_rejects_hashes;
  #endif

  int bypass_digests_done_new;  // --bypass-threshold cracked counter

  /**
   * timer
   */

  time_t runtime_start;
  time_t runtime_stop;

  time_t timer_bypass_start;
  time_t timer_bypass_cur;

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

  float runtime;

} cache_generate_t;

typedef struct hashlist_parse
{
  u64 hashes_cnt;
  u64 hashes_avail;

} hashlist_parse_t;

typedef struct event_ctx
{
  char   msg_buf[HCBUFSIZ_LARGE];
  size_t msg_len;
  bool   msg_newline;

  size_t prev_len;

  // How many lines have been logged, and whether the last of them was a blank one. They exist so
  // that a caller who brackets somebody else's output can tell whether there was any and whether it
  // already ended in a separator. Neither is a question prev_len can answer: prev_len says whether
  // the last line ended in a newline, and the bracket's own closing line always dirties it.

  u64    log_cnt;
  bool   log_blank;

  hc_thread_mutex_t mux_event;

  // msg_buf below is one buffer shared by every caller, and a log event deliberately does not take
  // mux_event: handlers that run with mux_event held log from inside it, so reusing that lock would
  // deadlock. This one covers the buffer and the emission that reads it, and nothing held while it
  // is taken ever waits on it, so the two cannot form a cycle.

  hc_thread_mutex_t mux_log;

} event_ctx_t;

#define BRIDGE_DEFAULT (void *) -1

typedef void (*BRIDGE_INIT) (void *);

// Declared ahead of bridge_ctx because platform_init takes one, and the definition comes further
// down this file. A bridge is handed the whole context rather than a few pieces of it, which is what
// lets it call hashcat's own logging functions with no wrapper of any kind.

typedef struct hashcat_ctx hashcat_ctx_t;

typedef struct bridge_ctx
{
  // local variables

  size_t      bridge_context_size;
  int         bridge_interface_version;

  hc_dynlib_t bridge_handle;

  BRIDGE_INIT bridge_init;

  bool        enabled;

  void       *platform_context;

  void       *pws_buf; // transfer buffer for tmps[]

  // functions

  void     *(*platform_init)      (hashcat_ctx_t *);
  void      (*platform_term)      (hashcat_ctx_t *, void *);

  int       (*get_unit_count)        (hashcat_ctx_t *, void *);
  char     *(*get_unit_info)         (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_count)    (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_multiple) (hashcat_ctx_t *, void *, const int);

  // Which units are interchangeable, for anything that wants to treat one unit's answer as valid for
  // another. Two units share a class when the same tuning is right for both.
  //
  // OPTIONAL. Leave it unset and units are compared by get_unit_info instead, which is correct
  // whenever a bridge's units are genuinely identical, and that is the usual case for a bridge whose
  // units are CPU threads. A bridge whose unit info names the individual device, by carrying its
  // device node for instance, has to answer this or no two of its units will ever look alike.
  //
  // It describes the CLASS, never the instance: same board, same design, same width, same clock. It
  // must not carry a serial number, a device path or an index.

  char     *(*get_unit_class)        (hashcat_ctx_t *, void *, const int);

  // What one unit is MADE OF, for a bridge whose unit is several pieces of hardware driven together.
  //
  // OPTIONAL, and a bridge whose units are single things leaves both unset. A bridge that groups
  // hardware has to answer them, because grouping is what takes the per-unit Speed line away from the
  // individual member: without a way to list them, a user with forty of them can see that one is
  // misbehaving and has no way to learn which.
  //
  // The member index is the unit's own numbering, from 0, and it is the SAME number the bridge uses
  // anywhere else it names a member. get_unit_member_info returns NULL for an index the unit does not
  // have.

  int       (*get_unit_member_count) (hashcat_ctx_t *, void *, const int);
  char     *(*get_unit_member_info)  (hashcat_ctx_t *, void *, const int, const int);

  // ★ hashes IS PASSED EXPLICITLY AND YOU MUST USE IT. Do not read hashcat_ctx->hashes here.
  //
  // The self test hands these functions a hashes_t that is a LOCAL COPY of the real one with its
  // digest, salt, esalt and hook salt buffers swapped for the self test's own. It is not the struct
  // hanging off hashcat_ctx, and it never will be. A bridge that reaches through the context instead
  // of taking the argument computes against the user's real hashes during the self test, which
  // either passes for the wrong reason or fails for one that makes no sense.
  //
  // This is the one place where having the whole context is a hazard rather than a convenience, and
  // it is why these signatures still carry what looks like redundant information. hashconfig is kept
  // beside it for the same reason: they arrive as a pair and separating them invites the mistake.

  bool      (*salt_prepare)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  void      (*salt_destroy)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);

  bool      (*thread_init)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  void      (*thread_term)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);

  bool      (*launch_loop)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  bool      (*launch_loop2)       (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);

  const char *(*st_update_pass)  (hashcat_ctx_t *, void *);
  const char *(*st_update_hash)  (hashcat_ctx_t *, void *);

  // Sensor readings for one unit, for bridges whose units are real hardware.
  //
  // hwmon otherwise describes the device that generates the candidates, which under a bridge is only
  // the feeder. These report the device that actually does the work instead.
  //
  // A bridge that has no sensors leaves them all at BRIDGE_DEFAULT. Return -1 for a reading this
  // particular unit cannot give, or 0 for the unsigned ones, which is what the rest of hwmon uses.

  int (*get_unit_temperature) (hashcat_ctx_t *, void *, const int);

  // Optional. A bridge unit whose hardware carries SEVERAL temperature sensors can render its own
  // field, so all of the readings show on one line instead of a single summary number. Return false
  // to let the plain get_unit_temperature reading be formatted as usual.

  bool (*get_unit_temperature_str) (hashcat_ctx_t *, void *, const int, char *, const size_t);

  // How the unit is attached, as text, when a lane count cannot say it. Optional, and only needed by a
  // bridge whose units are not all reached the same way.

  bool (*get_unit_buslanes_str) (hashcat_ctx_t *, void *, const int, char *, const size_t);

  // Optional. What temperature this unit must not exceed, when the bridge knows better than the
  // watchdog's default does. The default is chosen for GPUs, and a unit that is not one has no reason
  // to share it: its sensor may not sit where a GPU's does, so the same number does not mean the same
  // thing. Return 0 to keep the default.

  u32 (*get_unit_temperature_abort) (hashcat_ctx_t *, void *, const int);

  // Optional. How many of a unit's members report no temperature at all.
  //
  // A unit made of one piece of hardware is watched or it is not, and get_unit_temperature returning
  // -1 says which. A unit made of several is neither: the watchdog acts on the hottest member that
  // HAS a sensor, and the members that have none are simply not covered. Sensor presence is not even
  // a property of the class, because two members can report the same class string when only one of
  // them has a sensor fitted.
  //
  // So the banner has to be able to say how much of a watched unit is actually watched. Returning 0,
  // or leaving this unset, means everything the unit holds is covered.

  int (*get_unit_temperature_unwatched) (hashcat_ctx_t *, void *, const int);

  int (*get_unit_fanspeed)    (hashcat_ctx_t *, void *, const int);
  int (*get_unit_utilization) (hashcat_ctx_t *, void *, const int);
  int (*get_unit_corespeed)   (hashcat_ctx_t *, void *, const int);
  int (*get_unit_memoryspeed) (hashcat_ctx_t *, void *, const int);
  int (*get_unit_buslanes)    (hashcat_ctx_t *, void *, const int);
  u64 (*get_unit_power)       (hashcat_ctx_t *, void *, const int);

} bridge_ctx_t;

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
  const char *(*module_usage_notice)            (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_advice_notice)           (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos0)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos1)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos2)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_pos3)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u32         (*module_dgst_size)               (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  u64         (*module_esalt_size)              (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_extra_tuningdb_block)    (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const backend_ctx_t *, const hashes_t *, const u32, const u32);
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
  bool        (*module_hook_extra_param_init)   (hashcat_ctx_t *, const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const folder_config_t *, const backend_ctx_t *, void *);
  bool        (*module_hook_extra_param_term)   (hashcat_ctx_t *, const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const folder_config_t *, const backend_ctx_t *, void *);

  void        (*module_hook12)                  (hc_device_param_t *, const void *, const void *, const u32, const u64);
  void        (*module_hook23)                  (hc_device_param_t *, const void *, const void *, const u32, const u64);

  int         (*module_build_plain_postprocess) (const hashconfig_t *, const hashes_t *, const void *, const u32 *, const size_t, const int, u32 *, const size_t);

  bool        (*module_unstable_warning)        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hc_device_param_t *);

  bool        (*module_potfile_custom_check)    (const hashconfig_t *, const hash_t *, const hash_t *, const void *);

  u64         (*module_bridge_type)             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
  const char *(*module_bridge_name)             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);

} module_ctx_t;

struct hashcat_ctx
{
  brain_ctx_t           *brain_ctx;
  bitmap_ctx_t          *bitmap_ctx;
  bridge_ctx_t          *bridge_ctx;
  combinator_ctx_t      *combinator_ctx;
  cpt_ctx_t             *cpt_ctx;
  debugfile_ctx_t       *debugfile_ctx;
  event_ctx_t           *event_ctx;
  folder_config_t       *folder_config;
  generic_ctx_t         *generic_ctx;
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
  pubkey_ctx_t          *pubkey_ctx;
  pidfile_ctx_t         *pidfile_ctx;
  potfile_ctx_t         *potfile_ctx;
  restore_ctx_t         *restore_ctx;
  status_ctx_t          *status_ctx;
  straight_ctx_t        *straight_ctx;
  tuning_db_t           *tuning_db;
  user_options_extra_t  *user_options_extra;
  user_options_t        *user_options;

  void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t);

};

typedef struct thread_param
{
  u32 tid;

  hashcat_ctx_t *hashcat_ctx;

} thread_param_t;

typedef struct hook_thread_param
{
  int tid;
  int tsz;

  bridge_ctx_t *bridge_ctx;
  module_ctx_t *module_ctx;
  status_ctx_t *status_ctx;

  hc_device_param_t *device_param;

  void *hook_extra_param;
  void *hook_salts_buf;

  u32 salt_pos;
  u64 pws_cnt;

  // An association attack gives every candidate a salt of its own, and the kernel reaches it as
  // pws_pos + gid. A hook runs on the host and has to land on the same salt, so it is handed the
  // base of the chunk and adds the position of the candidate it is working on. Every other attack
  // has one salt for the whole launch and uses salt_pos.

  bool salt_per_pw;
  u64  pws_pos;

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
  HASH_CATEGORY_FBE                     = 23,
  HASH_CATEGORY_APPLICATION_DATABASE    = 24,
  HASH_CATEGORY_UNDEFINED               = -1,
} hash_category_t;

// hash specific

typedef aes_ctx AES_KEY;

#endif // HC_TYPES_H
