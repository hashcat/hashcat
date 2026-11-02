/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "shared.h"
#include "path.h"
#include "outfile.h"
#include "interface.h"
#include "rp.h"
#include "rp_cpu.h"
#include "recipe.h"
#include "module_options.h"
#include "user_options_table.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>

// The option table and the validator that reads it. Every refusal of a command line option is decided
// here, in four phases:
//
//   parse   type, range, nonempty, le, value validators              option_table_parse ()
//   static  one action, harmful options out of scope, attack modes
//           that conflict, excludes, requires, cross-option code,
//           stdin input                                              option_table_check ()
//   late    the loaded module, and the feed                          option_table_check_module (),
//                                                                    option_table_check_feed ()
//   derive  implications, which user_options_preprocess () and user_options_postprocess () apply
//
// Only a conflict is refused. An option that has no effect in the action or the attack mode of the run
// is accepted and ignored, unless being ignored does harm, which is OPTION_FLAG_HARM. The scope of
// every option stays in the table all the same, because the action model and the derivation read it.
//
// The table holds the core options of include/options.def and, after them, the options the modules
// registered, see src/module_options.c.
//
// With HASHCAT_OPTION_DEBUG=1 every verdict is printed on stderr as one OPTION-VERDICT line, and
// user_options_check_files () compares what the table implies with what preprocess set.

#define OPTION_REL_MAX 6

#define AB(a) (1u << (a))

// What a run does. Exactly one of these is selected by the options given, see table_resolve_action ().

typedef enum option_action
{
  ACTION_CRACK,
  ACTION_STDOUT,
  ACTION_KEYSPACE,
  ACTION_SHOW,
  ACTION_LEFT,
  ACTION_BENCHMARK,
  ACTION_SPEED_ONLY,
  ACTION_IDENTIFY,
  ACTION_USAGE,
  ACTION_HASH_INFO,
  ACTION_BACKEND_INFO,
  ACTION_RESTORE_PRINT,
  ACTION_VERSION,
  ACTION_BRAIN_SERVER,
  ACTION_BRAIN_FEED,
  ACTION_MODULE_CACHE,

  ACTION_COUNT,

} option_action_t;

#define ACT_CRACK        AB (ACTION_CRACK)
#define ACT_STDOUT       AB (ACTION_STDOUT)
#define ACT_KEYSPACE     AB (ACTION_KEYSPACE)
#define ACT_SHOW         AB (ACTION_SHOW)
#define ACT_LEFT         AB (ACTION_LEFT)
#define ACT_BENCHMARK    AB (ACTION_BENCHMARK)
#define ACT_SPEED_ONLY   AB (ACTION_SPEED_ONLY)
#define ACT_IDENTIFY     AB (ACTION_IDENTIFY)
#define ACT_USAGE        AB (ACTION_USAGE)
#define ACT_HASH_INFO    AB (ACTION_HASH_INFO)
#define ACT_BACKEND_INFO AB (ACTION_BACKEND_INFO)
#define ACT_RESTORE      AB (ACTION_RESTORE_PRINT)
#define ACT_VERSION      AB (ACTION_VERSION)
#define ACT_BRAIN_SERVER AB (ACTION_BRAIN_SERVER)
#define ACT_BRAIN_FEED   AB (ACTION_BRAIN_FEED)
#define ACT_MODULE_CACHE AB (ACTION_MODULE_CACHE)

// every action that sets up a session, which is all of them but --version, --restore, the brain and
// --module-cache-rebuild

#define ACT_SESSION (ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SHOW | ACT_LEFT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_IDENTIFY | ACT_USAGE | ACT_HASH_INFO | ACT_BACKEND_INFO)

// the actions that run an attack, and so read -a and are subject to attack_modes

#define ACT_ATTACK (ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY)

// the actions in which autodetect picks the hash-mode when -m is not given, see
// user_options_preprocess ()

#define ACT_AUTODETECT (ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_SPEED_ONLY | ACT_IDENTIFY)

#define ACT_ALL (AB (ACTION_COUNT) - 1)

#define AM(n) (1u << (n))

#define AM_ALL (AM (0) | AM (1) | AM (3) | AM (4) | AM (5) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12))

typedef enum option_type
{
  OPTION_TYPE_FLAG,
  OPTION_TYPE_COUNTER,
  OPTION_TYPE_U32,
  OPTION_TYPE_U64,
  OPTION_TYPE_STR,

} option_type_t;

// MAX bounds the value of a number, the count of a counter and how often a string option can be
// given. ZERO_UNSET is for a number whose 0 means what leaving it out means, so the rules between
// options see a 0 as not given.

typedef enum option_flag
{
  OPTION_FLAG_MIN        = (1 << 0),
  OPTION_FLAG_MAX        = (1 << 1),
  OPTION_FLAG_NONEMPTY   = (1 << 2),
  OPTION_FLAG_LEGACY     = (1 << 3),
  OPTION_FLAG_HARM       = (1 << 4),
  OPTION_FLAG_ZERO_UNSET = (1 << 5),

} option_flag_t;

typedef struct option_given
{
  u32         count;
  const char *arg;
  u32         order;

} option_given_t;

typedef struct option_rule option_rule_t;

// Every array below has one element per option: the core options and then the module options, which
// is count in all.

typedef struct option_table
{
  u32             debug;

  u32             count;

  module_options_t *module_options;
  option_rule_t    *module_rules;

  struct option  *long_options;
  char            short_options[128];

  option_given_t *given;
  u64            *value;
  char          (*numbers)[24];

  option_id_t    *order;
  u32             order_cnt;

  i32             argc;

  bool            from_struct;
  bool            checked;
  bool            refused;

  u32             action;
  option_id_t     action_opt;
  u32             attack_mode;

  bool           *ignored;

  bool            module_done;

  bool           *implied;
  option_id_t    *implied_by;

} option_table_t;

// A refusal is one error line, or several for a message that shows where in a value the problem is,
// and optional advice printed as warnings below it.

typedef struct option_text
{
  char msg[4096];
  char advice[1024];

} option_text_t;

typedef struct option_verdict
{
  bool          refuse;
  const char   *phase;
  const char   *rule;

  option_id_t   opt;
  option_id_t   opt2;

  option_text_t text;

} option_verdict_t;

typedef struct option_imply
{
  option_id_t opt;
  u64         value;

} option_imply_t;

typedef bool (*option_value_fn_t)  (option_table_t *, const option_id_t, option_text_t *);
typedef bool (*option_static_fn_t) (const option_table_t *, const option_id_t, option_text_t *);

// attack_modes is where the option has an effect, and outside it the option is ignored. conflict_modes
// is where it is refused instead, because the attack does the opposite of what the option is for or
// would apply it only in part.

struct option_rule
{
  option_id_t        alias;

  option_type_t      type;
  u32                flags;
  u64                min;
  u64                max;
  u64                def;
  option_id_t        le;
  option_value_fn_t  value_fn;

  u32                selects;
  bool               selects_with;
  u32                actions;
  u32                attack_modes;
  u32                conflict_modes;

  option_id_t        excludes[OPTION_REL_MAX];
  option_id_t        requires[OPTION_REL_MAX];
  option_id_t        requires_any[OPTION_REL_MAX];
  option_id_t        requires_opt;
  u64                requires_val;
  option_static_fn_t static_fn;

  option_imply_t     implies[OPTION_REL_MAX];

  u32                late;

};

// A message more specific than the generated one, matched by the rule and the options it names. A
// NULL msg keeps the generated message and only adds the advice. For excludes and one_action the two
// options match in either order.

typedef struct option_message
{
  const char  *rule;
  option_id_t  opt;
  option_id_t  opt2;
  const char  *msg;
  const char  *advice;

} option_message_t;

static const struct option option_table_long[] =
{
  #define OPTION(id, name, letter, idx, arg) { name, arg, NULL, idx },
  #include "options.def"
  #undef OPTION
  { NULL, 0, NULL, 0 }
};

static const char option_table_letter[] =
{
  #define OPTION(id, name, letter, idx, arg) letter,
  #include "options.def"
  #undef OPTION
  0
};

static const char *const action_name[ACTION_COUNT] =
{
  [ACTION_CRACK]         = "crack",
  [ACTION_STDOUT]        = "stdout",
  [ACTION_KEYSPACE]      = "keyspace",
  [ACTION_SHOW]          = "show",
  [ACTION_LEFT]          = "left",
  [ACTION_BENCHMARK]     = "benchmark",
  [ACTION_SPEED_ONLY]    = "speed_only",
  [ACTION_IDENTIFY]      = "identify",
  [ACTION_USAGE]         = "usage",
  [ACTION_HASH_INFO]     = "hash_info",
  [ACTION_BACKEND_INFO]  = "backend_info",
  [ACTION_RESTORE_PRINT] = "restore_print",
  [ACTION_VERSION]       = "version",
  [ACTION_BRAIN_SERVER]  = "brain_server",
  [ACTION_BRAIN_FEED]    = "brain_feed",
  [ACTION_MODULE_CACHE]  = "module_cache",
};

// The option a message names for an action when the user typed none of its selectors.

static const option_id_t action_selector[ACTION_COUNT] =
{
  [ACTION_CRACK]         = OPT_NONE,
  [ACTION_STDOUT]        = OPT_STDOUT_FLAG,
  [ACTION_KEYSPACE]      = OPT_KEYSPACE,
  [ACTION_SHOW]          = OPT_SHOW,
  [ACTION_LEFT]          = OPT_LEFT,
  [ACTION_BENCHMARK]     = OPT_BENCHMARK,
  [ACTION_SPEED_ONLY]    = OPT_SPEED_ONLY,
  [ACTION_IDENTIFY]      = OPT_IDENTIFY,
  [ACTION_USAGE]         = OPT_HELP,
  [ACTION_HASH_INFO]     = OPT_HASH_INFO,
  [ACTION_BACKEND_INFO]  = OPT_BACKEND_INFO,
  [ACTION_RESTORE_PRINT] = OPT_RESTORE,
  [ACTION_VERSION]       = OPT_VERSION,
  #ifdef WITH_BRAIN
  [ACTION_BRAIN_SERVER]  = OPT_BRAIN_SERVER,
  [ACTION_BRAIN_FEED]    = OPT_BRAIN_FEED,
  #endif
  [ACTION_MODULE_CACHE]  = OPT_MODULE_CACHE_REBUILD,
};

// Which action runs when several are selected. This is the order the code resolves them in: main.c
// leaves early for the brain modes, --version and --module-cache-rebuild, then picks usage, hash info
// and backend info after the session is set up, -b and the keyspace actions turn autodetect off,
// --stdout and the keyspace actions clear --show and --left in user_options_preprocess, autodetect
// answers --identify before the outer loop, outer_loop tests --show before --left, and
// restore_ctx_init skips the --restore printout for every action above it. Two action selectors given
// together are refused, unless both combine as the benchmark group does, so the order only determines
// which action a refusal names.

static const option_action_t action_precedence[ACTION_COUNT] =
{
  ACTION_BRAIN_FEED,
  ACTION_BRAIN_SERVER,
  ACTION_VERSION,
  ACTION_MODULE_CACHE,
  ACTION_USAGE,
  ACTION_HASH_INFO,
  ACTION_BACKEND_INFO,
  ACTION_BENCHMARK,
  ACTION_KEYSPACE,
  ACTION_STDOUT,
  ACTION_IDENTIFY,
  ACTION_SPEED_ONLY,
  ACTION_SHOW,
  ACTION_LEFT,
  ACTION_RESTORE_PRINT,
  ACTION_CRACK,
};

static bool vf_attack_mode         (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_hash_mode           (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_separator           (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_outfile_format      (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_lookup              (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_session             (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_rule                (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_hash_recipe         (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_cache_path          (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_vector_width        (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_backend_devices     (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_device_types        (option_table_t *table, const option_id_t id, option_text_t *text);
#ifdef WITH_BRAIN
static bool vf_brain_server_timer  (option_table_t *table, const option_id_t id, option_text_t *text);
static bool vf_brain_session       (option_table_t *table, const option_id_t id, option_text_t *text);
#endif

static bool sf_outfile_format      (const option_table_t *table, const option_id_t id, option_text_t *text);
static bool sf_debug_mode          (const option_table_t *table, const option_id_t id, option_text_t *text);
static bool sf_hash_mode           (const option_table_t *table, const option_id_t id, option_text_t *text);
static bool sf_custom_charset      (const option_table_t *table, const option_id_t id, option_text_t *text);
static bool sf_lookup              (const option_table_t *table, const option_id_t id, option_text_t *text);
static bool sf_device_types        (const option_table_t *table, const option_id_t id, option_text_t *text);

// A charset belongs to a mask. -a 4 and -a 8 read theirs from the setting mask=, and a feed that reads
// none ignores it, which is LATE_FEED_MASK.

#define CUSTOM_CHARSET_RULE                                                         \
  {                                                                                 \
    .type         = OPTION_TYPE_STR,                                                \
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,         \
    .attack_modes = AM (3) | AM (4) | AM (6) | AM (7) | AM (8) | AM (12),           \
    .static_fn    = sf_custom_charset,                                              \
    .late         = LATE_FEED_MASK,                                                 \
  }

#define BACKEND_IGNORE_RULE                                                         \
  {                                                                                 \
    .type         = OPTION_TYPE_FLAG,                                               \
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_BACKEND_INFO, \
  }

#define BRIDGE_PARAMETER_RULE                                                       \
  {                                                                                 \
    .type         = OPTION_TYPE_STR,                                                \
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,                     \
    .late         = LATE_MODULE_BRIDGE,                                             \
  }

static const option_rule_t option_rules[OPTION_COUNT] =
{
  [OPT_ADVICE_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_SESSION,
  },
  [OPT_ATTACK_MODE] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = ATTACK_MODE,
    .value_fn     = vf_attack_mode,
    .actions      = ACT_ATTACK,
  },
  [OPT_BACKEND_DEVICES] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .value_fn     = vf_backend_devices,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_BACKEND_DEVICES_VIRTMULTI] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = BACKEND_DEVICES_VIRTMULTI,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_BACKEND_INFO,
  },
  [OPT_BACKEND_DEVICES_VIRTHOST] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = BACKEND_DEVICES_VIRTHOST,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_BACKEND_INFO,
  },
  [OPT_BACKEND_IGNORE_CUDA]   = BACKEND_IGNORE_RULE,
  [OPT_BACKEND_IGNORE_HIP]    = BACKEND_IGNORE_RULE,
  #if defined (__APPLE__)
  [OPT_BACKEND_IGNORE_METAL]  = BACKEND_IGNORE_RULE,
  #endif
  [OPT_BACKEND_IGNORE_OPENCL] = BACKEND_IGNORE_RULE,
  [OPT_BACKEND_INFO] =
  {
    .type         = OPTION_TYPE_COUNTER,
    .flags        = OPTION_FLAG_MAX,
    .max          = 2,
    .selects      = ACT_BACKEND_INFO,
    .actions      = ACT_BACKEND_INFO,
    .implies      = { { OPT_QUIET, 0 } },
  },
  [OPT_BACKEND_VECTOR_WIDTH] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = BACKEND_VECTOR_WIDTH,
    .value_fn     = vf_vector_width,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .excludes     = { OPT_SLOW_CANDIDATES },
  },

  // The monitor only tests the threshold once the delay is given, and a threshold of 0 is never
  // undercut, so either one alone would quietly do nothing.

  [OPT_BYPASS_DELAY] =
  {
    .type         = OPTION_TYPE_U32,
    .actions      = ACT_CRACK,
    .requires     = { OPT_BYPASS_THRESHOLD },
  },
  [OPT_BYPASS_THRESHOLD] =
  {
    .type         = OPTION_TYPE_U32,
    .actions      = ACT_CRACK,
    .requires     = { OPT_BYPASS_DELAY },
  },
  [OPT_BENCHMARK_ALL] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BENCHMARK,
    .selects_with = true,
    .actions      = ACT_BENCHMARK,
    .excludes     = { OPT_HASH_MODE },
    .implies      = { { OPT_BENCHMARK, 0 } },
  },
  [OPT_BENCHMARK_JSON] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BENCHMARK,
    .selects_with = true,
    .actions      = ACT_BENCHMARK,
    .implies      = { { OPT_BENCHMARK, 0 } },
  },
  [OPT_BENCHMARK_MAX] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = BENCHMARK_MAX,
    .def          = BENCHMARK_MAX,
    .actions      = ACT_BENCHMARK,
    .excludes     = { OPT_HASH_MODE },
  },
  [OPT_BENCHMARK_MIN] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = BENCHMARK_MIN,
    .le           = OPT_BENCHMARK_MAX,
    .actions      = ACT_BENCHMARK,
    .excludes     = { OPT_HASH_MODE },
  },
  [OPT_BENCHMARK_PURE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BENCHMARK,
    .selects_with = true,
    .actions      = ACT_BENCHMARK,
    .excludes     = { OPT_OPTIMIZED_KERNEL_ENABLE },
    .implies      = { { OPT_BENCHMARK, 0 } },
  },
  [OPT_BENCHMARK] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BENCHMARK,
    .selects_with = true,
    .actions      = ACT_BENCHMARK,
    .implies      = { { OPT_SPEED_ONLY, 0 } },
  },
  [OPT_BITMAP_MAX] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = 28,
    .def          = BITMAP_MAX,
    .actions      = ACT_CRACK | ACT_SPEED_ONLY,
  },
  [OPT_BITMAP_MIN] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = BITMAP_MIN,
    .le           = OPT_BITMAP_MAX,
    .actions      = ACT_CRACK | ACT_SPEED_ONLY,
  },
  [OPT_BRIDGE_PARAMETER1] = BRIDGE_PARAMETER_RULE,
  [OPT_BRIDGE_PARAMETER2] = BRIDGE_PARAMETER_RULE,
  [OPT_BRIDGE_PARAMETER3] = BRIDGE_PARAMETER_RULE,
  [OPT_BRIDGE_PARAMETER4] = BRIDGE_PARAMETER_RULE,
  [OPT_CACHE_PATH] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .value_fn     = vf_cache_path,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_MODULE_CACHE,
  },
  [OPT_CPU_AFFINITY] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .actions      = ACT_SESSION,
  },
  [OPT_CUSTOM_CHARSET_1] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_2] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_3] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_4] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_5] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_6] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_7] = CUSTOM_CHARSET_RULE,
  [OPT_CUSTOM_CHARSET_8] = CUSTOM_CHARSET_RULE,

  // Without --debug-mode nothing is written to the file the user asked for.

  [OPT_DEBUG_FILE] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .actions      = ACT_CRACK,
    .requires     = { OPT_DEBUG_MODE },
  },
  [OPT_DEBUG_MODE] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = DEBUG_MODE_FEED,
    .def          = DEBUG_MODE,
    .actions      = ACT_CRACK,
    .static_fn    = sf_debug_mode,
  },
  [OPT_DEPRECATED_CHECK_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SHOW | ACT_LEFT | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_DYNAMIC_X] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_SPEED_ONLY,
  },
  [OPT_ENCODING_FROM] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (0) | AM (1) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12),
  },
  [OPT_ENCODING_TO] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (0) | AM (1) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12),
  },
  [OPT_EXAMPLE_HASHES] =
  {
    .alias        = OPT_HASH_INFO,
  },
  [OPT_FORCE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_SESSION,
  },
  [OPT_RP_GEN_FUNC_MAX] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = RP_GEN_FUNC_MAX,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
  },
  [OPT_RP_GEN_FUNC_MIN] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = RP_GEN_FUNC_MIN,
    .le           = OPT_RP_GEN_FUNC_MAX,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
  },
  [OPT_RP_GEN_FUNC_SEL] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
  },
  [OPT_RP_GEN] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_ZERO_UNSET,
    .def          = RP_GEN,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM_ALL,
    .excludes     = { OPT_RP_FILE },
  },
  [OPT_RP_GEN_SEED] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = RP_GEN_SEED,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
  },
  [OPT_HWMON_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_BACKEND_INFO,
    .excludes     = { OPT_HWMON_TEMP_ABORT },
  },
  [OPT_HWMON_TEMP_ABORT] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = HWMON_TEMP_ABORT,
    .actions      = ACT_CRACK,
  },
  [OPT_HASH_COPY] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT,
  },
  [OPT_HASH_INFO] =
  {
    .type         = OPTION_TYPE_COUNTER,
    .flags        = OPTION_FLAG_MAX,
    .max          = 2,
    .selects      = ACT_HASH_INFO,
    .actions      = ACT_HASH_INFO,
    .implies      = { { OPT_QUIET, 0 } },
  },
  [OPT_HASH_RECIPE] =
  {
    .type         = OPTION_TYPE_STR,
    .value_fn     = vf_hash_recipe,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_HASH_INFO,
    .requires_opt = OPT_HASH_MODE,
    .requires_val = 4000,
  },
  [OPT_HASH_MODE] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = HASH_MODE,
    .value_fn     = vf_hash_mode,
    .actions      = ACT_CRACK | ACT_KEYSPACE | ACT_SHOW | ACT_LEFT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_HASH_INFO,
    .static_fn    = sf_hash_mode,
  },
  [OPT_HELP] =
  {
    .type         = OPTION_TYPE_COUNTER,
    .flags        = OPTION_FLAG_MAX,
    .max          = 2,
    .selects      = ACT_USAGE,
    .actions      = ACT_USAGE,
    .implies      = { { OPT_QUIET, 0 } },
  },
  [OPT_HEX_CHARSET] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM (3) | AM (4) | AM (6) | AM (7) | AM (8) | AM (12),
  },
  [OPT_HEX_SALT] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_SPEED_ONLY | ACT_IDENTIFY,
    .late         = LATE_MODULE_HEX_SALT,
  },
  [OPT_HEX_WORDLIST] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (0) | AM (1) | AM (5) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12),
  },
  [OPT_HOOK_THREADS] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = HOOK_THREADS,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .late         = LATE_MODULE_HOOK,
  },
  [OPT_IDENTIFY] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_IDENTIFY,
    .actions      = ACT_IDENTIFY,
  },

  // Without -i the mask runs at its own length only, so a length bound given alone is not applied.

  [OPT_INCREMENT_MAX] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = INCREMENT_MAX,
    .def          = INCREMENT_MAX,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE,
    .attack_modes = AM (1) | AM (3) | AM (6) | AM (7),
    .requires_any = { OPT_INCREMENT, OPT_INCREMENT_INVERSE },
  },
  [OPT_INCREMENT_MIN] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = INCREMENT_MIN,
    .def          = INCREMENT_MIN,
    .le           = OPT_INCREMENT_MAX,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE,
    .attack_modes = AM (1) | AM (3) | AM (6) | AM (7),
    .requires_any = { OPT_INCREMENT, OPT_INCREMENT_INVERSE },
  },

  // -a 12 is left out because its ?w has a fixed position in the mask, and a shorter mask has nowhere
  // to put it. A feed can read a mask, and the increment code would then shorten it as well, so the
  // feed attacks are refused rather than ignored. -a 0 and -a 9 never build a mask.

  [OPT_INCREMENT] =
  {
    .type           = OPTION_TYPE_COUNTER,
    .flags          = OPTION_FLAG_MAX,
    .max            = 2,
    .actions        = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE,
    .attack_modes   = AM (1) | AM (3) | AM (6) | AM (7),
    .conflict_modes = AM (4) | AM (5) | AM (8) | AM (12),
  },
  [OPT_INCREMENT_INVERSE] =
  {
    .type           = OPTION_TYPE_FLAG,
    .actions        = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE,
    .attack_modes   = AM (1) | AM (3) | AM (6) | AM (7),
    .conflict_modes = AM (4) | AM (5) | AM (8) | AM (12),
  },

  // An association attack reads the induction folder as well, from a loop that was not written for it.

  [OPT_INDUCTION_DIR] =
  {
    .type           = OPTION_TYPE_STR,
    .actions        = ACT_CRACK,
    .attack_modes   = AM (0),
    .conflict_modes = AM (9),
  },
  [OPT_JSON] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_KEYSPACE | ACT_SHOW | ACT_LEFT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_IDENTIFY | ACT_HASH_INFO | ACT_BACKEND_INFO,
    .implies      = { { OPT_STATUS_JSON, 0 }, { OPT_OUTFILE_JSON, 0 }, { OPT_BENCHMARK_JSON, 0 } },
  },
  [OPT_KEEP_GUESSING] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
    .excludes     = { OPT_REMOVE },
  },

  // The ceiling here is the one a bridge allows, where kernel_accel counts candidates. Every other
  // mode is held against its own range once it is loaded, which is LATE_MODULE_ACCEL.

  [OPT_KERNEL_ACCEL] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN | OPTION_FLAG_MAX,
    .min          = 1,
    .max          = KERNEL_ACCEL_MAX_BRIDGE,
    .def          = KERNEL_ACCEL,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .requires     = { OPT_FORCE },
    .late         = LATE_MODULE_ACCEL,
  },

  // No upper bound: KERNEL_LOOPS_MAX is only the default ceiling, and several modules raise their own
  // through module_kernel_loops_max, up to 131072. backend_session_begin holds -u against it.

  [OPT_KERNEL_LOOPS] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = KERNEL_LOOPS,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .requires     = { OPT_FORCE },
    .late         = LATE_FEED_ENGINE_LOOPS,
  },
  [OPT_KERNEL_THREADS] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN | OPTION_FLAG_MAX,
    .min          = 1,
    .max          = 1024,
    .def          = KERNEL_THREADS,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .requires     = { OPT_FORCE },
    .late         = LATE_MODULE_THREADS,
  },
  [OPT_KEYSPACE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_KEYSPACE,
    .actions      = ACT_KEYSPACE,
    .attack_modes = AM_ALL & ~AM (9),
    .implies      = { { OPT_QUIET, 0 } },
  },
  [OPT_TOTAL_CANDIDATES] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_KEYSPACE,
    .actions      = ACT_KEYSPACE,
    .attack_modes = AM_ALL & ~AM (9),
    .implies      = { { OPT_QUIET, 0 }, { OPT_KEYSPACE, 0 } },
  },

  // --show and --left read the potfile, so a run that turns it off has nothing to show from.

  [OPT_LEFT] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_LEFT,
    .actions      = ACT_LEFT,
    .excludes     = { OPT_POTFILE_DISABLE },
    .implies      = { { OPT_QUIET, 0 }, { OPT_OUTFILE_FORMAT, OUTFILE_FMT_HASH }, { OPT_RESTORE_DISABLE, 0 } },
  },
  [OPT_LENGTH_SORT_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_LIMIT] =
  {
    .type         = OPTION_TYPE_U64,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = LIMIT,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .excludes     = { OPT_LOOPBACK },
  },
  [OPT_LOGFILE_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT,
  },

  // --lookup sizes every round the way --keyspace does and then reports where one candidate falls,
  // so it is a keyspace action. A rule cannot be inverted, and only the attack modes listed have an
  // inversion written for them, so everything else is refused rather than answered wrongly.

  [OPT_LOOKUP] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .value_fn     = vf_lookup,
    .selects      = ACT_KEYSPACE,
    .actions      = ACT_KEYSPACE,
    .attack_modes = AM (0) | AM (1) | AM (3) | AM (4) | AM (6) | AM (7) | AM (12),
    .excludes     = { OPT_RP_FILE, OPT_RP_GEN },
    .static_fn    = sf_lookup,
    .implies      = { { OPT_QUIET, 0 }, { OPT_KEYSPACE, 0 } },
  },

  // The loopback file is written in every attack mode, but only a straight attack reads it back, so
  // elsewhere it would collect plains that nothing ever feeds back. Without rules a loopback round
  // tries the plains it was given once more, and with --keep-guessing it finds them again forever.

  [OPT_LOOPBACK] =
  {
    .type           = OPTION_TYPE_FLAG,
    .actions        = ACT_CRACK,
    .attack_modes   = AM (0),
    .conflict_modes = AM_ALL & ~AM (0),
    .requires_any   = { OPT_RP_FILE, OPT_RP_GEN },
  },
  [OPT_MACHINE_READABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_IDENTIFY | ACT_HASH_INFO | ACT_BACKEND_INFO,
    .excludes     = { OPT_STATUS_JSON, OPT_JSON, OPT_BENCHMARK_JSON },
  },
  [OPT_MARKOV_CLASSIC] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (3) | AM (6) | AM (7) | AM (12),
  },
  [OPT_MARKOV_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (3) | AM (6) | AM (7) | AM (12),
    .excludes     = { OPT_MARKOV_CLASSIC, OPT_MARKOV_INVERSE },
  },
  [OPT_MARKOV_HCSTAT2] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE,
    .attack_modes = AM (3) | AM (6) | AM (7) | AM (12),
  },
  [OPT_MARKOV_INVERSE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (3) | AM (6) | AM (7) | AM (12),
  },
  [OPT_MARKOV_THRESHOLD] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = MARKOV_THRESHOLD,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM (3) | AM (6) | AM (7) | AM (12),
  },
  [OPT_METAL_COMPILER_RUNTIME] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = METAL_COMPILER_RUNTIME,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },

  // hidden from --help: rebuilds the module option cache, see src/module_options_cache.c, and exits

  [OPT_MODULE_CACHE_REBUILD] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_MODULE_CACHE,
    .actions      = ACT_MODULE_CACHE,
  },
  [OPT_OPENCL_DEVICE_TYPES] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .value_fn     = vf_device_types,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_BENCHMARK | ACT_SPEED_ONLY | ACT_BACKEND_INFO,
    .static_fn    = sf_device_types,
  },
  [OPT_OPTIMIZED_KERNEL_ENABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
    .late         = LATE_FEED_ENGINE_KERNEL,
  },
  [OPT_MULTIPLY_ACCEL_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_OUTFILE_AUTOHEX_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_LEFT,
  },
  [OPT_OUTFILE_CHECK_DIR] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK,
  },
  [OPT_OUTFILE_CHECK_TIMER] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = OUTFILE_CHECK_TIMER,
    .actions      = ACT_CRACK,
  },
  [OPT_OUTFILE_FORMAT] =
  {
    .type         = OPTION_TYPE_STR,
    .def          = OUTFILE_FORMAT,
    .value_fn     = vf_outfile_format,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT,
    .excludes     = { OPT_OUTFILE_JSON },
    .static_fn    = sf_outfile_format,
  },
  [OPT_OUTFILE_JSON] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT,
  },
  [OPT_OUTFILE] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_SHOW | ACT_LEFT,
  },
  [OPT_POTFILE_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
    .attack_modes = AM_ALL & ~AM (9),
    .excludes     = { OPT_POTFILE_PATH },
  },

  // An association attack turns the potfile off, so a potfile named for it would never be written.
  // --potfile-disable agrees with that and is accepted.

  [OPT_POTFILE_PATH] =
  {
    .type           = OPTION_TYPE_STR,
    .actions        = ACT_CRACK | ACT_SHOW | ACT_LEFT,
    .attack_modes   = AM_ALL & ~AM (9),
    .conflict_modes = AM (9),
  },
  [OPT_PROGRESS_ONLY] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_SPEED_ONLY,
    .actions      = ACT_SPEED_ONLY,
    .implies      = { { OPT_SPEED_ONLY, 0 } },
  },

  // --quiet silences the human text and nothing else, so it stands beside every machine readable
  // output

  [OPT_QUIET] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_SESSION,
  },

  // The two file form of an association attack pairs the hash file with the wordlist by line number,
  // so taking the cracked lines out of the hash file would pair every later line with the wrong word.

  [OPT_REMOVE] =
  {
    .type           = OPTION_TYPE_FLAG,
    .actions        = ACT_CRACK,
    .attack_modes   = AM_ALL & ~AM (9),
    .conflict_modes = AM (9),
  },
  [OPT_REMOVE_TIMER] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = REMOVE_TIMER,
    .actions      = ACT_CRACK,
  },
  [OPT_RESTORE_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
  },
  [OPT_RESTORE_FILE_PATH] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .actions      = ACT_CRACK | ACT_RESTORE,
  },
  [OPT_RESTORE_POSITION] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
  },
  [OPT_RESTORE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_RESTORE,
    .actions      = ACT_RESTORE,
    .excludes     = { OPT_RESTORE_POSITION },
  },

  // -a 4 and -a 5 are -a 8 with the feed named, so -j reaches them wherever the host makes the
  // candidates. The device engine has no base word side to apply it to, which is LATE_FEED_ENGINE.

  [OPT_RULE_BUF_L] =
  {
    .type         = OPTION_TYPE_STR,
    .value_fn     = vf_rule,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM (0) | AM (1) | AM (4) | AM (5) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12),
    .late         = LATE_FEED_ENGINE,
  },
  [OPT_RULE_BUF_R] =
  {
    .type         = OPTION_TYPE_STR,
    .value_fn     = vf_rule,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM (1) | AM (7) | AM (12),
    .late         = LATE_FEED_ENGINE,
  },

  // user_options_init () has room for 256 rules files

  [OPT_RP_FILE] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_MAX,
    .max          = 256,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes = AM_ALL,
  },
  [OPT_RP_FILE_CONCAT] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
  },
  [OPT_RUNTIME] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = RUNTIME,
    .actions      = ACT_CRACK | ACT_STDOUT,
  },
  [OPT_SELF_TEST_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_SEPARATOR] =
  {
    .type         = OPTION_TYPE_STR,
    .value_fn     = vf_separator,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_SPEED_ONLY,
  },
  [OPT_SEPERATOR] =
  {
    .alias        = OPT_SEPARATOR,
  },
  [OPT_SESSION] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_NONEMPTY,
    .value_fn     = vf_session,
    .actions      = ACT_SESSION | ACT_RESTORE,
  },
  [OPT_SHOW] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_SHOW,
    .actions      = ACT_SHOW,
    .excludes     = { OPT_POTFILE_DISABLE },
    .implies      = { { OPT_QUIET, 0 }, { OPT_RESTORE_DISABLE, 0 } },
  },
  [OPT_SKIP] =
  {
    .type         = OPTION_TYPE_U64,
    .def          = SKIP,
    .actions      = ACT_CRACK | ACT_STDOUT,
  },

  // The slow candidate generators have no association attack.

  [OPT_SLOW_CANDIDATES] =
  {
    .type           = OPTION_TYPE_FLAG,
    .actions        = ACT_CRACK | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes   = AM_ALL & ~AM (9),
    .conflict_modes = AM (9),
    .late           = LATE_INPUT_NOT_STDIN,
  },
  [OPT_SPEED_ONLY] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_SPEED_ONLY,
    .actions      = ACT_SPEED_ONLY,
  },
  [OPT_SPIN_DAMP] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = 100,
    .def          = SPIN_DAMP,
    .actions      = ACT_CRACK,
  },
  [OPT_STATUS] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
  },
  [OPT_STATUS_JSON] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SPEED_ONLY,
  },
  [OPT_PIPELINE_STATS] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_TASK_TIME_BREAKDOWN] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_BENCHMARK | ACT_SPEED_ONLY,
  },
  [OPT_STATUS_TIMER] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = STATUS_TIMER,
    .actions      = ACT_CRACK,
  },
  [OPT_STDOUT_FLAG] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_STDOUT,
    .actions      = ACT_STDOUT,
    .attack_modes = AM_ALL & ~AM (9),
    .implies      = { { OPT_QUIET, 0 }, { OPT_FORCE, 0 } },
  },
  [OPT_STDIN_COUNT] =
  {
    .type         = OPTION_TYPE_U64,
    .flags        = OPTION_FLAG_MIN,
    .min          = 1,
    .def          = STDIN_COUNT,
    .actions      = ACT_CRACK,
    .attack_modes = AM (0),
    .excludes     = { OPT_LIMIT },
    .late         = LATE_INPUT_STDIN,
  },
  [OPT_STDIN_TIMEOUT_ABORT] =
  {
    .type         = OPTION_TYPE_U32,
    .def          = STDIN_TIMEOUT_ABORT,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (0),
    .late         = LATE_INPUT_STDIN,
  },
  [OPT_USERNAME] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_SHOW | ACT_LEFT | ACT_SPEED_ONLY | ACT_IDENTIFY,
  },
  [OPT_VERSION] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_VERSION,
    .actions      = ACT_VERSION,
  },
  [OPT_WORDLIST_AUTOHEX_DISABLE] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK | ACT_STDOUT,
    .attack_modes = AM (0) | AM (1) | AM (6) | AM (7) | AM (8) | AM (9) | AM (12),
  },

  // -w selected one of four launch budgets. There is one budget now, and every tutorial and front end
  // still passes it, so every action takes it and nothing about it is checked.

  [OPT_WORKLOAD_PROFILE] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_LEGACY,
  },
  #ifdef WITH_BRAIN
  // --stdout keeps the brain client on, unlike the other actions that run no attack. --keyspace and
  // --speed-only measure the slow candidate path the client puts a cracking run on, so the keyspace
  // and the speed they report are the ones that run walks.

  [OPT_BRAIN_CLIENT] =
  {
    .type           = OPTION_TYPE_FLAG,
    .actions        = ACT_CRACK | ACT_STDOUT | ACT_KEYSPACE | ACT_SPEED_ONLY,
    .attack_modes   = AM_ALL & ~AM (9),
    .conflict_modes = AM (9),
    .excludes       = { OPT_REMOVE, OPT_POTFILE_DISABLE },
    .requires       = { OPT_BRAIN_PASSWORD },
    .late           = LATE_INPUT_NOT_STDIN,
  },

  // The feeder reads stdin and exits. It has no hash list to compute the session from, so the session
  // has to be given.

  [OPT_BRAIN_FEED] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BRAIN_FEED,
    .actions      = ACT_BRAIN_FEED,
    .requires     = { OPT_BRAIN_PASSWORD, OPT_BRAIN_SESSION },
  },
  [OPT_BRAIN_CLIENT_FEATURES] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MIN | OPTION_FLAG_MAX,
    .min          = 1,
    .max          = 3,
    .def          = BRAIN_CLIENT_FEATURES,
    .actions      = ACT_CRACK,
  },
  [OPT_BRAIN_SERVER] =
  {
    .type         = OPTION_TYPE_FLAG,
    .selects      = ACT_BRAIN_SERVER,
    .actions      = ACT_BRAIN_SERVER,
  },
  [OPT_BRAIN_SERVER_TIMER] =
  {
    .type         = OPTION_TYPE_U32,
    .value_fn     = vf_brain_server_timer,
    .actions      = ACT_BRAIN_SERVER,
  },
  [OPT_BRAIN_HOST] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK | ACT_BRAIN_SERVER | ACT_BRAIN_FEED,
  },
  [OPT_BRAIN_PORT] =
  {
    .type         = OPTION_TYPE_U32,
    .flags        = OPTION_FLAG_MAX,
    .max          = 65535,
    .def          = BRAIN_PORT,
    .actions      = ACT_CRACK | ACT_BRAIN_SERVER | ACT_BRAIN_FEED,
  },
  [OPT_BRAIN_PASSWORD] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_CRACK | ACT_BRAIN_SERVER | ACT_BRAIN_FEED,
  },
  [OPT_BRAIN_SESSION] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_ZERO_UNSET,
    .value_fn     = vf_brain_session,
    .actions      = ACT_CRACK | ACT_BRAIN_FEED,
  },
  [OPT_BRAIN_SESSION_WHITELIST] =
  {
    .type         = OPTION_TYPE_STR,
    .actions      = ACT_BRAIN_SERVER,
  },
  #endif
  [OPT_COLOR_CRACKED] =
  {
    .type         = OPTION_TYPE_FLAG,
    .actions      = ACT_CRACK,
  },

  // --encrypt-with-pubkey exists so that a recovered password never appears in the clear on the
  // machine doing the cracking. Each option it excludes would write one out in the clear somewhere
  // else, so the pair is refused rather than half honoured. Ignored in another action it would let
  // that action print plains in the clear, --show among them, so it is refused there too.

  [OPT_ENCRYPT_WITH_PUBKEY] =
  {
    .type         = OPTION_TYPE_STR,
    .flags        = OPTION_FLAG_HARM,
    .actions      = ACT_CRACK,
    .excludes     = { OPT_LOOPBACK, OPT_DEBUG_FILE, OPT_DEBUG_MODE, OPT_RESTORE_POSITION },
    .implies      = { { OPT_RESTORE_DISABLE, 0 } },
  },
};

static const option_message_t option_messages[] =
{
  { "excludes",       OPT_ENCRYPT_WITH_PUBKEY,     OPT_LOOPBACK,         NULL, "The loopback file would receive the encrypted plains and feed them back as candidates." },
  { "excludes",       OPT_ENCRYPT_WITH_PUBKEY,     OPT_DEBUG_FILE,       NULL, "The debug file records the originating word in the clear." },
  { "excludes",       OPT_ENCRYPT_WITH_PUBKEY,     OPT_DEBUG_MODE,       NULL, "The debug output records the originating word in the clear." },
  { "excludes",       OPT_ENCRYPT_WITH_PUBKEY,     OPT_RESTORE_POSITION, NULL, "A protected run writes no restore file, because it would record how far the run got." },
  { "scope",          OPT_ENCRYPT_WITH_PUBKEY,     OPT_RESTORE,          NULL, "A protected run writes no restore file, because it would record how far the run got." },
  { "scope",          OPT_ENCRYPT_WITH_PUBKEY,     OPT_SHOW,             NULL, "The potfile can hold plains in the clear from unprotected runs. Entries from a protected run are already encrypted, so use --show without this option." },
  { "scope",          OPT_ENCRYPT_WITH_PUBKEY,     OPT_STDOUT_FLAG,      NULL, "--stdout prints every candidate in the clear, and a protected run hides its candidates." },
  { "excludes",       OPT_RESTORE_POSITION,        OPT_RESTORE,          NULL, "--restore prints the command line to run. --restore-position belongs to that printed command line." },
  #ifdef WITH_BRAIN
  { "requires",       OPT_BRAIN_FEED,              OPT_BRAIN_SESSION,    NULL, "The session selects the brain database the candidates go into. It is normally\ncomputed from the hash list, which a feeder does not have. Any brain run prints\nit on the status line as Brain Session/Attack." },
  #endif
  { "requires",       OPT_KERNEL_ACCEL,            OPT_FORCE,            "The manual use of -n (--kernel-accel) is outdated.",   "Autotune sizes the launch itself.\nYou can use --force to override this, but do not report related errors." },
  { "requires",       OPT_KERNEL_LOOPS,            OPT_FORCE,            "The manual use of -u (--kernel-loops) is outdated.",   "Autotune sizes the launch itself.\nYou can use --force to override this, but do not report related errors." },
  { "requires",       OPT_KERNEL_THREADS,          OPT_FORCE,            "The manual use of -T (--kernel-threads) is outdated.", "You can use --force to override this, but do not report related errors." },
  { "attack_modes",   OPT_STDOUT_FLAG,             OPT_NONE,             NULL, "An association attack takes its candidates from the hash file, which --stdout does not read. Use --debug-mode to see what a run is trying." },
  { "attack_modes",   OPT_KEYSPACE,                OPT_NONE,             NULL, "An association attack takes its keyspace from the hash file, which --keyspace does not read." },
  { "attack_modes",   OPT_TOTAL_CANDIDATES,        OPT_NONE,             NULL, "An association attack takes its keyspace from the hash file, which --total-candidates does not read." },
  { "attack_modes",   OPT_LOOKUP,                  OPT_NONE,             NULL, "The other attack modes have no inversion yet, so there is no offset to give rather than a wrong one." },
  { "excludes",       OPT_LOOKUP,                  OPT_RP_FILE,          NULL, "A rule cannot be inverted, so the answer would have to be found by building every candidate the run builds.\nWithout rules --lookup answers in one pass over the base words, and answers a mask without reading anything at all." },
  { "excludes",       OPT_LOOKUP,                  OPT_RP_GEN,           NULL, "A rule cannot be inverted, so the answer would have to be found by building every candidate the run builds.\nWithout rules --lookup answers in one pass over the base words, and answers a mask without reading anything at all." },
  { "one_action",     OPT_LOOKUP,                  OPT_RESTORE,          NULL, "Give --lookup the command line of the run instead. It answers about the attack, not about how far a session got." },
  { "conflict_modes", OPT_POTFILE_PATH,            OPT_ATTACK_MODE,      NULL, "An association attack turns the potfile off, so this potfile would never be written." },
  { "conflict_modes", OPT_REMOVE,                  OPT_ATTACK_MODE,      NULL, "The hash file and the wordlist are paired by line number, and removing the cracked lines would pair the rest with the wrong words." },
  { "conflict_modes", OPT_LOOPBACK,                OPT_ATTACK_MODE,      NULL, "Only a straight attack feeds the loopback file back. Anywhere else it would collect plains for nothing." },
  { "conflict_modes", OPT_INCREMENT,               OPT_ATTACK_MODE,      NULL, "Attack mode 12 keeps ?w at a fixed position that a shorter mask has no room for. A feed would have its own mask shortened." },
  { "conflict_modes", OPT_INCREMENT_INVERSE,       OPT_ATTACK_MODE,      NULL, "Attack mode 12 keeps ?w at a fixed position that a shorter mask has no room for. A feed would have its own mask shortened." },
  { "late_feed",      OPT_OPTIMIZED_KERNEL_ENABLE, OPT_NONE,             "The device engine has no optimized kernel for this hash-mode. Run this without -O.", NULL },
  { "late_feed",      OPT_RULE_BUF_L,              OPT_NONE,             NULL, "The engine builds a candidate out of the grammar rather than out of the base word, so a rule on the base word reaches only part of what it generates.\nUse -r instead, which the engine applies to every candidate it makes.\nThe same attack keeps -j and -k wherever the host makes the candidates, which is any slow hash, --stdout and --slow-candidates." },
  { "late_feed",      OPT_RULE_BUF_R,              OPT_NONE,             NULL, "The engine builds a candidate out of the grammar rather than out of the base word, so a rule on the base word reaches only part of what it generates.\nUse -r instead, which the engine applies to every candidate it makes.\nThe same attack keeps -j and -k wherever the host makes the candidates, which is any slow hash, --stdout and --slow-candidates." },
};

// An option's id is its row in long_options, plus one. The core rows come first, in the order of
// include/options.def, and the module rows after them.

static const char *option_name (const option_table_t *table, const option_id_t id)
{
  if (id == OPT_NONE) return "-";

  const char *name = table->long_options[id - 1].name;

  return name;
}

static const option_rule_t *option_rule (const option_table_t *table, const option_id_t id)
{
  if ((u32) id >= OPTION_COUNT)
  {
    const option_rule_t *rule = &table->module_rules[id - OPTION_COUNT];

    return rule;
  }

  const option_rule_t *rule = &option_rules[id];

  return rule;
}

static bool option_given (const option_table_t *table, const option_id_t id)
{
  const bool given = (table->given[id].count > 0);

  return given;
}

static void text_printf (option_text_t *text, const char *fmt, ...) __attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3)));

static void text_printf (option_text_t *text, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  vsnprintf (text->msg, sizeof (text->msg), fmt, ap);

  va_end (ap);

  text->advice[0] = 0;
}

static void verdict_message (option_verdict_t *v)
{
  const bool symmetric = (strcmp (v->rule, "excludes") == 0) || (strcmp (v->rule, "one_action") == 0);

  const size_t cnt = sizeof (option_messages) / sizeof (option_messages[0]);

  for (size_t i = 0; i < cnt; i++)
  {
    const option_message_t *m = &option_messages[i];

    if (strcmp (m->rule, v->rule) != 0) continue;

    bool match = (m->opt == v->opt) && ((m->opt2 == OPT_NONE) || (m->opt2 == v->opt2));

    if ((match == false) && (symmetric == true)) match = (m->opt == v->opt2) && (m->opt2 == v->opt);

    if (match == false) continue;

    if (m->msg    != NULL) snprintf (v->text.msg,    sizeof (v->text.msg),    "%s", m->msg);
    if (m->advice != NULL) snprintf (v->text.advice, sizeof (v->text.advice), "%s", m->advice);

    return;
  }
}

// The first refusal is the verdict.

static void verdict_refuse (option_verdict_t *v, const char *phase, const char *rule, const option_id_t opt, const option_id_t opt2, const option_text_t *text)
{
  if (v->refuse == true) return;

  v->refuse = true;
  v->phase  = phase;
  v->rule   = rule;
  v->opt    = opt;
  v->opt2   = opt2;
  v->text   = *text;

  verdict_message (v);
}

static void table_log_lines (hashcat_ctx_t *hashcat_ctx, const char *text, const bool error)
{
  const size_t len = strlen (text);

  size_t start = 0;

  for (size_t i = 0; i <= len; i++)
  {
    if ((text[i] != '\n') && (text[i] != 0)) continue;

    const int line_len = (int) (i - start);

    if (error == true)
    {
      event_log_error (hashcat_ctx, "%.*s", line_len, &text[start]);
    }
    else
    {
      event_log_warning (hashcat_ctx, "%.*s", line_len, &text[start]);
    }

    start = i + 1;
  }
}

static void table_debug_verdict (const option_table_t *table, const option_verdict_t *v, const char *tag)
{
  fprintf (stderr, "%s refuse=%s phase=%s rule=%s opt=%s opt2=%s action=%s am=%u\n",
    tag,
    (v->refuse == true) ? "yes"    : "no",
    (v->refuse == true) ? v->phase : "-",
    (v->refuse == true) ? v->rule  : "-",
    option_name (table, v->opt),
    option_name (table, v->opt2),
    action_name[table->action],
    table->attack_mode);

  fflush (stderr);
}

static void table_report (hashcat_ctx_t *hashcat_ctx, const option_table_t *table, const option_verdict_t *v)
{
  if (table->debug > 0) table_debug_verdict (table, v, "OPTION-VERDICT");

  if (v->refuse == false) return;

  table_log_lines (hashcat_ctx, v->text.msg, true);

  if (v->text.advice[0] == 0) return;

  table_log_lines (hashcat_ctx, v->text.advice, false);

  event_log_warning (hashcat_ctx, NULL);
}

static void attack_modes_text (const u32 attack_modes, char *buf, const size_t buf_sz)
{
  u32 list[32];
  u32 list_cnt = 0;

  for (u32 i = 0; i < 32; i++)
  {
    if ((attack_modes & AM (i)) == 0) continue;

    list[list_cnt] = i;

    list_cnt++;
  }

  buf[0] = 0;

  for (u32 i = 0; i < list_cnt; i++)
  {
    const size_t len = strlen (buf);

    const char *sep = "";

    if (i > 0) sep = ((i + 1) == list_cnt) ? " or " : ", ";

    snprintf (&buf[len], buf_sz - len, "%s%u", sep, list[i]);
  }
}

// value validators, parse phase

static bool vf_attack_mode (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const u64 attack_mode = table->value[id];

  if ((attack_mode < 32) && ((AM_ALL & AM (attack_mode)) != 0)) return true;

  char modes[64];

  attack_modes_text (AM_ALL, modes, sizeof (modes));

  text_printf (text, "--attack-mode %s is not an attack mode, use %s.", table->given[id].arg, modes);

  return false;
}

static bool vf_hash_mode (option_table_t *table, const option_id_t id, option_text_t *text)
{
  if (table->value[id] < (u64) MODULE_HASH_MODES_MAXIMUM) return true;

  text_printf (text, "--hash-type must be lower than %d.", MODULE_HASH_MODES_MAXIMUM);

  return false;
}

static bool vf_separator (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const char *sep = table->given[id].arg;

  const size_t len = strlen (sep);

  if (len == 1) return true;

  // user_options_sanity () turns 0xHH into the byte, which a program that fills user_options skips

  if (table->from_struct == true)
  {
    text_printf (text, "--separator must be one byte.");

    return false;
  }

  if ((len == 4) && (sep[0] == '0') && (sep[1] == 'x') && (is_valid_hex_string ((const u8 *) &sep[2], 2) == true)) return true;

  text_printf (text, "--separator must be one byte, a character or 0xHH, for example 0x09 for a tab.");

  return false;
}

static bool vf_outfile_format (option_table_t *table, const option_id_t id, option_text_t *text)
{
  // a program that fills user_options hands the format over already parsed

  if (table->from_struct == true)
  {
    if (table->value[id] != 0) return true;

    text_printf (text, "--outfile-format names no output format.");

    return false;
  }

  const u32 format = outfile_format_parse (table->given[id].arg);

  table->value[id] = format;

  if (format != 0) return true;

  text_printf (text, "--outfile-format '%s' names no output format.", table->given[id].arg);

  return false;
}

// A candidate is bytes, and $HEX[...] is how the potfile and --show spell the ones no shell can pass,
// so the length that has to fit is the decoded one.

static bool vf_lookup (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const char *lookup = table->given[id].arg;

  const size_t len = strlen (lookup);

  size_t bytes = len;

  if (is_hexify ((const u8 *) lookup, len) == true) bytes = (len - 6) / 2;

  if (bytes <= PW_MAX) return true;

  text_printf (text, "--lookup must not be longer than %d bytes.", PW_MAX);

  return false;
}

static bool vf_session (option_table_t *table, const option_id_t id, option_text_t *text)
{
  #if defined (_WIN)
  const char *invalid = "/<>:\"\\|?*";
  #else
  const char *invalid = "/";
  #endif

  const char *session = table->given[id].arg;

  const size_t len = strlen (session);

  for (size_t i = 0; i < len; i++)
  {
    if (strchr (invalid, session[i]) == NULL) continue;

    text_printf (text, "--session must not contain any of '%s'.", invalid);

    return false;
  }

  return true;
}

static bool vf_rule (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const char *rule = table->given[id].arg;

  char rule_buf_in[RP_PASSWORD_SIZE];
  char rule_buf_out[RP_PASSWORD_SIZE];

  rule_buf_in[0] = 0;

  const int rc = _old_apply_rule (rule, (int) strlen (rule), rule_buf_in, 0, rule_buf_out);

  if (rc != RULE_RC_SYNTAX_ERROR) return true;

  text_printf (text, "--%s '%s' is not a valid rule.", option_name (table, id), rule);

  return false;
}

static bool vf_hash_recipe (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const char *recipe = table->given[id].arg;

  recipe_prog_t recipe_prog;

  if (recipe_compile (&recipe_prog, recipe) == true) return true;

  // a recipe can span several lines, so the line holding the error is shown with a caret below it

  u32 line_start = recipe_prog.error_pos;

  while ((line_start > 0) && (recipe[line_start - 1] != '\n')) line_start--;

  u32 line_end = recipe_prog.error_pos;

  while ((recipe[line_end] != 0) && (recipe[line_end] != '\n')) line_end++;

  text_printf (text, "--hash-recipe is invalid, %s:\n  %.*s\n  %*s^", recipe_prog.error, (int) (line_end - line_start), &recipe[line_start], (int) (recipe_prog.error_pos - line_start), "");

  return false;
}

// A directory that is not there is worth stopping for, because the alternative is a run that rebuilds
// every kernel every time and never prints why. Not being able to write to it is fine: a read only share
// is a normal way to use this.

static bool vf_cache_path (option_table_t *table, const option_id_t id, option_text_t *text)
{
  if (hc_path_is_directory (table->given[id].arg) == true) return true;

  text_printf (text, "--cache-path must be an existing directory.");

  return false;
}

static bool vf_vector_width (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const u64 width = table->value[id];

  if ((width <= 16) && (is_power_of_2 ((u32) width) == true)) return true;

  text_printf (text, "--backend-vector-width must be 1, 2, 4, 8 or 16.");

  return false;
}

// A comma separated list of numbers, each one tested against the caller's range. Spaces around a
// number are fine, the way strtol () reads them in backend.c, but the list has to hold a number,
// because a list of commas alone leaves backend.c no token to read.

static bool number_list_valid (const char *list, const u64 min, const u64 max, u64 *bad)
{
  const size_t len = strlen (list);

  u64 cur = 0;

  bool in_number   = false;
  bool number_done = false;
  bool any         = false;

  *bad = 0;

  for (size_t i = 0; i <= len; i++)
  {
    const char c = list[i];

    if ((c == ',') || (c == 0))
    {
      if (in_number == false) continue;

      *bad = cur;

      if (cur < min) return false;
      if (cur > max) return false;

      cur = 0;

      in_number   = false;
      number_done = false;

      continue;
    }

    if (c == ' ')
    {
      if (in_number == true) number_done = true;

      continue;
    }

    if ((c < '0') || (c > '9')) return false;

    if (number_done == true) return false;

    if (cur < 0xffffffff) cur = (cur * 10) + (u64) (c - '0');

    in_number = true;

    any = true;
  }

  return any;
}

static bool vf_backend_devices (option_table_t *table, const option_id_t id, option_text_t *text)
{
  u64 bad = 0;

  if (number_list_valid (table->given[id].arg, 1, DEVICES_MAX - 1, &bad) == true) return true;

  text_printf (text, "--backend-devices takes device numbers from 1 to %d, separated by commas.", DEVICES_MAX - 1);

  return false;
}

// Device type 3 was the OpenCL accelerator card. It parses here, and sf_device_types () refuses it
// for a run once the action is known.

static bool vf_device_types (option_table_t *table, const option_id_t id, option_text_t *text)
{
  u64 bad = 0;

  if (number_list_valid (table->given[id].arg, 1, 3, &bad) == true) return true;

  text_printf (text, "--opencl-device-types takes 1 (CPU) and 2 (GPU), separated by commas.");

  return false;
}

#ifdef WITH_BRAIN
static bool vf_brain_server_timer (option_table_t *table, const option_id_t id, option_text_t *text)
{
  const u64 timer = table->value[id];

  // 0 turns the intermediate dumps off

  if ((timer == 0) || (timer >= 60)) return true;

  text_printf (text, "--brain-server-timer must be 0 or at least 60 seconds.");

  return false;
}

// The session is hexadecimal and read the way user_options_getopt () reads it, so that a 0, which
// OPTION_FLAG_ZERO_UNSET turns into not given, is the 0 the run gets. A program that fills
// user_options hands the number over.

static bool vf_brain_session (option_table_t *table, const option_id_t id, MAYBE_UNUSED option_text_t *text)
{
  if (table->from_struct == true) return true;

  table->value[id] = hc_strtoul (table->given[id].arg, NULL, 16);

  return true;
}
#endif

// cross-option checks that depend on a value, static phase

static bool sf_outfile_format (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  const u64 format = table->value[id];

  if ((table->action == ACTION_LEFT) && (format > 1))
  {
    text_printf (text, "--outfile-format must be 1 with --left.");

    return false;
  }

  if (table->action != ACTION_SHOW) return true;

  if ((format & (OUTFILE_FMT_CRACKPOS | OUTFILE_FMT_TIME_ABS | OUTFILE_FMT_TIME_REL)) == 0) return true;

  text_printf (text, "--outfile-format with --show takes no crack position and no timestamp.");

  return false;
}

// --debug-mode writes the rule that made a candidate. The attack modes whose candidates are built from
// a mask have one as soon as they are given rules, which make them a feed with the rule as amplifier.
// Mode 6 writes what the feed did instead, which is the answer for an attack with no rules at all.
// Whether the feed can report what it did is settled once the feed is loaded.

static bool sf_debug_mode (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  const u64 debug_mode = table->value[id];

  if (debug_mode == 0) return true;

  const u32 attack_mode = table->attack_mode;

  const bool rules_given = (option_given (table, OPT_RP_FILE) == true) || (option_given (table, OPT_RP_GEN) == true);

  const bool has_feed = (attack_mode == ATTACK_MODE_PCFG) || (attack_mode == ATTACK_MODE_TABLE) || (attack_mode == ATTACK_MODE_GENERIC) || (attack_mode == ATTACK_MODE_ASSOCIATION);

  const bool mask_is_typed = (attack_mode == ATTACK_MODE_COMBI) || (attack_mode == ATTACK_MODE_BF) || (attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2) || (attack_mode == ATTACK_MODE_HYBRID);

  if ((attack_mode != ATTACK_MODE_STRAIGHT) && (has_feed == false) && ((mask_is_typed == false) || (rules_given == false)))
  {
    text_printf (text, "--debug-mode needs attack mode 0, 4, 5, 8 or 9, or attack mode 1, 3, 6, 7 or 12 with --rules-file or --generate-rules.");

    return false;
  }

  if (debug_mode == DEBUG_MODE_FEED)
  {
    if (has_feed == true) return true;

    text_printf (text, "--debug-mode %d needs attack mode 4, 5, 8 or 9.", DEBUG_MODE_FEED);

    return false;
  }

  if ((rules_given == true) || (has_feed == true)) return true;

  text_printf (text, "--debug-mode needs --rules-file or --generate-rules.");

  return false;
}

static bool sf_hash_mode (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  if (table->value[id] != 4000) return true;

  if (option_given (table, OPT_HASH_RECIPE) == true) return true;
  if (option_given (table, OPT_HASH_INFO)   == true) return true;
  if (option_given (table, OPT_DYNAMIC_X)   == true) return true;

  text_printf (text, "--hash-type 4000 needs --hash-recipe, for example --hash-recipe 'md5(md5(salt) . pass)'.");

  return false;
}

static bool sf_custom_charset (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  // -a 4 and -a 8 take their mask as a setting, so there is no positional mask to count

  if ((table->attack_mode == ATTACK_MODE_PCFG) || (table->attack_mode == ATTACK_MODE_GENERIC)) return true;

  i32 masks = table->argc;

  if ((table->action != ACTION_KEYSPACE) && (table->action != ACTION_STDOUT)) masks--;

  if (masks > 0) return true;

  text_printf (text, "--%s needs a mask.", option_name (table, id));

  return false;
}

// --lookup reads no hashes, exactly as --keyspace reads none, so a hash file in front of the mask would
// be opened as the mask. Only the two modes whose command line is one work argument are checked here.
// The argument count table in user_options_sanity () covers the rest.

static bool sf_lookup (const option_table_t *table, MAYBE_UNUSED const option_id_t id, option_text_t *text)
{
  if ((table->attack_mode != ATTACK_MODE_BF) && (table->attack_mode != ATTACK_MODE_STRAIGHT)) return true;

  const char *want = (table->attack_mode == ATTACK_MODE_BF) ? "mask" : "wordlist";

  if (table->argc == 1) return true;

  if (table->argc > 1)
  {
    text_printf (text, "--lookup takes the %s on its own, with no hash file, exactly as --keyspace does.", want);

    snprintf (text->advice, sizeof (text->advice), "It answers about the attack and reads no hashes, so the hash file would be read as the %s.", want);
  }
  else
  {
    text_printf (text, "--lookup needs a %s to look in.", want);
  }

  return false;
}

// Device type 3 was the OpenCL accelerator card. Hardware of that kind is reached through an
// assimilation bridge now, and a bridge is selected by the hash-mode, so there is nothing left for -D
// to point at in a run. -I is a question about the machine instead, which backend.c answers with the
// devices that match and the same reason, see setup_opencl_device_types_filter ().

static bool sf_device_types (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  if (table->action == ACTION_BACKEND_INFO) return true;

  u64 bad = 0;

  if (number_list_valid (table->given[id].arg, 1, 2, &bad) == true) return true;

  text_printf (text, "--opencl-device-types 3, the accelerator card, no longer exists.");

  snprintf (text->advice, sizeof (text->advice), "Hardware reached through an assimilation bridge is selected by the hash-mode, never by -D.\n-D 1 is CPU and -D 2 is GPU.");

  return false;
}

// The table's own getopt pass. It reads the command line exactly as typed, independently of the one
// in user_options_getopt () that sets the values, and fills the given record.

static option_id_t option_by_value (const option_table_t *table, const int c)
{
  for (u32 i = 0; table->long_options[i].name != NULL; i++)
  {
    if (table->long_options[i].val != c) continue;

    const option_id_t id = (option_id_t) (i + 1);

    const option_id_t alias = option_rule (table, id)->alias;

    if (alias != OPT_NONE) return alias;

    return id;
  }

  return OPT_NONE;
}

static option_id_t option_by_name (const option_table_t *table, const char *name)
{
  if (name == NULL) return OPT_NONE;

  for (u32 i = 0; table->long_options[i].name != NULL; i++)
  {
    if (strcmp (table->long_options[i].name, name) != 0) continue;

    const option_id_t id = (option_id_t) (i + 1);

    return id;
  }

  return OPT_NONE;
}

// A module row becomes a rule like any other. It is in scope in every action, and its hash-modes are
// tested once the module is loaded, see option_table_check_module ().

static void table_module_rule (option_table_t *table, const u32 idx)
{
  const module_option_t *row = &table->module_options->entries[idx].row;

  option_rule_t *rule = &table->module_rules[idx];

  rule->alias = option_by_name (table, row->alias);

  if (rule->alias != OPT_NONE) return;

  if (row->type == MODULE_OPTION_TYPE_FLAG) rule->type = OPTION_TYPE_FLAG;
  if (row->type == MODULE_OPTION_TYPE_U32)  rule->type = OPTION_TYPE_U32;
  if (row->type == MODULE_OPTION_TYPE_STR)  rule->type = OPTION_TYPE_STR;

  if ((row->flags & MODULE_OPTION_FLAG_MIN) != 0) rule->flags |= OPTION_FLAG_MIN;
  if ((row->flags & MODULE_OPTION_FLAG_MAX) != 0) rule->flags |= OPTION_FLAG_MAX;

  rule->min     = row->min;
  rule->max     = row->max;
  rule->def     = row->def;
  rule->le      = option_by_name (table, row->le);
  rule->actions = ACT_ALL;

  rule->excludes[0] = option_by_name (table, row->excludes);
  rule->requires[0] = option_by_name (table, row->requires);
}

static option_table_t *table_create (module_options_t *module_options)
{
  option_table_t *table = (option_table_t *) hccalloc (1, sizeof (option_table_t));

  const char *env = getenv ("HASHCAT_OPTION_DEBUG");

  if ((env != NULL) && (env[0] >= '1') && (env[0] <= '9')) table->debug = (u32) (env[0] - '0');

  const u32 module_cnt = (module_options == NULL) ? 0 : module_options->entries_cnt;

  const u32 core_cnt = OPTION_COUNT - 1;

  table->count          = OPTION_COUNT + module_cnt;
  table->module_options = module_options;

  table->module_rules = (option_rule_t *)   hccalloc (module_cnt + 1,           sizeof (option_rule_t));
  table->long_options = (struct option *)   hccalloc (core_cnt + module_cnt + 1, sizeof (struct option));
  table->given        = (option_given_t *)  hccalloc (table->count,             sizeof (option_given_t));
  table->value        = (u64 *)             hccalloc (table->count,             sizeof (u64));
  table->numbers      = (char (*)[24])      hccalloc (table->count,             sizeof (*table->numbers));
  table->order        = (option_id_t *)     hccalloc (table->count,             sizeof (option_id_t));
  table->ignored      = (bool *)            hccalloc (table->count,             sizeof (bool));
  table->implied      = (bool *)            hccalloc (table->count,             sizeof (bool));
  table->implied_by   = (option_id_t *)     hccalloc (table->count,             sizeof (option_id_t));

  memcpy (table->long_options, option_table_long, core_cnt * sizeof (struct option));

  for (u32 i = 0; i < module_cnt; i++)
  {
    const module_option_t *row = &module_options->entries[i].row;

    struct option *long_option = &table->long_options[core_cnt + i];

    long_option->name    = row->name;
    long_option->has_arg = (row->type == MODULE_OPTION_TYPE_FLAG) ? no_argument : required_argument;
    long_option->flag    = NULL;
    long_option->val     = IDX_MODULE_OPTION + (int) i;
  }

  for (u32 i = 0; i < module_cnt; i++) table_module_rule (table, i);

  // a leading ':' makes getopt return ':' for a missing value and '?' for an unknown option

  u32 short_len = 0;

  table->short_options[short_len] = ':';

  short_len++;

  for (u32 i = 0; i < core_cnt; i++)
  {
    const char letter = option_table_letter[i];

    if (letter == 0) continue;

    table->short_options[short_len] = letter;

    short_len++;

    if (option_table_long[i].has_arg == no_argument) continue;

    table->short_options[short_len] = ':';

    short_len++;
  }

  table->short_options[short_len] = 0;

  for (u32 i = 1; i < table->count; i++) table->value[i] = option_rule (table, (option_id_t) i)->def;

  return table;
}

static void table_destroy (option_table_t *table)
{
  if (table == NULL) return;

  hcfree (table->module_rules);
  hcfree (table->long_options);
  hcfree (table->given);
  hcfree (table->value);
  hcfree (table->numbers);
  hcfree (table->order);
  hcfree (table->ignored);
  hcfree (table->implied);
  hcfree (table->implied_by);

  hcfree (table);
}

// For an option getopt could not take. optopt is the character of a short option, or the getopt
// value of a long one, which is a letter as well for a long option that has a short form. A long
// option that is not known at all leaves optopt at 0.

static void table_parse_error (const option_table_t *table, option_text_t *text, const int c, const int argc, char **argv)
{
  const char *typed = ((optind > 0) && (optind <= argc)) ? argv[optind - 1] : "";

  const bool typed_long = (typed[0] == '-') && (typed[1] == '-');

  const size_t name_len = strcspn (typed, "=");

  // A missing value is reported for the option as it was typed, whichever form that was. The BSD
  // getopt_long () that macOS and mingw-w64 ship returns the same ':' for a value given to an option
  // that takes none, which only a typed "=" distinguishes.

  if (c == ':')
  {
    if ((typed_long == true) && (typed[name_len] == '='))
    {
      text_printf (text, "%.*s takes no value.", (int) name_len, typed);
    }
    else if (typed_long == true)
    {
      text_printf (text, "%.*s needs a value.", (int) name_len, typed);
    }
    else
    {
      text_printf (text, "-%c needs a value.", optopt);
    }

    return;
  }

  if (optopt == 0)
  {
    text_printf (text, "%.*s is not an option, or is short for more than one.", (int) name_len, typed);

    return;
  }

  // getopt does not refuse a short option the short option string holds, so a known value is a long
  // option that was given a value it does not take. The ':' in that string is no option of its own.

  const bool known_letter = (optopt < 256) && (optopt != ':') && (strchr (table->short_options, optopt) != NULL);

  if ((optopt >= 256) || (known_letter == true))
  {
    text_printf (text, "--%s takes no value.", option_name (table, option_by_value (table, optopt)));

    return;
  }

  text_printf (text, "-%c is not an option.", optopt);
}

static void table_give (option_table_t *table, const option_id_t id, const u32 count, const char *arg)
{
  option_given_t *given = &table->given[id];

  if (given->count == 0)
  {
    table->order[table->order_cnt] = id;

    table->order_cnt++;

    given->order = table->order_cnt;
  }

  given->count += count;
  given->arg    = arg;
}

static void table_parse_argv (option_table_t *table, option_verdict_t *v, const int argc, char **argv)
{
  // optind 0 rather than 1 makes getopt start from scratch, whatever an earlier pass left behind

  const int opterr_sav = opterr;

  opterr = 0;
  optind = 0;
  optopt = 0;

  int option_index = 0;

  int c = -1;

  while ((c = getopt_long (argc, argv, table->short_options, table->long_options, &option_index)) != -1)
  {
    if ((c == '?') || (c == ':'))
    {
      option_text_t text;

      table_parse_error (table, &text, c, argc, argv);

      verdict_refuse (v, "parse", "parser", OPT_NONE, OPT_NONE, &text);

      break;
    }

    const option_id_t id = option_by_value (table, c);

    if (id == OPT_NONE) continue;

    table_give (table, id, 1, optarg);
  }

  table->argc = argc - optind;

  opterr = opterr_sav;
  optind = 1;
  optopt = 0;
}

// A program that fills user_options itself has no command line, so what it gave is read off the
// struct: an option counts as given where its field differs from the default user_options_init ()
// set, or where its _chgd flag is set. A caller never has a reason to set a _chgd flag, so a field
// that has one is tested against its default as well. A value equal to the default is not distinguished
// from no value, which only matters for the pairs whose rule names a given option.
//
// Two are detected by the flag alone. hashcat_session_init () names the session itself for several
// actions before this runs, and a seed without the flag is not used, see setup_seeding ().

static u32 table_struct_given (const user_options_t *user_options, const option_id_t id, u64 *value, const char **arg)
{
  const user_options_t *uo = user_options;

  u32 count = 0;

  *value = 0;
  *arg   = NULL;

  switch (id)
  {
    case OPT_ADVICE_DISABLE:            count = (uo->advice                    == false);                                                     break;
    case OPT_ATTACK_MODE:               count = ((uo->attack_mode_chgd == true) || (uo->attack_mode != ATTACK_MODE)); *value = uo->attack_mode;                           break;
    case OPT_BACKEND_DEVICES:           count = (uo->backend_devices           != NULL);  *arg   = uo->backend_devices;                       break;
    case OPT_BACKEND_DEVICES_VIRTMULTI: count = (uo->backend_devices_virtmulti != BACKEND_DEVICES_VIRTMULTI); *value = uo->backend_devices_virtmulti; break;
    case OPT_BACKEND_DEVICES_VIRTHOST:  count = (uo->backend_devices_virthost  != BACKEND_DEVICES_VIRTHOST);  *value = uo->backend_devices_virthost;  break;
    case OPT_BACKEND_IGNORE_CUDA:       count = (uo->backend_ignore_cuda       == true);                                                      break;
    case OPT_BACKEND_IGNORE_HIP:        count = (uo->backend_ignore_hip        == true);                                                      break;
    #if defined (__APPLE__)
    case OPT_BACKEND_IGNORE_METAL:      count = (uo->backend_ignore_metal      == true);                                                      break;
    #endif
    case OPT_BACKEND_IGNORE_OPENCL:     count = (uo->backend_ignore_opencl     == true);                                                      break;
    case OPT_BACKEND_INFO:              count = uo->backend_info;                                                                             break;
    case OPT_BACKEND_VECTOR_WIDTH:      count = ((uo->backend_vector_width_chgd == true) || (uo->backend_vector_width != BACKEND_VECTOR_WIDTH));  *value = uo->backend_vector_width;                  break;
    case OPT_BYPASS_DELAY:              count = ((uo->bypass_delay_chgd == true) || (uo->bypass_delay != 0));  *value = uo->bypass_delay;                          break;
    case OPT_BYPASS_THRESHOLD:          count = ((uo->bypass_threshold_chgd == true) || (uo->bypass_threshold != 0));  *value = uo->bypass_threshold;                      break;
    case OPT_BENCHMARK_ALL:             count = (uo->benchmark_all             == true);                                                      break;
    case OPT_BENCHMARK_JSON:            count = (uo->benchmark_json            == true);                                                      break;
    case OPT_BENCHMARK_MAX:             count = (uo->benchmark_max             != BENCHMARK_MAX); *value = uo->benchmark_max;                 break;
    case OPT_BENCHMARK_MIN:             count = (uo->benchmark_min             != BENCHMARK_MIN); *value = uo->benchmark_min;                 break;
    case OPT_BENCHMARK_PURE:            count = (uo->benchmark_pure            == true);                                                      break;
    case OPT_BENCHMARK:                 count = (uo->benchmark                 == true);                                                      break;
    case OPT_BITMAP_MAX:                count = (uo->bitmap_max                != BITMAP_MAX);    *value = uo->bitmap_max;                    break;
    case OPT_BITMAP_MIN:                count = (uo->bitmap_min                != BITMAP_MIN);    *value = uo->bitmap_min;                    break;
    case OPT_BRIDGE_PARAMETER1:         count = (uo->bridge_parameter1         != NULL);  *arg   = uo->bridge_parameter1;                     break;
    case OPT_BRIDGE_PARAMETER2:         count = (uo->bridge_parameter2         != NULL);  *arg   = uo->bridge_parameter2;                     break;
    case OPT_BRIDGE_PARAMETER3:         count = (uo->bridge_parameter3         != NULL);  *arg   = uo->bridge_parameter3;                     break;
    case OPT_BRIDGE_PARAMETER4:         count = (uo->bridge_parameter4         != NULL);  *arg   = uo->bridge_parameter4;                     break;
    case OPT_CACHE_PATH:                count = (uo->cache_path                != NULL);  *arg   = uo->cache_path;                            break;
    case OPT_CPU_AFFINITY:              count = (uo->cpu_affinity              != NULL);  *arg   = uo->cpu_affinity;                          break;
    case OPT_CUSTOM_CHARSET_1:          count = (uo->custom_charset_1          != NULL);  *arg   = uo->custom_charset_1;                      break;
    case OPT_CUSTOM_CHARSET_2:          count = (uo->custom_charset_2          != NULL);  *arg   = uo->custom_charset_2;                      break;
    case OPT_CUSTOM_CHARSET_3:          count = (uo->custom_charset_3          != NULL);  *arg   = uo->custom_charset_3;                      break;
    case OPT_CUSTOM_CHARSET_4:          count = (uo->custom_charset_4          != NULL);  *arg   = uo->custom_charset_4;                      break;
    case OPT_CUSTOM_CHARSET_5:          count = (uo->custom_charset_5          != NULL);  *arg   = uo->custom_charset_5;                      break;
    case OPT_CUSTOM_CHARSET_6:          count = (uo->custom_charset_6          != NULL);  *arg   = uo->custom_charset_6;                      break;
    case OPT_CUSTOM_CHARSET_7:          count = (uo->custom_charset_7          != NULL);  *arg   = uo->custom_charset_7;                      break;
    case OPT_CUSTOM_CHARSET_8:          count = (uo->custom_charset_8          != NULL);  *arg   = uo->custom_charset_8;                      break;
    case OPT_DEBUG_FILE:                count = (uo->debug_file                != NULL);  *arg   = uo->debug_file;                            break;
    case OPT_DEBUG_MODE:                count = (uo->debug_mode                != DEBUG_MODE);    *value = uo->debug_mode;                    break;
    case OPT_DEPRECATED_CHECK_DISABLE:  count = (uo->deprecated_check          == false);                                                     break;
    case OPT_DYNAMIC_X:                 count = (uo->dynamic_x                 == true);                                                      break;
    case OPT_ENCODING_FROM:             count = ((uo->encoding_from != NULL) && (strcmp (uo->encoding_from, "utf-8") != 0)); *arg = uo->encoding_from;                         break;
    case OPT_ENCODING_TO:               count = ((uo->encoding_to   != NULL) && (strcmp (uo->encoding_to,   "utf-8") != 0)); *arg = uo->encoding_to;                           break;
    case OPT_FORCE:                     count = (uo->force                     == true);                                                      break;
    case OPT_RP_GEN_FUNC_MAX:           count = (uo->rp_gen_func_max           != RP_GEN_FUNC_MAX); *value = uo->rp_gen_func_max;             break;
    case OPT_RP_GEN_FUNC_MIN:           count = (uo->rp_gen_func_min           != RP_GEN_FUNC_MIN); *value = uo->rp_gen_func_min;             break;
    case OPT_RP_GEN_FUNC_SEL:           count = (uo->rp_gen_func_sel           != NULL);  *arg   = uo->rp_gen_func_sel;                       break;
    case OPT_RP_GEN:                    count = (uo->rp_gen                    != RP_GEN);        *value = uo->rp_gen;                        break;
    case OPT_RP_GEN_SEED:               count = (uo->rp_gen_seed_chgd          == true);  *value = uo->rp_gen_seed;                           break;
    case OPT_HWMON_DISABLE:             count = (uo->hwmon                     == false);                                                     break;
    case OPT_HWMON_TEMP_ABORT:          count = (uo->hwmon_temp_abort          != HWMON_TEMP_ABORT); *value = uo->hwmon_temp_abort;           break;
    case OPT_HASH_COPY:                 count = (uo->hash_copy                 == true);                                                      break;
    case OPT_HASH_INFO:                 count = uo->hash_info;                                                                                break;
    case OPT_HASH_RECIPE:               count = (uo->hash_recipe               != NULL);  *arg   = uo->hash_recipe;                           break;
    case OPT_HASH_MODE:                 count = ((uo->hash_mode_chgd == true) || (uo->hash_mode != HASH_MODE));  *value = (u64) uo->hash_mode;                       break;
    case OPT_HELP:                      count = uo->usage;                                                                                    break;
    case OPT_HEX_CHARSET:               count = (uo->hex_charset               == true);                                                      break;
    case OPT_HEX_SALT:                  count = (uo->hex_salt                  == true);                                                      break;
    case OPT_HEX_WORDLIST:              count = (uo->hex_wordlist              == true);                                                      break;
    case OPT_HOOK_THREADS:              count = (uo->hook_threads              != HOOK_THREADS);  *value = uo->hook_threads;                  break;
    case OPT_IDENTIFY:                  count = (uo->identify                  == true);                                                      break;
    case OPT_INCREMENT_MAX:             count = ((uo->increment_max_chgd == true) || (uo->increment_max != INCREMENT_MAX));  *value = uo->increment_max;                         break;
    case OPT_INCREMENT_MIN:             count = ((uo->increment_min_chgd == true) || (uo->increment_min != INCREMENT_MIN));  *value = uo->increment_min;                         break;
    case OPT_INCREMENT:                 count = (uo->increment                 == INCREMENT_NORMAL);                                          break;
    case OPT_INCREMENT_INVERSE:         count = (uo->increment                 == INCREMENT_INVERSED);                                        break;
    case OPT_INDUCTION_DIR:             count = (uo->induction_dir             != NULL);  *arg   = uo->induction_dir;                         break;
    case OPT_JSON:                      count = (uo->json                      == true);                                                      break;
    case OPT_KEEP_GUESSING:             count = (uo->keep_guessing             == true);                                                      break;
    case OPT_KERNEL_ACCEL:              count = ((uo->kernel_accel_chgd == true) || (uo->kernel_accel != KERNEL_ACCEL));  *value = uo->kernel_accel;                          break;
    case OPT_KERNEL_LOOPS:              count = ((uo->kernel_loops_chgd == true) || (uo->kernel_loops != KERNEL_LOOPS));  *value = uo->kernel_loops;                          break;
    case OPT_KERNEL_THREADS:            count = ((uo->kernel_threads_chgd == true) || (uo->kernel_threads != KERNEL_THREADS));  *value = uo->kernel_threads;                        break;
    case OPT_KEYSPACE:                  count = (uo->keyspace                  == true);                                                      break;
    case OPT_TOTAL_CANDIDATES:          count = (uo->total_candidates          == true);                                                      break;
    case OPT_LEFT:                      count = (uo->left                      == true);                                                      break;
    case OPT_LENGTH_SORT_DISABLE:       count = (uo->length_sort_disable       == true);                                                      break;
    case OPT_LIMIT:                     count = ((uo->limit_chgd == true) || (uo->limit != LIMIT));  *value = uo->limit;                                 break;
    case OPT_LOGFILE_DISABLE:           count = (uo->logfile                   == false);                                                     break;
    case OPT_LOOKUP:                    count = (uo->lookup                    != NULL);  *arg   = uo->lookup;                                break;
    case OPT_LOOPBACK:                  count = (uo->loopback                  == true);                                                      break;
    case OPT_MACHINE_READABLE:          count = (uo->machine_readable          == true);                                                      break;
    case OPT_MARKOV_CLASSIC:            count = (uo->markov_classic            == true);                                                      break;
    case OPT_MARKOV_DISABLE:            count = (uo->markov                    == false);                                                     break;
    case OPT_MARKOV_HCSTAT2:            count = (uo->markov_hcstat2            != NULL);  *arg   = uo->markov_hcstat2;                        break;
    case OPT_MARKOV_INVERSE:            count = (uo->markov_inverse            == true);                                                      break;
    case OPT_MARKOV_THRESHOLD:          count = (uo->markov_threshold          != MARKOV_THRESHOLD); *value = uo->markov_threshold;           break;
    case OPT_METAL_COMPILER_RUNTIME:    count = ((uo->metal_compiler_runtime_chgd == true) || (uo->metal_compiler_runtime != METAL_COMPILER_RUNTIME)); *value = uo->metal_compiler_runtime;               break;
    case OPT_OPENCL_DEVICE_TYPES:       count = (uo->opencl_device_types       != NULL);  *arg   = uo->opencl_device_types;                   break;
    case OPT_OPTIMIZED_KERNEL_ENABLE:   count = (uo->optimized_kernel          == true);                                                      break;
    case OPT_MULTIPLY_ACCEL_DISABLE:    count = (uo->multiply_accel            == false);                                                     break;
    case OPT_OUTFILE_AUTOHEX_DISABLE:   count = (uo->outfile_autohex           == false);                                                     break;
    case OPT_OUTFILE_CHECK_DIR:         count = (uo->outfile_check_dir         != NULL);  *arg   = uo->outfile_check_dir;                     break;
    case OPT_OUTFILE_CHECK_TIMER:       count = (uo->outfile_check_timer       != OUTFILE_CHECK_TIMER); *value = uo->outfile_check_timer;     break;
    case OPT_OUTFILE_FORMAT:            count = ((uo->outfile_format_chgd == true) || (uo->outfile_format != OUTFILE_FORMAT));  *value = uo->outfile_format;                        break;
    case OPT_OUTFILE_JSON:              count = (uo->outfile_json              == true);                                                      break;
    case OPT_OUTFILE:                   count = (uo->outfile                   != NULL);  *arg   = uo->outfile;                               break;
    case OPT_POTFILE_DISABLE:           count = (uo->potfile                   == false);                                                     break;
    case OPT_POTFILE_PATH:              count = (uo->potfile_path              != NULL);  *arg   = uo->potfile_path;                          break;
    case OPT_PROGRESS_ONLY:             count = (uo->progress_only             == true);                                                      break;
    case OPT_QUIET:                     count = (uo->quiet                     == true);                                                      break;
    case OPT_REMOVE:                    count = (uo->remove                    == true);                                                      break;
    case OPT_REMOVE_TIMER:              count = ((uo->remove_timer_chgd == true) || (uo->remove_timer != REMOVE_TIMER));  *value = uo->remove_timer;                          break;
    case OPT_RESTORE_DISABLE:           count = (uo->restore_enable            == false);                                                     break;
    case OPT_RESTORE_FILE_PATH:         count = (uo->restore_file_path         != NULL);  *arg   = uo->restore_file_path;                     break;
    case OPT_RESTORE_POSITION:          count = (uo->restore_position          == true);                                                      break;
    case OPT_RESTORE:                   count = (uo->restore                   == true);                                                      break;
    case OPT_RULE_BUF_L:                count = ((uo->rule_buf_l_chgd == true) || ((uo->rule_buf_l != NULL) && (strcmp (uo->rule_buf_l, ":") != 0)));  *arg   = uo->rule_buf_l;                            break;
    case OPT_RULE_BUF_R:                count = ((uo->rule_buf_r_chgd == true) || ((uo->rule_buf_r != NULL) && (strcmp (uo->rule_buf_r, ":") != 0)));  *arg   = uo->rule_buf_r;                            break;
    case OPT_RP_FILE:                   count = uo->rp_files_cnt;                         *arg   = (count > 0) ? uo->rp_files[0] : NULL;      break;
    case OPT_RP_FILE_CONCAT:            count = (uo->rp_files_concat           == true);                                                      break;
    case OPT_RUNTIME:                   count = ((uo->runtime_chgd == true) || (uo->runtime != RUNTIME));  *value = uo->runtime;                               break;
    case OPT_SELF_TEST_DISABLE:         count = (uo->self_test                 == false);                                                     break;
    case OPT_SEPARATOR:                 count = ((uo->separator_chgd == true) || ((uo->separator != NULL) && (strcmp (uo->separator, ":") != 0)));  *arg   = uo->separator;                             break;
    case OPT_SESSION:                   count = (uo->session_chgd              == true);  *arg   = uo->session;                               break;
    case OPT_SHOW:                      count = (uo->show                      == true);                                                      break;
    case OPT_SKIP:                      count = ((uo->skip_chgd == true) || (uo->skip != SKIP));  *value = uo->skip;                                  break;
    case OPT_SLOW_CANDIDATES:           count = (uo->slow_candidates           == true);                                                      break;
    case OPT_SPEED_ONLY:                count = (uo->speed_only                == true);                                                      break;
    case OPT_SPIN_DAMP:                 count = ((uo->spin_damp_chgd == true) || (uo->spin_damp != SPIN_DAMP));  *value = uo->spin_damp;                             break;
    case OPT_STATUS:                    count = (uo->status                    == true);                                                      break;
    case OPT_STATUS_JSON:               count = (uo->status_json               == true);                                                      break;
    case OPT_PIPELINE_STATS:            count = (uo->pipeline_stats            == true);                                                      break;
    case OPT_TASK_TIME_BREAKDOWN:       count = (uo->task_time_breakdown       == true);                                                      break;
    case OPT_STATUS_TIMER:              count = (uo->status_timer              != STATUS_TIMER);  *value = uo->status_timer;                  break;
    case OPT_STDOUT_FLAG:               count = (uo->stdout_flag               == true);                                                      break;
    case OPT_STDIN_COUNT:               count = ((uo->stdin_count_chgd == true) || (uo->stdin_count != STDIN_COUNT));  *value = uo->stdin_count;                           break;
    case OPT_STDIN_TIMEOUT_ABORT:       count = ((uo->stdin_timeout_abort_chgd == true) || (uo->stdin_timeout_abort != STDIN_TIMEOUT_ABORT));  *value = uo->stdin_timeout_abort;                   break;
    case OPT_USERNAME:                  count = (uo->username                  == true);                                                      break;
    case OPT_VERSION:                   count = (uo->version                   == true);                                                      break;
    case OPT_MODULE_CACHE_REBUILD:      count = (uo->module_cache_rebuild      == true);                                                      break;
    case OPT_WORDLIST_AUTOHEX_DISABLE:  count = (uo->wordlist_autohex          == false);                                                     break;
    #ifdef WITH_BRAIN
    case OPT_BRAIN_CLIENT:              count = (uo->brain_client              == true);                                                      break;
    case OPT_BRAIN_FEED:                count = (uo->brain_feed                == true);                                                      break;
    case OPT_BRAIN_CLIENT_FEATURES:     count = ((uo->brain_client_features_chgd == true) || (uo->brain_client_features != BRAIN_CLIENT_FEATURES)); *value = uo->brain_client_features;                 break;
    case OPT_BRAIN_SERVER:              count = (uo->brain_server              == true);                                                      break;
    case OPT_BRAIN_SERVER_TIMER:        count = ((uo->brain_server_timer_chgd == true) || (uo->brain_server_timer != BRAIN_SERVER_TIMER));  *value = uo->brain_server_timer;                    break;
    case OPT_BRAIN_HOST:                count = ((uo->brain_host_chgd == true) || (uo->brain_host != NULL));  *arg   = uo->brain_host;                            break;
    case OPT_BRAIN_PORT:                count = ((uo->brain_port_chgd == true) || (uo->brain_port != BRAIN_PORT));  *value = uo->brain_port;                            break;
    case OPT_BRAIN_PASSWORD:            count = ((uo->brain_password_chgd == true) || (uo->brain_password != NULL));  *arg   = uo->brain_password;                        break;
    case OPT_BRAIN_SESSION:             count = (uo->brain_session             != BRAIN_SESSION); *value = uo->brain_session;                 break;
    case OPT_BRAIN_SESSION_WHITELIST:   count = (uo->brain_session_whitelist   != NULL);  *arg   = uo->brain_session_whitelist;               break;
    #endif
    case OPT_COLOR_CRACKED:             count = (uo->color_cracked             == true);                                                      break;
    case OPT_ENCRYPT_WITH_PUBKEY:       count = (uo->encrypt_with_pubkey       != NULL);  *arg   = uo->encrypt_with_pubkey;                   break;
    default:                                                                                                                                  break;
  }

  return count;
}

static void table_parse_struct (option_table_t *table, const user_options_t *user_options)
{
  for (u32 i = 1; i < OPTION_COUNT; i++)
  {
    const option_id_t id = (option_id_t) i;

    if (option_rule (table, id)->alias != OPT_NONE) continue;

    u64 value = 0;

    const char *arg = NULL;

    const u32 count = table_struct_given (user_options, id, &value, &arg);

    // the attack mode rules read the attack mode in effect, given or not

    if (id == OPT_ATTACK_MODE) table->value[id] = value;

    if (count == 0) continue;

    // the parse phase reads a number off its text, as it does for a command line

    if (arg == NULL)
    {
      snprintf (table->numbers[id], sizeof (table->numbers[id]), "%" PRIu64, value);

      arg = table->numbers[id];
    }

    table_give (table, id, count, arg);

    table->value[id] = value;
  }

  const module_options_t *module_options = table->module_options;

  const u32 module_cnt = (module_options == NULL) ? 0 : module_options->entries_cnt;

  for (u32 i = 0; i < module_cnt; i++)
  {
    const module_option_entry_t *entry = &module_options->entries[i];

    if (entry->given == false) continue;

    const option_id_t id = (option_id_t) (OPTION_COUNT + i);

    const char *arg = entry->str;

    if (arg == NULL)
    {
      snprintf (table->numbers[id], sizeof (table->numbers[id]), "%" PRIu64, entry->value);

      arg = table->numbers[id];
    }

    table_give (table, id, 1, arg);
  }

  table->argc = user_options->hc_argc;
}

// What the parse phase read for a module option is what the module reads back.

static void table_store_module_values (const option_table_t *table)
{
  module_options_t *module_options = table->module_options;

  if (module_options == NULL) return;

  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    module_option_entry_t *entry = &module_options->entries[i];

    if (entry->row.alias != NULL) continue;

    const option_id_t id = (option_id_t) (OPTION_COUNT + i);

    if (option_given (table, id) == false) continue;

    entry->given = true;
    entry->value = (entry->row.type == MODULE_OPTION_TYPE_FLAG) ? 1 : table->value[id];
    entry->str   = (entry->row.type == MODULE_OPTION_TYPE_STR) ? table->given[id].arg : NULL;
  }
}

// parse phase

static void table_parse_option (option_table_t *table, option_verdict_t *v, const option_id_t id)
{
  const option_rule_t  *rule  = option_rule (table, id);
  const option_given_t *given = &table->given[id];

  if ((rule->flags & OPTION_FLAG_LEGACY) != 0) return;

  option_text_t text;

  if (rule->type == OPTION_TYPE_COUNTER)
  {
    if (((rule->flags & OPTION_FLAG_MAX) != 0) && (given->count > rule->max))
    {
      text_printf (&text, "--%s can be given at most %u times.", option_name (table, id), (u32) rule->max);

      verdict_refuse (v, "parse", "counter", id, OPT_NONE, &text);
    }

    return;
  }

  if (rule->type == OPTION_TYPE_FLAG) return;

  if ((rule->type == OPTION_TYPE_U32) || (rule->type == OPTION_TYPE_U64))
  {
    if (hc_string_is_digit (given->arg) == false)
    {
      text_printf (&text, "--%s takes a number, '%s' is not one.", option_name (table, id), given->arg);

      verdict_refuse (v, "parse", "type", id, OPT_NONE, &text);

      return;
    }

    errno = 0;

    const u64 value = (u64) strtoull (given->arg, NULL, 10);

    const bool overflow = (errno == ERANGE);

    const u64 type_max = (rule->type == OPTION_TYPE_U32) ? 0xffffffff : 0xffffffffffffffff;

    if ((value > type_max) || (overflow == true))
    {
      text_printf (&text, "--%s %s is too large.", option_name (table, id), given->arg);

      verdict_refuse (v, "parse", "range", id, OPT_NONE, &text);

      return;
    }

    table->value[id] = value;

    if (((rule->flags & OPTION_FLAG_MIN) != 0) && (value < rule->min))
    {
      text_printf (&text, "--%s must be at least %" PRIu64 ".", option_name (table, id), rule->min);

      verdict_refuse (v, "parse", "range", id, OPT_NONE, &text);

      return;
    }

    if (((rule->flags & OPTION_FLAG_MAX) != 0) && (value > rule->max))
    {
      text_printf (&text, "--%s must be at most %" PRIu64 ".", option_name (table, id), rule->max);

      verdict_refuse (v, "parse", "range", id, OPT_NONE, &text);

      return;
    }
  }

  if (rule->type == OPTION_TYPE_STR)
  {
    if (((rule->flags & OPTION_FLAG_MAX) != 0) && (given->count > rule->max))
    {
      text_printf (&text, "--%s can be given at most %u times.", option_name (table, id), (u32) rule->max);

      verdict_refuse (v, "parse", "counter", id, OPT_NONE, &text);

      return;
    }

    if (((rule->flags & OPTION_FLAG_NONEMPTY) != 0) && (given->arg[0] == 0))
    {
      text_printf (&text, "--%s must not be empty.", option_name (table, id));

      verdict_refuse (v, "parse", "nonempty", id, OPT_NONE, &text);

      return;
    }
  }

  if (rule->value_fn == NULL) return;

  if (rule->value_fn (table, id, &text) == true) return;

  verdict_refuse (v, "parse", "validator", id, OPT_NONE, &text);
}

static void table_phase_parse (option_table_t *table, option_verdict_t *v)
{
  for (u32 i = 0; i < table->order_cnt; i++)
  {
    table_parse_option (table, v, table->order[i]);

    if (v->refuse == true) return;
  }

  // A 0 that means what leaving the option out means is taken as not given, so the rules between
  // options read -g 0 and --brain-session 0 the way the run does, and the way the struct does.

  u32 kept = 0;

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    const option_id_t id = table->order[i];

    const bool unset = ((option_rule (table, id)->flags & OPTION_FLAG_ZERO_UNSET) != 0) && (table->value[id] == 0);

    if (unset == true)
    {
      table->given[id].count = 0;

      continue;
    }

    table->order[kept] = id;

    table->given[id].order = kept + 1;

    kept++;
  }

  table->order_cnt = kept;

  // An ordering is tested whenever either side was given, against the default of the other side.

  for (u32 i = 1; i < table->count; i++)
  {
    const option_id_t id = (option_id_t) i;

    const option_id_t le = option_rule (table, id)->le;

    if (le == OPT_NONE) continue;

    const bool id_given = option_given (table, id);
    const bool le_given = option_given (table, le);

    if ((id_given == false) && (le_given == false)) continue;

    if (table->value[id] <= table->value[le]) continue;

    option_text_t text;

    if (le_given == false)
    {
      text_printf (&text, "--%s %" PRIu64 " is greater than --%s, which defaults to %" PRIu64 ".", option_name (table, id), table->value[id], option_name (table, le), table->value[le]);
    }
    else if (id_given == false)
    {
      text_printf (&text, "--%s %" PRIu64 " is lower than --%s, which defaults to %" PRIu64 ".", option_name (table, le), table->value[le], option_name (table, id), table->value[id]);
    }
    else
    {
      text_printf (&text, "--%s must not be greater than --%s.", option_name (table, id), option_name (table, le));
    }

    verdict_refuse (v, "parse", "le", id, le, &text);

    return;
  }
}

// The action is resolved once, from the selectors given. Two selectors of different actions are
// refused. Selectors marked selects_with combine with the other selectors of their action, which is
// the benchmark group: -b, -B, --benchmark-all and --benchmark-json.

static void table_resolve_action (option_table_t *table, option_verdict_t *v)
{
  table->action     = ACTION_CRACK;
  table->action_opt = OPT_NONE;

  option_id_t first = OPT_NONE;

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    const option_id_t id = table->order[i];

    const option_rule_t *rule = option_rule (table, id);

    if (rule->selects == 0) continue;

    if (first == OPT_NONE)
    {
      first = id;

      continue;
    }

    const option_rule_t *rule_first = option_rule (table, first);

    if ((rule->selects == rule_first->selects) && (rule->selects_with == true) && (rule_first->selects_with == true)) continue;

    option_text_t text;

    text_printf (&text, "--%s cannot be combined with --%s.", option_name (table, first), option_name (table, id));

    verdict_refuse (v, "static", "one_action", first, id, &text);

    break;
  }

  for (u32 p = 0; p < ACTION_COUNT; p++)
  {
    const option_action_t action = action_precedence[p];

    for (u32 i = 0; i < table->order_cnt; i++)
    {
      const option_id_t id = table->order[i];

      if ((option_rule (table, id)->selects & AB (action)) == 0) continue;

      table->action     = action;
      table->action_opt = id;

      return;
    }
  }
}

static void scope_message (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  if (table->action != ACTION_CRACK)
  {
    text_printf (text, "--%s has no effect with --%s.", option_name (table, id), option_name (table, table->action_opt));

    return;
  }

  // an option that works in exactly one other action names that action's selector

  const u32 actions = option_rule (table, id)->actions;

  for (u32 a = 0; a < ACTION_COUNT; a++)
  {
    if (actions != AB (a)) continue;

    if (action_selector[a] == OPT_NONE) break;

    text_printf (text, "--%s has no effect without --%s.", option_name (table, id), option_name (table, action_selector[a]));

    return;
  }

  text_printf (text, "--%s has no effect in a cracking run.", option_name (table, id));
}

static void attack_modes_message (const option_table_t *table, const option_id_t id, const u32 attack_modes, option_text_t *text)
{
  // a list that leaves out one mode names the one it leaves out

  const u32 left_out = AM_ALL & ~attack_modes;

  if (((attack_modes & ~AM_ALL) == 0) && (is_power_of_2 (left_out) == true))
  {
    u32 mode = 0;

    while ((left_out & AM (mode)) == 0) mode++;

    text_printf (text, "--%s cannot be used with attack mode %u.", option_name (table, id), mode);

    return;
  }

  char modes[64];

  attack_modes_text (attack_modes, modes, sizeof (modes));

  text_printf (text, "--%s needs attack mode %s.", option_name (table, id), modes);
}

// Out of scope is not a refusal by itself. An option the action or the attack mode does not read is
// marked ignored and accepted, and the later checks leave it alone. An ignored option has no effect,
// so the excludes it lists contradict nothing either. Every option is placed first, then the rules
// between them run.

static void table_static_scope (option_table_t *table, option_verdict_t *v, const option_id_t id)
{
  const option_rule_t *rule = option_rule (table, id);

  if ((rule->flags & OPTION_FLAG_LEGACY) != 0) return;

  // a selector of another action was refused by the one action rule already

  if ((rule->selects != 0) && ((rule->selects & AB (table->action)) == 0)) return;

  const bool harm = ((rule->flags & OPTION_FLAG_HARM) != 0);

  option_text_t text;

  bool ignored = false;

  if ((rule->actions & AB (table->action)) == 0)
  {
    if (harm == true)
    {
      scope_message (table, id, &text);

      verdict_refuse (v, "static", "scope", id, table->action_opt, &text);

      return;
    }

    ignored = true;
  }

  if ((ignored == false) && (rule->attack_modes != 0) && ((ACT_ATTACK & AB (table->action)) != 0))
  {
    const bool known = (table->attack_mode < 32);

    const u32 attack_mode = (known == true) ? AM (table->attack_mode) : 0;

    if ((rule->conflict_modes & attack_mode) != 0)
    {
      text_printf (&text, "--%s cannot be used with attack mode %u.", option_name (table, id), table->attack_mode);

      verdict_refuse (v, "static", "conflict_modes", id, OPT_ATTACK_MODE, &text);

      return;
    }

    // a selector is an action, and an action that cannot run this attack is a conflict

    if ((rule->attack_modes & attack_mode) == 0)
    {
      if ((harm == true) || (rule->selects != 0))
      {
        attack_modes_message (table, id, rule->attack_modes, &text);

        verdict_refuse (v, "static", "attack_modes", id, OPT_NONE, &text);

        return;
      }

      ignored = true;
    }
  }

  table->ignored[id] = ignored;
}

// An option that modules register differently is taken by no hash-mode, see
// module_options_conflicts (). A run of a hash-mode that registered it refuses it, rather than run
// without it, and so does a run whose hash-mode is not known yet: -b without -m runs all of them, and
// autodetect only considers modes that take every module option given.

static bool table_module_conflict (const option_table_t *table, const option_id_t id, option_text_t *text)
{
  const module_option_entry_t *entry = &table->module_options->entries[id - OPTION_COUNT];

  if (entry->conflict == false) return false;

  const bool mode_read = ((option_rules[OPT_HASH_MODE].actions & AB (table->action)) != 0);

  bool hit = false;

  if ((option_given (table, OPT_HASH_MODE) == true) && (mode_read == true))
  {
    const u32 hash_mode = module_hash_mode_resolve ((u32) table->value[OPT_HASH_MODE]);

    for (u32 i = 0; i < entry->modes_cnt; i++)
    {
      if (entry->modes[i] == hash_mode) hit = true;
    }
  }
  else if (table->action == ACTION_BENCHMARK)
  {
    hit = true;
  }
  else if ((ACT_AUTODETECT & AB (table->action)) != 0)
  {
    hit = true;
  }

  if (hit == false) return false;

  if (strcmp (entry->file, entry->file_conflict) == 0)
  {
    text_printf (text, "--%s is left out, because %s registers it twice, differently.", option_name (table, id), entry->file);
  }
  else
  {
    text_printf (text, "--%s is left out, because %s and %s register it differently.", option_name (table, id), entry->file, entry->file_conflict);
  }

  return true;
}

static void table_static_rules (option_table_t *table, option_verdict_t *v, const option_id_t id)
{
  const option_rule_t *rule = option_rule (table, id);

  if ((rule->flags & OPTION_FLAG_LEGACY) != 0) return;

  if ((rule->selects != 0) && ((rule->selects & AB (table->action)) == 0)) return;

  if (table->ignored[id] == true) return;

  option_text_t text;

  if (((u32) id >= OPTION_COUNT) && (table_module_conflict (table, id, &text) == true))
  {
    verdict_refuse (v, "static", "module_conflict", id, OPT_NONE, &text);

    return;
  }

  for (u32 j = 0; j < OPTION_REL_MAX; j++)
  {
    const option_id_t other = rule->excludes[j];

    if (other == OPT_NONE) break;

    if (option_given (table, other) == false) continue;

    text_printf (&text, "--%s cannot be combined with --%s.", option_name (table, id), option_name (table, other));

    verdict_refuse (v, "static", "excludes", id, other, &text);

    return;
  }

  for (u32 j = 0; j < OPTION_REL_MAX; j++)
  {
    const option_id_t other = rule->requires[j];

    if (other == OPT_NONE) break;

    if (option_given (table, other) == true) continue;

    text_printf (&text, "--%s needs --%s.", option_name (table, id), option_name (table, other));

    verdict_refuse (v, "static", "requires", id, other, &text);

    return;
  }

  if (rule->requires_any[0] != OPT_NONE)
  {
    bool any = false;

    for (u32 j = 0; j < OPTION_REL_MAX; j++)
    {
      const option_id_t other = rule->requires_any[j];

      if (other == OPT_NONE) break;

      if (option_given (table, other) == true) any = true;
    }

    if (any == false)
    {
      text_printf (&text, "--%s needs --%s or --%s.", option_name (table, id), option_name (table, rule->requires_any[0]), option_name (table, rule->requires_any[1]));

      verdict_refuse (v, "static", "requires_any", id, rule->requires_any[0], &text);

      return;
    }
  }

  if (rule->requires_opt != OPT_NONE)
  {
    if ((option_given (table, rule->requires_opt) == false) || (table->value[rule->requires_opt] != rule->requires_val))
    {
      text_printf (&text, "--%s needs --%s %" PRIu64 ".", option_name (table, id), option_name (table, rule->requires_opt), rule->requires_val);

      verdict_refuse (v, "static", "requires_value", id, rule->requires_opt, &text);

      return;
    }
  }

  if (rule->static_fn == NULL) return;

  if (rule->static_fn (table, id, &text) == true) return;

  verdict_refuse (v, "static", "code", id, OPT_NONE, &text);
}

static void table_phase_static (option_table_t *table, option_verdict_t *v)
{
  table_resolve_action (table, v);

  table->attack_mode = (u32) table->value[OPT_ATTACK_MODE];

  if (v->refuse == true) return;

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    table_static_scope (table, v, table->order[i]);

    if (v->refuse == true) return;
  }

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    table_static_rules (table, v, table->order[i]);

    if (v->refuse == true) return;
  }
}

// Whether the candidates come from stdin, which user_options_extra_init () settles later from the
// same three things: -a 0, the action, and no wordlist among the arguments. Only -a 0 reads stdin, and
// the actions that take a hash file have it as their first argument.

static bool table_stdin (const option_table_t *table)
{
  if (table->attack_mode != ATTACK_MODE_STRAIGHT) return false;

  const bool no_hash_file = (table->action == ACTION_KEYSPACE) || (table->action == ACTION_STDOUT);
  const bool hash_file    = (table->action == ACTION_CRACK) || (table->action == ACTION_SPEED_ONLY) || (table->action == ACTION_IDENTIFY);

  const bool is_stdin = ((no_hash_file == true) && (table->argc == 0)) || ((hash_file == true) && (table->argc == 1));

  return is_stdin;
}

static void table_phase_input (option_table_t *table, option_verdict_t *v)
{
  const bool is_stdin = table_stdin (table);

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    const option_id_t id = table->order[i];

    if (table->ignored[id] == true) continue;

    const u32 late = option_rule (table, id)->late & LATE_REFUSE;

    option_text_t text;

    if (((late & LATE_INPUT_NOT_STDIN) != 0) && (is_stdin == true))
    {
      text_printf (&text, "--%s cannot take the candidates from stdin.", option_name (table, id));

      verdict_refuse (v, "late", "late_input", id, OPT_NONE, &text);

      return;
    }
  }
}

// The module predicates the loaded module does not meet. Each is a property the module already
// declares: the hex salt bit, a hook kernel and a bridge.

static u32 table_module_missing (const hashconfig_t *hashconfig, const module_ctx_t *module_ctx)
{
  u32 missing = 0;

  if (hashconfig->salt_type != SALT_TYPE_GENERIC) missing |= LATE_MODULE_HEX_SALT;

  const bool hook_kernel = ((hashconfig->kern_bits & (KERN_BIT_HOOK12 | KERN_BIT_HOOK23)) != 0);

  const bool hook_param = (hashconfig->hook_extra_param_size > 0) || (module_ctx->module_hook_extra_param_init != MODULE_DEFAULT);

  if ((hook_kernel == false) && (hook_param == false)) missing |= LATE_MODULE_HOOK;

  if (hashconfig->bridge_type == BRIDGE_TYPE_NONE) missing |= LATE_MODULE_BRIDGE;

  return missing;
}

static bool table_module_range (const option_table_t *table, const hashconfig_t *hashconfig, const option_id_t id, option_text_t *text)
{
  const u32 late = option_rule (table, id)->late;

  const u64 value = table->value[id];

  u32 lo = 0;
  u32 hi = 0;

  if ((late & LATE_MODULE_ACCEL) != 0)
  {
    // a bridge clamps -n into the range it has allocated for, which only the device side can check

    if (hashconfig->bridge_type != BRIDGE_TYPE_NONE) return true;

    lo = hashconfig->kernel_accel_min;
    hi = hashconfig->kernel_accel_max;
  }
  else if ((late & LATE_MODULE_THREADS) != 0)
  {
    lo = hashconfig->kernel_threads_min;
    hi = hashconfig->kernel_threads_max;
  }
  else
  {
    return true;
  }

  if ((value >= lo) && (value <= hi)) return true;

  text_printf (text, "--%s %" PRIu64 " is outside the range %u-%u that hash-type %u allows.", option_name (table, id), value, lo, hi, hashconfig->hash_mode);

  return false;
}

// Whether the hash-mode of the run is one the user chose, by -m or through autodetect, rather than the
// default every action starts from. Only a chosen one can refuse a module option.

static bool table_mode_chosen (const option_table_t *table)
{
  const bool mode_read = ((option_rules[OPT_HASH_MODE].actions & AB (table->action)) != 0);

  if ((option_given (table, OPT_HASH_MODE) == true) && (mode_read == true)) return true;

  // without -m, or with a -m the action ignores, as --identify does, autodetect picks the mode

  const bool chosen = ((ACT_AUTODETECT & AB (table->action)) != 0);

  return chosen;
}

int option_table_check_module (hashcat_ctx_t *hashcat_ctx, const u32 flags)
{
  option_table_t *table = hashcat_ctx->user_options->option_table;

  if (table == NULL) return 0;

  const bool say = ((flags & OPTION_MODULE_SAY) != 0);

  if (say == true)
  {
    if (table->module_done == true) return 0;

    // a benchmark without -m runs every mode, so a module specific option only has to work on some

    if ((table->action == ACTION_BENCHMARK) && (option_given (table, OPT_HASH_MODE) == false)) return 0;
  }

  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  const u32 missing = table_module_missing (hashconfig, module_ctx) & LATE_REFUSE;

  const bool mode_chosen = table_mode_chosen (table);

  // an old hash-mode number loads the module of its new number, which is the one that registered

  const u32 module_hash_mode = module_hash_mode_resolve (hashconfig->hash_mode);

  option_verdict_t v;

  memset (&v, 0, sizeof (v));

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    const option_id_t id = table->order[i];

    if (table->ignored[id] == true) continue;

    option_text_t text;

    // a module option can only work on the hash-modes whose module registered it

    if ((u32) id >= OPTION_COUNT)
    {
      if (mode_chosen == false) continue;

      const module_option_entry_t *entry = &table->module_options->entries[id - OPTION_COUNT];

      if (module_option_registered (entry, module_hash_mode) == true) continue;

      text_printf (&text, "--%s is not an option of hash-type %u (%s).", option_name (table, id), hashconfig->hash_mode, hashconfig->hash_name);

      verdict_refuse (&v, "late", "late_module", id, OPT_NONE, &text);

      break;
    }

    if ((option_rule (table, id)->late & missing) != 0)
    {
      text_printf (&text, "--%s has no effect on hash-type %u (%s).", option_name (table, id), hashconfig->hash_mode, hashconfig->hash_name);

      verdict_refuse (&v, "late", "late_module", id, OPT_NONE, &text);

      break;
    }

    if ((flags & OPTION_MODULE_RANGE) == 0) continue;

    if (table_module_range (table, hashconfig, id, &text) == true) continue;

    verdict_refuse (&v, "late", "late_module_range", id, OPT_NONE, &text);

    break;
  }

  if (say == false)
  {
    const int rc = (v.refuse == true) ? -1 : 0;

    return rc;
  }

  if (v.refuse == true)
  {
    table_report (hashcat_ctx, table, &v);

    return -1;
  }

  table->module_done = true;

  return 0;
}

// The feed predicates the caller found false, as LATE_FEED_* bits. The feed is known only once
// generic_ctx_init () has loaded it, so the caller checks them there.

int option_table_check_feed (hashcat_ctx_t *hashcat_ctx, const u32 failed)
{
  option_table_t *table = hashcat_ctx->user_options->option_table;

  if (table == NULL) return 0;

  option_verdict_t v;

  memset (&v, 0, sizeof (v));

  for (u32 i = 0; i < table->order_cnt; i++)
  {
    const option_id_t id = table->order[i];

    if (table->ignored[id] == true) continue;

    const u32 late = option_rule (table, id)->late & failed & LATE_REFUSE;

    if (late == 0) continue;

    option_text_t text;

    text_printf (&text, "--%s has no effect while the device engine makes the candidates.", option_name (table, id));

    verdict_refuse (&v, "late", "late_feed", id, OPT_NONE, &text);

    break;
  }

  if (v.refuse == false) return 0;

  table_report (hashcat_ctx, table, &v);

  return -1;
}

int option_table_parse (hashcat_ctx_t *hashcat_ctx, const int argc, char **argv)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  table_destroy (user_options->option_table);

  option_table_t *table = table_create (user_options->module_options);

  user_options->option_table = table;

  option_verdict_t v;

  memset (&v, 0, sizeof (v));

  table_parse_argv (table, &v, argc, argv);

  if (v.refuse == false) table_phase_parse (table, &v);

  if (v.refuse == false)
  {
    table_store_module_values (table);

    return 0;
  }

  // a caller that goes on to hashcat_session_init () regardless gets the refusal again

  table->checked = true;
  table->refused = true;

  table_report (hashcat_ctx, table, &v);

  return -1;
}

// The static and input phases on a table read off the struct. The command line is not needed for any
// of it, which is what makes the same rules reach a program that never had one.

static void table_struct_verdict (const hashcat_ctx_t *hashcat_ctx, option_table_t *table, option_verdict_t *v)
{
  table->from_struct = true;

  table_parse_struct (table, hashcat_ctx->user_options);

  table_phase_parse (table, v);

  if (v->refuse == true) return;

  table_phase_static (table, v);

  if (v->refuse == true) return;

  table_phase_input (table, v);
}

int option_table_check (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  option_table_t *table = user_options->option_table;

  option_verdict_t v;

  memset (&v, 0, sizeof (v));

  if (table == NULL)
  {
    table = table_create (user_options->module_options);

    user_options->option_table = table;

    table->checked = true;

    table_struct_verdict (hashcat_ctx, table, &v);

    table->refused = v.refuse;

    table_report (hashcat_ctx, table, &v);

    if (v.refuse == true) return -1;

    return 0;
  }

  // The frontend checks from user_options_sanity () and hashcat_session_init () checks again. The
  // second time returns the first verdict, a refusal included, so a caller that went on regardless
  // gets nowhere.

  if (table->checked == true)
  {
    const int rc = (table->refused == true) ? -1 : 0;

    return rc;
  }

  table->checked = true;

  table_phase_static (table, &v);

  if (v.refuse == false) table_phase_input (table, &v);

  table->refused = v.refuse;

  table_report (hashcat_ctx, table, &v);

  // With HASHCAT_OPTION_DEBUG the verdict a library caller would get for the same settings is printed
  // beside it, from the struct alone.

  if (table->debug > 0)
  {
    option_table_t *table_struct = table_create (user_options->module_options);

    option_verdict_t v_struct;

    memset (&v_struct, 0, sizeof (v_struct));

    table_struct_verdict (hashcat_ctx, table_struct, &v_struct);

    table_debug_verdict (table_struct, &v_struct, "OPTION-STRUCT");

    table_destroy (table_struct);
  }

  if (v.refuse == true) return -1;

  return 0;
}

const struct option *option_table_long_options (const hashcat_ctx_t *hashcat_ctx)
{
  const option_table_t *table = hashcat_ctx->user_options->option_table;

  return table->long_options;
}

const char *option_table_short_options (const hashcat_ctx_t *hashcat_ctx)
{
  const option_table_t *table = hashcat_ctx->user_options->option_table;

  return table->short_options;
}

// derive phase. The implications never refuse anything, they are what user_options_preprocess () and
// user_options_postprocess () set on top of what was given. With HASHCAT_OPTION_DEBUG they are checked
// against what those functions set.

static void table_imply (option_table_t *table, const option_id_t opt, const option_id_t by)
{
  if (opt == OPT_NONE) return;

  if (option_given (table, opt) == true) return;

  if (table->implied[opt] == true) return;

  table->implied[opt]    = true;
  table->implied_by[opt] = by;
}

static void table_phase_derive (option_table_t *table, const bool is_stdin)
{
  // An implied action selector does not pass its own implications on. --json implies --benchmark-json
  // as an output format, but that does not make the run a benchmark.

  for (u32 pass = 0; pass < 3; pass++)
  {
    for (u32 i = 1; i < table->count; i++)
    {
      const option_id_t id = (option_id_t) i;

      const option_rule_t *rule = option_rule (table, id);

      if (option_given (table, id) == false)
      {
        if (table->implied[id] == false) continue;

        if (rule->selects != 0) continue;
      }

      for (u32 j = 0; j < OPTION_REL_MAX; j++) table_imply (table, rule->implies[j].opt, id);
    }
  }

  // the implications that depend on a value or on the context

  if (table->action == ACTION_BENCHMARK)
  {
    table_imply (table, OPT_SPEED_ONLY, OPT_BENCHMARK);

    if ((table->value[OPT_BENCHMARK_MIN] != BENCHMARK_MIN) || (table->value[OPT_BENCHMARK_MAX] != BENCHMARK_MAX)) table_imply (table, OPT_BENCHMARK_ALL, OPT_BENCHMARK_MIN);

    if (option_given (table, OPT_BENCHMARK_PURE) == false) table_imply (table, OPT_OPTIMIZED_KERNEL_ENABLE, OPT_BENCHMARK);
  }

  if ((ACT_ATTACK & AB (table->action)) != 0)
  {
    if (table->attack_mode == ATTACK_MODE_ASSOCIATION) table_imply (table, OPT_POTFILE_DISABLE, OPT_ATTACK_MODE);
  }

  #ifdef WITH_BRAIN
  if ((option_given (table, OPT_BRAIN_CLIENT) == true) && (table->ignored[OPT_BRAIN_CLIENT] == false) && ((table->value[OPT_BRAIN_CLIENT_FEATURES] & BRAIN_CLIENT_FEATURE_HASHES) != 0)) table_imply (table, OPT_SLOW_CANDIDATES, OPT_BRAIN_CLIENT_FEATURES);
  #endif

  if (is_stdin == true) table_imply (table, OPT_STATUS, OPT_NONE);
}

// 1 when user_options shows the implied setting, 0 when it does not, -1 when there is nothing to read

static i32 derive_holds (const hashcat_ctx_t *hashcat_ctx, const option_id_t id)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  i32 holds = -1;

  switch (id)
  {
    case OPT_RESTORE_DISABLE:         holds = (user_options->restore_enable   == false);            break;
    case OPT_BENCHMARK:               holds = (user_options->benchmark        == true);             break;
    case OPT_BENCHMARK_ALL:           holds = (user_options->benchmark_all    == true);             break;
    case OPT_BENCHMARK_JSON:          holds = (user_options->benchmark_json   == true);             break;
    case OPT_SPEED_ONLY:              holds = (user_options->speed_only       == true);             break;
    case OPT_QUIET:                   holds = (user_options->quiet            == true);             break;
    case OPT_KEYSPACE:                holds = (user_options->keyspace         == true);             break;
    case OPT_STATUS_JSON:             holds = (user_options->status_json      == true);             break;
    case OPT_OUTFILE_JSON:            holds = (user_options->outfile_json     == true);             break;
    case OPT_STATUS:                  holds = (user_options->status           == true);             break;
    case OPT_POTFILE_DISABLE:         holds = (user_options->potfile          == false);            break;
    case OPT_FORCE:                   holds = (user_options->force            == true);             break;
    case OPT_SLOW_CANDIDATES:         holds = (user_options->slow_candidates  == true);             break;
    case OPT_OPTIMIZED_KERNEL_ENABLE: holds = (user_options->optimized_kernel == true);             break;
    case OPT_OUTFILE_FORMAT:          holds = (user_options->outfile_format   == OUTFILE_FMT_HASH); break;
    default:                                                                                         break;
  }

  return holds;
}

void option_table_debug_derive (hashcat_ctx_t *hashcat_ctx)
{
  option_table_t *table = hashcat_ctx->user_options->option_table;

  if (table == NULL) return;

  if (table->debug == 0) return;

  const bool is_stdin = (hashcat_ctx->user_options_extra->wordlist_mode == WL_MODE_STDIN);

  table_phase_derive (table, is_stdin);

  for (u32 i = 1; i < table->count; i++)
  {
    if (table->implied[i] == false) continue;

    const i32 holds = derive_holds (hashcat_ctx, (option_id_t) i);

    if (holds == 1) continue;

    if ((holds == -1) && (table->debug < 2)) continue;

    fprintf (stderr, "OPTION-DERIVE opt=%s by=%s holds=%s\n", option_name (table, (option_id_t) i), option_name (table, table->implied_by[i]), (holds == 0) ? "no" : "unknown");
  }

  fflush (stderr);
}

void option_table_destroy (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  table_destroy (user_options->option_table);

  user_options->option_table = NULL;
}
