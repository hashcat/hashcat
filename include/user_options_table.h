/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_USER_OPTIONS_TABLE_H
#define HC_USER_OPTIONS_TABLE_H

typedef enum option_id
{
  OPT_NONE = 0,

  #define OPTION(id, name, letter, idx, arg) id,
  #include "options.def"
  #undef OPTION

  OPTION_COUNT,

} option_id_t;

// Conditions only known once the context is set up. The input predicates are evaluated at the end of
// option_table_check (), the module predicates once the module is loaded and the feed predicates once
// the feed is loaded. Most of them only record where an option has an effect. The ones in
// LATE_REFUSE are refused when they fail: an option that cannot take stdin, a salt that would not be
// decoded as --hex-salt specifies, a rule the device engine would apply to part of a candidate only,
// and -O where the engine has no optimized kernel.

typedef enum option_late
{
  LATE_INPUT_STDIN        = (1 <<  0),
  LATE_INPUT_NOT_STDIN    = (1 <<  1),
  LATE_MODULE_HEX_SALT    = (1 <<  2),
  LATE_MODULE_HOOK        = (1 <<  3),
  LATE_MODULE_BRIDGE      = (1 <<  4),
  LATE_MODULE_ACCEL       = (1 <<  5),
  LATE_MODULE_THREADS     = (1 <<  6),
  LATE_FEED_ENGINE        = (1 <<  7),
  LATE_FEED_ENGINE_LOOPS  = (1 <<  8),
  LATE_FEED_ENGINE_KERNEL = (1 <<  9),
  LATE_FEED_MASK          = (1 << 10),

} option_late_t;

#define LATE_REFUSE (LATE_INPUT_NOT_STDIN | LATE_MODULE_HEX_SALT | LATE_FEED_ENGINE | LATE_FEED_ENGINE_KERNEL)

typedef enum option_module_check
{
  OPTION_MODULE_SAY   = (1 << 0),
  OPTION_MODULE_RANGE = (1 << 1),

} option_module_check_t;

int  option_table_parse        (hashcat_ctx_t *hashcat_ctx, int argc, char **argv);
int  option_table_check        (hashcat_ctx_t *hashcat_ctx);

const struct option *option_table_long_options  (const hashcat_ctx_t *hashcat_ctx);
const char          *option_table_short_options (const hashcat_ctx_t *hashcat_ctx);

int  option_table_check_module (hashcat_ctx_t *hashcat_ctx, const u32 flags);
int  option_table_check_feed   (hashcat_ctx_t *hashcat_ctx, const u32 failed);
void option_table_debug_derive (hashcat_ctx_t *hashcat_ctx);
void option_table_destroy      (hashcat_ctx_t *hashcat_ctx);

#endif // HC_USER_OPTIONS_TABLE_H
