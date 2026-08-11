/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "shared.h"
#include "mpsp.h"
#include "generic.h"
#include "combinator.h"

// The two dictionary counts of a -a 1, as the two feed instances already counted them. Neither
// dictionary can be chosen as the base until both are counted, which is why generic_ctx_init brings
// both instances up before this runs and leaves them in the order the dictionaries were typed.
//
// What to do with the two numbers is the only thing the call sites disagree about: one always takes
// the left as base, one takes the bigger.

static int combinator_count_dicts (hashcat_ctx_t *hashcat_ctx, const char *dictfile1, const char *dictfile2, u64 *words1_cnt, u64 *words2_cnt)
{
  const generic_ctx_t *generic_ctx = hashcat_ctx->generic_ctx;

  words1_cnt[0] = generic_ctx[GENERIC_ROLE_BASE].keyspace;
  words2_cnt[0] = generic_ctx[GENERIC_ROLE_AMP].keyspace;

  // A feed that cannot count itself has no place here, because -a 1 divides one of these counts into
  // the other to build its keyspace

  if (words1_cnt[0] == GENERIC_KEYSPACE_UNKNOWN)
  {
    event_log_error (hashcat_ctx, "%s: feed cannot report a keyspace.", dictfile1);

    return -1;
  }

  if (words2_cnt[0] == GENERIC_KEYSPACE_UNKNOWN)
  {
    event_log_error (hashcat_ctx, "%s: feed cannot report a keyspace.", dictfile2);

    return -1;
  }

  if (words1_cnt[0] == 0)
  {
    event_log_error (hashcat_ctx, "%s: empty file.", dictfile1);

    return -1;
  }

  if (words2_cnt[0] == 0)
  {
    event_log_error (hashcat_ctx, "%s: empty file.", dictfile2);

    return -1;
  }

  return 0;
}

int combinator_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx      = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  combinator_ctx->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;

  if (user_options->attack_mode != ATTACK_MODE_HYBRID) return 0;

  combinator_ctx->enabled = true;

  // The default, which the mask decides for itself per mask in mask_ctx_update_loop. What is left
  // here is the two arrangements that are settled before any mask is parsed.

  combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_MIDDLE;

  // A ?q amplifies with a wordlist rather than with the mask, and its instance holds the count. The
  // mask multiplies that in later, once it knows its own size.
  //
  // Two wordlists and nothing else is what -a 1 is, and there the bigger one should be the base word
  // source: the base word is hashed into a context once and the amplifier is appended per candidate,
  // so the side with more words is the one worth doing once. Both were counted by their own instance
  // before this ran, and the instances are in the order the dictionaries were typed.

  if (user_options_extra->hybrid_q == true)
  {
    char *dictfile1 = user_options_extra->hc_workv[1];
    char *dictfile2 = user_options_extra->hc_workv[2];

    u64 words1_cnt = 0;
    u64 words2_cnt = 0;

    if (combinator_count_dicts (hashcat_ctx, dictfile1, dictfile2, &words1_cnt, &words2_cnt) == -1) return -1;

    combinator_ctx->combs_cnt = words2_cnt;

    const bool swap = (user_options->attack_mode_typed == ATTACK_MODE_COMBI) && (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) && (words1_cnt < words2_cnt);

    if (swap == true)
    {
      // The rule for the base word follows from this, and user_options_extra_init_rules () works it
      // out. This used to swap rule_buf_l and rule_buf_r in place, which left the user's own -j
      // holding the value of their -k for the rest of the session.

      combinator_ctx->combs_cnt = words1_cnt;

      combinator_ctx->roles_swapped = true;

      generic_ctx_roles_swap (hashcat_ctx);
    }

    return 0;
  }

  // The mask is the base word source, so the wordlist is what each base word is combined with and its
  // instance holds the count. That is a mask ending in ?w under a pure kernel, which is what -a 7
  // builds and is why it keeps -a 7's speed.

  if (user_options_extra->base_source == BASE_SOURCE_MASK)
  {
    const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP];

    char *dictfile = user_options_extra->hc_workv[1];

    if (generic_ctx->keyspace == GENERIC_KEYSPACE_UNKNOWN)
    {
      event_log_error (hashcat_ctx, "%s: feed cannot report a keyspace.", dictfile);

      return -1;
    }

    combinator_ctx->combs_cnt  = generic_ctx->keyspace;
    combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
  }

  return 0;
}

void combinator_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

  if (combinator_ctx->enabled == false) return;

  memset (combinator_ctx, 0, sizeof (combinator_ctx_t));
}
