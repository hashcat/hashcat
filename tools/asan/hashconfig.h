/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_HARNESS_HASHCONFIG_H
#define HC_HARNESS_HASHCONFIG_H

#include "common.h"
#include "types.h"
#include "modules.h"

// Fills in the subset of hashconfig_init () that a parser can observe, out of the module's own
// getters. Anything a parser reads that is not set here reads as zero, which is how a parser that
// depends on something it should not shows up as a finding rather than as a guess.

void harness_build_hashconfig (hashconfig_t *hashconfig, module_ctx_t *m,
                               user_options_t *uo, user_options_extra_t *uoe,
                               const int hash_mode);

#endif // HC_HARNESS_HASHCONFIG_H
