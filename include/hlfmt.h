/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_HLFMT_H
#define HC_HLFMT_H

#include <stdio.h>

#define HLFMTS_CNT 11

// How many words one account name is allowed to become, and so how many rounds an association attack
// that splits its own hash file can have. john caps the same list at 60, but it feeds that list from the
// gecos field and the home directory as well, where this has only the name itself.
//
// The cap matters because every account is tried as many times as the account with the most words. One
// name with an underscore in it makes every other account in the file run a second and a third time, so
// a name that falls apart into a dozen pieces must not set the cost of the whole run.
//
// An account name that produces more words than this keeps the ones its ranking puts first, and one
// slot is always the name as it was written. What falls off the end is the shortest pieces, which are
// the initials and the digits, and they are the least like a password on their own.

#define ASSOCIATION_WORDS_MAX 8

// How many words are collected before the cap is applied. Only what survives the cap is ever tried, this
// is the working set the longest are picked out of.

#define ASSOCIATION_WORDS_COLLECT 32

// The shortest piece worth cutting a name into. Below this a split produces initials, which are not
// passwords, and every one of them costs a round for EVERY account in the file rather than only for the
// name it came out of. That is what makes a useless piece expensive.
//
// It applies to every piece a split produces, at a separator and at a case or digit boundary alike, and
// to the joined form built out of them. "j.smith" is therefore smith, jsmith and j.smith, where the "j"
// used to take a slot of its own.
//
// The name as it was written is exempt, which is what keeps a short account name usable: a person whose
// account is "jo" still has "jo" tried, because the name is added whatever its length and is the last
// word in the list. That exemption is the whole of the "unless it is the only word" rule, and it needs
// no test of its own.

#define ASSOCIATION_WORD_MIN_LEN 3

// What -a 9 tries, in the order it tries it.
//
// A phase is one way of turning what a hash carries into candidates, and the queue runs
// from the cheapest to the most expensive, so that a run stopped early has spent its time on the
// guesses most likely to land. That is the one thing worth taking from how john orders its modes: the
// last phase is the one that never runs out, and everything ahead of it is bounded and quick.
//
// The words phase is every word of an account as it stands, and it is a phase of its own rather than a
// property of the one behind it. The rules phase reaches the same candidates, because the first rule of
// any rule list ordered by yield is the do-nothing rule and assoc_sched_build () prices that rule at
// zero on every word, so either of them alone tries every word before it modifies any. What a phase
// buys is that the guarantee no longer depends on what a rule file happens to hold: a list whose first
// rule is not the do-nothing rule, or one cut to its second rule onwards by rulemax, still yields the
// words tried first.
//
// The two do overlap, and a word an account has is therefore tried twice, once here and once under that
// first rule. Eight words against a thousand rules is eight repeats in eight thousand and eight, so the
// duplication the overlap costs is a tenth of a per cent of the phase behind it. Dropping the first rule
// from the rules phase instead would make one phase's content depend on which other phases the run was
// given, which is worse than the repeat.
//
// All three run by default. The grammar does not run out, so -a 9 no longer finishes on its own, where
// before it always did. The alternative is an attack that stops after a few thousand guesses an account
// and leaves the best of itself behind a setting the output gives no sign of. phases=words,rules is
// the bounded run for anyone who prefers one.
//
// Each phase is one source in the queue, so the feed is opened once per phase and reports its own
// keyspace. How many rounds a phase covers is the phase's own business and is not counted here.
// The names are what hashcat writes in the logfile and what the feed reads back.

#define ASSOCIATION_PHASES         { "words", "rules", "pcfg" }
#define ASSOCIATION_PHASES_DEFAULT "words,rules,pcfg"

// What the grammar phase runs: hashcat's hint ruleset, and how many words it takes from one account
// name. The ruleset is the trained one with its letters taken out, so every candidate it makes is one
// of the account's own words with something around it. See docs/hashcat-pcfg.md section 4.
//
// The count is the same for every account on purpose. It is what makes the grammar, its cost index and
// its keyspace the same for all of them, so one of each serves the whole hash file rather than one per
// hash. An account with fewer words repeats one.

// What the rules phase runs: a rule list ordered by how often each rule won, and how deep into it to
// go. The first rules of rockyou-30000 are the pad rules the attack has always used.

#define ASSOCIATION_RULES_FILE "rulefile=rules/rockyou-30000.rule"
#define ASSOCIATION_RULES_MAX  "rulemax=1000"

#define ASSOCIATION_PCFG_RULESET "hints"
#define ASSOCIATION_PCFG_HINTS   "hintaccount=8"

HC_PLUGIN_API const char *strhlfmt (const u32 hashfile_format);

// The hints the grammar phase uses, which are ranked and filtered differently from the words above
// because a grammar puts something around a hint rather than trying it. See the comment on the
// definition. scratch holds the one hint that is not a substring of the name.

#define ASSOCIATION_HINT_SCRATCH 256

HC_PLUGIN_API u32 hlfmt_user_hints (const char *user_buf, const u32 user_len, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size);

// The same, for a hash list format that carries more than the login. See the definition for the order
// the fields are taken in and why.

HC_PLUGIN_API u32 hlfmt_account_hints (const char *user_buf, const u32 user_len, const char *gecos_buf, const u32 gecos_len, const char *home_buf, const u32 home_len, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size);

// What one hash carries about its owner, which is what a feed asks for rather than cutting a name up
// itself. The module answers, so a mode whose salt or esalt holds something better than an account name
// says so and every attack gets it for free.

HC_PLUGIN_API u32 hlfmt_hash_hints (hashcat_ctx_t *hashcat_ctx, const u64 hash_pos, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size);

void hlfmt_hash (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len);
void hlfmt_user (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len);
void hlfmt_user_extra (u32 hashfile_format, char *line_buf, const int line_len, char **gecos_pos, int *gecos_len, char **home_pos, int *home_len);

u32 hlfmt_detect (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, u32 max_check);

#endif // HC_HLFMT_H
