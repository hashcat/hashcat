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
// An account name that produces more words than this keeps the longest ones. The short pieces are the
// initials and the digits, which are the least like a password on their own.

#define ASSOCIATION_WORDS_MAX 8

// How many words are collected before the cap is applied. Only what survives the cap is ever tried, this
// is the working set the longest are picked out of.

#define ASSOCIATION_WORDS_COLLECT 32

// The shortest piece worth trying on its own. Below this a split produces initials and stray digits,
// which are not passwords, and every one of them costs a round for EVERY account in the file rather
// than only for the name it came out of. That is what makes a useless piece expensive.
//
// The whole account name is exempt. It is the candidate the attack is really about, round zero is meant
// to be byte for byte what one word per account always did, and a person whose account is "jo" should
// still have "jo" tried.

#define ASSOCIATION_WORD_MIN_LEN 3

// An account with fewer words than the round count would spend the rest of its rounds repeating itself.
// Those rounds are already paid for, so they are filled with one of these applied to the words the
// account does have.
//
// They are the first rules of rules/rockyou-30000.rule, which is ordered by how often each rule wins, so
// these are the best few. The cap above is what makes hardcoding them enough: no account can need more
// than one fewer than it. They stack with whatever -r the user asked for rather than replacing it, which
// is the point, because a rule the user brings is applied to these as well.

#define ASSOCIATION_PAD_RULES { "$1", "r", "$2", "$1 $2 $3", "$1 $2", "$3", "$7", "^1" }

// One word taken out of an account name. Every word is a substring of the name, so this points into the
// name itself and nothing is copied or allocated.

typedef struct hlfmt_word
{
  const char *buf;

  u32 len;

} hlfmt_word_t;

HC_PLUGIN_API const char *strhlfmt (const u32 hashfile_format);

HC_PLUGIN_API u32 hlfmt_user_words (const char *user_buf, const u32 user_len, hlfmt_word_t *out_words, const u32 out_max);

void hlfmt_hash (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len);
void hlfmt_user (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len);

u32 hlfmt_detect (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, u32 max_check);

#endif // HC_HLFMT_H
