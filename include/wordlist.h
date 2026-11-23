/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_WORDLIST_H
#define HC_WORDLIST_H

#include "ext_iconv.h"

#include <time.h>
#include <inttypes.h>

size_t convert_from_hex     (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len);
size_t convert_hex_wordlist (char *line_buf, const size_t line_len);

// Everything that happens to one side of a candidate between the source handing it over and the
// device receiving it. There are four producers and each used to carry its own copy of this, in its
// own order, so a word could come out of a -a 1 with its two halves transformed differently.
//
// The order is fixed here and is the same for every producer:
//
//   1. the hex decodes, because until the line is decoded there is no password to do anything to
//   2. the rule, because that is what the user asked to try, and it applies to the password
//   3. PT_UPPER, because the hash mode defines its plaintext as uppercase, whatever the rule made
//   4. the encoding change, because those are the bytes the kernel gets and nothing may touch them
//
// The rule is the only field that differs between the two sides: -j belongs to the base word and -k
// to the amplifier.

typedef struct pw_transform
{
  bool pt_uppercase;
  bool pt_lowercase;
  bool pt_hex;
  bool wordlist_autohex;

  int         rule_len;
  const char *rule_buf;

  // An iconv descriptor carries conversion state, so one belongs to one thread and never to two.
  // The library is held here as well, because it is loaded at runtime and asking for it again is a
  // once-check this would otherwise do for every candidate.

  bool       iconv_enabled;
  hc_iconv_t iconv_ctx;
  char      *iconv_tmp;

  const hc_iconv_lib_t *iconv_lib;

  // True when the autohex step is the only one that could fire, which is the ordinary wordlist run.
  // Worked out once in pw_transform_init () rather than per candidate.

  bool autohex_only;

} pw_transform_t;

int  pw_transform_init    (pw_transform_t *transform, hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int rule_len, const char *rule_buf);
void pw_transform_term    (pw_transform_t *transform);
bool pw_transform_shrinks (const pw_transform_t *transform);
int  pw_transform_apply   (const pw_transform_t *transform, u8 *buf, const int len, const int buf_size);

void pw_pre_add       (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx);
void pw_base_add      (pw_batch_t *batch, const u64 pws_max, const u8 *base_buf, const int base_len, const int rule_idx);
void pw_batch_reset   (pw_batch_t *batch);
bool pw_runs_grow     (pw_runs_t *runs);
void pw_add_zerocopy  (pw_batch_t *batch, const u64 pws_max, u8 *out_buf, const int pw_len);
void pw_add           (pw_batch_t *batch, const u64 pws_max, const u8 *pw_buf, const int pw_len);

// The candidates from pws_idx on come from words_off onwards, see pw_run_t. A run that has not had a
// candidate yet is moved rather than kept, because nothing came from where it pointed, so a row of
// rejected words costs one run. A producer calls this for every word it rejects, which is why it is
// inline.

static inline void pw_runs_from (pw_runs_t *runs, const u64 pws_idx, const u128 words_off)
{
  if (runs->cnt > 0)
  {
    pw_run_t *last = &runs->buf[runs->cnt - 1];

    if (last->pws_idx == pws_idx)
    {
      last->words_off = words_off;

      return;
    }
  }

  if (runs->cnt == runs->max)
  {
    if (pw_runs_grow (runs) == false) return;
  }

  pw_run_t *run = &runs->buf[runs->cnt];

  run->pws_idx   = pws_idx;
  run->words_off = words_off;

  runs->cnt++;
}

// The candidates added from here on come from words_off onwards. For an empty batch that is where it
// starts. Otherwise it is a run of its own.

static inline void pw_batch_from (pw_batch_t *batch, const u128 words_off)
{
  if (batch->pws_cnt == 0)
  {
    batch->words_off = words_off;

    return;
  }

  pw_runs_from (&batch->runs, batch->pws_cnt, words_off);
}

#endif // HC_WORDLIST_H
