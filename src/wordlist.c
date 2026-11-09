/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "rp.h"
#include "rp_cpu.h"
#include "shared.h"
#include "wordlist.h"

// The whole-wordlist hex decode. It is driven by the hash mode and not by anything the user or a
// plugin chose, so it always applies when the mode asks for it.

size_t convert_hex_wordlist (char *line_buf, const size_t line_len)
{
  if (line_len & 1) return (line_len); // not in hex

  size_t i, j;

  for (i = 0, j = 0; j < line_len; i += 1, j += 2)
  {
    line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
  }

  memset (line_buf + i, 0, line_len - i);

  return (i);
}

size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (line_len & 1) return (line_len); // not in hex

  if (hashconfig->opts_type & OPTS_TYPE_PT_HEX)
  {
    const size_t new_len = convert_hex_wordlist (line_buf, line_len);

    return (new_len);
  }

  if (user_options->wordlist_autohex == true)
  {
    if (is_hexify ((const u8 *) line_buf, line_len) == true)
    {
      const size_t new_len = exec_unhexify ((const u8 *) line_buf, line_len, (u8 *) line_buf, line_len);

      return new_len;
    }
  }

  return (line_len);
}

// A comma separated encoding list, split into its elements. The same shape the device list takes:
// empty elements are collapsed by strtok_r () rather than refused.

static int encoding_list_split (const char *str, char items[][ENCODING_NAME_MAX], u32 *items_cnt)
{
  char *copy = hcstrdup (str);

  char *saveptr = NULL;

  u32 cnt = 0;

  char *next = strtok_r (copy, ",", &saveptr);

  while (next != NULL)
  {
    const size_t len = strlen (next);

    if (len >= ENCODING_NAME_MAX) break;

    if (cnt >= ENCODING_LIST_MAX) break;

    strcpy (items[cnt], next);

    cnt++;

    next = strtok_r (NULL, ",", &saveptr);
  }

  hcfree (copy);

  if (next != NULL) return -1;

  *items_cnt = cnt;

  return 0;
}

// The (from, to) pairs the two encoding lists make, in list order. Several identical pairs are one
// candidate and so are several identity pairs, so the list keeps the first of each.

static int encoding_pairs_build (const char *encoding_from, const char *encoding_to, char pairs_from[][ENCODING_NAME_MAX], char pairs_to[][ENCODING_NAME_MAX], u32 *pairs_cnt)
{
  char froms[ENCODING_LIST_MAX][ENCODING_NAME_MAX];
  char tos  [ENCODING_LIST_MAX][ENCODING_NAME_MAX];

  u32 froms_cnt = 0;
  u32 tos_cnt   = 0;

  if (encoding_list_split (encoding_from, froms, &froms_cnt) == -1) return -1;
  if (encoding_list_split (encoding_to,   tos,   &tos_cnt)   == -1) return -1;

  // An empty list is not an empty answer, it is a list that does not parse: a single empty name used
  // to reach iconv and fail there, and it is the same command line mistake now.

  if ((froms_cnt == 0) || (tos_cnt == 0)) return -1;

  u32 cnt = 0;

  bool identity_seen = false;

  for (u32 i = 0; i < froms_cnt; i++)
  {
    for (u32 j = 0; j < tos_cnt; j++)
    {
      if (strcmp (froms[i], tos[j]) == 0)
      {
        if (identity_seen == true) continue;

        identity_seen = true;
      }
      else
      {
        bool dup = false;

        for (u32 k = 0; k < cnt; k++)
        {
          if ((strcmp (pairs_from[k], froms[i]) == 0) && (strcmp (pairs_to[k], tos[j]) == 0))
          {
            dup = true;

            break;
          }
        }

        if (dup == true) continue;
      }

      if (cnt >= ENCODING_VARIANTS_MAX) return -2;

      strcpy (pairs_from[cnt], froms[i]);
      strcpy (pairs_to  [cnt], tos[j]);

      cnt++;
    }
  }

  *pairs_cnt = cnt;

  return 0;
}

int encoding_variants_cnt (const char *encoding_from, const char *encoding_to)
{
  char pairs_from[ENCODING_VARIANTS_MAX][ENCODING_NAME_MAX];
  char pairs_to  [ENCODING_VARIANTS_MAX][ENCODING_NAME_MAX];

  u32 pairs_cnt = 0;

  const int rc = encoding_pairs_build (encoding_from, encoding_to, pairs_from, pairs_to, &pairs_cnt);

  if (rc != 0) return rc;

  const int variants = (int) pairs_cnt;

  return variants;
}

// Set a transform up for one side of a candidate. role says which feed instance that side is read
// from, because a plugin declares which of these hashcat should do for it: a generator that produces
// finished candidates does not want the user's rule applied on top of them. PT_UPPER and PT_HEX are
// not offered as a choice, because they are what the hash mode requires of a plaintext rather than
// anything the plugin or the user asked for.
//
// rule_len and rule_buf are the side this producer is filling: -j for a base word and -k for an
// amplifier word.

int pw_transform_init (pw_transform_t *transform, hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int rule_len, const char *rule_buf)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;
  const generic_ctx_t  *generic_ctx  = &hashcat_ctx->generic_ctx[role];

  memset (transform, 0, sizeof (pw_transform_t));

  transform->pt_uppercase     = (hashconfig->opts_type & OPTS_TYPE_PT_UPPER) ? true : false;
  transform->pt_lowercase     = (hashconfig->opts_type & OPTS_TYPE_PT_LOWER) ? true : false;
  transform->pt_hex           = (hashconfig->opts_type & OPTS_TYPE_PT_HEX)   ? true : false;
  transform->wordlist_autohex = generic_ctx->autohex_enable && user_options->wordlist_autohex;

  if (generic_ctx->rules_enable == true)
  {
    transform->rule_len = rule_len;
    transform->rule_buf = rule_buf;
  }

  transform->iconv_cnt = 0;

  if (generic_ctx->iconv_enable == true)
  {
    char pairs_from[ENCODING_VARIANTS_MAX][ENCODING_NAME_MAX];
    char pairs_to  [ENCODING_VARIANTS_MAX][ENCODING_NAME_MAX];

    u32 pairs_cnt = 0;

    const int rc = encoding_pairs_build (user_options->encoding_from, user_options->encoding_to, pairs_from, pairs_to, &pairs_cnt);

    if (rc != 0)
    {
      // user_options_sanity () has already turned a bad list down, so this is unreachable in a run
      // that started from the command line

      event_log_error (hashcat_ctx, "Invalid --encoding-from or --encoding-to list");

      return -1;
    }

    // A single pair that converts an encoding to itself is no encoding change at all, which is the
    // case the fast paths test for.

    const bool no_change = (pairs_cnt == 1) && (strcmp (pairs_from[0], pairs_to[0]) == 0);

    if (no_change == false)
    {
      // iconv is loaded at runtime and only this path needs it, so a machine without one runs every
      // attack that does not change encoding and hears about the library the first time one does.

      const hc_iconv_lib_t *iconv_lib = hc_iconv ();

      if (iconv_lib == NULL)
      {
        event_log_error (hashcat_ctx, "iconv support is unavailable: %s. To fix this, %s", hc_iconv_error (), hc_iconv_hint ());

        return -1;
      }

      transform->iconv_lib = iconv_lib;

      for (u32 i = 0; i < pairs_cnt; i++)
      {
        // an identity pair converts the candidate to itself and gets no descriptor

        if (strcmp (pairs_from[i], pairs_to[i]) == 0)
        {
          transform->iconv_ctx[i] = NULL;

          continue;
        }

        transform->iconv_ctx[i] = iconv_lib->iconv_open (pairs_to[i], pairs_from[i]);

        if (transform->iconv_ctx[i] == HC_ICONV_ERR)
        {
          event_log_error (hashcat_ctx, "Cannot convert from encoding '%s' to '%s': %s", pairs_from[i], pairs_to[i], strerror (errno));

          transform->iconv_ctx[i] = NULL;

          return -1;
        }
      }

      transform->iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);

      transform->iconv_cnt = pairs_cnt;
    }
  }

  const bool others = transform->pt_hex | transform->pt_uppercase | transform->pt_lowercase | (transform->iconv_cnt > 0);
  const bool rules  = (run_rule_engine (transform->rule_len, transform->rule_buf) != 0);

  transform->autohex_only = (others == false) && (rules == false);

  return 0;
}

void pw_transform_term (pw_transform_t *transform)
{
  if (transform->iconv_cnt == 0) return;

  for (u32 i = 0; i < transform->iconv_cnt; i++)
  {
    if (transform->iconv_ctx[i] == NULL) continue;

    transform->iconv_lib->iconv_close (transform->iconv_ctx[i]);

    transform->iconv_ctx[i] = NULL;
  }

  hcfree (transform->iconv_tmp);

  transform->iconv_cnt = 0;
  transform->iconv_tmp = NULL;
  transform->iconv_lib = NULL;
}

// Whether a candidate can come out shorter than it arrived. Only these three can do that, and without
// one of them a word too long for the buffer is too long for good and there is nothing to re-read.

bool pw_transform_shrinks (const pw_transform_t *transform)
{
  const bool result = transform->pt_hex | transform->wordlist_autohex | (transform->iconv_cnt > 0);

  return result;
}

// How many candidates one word becomes. 1 when the run does no encoding change, so the producers
// that cannot lay several candidates out can keep calling pw_transform_apply () untouched.

u32 pw_transform_variants (const pw_transform_t *transform)
{
  const u32 variants = (transform->iconv_cnt > 0) ? transform->iconv_cnt : 1;

  return variants;
}

// Apply the whole transform in place, and return the new length or -1 when the word cannot be used.
//
// buf_size is what buf can hold. The encoding change is the one step that can make a word LONGER, so
// it converts into its own buffer and a result that does not fit is refused rather than truncated: a
// utf-16 string cut in half is not a shorter password, it is a different one.

int pw_transform_apply (const pw_transform_t *transform, u8 *buf, const int len, const int buf_size)
{
  const int out_len = pw_transform_apply_variant (transform, 0, buf, len, buf, buf_size);

  return out_len;
}

// The same transform, producing the word's variant: which (from, to) pair the encoding step uses.
// src_buf is only read, so a producer with several variants can hand each of them the word as it was
// read; a caller that has no use for the original passes one buffer for both and it works in place.

int pw_transform_apply_variant (const pw_transform_t *transform, const u32 variant, const u8 *src_buf, const int src_len, u8 *dst_buf, const int dst_size)
{
  if (dst_buf != src_buf)
  {
    if (src_len > dst_size) return -1;

    memcpy (dst_buf, src_buf, (size_t) src_len);
  }

  u8 *buf = dst_buf;

  const int len = src_len;

  const int buf_size = dst_size;

  // The ordinary wordlist run has no inline rule, no encoding change, no hex mode and no forced
  // uppercase, so the only step below that could fire is the autohex one, and that needs the word to
  // spell $HEX[ and to be an even number of bytes at least 6 long. Those are the first three things
  // is_hexify () checks, so a word that fails them here would have failed there, and every step below
  // it is off. Checking them inline keeps a call out of the per candidate path.

  if (transform->autohex_only == true)
  {
    if (transform->wordlist_autohex == false) return len;

    if (len < 6)        return len;
    if ((len & 1) == 1) return len;
    if (buf[0] != '$')  return len;
    if (buf[1] != 'H')  return len;
    if (buf[2] != 'E')  return len;
    if (buf[3] != 'X')  return len;
    if (buf[4] != '[')  return len;
  }

  int out_len = len;

  // 1. how the line spells the password

  if (transform->pt_hex == true)
  {
    out_len = (int) convert_hex_wordlist ((char *) buf, (size_t) out_len);
  }

  if (transform->wordlist_autohex == true)
  {
    if (is_hexify (buf, (size_t) out_len) == true)
    {
      out_len = (int) exec_unhexify (buf, (size_t) out_len, buf, (size_t) out_len);
    }
  }

  // 2. what the user asked to try

  if (run_rule_engine (transform->rule_len, transform->rule_buf))
  {
    if (out_len >= RP_PASSWORD_SIZE) return -1;

    char rule_buf_out[RP_PASSWORD_SIZE];

    const int rule_len_out = _old_apply_rule (transform->rule_buf, transform->rule_len, (char *) buf, out_len, rule_buf_out);

    if (rule_len_out < 0) return -1;

    if (rule_len_out > buf_size) return -1;

    memcpy (buf, rule_buf_out, (size_t) rule_len_out);

    out_len = rule_len_out;
  }

  // 3. what this hash mode hashes

  if (transform->pt_uppercase == true) uppercase (buf, (size_t) out_len);
  if (transform->pt_lowercase == true) lowercase (buf, (size_t) out_len);

  // 4. the bytes the kernel gets

  if (transform->iconv_cnt > 0)
  {
    const hc_iconv_t iconv_ctx = transform->iconv_ctx[variant];

    // an identity pair converts the candidate to itself and has no descriptor

    if (iconv_ctx != NULL)
    {
      char  *iconv_ptr = transform->iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      char  *in_buf = (char *) buf;
      size_t in_len = (size_t) out_len;

      if (transform->iconv_lib->iconv (iconv_ctx, &in_buf, &in_len, &iconv_ptr, &iconv_sz) == (size_t) -1) return -1;

      const size_t iconv_left = HCBUFSIZ_TINY - iconv_sz;

      if (iconv_left > (size_t) buf_size) return -1;

      memcpy (buf, transform->iconv_tmp, iconv_left);

      out_len = (int) iconv_left;
    }
  }

  return out_len;
}

void pw_pre_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx)
{
  if (device_param->pws_pre_cnt < device_param->kernel_power)
  {
    pw_pre_t *pw_pre = device_param->pws_pre_buf + device_param->pws_pre_cnt;

    memcpy (pw_pre->pw_buf, pw_buf, pw_len);

    pw_pre->pw_len = pw_len;

    if (base_buf != NULL)
    {
      memcpy (pw_pre->base_buf, base_buf, base_len);

      pw_pre->base_len = base_len;
    }
    else
    {
      pw_pre->base_len = 0;
    }

    pw_pre->rule_idx = rule_idx;

    device_param->pws_pre_cnt++;
  }
  else
  {
    fprintf (stdout, "BUG pw_pre_add()!!\n");

    return;
  }
}

void pw_base_add (pw_batch_t *batch, const u64 pws_max, const u8 *base_buf, const int base_len, const int rule_idx)
{
  if (batch->pws_base_cnt < pws_max)
  {
    // The fields rather than a pw_pre_t, because a candidate that goes straight into the batch never
    // had one. Only these three are what build_debugdata () reads back, and the candidate itself
    // reaches the batch through pw_add (), so copying pw_buf here would be a second copy of it.

    pw_pre_t *pw_base = batch->pws_base + batch->pws_base_cnt;

    memcpy (pw_base->base_buf, base_buf, base_len);

    pw_base->base_len = base_len;
    pw_base->rule_idx = rule_idx;

    batch->pws_base_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_base_add()!!\n");

    return;
  }
}

// Hand a batch back empty. Clearing the staging buffers in full would be tens of megabytes of memset
// on a large launch to guarantee one zero: pw_add writes every byte it uses, and only the prefix it
// wrote is ever uploaded. The one thing it cannot write for itself is the first entry's offset,
// because each entry only sets up the NEXT one.

void pw_batch_reset (pw_batch_t *batch)
{
  batch->pws_cnt      = 0;
  batch->pws_base_cnt = 0;
  batch->pcfg_waves   = 0;

  batch->words_off       = 0;
  batch->words_fin       = 0;
  batch->words_extra     = 0;
  batch->words_extra_amp = 0;

  batch->runs_cnt = 0;

  batch->pws_idx[0].off = 0;
  batch->pws_idx[0].cnt = 0;
  batch->pws_idx[0].len = 0;
}

// The candidates added from here on come from words_off onwards. For an empty batch that is where it
// starts. Otherwise it is a run of its own, see pw_run_t, and a run that has not had a candidate yet
// is moved rather than kept, because nothing in the batch came from where it pointed.
//
// Both producers stop refilling once the table is full, so the bound below is only a backstop.

void pw_batch_from (pw_batch_t *batch, const u64 words_off)
{
  if (batch->pws_cnt == 0)
  {
    batch->words_off = words_off;

    return;
  }

  if (batch->runs_cnt > 0)
  {
    pw_run_t *last = &batch->runs_buf[batch->runs_cnt - 1];

    if (last->pws_idx == batch->pws_cnt)
    {
      last->words_off = words_off;

      return;
    }
  }

  if (batch->runs_cnt >= PW_RUNS_MAX) return;

  pw_run_t *run = &batch->runs_buf[batch->runs_cnt];

  run->pws_idx   = batch->pws_cnt;
  run->words_off = words_off;

  batch->runs_cnt++;
}

void pw_add_zerocopy (pw_batch_t *batch, const u64 pws_max, u8 *out_buf, const int pw_len)
{
  if (batch->pws_cnt < pws_max)
  {
    pw_idx_t *pw_idx = batch->pws_idx + batch->pws_cnt;

    const u32 pw_len4 = (pw_len + 3) & ~3; // round up to multiple of 4

    const u32 pw_len4_cnt = pw_len4 / 4;

    pw_idx->cnt = pw_len4_cnt;
    pw_idx->len = pw_len;

    memset (out_buf + pw_len, 0, pw_len4 - pw_len);

    // prepare next element

    pw_idx_t *pw_idx_next = pw_idx + 1;

    pw_idx_next->off = pw_idx->off + pw_idx->cnt;

    batch->pws_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_add_zerocopy()!!\n");

    return;
  }
}

void pw_add (pw_batch_t *batch, const u64 pws_max, const u8 *pw_buf, const int pw_len)
{
  if (batch->pws_cnt < pws_max)
  {
    pw_idx_t *pw_idx = batch->pws_idx + batch->pws_cnt;

    const u32 pw_len4 = (pw_len + 3) & ~3; // round up to multiple of 4

    const u32 pw_len4_cnt = pw_len4 / 4;

    pw_idx->cnt = pw_len4_cnt;
    pw_idx->len = pw_len;

    u8 *dst = (u8 *) (batch->pws_comp + pw_idx->off);

    memcpy (dst, pw_buf, pw_len);

    memset (dst + pw_len, 0, pw_len4 - pw_len);

    // prepare next element

    pw_idx_t *pw_idx_next = pw_idx + 1;

    pw_idx_next->off = pw_idx->off + pw_idx->cnt;

    batch->pws_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_add()!!\n");

    return;
  }
}
