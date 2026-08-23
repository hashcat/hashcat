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
  transform->pt_hex           = (hashconfig->opts_type & OPTS_TYPE_PT_HEX)   ? true : false;
  transform->wordlist_autohex = generic_ctx->autohex_enable && user_options->wordlist_autohex;

  if (generic_ctx->rules_enable == true)
  {
    transform->rule_len = rule_len;
    transform->rule_buf = rule_buf;
  }

  if (generic_ctx->iconv_enable == false) return 0;

  if (strcmp (user_options->encoding_from, user_options->encoding_to) == 0) return 0;

  transform->iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

  if (transform->iconv_ctx == (iconv_t) -1)
  {
    event_log_error (hashcat_ctx, "iconv_open: %s", strerror (errno));

    transform->iconv_ctx = NULL;

    return -1;
  }

  transform->iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);

  transform->iconv_enabled = true;

  return 0;
}

void pw_transform_term (pw_transform_t *transform)
{
  if (transform->iconv_enabled == false) return;

  iconv_close (transform->iconv_ctx);

  hcfree (transform->iconv_tmp);

  transform->iconv_enabled = false;
  transform->iconv_ctx     = NULL;
  transform->iconv_tmp     = NULL;
}

// Whether a candidate can come out shorter than it arrived. Only these three can do that, and without
// one of them a word too long for the buffer is too long for good and there is nothing to re-read.

bool pw_transform_shrinks (const pw_transform_t *transform)
{
  const bool result = transform->pt_hex | transform->wordlist_autohex | transform->iconv_enabled;

  return result;
}

// Apply the whole transform in place, and return the new length or -1 when the word cannot be used.
//
// buf_size is what buf can hold. The encoding change is the one step that can make a word LONGER, so
// it converts into its own buffer and a result that does not fit is refused rather than truncated: a
// utf-16 string cut in half is not a shorter password, it is a different one.

int pw_transform_apply (const pw_transform_t *transform, u8 *buf, const int len, const int buf_size)
{
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

  // 4. the bytes the kernel gets

  if (transform->iconv_enabled == true)
  {
    char  *iconv_ptr = transform->iconv_tmp;
    size_t iconv_sz  = HCBUFSIZ_TINY;

    char  *in_buf = (char *) buf;
    size_t in_len = (size_t) out_len;

    if (iconv (transform->iconv_ctx, &in_buf, &in_len, &iconv_ptr, &iconv_sz) == (size_t) -1) return -1;

    const size_t iconv_left = HCBUFSIZ_TINY - iconv_sz;

    if (iconv_left > (size_t) buf_size) return -1;

    memcpy (buf, transform->iconv_tmp, iconv_left);

    out_len = (int) iconv_left;
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

    pw_pre->rule_idx = rule_idx;

    device_param->pws_pre_cnt++;
  }
  else
  {
    fprintf (stdout, "BUG pw_pre_add()!!\n");

    return;
  }
}

void pw_base_add (pw_batch_t *batch, const u64 pws_max, pw_pre_t *pw_pre)
{
  if (batch->pws_base_cnt < pws_max)
  {
    memcpy (batch->pws_base + batch->pws_base_cnt, pw_pre, sizeof (pw_pre_t));

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

  batch->words_off   = 0;
  batch->words_fin   = 0;
  batch->words_extra = 0;

  batch->pws_idx[0].off = 0;
  batch->pws_idx[0].cnt = 0;
  batch->pws_idx[0].len = 0;
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
