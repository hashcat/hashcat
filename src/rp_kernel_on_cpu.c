/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "rp.h"
#include "rp_kernel_on_cpu.h"

static void upper_at (u8 *buf, const int pos)
{
  const u8 c = buf[pos];

  if ((c >= 'a') && (c <= 'z')) buf[pos] ^= 0x20;
}

static void lower_at (u8 *buf, const int pos)
{
  const u8 c = buf[pos];

  if ((c >= 'A') && (c <= 'Z')) buf[pos] ^= 0x20;
}

static void toggle_at (u8 *buf, const int pos)
{
  const u8 c = buf[pos];

  if ((c >= 'a') && (c <= 'z')) buf[pos] ^= 0x20;
  if ((c >= 'A') && (c <= 'Z')) buf[pos] ^= 0x20;
}

static void mangle_switch (u8 *buf, const int l, const int r)
{
  const u8 c = buf[r];
  buf[r] = buf[l];
  buf[l] = c;
}

static int mangle_lrest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) lower_at (buf, pos);

  return (len);
}

static int mangle_lrest_ufirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) lower_at (buf, pos);

  upper_at (buf, 0);

  return (len);
}

static int mangle_urest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) upper_at (buf, pos);

  return (len);
}

static int mangle_urest_lfirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) upper_at (buf, pos);

  lower_at (buf, 0);

  return (len);
}

static int mangle_trest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) toggle_at (buf, pos);

  return (len);
}

static int mangle_toggle_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  toggle_at (buf, p0);

  return (len);
}

static int mangle_reverse (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int l = 0; l < len / 2; l++)
  {
    const int r = len - 1 - l;

    mangle_switch (buf, l, r);
  }

  return (len);
}

static int mangle_dupeword (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  u8 *out = buf + len;

  for (int i = 0; i < len; i++) *out++ = *buf++;

  return (out_len);
}

static int mangle_dupeword_times (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = (len * p0) + len;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  u8 *out = buf + len;

  for (int t = 0; t < p0; t++) for (int i = 0; i < len; i++) *out++ = *buf++;

  return (out_len);
}

static int mangle_reflect (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  mangle_dupeword (p0, p1, buf, len);

  mangle_reverse (p0, p1, buf + len, len);

  return out_len;
}

static int mangle_append (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  buf[len] = p0;

  return (out_len);
}

static int mangle_prepend (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  for (int pos = len - 1; pos >= 0; pos--)
  {
    buf[pos + 1] = buf[pos];
  }

  buf[0] = p0;

  return (out_len);
}

static int mangle_rotate_left (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int l = 0, r = len - 1; r > l; r--)
  {
    mangle_switch (buf, l, r);
  }

  return (len);
}

static int mangle_rotate_right (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int l = 0, r = len - 1; l < r; l++)
  {
    mangle_switch (buf, l, r);
  }

  return (len);
}

static int mangle_delete_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  for (int pos = p0; pos < len - 1; pos++)
  {
    buf[pos] = buf[pos + 1];
  }

  buf[len - 1] = 0;

  return (len - 1);
}

static int mangle_delete_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  return mangle_delete_at (0, p1, buf, len);
}

static int mangle_delete_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (len == 0) return 0;

  return mangle_delete_at (len - 1, p1, buf, len);
}

static int mangle_extract (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  if ((p0 + p1) > len) return (len);

  for (int pos = 0; pos < p1; pos++)
  {
    buf[pos] = buf[p0 + pos];
  }

  for (int pos = p1; pos < len; pos++)
  {
    buf[pos] = 0;
  }

  return (p1);
}

static int mangle_omit (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  if ((p0 + p1) > len) return (len);

  for (int pos = p0; pos < len - p1; pos++)
  {
    buf[pos] = buf[pos + p1];
  }

  for (int pos = len - p1; pos < len; pos++)
  {
    buf[pos] = 0;
  }

  return (len - p1);
}

static int mangle_insert (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len + 1) return (len);

  const int out_len = len + 1;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  for (int pos = len - 1; pos > p0 - 1; pos--)
  {
    buf[pos + 1] = buf[pos];
  }

  buf[p0] = p1;

  return (out_len);
}

static int mangle_overstrike (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] = p1;

  return (len);
}

static int mangle_truncate_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  for (int pos = p0; pos < len; pos++)
  {
    buf[pos] = 0;
  }

  return (p0);
}

static int mangle_replace (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++)
  {
    if (buf[pos] != p0) continue;

    buf[pos] = p1;
  }

  return (len);
}

static int mangle_purgechar (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  int out_len = 0;

  for (int pos = 0; pos < len; pos++)
  {
    if (buf[pos] == p0) continue;

    buf[out_len] = buf[pos];

    out_len++;
  }

  for (int pos = out_len; pos < len; pos++)
  {
    buf[pos] = 0;
  }

  return (out_len);
}

static int mangle_dupechar_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + p0;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  const u8 c = buf[0];

  for (int i = 0; i < p0; i++)
  {
    mangle_prepend (c, 0, buf, len + i);
  }

  return (out_len);
}

static int mangle_dupechar_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + p0;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  const u8 c = buf[len - 1];

  for (int i = 0; i < p0; i++)
  {
    mangle_append (c, 0, buf, len + i);
  }

  return (out_len);
}

static int mangle_dupechar_all (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + len;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  for (int pos = len - 1; pos >= 0; pos--)
  {
    int new_pos = pos * 2;

    buf[new_pos] = buf[pos];

    buf[new_pos + 1] = buf[pos];
  }

  return (out_len);
}

static int mangle_switch_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (len < 2) return (len);

  mangle_switch (buf, 0, 1);

  return (len);
}

static int mangle_switch_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (len < 2) return (len);

  mangle_switch (buf, len - 2, len - 1);

  return (len);
}

static int mangle_switch_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);
  if (p1 >= len) return (len);

  mangle_switch (buf, p0, p1);

  return (len);
}

static int mangle_chr_shiftl (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] <<= 1;

  return (len);
}

static int mangle_chr_shiftr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] >>= 1;

  return (len);
}

static int mangle_chr_incr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0]++;

  return (len);
}

static int mangle_chr_decr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0]--;

  return (len);
}

static int mangle_replace_np1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if ((p0 + 1) >= len) return (len);

  buf[p0] = buf[p0 + 1];

  return (len);
}

static int mangle_replace_nm1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 == 0) return (len);

  if (p0 >= len) return (len);

  buf[p0] = buf[p0 - 1];

  return (len);
}

static int mangle_dupeblock_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  const int out_len = len + p0;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  for (int i = 0; i < p0; i++)
  {
    const u8 c = buf[i * 2];

    mangle_insert (i, c, buf, len + i);
  }

  return (out_len);
}

static int mangle_dupeblock_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  const int out_len = len + p0;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  for (int i = 0; i < p0; i++)
  {
    const u8 c = buf[len - p0 + i];

    mangle_append (c, 0, buf, len + i);
  }

  return (out_len);
}

static int mangle_title_sep (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  int upper_next = 1;

  for (int pos = 0; pos < len; pos++)
  {
    if (buf[pos] == p0)
    {
      upper_next = 1;

      continue;
    }

    if (upper_next)
    {
      upper_next = 0;

      upper_at (buf, pos);
    }
    else
    {
      lower_at (buf, pos);
    }
  }

  return (len);
}

static int apply_rule (const u32 name, MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int in_len)
{
  int out_len = in_len;

  switch (name)
  {
    case RULE_OP_MANGLE_LREST:            out_len = mangle_lrest            (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_LREST_UFIRST:     out_len = mangle_lrest_ufirst     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_UREST:            out_len = mangle_urest            (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_UREST_LFIRST:     out_len = mangle_urest_lfirst     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TREST:            out_len = mangle_trest            (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TOGGLE_AT:        out_len = mangle_toggle_at        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REVERSE:          out_len = mangle_reverse          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD:         out_len = mangle_dupeword         (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD_TIMES:   out_len = mangle_dupeword_times   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REFLECT:          out_len = mangle_reflect          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_APPEND:           out_len = mangle_append           (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_PREPEND:          out_len = mangle_prepend          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_LEFT:      out_len = mangle_rotate_left      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_RIGHT:     out_len = mangle_rotate_right     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_FIRST:     out_len = mangle_delete_first     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_LAST:      out_len = mangle_delete_last      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_AT:        out_len = mangle_delete_at        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_EXTRACT:          out_len = mangle_extract          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_OMIT:             out_len = mangle_omit             (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_INSERT:           out_len = mangle_insert           (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_OVERSTRIKE:       out_len = mangle_overstrike       (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TRUNCATE_AT:      out_len = mangle_truncate_at      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE:          out_len = mangle_replace          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_PURGECHAR:        out_len = mangle_purgechar        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_FIRST:   out_len = mangle_dupechar_first   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_LAST:    out_len = mangle_dupechar_last    (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_ALL:     out_len = mangle_dupechar_all     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_FIRST:     out_len = mangle_switch_first     (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_LAST:      out_len = mangle_switch_last      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_AT:        out_len = mangle_switch_at        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTL:       out_len = mangle_chr_shiftl       (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTR:       out_len = mangle_chr_shiftr       (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_CHR_INCR:         out_len = mangle_chr_incr         (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_CHR_DECR:         out_len = mangle_chr_decr         (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NP1:      out_len = mangle_replace_np1      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NM1:      out_len = mangle_replace_nm1      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_FIRST:  out_len = mangle_dupeblock_first  (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_LAST:   out_len = mangle_dupeblock_last   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TITLE_SEP:        out_len = mangle_title_sep        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TITLE:            out_len = mangle_title_sep        (' ', p1, buf, out_len); break;
  }

  return out_len;
}

int apply_rules (const u32 *cmds, u32 buf[64], const int in_len)
{
  int out_len = in_len;

  for (u32 i = 0; cmds[i] != 0; i++)
  {
    const u32 cmd = cmds[i];

    const u8 name = (cmd >>  0) & 0xff;
    const u8 p0   = (cmd >>  8) & 0xff;
    const u8 p1   = (cmd >> 16) & 0xff;

    out_len = apply_rule (name, p0, p1, (u8 *) buf, out_len);
  }

  return out_len;
}
