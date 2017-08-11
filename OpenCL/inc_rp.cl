/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

int class_digit (const u8 c)
{
  if ((c >= '0') && (c <= '9')) return 1;

  return 0;
}

int class_lower (const u8 c)
{
  if ((c >= 'a') && (c <= 'z')) return 1;

  return 0;
}

int class_upper (const u8 c)
{
  if ((c >= 'A') && (c <= 'Z')) return 1;

  return 0;
}

int class_alpha (const u8 c)
{
  if (class_lower (c) == 1) return 1;
  if (class_upper (c) == 1) return 1;

  return 0;
}

void upper_at (u8 *buf, const int pos)
{
  if (class_lower (buf[pos])) buf[pos] ^= 0x20;
}

void lower_at (u8 *buf, const int pos)
{
  if (class_upper (buf[pos])) buf[pos] ^= 0x20;
}

void toggle_at (u8 *buf, const int pos)
{
  if (class_alpha (buf[pos])) buf[pos] ^= 0x20;
}

void mangle_switch (u8 *buf, const int l, const int r)
{
  const u8 c = buf[r];
  buf[r] = buf[l];
  buf[l] = c;
}

int mangle_lrest (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) lower_at (buf, pos);

  return (len);
}

int mangle_lrest_ufirst (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) lower_at (buf, pos);

  upper_at (buf, 0);

  return (len);
}

int mangle_urest (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) upper_at (buf, pos);

  return (len);
}

int mangle_urest_lfirst (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) upper_at (buf, pos);

  lower_at (buf, 0);

  return (len);
}

int mangle_trest (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++) toggle_at (buf, pos);

  return (len);
}

int mangle_toggle_at (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  toggle_at (buf, p0);

  return (len);
}

int mangle_reverse (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int l = 0; l < len / 2; l++)
  {
    const int r = len - 1 - l;

    mangle_switch (buf, l, r);
  }

  return (len);
}

int mangle_dupeword (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  u8 *out = buf + len;

  for (int i = 0; i < len; i++) *out++ = *buf++;

  return (out_len);
}

int mangle_dupeword_times (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  const int out_len = (len * p0) + len;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  u8 *out = buf + len;

  for (int t = 0; t < p0; t++) for (int i = 0; i < len; i++) *out++ = *buf++;

  return (out_len);
}

int mangle_reflect (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  mangle_dupeword (p0, p1, buf, len);

  mangle_reverse (p0, p1, buf + len, len);

  return out_len;
}

int mangle_append (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  buf[len] = p0;

  return (out_len);
}

int mangle_prepend (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  for (int pos = len - 1; pos >= 0; pos--)
  {
    buf[pos + 1] = buf[pos];
  }

  buf[0] = p0;

  return (out_len);
}

int mangle_rotate_left (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int l = 0, r = len - 1; r > l; r--)
  {
    mangle_switch (buf, l, r);
  }

  return (len);
}

int mangle_rotate_right (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  for (int l = 0, r = len - 1; l < r; l++)
  {
    mangle_switch (buf, l, r);
  }

  return (len);
}

int mangle_delete_at (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  for (int pos = p0; pos < len - 1; pos++)
  {
    buf[pos] = buf[pos + 1];
  }

  buf[len - 1] = 0;

  return (len - 1);
}

int mangle_delete_first (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  return mangle_delete_at (0, p1, buf, len);
}

int mangle_delete_last (const u8 p0, const u8 p1, u8 *buf, const int len)
{
  if (len == 0) return 0;

  return mangle_delete_at (len - 1, p1, buf, len);
}

int mangle_extract (const u8 p0, const u8 p1, u8 *buf, const int len)
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


int apply_rule (const u32 name, const u8 p0, const u8 p1, u8 *buf, const int in_len)
{
  int out_len = in_len;

  switch (name)
  {
    case RULE_OP_MANGLE_LREST:          out_len = mangle_lrest          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_LREST_UFIRST:   out_len = mangle_lrest_ufirst   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_UREST:          out_len = mangle_urest          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_UREST_LFIRST:   out_len = mangle_urest_lfirst   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TREST:          out_len = mangle_trest          (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_TOGGLE_AT:      out_len = mangle_toggle_at      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REVERSE:        out_len = mangle_reverse        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD:       out_len = mangle_dupeword       (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD_TIMES: out_len = mangle_dupeword_times (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_REFLECT:        out_len = mangle_reflect        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_APPEND:         out_len = mangle_append         (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_PREPEND:        out_len = mangle_prepend        (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_LEFT:    out_len = mangle_rotate_left    (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_RIGHT:   out_len = mangle_rotate_right   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_FIRST:   out_len = mangle_delete_first   (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_LAST:    out_len = mangle_delete_last    (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_AT:      out_len = mangle_delete_at      (p0, p1, buf, out_len); break;
    case RULE_OP_MANGLE_EXTRACT:        out_len = mangle_extract        (p0, p1, buf, out_len); break;
  }

  return out_len;
}

u32 apply_rules (__global const u32 *cmds, u32 in_buf[64], const int in_len, u32 out_buf[64])
{
  const int in_lenv = ceil ((float) in_len / 4);

  for (int i = 0; i < in_lenv; i++) out_buf[i] = in_buf[i];

  int out_len = in_len;

  for (u32 i = 0; cmds[i] != 0; i++)
  {
    const u32 cmd = cmds[i];

    const u8 name = (cmd >>  0) & 0xff;
    const u8 p0   = (cmd >>  8) & 0xff;
    const u8 p1   = (cmd >> 16) & 0xff;

    out_len = apply_rule (name, p0, p1, (u8 *) out_buf, out_len);
  }

  return (u32) out_len;
}
