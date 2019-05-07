/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_rp.h"

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

#ifdef REAL_SHM
#define COPY_PW(x)                \
  LOCAL_VK pw_t s_pws[64];         \
  s_pws[get_local_id (0)] = (x);
#else
#define COPY_PW(x)                \
  pw_t pw = (x);
#endif

#ifdef REAL_SHM
#define PASTE_PW s_pws[get_local_id(0)];
#else
#define PASTE_PW pw;
#endif

DECLSPEC u32 generate_cmask (const u32 value)
{
  const u32 rmask =  ((value & 0x40404040u) >> 1u)
                  & ~((value & 0x80808080u) >> 2u);

  const u32 hmask = (value & 0x1f1f1f1fu) + 0x05050505u;
  const u32 lmask = (value & 0x1f1f1f1fu) + 0x1f1f1f1fu;

  return rmask & ~hmask & lmask;
}

DECLSPEC void append_four_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst)
{
  const int sd  = off_src / 4;
  const int sm  = off_src & 3;
  const int sm8 = sm * 8;

  const int dd  = off_dst / 4;
  const int dm  = off_dst & 3;
  const int dm8 = dm * 8;

  u64 t64 = hl32_to_64_S (buf_src[sd + 1], buf_src[sd + 0]);

  t64 >>= sm8;
  t64  &= 0xffffffff;
  t64 <<= dm8;

  const u32 t0 = l32_from_64_S (t64);
  const u32 t1 = h32_from_64_S (t64);

  buf_dst[dd + 0] |= t0;
  buf_dst[dd + 1] |= t1;
}

DECLSPEC void append_three_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst)
{
  const int sd  = off_src / 4;
  const int sm  = off_src & 3;
  const int sm8 = sm * 8;

  const int dd  = off_dst / 4;
  const int dm  = off_dst & 3;
  const int dm8 = dm * 8;

  u64 t64 = hl32_to_64_S (buf_src[sd + 1], buf_src[sd + 0]);

  t64 >>= sm8;
  t64  &= 0x00ffffff;
  t64 <<= dm8;

  const u32 t0 = l32_from_64_S (t64);
  const u32 t1 = h32_from_64_S (t64);

  buf_dst[dd + 0] |= t0;
  buf_dst[dd + 1] |= t1;
}

DECLSPEC void append_two_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst)
{
  const int sd  = off_src / 4;
  const int sm  = off_src & 3;
  const int sm8 = sm * 8;

  const int dd  = off_dst / 4;
  const int dm  = off_dst & 3;
  const int dm8 = dm * 8;

  u64 t64 = hl32_to_64_S (buf_src[sd + 1], buf_src[sd + 0]);

  t64 >>= sm8;
  t64  &= 0x0000ffff;
  t64 <<= dm8;

  const u32 t0 = l32_from_64_S (t64);
  const u32 t1 = h32_from_64_S (t64);

  buf_dst[dd + 0] |= t0;
  buf_dst[dd + 1] |= t1;
}

DECLSPEC void append_one_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst)
{
  const int sd  = off_src / 4;
  const int sm  = off_src & 3;
  const int sm8 = sm * 8;

  const int dd  = off_dst / 4;
  const int dm  = off_dst & 3;
  const int dm8 = dm * 8;

  u32 t = buf_src[sd];

  t >>= sm8;
  t  &= 0xff;
  t <<= dm8;

  buf_dst[dd] |= t;
}

DECLSPEC void append_block (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst, const int len)
{
  int i;

  for (i = 0; i < len - 3; i += 4)
  {
    append_four_byte (buf_src, off_src + i, buf_dst, off_dst + i);
  }

  const int left = len - i;

  switch (left)
  {
    case 3: append_three_byte (buf_src, off_src + i, buf_dst, off_dst + i); break;
    case 2: append_two_byte   (buf_src, off_src + i, buf_dst, off_dst + i); break;
    case 1: append_one_byte   (buf_src, off_src + i, buf_dst, off_dst + i); break;
  }
}

DECLSPEC void exchange_byte (u32 *buf, const int off_src, const int off_dst)
{
  u8 *ptr = (u8 *) buf;

  const u8 tmp = ptr[off_src];

  ptr[off_src] = ptr[off_dst];
  ptr[off_dst] = tmp;

  /*
  something tells me we do this faster

  const int sd  = off_src / 4;
  const int sm  = off_src & 3;
  const int sm8 = sm * 8;

  const int dd  = off_dst / 4;
  const int dm  = off_dst & 3;
  const int dm8 = dm * 8;

  u32 ts = buf[sd];
  u32 td = buf[dd];

  ts >>= sm8;
  td >>= dm8;

  ts &= 0xff;
  td &= 0xff;

  const u32 x = ts ^ td;

  const u32 xs = x << sm8;
  const u32 xd = x << dm8;

  buf[sd] ^= xs;
  buf[dd] ^= xd;
  */
}

DECLSPEC int mangle_lrest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t | generate_cmask (t);
  }

  return (len);
}

DECLSPEC int mangle_lrest_ufirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t | generate_cmask (t);
  }

  const u32 t = buf[0];

  buf[0] = t & ~(0x00000020 & generate_cmask (t));

  return (len);
}

DECLSPEC int mangle_urest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t & ~(generate_cmask (t));
  }

  return (len);
}

DECLSPEC int mangle_urest_lfirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t & ~(generate_cmask (t));
  }

  const u32 t = buf[0];

  buf[0] = t | (0x00000020 & generate_cmask (t));

  return (len);
}

DECLSPEC int mangle_trest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t ^ generate_cmask (t);
  }

  return (len);
}

DECLSPEC int mangle_toggle_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  if (p0 >= len) return (len);

  const u8 p0d = p0 / 4;
  const u8 p0m = p0 & 3;

  const u32 tmp = 0x20u << (p0m * 8);

  const u32 t = buf[p0d];

  buf[p0d] = t ^ (generate_cmask (t) & tmp);

  return (len);
}

DECLSPEC int mangle_reverse (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int l = 0; l < len / 2; l++)
  {
    const int r = len - 1 - l;

    exchange_byte (buf, l, r);
  }

  return (len);
}

DECLSPEC int mangle_dupeword (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  append_block (buf, 0, buf, len, len);

  return (out_len);
}

DECLSPEC int mangle_dupeword_times (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = (len * p0) + len;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  u8 *out = buf + len;

  for (int t = 0; t < p0; t++) for (int i = 0; i < len; i++) *out++ = *buf++;

  return (out_len);
}

DECLSPEC int mangle_reflect (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  const int out_len = len * 2;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  append_block (buf, 0, buf, len, len);

  for (int l = 0; l < len / 2; l++)
  {
    const int r = len - 1 - l;

    exchange_byte (buf, len + l, len + r);
  }

  return out_len;
}

DECLSPEC int mangle_append (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  buf[len] = p0;

  return (out_len);
}

DECLSPEC int mangle_prepend (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + 1;

  if (out_len >= RP_PASSWORD_SIZE) return (len);

  for (int pos = len - 1; pos >= 0; pos--)
  {
    buf[pos + 1] = buf[pos];
  }

  buf[0] = p0;

  return (out_len);
}

DECLSPEC int mangle_rotate_left (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int l = 0, r = len - 1; r > l; r--)
  {
    exchange_byte (buf, l, r);
  }

  return (len);
}

DECLSPEC int mangle_rotate_right (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  for (int l = 0, r = len - 1; l < r; l++)
  {
    exchange_byte (buf, l, r);
  }

  return (len);
}

DECLSPEC int mangle_delete_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  for (int pos = p0; pos < len - 1; pos++)
  {
    buf[pos] = buf[pos + 1];
  }

  buf[len - 1] = 0;

  return (len - 1);
}

DECLSPEC int mangle_delete_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  return mangle_delete_at (0, p1, buf, len);
}

DECLSPEC int mangle_delete_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (len == 0) return 0;

  return mangle_delete_at (len - 1, p1, buf, len);
}

DECLSPEC int mangle_extract (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_omit (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_insert (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_overstrike (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] = p1;

  return (len);
}

DECLSPEC int mangle_truncate_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  for (int pos = p0; pos < len; pos++)
  {
    buf[pos] = 0;
  }

  return (p0);
}

DECLSPEC int mangle_replace (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  for (int pos = 0; pos < len; pos++)
  {
    if (buf[pos] != p0) continue;

    buf[pos] = p1;
  }

  return (len);
}

DECLSPEC int mangle_purgechar (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_dupechar_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_dupechar_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  const int out_len = len + p0;

  if (len     ==                0) return (len);
  if (out_len >= RP_PASSWORD_SIZE) return (len);

  const u8 c = buf[len - 1];

  for (int i = 0; i < p0; i++)
  {
    mangle_append (c, 0, buf, len + i);
  }

  return (out_len);
}

DECLSPEC int mangle_dupechar_all (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_switch_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  if (len < 2) return (len);

  exchange_byte (buf, 0, 1);

  return (len);
}

DECLSPEC int mangle_switch_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  if (len < 2) return (len);

  exchange_byte (buf, len - 2, len - 1);

  return (len);
}

DECLSPEC int mangle_switch_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  if (p0 >= len) return (len);
  if (p1 >= len) return (len);

  exchange_byte (buf, p0, p1);

  return (len);
}

DECLSPEC int mangle_chr_shiftl (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] <<= 1;

  return (len);
}

DECLSPEC int mangle_chr_shiftr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0] >>= 1;

  return (len);
}

DECLSPEC int mangle_chr_incr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0]++;

  return (len);
}

DECLSPEC int mangle_chr_decr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 >= len) return (len);

  buf[p0]--;

  return (len);
}

DECLSPEC int mangle_replace_np1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if ((p0 + 1) >= len) return (len);

  buf[p0] = buf[p0 + 1];

  return (len);
}

DECLSPEC int mangle_replace_nm1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
{
  if (p0 == 0) return (len);

  if (p0 >= len) return (len);

  buf[p0] = buf[p0 - 1];

  return (len);
}

DECLSPEC int mangle_dupeblock_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_dupeblock_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len)
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

DECLSPEC int mangle_title_sep (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len)
{
  if ((len + 4) >= RP_PASSWORD_SIZE) return (len); // cheap way to not need to check for overflow of i + 1

  for (int i = 0, idx = 0; i < len; i += 4, idx += 1)
  {
    const u32 t = buf[idx];

    buf[idx] = t | generate_cmask (t);

    u32 out0 = 0;
    u32 out1 = 0;

    if (((t >>  0) & 0xff) == p0) out0 |= 0x0000ff00;
    if (((t >>  8) & 0xff) == p0) out0 |= 0x00ff0000;
    if (((t >> 16) & 0xff) == p0) out0 |= 0xff000000;
    if (((t >> 24) & 0xff) == p0) out1 |= 0x000000ff;

    buf[idx + 0] &= ~(generate_cmask (buf[idx + 0]) & out0);
    buf[idx + 1] &= ~(generate_cmask (buf[idx + 1]) & out1);
  }

  const u32 t = buf[0];

  buf[0] = t & ~(0x00000020 & generate_cmask (t));

  return (len);
}

DECLSPEC int apply_rule (const u32 name, MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int in_len)
{
  int out_len = in_len;

  switch (name)
  {
    case RULE_OP_MANGLE_LREST:            out_len = mangle_lrest            (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_LREST_UFIRST:     out_len = mangle_lrest_ufirst     (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_UREST:            out_len = mangle_urest            (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_UREST_LFIRST:     out_len = mangle_urest_lfirst     (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_TREST:            out_len = mangle_trest            (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_TOGGLE_AT:        out_len = mangle_toggle_at        (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_REVERSE:          out_len = mangle_reverse          (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD:         out_len = mangle_dupeword         (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD_TIMES:   out_len = mangle_dupeword_times   (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_REFLECT:          out_len = mangle_reflect          (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_APPEND:           out_len = mangle_append           (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_PREPEND:          out_len = mangle_prepend          (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_LEFT:      out_len = mangle_rotate_left      (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_ROTATE_RIGHT:     out_len = mangle_rotate_right     (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_FIRST:     out_len = mangle_delete_first     (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_LAST:      out_len = mangle_delete_last      (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DELETE_AT:        out_len = mangle_delete_at        (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_EXTRACT:          out_len = mangle_extract          (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_OMIT:             out_len = mangle_omit             (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_INSERT:           out_len = mangle_insert           (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_OVERSTRIKE:       out_len = mangle_overstrike       (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_TRUNCATE_AT:      out_len = mangle_truncate_at      (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE:          out_len = mangle_replace          (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_PURGECHAR:        out_len = mangle_purgechar        (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_FIRST:   out_len = mangle_dupechar_first   (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_LAST:    out_len = mangle_dupechar_last    (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_ALL:     out_len = mangle_dupechar_all     (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_FIRST:     out_len = mangle_switch_first     (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_LAST:      out_len = mangle_switch_last      (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_SWITCH_AT:        out_len = mangle_switch_at        (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTL:       out_len = mangle_chr_shiftl       (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTR:       out_len = mangle_chr_shiftr       (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_CHR_INCR:         out_len = mangle_chr_incr         (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_CHR_DECR:         out_len = mangle_chr_decr         (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NP1:      out_len = mangle_replace_np1      (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NM1:      out_len = mangle_replace_nm1      (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_FIRST:  out_len = mangle_dupeblock_first  (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_LAST:   out_len = mangle_dupeblock_last   (p0, p1, (u8 *) buf, out_len); break;
    case RULE_OP_MANGLE_TITLE_SEP:        out_len = mangle_title_sep        (p0, p1,        buf, out_len); break;
    case RULE_OP_MANGLE_TITLE:            out_len = mangle_title_sep        (' ', p1,       buf, out_len); break;
  }

  return out_len;
}

DECLSPEC int apply_rules (CONSTANT_AS const u32 *cmds, u32 *buf, const int in_len)
{
  int out_len = in_len;

  for (u32 i = 0; cmds[i] != 0; i++)
  {
    const u32 cmd = cmds[i];

    const u8 name = (cmd >>  0) & 0xff;
    const u8 p0   = (cmd >>  8) & 0xff;
    const u8 p1   = (cmd >> 16) & 0xff;

    out_len = apply_rule (name, p0, p1, buf, out_len);
  }

  return out_len;
}
