/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"

#define CHARSIZ 256

#include "inc_types.cl"

DECLSPEC void generate_pw (u32 *pw_buf, __global const cs_t *root_css_buf, __global const cs_t *markov_css_buf, const u32 pw_l_len, const u32 pw_r_len, const u32 mask80, const u32 bits14, const u32 bits15, u64 val)
{
  __global const cs_t *cs = &root_css_buf[pw_r_len];

  u32 i;
  u32 j;

  for (i = 0, j = pw_r_len; i < pw_l_len; i++, j++)
  {
    const u32 len = cs->cs_len;

    const u64 next = val / len;
    const u64 pos  = val % len;

    val = next;

    const u32 key = cs->cs_buf[pos];

    const u32 jd4 = j / 4;
    const u32 jm4 = j % 4;

    pw_buf[jd4] |= key << (jm4 * 8);

    cs = &markov_css_buf[(j * CHARSIZ) + key];
  }

  const u32 jd4 = j / 4;
  const u32 jm4 = j % 4;

  pw_buf[jd4] |= (0xff << (jm4 * 8)) & mask80;

  if (bits14) pw_buf[14] = (pw_l_len + pw_r_len) * 8;
  if (bits15) pw_buf[15] = (pw_l_len + pw_r_len) * 8;
}

__kernel void l_markov (__global pw_t * restrict pws_buf_l, __global const cs_t * restrict root_css_buf, __global const cs_t * restrict markov_css_buf, const u64 off, const u32 pw_l_len, const u32 pw_r_len, const u32 mask80, const u32 bits14, const u32 bits15, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf[64] = { 0 };

  generate_pw (pw_buf, root_css_buf, markov_css_buf, pw_l_len, pw_r_len, mask80, bits14, bits15, off + gid);

  #pragma unroll
  for (int idx = 0; idx < 64; idx++)
  {
    pws_buf_l[gid].i[idx] = pw_buf[idx];
  }

  pws_buf_l[gid].pw_len = pw_l_len + pw_r_len;
}

__kernel void r_markov (__global bf_t * restrict pws_buf_r, __global const cs_t * restrict root_css_buf, __global const cs_t * restrict markov_css_buf, const u64 off, const u32 pw_r_len, const u32 mask80, const u32 bits14, const u32 bits15, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf[64] = { 0 };

  generate_pw (pw_buf, root_css_buf, markov_css_buf, pw_r_len, 0, 0, 0, 0, off + gid);

  pws_buf_r[gid].i = pw_buf[0];
}

__kernel void C_markov (__global pw_t * restrict pws_buf, __global const cs_t * restrict root_css_buf, __global const cs_t * restrict markov_css_buf, const u64 off, const u32 pw_len, const u32 mask80, const u32 bits14, const u32 bits15, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf[64] = { 0 };

  generate_pw (pw_buf, root_css_buf, markov_css_buf, pw_len, 0, mask80, bits14, bits15, off + gid);

  #pragma unroll
  for (int idx = 0; idx < 64; idx++)
  {
    pws_buf[gid].i[idx] = pw_buf[idx];
  }

  pws_buf[gid].pw_len = pw_len;
}
