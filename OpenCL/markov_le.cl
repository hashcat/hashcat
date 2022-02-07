/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_markov.h)
#endif

#define CHARSIZ 256

DECLSPEC void generate_pw (PRIVATE_AS u32 *pw_buf, GLOBAL_AS const cs_t *root_css_buf, GLOBAL_AS const cs_t *markov_css_buf, const u32 pw_l_len, const u32 pw_r_len, const u32 mask80, const u32 bits14, const u32 bits15, u64 val)
{
  GLOBAL_AS const cs_t *cs = &root_css_buf[pw_r_len];

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

KERNEL_FQ void l_markov (KERN_ATTR_L_MARKOV)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw;

  pw.i[ 0] = 0;
  pw.i[ 1] = 0;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0;

  pw.pw_len = pw_l_len + pw_r_len;

  generate_pw (pw.i, root_css_buf, markov_css_buf, pw_l_len, pw_r_len, mask80, bits14, bits15, off + gid);

  pws_buf_l[gid] = pw;
}

KERNEL_FQ void r_markov (KERN_ATTR_R_MARKOV)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw;

  pw.i[ 0] = 0;
  pw.i[ 1] = 0;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0;

  generate_pw (pw.i, root_css_buf, markov_css_buf, pw_r_len, 0, 0, 0, 0, off + gid);

  pws_buf_r[gid].i = pw.i[0];
}

KERNEL_FQ void C_markov (KERN_ATTR_C_MARKOV)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw;

  pw.i[ 0] = 0;
  pw.i[ 1] = 0;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0;

  pw.pw_len = pw_len;

  generate_pw (pw.i, root_css_buf, markov_css_buf, pw_len, 0, mask80, bits14, bits15, off + gid);

  pws_buf[gid] = pw;
}
