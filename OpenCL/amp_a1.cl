/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_amp.h)
#endif

KERNEL_FQ void amp (KERN_ATTR_AMP)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw = pws_amp[gid];

  pw_t comb = combs_buf[0];

  const u32 pw_len = pw.pw_len;

  const u32 comb_len = comb.pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
  {
    switch_buffer_by_offset_1x64_le_S (comb.i, pw_len);
  }

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset_1x64_le_S (pw.i, comb_len);
  }

  pw.i[ 0] |= comb.i[ 0];
  pw.i[ 1] |= comb.i[ 1];
  pw.i[ 2] |= comb.i[ 2];
  pw.i[ 3] |= comb.i[ 3];
  pw.i[ 4] |= comb.i[ 4];
  pw.i[ 5] |= comb.i[ 5];
  pw.i[ 6] |= comb.i[ 6];
  pw.i[ 7] |= comb.i[ 7];
  pw.i[ 8] |= comb.i[ 8];
  pw.i[ 9] |= comb.i[ 9];
  pw.i[10] |= comb.i[10];
  pw.i[11] |= comb.i[11];
  pw.i[12] |= comb.i[12];
  pw.i[13] |= comb.i[13];
  pw.i[14] |= comb.i[14];
  pw.i[15] |= comb.i[15];
  pw.i[16] |= comb.i[16];
  pw.i[17] |= comb.i[17];
  pw.i[18] |= comb.i[18];
  pw.i[19] |= comb.i[19];
  pw.i[20] |= comb.i[20];
  pw.i[21] |= comb.i[21];
  pw.i[22] |= comb.i[22];
  pw.i[23] |= comb.i[23];
  pw.i[24] |= comb.i[24];
  pw.i[25] |= comb.i[25];
  pw.i[26] |= comb.i[26];
  pw.i[27] |= comb.i[27];
  pw.i[28] |= comb.i[28];
  pw.i[29] |= comb.i[29];
  pw.i[30] |= comb.i[30];
  pw.i[31] |= comb.i[31];
  pw.i[32] |= comb.i[32];
  pw.i[33] |= comb.i[33];
  pw.i[34] |= comb.i[34];
  pw.i[35] |= comb.i[35];
  pw.i[36] |= comb.i[36];
  pw.i[37] |= comb.i[37];
  pw.i[38] |= comb.i[38];
  pw.i[39] |= comb.i[39];
  pw.i[40] |= comb.i[40];
  pw.i[41] |= comb.i[41];
  pw.i[42] |= comb.i[42];
  pw.i[43] |= comb.i[43];
  pw.i[44] |= comb.i[44];
  pw.i[45] |= comb.i[45];
  pw.i[46] |= comb.i[46];
  pw.i[47] |= comb.i[47];
  pw.i[48] |= comb.i[48];
  pw.i[49] |= comb.i[49];
  pw.i[50] |= comb.i[50];
  pw.i[51] |= comb.i[51];
  pw.i[52] |= comb.i[52];
  pw.i[53] |= comb.i[53];
  pw.i[54] |= comb.i[54];
  pw.i[55] |= comb.i[55];
  pw.i[56] |= comb.i[56];
  pw.i[57] |= comb.i[57];
  pw.i[58] |= comb.i[58];
  pw.i[59] |= comb.i[59];
  pw.i[60] |= comb.i[60];
  pw.i[61] |= comb.i[61];
  pw.i[62] |= comb.i[62];
  pw.i[63] |= comb.i[63];

  pw.pw_len = pw_len + comb_len;

  pws[gid] = pw;
}
