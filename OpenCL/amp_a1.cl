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

KERNEL_FQ KERNEL_FA void amp (KERN_ATTR_AMP)
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

    pw.pw_len = pw_len + comb_len;
  }

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset_1x64_le_S (pw.i, comb_len);

    pw.pw_len = pw_len + comb_len;
  }

  // The base word sits inside the amplifier rather than beside it. Four pieces arrive in a fixed
  // order: the mask in front of the base word, the mask between the two words, the second word, and
  // the mask behind the last word. Any of them may be empty, and a mask with no ?q always has the
  // middle two empty, which is what makes ?w?d?d cost what it did before ?q existed.
  //
  // Each piece is moved to where it starts and then ORed in. Nothing has to be masked off on the way,
  // because a buffer is already zero outside its own bytes, and the piece in front never moves at all
  // because it starts the candidate.

  if (combs_mode == COMBINATOR_MODE_BASE_MIDDLE)
  {
    pw_t pre  = comb;
    pw_t mid  = combs_buf[1];
    pw_t word = combs_buf[2];

    comb = combs_buf[3];

    const u32 mid_off  = pre.pw_len + pw_len;
    const u32 word_off = mid_off + mid.pw_len;
    const u32 post_off = word_off + word.pw_len;

    switch_buffer_by_offset_1x64_le_S (pw.i,   pre.pw_len);
    switch_buffer_by_offset_1x64_le_S (mid.i,  mid_off);
    switch_buffer_by_offset_1x64_le_S (word.i, word_off);
    switch_buffer_by_offset_1x64_le_S (comb.i, post_off);

    pw.i[ 0] |= pre.i[ 0] | mid.i[ 0] | word.i[ 0];
    pw.i[ 1] |= pre.i[ 1] | mid.i[ 1] | word.i[ 1];
    pw.i[ 2] |= pre.i[ 2] | mid.i[ 2] | word.i[ 2];
    pw.i[ 3] |= pre.i[ 3] | mid.i[ 3] | word.i[ 3];
    pw.i[ 4] |= pre.i[ 4] | mid.i[ 4] | word.i[ 4];
    pw.i[ 5] |= pre.i[ 5] | mid.i[ 5] | word.i[ 5];
    pw.i[ 6] |= pre.i[ 6] | mid.i[ 6] | word.i[ 6];
    pw.i[ 7] |= pre.i[ 7] | mid.i[ 7] | word.i[ 7];
    pw.i[ 8] |= pre.i[ 8] | mid.i[ 8] | word.i[ 8];
    pw.i[ 9] |= pre.i[ 9] | mid.i[ 9] | word.i[ 9];
    pw.i[10] |= pre.i[10] | mid.i[10] | word.i[10];
    pw.i[11] |= pre.i[11] | mid.i[11] | word.i[11];
    pw.i[12] |= pre.i[12] | mid.i[12] | word.i[12];
    pw.i[13] |= pre.i[13] | mid.i[13] | word.i[13];
    pw.i[14] |= pre.i[14] | mid.i[14] | word.i[14];
    pw.i[15] |= pre.i[15] | mid.i[15] | word.i[15];
    pw.i[16] |= pre.i[16] | mid.i[16] | word.i[16];
    pw.i[17] |= pre.i[17] | mid.i[17] | word.i[17];
    pw.i[18] |= pre.i[18] | mid.i[18] | word.i[18];
    pw.i[19] |= pre.i[19] | mid.i[19] | word.i[19];
    pw.i[20] |= pre.i[20] | mid.i[20] | word.i[20];
    pw.i[21] |= pre.i[21] | mid.i[21] | word.i[21];
    pw.i[22] |= pre.i[22] | mid.i[22] | word.i[22];
    pw.i[23] |= pre.i[23] | mid.i[23] | word.i[23];
    pw.i[24] |= pre.i[24] | mid.i[24] | word.i[24];
    pw.i[25] |= pre.i[25] | mid.i[25] | word.i[25];
    pw.i[26] |= pre.i[26] | mid.i[26] | word.i[26];
    pw.i[27] |= pre.i[27] | mid.i[27] | word.i[27];
    pw.i[28] |= pre.i[28] | mid.i[28] | word.i[28];
    pw.i[29] |= pre.i[29] | mid.i[29] | word.i[29];
    pw.i[30] |= pre.i[30] | mid.i[30] | word.i[30];
    pw.i[31] |= pre.i[31] | mid.i[31] | word.i[31];
    pw.i[32] |= pre.i[32] | mid.i[32] | word.i[32];
    pw.i[33] |= pre.i[33] | mid.i[33] | word.i[33];
    pw.i[34] |= pre.i[34] | mid.i[34] | word.i[34];
    pw.i[35] |= pre.i[35] | mid.i[35] | word.i[35];
    pw.i[36] |= pre.i[36] | mid.i[36] | word.i[36];
    pw.i[37] |= pre.i[37] | mid.i[37] | word.i[37];
    pw.i[38] |= pre.i[38] | mid.i[38] | word.i[38];
    pw.i[39] |= pre.i[39] | mid.i[39] | word.i[39];
    pw.i[40] |= pre.i[40] | mid.i[40] | word.i[40];
    pw.i[41] |= pre.i[41] | mid.i[41] | word.i[41];
    pw.i[42] |= pre.i[42] | mid.i[42] | word.i[42];
    pw.i[43] |= pre.i[43] | mid.i[43] | word.i[43];
    pw.i[44] |= pre.i[44] | mid.i[44] | word.i[44];
    pw.i[45] |= pre.i[45] | mid.i[45] | word.i[45];
    pw.i[46] |= pre.i[46] | mid.i[46] | word.i[46];
    pw.i[47] |= pre.i[47] | mid.i[47] | word.i[47];
    pw.i[48] |= pre.i[48] | mid.i[48] | word.i[48];
    pw.i[49] |= pre.i[49] | mid.i[49] | word.i[49];
    pw.i[50] |= pre.i[50] | mid.i[50] | word.i[50];
    pw.i[51] |= pre.i[51] | mid.i[51] | word.i[51];
    pw.i[52] |= pre.i[52] | mid.i[52] | word.i[52];
    pw.i[53] |= pre.i[53] | mid.i[53] | word.i[53];
    pw.i[54] |= pre.i[54] | mid.i[54] | word.i[54];
    pw.i[55] |= pre.i[55] | mid.i[55] | word.i[55];
    pw.i[56] |= pre.i[56] | mid.i[56] | word.i[56];
    pw.i[57] |= pre.i[57] | mid.i[57] | word.i[57];
    pw.i[58] |= pre.i[58] | mid.i[58] | word.i[58];
    pw.i[59] |= pre.i[59] | mid.i[59] | word.i[59];
    pw.i[60] |= pre.i[60] | mid.i[60] | word.i[60];
    pw.i[61] |= pre.i[61] | mid.i[61] | word.i[61];
    pw.i[62] |= pre.i[62] | mid.i[62] | word.i[62];
    pw.i[63] |= pre.i[63] | mid.i[63] | word.i[63];

    pw.pw_len = post_off + comb.pw_len;
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

  pws[gid] = pw;
}
