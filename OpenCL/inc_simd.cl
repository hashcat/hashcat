/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"

// attack-mode 0

DECLSPEC u32x ix_create_bft (CONSTANT_AS const bf_t *arr, const u32 il_pos)
{
  #if   VECT_SIZE == 1
  const u32x ix = make_u32x (arr[il_pos + 0].i);
  #elif VECT_SIZE == 2
  const u32x ix = make_u32x (arr[il_pos + 0].i, arr[il_pos + 1].i);
  #elif VECT_SIZE == 4
  const u32x ix = make_u32x (arr[il_pos + 0].i, arr[il_pos + 1].i, arr[il_pos + 2].i, arr[il_pos + 3].i);
  #elif VECT_SIZE == 8
  const u32x ix = make_u32x (arr[il_pos + 0].i, arr[il_pos + 1].i, arr[il_pos + 2].i, arr[il_pos + 3].i, arr[il_pos + 4].i, arr[il_pos + 5].i, arr[il_pos + 6].i, arr[il_pos + 7].i);
  #elif VECT_SIZE == 16
  const u32x ix = make_u32x (arr[il_pos + 0].i, arr[il_pos + 1].i, arr[il_pos + 2].i, arr[il_pos + 3].i, arr[il_pos + 4].i, arr[il_pos + 5].i, arr[il_pos + 6].i, arr[il_pos + 7].i, arr[il_pos + 8].i, arr[il_pos + 9].i, arr[il_pos + 10].i, arr[il_pos + 11].i, arr[il_pos + 12].i, arr[il_pos + 13].i, arr[il_pos + 14].i, arr[il_pos + 15].i);
  #endif

  return ix;
}

// attack-mode 1

DECLSPEC u32x pwlenx_create_combt (GLOBAL_AS const pw_t *arr, const u32 il_pos)
{
  #if   VECT_SIZE == 1
  const u32x pw_lenx = make_u32x (arr[il_pos + 0].pw_len);
  #elif VECT_SIZE == 2
  const u32x pw_lenx = make_u32x (arr[il_pos + 0].pw_len, arr[il_pos + 1].pw_len);
  #elif VECT_SIZE == 4
  const u32x pw_lenx = make_u32x (arr[il_pos + 0].pw_len, arr[il_pos + 1].pw_len, arr[il_pos + 2].pw_len, arr[il_pos + 3].pw_len);
  #elif VECT_SIZE == 8
  const u32x pw_lenx = make_u32x (arr[il_pos + 0].pw_len, arr[il_pos + 1].pw_len, arr[il_pos + 2].pw_len, arr[il_pos + 3].pw_len, arr[il_pos + 4].pw_len, arr[il_pos + 5].pw_len, arr[il_pos + 6].pw_len, arr[il_pos + 7].pw_len);
  #elif VECT_SIZE == 16
  const u32x pw_lenx = make_u32x (arr[il_pos + 0].pw_len, arr[il_pos + 1].pw_len, arr[il_pos + 2].pw_len, arr[il_pos + 3].pw_len, arr[il_pos + 4].pw_len, arr[il_pos + 5].pw_len, arr[il_pos + 6].pw_len, arr[il_pos + 7].pw_len, arr[il_pos + 8].pw_len, arr[il_pos + 9].pw_len, arr[il_pos + 10].pw_len, arr[il_pos + 11].pw_len, arr[il_pos + 12].pw_len, arr[il_pos + 13].pw_len, arr[il_pos + 14].pw_len, arr[il_pos + 15].pw_len);
  #endif

  return pw_lenx;
}

DECLSPEC u32x ix_create_combt (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int idx)
{
  #if   VECT_SIZE == 1
  const u32x ix = make_u32x (arr[il_pos + 0].i[idx]);
  #elif VECT_SIZE == 2
  const u32x ix = make_u32x (arr[il_pos + 0].i[idx], arr[il_pos + 1].i[idx]);
  #elif VECT_SIZE == 4
  const u32x ix = make_u32x (arr[il_pos + 0].i[idx], arr[il_pos + 1].i[idx], arr[il_pos + 2].i[idx], arr[il_pos + 3].i[idx]);
  #elif VECT_SIZE == 8
  const u32x ix = make_u32x (arr[il_pos + 0].i[idx], arr[il_pos + 1].i[idx], arr[il_pos + 2].i[idx], arr[il_pos + 3].i[idx], arr[il_pos + 4].i[idx], arr[il_pos + 5].i[idx], arr[il_pos + 6].i[idx], arr[il_pos + 7].i[idx]);
  #elif VECT_SIZE == 16
  const u32x ix = make_u32x (arr[il_pos + 0].i[idx], arr[il_pos + 1].i[idx], arr[il_pos + 2].i[idx], arr[il_pos + 3].i[idx], arr[il_pos + 4].i[idx], arr[il_pos + 5].i[idx], arr[il_pos + 6].i[idx], arr[il_pos + 7].i[idx], arr[il_pos + 8].i[idx], arr[il_pos + 9].i[idx], arr[il_pos + 10].i[idx], arr[il_pos + 11].i[idx], arr[il_pos + 12].i[idx], arr[il_pos + 13].i[idx], arr[il_pos + 14].i[idx], arr[il_pos + 15].i[idx]);
  #endif

  return ix;
}

// attack-mode 12

// The four pieces of one amplifier item sit next to each other, so a run of VECT_SIZE consecutive
// items is COMBS_PIECE_CNT apart rather than one apart. The pair above cannot say that, and it is
// left alone so that the attack modes which put one buffer per item keep the address arithmetic they
// have today.

DECLSPEC u32x pwlenx_create_combp (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int piece)
{
  #if   VECT_SIZE == 1
  const u32x pw_lenx = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].pw_len);
  #elif VECT_SIZE == 2
  const u32x pw_lenx = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].pw_len);
  #elif VECT_SIZE == 4
  const u32x pw_lenx = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].pw_len);
  #elif VECT_SIZE == 8
  const u32x pw_lenx = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 4) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 5) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 6) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 7) * COMBS_PIECE_CNT) + piece].pw_len);
  #elif VECT_SIZE == 16
  const u32x pw_lenx = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 4) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 5) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 6) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 7) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 8) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 9) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 10) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 11) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 12) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 13) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 14) * COMBS_PIECE_CNT) + piece].pw_len, arr[((il_pos + 15) * COMBS_PIECE_CNT) + piece].pw_len);
  #endif

  return pw_lenx;
}

DECLSPEC u32x ix_create_combp (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int idx, const int piece)
{
  #if   VECT_SIZE == 1
  const u32x ix = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].i[idx]);
  #elif VECT_SIZE == 2
  const u32x ix = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].i[idx]);
  #elif VECT_SIZE == 4
  const u32x ix = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].i[idx]);
  #elif VECT_SIZE == 8
  const u32x ix = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 4) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 5) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 6) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 7) * COMBS_PIECE_CNT) + piece].i[idx]);
  #elif VECT_SIZE == 16
  const u32x ix = make_u32x (arr[((il_pos + 0) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 1) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 2) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 3) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 4) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 5) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 6) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 7) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 8) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 9) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 10) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 11) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 12) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 13) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 14) * COMBS_PIECE_CNT) + piece].i[idx], arr[((il_pos + 15) * COMBS_PIECE_CNT) + piece].i[idx]);
  #endif

  return ix;
}

// One piece of a -a 12 amplifier item, moved into a register set. The three sizes are the three
// amplifier limits the optimized kernels work to. A kernel takes the same number of words it already
// takes for the single buffer, so -a 12 is capped exactly where -a 1 is capped in that kernel.

DECLSPEC void combs_piece4_VV (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int piece, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3)
{
  w0[0] = ix_create_combp (arr, il_pos, 0, piece);
  w0[1] = ix_create_combp (arr, il_pos, 1, piece);
  w0[2] = ix_create_combp (arr, il_pos, 2, piece);
  w0[3] = ix_create_combp (arr, il_pos, 3, piece);

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
}

DECLSPEC void combs_piece6_VV (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int piece, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3)
{
  w0[0] = ix_create_combp (arr, il_pos, 0, piece);
  w0[1] = ix_create_combp (arr, il_pos, 1, piece);
  w0[2] = ix_create_combp (arr, il_pos, 2, piece);
  w0[3] = ix_create_combp (arr, il_pos, 3, piece);
  w1[0] = ix_create_combp (arr, il_pos, 4, piece);
  w1[1] = ix_create_combp (arr, il_pos, 5, piece);

  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
}

DECLSPEC void combs_piece8_VV (GLOBAL_AS const pw_t *arr, const u32 il_pos, const int piece, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3)
{
  w0[0] = ix_create_combp (arr, il_pos, 0, piece);
  w0[1] = ix_create_combp (arr, il_pos, 1, piece);
  w0[2] = ix_create_combp (arr, il_pos, 2, piece);
  w0[3] = ix_create_combp (arr, il_pos, 3, piece);
  w1[0] = ix_create_combp (arr, il_pos, 4, piece);
  w1[1] = ix_create_combp (arr, il_pos, 5, piece);
  w1[2] = ix_create_combp (arr, il_pos, 6, piece);
  w1[3] = ix_create_combp (arr, il_pos, 7, piece);

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
}

// Everything one piece contributed, folded into the set that is accumulating the candidate.

DECLSPEC void combs_fold_VV (PRIVATE_AS u32x *wl0, PRIVATE_AS u32x *wl1, PRIVATE_AS u32x *wl2, PRIVATE_AS u32x *wl3, PRIVATE_AS const u32x *wr0, PRIVATE_AS const u32x *wr1, PRIVATE_AS const u32x *wr2, PRIVATE_AS const u32x *wr3)
{
  wl0[0] |= wr0[0];
  wl0[1] |= wr0[1];
  wl0[2] |= wr0[2];
  wl0[3] |= wr0[3];
  wl1[0] |= wr1[0];
  wl1[1] |= wr1[1];
  wl1[2] |= wr1[2];
  wl1[3] |= wr1[3];
  wl2[0] |= wr2[0];
  wl2[1] |= wr2[1];
  wl2[2] |= wr2[2];
  wl2[3] |= wr2[3];
  wl3[0] |= wr3[0];
  wl3[1] |= wr3[1];
  wl3[2] |= wr3[2];
  wl3[3] |= wr3[3];
}

// The length of the whole amplifier, which is what the candidate length is built from. The order the
// pieces go in does not matter to a length, so a kernel that adds this to the base word length needs
// no other change.

DECLSPEC u32x pwlenx_create_combsum (GLOBAL_AS const pw_t *arr, const u32 il_pos)
{
  const u32x pre  = pwlenx_create_combp (arr, il_pos, COMBS_PIECE_PRE);
  const u32x mid  = pwlenx_create_combp (arr, il_pos, COMBS_PIECE_MID);
  const u32x word = pwlenx_create_combp (arr, il_pos, COMBS_PIECE_WORD);
  const u32x post = pwlenx_create_combp (arr, il_pos, COMBS_PIECE_POST);

  const u32x sum = pre + mid + word + post;

  return sum;
}
