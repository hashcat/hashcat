/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_simd.h"

// attack-mode 0

DECLSPEC u32x ix_create_bft (GLOBAL_AS const bf_t *bfs_buf, const u32 il_pos)
{
  #if   VECT_SIZE == 1
  const u32x ix = (u32x) (bfs_buf[il_pos + 0].i);
  #elif VECT_SIZE == 2
  const u32x ix = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i);
  #elif VECT_SIZE == 4
  const u32x ix = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i, bfs_buf[il_pos + 2].i, bfs_buf[il_pos + 3].i);
  #elif VECT_SIZE == 8
  const u32x ix = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i, bfs_buf[il_pos + 2].i, bfs_buf[il_pos + 3].i, bfs_buf[il_pos + 4].i, bfs_buf[il_pos + 5].i, bfs_buf[il_pos + 6].i, bfs_buf[il_pos + 7].i);
  #elif VECT_SIZE == 16
  const u32x ix = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i, bfs_buf[il_pos + 2].i, bfs_buf[il_pos + 3].i, bfs_buf[il_pos + 4].i, bfs_buf[il_pos + 5].i, bfs_buf[il_pos + 6].i, bfs_buf[il_pos + 7].i, bfs_buf[il_pos + 8].i, bfs_buf[il_pos + 9].i, bfs_buf[il_pos + 10].i, bfs_buf[il_pos + 11].i, bfs_buf[il_pos + 12].i, bfs_buf[il_pos + 13].i, bfs_buf[il_pos + 14].i, bfs_buf[il_pos + 15].i);
  #endif

  return ix;
}

// attack-mode 1

DECLSPEC u32x pwlenx_create_combt (GLOBAL_AS const pw_t *combs_buf, const u32 il_pos)
{
  #if   VECT_SIZE == 1
  const u32x pw_lenx = (u32x) (combs_buf[il_pos + 0].pw_len);
  #elif VECT_SIZE == 2
  const u32x pw_lenx = (u32x) (combs_buf[il_pos + 0].pw_len, combs_buf[il_pos + 1].pw_len);
  #elif VECT_SIZE == 4
  const u32x pw_lenx = (u32x) (combs_buf[il_pos + 0].pw_len, combs_buf[il_pos + 1].pw_len, combs_buf[il_pos + 2].pw_len, combs_buf[il_pos + 3].pw_len);
  #elif VECT_SIZE == 8
  const u32x pw_lenx = (u32x) (combs_buf[il_pos + 0].pw_len, combs_buf[il_pos + 1].pw_len, combs_buf[il_pos + 2].pw_len, combs_buf[il_pos + 3].pw_len, combs_buf[il_pos + 4].pw_len, combs_buf[il_pos + 5].pw_len, combs_buf[il_pos + 6].pw_len, combs_buf[il_pos + 7].pw_len);
  #elif VECT_SIZE == 16
  const u32x pw_lenx = (u32x) (combs_buf[il_pos + 0].pw_len, combs_buf[il_pos + 1].pw_len, combs_buf[il_pos + 2].pw_len, combs_buf[il_pos + 3].pw_len, combs_buf[il_pos + 4].pw_len, combs_buf[il_pos + 5].pw_len, combs_buf[il_pos + 6].pw_len, combs_buf[il_pos + 7].pw_len, combs_buf[il_pos + 8].pw_len, combs_buf[il_pos + 9].pw_len, combs_buf[il_pos + 10].pw_len, combs_buf[il_pos + 11].pw_len, combs_buf[il_pos + 12].pw_len, combs_buf[il_pos + 13].pw_len, combs_buf[il_pos + 14].pw_len, combs_buf[il_pos + 15].pw_len);
  #endif

  return pw_lenx;
}

DECLSPEC u32x ix_create_combt (GLOBAL_AS const pw_t *combs_buf, const u32 il_pos, const int idx)
{
  #if   VECT_SIZE == 1
  const u32x ix = (u32x) (combs_buf[il_pos + 0].i[idx]);
  #elif VECT_SIZE == 2
  const u32x ix = (u32x) (combs_buf[il_pos + 0].i[idx], combs_buf[il_pos + 1].i[idx]);
  #elif VECT_SIZE == 4
  const u32x ix = (u32x) (combs_buf[il_pos + 0].i[idx], combs_buf[il_pos + 1].i[idx], combs_buf[il_pos + 2].i[idx], combs_buf[il_pos + 3].i[idx]);
  #elif VECT_SIZE == 8
  const u32x ix = (u32x) (combs_buf[il_pos + 0].i[idx], combs_buf[il_pos + 1].i[idx], combs_buf[il_pos + 2].i[idx], combs_buf[il_pos + 3].i[idx], combs_buf[il_pos + 4].i[idx], combs_buf[il_pos + 5].i[idx], combs_buf[il_pos + 6].i[idx], combs_buf[il_pos + 7].i[idx]);
  #elif VECT_SIZE == 16
  const u32x ix = (u32x) (combs_buf[il_pos + 0].i[idx], combs_buf[il_pos + 1].i[idx], combs_buf[il_pos + 2].i[idx], combs_buf[il_pos + 3].i[idx], combs_buf[il_pos + 4].i[idx], combs_buf[il_pos + 5].i[idx], combs_buf[il_pos + 6].i[idx], combs_buf[il_pos + 7].i[idx], combs_buf[il_pos + 8].i[idx], combs_buf[il_pos + 9].i[idx], combs_buf[il_pos + 10].i[idx], combs_buf[il_pos + 11].i[idx], combs_buf[il_pos + 12].i[idx], combs_buf[il_pos + 13].i[idx], combs_buf[il_pos + 14].i[idx], combs_buf[il_pos + 15].i[idx]);
  #endif

  return ix;
}
