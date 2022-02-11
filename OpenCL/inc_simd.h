/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_SIMD_H
#define _INC_SIMD_H

// vliw1

#if VECT_SIZE == 1

#define MATCHES_ONE_VV(a,b) ((a) == (b))
#define MATCHES_ONE_VS(a,b) ((a) == (b))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0) == search[0]) && ((h1) == search[1]) && ((h2) == search[2]) && ((h3) == search[3]))             \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  const u32 digest_tp0[4] = { h0, h1, h2, h3 };                                                             \
                                                                                                            \
  if (check (digest_tp0,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw2

#define vector_accessible(p,c,e) (((p) + (e)) < (c))

#if VECT_SIZE == 2

#define MATCHES_ONE_VV(a,b) (((a).s0 == (b).s0) || ((a).s1 == (b).s1))
#define MATCHES_ONE_VS(a,b) (((a).s0 == (b)   ) || ((a).s1 == (b)   ))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0).s0 == search[0]) && ((h1).s0 == search[1]) && ((h2).s0 == search[2]) && ((h3).s0 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 0, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 1, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  const u32 digest_tp0[4] = { h0.s0, h1.s0, h2.s0, h3.s0 };                                                 \
  const u32 digest_tp1[4] = { h0.s1, h1.s1, h2.s1, h3.s1 };                                                 \
                                                                                                            \
  if (check (digest_tp0,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 0, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp1, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 1, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw4

#if VECT_SIZE == 4

#define MATCHES_ONE_VV(a,b) (((a).s0 == (b).s0) || ((a).s1 == (b).s1) || ((a).s2 == (b).s2) || ((a).s3 == (b).s3))
#define MATCHES_ONE_VS(a,b) (((a).s0 == (b)   ) || ((a).s1 == (b)   ) || ((a).s2 == (b)   ) || ((a).s3 == (b)   ))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0).s0 == search[0]) && ((h1).s0 == search[1]) && ((h2).s0 == search[2]) && ((h3).s0 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 0, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 1, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s2 == search[0]) && ((h1).s2 == search[1]) && ((h2).s2 == search[2]) && ((h3).s2 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 2, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s3 == search[0]) && ((h1).s3 == search[1]) && ((h2).s3 == search[2]) && ((h3).s3 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 3, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  const u32 digest_tp0[4] = { h0.s0, h1.s0, h2.s0, h3.s0 };                                                 \
  const u32 digest_tp1[4] = { h0.s1, h1.s1, h2.s1, h3.s1 };                                                 \
  const u32 digest_tp2[4] = { h0.s2, h1.s2, h2.s2, h3.s2 };                                                 \
  const u32 digest_tp3[4] = { h0.s3, h1.s3, h2.s3, h3.s3 };                                                 \
                                                                                                            \
  if (check (digest_tp0,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 0, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp1, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 1, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp2,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp2, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 2, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp3,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp3, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 3, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw8

#if VECT_SIZE == 8

#define MATCHES_ONE_VV(a,b) (((a).s0 == (b).s0) || ((a).s1 == (b).s1) || ((a).s2 == (b).s2) || ((a).s3 == (b).s3) || ((a).s4 == (b).s4) || ((a).s5 == (b).s5) || ((a).s6 == (b).s6) || ((a).s7 == (b).s7))
#define MATCHES_ONE_VS(a,b) (((a).s0 == (b)   ) || ((a).s1 == (b)   ) || ((a).s2 == (b)   ) || ((a).s3 == (b)   ) || ((a).s4 == (b)   ) || ((a).s5 == (b)   ) || ((a).s6 == (b)   ) || ((a).s7 == (b)   ))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0).s0 == search[0]) && ((h1).s0 == search[1]) && ((h2).s0 == search[2]) && ((h3).s0 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 0, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 1, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s2 == search[0]) && ((h1).s2 == search[1]) && ((h2).s2 == search[2]) && ((h3).s2 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 2, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s3 == search[0]) && ((h1).s3 == search[1]) && ((h2).s3 == search[2]) && ((h3).s3 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 3, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
  if (((h0).s4 == search[0]) && ((h1).s4 == search[1]) && ((h2).s4 == search[2]) && ((h3).s4 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 4) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 4, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s5 == search[0]) && ((h1).s5 == search[1]) && ((h2).s5 == search[2]) && ((h3).s5 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 5) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 5, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s6 == search[0]) && ((h1).s6 == search[1]) && ((h2).s6 == search[2]) && ((h3).s6 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 6) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 6, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s7 == search[0]) && ((h1).s7 == search[1]) && ((h2).s7 == search[2]) && ((h3).s7 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 7) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 7, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  const u32 digest_tp0[4] = { h0.s0, h1.s0, h2.s0, h3.s0 };                                                 \
  const u32 digest_tp1[4] = { h0.s1, h1.s1, h2.s1, h3.s1 };                                                 \
  const u32 digest_tp2[4] = { h0.s2, h1.s2, h2.s2, h3.s2 };                                                 \
  const u32 digest_tp3[4] = { h0.s3, h1.s3, h2.s3, h3.s3 };                                                 \
  const u32 digest_tp4[4] = { h0.s4, h1.s4, h2.s4, h3.s4 };                                                 \
  const u32 digest_tp5[4] = { h0.s5, h1.s5, h2.s5, h3.s5 };                                                 \
  const u32 digest_tp6[4] = { h0.s6, h1.s6, h2.s6, h3.s6 };                                                 \
  const u32 digest_tp7[4] = { h0.s7, h1.s7, h2.s7, h3.s7 };                                                 \
                                                                                                            \
  if (check (digest_tp0,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 0, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp1, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 1, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp2,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp2, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 2, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp3,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp3, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 3, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
  if (check (digest_tp4,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp4, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 4) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 4, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp5,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp5, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 5) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 5, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp6,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp6, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 6) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 6, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp7,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp7, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 7) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 7, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw16

#if VECT_SIZE == 16

#define MATCHES_ONE_VV(a,b) (((a).s0 == (b).s0) || ((a).s1 == (b).s1) || ((a).s2 == (b).s2) || ((a).s3 == (b).s3) || ((a).s4 == (b).s4) || ((a).s5 == (b).s5) || ((a).s6 == (b).s6) || ((a).s7 == (b).s7) || ((a).s8 == (b).s8) || ((a).s9 == (b).s9) || ((a).sa == (b).sa) || ((a).sb == (b).sb) || ((a).sc == (b).sc) || ((a).sd == (b).sd) || ((a).se == (b).se) || ((a).sf == (b).sf))
#define MATCHES_ONE_VS(a,b) (((a).s0 == (b)   ) || ((a).s1 == (b)   ) || ((a).s2 == (b)   ) || ((a).s3 == (b)   ) || ((a).s4 == (b)   ) || ((a).s5 == (b)   ) || ((a).s6 == (b)   ) || ((a).s7 == (b)   ) || ((a).s8 == (b)   ) || ((a).s9 == (b)   ) || ((a).sa == (b)   ) || ((a).sb == (b)   ) || ((a).sc == (b)   ) || ((a).sd == (b)   ) || ((a).se == (b)   ) || ((a).sf == (b)   ))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0).s0 == search[0]) && ((h1).s0 == search[1]) && ((h2).s0 == search[2]) && ((h3).s0 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 0, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 1, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s2 == search[0]) && ((h1).s2 == search[1]) && ((h2).s2 == search[2]) && ((h3).s2 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 2, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s3 == search[0]) && ((h1).s3 == search[1]) && ((h2).s3 == search[2]) && ((h3).s3 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 3, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
  if (((h0).s4 == search[0]) && ((h1).s4 == search[1]) && ((h2).s4 == search[2]) && ((h3).s4 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 4) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 4, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s5 == search[0]) && ((h1).s5 == search[1]) && ((h2).s5 == search[2]) && ((h3).s5 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 5) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 5, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s6 == search[0]) && ((h1).s6 == search[1]) && ((h2).s6 == search[2]) && ((h3).s6 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 6) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 6, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s7 == search[0]) && ((h1).s7 == search[1]) && ((h2).s7 == search[2]) && ((h3).s7 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 7) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 7, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s8 == search[0]) && ((h1).s8 == search[1]) && ((h2).s8 == search[2]) && ((h3).s8 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 8) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 8, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s9 == search[0]) && ((h1).s9 == search[1]) && ((h2).s9 == search[2]) && ((h3).s9 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 9) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))      \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 9, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).sa == search[0]) && ((h1).sa == search[1]) && ((h2).sa == search[2]) && ((h3).sa == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 10) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 10, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).sb == search[0]) && ((h1).sb == search[1]) && ((h2).sb == search[2]) && ((h3).sb == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 11) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 11, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).sc == search[0]) && ((h1).sc == search[1]) && ((h2).sc == search[2]) && ((h3).sc == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 12) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 12, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).sd == search[0]) && ((h1).sd == search[1]) && ((h2).sd == search[2]) && ((h3).sd == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 13) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 13, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).se == search[0]) && ((h1).se == search[1]) && ((h2).se == search[2]) && ((h3).se == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 14) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 14, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).sf == search[0]) && ((h1).sf == search[1]) && ((h2).sf == search[2]) && ((h3).sf == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (vector_accessible (il_pos, IL_CNT, 15) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))     \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + 15, 0, 0); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  const u32 digest_tp00[4] = { h0.s0, h1.s0, h2.s0, h3.s0 };                                                \
  const u32 digest_tp01[4] = { h0.s1, h1.s1, h2.s1, h3.s1 };                                                \
  const u32 digest_tp02[4] = { h0.s2, h1.s2, h2.s2, h3.s2 };                                                \
  const u32 digest_tp03[4] = { h0.s3, h1.s3, h2.s3, h3.s3 };                                                \
  const u32 digest_tp04[4] = { h0.s4, h1.s4, h2.s4, h3.s4 };                                                \
  const u32 digest_tp05[4] = { h0.s5, h1.s5, h2.s5, h3.s5 };                                                \
  const u32 digest_tp06[4] = { h0.s6, h1.s6, h2.s6, h3.s6 };                                                \
  const u32 digest_tp07[4] = { h0.s7, h1.s7, h2.s7, h3.s7 };                                                \
  const u32 digest_tp08[4] = { h0.s8, h1.s8, h2.s8, h3.s8 };                                                \
  const u32 digest_tp09[4] = { h0.s9, h1.s9, h2.s9, h3.s9 };                                                \
  const u32 digest_tp10[4] = { h0.sa, h1.sa, h2.sa, h3.sa };                                                \
  const u32 digest_tp11[4] = { h0.sb, h1.sb, h2.sb, h3.sb };                                                \
  const u32 digest_tp12[4] = { h0.sc, h1.sc, h2.sc, h3.sc };                                                \
  const u32 digest_tp13[4] = { h0.sd, h1.sd, h2.sd, h3.sd };                                                \
  const u32 digest_tp14[4] = { h0.se, h1.se, h2.se, h3.se };                                                \
  const u32 digest_tp15[4] = { h0.sf, h1.sf, h2.sf, h3.sf };                                                \
                                                                                                            \
  if (check (digest_tp00,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp00, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 0) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 0, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp01,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp01, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 1) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 1, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp02,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp02, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 2) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 2, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp03,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp03, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 3) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 3, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp04,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp04, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 4) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 4, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp05,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp05, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 5) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 5, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp06,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp06, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 6) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 6, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp07,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp07, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 7) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 7, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp08,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp08, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 8) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 8, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp09,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp09, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 9) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))    \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 9, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp10,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp10, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 10) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 10, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp11,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp11, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 11) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 11, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp12,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp12, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 12) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 12, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp13,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp13, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 13) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 13, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp14,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp14, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 14) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 14, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp15,                                                                                   \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK,                                                                                   \
             BITMAP_SHIFT1,                                                                                 \
             BITMAP_SHIFT2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp15, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);               \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (vector_accessible (il_pos, IL_CNT, 15) && (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0))   \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos + 15, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

#define MATCHES_NONE_VV(a,b) !(MATCHES_ONE_VV ((a), (b)))
#define MATCHES_NONE_VS(a,b) !(MATCHES_ONE_VS ((a), (b)))

#if   VECT_SIZE == 1
#define pack(arr,var,gid,idx) make_u32x ((arr)[((gid) *  1) + 0].var)
#elif VECT_SIZE == 2
#define pack(arr,var,gid,idx) make_u32x ((arr)[((gid) *  2) + 0].var, (arr)[((gid) *  2) + 1].var)
#elif VECT_SIZE == 4
#define pack(arr,var,gid,idx) make_u32x ((arr)[((gid) *  4) + 0].var, (arr)[((gid) *  4) + 1].var, (arr)[((gid) *  4) + 2].var, (arr)[((gid) *  4) + 3].var)
#elif VECT_SIZE == 8
#define pack(arr,var,gid,idx) make_u32x ((arr)[((gid) *  8) + 0].var, (arr)[((gid) *  8) + 1].var, (arr)[((gid) *  8) + 2].var, (arr)[((gid) *  8) + 3].var, (arr)[((gid) *  8) + 4].var, (arr)[((gid) *  8) + 5].var, (arr)[((gid) *  8) + 6].var, (arr)[((gid) *  8) + 7].var)
#elif VECT_SIZE == 16
#define pack(arr,var,gid,idx) make_u32x ((arr)[((gid) * 16) + 0].var, (arr)[((gid) * 16) + 1].var, (arr)[((gid) * 16) + 2].var, (arr)[((gid) * 16) + 3].var, (arr)[((gid) * 16) + 4].var, (arr)[((gid) * 16) + 5].var, (arr)[((gid) * 16) + 6].var, (arr)[((gid) * 16) + 7].var, (arr)[((gid) * 16) + 8].var, (arr)[((gid) * 16) + 9].var, (arr)[((gid) * 16) + 10].var, (arr)[((gid) * 16) + 11].var, (arr)[((gid) * 16) + 12].var, (arr)[((gid) * 16) + 13].var, (arr)[((gid) * 16) + 14].var, (arr)[((gid) * 16) + 15].var)
#endif

#if   VECT_SIZE == 1
#define packv(arr,var,gid,idx) make_u32x ((arr)[((gid) *  1) + 0].var[(idx)])
#elif VECT_SIZE == 2
#define packv(arr,var,gid,idx) make_u32x ((arr)[((gid) *  2) + 0].var[(idx)], (arr)[((gid) *  2) + 1].var[(idx)])
#elif VECT_SIZE == 4
#define packv(arr,var,gid,idx) make_u32x ((arr)[((gid) *  4) + 0].var[(idx)], (arr)[((gid) *  4) + 1].var[(idx)], (arr)[((gid) *  4) + 2].var[(idx)], (arr)[((gid) *  4) + 3].var[(idx)])
#elif VECT_SIZE == 8
#define packv(arr,var,gid,idx) make_u32x ((arr)[((gid) *  8) + 0].var[(idx)], (arr)[((gid) *  8) + 1].var[(idx)], (arr)[((gid) *  8) + 2].var[(idx)], (arr)[((gid) *  8) + 3].var[(idx)], (arr)[((gid) *  8) + 4].var[(idx)], (arr)[((gid) *  8) + 5].var[(idx)], (arr)[((gid) *  8) + 6].var[(idx)], (arr)[((gid) *  8) + 7].var[(idx)])
#elif VECT_SIZE == 16
#define packv(arr,var,gid,idx) make_u32x ((arr)[((gid) * 16) + 0].var[(idx)], (arr)[((gid) * 16) + 1].var[(idx)], (arr)[((gid) * 16) + 2].var[(idx)], (arr)[((gid) * 16) + 3].var[(idx)], (arr)[((gid) * 16) + 4].var[(idx)], (arr)[((gid) * 16) + 5].var[(idx)], (arr)[((gid) * 16) + 6].var[(idx)], (arr)[((gid) * 16) + 7].var[(idx)], (arr)[((gid) * 16) + 8].var[(idx)], (arr)[((gid) * 16) + 9].var[(idx)], (arr)[((gid) * 16) + 10].var[(idx)], (arr)[((gid) * 16) + 11].var[(idx)], (arr)[((gid) * 16) + 12].var[(idx)], (arr)[((gid) * 16) + 13].var[(idx)], (arr)[((gid) * 16) + 14].var[(idx)], (arr)[((gid) * 16) + 15].var[(idx)])
#endif

#if   VECT_SIZE == 1
#define pack64v(arr,var,gid,idx) make_u64x ((arr)[((gid) *  1) + 0].var[(idx)])
#elif VECT_SIZE == 2
#define pack64v(arr,var,gid,idx) make_u64x ((arr)[((gid) *  2) + 0].var[(idx)], (arr)[((gid) *  2) + 1].var[(idx)])
#elif VECT_SIZE == 4
#define pack64v(arr,var,gid,idx) make_u64x ((arr)[((gid) *  4) + 0].var[(idx)], (arr)[((gid) *  4) + 1].var[(idx)], (arr)[((gid) *  4) + 2].var[(idx)], (arr)[((gid) *  4) + 3].var[(idx)])
#elif VECT_SIZE == 8
#define pack64v(arr,var,gid,idx) make_u64x ((arr)[((gid) *  8) + 0].var[(idx)], (arr)[((gid) *  8) + 1].var[(idx)], (arr)[((gid) *  8) + 2].var[(idx)], (arr)[((gid) *  8) + 3].var[(idx)], (arr)[((gid) *  8) + 4].var[(idx)], (arr)[((gid) *  8) + 5].var[(idx)], (arr)[((gid) *  8) + 6].var[(idx)], (arr)[((gid) *  8) + 7].var[(idx)])
#elif VECT_SIZE == 16
#define pack64v(arr,var,gid,idx) make_u64x ((arr)[((gid) * 16) + 0].var[(idx)], (arr)[((gid) * 16) + 1].var[(idx)], (arr)[((gid) * 16) + 2].var[(idx)], (arr)[((gid) * 16) + 3].var[(idx)], (arr)[((gid) * 16) + 4].var[(idx)], (arr)[((gid) * 16) + 5].var[(idx)], (arr)[((gid) * 16) + 6].var[(idx)], (arr)[((gid) * 16) + 7].var[(idx)], (arr)[((gid) * 16) + 8].var[(idx)], (arr)[((gid) * 16) + 9].var[(idx)], (arr)[((gid) * 16) + 10].var[(idx)], (arr)[((gid) * 16) + 11].var[(idx)], (arr)[((gid) * 16) + 12].var[(idx)], (arr)[((gid) * 16) + 13].var[(idx)], (arr)[((gid) * 16) + 14].var[(idx)], (arr)[((gid) * 16) + 15].var[(idx)])
#endif

#if   VECT_SIZE == 1
#define packvf(arr,var,gid) make_u32x ((arr)[((gid) *  1) + 0].var)
#elif VECT_SIZE == 2
#define packvf(arr,var,gid) make_u32x ((arr)[((gid) *  2) + 0].var, (arr)[((gid) *  2) + 1].var)
#elif VECT_SIZE == 4
#define packvf(arr,var,gid) make_u32x ((arr)[((gid) *  4) + 0].var, (arr)[((gid) *  4) + 1].var, (arr)[((gid) *  4) + 2].var, (arr)[((gid) *  4) + 3].var)
#elif VECT_SIZE == 8
#define packvf(arr,var,gid) make_u32x ((arr)[((gid) *  8) + 0].var, (arr)[((gid) *  8) + 1].var, (arr)[((gid) *  8) + 2].var, (arr)[((gid) *  8) + 3].var, (arr)[((gid) *  8) + 4].var, (arr)[((gid) *  8) + 5].var, (arr)[((gid) *  8) + 6].var, (arr)[((gid) *  8) + 7].var)
#elif VECT_SIZE == 16
#define packvf(arr,var,gid) make_u32x ((arr)[((gid) * 16) + 0].var, (arr)[((gid) * 16) + 1].var, (arr)[((gid) * 16) + 2].var, (arr)[((gid) * 16) + 3].var, (arr)[((gid) * 16) + 4].var, (arr)[((gid) * 16) + 5].var, (arr)[((gid) * 16) + 6].var, (arr)[((gid) * 16) + 7].var, (arr)[((gid) * 16) + 8].var, (arr)[((gid) * 16) + 9].var, (arr)[((gid) * 16) + 10].var, (arr)[((gid) * 16) + 11].var, (arr)[((gid) * 16) + 12].var, (arr)[((gid) * 16) + 13].var, (arr)[((gid) * 16) + 14].var, (arr)[((gid) * 16) + 15].var)
#endif

#if   VECT_SIZE == 1
#define pack64vf(arr,var,gid) make_u64x ((arr)[((gid) *  1) + 0].var)
#elif VECT_SIZE == 2
#define pack64vf(arr,var,gid) make_u64x ((arr)[((gid) *  2) + 0].var, (arr)[((gid) *  2) + 1].var)
#elif VECT_SIZE == 4
#define pack64vf(arr,var,gid) make_u64x ((arr)[((gid) *  4) + 0].var, (arr)[((gid) *  4) + 1].var, (arr)[((gid) *  4) + 2].var, (arr)[((gid) *  4) + 3].var)
#elif VECT_SIZE == 8
#define pack64vf(arr,var,gid) make_u64x ((arr)[((gid) *  8) + 0].var, (arr)[((gid) *  8) + 1].var, (arr)[((gid) *  8) + 2].var, (arr)[((gid) *  8) + 3].var, (arr)[((gid) *  8) + 4].var, (arr)[((gid) *  8) + 5].var, (arr)[((gid) *  8) + 6].var, (arr)[((gid) *  8) + 7].var)
#elif VECT_SIZE == 16
#define pack64vf(arr,var,gid) make_u64x ((arr)[((gid) * 16) + 0].var, (arr)[((gid) * 16) + 1].var, (arr)[((gid) * 16) + 2].var, (arr)[((gid) * 16) + 3].var, (arr)[((gid) * 16) + 4].var, (arr)[((gid) * 16) + 5].var, (arr)[((gid) * 16) + 6].var, (arr)[((gid) * 16) + 7].var, (arr)[((gid) * 16) + 8].var, (arr)[((gid) * 16) + 9].var, (arr)[((gid) * 16) + 10].var, (arr)[((gid) * 16) + 11].var, (arr)[((gid) * 16) + 12].var, (arr)[((gid) * 16) + 13].var, (arr)[((gid) * 16) + 14].var, (arr)[((gid) * 16) + 15].var)
#endif

#if   VECT_SIZE == 1
#define unpack(arr,var,gid,val) (arr)[((gid) *  1) + 0].var = val;
#elif VECT_SIZE == 2
#define unpack(arr,var,gid,val) (arr)[((gid) *  2) + 0].var = val.s0; (arr)[((gid) *  2) + 1].var = val.s1;
#elif VECT_SIZE == 4
#define unpack(arr,var,gid,val) (arr)[((gid) *  4) + 0].var = val.s0; (arr)[((gid) *  4) + 1].var = val.s1; (arr)[((gid) *  4) + 2].var = val.s2; (arr)[((gid) *  4) + 3].var = val.s3;
#elif VECT_SIZE == 8
#define unpack(arr,var,gid,val) (arr)[((gid) *  8) + 0].var = val.s0; (arr)[((gid) *  8) + 1].var = val.s1; (arr)[((gid) *  8) + 2].var = val.s2; (arr)[((gid) *  8) + 3].var = val.s3; (arr)[((gid) *  8) + 4].var = val.s4; (arr)[((gid) *  8) + 5].var = val.s5; (arr)[((gid) *  8) + 6].var = val.s6; (arr)[((gid) *  8) + 7].var = val.s7;
#elif VECT_SIZE == 16
#define unpack(arr,var,gid,val) (arr)[((gid) * 16) + 0].var = val.s0; (arr)[((gid) * 16) + 1].var = val.s1; (arr)[((gid) * 16) + 2].var = val.s2; (arr)[((gid) * 16) + 3].var = val.s3; (arr)[((gid) * 16) + 4].var = val.s4; (arr)[((gid) * 16) + 5].var = val.s5; (arr)[((gid) * 16) + 6].var = val.s6; (arr)[((gid) * 16) + 7].var = val.s7; (arr)[((gid) * 16) + 8].var = val.s8; (arr)[((gid) * 16) + 9].var = val.s9; (arr)[((gid) * 16) + 10].var = val.sa; (arr)[((gid) * 16) + 11].var = val.sb; (arr)[((gid) * 16) + 12].var = val.sc; (arr)[((gid) * 16) + 13].var = val.sd; (arr)[((gid) * 16) + 14].var = val.se; (arr)[((gid) * 16) + 15].var = val.sf;
#endif

#if   VECT_SIZE == 1
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) *  1) + 0].var[(idx)] = val;
#elif VECT_SIZE == 2
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) *  2) + 0].var[(idx)] = val.s0; (arr)[((gid) *  2) + 1].var[(idx)] = val.s1;
#elif VECT_SIZE == 4
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) *  4) + 0].var[(idx)] = val.s0; (arr)[((gid) *  4) + 1].var[(idx)] = val.s1; (arr)[((gid) *  4) + 2].var[(idx)] = val.s2; (arr)[((gid) *  4) + 3].var[(idx)] = val.s3;
#elif VECT_SIZE == 8
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) *  8) + 0].var[(idx)] = val.s0; (arr)[((gid) *  8) + 1].var[(idx)] = val.s1; (arr)[((gid) *  8) + 2].var[(idx)] = val.s2; (arr)[((gid) *  8) + 3].var[(idx)] = val.s3; (arr)[((gid) *  8) + 4].var[(idx)] = val.s4; (arr)[((gid) *  8) + 5].var[(idx)] = val.s5; (arr)[((gid) *  8) + 6].var[(idx)] = val.s6; (arr)[((gid) *  8) + 7].var[(idx)] = val.s7;
#elif VECT_SIZE == 16
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) * 16) + 0].var[(idx)] = val.s0; (arr)[((gid) * 16) + 1].var[(idx)] = val.s1; (arr)[((gid) * 16) + 2].var[(idx)] = val.s2; (arr)[((gid) * 16) + 3].var[(idx)] = val.s3; (arr)[((gid) * 16) + 4].var[(idx)] = val.s4; (arr)[((gid) * 16) + 5].var[(idx)] = val.s5; (arr)[((gid) * 16) + 6].var[(idx)] = val.s6; (arr)[((gid) * 16) + 7].var[(idx)] = val.s7; (arr)[((gid) * 16) + 8].var[(idx)] = val.s8; (arr)[((gid) * 16) + 9].var[(idx)] = val.s9; (arr)[((gid) * 16) + 10].var[(idx)] = val.sa; (arr)[((gid) * 16) + 11].var[(idx)] = val.sb; (arr)[((gid) * 16) + 12].var[(idx)] = val.sc; (arr)[((gid) * 16) + 13].var[(idx)] = val.sd; (arr)[((gid) * 16) + 14].var[(idx)] = val.se; (arr)[((gid) * 16) + 15].var[(idx)] = val.sf;
#endif

#if   VECT_SIZE == 1
#define unpack64v(arr,var,gid,idx,val) (arr)[((gid) *  1) + 0].var[(idx)] = val;
#elif VECT_SIZE == 2
#define unpack64v(arr,var,gid,idx,val) (arr)[((gid) *  2) + 0].var[(idx)] = val.s0; (arr)[((gid) *  2) + 1].var[(idx)] = val.s1;
#elif VECT_SIZE == 4
#define unpack64v(arr,var,gid,idx,val) (arr)[((gid) *  4) + 0].var[(idx)] = val.s0; (arr)[((gid) *  4) + 1].var[(idx)] = val.s1; (arr)[((gid) *  4) + 2].var[(idx)] = val.s2; (arr)[((gid) *  4) + 3].var[(idx)] = val.s3;
#elif VECT_SIZE == 8
#define unpack64v(arr,var,gid,idx,val) (arr)[((gid) *  8) + 0].var[(idx)] = val.s0; (arr)[((gid) *  8) + 1].var[(idx)] = val.s1; (arr)[((gid) *  8) + 2].var[(idx)] = val.s2; (arr)[((gid) *  8) + 3].var[(idx)] = val.s3; (arr)[((gid) *  8) + 4].var[(idx)] = val.s4; (arr)[((gid) *  8) + 5].var[(idx)] = val.s5; (arr)[((gid) *  8) + 6].var[(idx)] = val.s6; (arr)[((gid) *  8) + 7].var[(idx)] = val.s7;
#elif VECT_SIZE == 16
#define unpack64v(arr,var,gid,idx,val) (arr)[((gid) * 16) + 0].var[(idx)] = val.s0; (arr)[((gid) * 16) + 1].var[(idx)] = val.s1; (arr)[((gid) * 16) + 2].var[(idx)] = val.s2; (arr)[((gid) * 16) + 3].var[(idx)] = val.s3; (arr)[((gid) * 16) + 4].var[(idx)] = val.s4; (arr)[((gid) * 16) + 5].var[(idx)] = val.s5; (arr)[((gid) * 16) + 6].var[(idx)] = val.s6; (arr)[((gid) * 16) + 7].var[(idx)] = val.s7; (arr)[((gid) * 16) + 8].var[(idx)] = val.s8; (arr)[((gid) * 16) + 9].var[(idx)] = val.s9; (arr)[((gid) * 16) + 10].var[(idx)] = val.sa; (arr)[((gid) * 16) + 11].var[(idx)] = val.sb; (arr)[((gid) * 16) + 12].var[(idx)] = val.sc; (arr)[((gid) * 16) + 13].var[(idx)] = val.sd; (arr)[((gid) * 16) + 14].var[(idx)] = val.se; (arr)[((gid) * 16) + 15].var[(idx)] = val.sf;
#endif

#if   VECT_SIZE == 1
#define unpackv_xor(arr,var,gid,idx,val) (arr)[((gid) *  1) + 0].var[(idx)] ^= val;
#elif VECT_SIZE == 2
#define unpackv_xor(arr,var,gid,idx,val) (arr)[((gid) *  2) + 0].var[(idx)] ^= val.s0; (arr)[((gid) *  2) + 1].var[(idx)] ^= val.s1;
#elif VECT_SIZE == 4
#define unpackv_xor(arr,var,gid,idx,val) (arr)[((gid) *  4) + 0].var[(idx)] ^= val.s0; (arr)[((gid) *  4) + 1].var[(idx)] ^= val.s1; (arr)[((gid) *  4) + 2].var[(idx)] ^= val.s2; (arr)[((gid) *  4) + 3].var[(idx)] ^= val.s3;
#elif VECT_SIZE == 8
#define unpackv_xor(arr,var,gid,idx,val) (arr)[((gid) *  8) + 0].var[(idx)] ^= val.s0; (arr)[((gid) *  8) + 1].var[(idx)] ^= val.s1; (arr)[((gid) *  8) + 2].var[(idx)] ^= val.s2; (arr)[((gid) *  8) + 3].var[(idx)] ^= val.s3; (arr)[((gid) *  8) + 4].var[(idx)] ^= val.s4; (arr)[((gid) *  8) + 5].var[(idx)] ^= val.s5; (arr)[((gid) *  8) + 6].var[(idx)] ^= val.s6; (arr)[((gid) *  8) + 7].var[(idx)] ^= val.s7;
#elif VECT_SIZE == 16
#define unpackv_xor(arr,var,gid,idx,val) (arr)[((gid) * 16) + 0].var[(idx)] ^= val.s0; (arr)[((gid) * 16) + 1].var[(idx)] ^= val.s1; (arr)[((gid) * 16) + 2].var[(idx)] ^= val.s2; (arr)[((gid) * 16) + 3].var[(idx)] ^= val.s3; (arr)[((gid) * 16) + 4].var[(idx)] ^= val.s4; (arr)[((gid) * 16) + 5].var[(idx)] ^= val.s5; (arr)[((gid) * 16) + 6].var[(idx)] ^= val.s6; (arr)[((gid) * 16) + 7].var[(idx)] ^= val.s7; (arr)[((gid) * 16) + 8].var[(idx)] ^= val.s8; (arr)[((gid) * 16) + 9].var[(idx)] ^= val.s9; (arr)[((gid) * 16) + 10].var[(idx)] ^= val.sa; (arr)[((gid) * 16) + 11].var[(idx)] ^= val.sb; (arr)[((gid) * 16) + 12].var[(idx)] ^= val.sc; (arr)[((gid) * 16) + 13].var[(idx)] ^= val.sd; (arr)[((gid) * 16) + 14].var[(idx)] ^= val.se; (arr)[((gid) * 16) + 15].var[(idx)] ^= val.sf;
#endif

#if   VECT_SIZE == 1
#define VECTOR_ELEMENT(v, n) (v)
#elif VECT_SIZE == 2
#define VECTOR_ELEMENT(v, n) (n == 0 ? (v).s0 : (v).s1)
#elif VECT_SIZE == 4
#define VECTOR_ELEMENT(v, n)       \
  (n < 2 ?                         \
   (n == 0 ? (v).s0 : (v).s1) :    \
   (n == 2 ? (v).s2 : (v).s3)      \
  )
#elif VECT_SIZE == 8
#define VECTOR_ELEMENT(v, n)       \
  (n < 4 ?                         \
   (n < 2 ?                        \
    (n == 0 ? (v).s0 : (v).s1) :   \
    (n == 2 ? (v).s2 : (v).s3)     \
   ) : (n < 6 ?                    \
    (n == 4 ? (v).s4 : (v).s5) :   \
    (n == 6 ? (v).s6 : (v).s7)     \
   )                               \
  )
#elif VECT_SIZE == 16
#define VECTOR_ELEMENT(v, n)       \
  (n < 8 ?                         \
   (n < 4 ?                        \
    (n < 2 ?                       \
     (n == 0 ? (v).s0 : (v).s1) :  \
     (n == 2 ? (v).s2 : (v).s3)    \
    ) : (n < 6 ?                   \
     (n == 4 ? (v).s4 : (v).s5) :  \
     (n == 6 ? (v).s6 : (v).s7)    \
    )                              \
   ) : (n < 12 ?                   \
    (n < 10 ?                      \
     (n == 8 ? (v).s8 : (v).s9) :  \
     (n == 10 ? (v).sa : (v).sb)   \
    ) : (n < 14 ?                  \
     (n == 12 ? (v).sc : (v).sd) : \
     (n == 14 ? (v).se : (v).sf)   \
    )                              \
   )                               \
  )
#endif

DECLSPEC u32x ix_create_bft       (CONSTANT_AS const bf_t *arr, const u32 il_pos);
DECLSPEC u32x pwlenx_create_combt (GLOBAL_AS   const pw_t *arr, const u32 il_pos);
DECLSPEC u32x ix_create_combt     (GLOBAL_AS   const pw_t *arr, const u32 il_pos, const int idx);

#endif
