
// vliw1

#if VECT_SIZE == 1

#define MATCHES_ONE_VV(a,b) ((a) == (b))
#define MATCHES_ONE_VS(a,b) ((a) == (b))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0) == search[0]) && ((h1) == search[1]) && ((h2) == search[2]) && ((h3) == search[3]))             \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);                                    \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
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
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);                                  \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw2

#if VECT_SIZE == 2

#define MATCHES_ONE_VV(a,b) (((a).s0 == (b).s0) || ((a).s1 == (b).s1))
#define MATCHES_ONE_VS(a,b) (((a).s0 == (b)   ) || ((a).s1 == (b)   ))

#define COMPARE_S_SIMD(h0,h1,h2,h3)                                                                         \
{                                                                                                           \
  if (((h0).s0 == search[0]) && ((h1).s0 == search[1]) && ((h2).s0 == search[2]) && ((h3).s0 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
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
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp1, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
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
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s2 == search[0]) && ((h1).s2 == search[1]) && ((h2).s2 == search[2]) && ((h3).s2 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 2);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s3 == search[0]) && ((h1).s3 == search[1]) && ((h2).s3 == search[2]) && ((h3).s3 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 3);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
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
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp1, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp2,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp2, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 2);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp3,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp3, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 3);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
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
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s1 == search[0]) && ((h1).s1 == search[1]) && ((h2).s1 == search[2]) && ((h3).s1 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s2 == search[0]) && ((h1).s2 == search[1]) && ((h2).s2 == search[2]) && ((h3).s2 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 2);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s3 == search[0]) && ((h1).s3 == search[1]) && ((h2).s3 == search[2]) && ((h3).s3 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 3);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
  if (((h0).s4 == search[0]) && ((h1).s4 == search[1]) && ((h2).s4 == search[2]) && ((h3).s4 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 4);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s5 == search[0]) && ((h1).s5 == search[1]) && ((h2).s5 == search[2]) && ((h3).s5 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 5);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s6 == search[0]) && ((h1).s6 == search[1]) && ((h2).s6 == search[2]) && ((h3).s6 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 6);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (((h0).s7 == search[0]) && ((h1).s7 == search[1]) && ((h2).s7 == search[2]) && ((h3).s7 == search[3])) \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 7);                                \
                                                                                                            \
      d_return_buf[lid] = 1;                                                                                \
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
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 0);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp1,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp1, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 1);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp2,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp2, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 2);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp3,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp3, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 3);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
  if (check (digest_tp4,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp4, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 4);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp5,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp5, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 5);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp6,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp6, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 6);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if (check (digest_tp7,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int hash_pos = find_hash (digest_tp7, digests_cnt, &digests_buf[digests_offset]);                       \
                                                                                                            \
    if (hash_pos != -1)                                                                                     \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + hash_pos;                                                 \
                                                                                                            \
      if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + 7);                              \
                                                                                                            \
        d_return_buf[lid] = 1;                                                                              \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

#define MATCHES_NONE_VV(a,b) !(MATCHES_ONE_VV ((a), (b)))
#define MATCHES_NONE_VS(a,b) !(MATCHES_ONE_VS ((a), (b)))

// attack-mode 0

static inline u32x w0r_create_bft (__global bf_t *bfs_buf, const u32 il_pos)
{
  #if   VECT_SIZE == 1
  const u32x w0r = (u32x) (bfs_buf[il_pos + 0].i);
  #elif VECT_SIZE == 2
  const u32x w0r = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i);
  #elif VECT_SIZE == 4
  const u32x w0r = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i, bfs_buf[il_pos + 2].i, bfs_buf[il_pos + 3].i);
  #elif VECT_SIZE == 8
  const u32x w0r = (u32x) (bfs_buf[il_pos + 0].i, bfs_buf[il_pos + 1].i, bfs_buf[il_pos + 2].i, bfs_buf[il_pos + 3].i, bfs_buf[il_pos + 4].i, bfs_buf[il_pos + 5].i, bfs_buf[il_pos + 6].i, bfs_buf[il_pos + 7].i);
  #endif

  return w0r;
}

#if   VECT_SIZE == 1
#define packv(arr,var,gid,idx) (u32x) ((arr)[((gid) * 1) + 0].var[(idx)])
#elif VECT_SIZE == 2
#define packv(arr,var,gid,idx) (u32x) ((arr)[((gid) * 2) + 0].var[(idx)], (arr)[((gid) * 2) + 1].var[(idx)])
#elif VECT_SIZE == 4
#define packv(arr,var,gid,idx) (u32x) ((arr)[((gid) * 4) + 0].var[(idx)], (arr)[((gid) * 4) + 1].var[(idx)], (arr)[((gid) * 4) + 2].var[(idx)], (arr)[((gid) * 4) + 3].var[(idx)])
#elif VECT_SIZE == 8
#define packv(arr,var,gid,idx) (u32x) ((arr)[((gid) * 8) + 0].var[(idx)], (arr)[((gid) * 8) + 1].var[(idx)], (arr)[((gid) * 8) + 2].var[(idx)], (arr)[((gid) * 8) + 3].var[(idx)], (arr)[((gid) * 8) + 4].var[(idx)], (arr)[((gid) * 8) + 5].var[(idx)], (arr)[((gid) * 8) + 6].var[(idx)], (arr)[((gid) * 8) + 7].var[(idx)])
#endif

#if   VECT_SIZE == 1
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) * 1) + 0].var[(idx)] = val;
#elif VECT_SIZE == 2
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) * 2) + 0].var[(idx)] = val.s0; (arr)[((gid) * 2) + 1].var[(idx)] = val.s1;
#elif VECT_SIZE == 4
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) * 4) + 0].var[(idx)] = val.s0; (arr)[((gid) * 4) + 1].var[(idx)] = val.s1; (arr)[((gid) * 4) + 2].var[(idx)] = val.s2; (arr)[((gid) * 4) + 3].var[(idx)] = val.s3;
#elif VECT_SIZE == 8
#define unpackv(arr,var,gid,idx,val) (arr)[((gid) * 8) + 0].var[(idx)] = val.s0; (arr)[((gid) * 8) + 1].var[(idx)] = val.s1; (arr)[((gid) * 8) + 2].var[(idx)] = val.s2; (arr)[((gid) * 8) + 3].var[(idx)] = val.s3; (arr)[((gid) * 8) + 4].var[(idx)] = val.s4; (arr)[((gid) * 8) + 5].var[(idx)] = val.s5; (arr)[((gid) * 8) + 6].var[(idx)] = val.s6; (arr)[((gid) * 8) + 7].var[(idx)] = val.s7;
#endif

