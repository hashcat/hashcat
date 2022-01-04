/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define COMPARE_S_SCALAR(h0,h1,h2,h3)                                                                       \
{                                                                                                           \
  if (((h0) == search[0]) && ((h1) == search[1]) && ((h2) == search[2]) && ((h3) == search[3]))             \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                          \
                                                                                                            \
    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                    \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);    \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SCALAR(h0,h1,h2,h3)                                                                       \
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
    int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                     \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                               \
                                                                                                            \
      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                  \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}
