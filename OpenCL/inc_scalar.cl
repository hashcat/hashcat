/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define COMPARE_S_SCALAR(h0,h1,h2,h3)                                                                       \
{                                                                                                           \
  if (((h0) == search[0]) && ((h1) == search[1]) && ((h2) == search[2]) && ((h3) == search[3]))             \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                    \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, final_hash_pos, gid, il_pos, 0, 0);    \
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
             bitmap_mask,                                                                                   \
             bitmap_shift1,                                                                                 \
             bitmap_shift2))                                                                                \
  {                                                                                                         \
    int digest_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);                     \
                                                                                                            \
    if (digest_pos != -1)                                                                                   \
    {                                                                                                       \
      const u32 final_hash_pos = digests_offset + digest_pos;                                               \
                                                                                                            \
      if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                  \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, final_hash_pos, gid, il_pos, 0, 0); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}
