/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A crack record carries two spare words beside il_pos, and every kernel until now had nothing to put
// in them. The device engine has: its candidate is named by the cell it was stepped to, and once the
// rules are applied on the device, by which rule made it as well. il_pos cannot say both, so the rule
// index rides in the first spare. The two names without the suffix are what every other kernel calls
// and they pass zero, so nothing else changes.

#define COMPARE_S_SCALAR_EXTRA(h0,h1,h2,h3,e1,e2)                                                           \
{                                                                                                           \
  if (((h0) == search[0]) && ((h1) == search[1]) && ((h2) == search[2]) && ((h3) == search[3]))             \
  {                                                                                                         \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;                                                     \
                                                                                                            \
    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                 \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, e1, e2); \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_S_SCALAR(h0,h1,h2,h3) COMPARE_S_SCALAR_EXTRA (h0, h1, h2, h3, 0, 0)

#define COMPARE_M_SCALAR_EXTRA(h0,h1,h2,h3,e1,e2)                                                           \
{                                                                                                           \
  const u32 digest_tp0[4] = { h0, h1, h2, h3 };                                                             \
                                                                                                            \
  if (check (digest_tp0,                                                                                    \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,                        \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,                        \
             BITMAP_MASK))                                                                                  \
  {                                                                                                         \
    const u32 digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);          \
                                                                                                            \
    if (digest_pos != (u32) -1)                                                                             \
    {                                                                                                       \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                                          \
                                                                                                            \
      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                               \
      {                                                                                                     \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, e1, e2); \
      }                                                                                                     \
    }                                                                                                       \
  }                                                                                                         \
}

#define COMPARE_M_SCALAR(h0,h1,h2,h3) COMPARE_M_SCALAR_EXTRA (h0, h1, h2, h3, 0, 0)
