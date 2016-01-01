u32 digest_tp[4];

digest_tp[0] = r0;
digest_tp[1] = r1;
digest_tp[2] = r2;
digest_tp[3] = r3;

if (check (digest_tp,
             bitmaps_buf_s1_a,
             bitmaps_buf_s1_b,
             bitmaps_buf_s1_c,
             bitmaps_buf_s1_d,
             bitmaps_buf_s2_a,
             bitmaps_buf_s2_b,
             bitmaps_buf_s2_c,
             bitmaps_buf_s2_d,
             bitmap_mask,
             bitmap_shift1,
             bitmap_shift2))
{
  int hash_pos = find_hash (digest_tp, digests_cnt, &digests_buf[digests_offset]);

  if (hash_pos != -1)
  {
    const u32 final_hash_pos = digests_offset + hash_pos;

    if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)
    {
      mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos + slice);

      d_return_buf[lid] = 1;
    }
  }
}
