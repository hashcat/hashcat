u32 digest_tp[4];

digest_tp[0] = r0.s0;
digest_tp[1] = r1.s0;
digest_tp[2] = r2.s0;
digest_tp[3] = r3.s0;

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

    if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 0) == 1))
    {
      mark_hash_s0_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

      d_return_buf[lid] = 1;
    }
  }
}

digest_tp[0] = r0.s1;
digest_tp[1] = r1.s1;
digest_tp[2] = r2.s1;
digest_tp[3] = r3.s1;

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

    if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 1) == 1))
    {
      mark_hash_s1_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

      d_return_buf[lid] = 1;
    }
  }
}

digest_tp[0] = r0.s2;
digest_tp[1] = r1.s2;
digest_tp[2] = r2.s2;
digest_tp[3] = r3.s2;

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

    if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 2) == 1))
    {
      mark_hash_s2_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

      d_return_buf[lid] = 1;
    }
  }
}

digest_tp[0] = r0.s3;
digest_tp[1] = r1.s3;
digest_tp[2] = r2.s3;
digest_tp[3] = r3.s3;

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

    if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 3) == 1))
    {
      mark_hash_s3_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

      d_return_buf[lid] = 1;
    }
  }
}
