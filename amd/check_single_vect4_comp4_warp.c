if ((r0.s0 == search[0])
 && (r1.s0 == search[1])
 && (r2.s0 == search[2])
 && (r3.s0 == search[3]))
{
  const u32 final_hash_pos = digests_offset + 0;

  if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 0) == 1))
  {
    mark_hash_s0_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

    d_return_buf[lid] = 1;
  }
}

if ((r0.s1 == search[0])
 && (r1.s1 == search[1])
 && (r2.s1 == search[2])
 && (r3.s1 == search[3]))
{
  const u32 final_hash_pos = digests_offset + 0;

  if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 1) == 1))
  {
    mark_hash_s1_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

    d_return_buf[lid] = 1;
  }
}

if ((r0.s2 == search[0])
 && (r1.s2 == search[1])
 && (r2.s2 == search[2])
 && (r3.s2 == search[3]))
{
  const u32 final_hash_pos = digests_offset + 0;

  if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 2) == 1))
  {
    mark_hash_s2_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

    d_return_buf[lid] = 1;
  }
}

if ((r0.s3 == search[0])
 && (r1.s3 == search[1])
 && (r2.s3 == search[2])
 && (r3.s3 == search[3]))
{
  const u32 final_hash_pos = digests_offset + 0;

  if ((atomic_add (&hashes_shown[final_hash_pos], 1) == 0) && (check_vector_accessible (il_pos, bf_loops, bfs_cnt, 3) == 1))
  {
    mark_hash_s3_warp (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

    d_return_buf[lid] = 1;
  }
}
