if ((r0 == search[0])
 && (r1 == search[1])
 && (r2 == search[2])
 && (r3 == search[3]))
{
  const u32 final_hash_pos = digests_offset + 0;

  if (atomic_add (&hashes_shown[final_hash_pos], 1) == 0)
  {
    mark_hash (plains_buf, hashes_shown, final_hash_pos, gid, il_pos);

    d_return_buf[lid] = 1;
  }
}
