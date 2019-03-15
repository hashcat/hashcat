
if ((il_pos + slice) < il_cnt)
{
  const u32 final_hash_pos = digests_offset + 0;

  if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, final_hash_pos, gid, il_pos + slice, 0, 0);
  }
}
