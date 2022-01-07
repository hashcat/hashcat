if ((r0 == search[0])
 && (r1 == search[1])
 && (r2 == search[2])
 && (r3 == search[3]))
{
  const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

  if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);
  }
}
