
if ((il_pos + slice) < IL_CNT)
{
  const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

  if (hc_atomic_inc (&hashes_shown[final_hash_pos]) < kernel_param->keep_guessing_limit)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, kernel_param->plains_cnt, 0, final_hash_pos, gid, il_pos + slice, 0, 0);
  }
}
