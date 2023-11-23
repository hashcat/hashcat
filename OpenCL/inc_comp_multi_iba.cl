
for (int digest_pos = 0; digest_pos < DIGESTS_CNT; digest_pos++)
{
  const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;

  const digest_t *digest = digests_buf + final_hash_pos;

  const int invalid_bits = count_bits_32 (digest->digest_buf[0], r0)
                         + count_bits_32 (digest->digest_buf[1], r1)
                         + count_bits_32 (digest->digest_buf[2], r2)
                         + count_bits_32 (digest->digest_buf[3], r3);

  if (invalid_bits > invalid_bits_accept) continue;

  if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
  }
}
