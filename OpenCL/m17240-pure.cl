/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#include M2S(INCLUDE_PATH/inc_pkzip_stream.h)
#endif

DECLSPEC void pkzip_stream_update (PRIVATE_AS u32 *key, const u32 plain, LOCAL_AS const u32 *table)
{
  key[0] = (key[0] >> 8) ^ table[(key[0] ^ plain) & 255];
  key[1] = (key[1] + (key[0] & 255)) * 0x08088405 + 1;
  key[2] = (key[2] >> 8) ^ table[(key[2] ^ (key[1] >> 24)) & 255];
}

DECLSPEC u32 pkzip_stream_decrypt (PRIVATE_AS u32 *key, const u32 cipher, LOCAL_AS const u32 *table)
{
  const u32 t     = (key[2] & 65535) | 3;
  const u32 plain = cipher ^ (((t * (t ^ 1)) >> 8) & 255);

  pkzip_stream_update (key, plain, table);

  return plain;
}

DECLSPEC u32 pkzip_stream_bits (PRIVATE_AS const u32 *head, const u32 pos, const u32 count)
{
  const u32 index = pos / 32;
  const u32 shift = pos & 31;

  u32 value = head[index + 0] >> shift;

  if (shift + count > 32) value |= head[index + 1] << (32 - shift);

  const u32 result = value & ((1u << count) - 1);

  return result;
}

DECLSPEC u32 pkzip_stream_reverse (const u32 value, const u32 count)
{
  u32 code = value;

  code = ((code >> 1) & 0x55555555) | ((code & 0x55555555) << 1);
  code = ((code >> 2) & 0x33333333) | ((code & 0x33333333) << 2);
  code = ((code >> 4) & 0x0f0f0f0f) | ((code & 0x0f0f0f0f) << 4);
  code = hc_swap32_S (code) >> (32 - count);

  return code;
}

DECLSPEC bool pkzip_stream_fixed (PRIVATE_AS const u32 *head, const u32 bytes, const u32 sample_bytes)
{
  const u32 bits = bytes * 8;

  u32 pos     = 3;
  u32 written = 0;
  u32 final   = head[0] & 1;

  while (pos + 9 <= bits)
  {
    const u32 code = pkzip_stream_reverse (pkzip_stream_bits (head, pos, 9), 9);

    u32 symbol = 0;

    if ((code >> 1) >= 200)
    {
      symbol = 144 + code - 400;
      pos += 9;
    }
    else if ((code >> 1) >= 192)
    {
      symbol = 280 + (code >> 1) - 192;
      pos += 8;
    }
    else if ((code >> 2) >= 24)
    {
      symbol = (code >> 1) - 48;
      pos += 8;
    }
    else
    {
      symbol = 256 + (code >> 2);
      pos += 7;
    }

    if (symbol < 256)
    {
      written++;

      continue;
    }

    if (symbol == 256)
    {
      if (final == 1)
      {
        const bool complete = ((pos + 7) / 8 == sample_bytes);

        return complete;
      }

      if (pos + 3 > bits) return true;

      final = pkzip_stream_bits (head, pos, 1);

      const u32 kind = pkzip_stream_bits (head, pos + 1, 2);

      pos += 3;

      if (kind == 3) return false;
      if (kind == 1) continue;

      if (kind == 0)
      {
        pos = (pos + 7) & ~7u;

        if (pos + 32 > bits) return true;

        const u32 len = pkzip_stream_bits (head, pos, 16);
        const u32 inv = pkzip_stream_bits (head, pos + 16, 16);

        if ((len ^ inv) != 65535) return false;
      }

      if ((kind == 2) && (pos + 5 <= bits))
      {
        if (pkzip_stream_bits (head, pos, 5) > 29) return false;
      }

      return true;
    }

    if (symbol > 285) return false;

    u32 length = symbol - 254;

    if (symbol >= 265)
    {
      if (symbol == 285)
      {
        length = 258;
      }
      else
      {
        const u32 extra = (symbol - 261) / 4;

        if (pos + extra > bits) return true;

        length = (1u << (extra + 2)) + 3 + (((symbol - 265) & 3) << extra) + pkzip_stream_bits (head, pos, extra);
        pos += extra;
      }
    }

    if (pos + 5 > bits) return true;

    const u32 code_dist = pkzip_stream_reverse (pkzip_stream_bits (head, pos, 5), 5);

    pos += 5;

    if (code_dist >= 30) return false;

    u32 distance = code_dist + 1;

    if (code_dist >= 4)
    {
      const u32 extra = code_dist / 2 - 1;

      if (pos + extra > bits) return true;

      distance = ((2 + (code_dist & 1)) << extra) + 1 + pkzip_stream_bits (head, pos, extra);
      pos += extra;
    }

    if (distance > written) return false;

    written += length;
  }

  // A valid stream may continue beyond the encrypted prefix.
  return true;
}

KERNEL_FQ KERNEL_FA void m17240_init (KERN_ATTR_TMPS_HOOKS_ESALT (pkzip_stream_tmp_t, pkzip_stream_hook_t, pkzip_stream_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 table[256];

  for (u32 i = lid; i < 256; i += lsz) table[i] = crc32tab[i];

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  tmps[gid].valid = 0;

  u32 key[3] = { 0x12345678, 0x23456789, 0x34567890 };

  for (u32 i = 0; i < pws[gid].pw_len; i++)
  {
    const u32 value = (pws[gid].i[i / 4] >> ((i & 3) * 8)) & 255;

    pkzip_stream_update (key, value, table);
  }

  u32 plain = 0;

  for (u32 i = 0; i < 12; i++)
  {
    const u32 value = (esalt_bufs[DIGESTS_OFFSET_HOST].data[i / 4] >> ((i & 3) * 8)) & 255;

    plain = pkzip_stream_decrypt (key, value, table);
  }

  if (plain != esalt_bufs[DIGESTS_OFFSET_HOST].check) return;

  tmps[gid].key[0] = key[0];
  tmps[gid].key[1] = key[1];
  tmps[gid].key[2] = key[2];

  if ((esalt_bufs[DIGESTS_OFFSET_HOST].method == 8) && (esalt_bufs[DIGESTS_OFFSET_HOST].sample_len >= 22))
  {
    u32 head[PKZIP_STREAM_PREFIX / 4] = { 0 };

    const u32 bytes = min (esalt_bufs[DIGESTS_OFFSET_HOST].sample_len - 12, (u32) PKZIP_STREAM_PREFIX);

    for (u32 i = 0; i < bytes; i++)
    {
      const u32 pos   = i + 12;
      const u32 value = (esalt_bufs[DIGESTS_OFFSET_HOST].data[pos / 4] >> ((pos & 3) * 8)) & 255;

      head[i / 4] |= pkzip_stream_decrypt (key, value, table) << ((i & 3) * 8);
    }

    const u32 kind = pkzip_stream_bits (head, 1, 2);

    if (kind == 3) return;

    if (kind == 0)
    {
      const u32 len = pkzip_stream_bits (head, 8, 16);
      const u32 inv = pkzip_stream_bits (head, 24, 16);

      if ((len ^ inv) != 65535) return;
    }

    if (kind == 1)
    {
      if (pkzip_stream_fixed (head, bytes, esalt_bufs[DIGESTS_OFFSET_HOST].sample_len - 12) == false) return;
    }

    if (kind == 2)
    {
      if (pkzip_stream_bits (head, 3, 5) > 29) return;

      const u32 count = pkzip_stream_bits (head, 13, 4) + 4;

      u32 counts[8] = { 0 };

      for (u32 i = 0; i < count; i++)
      {
        const u32 pos   = 17 + i * 3;
        const u32 value = pkzip_stream_bits (head, pos, 3);

        counts[value]++;
      }

      u32 left = 1;

      for (u32 i = 1; i < 8; i++)
      {
        left *= 2;

        if (counts[i] > left) return;

        left -= counts[i];
      }

      if (left != 0) return;
    }
  }

  tmps[gid].valid = 1;
}

KERNEL_FQ KERNEL_FA void m17240_loop (KERN_ATTR_TMPS_HOOKS_ESALT (pkzip_stream_tmp_t, pkzip_stream_hook_t, pkzip_stream_t))
{
}

KERNEL_FQ KERNEL_FA void m17240_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (pkzip_stream_tmp_t, pkzip_stream_hook_t, pkzip_stream_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  hooks[gid].state = PKZIP_STREAM_REJECT;

  if (tmps[gid].valid == 0) return;

  hooks[gid].state  = PKZIP_STREAM_VERIFY;
  hooks[gid].key[0] = tmps[gid].key[0];
  hooks[gid].key[1] = tmps[gid].key[1];
  hooks[gid].key[2] = tmps[gid].key[2];
}

KERNEL_FQ KERNEL_FA void m17240_comp (KERN_ATTR_TMPS_HOOKS_ESALT (pkzip_stream_tmp_t, pkzip_stream_hook_t, pkzip_stream_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
  if (hooks[gid].state != PKZIP_STREAM_MATCH) return;

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST, gid, 0, 0, 0);
  }
}
