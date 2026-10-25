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
  const u32 t = (key[2] & 65535) | 3;
  const u32 plain = cipher ^ (((t * (t ^ 1)) >> 8) & 255);

  pkzip_stream_update (key, plain, table);

  return plain;
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
    u32 head[10];

    for (u32 i = 0; i < 10; i++)
    {
      const u32 pos = i + 12;
      const u32 value = (esalt_bufs[DIGESTS_OFFSET_HOST].data[pos / 4] >> ((pos & 3) * 8)) & 255;

      head[i] = pkzip_stream_decrypt (key, value, table);
    }

    const u32 kind = (head[0] >> 1) & 3;

    if (kind == 3) return;

    if (kind == 0)
    {
      const u32 len = head[1] | (head[2] << 8);
      const u32 inv = head[3] | (head[4] << 8);

      if ((len ^ inv) != 65535) return;
    }

    if (kind == 2)
    {
      if ((head[0] >> 3) > 29) return;

      const u32 count = (((head[1] >> 5) | (head[2] << 3)) & 15) + 4;

      u32 counts[8] = { 0 };

      for (u32 i = 0; i < count; i++)
      {
        const u32 pos = 17 + i * 3;
        const u32 value = (head[pos / 8 + 0] | (head[pos / 8 + 1] << 8)) >> (pos & 7);

        counts[value & 7]++;
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

  hooks[gid].valid = tmps[gid].valid;
  hooks[gid].success = 0;

  if (hooks[gid].valid == 0) return;

  hooks[gid].key[0] = tmps[gid].key[0];
  hooks[gid].key[1] = tmps[gid].key[1];
  hooks[gid].key[2] = tmps[gid].key[2];
}

KERNEL_FQ KERNEL_FA void m17240_comp (KERN_ATTR_TMPS_HOOKS_ESALT (pkzip_stream_tmp_t, pkzip_stream_hook_t, pkzip_stream_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
  if (hooks[gid].success == 0) return;

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST, gid, 0, 0, 0);
  }
}
