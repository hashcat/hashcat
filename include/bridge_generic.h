/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRIDGE_GENERIC_H
#define HC_BRIDGE_GENERIC_H

#include "memory.h"
#include "emu_inc_hash_md4.h"

#include <limits.h>
#include <string.h>

typedef struct
{
  u32 hash_len;
  u32 salt_len;

} generic_io_t;

// OPTS_TYPE_HASH_COPY owns the variable data. Only lengths travel through the fixed-size esalt arrays.
static inline const char *generic_hash_original (const hashconfig_t *hashconfig, const hashinfo_t *hash_info, const generic_io_t *generic_io)
{
  if ((hash_info != NULL) && (hash_info->orighash != NULL)) return hash_info->orighash;

  if ((generic_io->hash_len == 0) && (generic_io->salt_len == 0)) return "*";

  return hashconfig->st_hash;
}

static inline void generic_hash_digest (const u8 *buf, const u32 len, u32 digest[4])
{
  md4_ctx_t ctx;

  md4_init (&ctx);

  for (u32 pos = 0; pos < len;)
  {
    u32 block[16] = { 0 };

    const u32 count = MIN (64, len - pos);

    memcpy (block, &buf[pos], count);

    md4_update (&ctx, block, count);

    pos += count;
  }

  md4_final (&ctx);

  memcpy (digest, ctx.h, 16);
}

// Packed records contain two native-endian lengths followed by the hash and salt bytes.
static inline bool generic_hash_pack (const hashconfig_t *hashconfig, const hashes_t *hashes, const bool selftest, u8 **out, u32 *out_len)
{
  const u32 count = selftest ? ((hashes->st_esalts_buf != NULL) ? 1 : 0) : hashes->digests_cnt;

  const generic_io_t *records = selftest ? hashes->st_esalts_buf : hashes->esalts_buf;

  *out = NULL;
  *out_len = 0;

  if (hashconfig->esalt_size != sizeof (generic_io_t)) return false;
  if ((count > 0) && (records == NULL)) return false;

  u64 size = 0;

  for (u32 i = 0; i < count; i++)
  {
    size += sizeof (generic_io_t) + (u64) records[i].hash_len + records[i].salt_len;

    if (size > INT_MAX) return false;
  }

  if (size == 0) return true;

  u8 *buf = (u8 *) hcmalloc ((size_t) size);

  if (buf == NULL) return false;

  u32 pos = 0;

  for (u32 i = 0; i < count; i++)
  {
    const hashinfo_t *hash_info = ((selftest == false) && (hashes->hash_info != NULL)) ? hashes->hash_info[i] : NULL;

    const char *line = generic_hash_original (hashconfig, hash_info, &records[i]);

    const u64 line_len = (u64) records[i].hash_len + 1 + records[i].salt_len;

    if ((line == NULL) || (strlen (line) != line_len) || (line[records[i].hash_len] != '*'))
    {
      hcfree (buf);

      return false;
    }

    memcpy (&buf[pos], &records[i], sizeof (generic_io_t));

    pos += sizeof (generic_io_t);

    memcpy (&buf[pos], line, records[i].hash_len);

    pos += records[i].hash_len;

    memcpy (&buf[pos], &line[records[i].hash_len + 1], records[i].salt_len);

    pos += records[i].salt_len;
  }

  *out = buf;
  *out_len = pos;

  return true;
}

#endif
