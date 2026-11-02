/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

static u64 stream_le (const u8 *buf, const u32 length)
{
  u64 value = 0;

  for (u32 i = 0; i < length; i++) value |= (u64) buf[i] << (i * 8);

  return value;
}

static bool stream_read_at (FILE *file, const u64 size, const u64 offset, void *buf, const u32 length)
{
  if (offset > size) return false;
  if (length > size - offset) return false;
  if (stream_seek (file, offset, SEEK_SET) != 0) return false;
  if (fread (buf, 1, length, file) != length) return false;

  return true;
}

static bool stream_zip64 (const u8 *extra, const u32 length, u64 *unpacked, u64 *packed, u64 *offset, u64 *disk)
{
  u32 position = 0;

  bool found = false;

  while (position < length)
  {
    if (length - position < 4) return false;

    const u32 tag  = stream_le (&extra[position + 0], 2);
    const u32 size = stream_le (&extra[position + 2], 2);

    position += 4;

    if (size > length - position) return false;

    if (tag == 1)
    {
      if (found == true) return false;

      found = true;

      u32 used = 0;
      u64 *const fields[4] = { unpacked, packed, offset, disk };

      for (u32 i = 0; i < 4; i++)
      {
        const u64 sentinel = (i == 3) ? 0xffff : 0xffffffff;

        if (*fields[i] != sentinel) continue;

        const u32 width = (i == 3) ? 4 : 8;

        if (width > size - used) return false;

        *fields[i] = stream_le (&extra[position + used], width);

        used += width;
      }
    }

    position += size;
  }

  if ((found == false) && ((*unpacked == 0xffffffff) || (*packed == 0xffffffff) || (*offset == 0xffffffff) || (*disk == 0xffff))) return false;

  return true;
}

static i32 stream_archive (FILE *file, const user_options_t *options, hash_t *hash)
{
  pkzip_stream_salt_t *selected = NULL;

  selected = (pkzip_stream_salt_t *) hash->hook_salt;

  if (stream_identity (file, selected->identity) == false) return PARSER_HAVE_ERRNO;

  const u64 size = selected->identity[2];

  if ((size < 22) || (size > LLONG_MAX)) return PARSER_FILE_SIZE;

  u8 tail[65557];

  const u32 tail_len = (size > sizeof (tail)) ? sizeof (tail) : (u32) size;

  if (stream_read_at (file, size, size - tail_len, tail, tail_len) == false) return PARSER_FILE_SIZE;

  i32 end = -1;

  for (i32 i = tail_len - 22; i >= 0; i--)
  {
    if (stream_le (&tail[i], 4) != 0x06054b50) continue;
    if (stream_le (&tail[i + 20], 2) != tail_len - i - 22) continue;

    end = i;

    break;
  }

  if (end == -1) return PARSER_SIGNATURE_UNMATCHED;
  if ((stream_le (&tail[end + 4], 2) != 0) || (stream_le (&tail[end + 6], 2) != 0)) return PARSER_HASH_VALUE;

  u64 entries = stream_le (&tail[end + 10], 2);
  u64 length  = stream_le (&tail[end + 12], 4);
  u64 offset  = stream_le (&tail[end + 16], 4);
  u64 limit   = size - tail_len + end;

  if (stream_le (&tail[end + 8], 2) != entries) return PARSER_HASH_VALUE;

  if ((entries == 0xffff) || (length == 0xffffffff) || (offset == 0xffffffff))
  {
    u8 locator[20];

    if (limit < sizeof (locator)) return PARSER_FILE_SIZE;
    if (stream_read_at (file, size, limit - 20, locator, 20) == false) return PARSER_FILE_SIZE;
    if (stream_le (locator, 4) != 0x07064b50) return PARSER_HASH_VALUE;
    if ((stream_le (&locator[4], 4) != 0) || (stream_le (&locator[16], 4) != 1)) return PARSER_HASH_VALUE;

    const u64 position = stream_le (&locator[8], 8);

    u8 record[56];

    if (position > limit - 20) return PARSER_FILE_SIZE;
    if (stream_read_at (file, limit - 20, position, record, 56) == false) return PARSER_FILE_SIZE;
    if (stream_le (record, 4) != 0x06064b50) return PARSER_HASH_VALUE;

    const u64 record_size = stream_le (&record[4], 8);

    if ((record_size < 44) || (record_size != limit - 20 - position - 12)) return PARSER_HASH_VALUE;
    if ((stream_le (&record[16], 4) != 0) || (stream_le (&record[20], 4) != 0)) return PARSER_HASH_VALUE;
    if (stream_le (&record[24], 8) != stream_le (&record[32], 8)) return PARSER_HASH_VALUE;

    entries = stream_le (&record[32], 8);
    length  = stream_le (&record[40], 8);
    offset  = stream_le (&record[48], 8);
    limit   = position;
  }

  if (offset > limit) return PARSER_FILE_SIZE;
  if (length > limit - offset) return PARSER_FILE_SIZE;
  if ((entries == 0) || (entries > length / 46) || (entries > UINT_MAX)) return PARSER_HASH_VALUE;

  const bool explicit = module_option_given (options, "pkzip-member-index");
  const u32 index     = module_option_u32 (options, "pkzip-member-index");

  if ((explicit == true) && (index >= entries)) return PARSER_PKZIP_MEMBER_INDEX;

  const u64 directory     = offset;
  const u64 directory_end = offset + length;

  bool found = false;

  for (u32 ordinal = 0; ordinal < entries; ordinal++)
  {
    u8 central[46];

    if (stream_read_at (file, directory_end, offset, central, 46) == false) return PARSER_FILE_SIZE;
    if (stream_le (central, 4) != 0x02014b50) return PARSER_HASH_VALUE;

    const u32 flags      = stream_le (&central[8], 2);
    const u32 method     = stream_le (&central[10], 2);
    const u32 crc        = stream_le (&central[16], 4);
    const u32 name_len   = stream_le (&central[28], 2);
    const u32 extra_len  = stream_le (&central[30], 2);
    const u32 comment    = stream_le (&central[32], 2);
    const u32 attributes = stream_le (&central[38], 4);

    u64 packed   = stream_le (&central[20], 4);
    u64 unpacked = stream_le (&central[24], 4);
    u64 local    = stream_le (&central[42], 4);
    u64 disk     = stream_le (&central[34], 2);

    const bool wide    = ((packed == 0xffffffff) || (unpacked == 0xffffffff));
    const u32 variable = name_len + extra_len + comment;

    offset += 46;

    if (variable > directory_end - offset) return PARSER_FILE_SIZE;

    u8 metadata[131070];

    if (stream_read_at (file, directory_end, offset, metadata, name_len + extra_len) == false) return PARSER_FILE_SIZE;
    if (stream_zip64 (&metadata[name_len], extra_len, &unpacked, &packed, &local, &disk) == false) return PARSER_HASH_VALUE;
    if (disk != 0) return PARSER_HASH_VALUE;

    offset += variable;

    u8 header[30];

    if (stream_read_at (file, directory, local, header, 30) == false) return PARSER_FILE_SIZE;
    if (stream_le (header, 4) != 0x04034b50) return PARSER_HASH_VALUE;
    if ((stream_le (&header[6], 2) != flags) || (stream_le (&header[8], 2) != method)) return PARSER_HASH_VALUE;

    const u32 local_name  = stream_le (&header[26], 2);
    const u32 local_extra = stream_le (&header[28], 2);

    const u64 data = local + 30 + local_name + local_extra;

    if ((data > directory) || (packed > directory - data)) return PARSER_FILE_SIZE;
    if (local_name != name_len) return PARSER_HASH_VALUE;

    u8 local_metadata[131070];

    if (stream_read_at (file, directory, local + 30, local_metadata, local_name + local_extra) == false) return PARSER_FILE_SIZE;
    if (memcmp (metadata, local_metadata, name_len) != 0) return PARSER_HASH_VALUE;

    if ((flags & 8) == 0)
    {
      u64 local_packed   = stream_le (&header[18], 4);
      u64 local_unpacked = stream_le (&header[22], 4);
      u64 unused_offset  = 0;
      u64 unused_disk    = 0;

      if (stream_zip64 (&local_metadata[local_name], local_extra, &local_unpacked, &local_packed, &unused_offset, &unused_disk) == false) return PARSER_HASH_VALUE;
      if ((local_packed != packed) || (local_unpacked != unpacked) || (stream_le (&header[14], 4) != crc)) return PARSER_HASH_VALUE;
    }
    else
    {
      u8 descriptor[24];

      const bool local_wide = ((stream_le (&header[18], 4) == 0xffffffff) || (stream_le (&header[22], 4) == 0xffffffff));

      const u32 width    = ((wide == true) || (local_wide == true)) ? 8 : 4;
      const u32 minimum  = 4 + width * 2;
      const u64 position = data + packed;

      if (stream_read_at (file, directory, position, descriptor, minimum) == false) return PARSER_FILE_SIZE;

      bool valid = ((stream_le (descriptor, 4) == crc) && (stream_le (&descriptor[4], width) == packed) && (stream_le (&descriptor[4 + width], width) == unpacked));

      if ((valid == false) && (stream_le (descriptor, 4) == 0x08074b50))
      {
        if (stream_read_at (file, directory, position, descriptor, minimum + 4) == false) return PARSER_FILE_SIZE;

        valid = ((stream_le (&descriptor[4], 4) == crc) && (stream_le (&descriptor[8], width) == packed) && (stream_le (&descriptor[8 + width], width) == unpacked));
      }

      if (valid == false) return PARSER_HASH_VALUE;
    }

    const bool directory_member = (((name_len > 0) && (metadata[name_len - 1] == '/')) || ((attributes & 0x10) != 0));
    const bool supported        = (((flags & 0x2041) == 1) && ((method == 0) || (method == 8)) && (directory_member == false));

    if ((explicit == true) && (ordinal != index)) continue;
    if ((explicit == true) && (supported == false)) return PARSER_PKZIP_MEMBER_UNSUPPORTED;
    if ((explicit == true) && (unpacked == 0)) return PARSER_PKZIP_MEMBER_EMPTY;
    if ((supported == false) || (unpacked == 0)) continue;
    if ((method == 0) && (unpacked < 4))
    {
      if (explicit == true) return PARSER_PKZIP_MEMBER_TOO_SHORT;

      continue;
    }

    if (packed < 12) return PARSER_HASH_VALUE;
    if ((method == 0) && (unpacked != packed - 12)) return PARSER_HASH_VALUE;
    if ((found == true) && (packed >= selected->packed)) continue;

    selected->offset     = data;
    selected->packed     = packed;
    selected->unpacked   = unpacked;
    selected->crc        = crc;
    selected->method     = method;
    selected->sample_len = (packed > PKZIP_STREAM_SAMPLE) ? PKZIP_STREAM_SAMPLE : (u32) packed;
    selected->external   = 1;

    pkzip_stream_t *zip = NULL;

    zip = (pkzip_stream_t *) hash->esalt;

    zip->check = ((flags & 8) != 0) ? header[11] : crc >> 24;

    found = true;
  }

  if (offset != directory_end) return PARSER_HASH_VALUE;
  if (found == false) return PARSER_PKZIP_MEMBER_UNSUPPORTED;
  if ((selected->method == 8) && (hc_zlib_available () == false)) return PARSER_ZLIB_UNAVAILABLE;
  if (stream_read_at (file, size, selected->offset, selected->sample, selected->sample_len) == false) return PARSER_FILE_SIZE;

  u64 identity[5];

  if (stream_identity (file, identity) == false) return PARSER_HAVE_ERRNO;
  if (memcmp (identity, selected->identity, sizeof (identity)) != 0) return PARSER_HASH_VALUE;

  pkzip_stream_t *zip = NULL;

  zip = (pkzip_stream_t *) hash->esalt;

  memcpy (zip->data, selected->sample, selected->sample_len);

  zip->sample_len = selected->sample_len;
  zip->method     = selected->method;

  const u64 fields[6] = { selected->offset, selected->packed, selected->unpacked, selected->crc, selected->method, zip->check };

  for (u32 n = 0; n < 8; n++)
  {
    u32 value = 2166136261 ^ n;

    for (u32 i = 0; i < selected->sample_len; i++) value = (value ^ selected->sample[i]) * 16777619;

    for (u32 i = 0; i < 6; i++)
    {
      for (u32 b = 0; b < 8; b++) value = (value ^ ((fields[i] >> (b * 8)) & 255)) * 16777619;
    }

    hash->salt->salt_buf[n] = value;
  }

  hash->salt->salt_len = 32;

  u32 *digest = NULL;

  digest = (u32 *) hash->digest;

  memcpy (digest, hash->salt->salt_buf, 16);

  return 1;
}

i32 module_hash_binary_count (const hashes_t *hashes)
{
  FILE *file = NULL;

  file = stream_open (hashes->hashfile);

  if (file == NULL) return PARSER_HAVE_ERRNO;

  char prefix[14] = { 0 };

  const u32 length = fread (prefix, 1, 14, file);

  i32 count = 1;

  if ((length == 14) && (memcmp (prefix, "$pkzip-stream$*", 14) == 0))
  {
    rewind (file);

    count = 0;

    char line[1024];

    while (fgets (line, sizeof (line), file) != NULL)
    {
      if (count == INT_MAX)
      {
        fclose (file);

        return PARSER_FILE_SIZE;
      }

      count++;
    }
  }

  const bool failed = (ferror (file) != 0);

  fclose (file);

  if (failed == true) return PARSER_HAVE_ERRNO;

  return count;
}

i32 module_hash_binary_parse (const hashconfig_t *hashconfig, const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, hashes_t *hashes)
{
  FILE *file = NULL;

  file = stream_open (hashes->hashfile);

  if (file == NULL) return PARSER_HAVE_ERRNO;

  char prefix[14] = { 0 };

  const u32 length = fread (prefix, 1, 14, file);

  rewind (file);

  i32 count = 0;

  if ((length == 14) && (memcmp (prefix, "$pkzip-stream$*", 14) == 0))
  {
    char line[1024];

    while (fgets (line, sizeof (line), file) != NULL)
    {
      if ((u32) count >= hashes->hashes_cnt)
      {
        count = PARSER_FILE_SIZE;

        break;
      }

      hash_t *hash = NULL;

      hash = &hashes->hashes_buf[count];

      const u32 len = strcspn (line, "\r\n");
      const i32 rc  = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, line, len);

      if (rc != PARSER_OK)
      {
        count = rc;

        break;
      }

      count++;
    }
  }
  else
  {
    count = stream_archive (file, user_options, &hashes->hashes_buf[0]);
  }

  if (ferror (file) != 0) count = PARSER_HAVE_ERRNO;

  fclose (file);

  return count;
}

bool module_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return true;
}

bool module_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return true;
}

const module_option_t *module_register_options (void)
{
  static const module_option_t options[] =
  {
    {
      .name         = "pkzip-member-index",
      .type         = MODULE_OPTION_TYPE_U32,
      .help_type    = "Num",
      .help         = "Select a PKZIP member by zero-based central directory index",
      .help_example = "--pkzip-member-index=0",
    },
    { .name = NULL },
  };

  return options;
}
