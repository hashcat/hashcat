/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "convert.h"
#include "parser.h"
#include "ext_zlib.h"
#include "event.h"
#include "inc_pkzip_stream.h"
#include "memory.h"
#include "module_options.h"
#include "status_rc.h"

#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>

#if defined (_WIN32)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif

#define STREAM_CHUNK 32768
#define STREAM_PATH  4096

typedef struct pkzip_stream_salt
{
  u64 offset;
  u64 packed;
  u64 unpacked;
  u32 crc;
  u32 method;
  u32 sample_len;
  u8 sample[PKZIP_STREAM_SAMPLE];
  u32 external;
  u64 identity[5];
} pkzip_stream_salt_t;

typedef struct pkzip_stream_worker
{
  u8 input[STREAM_CHUNK];
  u8 output[STREAM_CHUNK];
  FILE *file;
} pkzip_stream_worker_t;

typedef struct pkzip_stream_extra
{
  u32 table[256];
  hashcat_ctx_t *ctx;
  const char *source;
  pkzip_stream_worker_t *workers;
  u32 workers_cnt;
} pkzip_stream_extra_t;

static FILE *stream_open (const char *path)
{
  FILE *file = NULL;

  #if defined (_WIN32)
  wchar_t wide[STREAM_PATH];

  if (MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, STREAM_PATH) == 0) return NULL;

  HANDLE handle = NULL;

  handle = CreateFileW (wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (handle == INVALID_HANDLE_VALUE) return NULL;

  const i32 fd = _open_osfhandle ((intptr_t) handle, _O_RDONLY | _O_BINARY);

  if (fd == -1)
  {
    CloseHandle (handle);

    return NULL;
  }

  file = _fdopen (fd, "rb");

  if (file == NULL) _close (fd);
  #else
  file = fopen (path, "rb");
  #endif

  return file;
}

static bool stream_identity (FILE *file, u64 *identity)
{
  #if defined (_WIN32)
  BY_HANDLE_FILE_INFORMATION info;

  if (GetFileInformationByHandle ((HANDLE) _get_osfhandle (_fileno (file)), &info) == 0) return false;

  identity[0] = info.dwVolumeSerialNumber;
  identity[1] = ((u64) info.nFileIndexHigh << 32) | info.nFileIndexLow;
  identity[2] = ((u64) info.nFileSizeHigh << 32) | info.nFileSizeLow;
  identity[3] = ((u64) info.ftLastWriteTime.dwHighDateTime << 32) | info.ftLastWriteTime.dwLowDateTime;
  identity[4] = 0;
  #else
  struct stat info;

  if (fstat (fileno (file), &info) != 0) return false;

  identity[0] = info.st_dev;
  identity[1] = info.st_ino;
  identity[2] = info.st_size;
  identity[3] = info.st_mtime;
  #if defined (__APPLE__)
  identity[4] = info.st_mtimespec.tv_nsec;
  #else
  identity[4] = info.st_mtim.tv_nsec;
  #endif
  #endif

  return true;
}

static void stream_error (pkzip_stream_extra_t *extra, const char *reason)
{
  hashcat_ctx_t *ctx = NULL;

  ctx = extra->ctx;

  const bool first = status_abort_with_error (ctx, RC_FINAL_ERROR_TASK);

  if (first == true) event_log_error (ctx, "PKZIP source failure: %s.", reason);
}

static bool stream_source_valid (pkzip_stream_extra_t *extra, const pkzip_stream_salt_t *salt)
{
  FILE *file = NULL;

  file = stream_open (extra->source);

  u64 identity[5];

  const bool valid = ((file != NULL) && (stream_identity (file, identity) == true) && (memcmp (identity, salt->identity, sizeof (identity)) == 0));

  if (file != NULL) fclose (file);
  if (valid == false) stream_error (extra, "archive unavailable or changed");

  return valid;
}

static i32 stream_seek (FILE *file, const u64 offset, const i32 origin)
{
  #if defined (_WIN32)
  const i32 rc = _fseeki64 (file, offset, origin);
  #else
  const i32 rc = fseeko (file, (off_t) offset, origin);
  #endif

  return rc;
}

static u64 stream_number (const u8 *text, const u32 len)
{
  u64 value = 0;

  for (u32 i = 0; i < len; i++)
  {
    const u8 c      = text[i];
    const u32 digit = (c >= 'a') ? c - 'a' + 10 : (c >= 'A') ? c - 'A' + 10 : c - '0';

    value = value * 16 + digit;
  }

  return value;
}

static u32 stream_crc (const u32 crc, const u32 value, const u32 *table)
{
  const u32 result = (crc >> 8) ^ table[(crc ^ value) & 255];

  return result;
}

static u32 stream_decrypt_byte (const u32 cipher, u32 *key, const u32 *table)
{
  const u32 t     = (key[2] & 65535) | 3;
  const u32 value = cipher ^ (((t * (t ^ 1)) >> 8) & 255);

  key[0] = stream_crc (key[0], value, table);
  key[1] = (key[1] + (key[0] & 255)) * 0x08088405 + 1;
  key[2] = stream_crc (key[2], key[1] >> 24, table);

  return value;
}

static void stream_decrypt (u8 *buf, const u32 len, u32 *key, const u32 *table)
{
  for (u32 i = 0; i < len; i++) buf[i] = stream_decrypt_byte (buf[i], key, table);
}

static u32 stream_decrypt_crc (const u8 *buf, const u32 len, u32 *key, const u32 *table, u32 crc)
{
  for (u32 i = 0; i < len; i++)
  {
    const u32 value = stream_decrypt_byte (buf[i], key, table);

    crc = stream_crc (crc, value, table);
  }

  return crc;
}

bool module_hook_extra_param_init (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  pkzip_stream_extra_t *extra = NULL;

  extra = (pkzip_stream_extra_t *) hook_extra_param;

  if (user_options->remove == true)
  {
    event_log_error (hashcat_ctx, "PKZIP archive input does not support --remove.");

    return false;
  }

  extra->ctx         = hashcat_ctx;
  extra->source      = user_options_extra->hc_hash;
  extra->workers_cnt = backend_ctx->backend_devices_cnt;
  extra->workers     = hccalloc (extra->workers_cnt, sizeof (pkzip_stream_worker_t));

  if (extra->workers == NULL) return false;

  for (u32 i = 0; i < 256; i++)
  {
    u32 value = i;

    for (u32 bit = 0; bit < 8; bit++) value = (value >> 1) ^ (((value & 1) != 0) ? 0xedb88320 : 0);

    extra->table[i] = value;
  }

  return true;
}

bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  const pkzip_stream_extra_t *extra = NULL;

  extra = (const pkzip_stream_extra_t *) hook_extra_param;

  for (u32 i = 0; (extra->workers != NULL) && (i < extra->workers_cnt); i++)
  {
    if (extra->workers[i].file != NULL) fclose (extra->workers[i].file);
  }

  hcfree (extra->workers);

  return true;
}

void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  pkzip_stream_hook_t *hooks = NULL;

  hooks = (pkzip_stream_hook_t *) device_param->hooks_buf;

  pkzip_stream_hook_t *hook = NULL;

  hook = &hooks[pw_pos];

  const pkzip_stream_salt_t *salts = NULL;

  salts = (const pkzip_stream_salt_t *) hook_salts_buf;

  const pkzip_stream_salt_t *salt = NULL;

  salt = &salts[salt_pos];

  pkzip_stream_extra_t *extra = NULL;

  extra = (pkzip_stream_extra_t *) hook_extra_param;

  pkzip_stream_worker_t *worker = NULL;

  worker = &extra->workers[device_param->device_id];

  if ((salt->external != 0) && (pw_pos < extra->ctx->user_options->hook_threads))
  {
    if (stream_source_valid (extra, salt) == false) return;
  }

  if (hook->state != PKZIP_STREAM_VERIFY) return;

  hook->state = PKZIP_STREAM_REJECT;

  if (salt->external != 0)
  {
    if (stream_source_valid (extra, salt) == false) return;

    if (worker->file == NULL) worker->file = stream_open (extra->source);

    u64 identity[5];

    if ((worker->file == NULL) || (stream_identity (worker->file, identity) == false) || (memcmp (identity, salt->identity, sizeof (identity)) != 0))
    {
      stream_error (extra, "cannot open original archive");

      return;
    }

    if (stream_seek (worker->file, salt->offset, SEEK_SET) != 0)
    {
      stream_error (extra, "cannot seek archive");

      return;
    }

    if ((fread (worker->input, 1, salt->sample_len, worker->file) != salt->sample_len) || (memcmp (worker->input, salt->sample, salt->sample_len) != 0))
    {
      stream_error (extra, "cannot read original member");

      return;
    }

    memmove (worker->input, &worker->input[12], salt->sample_len - 12);
  }
  else
  {
    memcpy (worker->input, &salt->sample[12], salt->sample_len - 12);
  }

  u32 key[3]    = { hook->key[0], hook->key[1], hook->key[2] };
  u64 remaining = salt->packed - salt->sample_len;
  u64 written   = 0;
  u64 position  = salt->sample_len;
  u32 crc       = 0xffffffff;
  bool success  = false;

  hc_z_stream stream = { 0 };

  if (salt->method == 8)
  {
    if (hc_inflate_init (&stream) != HC_Z_OK)
    {
      stream_error (extra, "cannot initialize inflater");

      return;
    }

    stream_decrypt (worker->input, salt->sample_len - 12, key, extra->table);
  }

  stream.next_in  = worker->input;
  stream.avail_in = salt->sample_len - 12;

  while (true)
  {
    if ((stream.avail_in == 0) && (remaining > 0))
    {
      const u32 limit = (position == 12) ? PKZIP_STREAM_SAMPLE : STREAM_CHUNK;
      const u32 count = (remaining > limit) ? limit : (u32) remaining;

      if (salt->external != 0)
      {
        if (fread (worker->input, 1, count, worker->file) != count)
        {
          stream_error (extra, "cannot read archive");

          break;
        }
      }
      else
      {
        memcpy (worker->input, &salt->sample[position], count);
      }

      if (salt->method == 8) stream_decrypt (worker->input, count, key, extra->table);

      stream.next_in  = worker->input;
      stream.avail_in = count;
      remaining -= count;
      position += count;
    }

    if (salt->method == 0)
    {
      crc = stream_decrypt_crc (worker->input, stream.avail_in, key, extra->table, crc);

      written += stream.avail_in;
      stream.avail_in = 0;

      if (remaining > 0) continue;

      success = ((written == salt->unpacked) && ((crc ^ 0xffffffff) == salt->crc));

      break;
    }

    stream.next_out  = worker->output;
    stream.avail_out = STREAM_CHUNK;

    const u32 before = stream.avail_in;
    const i32 rc     = hc_inflate_step (&stream);
    const u32 count  = STREAM_CHUNK - stream.avail_out;

    if (count > salt->unpacked - written) break;

    for (u32 i = 0; i < count; i++) crc = stream_crc (crc, worker->output[i], extra->table);

    written += count;

    if (rc == HC_Z_STREAM_END)
    {
      success = ((remaining == 0) && (stream.avail_in == 0) && (written == salt->unpacked) && ((crc ^ 0xffffffff) == salt->crc));

      break;
    }

    if ((rc != HC_Z_OK) && (rc != -5)) break;
    if ((before == stream.avail_in) && (count == 0)) break;
  }

  if (salt->method == 8) hc_inflate_end (&stream);

  if (salt->external != 0)
  {
    if (stream_source_valid (extra, salt) == false) return;
  }

  if (success == true) hook->state = PKZIP_STREAM_MATCH;
}

i32 module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, void *digest_buf, salt_t *salt, void *esalt_buf, void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, const i32 line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (token));

  token.token_cnt         = 9;
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = "$pkzip-stream$";
  token.len[0]            = 14;
  token.attr[0]           = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

  for (u32 i = 0; i < 8; i++) token.sep[i] = '*';

  for (u32 i = 1; i < 9; i++)
  {
    token.len_min[i] = 1;
    token.len_max[i] = 16;
    token.attr[i]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_BASE16;
  }

  token.len_max[1] = 1;
  token.len_min[5] = 8;
  token.len_max[5] = 8;
  token.len_min[6] = 2;
  token.len_max[6] = 2;
  token.len_min[7] = 24;
  token.len_max[7] = PKZIP_STREAM_SAMPLE * 2;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.len_max[8] = 1;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH;

  const i32 rc = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc != PARSER_OK) return rc;
  if ((token.len[7] & 1) != 0) return PARSER_TOKEN_LENGTH;
  if (token.buf[8][0] != '-') return PARSER_HASH_VALUE;

  pkzip_stream_t *zip = NULL;

  zip = (pkzip_stream_t *) esalt_buf;

  pkzip_stream_salt_t *data = NULL;

  data = (pkzip_stream_salt_t *) hook_salt_buf;

  data->method     = stream_number (token.buf[1], token.len[1]);
  data->offset     = stream_number (token.buf[2], token.len[2]);
  data->packed     = stream_number (token.buf[3], token.len[3]);
  data->unpacked   = stream_number (token.buf[4], token.len[4]);
  data->crc        = stream_number (token.buf[5], token.len[5]);
  data->sample_len = token.len[7] / 2;

  if ((data->method != 0) && (data->method != 8)) return PARSER_PKZIP_CT_UNMATCHED;
  if (data->offset != 0) return PARSER_HASH_VALUE;
  if (data->packed != data->sample_len) return PARSER_HASH_VALUE;
  if (data->unpacked == 0) return PARSER_HASH_VALUE;
  if ((data->method == 0) && (data->unpacked < 4)) return PARSER_PKZIP_MEMBER_TOO_SHORT;
  if ((data->method == 0) && (data->unpacked != data->packed - 12)) return PARSER_HASH_VALUE;
  if ((data->method == 8) && (hc_zlib_available () == false)) return PARSER_ZLIB_UNAVAILABLE;

  for (u32 i = 0; i < data->sample_len; i++) data->sample[i] = hex_to_u8 (&token.buf[7][i * 2]);

  data->external = 0;

  memcpy (zip->data, data->sample, data->sample_len);

  zip->sample_len = data->sample_len;
  zip->method     = data->method;
  zip->check      = stream_number (token.buf[6], token.len[6]);

  for (u32 n = 0; n < 8; n++)
  {
    u32 value = 2166136261 ^ n;

    for (i32 i = 0; i < line_len; i++) value = (value ^ (u8) line_buf[i]) * 16777619;

    salt->salt_buf[n] = value;
  }

  salt->salt_len  = 32;
  salt->salt_iter = 0;

  u32 *digest = NULL;

  digest = (u32 *) digest_buf;

  for (u32 i = 0; i < 4; i++) digest[i] = salt->salt_buf[i];

  return PARSER_OK;
}

i32 module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, const void *hook_salt_buf, const hashinfo_t *hash_info, char *line_buf, const i32 line_size)
{
  const pkzip_stream_t *zip = NULL;

  zip = (const pkzip_stream_t *) esalt_buf;

  const pkzip_stream_salt_t *data = NULL;

  data = (const pkzip_stream_salt_t *) hook_salt_buf;

  if (data->external != 0)
  {
    const i32 count = snprintf (line_buf, line_size, "%s", hash_info->orighash);

    if (count >= line_size) return 0;

    return count;
  }

  static const char format[] = "$pkzip-stream$*%u*%" PRIx64 "*%" PRIx64 "*%" PRIx64 "*%08x*%02x*";
  const i32 header           = snprintf (NULL, 0, format, data->method, data->offset, data->packed, data->unpacked, data->crc, zip->check);
  const u32 needed           = header + data->sample_len * 2 + 2;

  if (needed >= (u32) line_size) return 0;

  i32 count = snprintf (line_buf, line_size, format, data->method, data->offset, data->packed, data->unpacked, data->crc, zip->check);

  for (u32 i = 0; i < data->sample_len; i++) count += snprintf (&line_buf[count], line_size - count, "%02x", data->sample[i]);

  line_buf[count++] = '*';

  line_buf[count++] = '-';

  line_buf[count] = 0;

  return count;
}

#include "pkzip_stream.c"

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = ATTACK_EXEC_OUTSIDE_KERNEL;

  return value;
}

u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 0;

  return value;
}

u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 1;

  return value;
}

u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 2;

  return value;
}

u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 3;

  return value;
}

u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = DGST_SIZE_4_4;

  return value;
}

u32 module_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = HASH_CATEGORY_ARCHIVE;

  return value;
}

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  static const char value[] = "PKZIP (Streaming)";

  return value;
}

u64 module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = 17240;

  return value;
}

u64 module_kern_bits (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = KERN_BIT_HOOK23;

  return value;
}

u64 module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = OPTS_TYPE_STOCK_MODULE | OPTS_TYPE_PT_GENERATE_LE | OPTS_TYPE_HASH_COPY | OPTS_TYPE_BINARY_HASHFILE | OPTS_TYPE_BINARY_HASHFILE_OPTIONAL | OPTS_TYPE_BINARY_HASHFILE_DIRECT | OPTS_TYPE_AUTODETECT_DISABLE | OPTS_TYPE_SUGGEST_KG;

  return value;
}

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = OPTI_TYPE_ZERO_BYTE;

  return value;
}

u32 module_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = SALT_TYPE_EMBEDDED;

  return value;
}

const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  static const char value[] = "$pkzip-stream$*0*0*5a*4e*c7da6c5b*c7*963adfae487332dce29a57023cf0bc4b9e4d1273142a8c580c7212de0ec7dc414e7e5f6b09e2e0f0bb7bedb35cb5cd3c62668ea2257c89c96c221a8068db1c001f90341405a2b38794c204c11956b9a676bf465416d53a119039*-";

  return value;
}

const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  static const char value[] = "hashcat";

  return value;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = sizeof (pkzip_stream_t);

  return value;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = sizeof (pkzip_stream_tmp_t);

  return value;
}

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = sizeof (pkzip_stream_hook_t);

  return value;
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = sizeof (pkzip_stream_salt_t);

  return value;
}

u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 value = sizeof (pkzip_stream_extra_t);

  return value;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 1;

  return value;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 1;

  return value;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 value = 256;

  return value;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size      = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice           = MODULE_DEFAULT;
  module_ctx->module_attack_exec             = module_attack_exec;
  module_ctx->module_benchmark_esalt         = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt     = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask          = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset       = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost          = MODULE_DEFAULT;
  module_ctx->module_bridge_name             = MODULE_DEFAULT;
  module_ctx->module_bridge_type             = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel        = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice       = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0               = module_dgst_pos0;
  module_ctx->module_dgst_pos1               = module_dgst_pos1;
  module_ctx->module_dgst_pos2               = module_dgst_pos2;
  module_ctx->module_dgst_pos3               = module_dgst_pos3;
  module_ctx->module_dgst_size               = module_dgst_size;
  module_ctx->module_esalt_size              = module_esalt_size;
  module_ctx->module_extra_buffer_size       = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size          = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block    = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format   = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count       = module_hash_binary_count;
  module_ctx->module_hash_binary_parse       = module_hash_binary_parse;
  module_ctx->module_hash_binary_save        = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile     = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash   = MODULE_DEFAULT;
  module_ctx->module_hash_decode             = module_hash_decode;
  module_ctx->module_hash_encode_status      = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile     = MODULE_DEFAULT;
  module_ctx->module_hash_encode             = module_hash_encode;
  module_ctx->module_hash_hints              = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest      = MODULE_DEFAULT;
  module_ctx->module_hash_mode               = MODULE_DEFAULT;
  module_ctx->module_hash_category           = module_hash_category;
  module_ctx->module_hash_name               = module_hash_name;
  module_ctx->module_hash_recipe             = MODULE_DEFAULT;
  module_ctx->module_hashes_count_min        = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max        = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable           = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size   = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init   = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term   = module_hook_extra_param_term;
  module_ctx->module_hook12                  = MODULE_DEFAULT;
  module_ctx->module_hook23                  = module_hook23;
  module_ctx->module_hook_salt_size          = module_hook_salt_size;
  module_ctx->module_hook_size               = module_hook_size;
  module_ctx->module_jit_build_options       = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable       = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min        = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max        = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min        = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max      = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min      = MODULE_DEFAULT;
  module_ctx->module_kern_bits               = module_kern_bits;
  module_ctx->module_kern_type               = module_kern_type;
  module_ctx->module_kern_type_dynamic       = MODULE_DEFAULT;
  module_ctx->module_length_sort             = MODULE_DEFAULT;
  module_ctx->module_opti_type               = module_opti_type;
  module_ctx->module_opts_type               = module_opts_type;
  module_ctx->module_outfile_check_disable   = module_outfile_check_disable;
  module_ctx->module_outfile_check_nocomp    = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check    = MODULE_DEFAULT;
  module_ctx->module_potfile_disable         = module_potfile_disable;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column           = MODULE_DEFAULT;
  module_ctx->module_pw_max                  = module_pw_max;
  module_ctx->module_pw_min                  = MODULE_DEFAULT;
  module_ctx->module_register_options        = module_register_options;
  module_ctx->module_salt_max                = MODULE_DEFAULT;
  module_ctx->module_salt_min                = MODULE_DEFAULT;
  module_ctx->module_salt_type               = module_salt_type;
  module_ctx->module_separator               = MODULE_DEFAULT;
  module_ctx->module_st_hash                 = module_st_hash;
  module_ctx->module_st_pass                 = module_st_pass;
  module_ctx->module_tmp_size                = module_tmp_size;
  module_ctx->module_unstable_warning        = MODULE_DEFAULT;
  module_ctx->module_usage_notice            = MODULE_DEFAULT;
  module_ctx->module_warmup_disable          = MODULE_DEFAULT;
}
