
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Shared by the BIP39 modules 36000 and 36001, the way scrypt_common.c is shared by the scrypt
// modules: the derivation path parser, the address decoders and the tuning bounds. The esalt
// structs stay with the modes, so the functions here take the fields they work on as pointers.

#include <inttypes.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "emu_inc_hash_base58.h"

#define BIP39_MAX_PATH_DEPTH 16u
#define BIP39_TARGET_IL_HEX   0u
#define BIP39_TARGET_P2SH     1u
#define BIP39_TARGET_P2PKH    2u
#define BIP39_TARGET_P2WPKH   3u
#define BIP39_PATH_KIND_FIXED   0u
#define BIP39_PATH_KIND_DYNAMIC 1u
#define BIP39_DYNAMIC_KIND_RANGE 0u
#define BIP39_DYNAMIC_KIND_LIST  1u
#define BIP39_MAX_DYNAMIC_SEGMENTS      4u
#define BIP39_MAX_DYNAMIC_VALUES        256u
#define BIP39_MAX_HITS                  16u
#define BIP39_MAX_DYNAMIC_RANGE_SPAN  4096u

typedef struct bip39_dynamic_segment
{
  u32 position;
  u32 kind;
  u32 count;
  u32 start;
  u32 end;
  u32 step;
  u32 values_offset;
} bip39_dynamic_segment_t;

static bool bip39_parse_uint_substring (const char *start, const char *end, u32 *value)
{
  while ((start < end) && isspace ((unsigned char) *start)) start++;
  while ((end > start) && isspace ((unsigned char) end[-1])) end--;

  if (start >= end) return false;

  u64 acc = 0;

  for (const char *p = start; p < end; p++)
  {
    const unsigned char ch = (unsigned char) *p;

    if ((ch < '0') || (ch > '9')) return false;

    acc = (acc * 10u) + (u64) (ch - '0');

    if (acc > 0x7fffffffULL) return false;
  }

  *value = (u32) acc;

  return true;
}

static int bip39_bech32_char_to_value (const u8 c)
{
  switch (c)
  {
  case 'q':
    return 0;
  case 'p':
    return 1;
  case 'z':
    return 2;
  case 'r':
    return 3;
  case 'y':
    return 4;
  case '9':
    return 5;
  case 'x':
    return 6;
  case '8':
    return 7;
  case 'g':
    return 8;
  case 'f':
    return 9;
  case '2':
    return 10;
  case 't':
    return 11;
  case 'v':
    return 12;
  case 'd':
    return 13;
  case 'w':
    return 14;
  case '0':
    return 15;
  case 's':
    return 16;
  case '3':
    return 17;
  case 'j':
    return 18;
  case 'n':
    return 19;
  case '5':
    return 20;
  case '4':
    return 21;
  case 'k':
    return 22;
  case 'h':
    return 23;
  case 'c':
    return 24;
  case 'e':
    return 25;
  case '6':
    return 26;
  case 'm':
    return 27;
  case 'u':
    return 28;
  case 'a':
    return 29;
  case '7':
    return 30;
  case 'l':
    return 31;
  default:
    return -1;
  }
}

static const u32 bip39_bech32_generator[5] = {
  0x3b6a57b2,
  0x26508e6d,
  0x1ea119fa,
  0x3d4233dd,
  0x2a1462b3
};

#define BECH32_CONST   1u
#define BECH32M_CONST  0x2bc830a3u

static u32 bip39_bech32_polymod (const u8 *values, const u32 len)
{
  u32 chk = 1u;

  for (u32 i = 0; i < len; i++)
  {
    const u32 top = chk >> 25;

    chk = ((chk & 0x1ffffffu) << 5) ^ values[i];

    for (u32 j = 0; j < 5; j++)
    {
      if ((top >> j) & 1u) chk ^= bip39_bech32_generator[j];
    }
  }

  return chk;
}

static u32 bip39_bech32_hrp_expand (const u8 *hrp, const u32 hrp_len, u8 *out)
{
  for (u32 i = 0; i < hrp_len; i++) out[i] = (u8) (hrp[i] >> 5);

  out[hrp_len] = 0;

  for (u32 i = 0; i < hrp_len; i++) out[hrp_len + 1 + i] = (u8) (hrp[i] & 31u);

  return (hrp_len * 2u) + 1u;
}

static bool bip39_bech32_convert_bits (u8 *out, u32 *out_len, const u8 *in, const u32 in_len, const u32 from_bits, const u32 to_bits)
{
  u32 acc = 0;
  u32 bits = 0;
  const u32 maxv = (1u << to_bits) - 1u;
  u32 pos = 0;

  for (u32 i = 0; i < in_len; i++)
  {
    const u32 value = in[i];

    if (value >= (1u << from_bits)) return false;

    acc = (acc << from_bits) | value;
    bits += from_bits;

    while (bits >= to_bits)
    {
      bits -= to_bits;
      out[pos++] = (u8) ((acc >> bits) & maxv);
    }
  }

  if (bits >= from_bits) return false;
  if (bits > 0) return false;

  *out_len = pos;

  return true;
}

static bool bip39_parse_derivation_path (const char *path_str, u32 *path_indices, u32 *path_kind, bip39_dynamic_segment_t *dynamic_segments, u32 *dynamic_values, u32 *out_path_depth, u32 *out_dynamic_count, u32 *out_value_total)
{
  if (path_str[0] != 'm') return false;

  u32 depth = 0;
  u32 dynamic_count = 0;
  u32 values_offset = 0;

  if (path_str[1] == 0)
  {
    *out_path_depth = 0;
    *out_dynamic_count = 0;
    *out_value_total = 0;

    return true;
  }

  if (path_str[1] != '/') return false;

  const char *cursor = path_str + 2;

  while (*cursor)
  {
    if (depth >= BIP39_MAX_PATH_DEPTH) return false;

    if (*cursor == '{')
    {
      const char *closing = strchr (cursor, '}');

      if (closing == 0) return false;

      const char *body_start = cursor + 1;
      const char *body_end = closing;

      if (body_start == body_end) return false;

      const char *post = closing + 1;
      bool hardened = false;

      if ((*post == '\'') || (*post == 'h') || (*post == 'H'))
      {
        hardened = true;
        post++;
      }

      if (dynamic_count >= BIP39_MAX_DYNAMIC_SEGMENTS) return false;

      bip39_dynamic_segment_t *seg = &dynamic_segments[dynamic_count];

      seg->position = depth;
      seg->kind = BIP39_DYNAMIC_KIND_RANGE;
      seg->count = 0;
      seg->start = 0;
      seg->end = 0;
      seg->step = 0;
      seg->values_offset = 0;

      bool has_comma = false;
      bool has_dash = false;

      for (const char *p = body_start; p < body_end; p++)
      {
        if (*p == ',')
          has_comma = true;
        else if (*p == '-')
          has_dash = true;
      }

      if (has_comma && has_dash) return false;

      if (has_dash && (has_comma == false))
      {
        const char *dash = strchr (body_start, '-');

        if ((dash == 0) || (dash >= body_end)) return false;

        u32 start_value = 0;
        u32 end_value = 0;

        if (bip39_parse_uint_substring (body_start, dash, &start_value) == false) return false;
        if (bip39_parse_uint_substring (dash + 1, body_end, &end_value) == false) return false;

        if (start_value > end_value) return false;

        const u32 span = (end_value - start_value) + 1u;

        if (span > BIP39_MAX_DYNAMIC_RANGE_SPAN) return false;

        if (hardened)
        {
          start_value |= 0x80000000u;
          end_value |= 0x80000000u;
        }

        seg->kind = BIP39_DYNAMIC_KIND_RANGE;
        seg->start = start_value;
        seg->end = end_value;
        seg->step = 1u;
        seg->count = span;
        seg->values_offset = 0;

        path_indices[depth] = start_value;
      }
      else
      {
        u32 local_count = 0;
        const char *item_start = body_start;

        seg->kind = BIP39_DYNAMIC_KIND_LIST;
        seg->values_offset = values_offset;

        while (item_start < body_end)
        {
          const char *item_end = item_start;

          while ((item_end < body_end) && (*item_end != ',')) item_end++;

          u32 value = 0;

          if (bip39_parse_uint_substring (item_start, item_end, &value) == false) return false;

          if ((values_offset + local_count) >= BIP39_MAX_DYNAMIC_VALUES) return false;

          if (hardened)
          {
            value |= 0x80000000u;
          }

          dynamic_values[values_offset + local_count] = value;

          local_count++;

          if (item_end == body_end) break;

          item_start = item_end + 1;
        }

        if (local_count == 0) return false;

        seg->count = local_count;

        path_indices[depth] = dynamic_values[values_offset];

        values_offset += local_count;
      }

      path_kind[depth] = BIP39_PATH_KIND_DYNAMIC;

      dynamic_count++;
      depth++;

      cursor = post;
    }
    else
    {
      const char *start = cursor;

      while ((*cursor >= '0') && (*cursor <= '9')) cursor++;

      if (start == cursor) return false;

      u32 value = 0;

      if (bip39_parse_uint_substring (start, cursor, &value) == false) return false;

      if ((*cursor == '\'') || (*cursor == 'h') || (*cursor == 'H'))
      {
        value |= 0x80000000u;
        cursor++;
      }

      path_indices[depth] = value;
      path_kind[depth] = BIP39_PATH_KIND_FIXED;

      depth++;
    }

    if (*cursor == 0)
    {
      break;
    }

    if (*cursor != '/') return false;

    cursor++;
    if (*cursor == 0) return false;
  }

  *out_path_depth = depth;
  *out_dynamic_count = dynamic_count;
  *out_value_total = values_offset;

  return true;
}

// The number of path combinations the dynamic segments produce. A zero-count segment makes the
// path unmatchable, and the product saturates rather than wrapping.

static u64 bip39_path_combo_total (const bip39_dynamic_segment_t *dynamic_segments, const u32 dynamic_count)
{
  u64 combo_total = 1;

  for (u32 i = 0; i < dynamic_count; i++)
  {
    const u32 segment_count = dynamic_segments[i].count;

    if (segment_count == 0) return 0;

    if (combo_total > (0xffffffffffffffffULL / segment_count)) return 0xffffffffffffffffULL;

    combo_total *= (u64) segment_count;
  }

  return combo_total;
}

static int bip39_decode_address_script_hash (const u8 *address, const u32 address_len, u32 *target_hash, u32 *target_type, u32 *digest)
{
  u8 decoded[64];

  memset (decoded, 0, sizeof (decoded));

  u32 decoded_len = (u32) sizeof (decoded);

  const bool ok = b58dec (decoded, &decoded_len, address, address_len);

  if (ok == false) return PARSER_HASH_LENGTH;

  if (decoded_len != 25) return PARSER_HASH_LENGTH;

  const u32 offset = (u32) sizeof (decoded) - decoded_len;

  u32 decoded_words[16];

  memset (decoded_words, 0, sizeof (decoded_words));

  u8 *decoded_bytes = (u8 *) decoded_words;

  for (u32 i = 0; i < decoded_len; i++)
  {
    decoded_bytes[i] = decoded[offset + i];
  }

  if (b58check_25 (decoded_words) == false) return PARSER_HASH_ENCODING;

  const u8 version = decoded_bytes[0];

  const bool is_p2sh = (version == 0x05) || (version == 0xC4);
  const bool is_p2pkh = (version == 0x00) || (version == 0x6F);

  if ((is_p2sh == false) && (is_p2pkh == false)) return PARSER_HASH_VALUE;

  const u8 *hash_bytes = decoded_bytes + 1;

  memset (target_hash, 0, 5 * sizeof (u32));

  for (u32 i = 0; i < 5; i++)
  {
    const u32 idx = i * 4;

    const u32 word = ((u32) hash_bytes[idx + 0] << 0) | ((u32) hash_bytes[idx + 1] << 8) | ((u32) hash_bytes[idx + 2] << 16) | ((u32) hash_bytes[idx + 3] << 24);

    target_hash[i] = word;

    if (i < 4)
    {
      digest[i] = word;
    }
  }

  digest[4] = target_hash[4];

  *target_type = is_p2sh ? BIP39_TARGET_P2SH : BIP39_TARGET_P2PKH;

  return PARSER_OK;
}

static int bip39_decode_address_bech32 (const u8 *address, const u32 address_len, u32 *target_hash, u32 *target_type, u32 *digest)
{
  if (address_len < 8) return PARSER_HASH_LENGTH;

  bool has_lower = false;
  bool has_upper = false;

  for (u32 i = 0; i < address_len; i++)
  {
    const unsigned char ch = address[i];

    if ((ch < 33) || (ch > 126)) return PARSER_HASH_ENCODING;
    if ((ch >= 'a') && (ch <= 'z'))
      has_lower = true;
    else if ((ch >= 'A') && (ch <= 'Z'))
      has_upper = true;
  }

  if (has_lower && has_upper) return PARSER_HASH_ENCODING;

  u8 lower_addr[96];

  for (u32 i = 0; i < address_len; i++)
  {
    const unsigned char ch = address[i];

    lower_addr[i] = (has_upper) ? (u8) tolower (ch) : ch;
  }

  u32 separator_index = 0xffffffffu;

  for (u32 i = 0; i < address_len; i++)
  {
    if (lower_addr[i] == '1')
    {
      separator_index = i;
      break;
    }
  }

  if ((separator_index == 0xffffffffu) || (separator_index == 0)) return PARSER_HASH_VALUE;

  const u32 hrp_len = separator_index;
  const u32 data_len = address_len - separator_index - 1u;

  if (data_len < 6u) return PARSER_HASH_LENGTH;

  const u8 *hrp = lower_addr;
  const u8 *data = lower_addr + separator_index + 1u;

  u8 data_values[90];

  for (u32 i = 0; i < data_len; i++)
  {
    const int value = bip39_bech32_char_to_value (data[i]);

    if (value < 0) return PARSER_HASH_VALUE;
    data_values[i] = (u8) value;
  }

  u8 hrp_expand[200];
  const u32 hrp_expand_len = bip39_bech32_hrp_expand (hrp, hrp_len, hrp_expand);

  u8 polymod_input[260];

  for (u32 i = 0; i < hrp_expand_len; i++) polymod_input[i] = hrp_expand[i];
  for (u32 i = 0; i < data_len; i++) polymod_input[hrp_expand_len + i] = data_values[i];

  const u32 polymod = bip39_bech32_polymod (polymod_input, hrp_expand_len + data_len);

  u32 encoding = 0u;

  if (polymod == BECH32_CONST)
    encoding = 0u;
  else if (polymod == BECH32M_CONST)
    encoding = 1u;
  else
    return PARSER_HASH_VALUE;

  if (data_len < 7u) return PARSER_HASH_LENGTH;

  const u32 payload_len = data_len - 6u;

  if (payload_len < 1u) return PARSER_HASH_VALUE;

  const u8 witness_version = data_values[0];

  if (witness_version > 16u) return PARSER_HASH_VALUE;

  const u8 *prog5 = data_values + 1u;
  const u32 prog5_len = payload_len - 1u;

  u8 program[40];
  u32 program_len = 0;

  if (bip39_bech32_convert_bits (program, &program_len, prog5, prog5_len, 5u, 8u) == false) return PARSER_HASH_VALUE;

  if ((program_len < 2u) || (program_len > 40u)) return PARSER_HASH_VALUE;

  if ((witness_version == 0u) && (encoding != 0u)) return PARSER_HASH_VALUE;
  if ((witness_version > 0u) && (encoding != 1u)) return PARSER_HASH_VALUE;

  if ((witness_version != 0u) || (program_len != 20u)) return PARSER_HASH_VALUE;

  *target_type = BIP39_TARGET_P2WPKH;

  memset (target_hash, 0, 5 * sizeof (u32));

  for (u32 i = 0; i < 5; i++)
  {
    const u32 idx = i * 4u;

    const u32 word = ((u32) program[idx + 0] << 0) | ((u32) program[idx + 1] << 8) | ((u32) program[idx + 2] << 16) | ((u32) program[idx + 3] << 24);

    target_hash[i] = word;

    if (i < 4)
    {
      digest[i] = word;
    }
  }

  digest[4] = target_hash[4];

  return PARSER_OK;
}

// The target is either the left half of the master key as 32 hex digits or a P2PKH, P2SH or
// P2WPKH address. Only the first four hash words go through the bitmap, so the fifth lives in the
// digest as well.

static int bip39_decode_target (const u8 *address_pos, const u32 address_len, u32 *target_hash, u32 *target_type, u32 *digest)
{
  digest[0] = 0;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;
  digest[4] = 0;

  if (address_len == 32)
  {
    if (is_valid_hex_string (address_pos, address_len) == false) return PARSER_HASH_VALUE;

    digest[0] = byte_swap_32 (hex_to_u32 (address_pos + 0));
    digest[1] = byte_swap_32 (hex_to_u32 (address_pos + 8));
    digest[2] = byte_swap_32 (hex_to_u32 (address_pos + 16));
    digest[3] = byte_swap_32 (hex_to_u32 (address_pos + 24));
    digest[4] = 0;

    *target_type = BIP39_TARGET_IL_HEX;

    return PARSER_OK;
  }

  bool maybe_bech32 = false;

  if (address_len >= 3)
  {
    const u8 c0 = (u8) tolower (address_pos[0]);
    const u8 c1 = (u8) tolower (address_pos[1]);

    if ((c0 == 'b') && (c1 == 'c'))
    {
      if (address_len >= 3)
      {
        const u8 c2 = (u8) tolower (address_pos[2]);

        if (c2 == '1')
        {
          maybe_bech32 = true;
        }
        else if ((address_len >= 5) && (c2 == 'r') && ((u8) tolower (address_pos[3]) == 't') && ((u8) tolower (address_pos[4]) == '1'))
        {
          maybe_bech32 = true;
        }
      }
    }
    else if ((c0 == 't') && (c1 == 'b'))
    {
      if ((address_len >= 3) && ((u8) tolower (address_pos[2]) == '1'))
      {
        maybe_bech32 = true;
      }
    }
  }

  if (maybe_bech32)
  {
    return bip39_decode_address_bech32 (address_pos, address_len, target_hash, target_type, digest);
  }

  return bip39_decode_address_script_hash (address_pos, address_len, target_hash, target_type, digest);
}

static int bip39_append_combo_status (const u64 combos, char *line_buf, const int line_size, const int line_len)
{
  if (combos == 0)
  {
    return line_len;
  }

  const int remain = line_size - line_len;

  const int extra = snprintf (line_buf + line_len, remain, " [combos=%llu]", (unsigned long long) combos);

  if (extra >= remain)
  {
    // Truncated; ensure caller does not overrun
    return line_size - 1;
  }

  return line_len + extra;
}

static char *bip39_module_extra_tuningdb_block (const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, MAYBE_UNUSED const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  char *sanitized = hcstrdup (device_param->device_name ? device_param->device_name : "DEVICE");

  // tuning_db_search_real () turns spaces into underscores and leaves every other character
  // alone, so a row keyed on anything more than that can never be found. Replacing only spaces
  // is what scrypt_common.c, argon2_common.c and yescrypt_common.c all do.

  for (size_t i = 0; sanitized[i] != '\0'; i++)
  {
    if (sanitized[i] == ' ') sanitized[i] = '_';
  }

  const size_t buf_sz = 512;
  char *lines_buf = (char *) hcmalloc (buf_sz);

  size_t offset = 0;

  const u32 hash_mode = hashconfig->hash_mode;

  offset += snprintf (lines_buf + offset, buf_sz - offset, "# module_%u tuningdb\n", hash_mode);

  if (device_param->is_cuda)
  {
    snprintf (lines_buf + offset, buf_sz - offset, "%s * %u N A A\n", sanitized, hash_mode);
  }
  else if ((device_param->is_opencl) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
  {
    snprintf (lines_buf + offset, buf_sz - offset, "# NVIDIA OpenCL uses autotune defaults (%s)\n", sanitized);
  }
  else if ((device_param->is_opencl) && ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) || (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_BEIGNET)))
  {
    // A conservative geometry on Intel, whose driver is slow to compile this kernel. The columns
    // are vector width 1, kernel accel 2 and kernel loops 4. A tuningdb line has no thread count
    // column at all, so a thread count cannot be expressed here.
    snprintf (lines_buf + offset, buf_sz - offset, "%s * %u 1 2 4\n", sanitized, hash_mode);
  }
  else
  {
    snprintf (lines_buf + offset, buf_sz - offset, "# no dynamic tuning for %s\n", sanitized);
  }

  hcfree (sanitized);

  return lines_buf;
}

// Autotune walks kernel_accel up towards this bound, and a trial launch of this kernel is
// expensive, so an unbounded walk spends longer choosing a geometry than the geometry saves.
// Measured on a Radeon Pro W7800: the default bound of 1024 costs 103 seconds of autotune to
// arrive at Accel:2, and 64 reaches the same answer in 27. A tighter bound than this starts to
// move autotune's thread choice down from 1024, which costs throughput, so 64 is the floor.

static u32 bip39_module_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_max = 64;

  return kernel_accel_max;
}
