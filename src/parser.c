/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// One line of a hash file, taken apart into the fields a module reads, put back together for the
// potfile and the status display, and explained when it is rejected.
//
// This is the half of module_hash_decode() and module_hash_encode() that no module writes for
// itself. A module says where the separators are and how long each field may be, and the tokenizer
// does the walking, the validating and the reporting. Everything here is called from a plugin, so it
// is kept apart from the rest of the helpers: a plugin that parses a hash line must not have to link
// the code that reads the environment or asks the operating system how much memory is free.

#include "common.h"
#include "types.h"
#include "convert.h"
#include "parser.h"

static const char *const PA_000 = "OK";
static const char *const PA_001 = "Ignored due to comment";
static const char *const PA_002 = "Ignored due to zero length";
static const char *const PA_003 = "Line-length exception";
static const char *const PA_004 = "Hash-length exception";
static const char *const PA_005 = "Hash-value exception";
static const char *const PA_006 = "Salt-length exception";
static const char *const PA_007 = "Salt-value exception";
static const char *const PA_008 = "Salt-iteration count exception";
static const char *const PA_009 = "Separator unmatched";
static const char *const PA_010 = "Signature unmatched";
static const char *const PA_011 = "Invalid hccapx file size";
static const char *const PA_012 = "Invalid hccapx eapol size";
static const char *const PA_013 = "Invalid psafe2 filesize";
static const char *const PA_014 = "Invalid psafe3 filesize";
static const char *const PA_015 = "Invalid truecrypt filesize";
static const char *const PA_016 = "Invalid veracrypt filesize";
static const char *const PA_017 = "Invalid SIP directive, only MD5 is supported";
static const char *const PA_018 = "Hash-file exception";
static const char *const PA_019 = "Hash-encoding exception";
static const char *const PA_020 = "Salt-encoding exception";
static const char *const PA_021 = "Invalid LUKS filesize";
static const char *const PA_022 = "Invalid LUKS identifier";
static const char *const PA_023 = "Invalid LUKS version";
static const char *const PA_024 = "Invalid or unsupported LUKS cipher type";
static const char *const PA_025 = "Invalid or unsupported LUKS cipher mode";
static const char *const PA_026 = "Invalid or unsupported LUKS hash type";
static const char *const PA_027 = "Invalid LUKS key size";
static const char *const PA_028 = "Disabled LUKS key detected";
static const char *const PA_029 = "Invalid LUKS key AF stripes count";
static const char *const PA_030 = "Invalid combination of LUKS hash type and cipher type";
static const char *const PA_031 = "Invalid hccapx signature";
static const char *const PA_032 = "Invalid hccapx version";
static const char *const PA_033 = "Invalid hccapx message pair";
static const char *const PA_034 = "Token encoding exception";
static const char *const PA_035 = "Token length exception";
static const char *const PA_036 = "Insufficient entropy exception";
static const char *const PA_037 = "Hash contains unsupported compression type for current mode";
static const char *const PA_038 = "Invalid key size";
static const char *const PA_039 = "Invalid block size";
static const char *const PA_040 = "Invalid or unsupported cipher";
static const char *const PA_041 = "Invalid filesize";
static const char *const PA_042 = "IV length exception";
static const char *const PA_043 = "CT length exception";
static const char *const PA_044 = "PT length exception";
static const char *const PA_045 = "PT offset exception";
static const char *const PA_046 = "Invalid or unsupported CryptoAPI hash type";
static const char *const PA_047 = "Invalid CryptoAPI key size";
static const char *const PA_255 = "Unknown error";

// input_tokenizer() records the offending part of the input line in here when it rejects that line.
// The core reads the message back with parser_error_string() right after the module_hash_decode()
// that failed, and drops it with parser_error_reset() right before the next one, so a message is
// never shown for a line that did not produce it.
//
// A module calls the core's input_tokenizer() through the library, so the write and the read reach
// the same variables. The static arrangement links a copy of this file into every module instead, so
// there the core reads variables nothing wrote and reports the plain reason.
//
// The storage is per thread because more than one thread parses hash lines. The outfile check thread
// runs for the whole session, not only while the hash list is being loaded.

// The message is built from four pieces and is sized from them, so the compiler can see that the
// longest message it could produce still fits. A buffer sized by a guess instead raises
// -Wformat-truncation at -O0 and -Og, where the reason string is not a constant the compiler can
// measure and it has to assume every piece is at its longest at the same time.

#define TOKENIZER_ERROR_SNIPPET_LEN   64
#define TOKENIZER_ERROR_ESCAPED_LEN   (TOKENIZER_ERROR_SNIPPET_LEN * 4 + 8)
#define TOKENIZER_ERROR_SEPARATOR_LEN 24
#define TOKENIZER_ERROR_LENGTH_LEN    64
#define TOKENIZER_ERROR_REASON_LEN    64

#define TOKENIZER_ERROR_MSG_LEN       (TOKENIZER_ERROR_REASON_LEN + TOKENIZER_ERROR_ESCAPED_LEN + TOKENIZER_ERROR_SEPARATOR_LEN + TOKENIZER_ERROR_LENGTH_LEN + 8)

static __thread char tokenizer_error_msg[TOKENIZER_ERROR_MSG_LEN];
static __thread bool tokenizer_error_set    = false;
static __thread u32  tokenizer_error_status = 0;

// len_expected and len_actual are optional, -1 omits them, and they append a clause describing the
// mismatch. That is "(only X allowed but Y entered)" when too many characters were found, and
// "(X required but only Y entered)" when too few were. separator_expected is optional too, 0 omits
// it, and it appends "(expected 'X')" naming the separator byte input_tokenizer() was scanning for
// when it ran out of input, for instance because a trailing field was dropped entirely and there was
// nothing left to find the separator in.

static void tokenizer_error_capture (const u32 parser_status, const char *reason, const u8 *buf, const int len, const int len_expected, const int len_actual, const u8 separator_expected)
{
  char escaped[TOKENIZER_ERROR_ESCAPED_LEN];

  escaped[0] = 0;

  if (len > 0)
  {
    const int cap = MIN (len, TOKENIZER_ERROR_SNIPPET_LEN);

    int escaped_len = 0;

    for (int i = 0; i < cap; i++)
    {
      const u8 c = buf[i];

      if ((c >= 0x20) && (c < 0x7f) && (c != '\'') && (c != '\\'))
      {
        escaped[escaped_len] = (char) c;

        escaped_len += 1;
      }
      else
      {
        escaped_len += snprintf (&escaped[escaped_len], 5, "\\x%02x", c);
      }
    }

    if (len > cap)
    {
      escaped[escaped_len + 0] = '.';
      escaped[escaped_len + 1] = '.';
      escaped[escaped_len + 2] = '.';

      escaped_len += 3;
    }

    escaped[escaped_len] = 0;
  }

  char length_clause[TOKENIZER_ERROR_LENGTH_LEN];

  length_clause[0] = 0;

  if (len_expected >= 0)
  {
    if (len_actual > len_expected)
    {
      snprintf (length_clause, sizeof (length_clause), " (only %d allowed but %d entered)", len_expected, len_actual);
    }
    else if (len_actual < len_expected)
    {
      snprintf (length_clause, sizeof (length_clause), " (%d required but only %d entered)", len_expected, len_actual);
    }
  }

  char separator_clause[TOKENIZER_ERROR_SEPARATOR_LEN];

  separator_clause[0] = 0;

  if (separator_expected != 0)
  {
    if ((separator_expected >= 0x20) && (separator_expected < 0x7f))
    {
      snprintf (separator_clause, sizeof (separator_clause), " (expected '%c')", separator_expected);
    }
    else
    {
      snprintf (separator_clause, sizeof (separator_clause), " (expected '\\x%02x')", separator_expected);
    }
  }

  if (escaped[0] != 0)
  {
    snprintf (tokenizer_error_msg, sizeof (tokenizer_error_msg), "%s near '%s'%s%s", reason, escaped, separator_clause, length_clause);
  }
  else
  {
    // nothing useful to add, the caller falls back to the plain reason

    if ((length_clause[0] == 0) && (separator_clause[0] == 0)) return;

    snprintf (tokenizer_error_msg, sizeof (tokenizer_error_msg), "%s%s%s", reason, separator_clause, length_clause);
  }

  tokenizer_error_status = parser_status;
  tokenizer_error_set    = true;
}

// call this right before a module_hash_decode(), so that a message left behind by an earlier line
// can never be reported for this one

void parser_error_reset (void)
{
  tokenizer_error_set = false;
}

// call this right after a module_hash_decode() that failed, while the message is still known to
// belong to that call. A status the tokenizer did not record is described by strparser() alone, so
// this reads as the detailed strparser() and every reporting site can use it.
//
// Every site that writes a line for a person to read, that is. The message quotes the input, and the
// input decides what is in it, so the message can hold anything the line held. That is fine in a
// sentence and it is not fine in a record whose fields are separated by a colon, which is what
// --machine-readable writes. Those sites keep strparser(), whose answers are a closed set with no
// separator in any of them.

const char *parser_error_string (const u32 parser_status)
{
  if (tokenizer_error_set == false) return strparser (parser_status);

  if (tokenizer_error_status != parser_status) return strparser (parser_status);

  return tokenizer_error_msg;
}
const char *strparser (const u32 parser_status)
{
  switch (parser_status)
  {
    case PARSER_OK:                   return PA_000;
    case PARSER_COMMENT:              return PA_001;
    case PARSER_GLOBAL_ZERO:          return PA_002;
    case PARSER_GLOBAL_LENGTH:        return PA_003;
    case PARSER_HASH_LENGTH:          return PA_004;
    case PARSER_HASH_VALUE:           return PA_005;
    case PARSER_SALT_LENGTH:          return PA_006;
    case PARSER_SALT_VALUE:           return PA_007;
    case PARSER_SALT_ITERATION:       return PA_008;
    case PARSER_SEPARATOR_UNMATCHED:  return PA_009;
    case PARSER_SIGNATURE_UNMATCHED:  return PA_010;
    case PARSER_HCCAPX_FILE_SIZE:     return PA_011;
    case PARSER_HCCAPX_EAPOL_LEN:     return PA_012;
    case PARSER_PSAFE2_FILE_SIZE:     return PA_013;
    case PARSER_PSAFE3_FILE_SIZE:     return PA_014;
    case PARSER_TC_FILE_SIZE:         return PA_015;
    case PARSER_VC_FILE_SIZE:         return PA_016;
    case PARSER_SIP_AUTH_DIRECTIVE:   return PA_017;
    case PARSER_HASH_FILE:            return PA_018;
    case PARSER_HASH_ENCODING:        return PA_019;
    case PARSER_SALT_ENCODING:        return PA_020;
    case PARSER_LUKS_FILE_SIZE:       return PA_021;
    case PARSER_LUKS_MAGIC:           return PA_022;
    case PARSER_LUKS_VERSION:         return PA_023;
    case PARSER_LUKS_CIPHER_TYPE:     return PA_024;
    case PARSER_LUKS_CIPHER_MODE:     return PA_025;
    case PARSER_LUKS_HASH_TYPE:       return PA_026;
    case PARSER_LUKS_KEY_SIZE:        return PA_027;
    case PARSER_LUKS_KEY_DISABLED:    return PA_028;
    case PARSER_LUKS_KEY_STRIPES:     return PA_029;
    case PARSER_LUKS_HASH_CIPHER:     return PA_030;
    case PARSER_HCCAPX_SIGNATURE:     return PA_031;
    case PARSER_HCCAPX_VERSION:       return PA_032;
    case PARSER_HCCAPX_MESSAGE_PAIR:  return PA_033;
    case PARSER_TOKEN_ENCODING:       return PA_034;
    case PARSER_TOKEN_LENGTH:         return PA_035;
    case PARSER_INSUFFICIENT_ENTROPY: return PA_036;
    case PARSER_PKZIP_CT_UNMATCHED:   return PA_037;
    case PARSER_KEY_SIZE:             return PA_038;
    case PARSER_BLOCK_SIZE:           return PA_039;
    case PARSER_CIPHER:               return PA_040;
    case PARSER_FILE_SIZE:            return PA_041;
    case PARSER_IV_LENGTH:            return PA_042;
    case PARSER_CT_LENGTH:            return PA_043;
    case PARSER_PT_LENGTH:            return PA_044;
    case PARSER_PT_OFFSET:            return PA_045;
    case PARSER_CRYPTOAPI_KERNELTYPE: return PA_046;
    case PARSER_CRYPTOAPI_KEYSIZE:    return PA_047;
  }

  return PA_255;
}

static int rounds_count_length (const char *input_buf, const int input_len)
{
  if (input_len >= 9) // 9 is minimum because of "rounds=X$"
  {
    static const char *const rounds = "rounds=";

    if (memcmp (input_buf, rounds, 7) == 0)
    {
      const char *next_pos = strchr (input_buf + 8, '$');

      if (next_pos == NULL) return -1;

      const int rounds_len = next_pos - input_buf;

      return rounds_len;
    }
  }

  return -1;
}

const u8 *hc_strchr_next (const u8 *input_buf, const int input_len, const u8 separator)
{
  for (int i = 0; i < input_len; i++)
  {
    if (input_buf[i] == separator) return &input_buf[i];
  }

  return NULL;
}

const u8 *hc_strchr_last (const u8 *input_buf, const int input_len, const u8 separator)
{
  for (int i = input_len - 1; i >= 0; i--)
  {
    if (input_buf[i] == separator) return &input_buf[i];
  }

  return NULL;
}

int input_tokenizer (const u8 *input_buf, const int input_len, hc_token_t *token)
{
  tokenizer_error_set = false;

  int len_left = input_len;

  token->buf[0] = input_buf;

  int token_idx;

  for (token_idx = 0; token_idx < token->token_cnt - 1; token_idx++)
  {
    if (token->attr[token_idx] & TOKEN_ATTR_FIXED_LENGTH)
    {
      int len = token->len[token_idx];

      if (len_left < len)
      {
        tokenizer_error_capture (PARSER_TOKEN_LENGTH, PA_035, token->buf[token_idx], len_left, len, len_left, 0);

        return (PARSER_TOKEN_LENGTH);
      }
    }
    else
    {
      if (token->attr[token_idx] & TOKEN_ATTR_OPTIONAL_ROUNDS)
      {
        const int len = rounds_count_length ((const char *) token->buf[token_idx], len_left);

        token->opt_buf = token->buf[token_idx];

        token->opt_len = len; // we want an eventual -1 in here, it's used later for verification

        if (len > 0)
        {
          token->buf[token_idx] += len + 1; // +1 = separator

          len_left -= len + 1; // +1 = separator
        }
      }
    }

    if (token->sep[token_idx] != 0x00)
    {
      const u8 *next_pos = NULL;

      if (token->attr[token_idx] & TOKEN_ATTR_SEPARATOR_FARTHEST)
      {
        next_pos = hc_strchr_last (token->buf[token_idx], len_left, token->sep[token_idx]);
      }
      else
      {
        next_pos = hc_strchr_next (token->buf[token_idx], len_left, token->sep[token_idx]);
      }

      if (next_pos == NULL)
      {
        tokenizer_error_capture (PARSER_SEPARATOR_UNMATCHED, PA_009, token->buf[token_idx], len_left, -1, -1, token->sep[token_idx]);

        return (PARSER_SEPARATOR_UNMATCHED);
      }

      const int len = next_pos - token->buf[token_idx];

      if (token->attr[token_idx] & TOKEN_ATTR_FIXED_LENGTH)
      {
        if (len != token->len[token_idx])
        {
          // len, not len_left: the count in the clause is about this token, so the snippet has to be
          // this token as well. len_left runs to the end of the line and would put the boundary the
          // reader is being pointed at somewhere inside the next field.

          tokenizer_error_capture (PARSER_TOKEN_LENGTH, PA_035, token->buf[token_idx], len, token->len[token_idx], len, 0);

          return (PARSER_TOKEN_LENGTH);
        }
      }

      token->len[token_idx] = len;

      token->buf[token_idx + 1] = next_pos + 1; // +1 = separator

      len_left -= len + 1; // +1 = separator
    }
    else
    {
      const int len = token->len[token_idx];

      if (len)
      {
        token->buf[token_idx + 1] = token->buf[token_idx] + len;

        len_left -= len;

        if (token->sep[token_idx] != 0)
        {
          token->buf[token_idx + 1]++; // +1 = separator

          len_left--; // -1 = separator
        }
      }

      const int len_min = token->len_min[token_idx];
      const int len_max = token->len_max[token_idx];

      if (len_max)
      {
        bool matched = false;

        if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_SIGNATURE)
        {
          for (int signature_idx = 0; signature_idx < token->signatures_cnt; signature_idx++)
          {
            const int len_sig = strlen (token->signatures_buf[signature_idx]);

            if (len_sig > len_left) continue;

            if ((len_sig >= len_min) && (len_sig <= len_max))
            {
              if (memcmp (token->buf[token_idx], token->signatures_buf[signature_idx], len_sig) == 0)
              {
                token->len[token_idx] = len_sig;

                token->buf[token_idx + 1] = token->buf[token_idx] + len_sig;

                len_left -= len_sig;

                matched = true;
              }
            }
          }

          if (matched == false) return (PARSER_SIGNATURE_UNMATCHED);
        }
      }
    }
  }

  if (token->attr[token_idx] & TOKEN_ATTR_FIXED_LENGTH)
  {
    int len = token->len[token_idx];

    if (len_left != len)
    {
      tokenizer_error_capture (PARSER_TOKEN_LENGTH, PA_035, token->buf[token_idx], len_left, len, len_left, 0);

      return (PARSER_TOKEN_LENGTH);
    }
  }
  else
  {
    token->len[token_idx] = len_left;
  }

  // verify data

  for (token_idx = 0; token_idx < token->token_cnt; token_idx++)
  {
    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_SIGNATURE)
    {
      bool matched = false;

      for (int signature_idx = 0; signature_idx < token->signatures_cnt; signature_idx++)
      {
        if (strncmp ((char *) token->buf[token_idx], token->signatures_buf[signature_idx], token->len[token_idx]) == 0) matched = true;
      }

      if (matched == false) return (PARSER_SIGNATURE_UNMATCHED);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_LENGTH)
    {
      if (token->len[token_idx] < token->len_min[token_idx])
      {
        tokenizer_error_capture (PARSER_TOKEN_LENGTH, PA_035, token->buf[token_idx], token->len[token_idx], token->len_min[token_idx], token->len[token_idx], 0);

        return (PARSER_TOKEN_LENGTH);
      }

      if (token->len[token_idx] > token->len_max[token_idx])
      {
        tokenizer_error_capture (PARSER_TOKEN_LENGTH, PA_035, token->buf[token_idx], token->len[token_idx], token->len_max[token_idx], token->len[token_idx], 0);

        return (PARSER_TOKEN_LENGTH);
      }
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_DIGIT)
    {
      if (is_valid_digit_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_FLOAT)
    {
      if (is_valid_float_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_HEX)
    {
      if (is_valid_hex_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_BASE64A)
    {
      if (is_valid_base64a_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_BASE64B)
    {
      if (is_valid_base64b_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }

    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_BASE64C)
    {
      if (is_valid_base64c_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }
    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_BASE58)
    {
      if (is_valid_base58_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }
    if (token->attr[token_idx] & TOKEN_ATTR_VERIFY_BECH32)
    {
      if (is_valid_bech32_string (token->buf[token_idx], token->len[token_idx]) == false) return (PARSER_TOKEN_ENCODING);
    }
  }

  return PARSER_OK;
}

bool generic_salt_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf, int *out_len)
{
  u32 tmp_u32[(64 * 2) + 1] = { 0 };

  u8 *tmp_u8 = (u8 *) tmp_u32;

  if (in_len > 512) return false; // 512 = 2 * 256 -- (2 * because of hex), 256 because of maximum salt length in salt_t

  int tmp_len = 0;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if (in_len < (int) (hashconfig->salt_min * 2)) return false;
    if (in_len > (int) (hashconfig->salt_max * 2)) return false;

    if (in_len & 1) return false;

    for (int i = 0, j = 0; j < in_len; i += 1, j += 2)
    {
      u8 p0 = in_buf[j + 0];
      u8 p1 = in_buf[j + 1];

      tmp_u8[i]  = hex_convert (p1) << 0;
      tmp_u8[i] |= hex_convert (p0) << 4;
    }

    tmp_len = in_len / 2;
  }
  else if (hashconfig->opts_type & OPTS_TYPE_ST_BASE64)
  {
    if (in_len < (int) (((hashconfig->salt_min * 8) / 6) + 0)) return false;
    if (in_len > (int) (((hashconfig->salt_max * 8) / 6) + 3)) return false;

    tmp_len = base64_decode (base64_to_int, in_buf, in_len, tmp_u8);
  }
  else
  {
    if (in_len < (int) hashconfig->salt_min) return false;
    if (in_len > (int) hashconfig->salt_max) return false;

    memcpy (tmp_u8, in_buf, in_len);

    tmp_len = in_len;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE)
  {
    if (tmp_len >= 128) return false;

    for (int i = 64 - 1; i >= 1; i -= 2)
    {
      const u32 v = tmp_u32[i / 2];

      tmp_u32[i - 0] = ((v >> 8) & 0x00FF0000) | ((v >> 16) & 0x000000FF);
      tmp_u32[i - 1] = ((v << 8) & 0x00FF0000) | ((v >>  0) & 0x000000FF);
    }

    tmp_len = tmp_len * 2;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_LOWER)
  {
    lowercase (tmp_u8, tmp_len);
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UPPER)
  {
    uppercase (tmp_u8, tmp_len);
  }

  int tmp2_len = tmp_len;

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    if (tmp2_len >= 256) return false;

    tmp_u8[tmp2_len++] = 0x80;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD01)
  {
    if (tmp2_len >= 256) return false;

    tmp_u8[tmp2_len++] = 0x01;
  }

  memcpy (out_buf, tmp_u8, tmp2_len);

  *out_len = tmp_len;

  return true;
}

int generic_salt_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf)
{
  u32 tmp_u32[(64 * 2) + 1] = { 0 };

  u8 *tmp_u8 = (u8 *) tmp_u32;

  memcpy (tmp_u8, in_buf, in_len);

  int tmp_len = in_len;

  if (hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE)
  {
    for (int i = 0, j = 0; j < in_len; i += 1, j += 2)
    {
      const u8 p = tmp_u8[j];

      tmp_u8[i] = p;
    }

    tmp_len = tmp_len / 2;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    for (int i = 0, j = 0; i < in_len; i += 1, j += 2)
    {
      u8_to_hex (in_buf[i], tmp_u8 + j);
    }

    tmp_len = in_len * 2;
  }
  else if (hashconfig->opts_type & OPTS_TYPE_ST_BASE64)
  {
    tmp_len = base64_encode (int_to_base64, in_buf, in_len, tmp_u8);
  }

  memcpy (out_buf, tmp_u8, tmp_len);

  return tmp_len;
}
int extract_dynamicx_hash (const u8 *input_buf, const int input_len, u8 **output_buf, int *output_len)
{
  int hash_mode = -1;

  if (sscanf ((char *) input_buf, "$dynamic_%d$", &hash_mode) != 1) return -1;

  *output_buf = (u8 *) strchr ((char *) input_buf + 10, '$');

  if (*output_buf == NULL) return -1;

  *output_buf += 1; // the $ itself

  *output_len = input_len - (*output_buf - input_buf);

  return hash_mode;
}