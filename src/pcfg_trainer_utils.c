/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "timer.h"
#include "filehandling.h"
#include "convert.h"
#include "thread.h"
#include "shared.h"
#include "xxhash.h"
#include "pcfg_trainer_utils.h"

//
// static
//

static const int8_t hex_lut[256] =
{
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
  -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static bool is_valid_local_part (const char *local, size_t len)
{
  if (len == 0 || len > 64) return false;

  // cannot start/end with dot
  if (local[0] == '.' || local[len - 1] == '.') return false;

  bool prev_dot = false;

  for (size_t i = 0; i < len; i++)
  {
    char c = local[i];

    // permitted chars: a-z, A-Z, 0-9, ._%+-
    bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '%' || c == '+' || c == '-';

    if (!valid) return false;

    if (c == '.')
    {
      if (prev_dot) return false;

      prev_dot = true;
    }
    else
    {
      prev_dot = false;
    }
  }

  return true;
}

static bool is_valid_domain (const char *domain, size_t len)
{
  if (len < 4 || len > 253) return false;

  // cannot start/end with dot or dash
  if (domain[0] == '.' || domain[0] == '-') return false;
  if (domain[len - 1] == '.' || domain[len - 1] == '-') return false;

  int dot_count = 0;

  size_t last_dot_pos = 0;

  bool prev_dot = false;
  bool prev_hyphen = false;

  for (size_t i = 0; i < len; i++)
  {
    char c = domain[i];

    // permitted chars: a-z, A-Z, 0-9, .- (NO underscore!)
    bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '-';

    if (!valid) return false;

    if (c == '.')
    {
      if (prev_dot) return false;      // consecutive dots
      if (prev_hyphen) return false;   // dash before dot

      prev_dot    = true;
      prev_hyphen = false;

      dot_count++;

      last_dot_pos = i;
    }
    else if (c == '-')
    {
      if (prev_dot) return false;      // dash after dot

      prev_dot    = false;
      prev_hyphen = true;
    }
    else
    {
      prev_dot    = false;
      prev_hyphen = false;
    }
  }

  if (dot_count == 0) return false;

  // TLD: min 2 letter
  size_t tld_len = len - last_dot_pos - 1;

  if (tld_len < 2) return false;

  const char *tld = domain + last_dot_pos + 1;

  for (size_t i = 0; i < tld_len; i++)
  {
    char c = tld[i];

    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
  }

  return true;
}

u32 get_domain_span (const char *domain, u32 max_len)
{
  if (max_len < 4) return 0;

  // cannot start with dot or dash
  if (domain[0] == '.' || domain[0] == '-') return 0;

  u32 i = 0;
  u32 best_end = 0;

  int last_dot_pos = -1;

  bool prev_dot    = false;
  bool prev_hyphen = false;

  while (i < max_len)
  {
    unsigned char c = (unsigned char) domain[i];

    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
    {
      i++;

      prev_dot    = false;
      prev_hyphen = false;

      // check for valid domain
      if (last_dot_pos >= 0)
      {
        u32 tld_start = (u32) (last_dot_pos + 1);
        u32 tld_len   = i - tld_start;

        if (tld_len >= 2)
        {
          // TLD only letter
          bool tld_valid = true;

          for (u32 k = tld_start; k < i; k++)
          {
            unsigned char tc = (unsigned char) domain[k];

            if (!((tc >= 'a' && tc <= 'z') || (tc >= 'A' && tc <= 'Z')))
            {
              tld_valid = false;
              break;
            }
          }

          if (tld_valid)
          {
            best_end = i;
          }
        }
      }
    }
    else if (c == '.')
    {
      if (i == 0) break;
      if (prev_dot) break;
      if (prev_hyphen) break;

      last_dot_pos = (int)i;

      i++;

      prev_dot    = true;
      prev_hyphen = false;
    }
    else if (c == '-')
    {
      if (prev_dot) break;

      i++;

      prev_dot    = false;
      prev_hyphen = true;
    }
    else
    {
      break; // no valid char
    }
  }

  return best_end;
}

static bool is_valid_email (const char *s, size_t len)
{
  if (len < 6 || len > 254) return false;

  // find @
  size_t at_pos = 0;

  int at_count = 0;

  for (size_t i = 0; i < len; i++)
  {
    if (s[i] == '@')
    {
      at_pos = i;
      at_count++;
    }
  }

  if (at_count != 1) return false;
  if (at_pos == 0 || at_pos == len - 1) return false;

  size_t local_len  = at_pos;
  size_t domain_len = len - at_pos - 1;

  return is_valid_local_part (s, local_len) && is_valid_domain (s + at_pos + 1, domain_len);
}

static size_t codepoint_to_utf8 (u32 cp, unsigned char *out)
{
  if (cp < 0x80)
  {
    out[0] = (unsigned char)cp;
    return 1;
  }
  else if (cp < 0x800)
  {
    out[0] = 0xC0 | (cp >> 6);
    out[1] = 0x80 | (cp & 0x3F);
    return 2;
  }
  else if (cp < 0x10000)
  {
    out[0] = 0xE0 | (cp >> 12);
    out[1] = 0x80 | ((cp >> 6) & 0x3F);
    out[2] = 0x80 | (cp & 0x3F);
    return 3;
  }
  else if (cp < 0x110000)
  {
    out[0] = 0xF0 | (cp >> 18);
    out[1] = 0x80 | ((cp >> 12) & 0x3F);
    out[2] = 0x80 | ((cp >> 6) & 0x3F);
    out[3] = 0x80 | (cp & 0x3F);
    return 4;
  }

  return 0;
}

static int detect_utf16_type (const unsigned char *data, size_t len)
{
  if (len < 4 || (len & 1) != 0) return UTF16_NONE;

  size_t pairs   = len / 2;

  int le_score   = 0;
  int be_score   = 0;
  int real_nulls = 0;

  for (size_t i = 0; i < len; i += 2)
  {
    unsigned char b0 = data[i];
    unsigned char b1 = data[i + 1];

    if (b0 == 0x00 && b1 == 0x00)
    {
      real_nulls++;
    }
    else if (b0 == 0x00 && b1 != 0x00)
    {
      be_score++;
    }
    else if (b0 != 0x00 && b1 == 0x00)
    {
      le_score++;
    }
  }

  if (real_nulls > (int) (pairs * 0.1)) return UTF16_NONE;

  int threshold = (int) (pairs * 0.7);

  if (le_score >= threshold && be_score < (int) (pairs * 0.2)) return UTF16_LE;
  if (be_score >= threshold && le_score < (int) (pairs * 0.2)) return UTF16_BE;

  return UTF16_NONE;
}

static size_t utf16_to_utf8 (const unsigned char *utf16, size_t utf16_len, int utf16_type, char *utf8_out, size_t utf8_max)
{
  if (utf16_len < 2 || (utf16_len & 1) != 0) return 0;

  size_t i = 0;
  size_t out_pos = 0;

  while (i < utf16_len && out_pos < utf8_max - 4)
  {
    u16 code_unit;

    if (utf16_type == UTF16_LE)
    {
      code_unit = utf16[i] | (utf16[i + 1] << 8);
    }
    else
    {
      code_unit = (utf16[i] << 8) | utf16[i + 1];
    }

    i += 2;

    u32 codepoint;

    if (code_unit >= 0xD800 && code_unit <= 0xDBFF)
    {
      if (i + 1 >= utf16_len) return 0;

      u16 low_surrogate;

      if (utf16_type == UTF16_LE)
      {
        low_surrogate = utf16[i] | (utf16[i + 1] << 8);
      }
      else
      {
        low_surrogate = (utf16[i] << 8) | utf16[i + 1];
      }

      if (low_surrogate < 0xDC00 || low_surrogate > 0xDFFF)
      {
        return 0;
      }

      i += 2;

      codepoint = 0x10000 + ((code_unit - 0xD800) << 10) + (low_surrogate - 0xDC00);
    }
    else if (code_unit >= 0xDC00 && code_unit <= 0xDFFF)
    {
      return 0;
    }
    else
    {
      codepoint = code_unit;
    }

    size_t written = codepoint_to_utf8 (codepoint, (unsigned char *) (utf8_out + out_pos));

    if (written == 0) return 0;

    out_pos += written;
  }

  utf8_out[out_pos] = '\0';

  return out_pos;
}

static size_t unhexify_raw (const char *hex_in, size_t hex_len, unsigned char *out, size_t out_max)
{
  const unsigned char *src = (const unsigned char *) (hex_in + 5);

  size_t src_len = hex_len - 6;

  if ((src_len & 1) != 0) return 0;

  size_t out_len = src_len / 2;

  if (out_len > out_max) return 0;

  unsigned char *dst = out;

  const unsigned char *end = src + src_len;

  while (src < end)
  {
    int8_t hi = hex_lut[src[0]];
    int8_t lo = hex_lut[src[1]];

    if (hi < 0 || lo < 0) return 0;

    *dst++ = (hi << 4) | lo;

    src += 2;
  }

  return out_len;
}

static bool is_encoded_hash_format (const char *s, size_t len)
{
  if (len < 6) return false;

  // JWT
  if (len > 36 && s[0] == 'e' && s[1] == 'y' && s[2] == 'J')
  {
    int dot_count = 0;

    for (size_t i = 0; i < len; i++)
    {
      if (s[i] == '.') dot_count++;
    }

    if (dot_count == 2) return true;
  }

  // RSA keys/certificates (PKCS#8, PKCS#1)
  if (len >= 40 && s[0] == 'M' && s[1] == 'I' && s[2] == 'I') return true;

  // SSH keys
  if (len >= 20 && s[0] == 'A' && s[1] == 'A' && s[2] == 'A' && s[3] == 'A') return true;

  // Crypto wallet seeds (Base58, typically 87-111 characters)
  if (len >= 80 && len <= 120)
  {
    bool is_base58 = true;

    for (size_t i = 0; i < len && is_base58; i++)
    {
      char c = s[i];
      // Base58 = alphanumeric without 0, O, I, l
      if (!((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
            (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
            (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')))
      {
        is_base58 = false;
      }
    }

    if (is_base58) return true;
  }

  // UUID in Base64 (36 bytes UUID → 48 base64 characters, or 32 bytes without hyphens → 44 characters)
  if ((len == 44 || len == 48) && s[len-1] != '=')
  {
    // if it is 44-48 characters long and all base64, it is probably a UUID
    bool all_b64 = true;

    for (size_t i = 0; i < len && all_b64; i++)
    {
      char c = s[i];

      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||  c == '+' || c == '/' || c == '='))
      {
        all_b64 = false;
      }
    }

    if (all_b64) return true;
  }

  if (s[0] == '$' && len >= 3)
  {
    switch (s[1])
    {
      // $P$, $H$ (phpass - WordPress, phpBB)
      // $S$ (Drupal7)
      // $Q$ (QNX)
      // $1$ (md5crypt)
      // $5$ (sha256crypt)
      // $6$ (sha512crypt)
      // $y$ (yescrypt)
      case 'P': case 'H': case 'S': case 'Q':
      case '1': case '5': case '6': case 'y':
        if (len > 4 && s[2] == '$') return true;
        break;

      case '2':
        // $2a$, $2b$, $2y$ (bcrypt)
        if (len > 6 && s[3] == '$')
        {
          char c = s[2];
          if (c == 'a' || c == 'b' || c == 'y') return true;
        }
        break;

      case '7':
        // $7$ (scrypt)
        if (len > 3 && s[2] == '$') return true;
        // $7z$
        if (len > 4 && s[2] == 'z' && s[3] == '$') return true;
        break;

      case 'N':
        // $NT$
        if (len > 4 && s[2] == 'T' && s[3] == '$') return true;
        break;

      case 'D':
        // $DCC$, $DCC2$ (Domain Cached Credentials)
        if (len > 5 && s[2] == 'C' && s[3] == 'C') return true;
        break;

      case 'z':
        // $zip$, $zip2$
        if (len > 5 && s[2] == 'i' && s[3] == 'p') return true;
        break;

      case 'r':
        // $rar3$, $rar5$
        // $racf$
        if (len > 5 && s[2] == 'a' && (s[3] == 'r' || s[3] == 'c')) return true;
        break;

      case 'g':
        // $gpg$
        if (len > 5 && s[2] == 'p' && s[3] == 'g' && s[4] == '$') return true;
        break;

      case 'w':
        // $wpa$, $wpapsk$
        if (len > 5 && s[2] == 'p' && s[3] == 'a') return true;
        break;

      case 'f':
        // $fvde$, $filevault$
        if (len > 6 && s[2] == 'v' && s[3] == 'd' && s[4] == 'e' && s[5] == '$') return true;
        break;

      case 'l':
        // $luks$
        if (len > 6 && s[2] == 'u' && s[3] == 'k' && s[4] == 's' && s[5] == '$') return true;
        break;

      case 'k':
        // $krb5pa$, $krb5tgs$, $krb5asrep$
        if (len > 7 && s[2] == 'r' && s[3] == 'b' && s[4] == '5') return true;
        // $keepass$
        if (len > 9 && s[2] == 'e' && s[3] == 'e' && s[4] == 'p' &&
            s[5] == 'a' && s[6] == 's' && s[7] == 's' && s[8] == '$') return true;
        break;

      case 'a':
        // $apr1$ (Apache MD5)
        if (len > 6 && s[2] == 'p' && s[3] == 'r' && s[4] == '1' && s[5] == '$') return true;
        // $argon2i$, $argon2d$, $argon2id$
        if (len > 8 && s[2] == 'r' && s[3] == 'g' && s[4] == 'o' && s[5] == 'n' && s[6] == '2') return true;
        // $ansible$
        if (len > 9 && s[2] == 'n' && s[3] == 's' && s[4] == 'i' && s[5] == 'b' &&
            s[6] == 'l' && s[7] == 'e' && s[8] == '$') return true;
        break;

      case 's':
        // $sip$
        if (len > 5 && s[2] == 'i' && s[3] == 'p' && s[4] == '$') return true;
        // $sha1$
        if (len > 6 && s[2] == 'h' && s[3] == 'a' && s[4] == '1' && s[5] == '$') return true;
        // $snmp$
        if (len > 6 && s[2] == 'n' && s[3] == 'm' && s[4] == 'p' && s[5] == '$') return true;
        // $sshng$
        if (len > 7 && s[2] == 's' && s[3] == 'h' && s[4] == 'n' && s[5] == 'g' && s[6] == '$') return true;
        // $scrypt$
        if (len > 8 && s[2] == 'c' && s[3] == 'r' && s[4] == 'y' && s[5] == 'p' && s[6] == 't') return true;
        // $signal$
        if (len > 8 && s[2] == 'i' && s[3] == 'g' && s[4] == 'n' && s[5] == 'a' && s[6] == 'l' && s[7] == '$') return true;
        // $securezip$
        if (len > 11 && s[2] == 'e' && s[3] == 'c' && s[4] == 'u' && s[5] == 'r' &&
            s[6] == 'e' && s[7] == 'z' && s[8] == 'i' && s[9] == 'p' && s[10] == '$') return true;
        break;

      case 'p':
        // $pdf$
        if (len > 5 && s[2] == 'd' && s[3] == 'f' && s[4] == '$') return true;
        // $pbkdf2$, $pbkdf2-sha256$, $pbkdf2-sha512$
        if (len > 8 && s[2] == 'b' && s[3] == 'k' && s[4] == 'd' && s[5] == 'f' && s[6] == '2') return true;
        // $postgres$
        if (len > 10 && s[2] == 'o' && s[3] == 's' && s[4] == 't' && s[5] == 'g' &&
            s[6] == 'r' && s[7] == 'e' && s[8] == 's' && s[9] == '$') return true;
        break;

      case 'v':
        // $vnc$
        if (len > 5 && s[2] == 'n' && s[3] == 'c' && s[4] == '$') return true;
        // $vmware1$, $vmware2$
        if (len > 8 && s[2] == 'm' && s[3] == 'w' && s[4] == 'a' && s[5] == 'r' && s[6] == 'e') return true;
        // $veracrypt$
        if (len > 11 && s[2] == 'e' && s[3] == 'r' && s[4] == 'a' && s[5] == 'c' &&
            s[6] == 'r' && s[7] == 'y' && s[8] == 'p' && s[9] == 't' && s[10] == '$') return true;
        break;

      case 'o':
        // $office$
        if (len > 8 && s[2] == 'f' && s[3] == 'f' && s[4] == 'i' && s[5] == 'c' && s[6] == 'e' && s[7] == '$') return true;
        // $oracle$
        if (len > 8 && s[2] == 'r' && s[3] == 'a' && s[4] == 'c' && s[5] == 'l' && s[6] == 'e') return true;
        // $oldoffice$
        if (len > 11 && s[2] == 'l' && s[3] == 'd' && s[4] == 'o' && s[5] == 'f' &&
            s[6] == 'f' && s[7] == 'i' && s[8] == 'c' && s[9] == 'e' && s[10] == '$') return true;
        break;

      case 'b':
        // $bitcoin$
        if (len > 9 && s[2] == 'i' && s[3] == 't' && s[4] == 'c' &&
            s[5] == 'o' && s[6] == 'i' && s[7] == 'n' && s[8] == '$') return true;
        // $bitlocker$
        if (len > 10 && s[2] == 'i' && s[3] == 't' && s[4] == 'l' &&
            s[5] == 'o' && s[6] == 'c' && s[7] == 'k' && s[8] == 'e' && s[9] == 'r') return true;
        break;

      case 'd':
        // $dynamic_
        if (len > 9 && s[2] == 'y' && s[3] == 'n' && s[4] == 'a' &&
            s[5] == 'm' && s[6] == 'i' && s[7] == 'c' && s[8] == '_') return true;
        break;

      case 'm':
        // $ml$ (macOS v10.8+)
        if (len > 4 && s[2] == 'l' && s[3] == '$') return true;
        // $mssql$
        if (len > 7 && s[2] == 's' && s[3] == 's' && s[4] == 'q' && s[5] == 'l' && s[6] == '$') return true;
        // $mongodb$
        if (len > 9 && s[2] == 'o' && s[3] == 'n' && s[4] == 'g' &&
            s[5] == 'o' && s[6] == 'd' && s[7] == 'b' && s[8] == '$') return true;
        // $mysql40$, $mysqlna$
        if (len > 6 && s[2] == 'y' && s[3] == 's' && s[4] == 'q' && s[5] == 'l') return true;
        break;

      case 'n':
        // $netntlm$, $netntlmv2$
        if (len > 9 && s[2] == 'e' && s[3] == 't' && s[4] == 'n' &&
            s[5] == 't' && s[6] == 'l' && s[7] == 'm') return true;
        break;

      case 'e':
        // $ethereum$
        if (len > 10 && s[2] == 't' && s[3] == 'h' && s[4] == 'e' && s[5] == 'r' &&
            s[6] == 'e' && s[7] == 'u' && s[8] == 'm' && s[9] == '$') return true;
        // $electrum$
        if (len > 10 && s[2] == 'l' && s[3] == 'e' && s[4] == 'c' && s[5] == 't' &&
            s[6] == 'r' && s[7] == 'u' && s[8] == 'm' && s[9] == '$') return true;
        // $episerver$
        if (len > 11 && s[2] == 'p' && s[3] == 'i' && s[4] == 's' && s[5] == 'e' &&
            s[6] == 'r' && s[7] == 'v' && s[8] == 'e' && s[9] == 'r' && s[10] == '$') return true;
        break;

      case 't':
        // $telegram$
        if (len > 10 && s[2] == 'e' && s[3] == 'l' && s[4] == 'e' && s[5] == 'g' &&
            s[6] == 'r' && s[7] == 'a' && s[8] == 'm' && s[9] == '$') return true;
        // $truecrypt$
        if (len > 11 && s[2] == 'r' && s[3] == 'u' && s[4] == 'e' && s[5] == 'c' &&
            s[6] == 'r' && s[7] == 'y' && s[8] == 'p' && s[9] == 't' && s[10] == '$') return true;
        break;

      case 'i':
        // $itunes_backup$
        if (len > 15 && s[2] == 't' && s[3] == 'u' && s[4] == 'n' && s[5] == 'e' &&
            s[6] == 's' && s[7] == '_' && s[8] == 'b' && s[9] == 'a' && s[10] == 'c' &&
            s[11] == 'k' && s[12] == 'u' && s[13] == 'p' && s[14] == '$') return true;
        break;
    }
  }

  // LDAP style: {HASH_TYPE}base64data
  if (s[0] == '{')
  {
    const char *closing = memchr (s, '}', len > 16 ? 16 : len);

    if (closing != NULL)
    {
      size_t tag_len = closing - s + 1;

      // Macro for case-insensitive comparison (converts A-Z to a-z)
      #define L(c) ((unsigned char) (c) | 0x20)

      switch (tag_len)
      {
        case 4:
          // {NT}
          if (L(s[1]) == 'n' && L(s[2]) == 't') return true;
          break;

        case 5:
          switch (L(s[1]))
          {
            case 'm':
              // {MD5}, {MD4}
              if (L(s[2]) == 'd' && (s[3] == '5' || s[3] == '4')) return true;
              break;
            case 's':
              // {SHA}
              if (L(s[2]) == 'h' && L(s[3]) == 'a') return true;
              break;
          }
          break;

        case 6:
          // {SHA1}, {SSHA}, {SMD5}
          if (L(s[1]) == 's')
          {
            if (L(s[2]) == 'h' && L(s[3]) == 'a' && s[4] == '1') return true;
            if (L(s[2]) == 's' && L(s[3]) == 'h' && L(s[4]) == 'a') return true;
            if (L(s[2]) == 'm' && L(s[3]) == 'd' && s[4] == '5') return true;
          }
          break;

        case 7:
          switch (L(s[1]))
          {
            case 'c':
              // {CRYPT}
              if (L(s[2]) == 'r' && L(s[3]) == 'y' && L(s[4]) == 'p' && L(s[5]) == 't') return true;
              // {CLEAR}
              if (L(s[2]) == 'l' && L(s[3]) == 'e' && L(s[4]) == 'a' && L(s[5]) == 'r') return true;
              break;
            case 'p':
              // {PLAIN}
              if (L(s[2]) == 'l' && L(s[3]) == 'a' && L(s[4]) == 'i' && L(s[5]) == 'n') return true;
              break;
          }
          break;

        case 8:
          switch (L(s[1]))
          {
            case 'b':
              // {BCRYPT}
              if (L(s[2]) == 'c' && L(s[3]) == 'r' && L(s[4]) == 'y' && L(s[5]) == 'p' && L(s[6]) == 't') return true;
              break;
            case 'p':
              // {PBKDF2}
              if (L(s[2]) == 'b' && L(s[3]) == 'k' && L(s[4]) == 'd' && L(s[5]) == 'f' && s[6] == '2') return true;
              break;
            case 'l':
              // {LANMAN}
              if (L(s[2]) == 'a' && L(s[3]) == 'n' && L(s[4]) == 'm' && L(s[5]) == 'a' && L(s[6]) == 'n') return true;
              break;
            case 's':
              // {SCRYPT}
              if (L(s[2]) == 'c' && L(s[3]) == 'r' && L(s[4]) == 'y' && L(s[5]) == 'p' && L(s[6]) == 't') return true;
              // {SHA256}
              if (L(s[2]) == 'h' && L(s[3]) == 'a' && s[4] == '2' && s[5] == '5' && s[6] == '6') return true;
              // {SHA512}
              if (L(s[2]) == 'h' && L(s[3]) == 'a' && s[4] == '5' && s[5] == '1' && s[6] == '2') return true;
              break;
            case 'a':
              // {ARGON2}
              if (L(s[2]) == 'r' && L(s[3]) == 'g' && L(s[4]) == 'o' && L(s[5]) == 'n' && s[6] == '2') return true;
              break;
          }
          break;

        case 9:
          switch (L(s[1]))
          {
            case 'p':
              // {PKCS5S2}
              if (L(s[2]) == 'k' && L(s[3]) == 'c' && L(s[4]) == 's' && s[5] == '5' && L(s[6]) == 's' && s[7] == '2') return true;
              break;
            case 's':
              // {SSHA256}
              if (L(s[2]) == 's' && L(s[3]) == 'h' && L(s[4]) == 'a' && s[5] == '2' && s[6] == '5' && s[7] == '6') return true;
              // {SSHA512}
              if (L(s[2]) == 's' && L(s[3]) == 'h' && L(s[4]) == 'a' && s[5] == '5' && s[6] == '1' && s[7] == '2') return true;
              break;
            case 'a':
              // {ARGON2I}, {ARGON2D}
              if (L(s[2]) == 'r' && L(s[3]) == 'g' && L(s[4]) == 'o' && L(s[5]) == 'n' && s[6] == '2' && (L(s[7]) == 'i' || L(s[7]) == 'd')) return true;
              break;
          }
          break;

        case 10:
          switch (L(s[1]))
          {
            case 'a':
              // {ARGON2ID}
              if (L(s[2]) == 'r' && L(s[3]) == 'g' && L(s[4]) == 'o' && L(s[5]) == 'n' && s[6] == '2' && L(s[7]) == 'i' && L(s[8]) == 'd') return true;
              break;
            case 's':
              // {SHA2-256}, {SHA2-512}
              if (L(s[2]) == 'h' && L(s[3]) == 'a' && s[4] == '2' && s[5] == '-')
              {
                if (s[6] == '2' && s[7] == '5' && s[8] == '6') return true;
                if (s[6] == '5' && s[7] == '1' && s[8] == '2') return true;
              }
              break;
          }
          break;

        case 11:
          // {BLF-CRYPT}
          if (L(s[1]) == 'b' && L(s[2]) == 'l' && L(s[3]) == 'f' && s[4] == '-' && L(s[5]) == 'c' && L(s[6]) == 'r' && L(s[7]) == 'y' && L(s[8]) == 'p' && L(s[9]) == 't') return true;
          break;
      }

      #undef L
    }
  }

  // Hex hashes (32, 40, 64, 128 hex chars)
  // MD5=32, SHA1=40, SHA256=64, SHA512=128
  if (len == 32 || len == 40 || len == 64 || len == 128)
  {
    bool all_hex = true;

    for (size_t i = 0; i < len; i++)
    {
      char c = s[i];

      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
      {
        all_hex = false;
        break;
      }
    }

    if (all_hex) return true;
  }

  // Specific Prefix
  if (len >= 4)
  {
    switch (s[0])
    {
      case 's':
        // sha256:, sha512:, sha384:
        if (len > 7 && s[1] == 'h' && s[2] == 'a')
        {
          if (s[3] == '2' && s[4] == '5' && s[5] == '6' && s[6] == ':') return true;
          if (s[3] == '5' && s[4] == '1' && s[5] == '2' && s[6] == ':') return true;
          if (s[3] == '3' && s[4] == '8' && s[5] == '4' && s[6] == ':') return true;
        }
        // sha1:
        if (len > 5 && s[1] == 'h' && s[2] == 'a' && s[3] == '1' && s[4] == ':') return true;
        break;

      case 'm':
        // md5:, md4:
        if (len > 4 && s[1] == 'd' && (s[2] == '5' || s[2] == '4') && s[3] == ':') return true;
        break;

      case 'g':
        // grub.pbkdf2....
        if (len > 20 && s[1] == 'r' && s[2] == 'u' && s[3] == 'b' && s[4] == '.' &&
            s[5] == 'p' && s[6] == 'b' && s[7] == 'k' && s[8] == 'd' && s[9] == 'f' &&
            s[10] == '2' && s[11] == '.') return true;
        break;

      case '0':
        // 0x0100..., 0x0200... (MSSQL)
        if (len > 6 && s[1] == 'x' && s[2] == '0' && (s[3] == '1' || s[3] == '2') &&
            s[4] == '0' && s[5] == '0') return true;
        break;

      case 'v':
        // v1;PPH1_... (SAP)
        if (len > 12 && s[1] == '1' && s[2] == ';' && s[3] == 'P' && s[4] == 'P' &&
            s[5] == 'H' && s[6] == '1' && s[7] == '_') return true;
        break;

      case 'S':
        // SCRAM-SHA-... (RFC 5802)
        if (len > 10 && s[1] == 'C' && s[2] == 'R' && s[3] == 'A' && s[4] == 'M' &&
            s[5] == '-' && s[6] == 'S' && s[7] == 'H' && s[8] == 'A' && s[9] == '-') return true;
        break;
    }
  }

  return false;
}

static bool is_supported_unicode_range (u32 cp)
{
  // PCFG_TK_LATIN_EXT - Latin Extended/Accents
  if (cp >= 0x00C0  && cp <= 0x024F)  return true; // Latin Extended-A/B
  if (cp >= 0x1E00  && cp <= 0x1EFF)  return true; // Latin Extended Additional

  // PCFG_TK_CYRILLIC
  if (cp >= 0x0400  && cp <= 0x04FF)  return true; // Cyrillic
  if (cp >= 0x0500  && cp <= 0x052F)  return true; // Cyrillic Supplement

  // PCFG_TK_GREEK
  if (cp >= 0x0370  && cp <= 0x03FF)  return true; // Greek and Coptic

  // PCFG_TK_ARABIC
  if (cp >= 0x0600  && cp <= 0x06FF)  return true; // Arabic
  if (cp >= 0x0750  && cp <= 0x077F)  return true; // Arabic Supplement
  if (cp >= 0xFB50  && cp <= 0xFDFF)  return true; // Arabic Presentation Forms-A
  if (cp >= 0xFE70  && cp <= 0xFEFF)  return true; // Arabic Presentation Forms-B

  // PCFG_TK_HEBREW
  if (cp >= 0x0590  && cp <= 0x05FF)  return true; // Hebrew
  if (cp >= 0xFB1D  && cp <= 0xFB4F)  return true; // Hebrew Presentation Forms

  // PCFG_TK_ASIAN (CJK, Hindi/Devanagari, Thai, etc.)
  if (cp >= 0x0900  && cp <= 0x097F)  return true; // Devanagari (Hindi)
  if (cp >= 0x0980  && cp <= 0x09FF)  return true; // Bengali
  if (cp >= 0x0A00  && cp <= 0x0A7F)  return true; // Gurmukhi (Punjabi)
  if (cp >= 0x0B00  && cp <= 0x0B7F)  return true; // Oriya
  if (cp >= 0x0C00  && cp <= 0x0C7F)  return true; // Telugu
  if (cp >= 0x0C80  && cp <= 0x0CFF)  return true; // Kannada
  if (cp >= 0x0D00  && cp <= 0x0D7F)  return true; // Malayalam
  if (cp >= 0x0E00  && cp <= 0x0E7F)  return true; // Thai
  if (cp >= 0x0E80  && cp <= 0x0EFF)  return true; // Lao
  if (cp >= 0x1000  && cp <= 0x109F)  return true; // Myanmar
  if (cp >= 0x3040  && cp <= 0x309F)  return true; // Hiragana
  if (cp >= 0x30A0  && cp <= 0x30FF)  return true; // Katakana
  if (cp >= 0x4E00  && cp <= 0x9FFF)  return true; // CJK Unified Ideographs
  if (cp >= 0xAC00  && cp <= 0xD7AF)  return true; // Hangul Syllables (Korean)
  if (cp >= 0x3400  && cp <= 0x4DBF)  return true; // CJK Extension A

  // PCFG_TK_EMOJI
  if (cp >= 0x1F300 && cp <= 0x1F9FF) return true; // Miscellaneous Symbols/Emoji
  if (cp >= 0x2600  && cp <= 0x26FF)  return true; // Misc Symbols
  if (cp >= 0x2700  && cp <= 0x27BF)  return true; // Dingbats
  if (cp >= 0x1F600 && cp <= 0x1F64F) return true; // Emoticons
  if (cp >= 0x1F680 && cp <= 0x1F6FF) return true; // Transport/Map

  return false;
}

static bool has_pattern (const char *s, size_t len, const char *pattern, size_t pat_len)
{
  if (pat_len > len) return false;

  for (size_t i = 0; i <= len - pat_len; i++)
  {
    if (memcmp (s + i, pattern, pat_len) == 0) return true;
  }

  return false;
}

static bool is_json_content (const char *s, size_t len)
{
  if (len < 2) return false;

  if (s[0] == '{' && s[len - 1] == '}')
  {
    if (has_pattern (s, len, "\":\"", 3)) return true;
    if (has_pattern (s, len, "\":", 2) && has_pattern (s, len, ",\"", 2)) return true;
  }

  if (s[0] == '[' && s[len - 1] == ']')
  {
    if (has_pattern (s, len, "\",\"", 3)) return true;
    if (has_pattern (s, len, "},{", 3)) return true;
  }

  return false;
}

static bool is_url_content (const char *s, size_t len)
{
  if (len < 10) return false;

  switch (s[0])
  {
    case 'h':
      // http://, https://
      if (s[1] == 't' && s[2] == 't' && s[3] == 'p')
      {
        if (s[4] == ':' && s[5] == '/' && s[6] == '/') return true;
        if (s[4] == 's' && s[5] == ':' && s[6] == '/' && s[7] == '/') return true;
      }
      break;

    case 'f':
      // ftp://, ftps://, file://
      if (s[1] == 't' && s[2] == 'p')
      {
        if (s[3] == ':' && s[4] == '/' && s[5] == '/') return true;
        if (s[3] == 's' && s[4] == ':' && s[5] == '/' && s[6] == '/') return true;
      }
      if (s[1] == 'i' && s[2] == 'l' && s[3] == 'e' && s[4] == ':' && s[5] == '/' && s[6] == '/') return true;
      break;

    case 'm':
      // mailto:
      if (s[1] == 'a' && s[2] == 'i' && s[3] == 'l' && s[4] == 't' && s[5] == 'o' && s[6] == ':') return true;
      break;

    case 'd':
      // data:
      if (s[1] == 'a' && s[2] == 't' && s[3] == 'a' && s[4] == ':') return true;
      break;

    case 's':
      // ssh://, sftp://
      if (s[1] == 's' && s[2] == 'h' && s[3] == ':' && s[4] == '/' && s[5] == '/') return true;
      if (s[1] == 'f' && s[2] == 't' && s[3] == 'p' && s[4] == ':' && s[5] == '/' && s[6] == '/') return true;
      break;

    case 'l':
      // ldap://, ldaps://
      if (s[1] == 'd' && s[2] == 'a' && s[3] == 'p')
      {
        if (s[4] == ':' && s[5] == '/' && s[6] == '/') return true;
        if (s[4] == 's' && s[5] == ':' && s[6] == '/' && s[7] == '/') return true;
      }
      break;

    case 't':
      // tel:
      if (s[1] == 'e' && s[2] == 'l' && s[3] == ':') return true;
      break;
  }

  return false;
}

static bool is_likely_garbage (const char *s, size_t len)
{
  if (len < 4) return true;

  size_t alpha   = 0;
  size_t digit   = 0;
  size_t special = 0;

  for (size_t i = 0; i < len; i++)
  {
    unsigned char c = (unsigned char) s[i];

    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) alpha++;
    else if (c >= '0'  && c <= '9')  digit++;
    else if (c >= 0x21 && c <= 0x7E) special++;
  }

  // Short strings (< 6) with too many special characters
  if (len < 6 && special > len / 2) return true;

  // Short string without letters and digit (probably garbage)
  if (len < 6 && alpha == 0 && digit == 0) return true;

  // Too many special characters compared to the total
  if (len < 8 && special >= alpha + digit) return true;

  return false;
}

//
// shared
//

bool is_probably_base64 (const char *s, size_t len)
{
  // Check base
  if (len < 4)
  {
    return false;
  }

  if (len % 4 != 0)
  {
    return false;
  }

  size_t padding_count = 0;

  bool has_letter      = false;
  bool has_b64_special = false;

  for (size_t i = 0; i < len; i++)
  {
    unsigned char c = (unsigned char) s[i];

    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) has_letter = true;

    if  (c == '+' || c == '/') has_b64_special = true;

    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||  c == '+' || c == '/')
    {
      // valid char
    }
    else if (c == '=')
    {
      if (i < len - 2)
      {
        return false;
      }

      padding_count++;

      if (padding_count > 2)
      {
        return false;
      }
    }
    else
    {
      return false;
    }
  }

  if (!has_letter)
  {
    return false;
  }

  // Require at least ONE strong indicator:
  // 1. Has padding ‘=’
  // 2. Contains ‘+’ or ‘/’
  // 3. Length >= 24

  if (padding_count > 0)
  {
    return true;
  }

  if (has_b64_special)
  {
    return true;
  }

  if (len >= 24)
  {
    return true;
  }

  return false;
}

size_t find_base64_boundary (const char *s, size_t len)
{
  // valid charatters in base64: A-Z, a-z, 0-9, +, /, =
  // find the first not valid
  for (size_t i = 0; i < len; i++)
  {
    unsigned char c = (unsigned char) s[i];

    bool is_b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||  c == '+' || c == '/'  || c == '=';

    if (!is_b64)
    {
      return i;
    }
  }

  return len;
}

char *find_email_delimiter (char *s, size_t len, size_t *email_len, size_t *pass_len)
{
  *email_len = 0;
  *pass_len  = 0;

  if (len < 7) return NULL;

  // Must contain @
  bool has_at = false;

  for (size_t i = 0; i < len; i++)
  {
    if (s[i] == '@')
    {
      has_at = true;
      break;
    }
  }

  if (!has_at) return NULL;

  // Search for: o ; AFTER the @ (the email:password delimiter)
  // Let's start from the end to avoid cases such as “user:name@domain.com:pass”
  // In that case, we want the last delimiter after the domain

  size_t at_pos = 0;

  for (size_t i = 0; i < len; i++)
  {
    if (s[i] == '@') at_pos = i;
  }

  // Search for the first : or ; after @ that separates the email from the password.
  // But there must be at least one . between @ and the delimiter (for the domain).
  for (size_t i = at_pos + 1; i < len; i++)
  {
    if (s[i] == ':' || s[i] == ';')
    {
      // Verify that the first part is a valid email address
      size_t potential_email_len = i;

      if (is_valid_email (s, potential_email_len))
      {
        *email_len = potential_email_len;
        *pass_len  = len - i - 1;

        return s + i;
      }
    }
  }

  return NULL;
}

bool find_hex_bounds (const char *s, size_t len, size_t *hex_len, const char **suffix_ptr, size_t *suffix_len)
{
  *hex_len    = 0;
  *suffix_ptr = NULL;
  *suffix_len = 0;

  if (!starts_with_hex (s, len)) return false;

  // Search for ']'
  for (size_t i = 5; i < len; i++)
  {
    if (s[i] == ']')
    {
      *hex_len = i + 1;

      // Is there a suffix?
      if (i + 1 < len)
      {
        *suffix_ptr = s + i + 1;
        *suffix_len = len - i - 1;
      }

      return true;
    }
  }

  return false;
}

size_t find_hex_chars_length (const char *s, size_t len)
{
  // Find the length of the valid hex part (stops at the first non-hex character)
  size_t count = 0;

  for (size_t i = 0; i < len; i++)
  {
    char c = s[i];

    bool is_hex_char = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    if (!is_hex_char) break;

    count++;
  }

  return count;
}

char *find_hex_delimiter_ex (char *s, size_t len, size_t *prefix_len, size_t *hex_len, size_t *suffix_len)
{
  *prefix_len = 0;
  *hex_len    = 0;
  *suffix_len = 0;

  if (len < 8) return NULL;

  // Search for “:$HEX[” or “;$HEX[”
  for (size_t i = 0; i + 6 < len; i++)
  {
    if ((s[i] == ':' || s[i] == ';') && s[i+1] == '$' && s[i+2] == 'H' && s[i+3] == 'E' && s[i+4] == 'X' && s[i+5] == '[')
    {
      *prefix_len = i;

      // Search for ‘]’ after “$HEX[”
      for (size_t j = i + 6; j < len; j++)
      {
        if (s[j] == ']')
        {
          *hex_len    = j - i;
          *suffix_len = len - j - 1;

          return s + i;
        }
      }

      return NULL;
    }
  }

  return NULL;
}

bool is_garbage_content (const char *s, size_t len, bool decoded)
{
  if (decoded)
  {
    if (len < 3) return true;

    if (is_likely_garbage (s, len)) return true;
  }

  if (is_json_content (s, len)) return true;
  if (is_url_content  (s, len)) return true;

  if (is_encoded_hash_format (s, len)) return true;

  const unsigned char *p = (const unsigned char *) s;
  const unsigned char *end = p + len;

  while (p < end)
  {
    unsigned char c = *p;

    // ASCII control characters
    if (c < 0x20 || c == 0x7F) return true;

    if (c < 0x80)
    {
      p++;
      continue;
    }

    // Decode UTF-8 and validate
    u32 cp = 0;

    size_t bytes = 0;

    if ((c & 0xE0) == 0xC0 && p + 1 < end && (p[1] & 0xC0) == 0x80)
    {
      cp = ((c & 0x1F) << 6) | (p[1] & 0x3F);
      bytes = 2;
    }
    else if ((c & 0xF0) == 0xE0 && p + 2 < end && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80)
    {
      cp = ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
      bytes = 3;
    }
    else if ((c & 0xF8) == 0xF0 && p + 3 < end && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80)
    {
      cp = ((c & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
      bytes = 4;
    }
    else
    {
      return true;  // Invalid UTF-8
    }

    // Reject if not in any supported range
    if (!is_supported_unicode_range (cp)) return true;

    p += bytes;
  }

  return false;
}

bool starts_with_bare_hex (const char *s, size_t len)
{
  return (len >= 5 && s[0] == 'H' && s[1] == 'E' && s[2] == 'X');
}

bool starts_with_hex (const char *s, size_t len)
{
  return (len >= 5 && s[0] == '$' && s[1] == 'H' && s[2] == 'E' && s[3] == 'X' && s[4] == '[');
}

size_t trim_padding_fast (char *s, size_t len)
{
  if (len == 0) return 0;

  size_t start = 0;

  bool has_control = false;

  while (start < len)
  {
    unsigned char c = (unsigned char) s[start];

    if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D)
    {
      if (c != 0x20) has_control = true;

      start++;
    }
    else if (c == 0xC2 && start + 1 < len && (unsigned char) s[start+1] == 0xA0)
    {
      start += 2;
    }
    else
    {
      break;
    }
  }

  if (start > 2 || has_control)
  {
    if (start >= len) return 0;

    len -= start;

    memmove (s, s + start, len);

    while (len > 0)
    {
      unsigned char c = (unsigned char) s[len - 1];

      if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D)
        len--;
      else
        break;
    }
  }

  s[len] = 0;

  return len;
}

size_t unhexify_bare (const char *hex_in, size_t hex_len, char *out, size_t out_max, bool *was_utf16)
{
  // Decodes bare HEX (without $HEX[] wrapper), returns decoded length, 0 if error
  *was_utf16 = false;

  // Must be even and at least 2 characters long
  if ((hex_len & 1) != 0) return 0;
  if  (hex_len < 2) return 0;

  size_t out_len = hex_len / 2;

  if (out_len > out_max) return 0;

  size_t raw_max = out_len + 1;

  unsigned char *raw = (unsigned char *) hcmalloc (raw_max);

  if (!raw) return 0;

  const unsigned char *src = (const unsigned char *) hex_in;

  unsigned char *dst = raw;

  for (size_t i = 0; i < hex_len; i += 2)
  {
    int8_t hi = hex_lut[src[i]];
    int8_t lo = hex_lut[src[i + 1]];

    if (hi < 0 || lo < 0)
    {
      hcfree (raw);

      return 0; // Invalid character
    }

    *dst++ = (hi << 4) | lo;
  }

  size_t raw_len = out_len;

  // Check UTF-16
  int utf16_type = detect_utf16_type (raw, raw_len);

  if (utf16_type != UTF16_NONE)
  {
    *was_utf16 = true;

    size_t ret = utf16_to_utf8 (raw, raw_len, utf16_type, out, out_max);

    hcfree (raw);

    return ret;
  }

  // Check NULL bytes
  for (size_t i = 0; i < raw_len; i++)
  {
    if (raw[i] == 0x00)
    {
      hcfree (raw);

      return 0;
    }
  }

  memcpy (out, raw, raw_len);
  out[raw_len] = '\0';

  hcfree (raw);

  return raw_len;
}

size_t unhexify_smart (const char *hex_in, size_t hex_len, char *out, size_t out_max, bool *was_utf16)
{
  *was_utf16 = false;

  size_t raw_max = (hex_len - 6) / 2 + 1;

  unsigned char *raw = (unsigned char *) hcmalloc (raw_max);

  if (!raw) return 0;

  size_t raw_len = unhexify_raw (hex_in, hex_len, raw, raw_max);

  if (raw_len == 0)
  {
    hcfree (raw);

    return 0;
  }

  int utf16_type = detect_utf16_type (raw, raw_len);

  if (utf16_type != UTF16_NONE)
  {
    *was_utf16 = true;

    size_t utf8_len = utf16_to_utf8 (raw, raw_len, utf16_type, out, out_max);

    hcfree (raw);

    return utf8_len;
  }

  for (size_t i = 0; i < raw_len; i++)
  {
    if (raw[i] == 0x00)
    {
      hcfree (raw);

      return 0;
    }
  }

  if (raw_len >= out_max)
  {
    hcfree (raw);

    return 0;
  }

  memcpy (out, raw, raw_len);

  out[raw_len] = '\0';

  hcfree (raw);

  return raw_len;
}
