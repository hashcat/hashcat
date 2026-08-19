/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "shared.h"
#include "memory.h"
#include <errno.h>
#include <inttypes.h>

static const char *const OPTI_STR_OPTIMIZED_KERNEL     = "Optimized-Kernel";
static const char *const OPTI_STR_ZERO_BYTE            = "Zero-Byte";
static const char *const OPTI_STR_PRECOMPUTE_INIT      = "Precompute-Init";
static const char *const OPTI_STR_MEET_IN_MIDDLE       = "Meet-In-The-Middle";
static const char *const OPTI_STR_EARLY_SKIP           = "Early-Skip";
static const char *const OPTI_STR_NOT_SALTED           = "Not-Salted";
static const char *const OPTI_STR_NOT_ITERATED         = "Not-Iterated";
static const char *const OPTI_STR_PREPENDED_SALT       = "Prepended-Salt";
static const char *const OPTI_STR_APPENDED_SALT        = "Appended-Salt";
static const char *const OPTI_STR_SINGLE_HASH          = "Single-Hash";
static const char *const OPTI_STR_SINGLE_SALT          = "Single-Salt";
static const char *const OPTI_STR_BRUTE_FORCE          = "Brute-Force";
static const char *const OPTI_STR_RAW_HASH             = "Raw-Hash";
static const char *const OPTI_STR_REGISTER_LIMIT       = "Register-Limit";
static const char *const OPTI_STR_SLOW_HASH_SIMD_INIT  = "Slow-Hash-SIMD-INIT";
static const char *const OPTI_STR_SLOW_HASH_SIMD_INIT2 = "Slow-Hash-SIMD-INIT-2";
static const char *const OPTI_STR_SLOW_HASH_SIMD_LOOP  = "Slow-Hash-SIMD-LOOP";
static const char *const OPTI_STR_SLOW_HASH_SIMD_LOOP2 = "Slow-Hash-SIMD-LOOP-2";
static const char *const OPTI_STR_SLOW_HASH_SIMD_COMP  = "Slow-Hash-SIMD-COMP";
static const char *const OPTI_STR_USES_BITS_8          = "Uses-8-Bit";
static const char *const OPTI_STR_USES_BITS_16         = "Uses-16-Bit";
static const char *const OPTI_STR_USES_BITS_32         = "Uses-32-Bit";
static const char *const OPTI_STR_USES_BITS_64         = "Uses-64-Bit";
static const char *const OPTI_STR_SLOW_HASH_DIMY_INIT  = "Slow-Hash-DimensionY-INIT";
static const char *const OPTI_STR_SLOW_HASH_DIMY_LOOP  = "Slow-Hash-DimensionY-LOOP";
static const char *const OPTI_STR_SLOW_HASH_DIMY_COMP  = "Slow-Hash-DimensionY-COMP";

static const char *const HASH_CATEGORY_UNDEFINED_STR              = "Undefined";
static const char *const HASH_CATEGORY_RAW_HASH_STR               = "Raw Hash";
static const char *const HASH_CATEGORY_RAW_HASH_SALTED_STR        = "Raw Hash salted and/or iterated";
static const char *const HASH_CATEGORY_RAW_HASH_AUTHENTICATED_STR = "Raw Hash authenticated";
static const char *const HASH_CATEGORY_RAW_CIPHER_KPA_STR         = "Raw Cipher, Known-plaintext attack";
static const char *const HASH_CATEGORY_GENERIC_KDF_STR            = "Generic KDF";
static const char *const HASH_CATEGORY_NETWORK_PROTOCOL_STR       = "Network Protocol";
static const char *const HASH_CATEGORY_FORUM_SOFTWARE_STR         = "Forums, CMS, E-Commerce";
static const char *const HASH_CATEGORY_DATABASE_SERVER_STR        = "Database Server";
static const char *const HASH_CATEGORY_NETWORK_SERVER_STR         = "FTP, HTTP, SMTP, LDAP Server";
static const char *const HASH_CATEGORY_RAW_CHECKSUM_STR           = "Raw Checksum";
static const char *const HASH_CATEGORY_OS_STR                     = "Operating System";
static const char *const HASH_CATEGORY_EAS_STR                    = "Enterprise Application Software (EAS)";
static const char *const HASH_CATEGORY_ARCHIVE_STR                = "Archive";
static const char *const HASH_CATEGORY_FDE_STR                    = "Full-Disk Encryption (FDE)";
static const char *const HASH_CATEGORY_FBE_STR                    = "File-Based Encryption (FBE)";
static const char *const HASH_CATEGORY_DOCUMENTS_STR              = "Document";
static const char *const HASH_CATEGORY_PASSWORD_MANAGER_STR       = "Password Manager";
static const char *const HASH_CATEGORY_OTP_STR                    = "One-Time Password";
static const char *const HASH_CATEGORY_PLAIN_STR                  = "Plaintext";
static const char *const HASH_CATEGORY_FRAMEWORK_STR              = "Framework";
static const char *const HASH_CATEGORY_PRIVATE_KEY_STR            = "Private Key";
static const char *const HASH_CATEGORY_IMS_STR                    = "Instant Messaging Service";
static const char *const HASH_CATEGORY_CRYPTOCURRENCY_WALLET_STR  = "Cryptocurrency Wallet";
static const char *const HASH_CATEGORY_APPLICATION_DATABASE_STR   = "Application Database";

int sort_by_string_sized (const void *p1, const void *p2)
{
  string_sized_t *s1 = (string_sized_t *) p1;
  string_sized_t *s2 = (string_sized_t *) p2;

  const int d = s1->len - s2->len;

  if (d != 0) return d;

  return memcmp (s1->buf, s2->buf, s1->len);
}

int sort_by_stringptr (const void *p1, const void *p2)
{
  const char* const *s1 = (const char* const *) p1;
  const char* const *s2 = (const char* const *) p2;

  return strcmp (*s1, *s2);
}

bool overflow_check_u32_add (const u32 a, const u32 b)
{
  return a > (UINT32_MAX - b);
}

bool overflow_check_u32_mul (const u32 a, const u32 b)
{
  if (a == 0 || b == 0) return false;

  return a > (UINT32_MAX / b);
}

bool overflow_check_u64_add (const u64 a, const u64 b)
{
  return a > (UINT64_MAX - b);
}

bool overflow_check_u64_mul (const u64 a, const u64 b)
{
  if (a == 0 || b == 0) return false;

  return a > (UINT64_MAX / b);
}

bool is_power_of_2 (const u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 smallest_repeat_double (const u32 v)
{
  return (v / (v & -v));
}

u32 mydivc32 (const u32 dividend, const u32 divisor)
{
  u32 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

u64 mydivc64 (const u64 dividend, const u64 divisor)
{
  u64 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

void naive_replace (char *s, const char key_char, const char replace_char)
{
  const size_t len = strlen (s);

  for (size_t in = 0; in < len; in++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s[in] = replace_char;
    }
  }
}

void naive_escape (char *s, size_t s_max, const char key_char, const char escape_char)
{
  char s_escaped[1024] = { 0 };

  size_t s_escaped_max = sizeof (s_escaped);

  const size_t len = strlen (s);

  for (size_t in = 0, out = 0; in < len; in++, out++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s_escaped[out] = escape_char;

      out++;
    }

    if (out == s_escaped_max - 2) break;

    s_escaped[out] = c;
  }

  strncpy (s, s_escaped, s_max - 1);
}

int hc_asprintf (char **strp, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  int rc = vasprintf (strp, fmt, args);
  va_end (args);
  return rc;
}

#if defined (_WIN)
#define __WINDOWS__
#endif
#include "sort_r.h"
#if defined (_WIN)
#undef __WINDOWS__
#endif

#if defined (__OpenBSD__)
static void *qsort_r_context;

static int qsort_r_comparator (const void *a, const void *b)
{
    typedef int (*compare_fn_t) (const void *, const void *, void *);

    compare_fn_t cmp = (compare_fn_t) qsort_r_context;

    return cmp (a, b, NULL);
}
#endif

void hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  #if defined (__OpenBSD__)

  (void) arg; // unused, make compiler happy

  qsort_r_context = (void *) compar;

  qsort (base, nmemb, size, qsort_r_comparator);

  #else

  sort_r (base, nmemb, size, compar, arg);

  #endif
}

void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  for (size_t l = 0, r = nmemb; r; r >>= 1)
  {
    const size_t m = r >> 1;

    const size_t c = l + m;

    const char *next = (const char *) base + (c * size);

    const int cmp = (*compar) (key, next, arg);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return ((void *) next);
  }

  return (NULL);
}

int hc_string_bom_size (const u8 *s)
{
  /* signatures from https://en.wikipedia.org/wiki/Byte_order_mark#Byte_order_marks_by_encoding */

  // utf-8

  if ((s[0] == 0xef)
   && (s[1] == 0xbb)
   && (s[2] == 0xbf)) return 3;

  // utf-16

  if ((s[0] == 0xfe)
   && (s[1] == 0xff)) return 2;

  if ((s[0] == 0xff)
   && (s[1] == 0xfe)) return 2;

  // utf-32

  if ((s[0] == 0x00)
   && (s[1] == 0x00)
   && (s[2] == 0xfe)
   && (s[3] == 0xff)) return 4;

  if ((s[0] == 0xff)
   && (s[1] == 0xfe)
   && (s[2] == 0x00)
   && (s[3] == 0x00)) return 4;

  // utf-7

  if ((s[0] == 0x2b)
   && (s[1] == 0x2f)
   && (s[2] == 0x76)
   && (s[3] == 0x38)) return 4;

  if ((s[0] == 0x2b)
   && (s[1] == 0x2f)
   && (s[2] == 0x76)
   && (s[3] == 0x39)) return 4;

  if ((s[0] == 0x2b)
   && (s[1] == 0x2f)
   && (s[2] == 0x76)
   && (s[3] == 0x2b)) return 4;

  if ((s[0] == 0x2b)
   && (s[1] == 0x2f)
   && (s[2] == 0x76)
   && (s[3] == 0x2f)) return 4;

  if ((s[0] == 0x2b)
   && (s[1] == 0x2f)
   && (s[2] == 0x76)
   && (s[3] == 0x38)
   && (s[4] == 0x2d)) return 5;

  // utf-1

  if ((s[0] == 0xf7)
   && (s[1] == 0x64)
   && (s[2] == 0x4c)) return 3;

  // utf-ebcdic

  if ((s[0] == 0xdd)
   && (s[1] == 0x73)
   && (s[2] == 0x66)
   && (s[3] == 0x73)) return 4;

  // scsu

  if ((s[0] == 0x0e)
   && (s[1] == 0xfe)
   && (s[2] == 0xff)) return 3;

  // bocu-1

  if ((s[0] == 0xfb)
   && (s[1] == 0xee)
   && (s[2] == 0x28)) return 3;

  // gb-18030

  if ((s[0] == 0x84)
   && (s[1] == 0x31)
   && (s[2] == 0x95)
   && (s[3] == 0x33)) return 4;

  return 0;
}

bool hc_string_is_digit (const char *s)
{
  if (s == NULL) return false;

  const size_t len = strlen (s);

  if (len == 0) return false;

  for (size_t i = 0; i < len; i++)
  {
    const int c = (const int) s[i];

    if (isdigit (c) == 0) return false;
  }

  return true;
}

void hc_string_trim_leading (char *s)
{
  int skip = 0;

  const int len = (int) strlen (s);

  for (int i = 0; i < len; i++)
  {
    const int c = (const int) s[i];

    if (isspace (c) == 0) break;

    skip++;
  }

  if (skip == 0) return;

  const int new_len = len - skip;

  memmove (s, s + skip, new_len);

  s[new_len] = 0;
}

void hc_string_trim_trailing (char *s)
{
  int skip = 0;

  const int len = (int) strlen (s);

  for (int i = len - 1; i >= 0; i--)
  {
    const int c = (const int) s[i];

    if (isspace (c) == 0) break;

    skip++;
  }

  if (skip == 0) return;

  const size_t new_len = len - skip;

  s[new_len] = 0;
}

u32 hc_strtoul (const char *nptr, char **endptr, int base)
{
  return (u32) strtoul (nptr, endptr, base);
}

u64 hc_strtoull (const char *nptr, char **endptr, int base)
{
  return (u64) strtoull (nptr, endptr, base);
}

u32 power_of_two_ceil_32 (const u32 v)
{
  u32 r = v;

  r--;

  r |= r >> 1;
  r |= r >> 2;
  r |= r >> 4;
  r |= r >> 8;
  r |= r >> 16;

  r++;

  return r;
}

u32 power_of_two_floor_32 (const u32 v)
{
  u32 r = power_of_two_ceil_32 (v);

  if (r > v)
  {
    r >>= 1;
  }

  return r;
}

u32 round_up_multiple_32 (const u32 v, const u32 m)
{
  if (m == 0) return v;

  const u32 r = v % m;

  if (r == 0) return v;

  return v + m - r;
}

u64 round_up_multiple_64 (const u64 v, const u64 m)
{
  if (m == 0) return v;

  const u64 r = v % m;

  if (r == 0) return v;

  return v + m - r;
}

// difference to original strncat is no returncode and u8* instead of char*

void hc_strncat (u8 *dst, const u8 *src, const size_t n)
{
  const size_t dst_len = strlen ((char *) dst);

  const u8 *src_ptr = src;

  u8 *dst_ptr = dst + dst_len;

  for (size_t i = 0; i < n && *src_ptr != 0; i++)
  {
    *dst_ptr++ = *src_ptr++;
  }

  *dst_ptr = 0;
}

int count_char (const u8 *buf, const int len, const u8 c)
{
  int r = 0;

  for (int i = 0; i < len; i++)
  {
    if (buf[i] == c) r++;
  }

  return r;
}

float get_entropy (const u8 *buf, const int len)
{
  float entropy = 0.0;

  for (int c = 0; c < 256; c++)
  {
    const int r = count_char (buf, len, (const u8) c);

    if (r == 0) continue;

    float w = (float) r / len;

    entropy += -w * log2f (w);
  }

  return entropy;
}

const char *strhashcategory (const u32 hash_category)
{
  switch (hash_category)
  {
    case HASH_CATEGORY_UNDEFINED:               return HASH_CATEGORY_UNDEFINED_STR;
    case HASH_CATEGORY_RAW_HASH:                return HASH_CATEGORY_RAW_HASH_STR;
    case HASH_CATEGORY_RAW_HASH_SALTED:         return HASH_CATEGORY_RAW_HASH_SALTED_STR;
    case HASH_CATEGORY_RAW_HASH_AUTHENTICATED:  return HASH_CATEGORY_RAW_HASH_AUTHENTICATED_STR;
    case HASH_CATEGORY_RAW_CIPHER_KPA:          return HASH_CATEGORY_RAW_CIPHER_KPA_STR;
    case HASH_CATEGORY_GENERIC_KDF:             return HASH_CATEGORY_GENERIC_KDF_STR;
    case HASH_CATEGORY_NETWORK_PROTOCOL:        return HASH_CATEGORY_NETWORK_PROTOCOL_STR;
    case HASH_CATEGORY_FORUM_SOFTWARE:          return HASH_CATEGORY_FORUM_SOFTWARE_STR;
    case HASH_CATEGORY_DATABASE_SERVER:         return HASH_CATEGORY_DATABASE_SERVER_STR;
    case HASH_CATEGORY_NETWORK_SERVER:          return HASH_CATEGORY_NETWORK_SERVER_STR;
    case HASH_CATEGORY_RAW_CHECKSUM:            return HASH_CATEGORY_RAW_CHECKSUM_STR;
    case HASH_CATEGORY_OS:                      return HASH_CATEGORY_OS_STR;
    case HASH_CATEGORY_EAS:                     return HASH_CATEGORY_EAS_STR;
    case HASH_CATEGORY_ARCHIVE:                 return HASH_CATEGORY_ARCHIVE_STR;
    case HASH_CATEGORY_FDE:                     return HASH_CATEGORY_FDE_STR;
    case HASH_CATEGORY_FBE:                     return HASH_CATEGORY_FBE_STR;
    case HASH_CATEGORY_DOCUMENTS:               return HASH_CATEGORY_DOCUMENTS_STR;
    case HASH_CATEGORY_PASSWORD_MANAGER:        return HASH_CATEGORY_PASSWORD_MANAGER_STR;
    case HASH_CATEGORY_OTP:                     return HASH_CATEGORY_OTP_STR;
    case HASH_CATEGORY_PLAIN:                   return HASH_CATEGORY_PLAIN_STR;
    case HASH_CATEGORY_FRAMEWORK:               return HASH_CATEGORY_FRAMEWORK_STR;
    case HASH_CATEGORY_PRIVATE_KEY:             return HASH_CATEGORY_PRIVATE_KEY_STR;
    case HASH_CATEGORY_IMS:                     return HASH_CATEGORY_IMS_STR;
    case HASH_CATEGORY_CRYPTOCURRENCY_WALLET:   return HASH_CATEGORY_CRYPTOCURRENCY_WALLET_STR;
    case HASH_CATEGORY_APPLICATION_DATABASE:    return HASH_CATEGORY_APPLICATION_DATABASE_STR;
  }

  return NULL;
}

const char *stroptitype (const u32 opti_type)
{
  switch (opti_type)
  {
    case OPTI_TYPE_OPTIMIZED_KERNEL:     return OPTI_STR_OPTIMIZED_KERNEL;
    case OPTI_TYPE_ZERO_BYTE:            return OPTI_STR_ZERO_BYTE;
    case OPTI_TYPE_PRECOMPUTE_INIT:      return OPTI_STR_PRECOMPUTE_INIT;
    case OPTI_TYPE_MEET_IN_MIDDLE:       return OPTI_STR_MEET_IN_MIDDLE;
    case OPTI_TYPE_EARLY_SKIP:           return OPTI_STR_EARLY_SKIP;
    case OPTI_TYPE_NOT_SALTED:           return OPTI_STR_NOT_SALTED;
    case OPTI_TYPE_NOT_ITERATED:         return OPTI_STR_NOT_ITERATED;
    case OPTI_TYPE_PREPENDED_SALT:       return OPTI_STR_PREPENDED_SALT;
    case OPTI_TYPE_APPENDED_SALT:        return OPTI_STR_APPENDED_SALT;
    case OPTI_TYPE_SINGLE_HASH:          return OPTI_STR_SINGLE_HASH;
    case OPTI_TYPE_SINGLE_SALT:          return OPTI_STR_SINGLE_SALT;
    case OPTI_TYPE_BRUTE_FORCE:          return OPTI_STR_BRUTE_FORCE;
    case OPTI_TYPE_RAW_HASH:             return OPTI_STR_RAW_HASH;
    case OPTI_TYPE_REGISTER_LIMIT:       return OPTI_STR_REGISTER_LIMIT;
    case OPTI_TYPE_SLOW_HASH_SIMD_INIT:  return OPTI_STR_SLOW_HASH_SIMD_INIT;
    case OPTI_TYPE_SLOW_HASH_SIMD_INIT2: return OPTI_STR_SLOW_HASH_SIMD_INIT2;
    case OPTI_TYPE_SLOW_HASH_SIMD_LOOP:  return OPTI_STR_SLOW_HASH_SIMD_LOOP;
    case OPTI_TYPE_SLOW_HASH_SIMD_LOOP2: return OPTI_STR_SLOW_HASH_SIMD_LOOP2;
    case OPTI_TYPE_SLOW_HASH_SIMD_COMP:  return OPTI_STR_SLOW_HASH_SIMD_COMP;
    case OPTI_TYPE_SLOW_HASH_DIMY_INIT:  return OPTI_STR_SLOW_HASH_DIMY_INIT;
    case OPTI_TYPE_SLOW_HASH_DIMY_LOOP:  return OPTI_STR_SLOW_HASH_DIMY_LOOP;
    case OPTI_TYPE_SLOW_HASH_DIMY_COMP:  return OPTI_STR_SLOW_HASH_DIMY_COMP;
    case OPTI_TYPE_USES_BITS_8:          return OPTI_STR_USES_BITS_8;
    case OPTI_TYPE_USES_BITS_16:         return OPTI_STR_USES_BITS_16;
    case OPTI_TYPE_USES_BITS_32:         return OPTI_STR_USES_BITS_32;
    case OPTI_TYPE_USES_BITS_64:         return OPTI_STR_USES_BITS_64;
  }

  return NULL;
}

u32 previous_power_of_two (const u32 x)
{
  // https://stackoverflow.com/questions/2679815/previous-power-of-2
  // really cool!

  if (x == 0) return 0;

  u32 r = x;

  r |= (r >>  1);
  r |= (r >>  2);
  r |= (r >>  4);
  r |= (r >>  8);
  r |= (r >> 16);

  return r - (r >> 1);
}

u32 next_power_of_two (const u32 x)
{
  if (x == 0) return 1;

  u32 r = x - 1;

  r |= (r >>  1);
  r |= (r >>  2);
  r |= (r >>  4);
  r |= (r >>  8);
  r |= (r >> 16);

  r++;

  return r;
}

// Whether an on/off environment switch is set, looked up once.
//
// Several of these exist (HASHCAT_PIPE, HASHCAT_MEMORY, HASHCAT_PIPE_SYNC, ...) and each one used to
// carry its own copy of the lookup and its own cache. The cache is what forced the duplication: one
// static inside a shared function would be a single slot shared by every variable, so the slot stays
// with the caller and only the logic moves here. Pass a static int initialised to -1.
//
// Presence is what counts, not the value, which is how these switches have always behaved.

bool hc_env_flag (const char *name, int *cache)
{
  if (*cache == -1) *cache = (getenv (name) != NULL) ? 1 : 0;

  const bool result = (*cache == 1) ? true : false;

  return result;
}

// A feed's settings, read out of the feed's own work arguments. What a setting is and why it is an
// argument rather than an option is written at feed_param_t in types.h.
//
// A work argument is a setting when it is key=value with a key that could not be a path: a letter
// followed by letters, digits, dash or underscore, and no directory separator anywhere in front of
// the '='. Everything else is a source, so a feed splits its own arguments by asking. A file whose
// name really does look like a setting is still reachable, as ./mode=2, because that has a
// separator in it.
//
// The test is deliberately about shape and not about which keys a feed knows, so that a misspelled
// setting is still recognised as a setting and can be reported as an unknown one. A rule that fell
// back to "not a key I know, so it must be a filename" would turn every typo into a missing file.

bool feed_param_is_setting (const char *arg)
{
  if (arg == NULL) return false;

  if ((arg[0] >= 'a' && arg[0] <= 'z') == false && (arg[0] >= 'A' && arg[0] <= 'Z') == false) return false;

  for (const char *p = arg; *p; p++)
  {
    if (*p == '=') return (p != arg) ? true : false;

    if (*p >= 'a' && *p <= 'z') continue;
    if (*p >= 'A' && *p <= 'Z') continue;
    if (*p >= '0' && *p <= '9') continue;
    if (*p == '-') continue;
    if (*p == '_') continue;

    return false;
  }

  return false;
}

// The value a setting was given, or NULL when the feed's arguments do not carry it. workv[0] is the
// plugin's own name and is skipped, the same way every feed skips it when reading its sources.

const char *feed_param_lookup (const int workc, char * const *workv, const char *key)
{
  if (workv == NULL) return NULL;
  if (key   == NULL) return NULL;

  const size_t key_len = strlen (key);

  for (int i = 1; i < workc; i++)
  {
    const char *arg = workv[i];

    if (feed_param_is_setting (arg) == false) continue;

    if (strncmp (arg, key, key_len) != 0) continue;

    if (arg[key_len] != '=') continue;

    return arg + key_len + 1;
  }

  return NULL;
}

static int feed_param_key_list (const feed_param_t *params, char *out_buf, const size_t out_size)
{
  int out_len = 0;

  for (const feed_param_t *p = params; p->key != NULL; p++)
  {
    const int rc = snprintf (out_buf + out_len, out_size - (size_t) out_len, "%s%s", (out_len == 0) ? "" : ", ", p->key);

    if (rc < 0) break;

    out_len += rc;

    if ((size_t) out_len >= out_size) return (int) out_size - 1;
  }

  return out_len;
}

static bool feed_param_store (const feed_param_t *param, const char *value, char *err_buf, const size_t err_size)
{
  switch (param->type)
  {
    case FEED_PARAM_TYPE_STR:
    {
      *((const char **) param->dst) = value;

      return true;
    }

    case FEED_PARAM_TYPE_BOOL:
    {
      if ((strcmp (value, "1") == 0) || (strcmp (value, "yes")   == 0) || (strcmp (value, "true")  == 0) || (strcmp (value, "on")  == 0))
      {
        *((bool *) param->dst) = true;

        return true;
      }

      if ((strcmp (value, "0") == 0) || (strcmp (value, "no")    == 0) || (strcmp (value, "false") == 0) || (strcmp (value, "off") == 0))
      {
        *((bool *) param->dst) = false;

        return true;
      }

      snprintf (err_buf, err_size, "%s: '%s' is not a yes or a no", param->key, value);

      return false;
    }

    case FEED_PARAM_TYPE_U64:
    {
      // strtoull takes a leading '-' and wraps it, so a negative number would arrive as a very large
      // one and pass any upper bound the feed set. It is rejected before the conversion sees it.

      if (value[0] == 0)
      {
        snprintf (err_buf, err_size, "%s: needs a number", param->key);

        return false;
      }

      if (value[0] == '-')
      {
        snprintf (err_buf, err_size, "%s: '%s' is negative", param->key, value);

        return false;
      }

      char *endptr = NULL;

      errno = 0;

      const unsigned long long v = strtoull (value, &endptr, 10);

      if ((endptr == value) || (*endptr != 0))
      {
        snprintf (err_buf, err_size, "%s: '%s' is not a number", param->key, value);

        return false;
      }

      if (errno == ERANGE)
      {
        snprintf (err_buf, err_size, "%s: '%s' does not fit", param->key, value);

        return false;
      }

      // A pair left at zero is a feed that did not want a range, not a range of nothing.

      if ((param->min != 0) || (param->max != 0))
      {
        if (((u64) v < param->min) || ((u64) v > param->max))
        {
          snprintf (err_buf, err_size, "%s: %s is outside %" PRIu64 " to %" PRIu64, param->key, value, param->min, param->max);

          return false;
        }
      }

      *((u64 *) param->dst) = (u64) v;

      return true;
    }

    case FEED_PARAM_TYPE_DBL:
    {
      char *endptr = NULL;

      errno = 0;

      const double v = strtod (value, &endptr);

      if ((endptr == value) || (*endptr != 0))
      {
        snprintf (err_buf, err_size, "%s: '%s' is not a number", param->key, value);

        return false;
      }

      if (errno == ERANGE)
      {
        snprintf (err_buf, err_size, "%s: '%s' does not fit", param->key, value);

        return false;
      }

      *((double *) param->dst) = v;

      return true;
    }
  }

  snprintf (err_buf, err_size, "%s: unknown setting type", param->key);

  return false;
}

// Read every setting in a feed's arguments into the variables the feed named, and refuse anything
// it did not name. Whatever the feed left in its variables before the call is the default, because
// an argument that is not there is not written.
//
// Refusing an unknown key is the point of the call. A feed's settings are invisible to --help and to
// tab completion, so a mistyped one has nothing else to catch it, and a feed that quietly ignored
// what it did not recognise would run a different attack than the one that was asked for and say
// nothing. A key given twice is refused for the same reason: last-one-wins reads as a preference
// being applied when it is a mistake.
//
// err_buf is written only on failure. Point it at global_ctx->error_msg and set global_ctx->error.

bool feed_param_parse (const int workc, char * const *workv, const feed_param_t *params, char *err_buf, const size_t err_size)
{
  if (params == NULL) return true;

  for (int i = 1; i < workc; i++)
  {
    const char *arg = workv[i];

    if (feed_param_is_setting (arg) == false) continue;

    const char *eq = strchr (arg, '=');

    const size_t key_len = (size_t) (eq - arg);

    const feed_param_t *found = NULL;

    for (const feed_param_t *p = params; p->key != NULL; p++)
    {
      if (strlen (p->key) != key_len) continue;
      if (strncmp (p->key, arg, key_len) != 0) continue;

      found = p;

      break;
    }

    if (found == NULL)
    {
      char keys[512];

      keys[0] = 0;

      feed_param_key_list (params, keys, sizeof (keys));

      snprintf (err_buf, err_size, "%.*s: no such setting. this feed takes: %s", (int) key_len, arg, keys);

      return false;
    }

    for (int j = 1; j < i; j++)
    {
      if (feed_param_is_setting (workv[j]) == false) continue;

      if (strncmp (workv[j], arg, key_len + 1) == 0)
      {
        snprintf (err_buf, err_size, "%s: given more than once", found->key);

        return false;
      }
    }

    if (feed_param_store (found, eq + 1, err_buf, err_size) == false) return false;
  }

  return true;
}

// The settings a feed takes, one per line, for the feed to print when its arguments make no sense.
// Returns the length written.

int feed_param_usage (const feed_param_t *params, char *out_buf, const size_t out_size)
{
  if (params == NULL) return 0;

  int out_len = 0;

  for (const feed_param_t *p = params; p->key != NULL; p++)
  {
    const char *type = "";

    switch (p->type)
    {
      case FEED_PARAM_TYPE_STR:  type = "=<str>";  break;
      case FEED_PARAM_TYPE_BOOL: type = "=<yes|no>"; break;
      case FEED_PARAM_TYPE_U64:  type = "=<num>";  break;
      case FEED_PARAM_TYPE_DBL:  type = "=<real>"; break;
    }

    char lhs[128];

    snprintf (lhs, sizeof (lhs), "%s%s", p->key, type);

    const int rc = snprintf (out_buf + out_len, out_size - (size_t) out_len, "  %-28s %s\n", lhs, (p->help == NULL) ? "" : p->help);

    if (rc < 0) break;

    out_len += rc;

    if ((size_t) out_len >= out_size) return (int) out_size - 1;
  }

  return out_len;
}
