/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "shared.h"
#include "memory.h"

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
// Several of these exist (HASHCAT_PIPE, HASHCAT_MEMORY, HASHCAT_PIPE_SYNC, ...) and each would otherwise
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

// Expanding a PCFG cell on the host, so that a crack can be reported as the candidate that produced it
// rather than as the base word the device started from. This is the same walk as pcfg_expand () in
// OpenCL/inc_pcfg.cl and has to stay the same walk: the device decides which candidate matched, and
// this decides what that candidate was.
//
// Bytes are addressed directly here rather than through shifts, which is the same thing on a little
// endian host and is what the kernel's word arithmetic amounts to.

HC_PLUGIN_API int pcfg_expand (const pcfg_cell_t *cell, const u32 *pool, const u32 il_pos, u32 *w, const int base_len)
{
  if (pool == NULL) return -1;

  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  // Whether an entry is reached by multiplying or by looking its offset up, which is a property of the
  // grammar and therefore of the cell. The kernel knows it at build time; this is compiled once and is
  // told. See PCFG_DEV_VARLEN.

  const bool varlen = ((cell->flags & PCFG_CELL_VARLEN) != 0);

  // Nothing on the device and nothing to expand: the base word is the candidate, and its length is the
  // one the caller handed over. A position past the end of a rectangle of one is still past the end.

  if (slot_cnt == 0)
  {
    if (il_pos != 0) return -1;

    return base_len;
  }

  u32 digit[PCFG_DEV_MAXSLOT];

  u64 carry = il_pos;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    if (radix == 0) return false;

    // A capitalisation slot's digit field carries the upper case image base rather than a starting
    // digit, so it contributes nothing to the decomposition. An ordinary slot's is always zero today
    // and is reserved for a rectangle wider than the inner loop.

    // A capitalisation slot's digit field carries something other than a starting digit either way: the
    // upper case image's base without per entry offsets and the distance to it with them.

    const u64 start = ((PCFG_SLOT_KIND (cell->slots[j].packed) == PCFG_SLOT_KIND_CASE) || (varlen == true)) ? 0 : (u64) cell->slots[j].digit;

    const u64 t = start + carry;

    digit[j] = (u32) (t % radix);

    carry = t / radix;
  }

  if (carry != 0) return -1;

  const u8 *pb = (const u8 *) pool;

  u8 *wb = (u8 *) w;

  // Where each slot writes and how long the candidate ends up. Without per entry offsets both are
  // constants of the cell and sit in the descriptor; with them the offset is a running sum over the
  // digits, exactly as the kernel's odometer word carries it.

  u32 dpos[PCFG_DEV_MAXSLOT];

  u32 pos = PCFG_SLOT_DST_OFF (cell->slots[0].packed);

  for (u32 j = 0; j < slot_cnt; j++)
  {
    const u32 packed = cell->slots[j].packed;

    const u32 kind = PCFG_SLOT_KIND (packed);

    const u32 ent_len = (varlen == true) ? (pool[cell->slots[j].pool_off + digit[j] + 1] - pool[cell->slots[j].pool_off + digit[j]]) : PCFG_SLOT_ENT_LEN (packed);
    const u32 dst_off = (varlen == true) ? pos                                                                                      : PCFG_SLOT_DST_OFF (packed);

    dpos[j] = dst_off;

    if (kind == PCFG_SLOT_KIND_BYTES)
    {
      const u32 src = (varlen == true) ? pool[cell->slots[j].pool_off + digit[j]] : cell->slots[j].pool_off + (digit[j] * ent_len);

      for (u32 k = 0; k < ent_len; k++)
      {
        wb[dst_off + k] = pb[src + k];
      }

      pos += ent_len;

      continue;
    }

    // The capitalisation walk, character by character, which is pcfg_case_slot () in inc_pcfg.cl and
    // has to agree with it byte for byte. A mask writes over the token in front of it and adds nothing
    // of its own, so it takes that token's offset and leaves the running one where it found it.

    const u32 from = PCFG_SLOT_FROM (cell->slots[j].packed);

    const u32 tok_len = (varlen == true) ? (pool[cell->slots[from].pool_off + digit[from] + 1] - pool[cell->slots[from].pool_off + digit[from]]) : PCFG_SLOT_ENT_LEN (cell->slots[from].packed);

    const u32 mask_src = (varlen == true) ? pool[cell->slots[j].pool_off + digit[j]] : cell->slots[j].pool_off + (digit[j] * ent_len);
    const u32 up_src   = (varlen == true) ? pool[cell->slots[from].pool_off + digit[from]] + cell->slots[j].digit : cell->slots[j].digit + (digit[from] * tok_len);

    // Where the mask writes, which is where the token in front of it wrote. Without per entry offsets
    // slot_geometry () already put that offset in the mask's own descriptor, so the two agree.

    const u32 mdst_off = dpos[from];

    u32 ci = 0;
    u32 at = 0;

    while ((at < tok_len) && (ci < ent_len))
    {
      if (pb[mask_src + ci] == 'U') wb[mdst_off + at] = pb[up_src + at];

      at++;

      while (at < tok_len)
      {
        if ((wb[mdst_off + at] & 0xc0) != 0x80) break;

        if (pb[mask_src + ci] == 'U') wb[mdst_off + at] = pb[up_src + at];

        at++;
      }

      ci++;
    }
  }

  // How long the candidate is. The device slots are a suffix of the structure, so the last of them is
  // where the candidate ends whether or not the lengths vary, and the running offset says where that
  // is. A cell with no device slots rewrote nothing and its candidate is the base word, which only the
  // caller knows the length of.

  const int len = (int) pos;

  return len;
}
