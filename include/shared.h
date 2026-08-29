/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_SHARED_H
#define HC_SHARED_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <math.h>

#ifndef __MINGW_PRINTF_FORMAT
#define __MINGW_PRINTF_FORMAT printf
#endif

HC_PLUGIN_API int sort_by_string_sized (const void *p1, const void *p2);
HC_PLUGIN_API int sort_by_stringptr    (const void *p1, const void *p2);

HC_PLUGIN_API bool overflow_check_u32_add (const u32 a, const u32 b);
HC_PLUGIN_API bool overflow_check_u32_mul (const u32 a, const u32 b);
HC_PLUGIN_API bool overflow_check_u64_add (const u64 a, const u64 b);
HC_PLUGIN_API bool overflow_check_u64_mul (const u64 a, const u64 b);

HC_PLUGIN_API bool is_power_of_2 (const u32 v);
HC_PLUGIN_API u32 smallest_repeat_double (const u32 v);

HC_PLUGIN_API u32 mydivc32 (const u32 dividend, const u32 divisor);
HC_PLUGIN_API u64 mydivc64 (const u64 dividend, const u64 divisor);

HC_PLUGIN_API void naive_replace (char *s, const char key_char, const char replace_char);
HC_PLUGIN_API void naive_escape (char *s, size_t s_max, const char key_char, const char escape_char);

HC_PLUGIN_API __attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) int hc_asprintf (char **strp, const char *fmt, ...);

HC_PLUGIN_API void  hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);
HC_PLUGIN_API void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);

HC_PLUGIN_API bool hc_string_is_digit (const char *s);
HC_PLUGIN_API int  hc_string_bom_size (const u8 *s);

HC_PLUGIN_API void hc_string_trim_trailing (char *s);
HC_PLUGIN_API void hc_string_trim_leading (char *s);

HC_PLUGIN_API u32 hc_strtoul  (const char *nptr, char **endptr, int base);
HC_PLUGIN_API u64 hc_strtoull (const char *nptr, char **endptr, int base);

HC_PLUGIN_API u32 power_of_two_ceil_32  (const u32 v);
HC_PLUGIN_API u32 power_of_two_floor_32 (const u32 v);

HC_PLUGIN_API u32 round_up_multiple_32 (const u32 v, const u32 m);
HC_PLUGIN_API u64 round_up_multiple_64 (const u64 v, const u64 m);

HC_PLUGIN_API void hc_strncat (u8 *dst, const u8 *src, const size_t n);

HC_PLUGIN_API int count_char (const u8 *buf, const int len, const u8 c);
HC_PLUGIN_API float get_entropy (const u8 *buf, const int len);

HC_API const char *strhashcategory (const u32 hash_category);
HC_API const char *stroptitype (const u32 opti_type);

HC_PLUGIN_API u32 previous_power_of_two (const u32 x);
HC_PLUGIN_API u32 next_power_of_two (const u32 x);

// On/off environment switch, looked up once. Pass a static int initialised to -1 as the cache.
bool hc_env_flag (const char *name, int *cache);

// Bounded appenders for a fixed size output buffer, used by outfile.c and potfile.c to build one
// cracked line. buf_sz is the whole buffer, and 1 byte is always kept back for the caller's trailing
// null. A field that does not fit is truncated. Each returns the new length.

int hc_append_raw    (char *buf, const int len, const int buf_sz, const u8 *src, int src_len);
int hc_append_hex    (char *buf, const int len, const int buf_sz, const u8 *src, int src_len);
int hc_append_hexify (char *buf, const int len, const int buf_sz, const u8 *src, int src_len);
int hc_append_chr    (char *buf, const int len, const int buf_sz, const char c);

// The candidate a cell reaches at il_pos, written into w, and its byte length as the answer.
//
// This is the one host copy of the device engine's expander, exported rather than internal so that
// outfile.c can rebuild a cracked plaintext with it. A second copy of this walk is a copy that will
// one day disagree with the kernel.
//
// It has to produce the same bytes the kernel does, so it reads the cell the same way: entry n of a
// slot is at pool_off + (n * ent_len) unless the cell says PCFG_CELL_VARLEN, in which case it is at
// pool[pool_off + n].
//
// base_len is the base word's length, which is the answer when the cell has no device slots at all and
// the base word is therefore the whole candidate. -1 means il_pos is past the end of the rectangle.

HC_PLUGIN_API int pcfg_expand (const pcfg_cell_t *cell, const u32 *pool, const u32 il_pos, u32 *w, const int base_len);

#endif // HC_SHARED_H
