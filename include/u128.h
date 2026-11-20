/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_U128_H
#define HC_U128_H

// The keyspace type, see OpenCL/inc_types.h. printf has no conversion for it, so it is printed with
// u128_to_dec (). The kernels and the restore file carry it as two u64 halves.
//
// The core and the feeds count with the same helpers. shared.h includes this for the core and feed.h
// for a feed, which is why it holds nothing else.

#define U128_DEC_SIZE 40
#define U128_MAX      ((u128) ~((u128) 0))

HC_PLUGIN_API bool overflow_check_u128_add (const u128 a, const u128 b);
HC_PLUGIN_API bool overflow_check_u128_mul (const u128 a, const u128 b);

HC_API const char *u128_to_dec (char *buf, const u128 v);

static inline u64 u128_lo (const u128 v)
{
  const u64 r = (u64) v;

  return r;
}

static inline u64 u128_hi (MAYBE_UNUSED const u128 v)
{
  #ifdef U128_WIDE
  const u64 r = (u64) (v >> 64);
  #else
  const u64 r = 0;
  #endif

  return r;
}

// On a host without the wide type every hi passed here is zero.

static inline u128 u128_join (MAYBE_UNUSED const u64 hi, const u64 lo)
{
  #ifdef U128_WIDE
  const u128 r = (((u128) hi) << 64) | (((u128) lo) << 0);
  #else
  const u128 r = lo;
  #endif

  return r;
}

static inline bool u128_fits_u64 (const u128 v)
{
  const bool r = (u128_hi (v) == 0);

  return r;
}

// Only for a figure that is compared against small bounds, such as the option table's rules. A
// keyspace value is never stored this way, because the largest u64 is a real position.

static inline u64 u128_saturate_u64 (const u128 v)
{
  const u64 r = (u128_fits_u64 (v) == true) ? u128_lo (v) : UINT64_MAX;

  return r;
}

#endif // HC_U128_H
