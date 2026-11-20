/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_u128.h"

DECLSPEC u128_t hc_u128_make (const u64 hi, const u64 lo)
{
  u128_t r;

  r.lo = lo;
  r.hi = hi;

  return r;
}

DECLSPEC u128_t hc_u128_add_u64 (const u128_t a, const u64 b)
{
  u128_t r;

  r.lo = a.lo + b;
  r.hi = a.hi + ((r.lo < b) ? 1 : 0);

  return r;
}

// x /= d in place, and the remainder is returned. While the high limb is zero this is one u64
// division. Otherwise it is three: the high limb, then the low limb in two 32-bit halves. Each of
// those fits a u64, because the remainder carried into it is below d.

DECLSPEC u32 hc_u128_divmod_u32 (PRIVATE_AS u128_t *x, const u32 d)
{
  if (x->hi == 0)
  {
    const u64 q = x->lo / d;

    const u32 r = (u32) (x->lo - (q * d));

    x->lo = q;

    return r;
  }

  const u64 qh = x->hi / d;
  const u64 rh = x->hi - (qh * d);

  const u64 lo_hi = (x->lo >> 32) & 0xffffffff;
  const u64 lo_lo = (x->lo >>  0) & 0xffffffff;

  const u64 t1 = (rh << 32) | lo_hi;
  const u64 q1 = t1 / d;
  const u64 r1 = t1 - (q1 * d);

  const u64 t0 = (r1 << 32) | lo_lo;
  const u64 q0 = t0 / d;
  const u64 r0 = t0 - (q0 * d);

  x->hi = qh;
  x->lo = (q1 << 32) | q0;

  const u32 r = (u32) r0;

  return r;
}
