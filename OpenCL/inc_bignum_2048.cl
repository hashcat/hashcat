/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_bignum_2048.h"

// 2048-bit modular arithmetic. Every value is u32[64], limb 0 least significant, and
// Montgomery form uses R = 2^2048. n must be odd.

DECLSPEC void bn2048_copy (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a)
{
  for (u32 i = 0; i < 64; i++) r[i] = a[i];
}

DECLSPEC u32 bn2048_ge (PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  for (u32 k = 64; k > 0; k--)
  {
    const u32 i = k - 1;

    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return 0;
  }

  return 1;
}

// r = (a - b) mod 2^2048, r may alias a or b

DECLSPEC void bn2048_sub (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 borrow = 0;

  for (u32 i = 0; i < 64; i++)
  {
    const u64 s = (u64) a[i] - b[i] - borrow;

    r[i] = (u32) s;

    borrow = (u32) (s >> 63);
  }
}

// r = 2 * r mod n, requires r < n

DECLSPEC void bn2048_mod_dbl (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *n)
{
  const u32 carry = r[63] >> 31;

  for (u32 k = 63; k > 0; k--) r[k] = (r[k] << 1) | (r[k - 1] >> 31);

  r[0] = r[0] << 1;

  // 2r < 2n, so one subtraction is enough, and with the carry set the true value is above n anyway

  if ((carry == 1) || (bn2048_ge (r, n) == 1)) bn2048_sub (r, r, n);
}

// r = a * b * R^-1 mod n, word by word (CIOS), with n0 = -n^-1 mod 2^32.
// a, b < R with a * b < R * n keeps t below 2n, so the result comes out canonical.
// r may alias a or b.

DECLSPEC void bn2048_mont_mul (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b, PRIVATE_AS const u32 *n, const u32 n0)
{
  u32 t[66] = { 0 };

  for (u32 i = 0; i < 64; i++)
  {
    u64 c = 0;

    for (u32 j = 0; j < 64; j++)
    {
      const u64 s = (u64) a[j] * b[i] + t[j] + c;

      t[j] = (u32) s;

      c = s >> 32;
    }

    const u64 s64 = (u64) t[64] + c;

    t[64] = (u32) (s64 >>  0);
    t[65] = (u32) (s64 >> 32);

    // m makes the low limb of t + m * n zero, which the shift by one limb then drops

    const u32 m = (u32) ((u64) t[0] * n0);

    c = ((u64) m * n[0] + t[0]) >> 32;

    for (u32 j = 1; j < 64; j++)
    {
      const u64 s = (u64) m * n[j] + t[j] + c;

      t[j - 1] = (u32) s;

      c = s >> 32;
    }

    const u64 s63 = (u64) t[64] + c;

    t[63] = (u32) s63;
    t[64] = t[65] + (u32) (s63 >> 32);
  }

  // t < 2n, t[64] is the 2^2048 bit

  bn2048_copy (r, t);

  if ((t[64] != 0) || (bn2048_ge (r, n) == 1)) bn2048_sub (r, r, n);
}

// n0 = -n^-1 mod 2^32, mont_one = R mod n. Returns false and leaves both untouched if n is even,
// which includes n = 0.

DECLSPEC bool bn2048_mont_ctx_init (PRIVATE_AS const u32 *n, PRIVATE_AS u32 *n0, PRIVATE_AS u32 *mont_one)
{
  if ((n[0] & 1) == 0) return false;

  // n^-1 mod 2^32 by Newton. n * n = 1 mod 8 for odd n gives 3 correct bits, each step doubles them

  u32 x = n[0];

  for (u32 i = 0; i < 4; i++)
  {
    const u32 nx = (u32) ((u64) n[0] * x);

    x = (u32) ((u64) x * (u32) (2 - nx));
  }

  // R mod n by doubling 1 mod n 2048 times. 1 >= n for odd n only when n = 1, where 1 mod n = 0

  u32 one[64] = { 1 };

  if (bn2048_ge (one, n) == 1) one[0] = 0;

  for (u32 i = 0; i < 2048; i++) bn2048_mod_dbl (one, n);

  *n0 = 0 - x;

  bn2048_copy (mont_one, one);

  return true;
}

// r = a * R mod n, a may be >= n. r may alias a.

DECLSPEC void bn2048_to_mont (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *n, const u32 n0, PRIVATE_AS const u32 *mont_one)
{
  // R^2 mod n from R mod n: 64 doublings give R * 2^64, and each Montgomery squaring turns
  // R * 2^k into R * 2^2k, so five of them reach R * 2^2048 = R^2

  u32 rr[64];

  bn2048_copy (rr, mont_one);

  for (u32 i = 0; i < 64; i++) bn2048_mod_dbl (rr, n);

  for (u32 i = 0; i < 5; i++) bn2048_mont_mul (rr, rr, rr, n, n0);

  bn2048_mont_mul (r, a, rr, n, n0);
}

// r = a * R^-1 mod n, the standard form of a Montgomery value. r may alias a.

DECLSPEC void bn2048_from_mont (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *n, const u32 n0)
{
  const u32 one[64] = { 1 };

  bn2048_mont_mul (r, a, one, n, n0);
}

// out = in^d mod n, canonical. in may be >= n, out may alias in.

DECLSPEC void bn2048_powm (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *in, PRIVATE_AS const u32 *d, PRIVATE_AS const u32 *n, const u32 n0, PRIVATE_AS const u32 *mont_one)
{
  u32 base[64];

  bn2048_to_mont (base, in, n, n0, mont_one);

  // skip the leading zero bits of d

  u32 bits = 0;

  for (u32 k = 2048; k > 0; k--)
  {
    const u32 i = k - 1;

    if (((d[i / 32] >> (i % 32)) & 1) == 0) continue;

    bits = k;

    break;
  }

  // left to right square and multiply, starting from 1 in Montgomery form. A d shared by all
  // work-items, such as one from the hash, keeps the branch below from diverging.

  u32 acc[64];

  bn2048_copy (acc, mont_one);

  for (u32 k = bits; k > 0; k--)
  {
    const u32 i = k - 1;

    bn2048_mont_mul (acc, acc, acc, n, n0);

    if (((d[i / 32] >> (i % 32)) & 1) == 1) bn2048_mont_mul (acc, acc, base, n, n0);
  }

  bn2048_from_mont (out, acc, n, n0);
}

// be is a 256 byte big-endian number held as bytes, 4 per u32 with the first byte in the low 8 bits
// of be[0], which is how a password or a hex-decoded buffer sits in u32 words. SHA-1 and SHA-2 keep
// their state as big-endian words instead, so such words need hc_swap32_S () first. The conversion
// reverses the words and swaps the bytes, so it is its own inverse. limbs may alias be.

DECLSPEC void bn2048_from_be (PRIVATE_AS u32 *limbs, PRIVATE_AS const u32 *be)
{
  for (u32 i = 0; i < 32; i++)
  {
    const u32 lo = be[i];
    const u32 hi = be[63 - i];

    limbs[i]      = hc_swap32_S (hi);
    limbs[63 - i] = hc_swap32_S (lo);
  }
}

DECLSPEC void bn2048_to_be (PRIVATE_AS u32 *be, PRIVATE_AS const u32 *limbs)
{
  bn2048_from_be (be, limbs);
}
