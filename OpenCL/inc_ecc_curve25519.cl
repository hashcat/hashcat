/**
 * Curve25519 (Weierstrass form) elliptic curve arithmetic for hashcat.
 * Ported from inc_ecc_secp256k1.cl.
 *
 * Key differences from secp256k1:
 * - Prime: p = 2^255 - 19 (not 2^256 - 2^32 - 977)
 * - Weierstrass a != 0 (point_double needs a*z^4 term)
 * - mul_mod reduction: 2^256 = 38 (mod p)
 *
 * License: MIT
 */

#include "inc_ecc_curve25519.h"

// --- Basic 256-bit arithmetic (same structure as secp256k1) ---

DECLSPEC u32 curve25519_sub (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 c = 0;

  #if defined IS_NV && HAS_SUB == 1 && HAS_SUBC == 1
  asm volatile
  (
    "sub.cc.u32   %0,  %9, %17;"
    "subc.cc.u32  %1, %10, %18;"
    "subc.cc.u32  %2, %11, %19;"
    "subc.cc.u32  %3, %12, %20;"
    "subc.cc.u32  %4, %13, %21;"
    "subc.cc.u32  %5, %14, %22;"
    "subc.cc.u32  %6, %15, %23;"
    "subc.cc.u32  %7, %16, %24;"
    "subc.u32     %8,   0,   0;"
    : "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3]), "=r"(r[4]), "=r"(r[5]), "=r"(r[6]), "=r"(r[7]),
      "=r"(c)
    :  "r"(a[0]),  "r"(a[1]),  "r"(a[2]),  "r"(a[3]),  "r"(a[4]),  "r"(a[5]),  "r"(a[6]),  "r"(a[7]),
       "r"(b[0]),  "r"(b[1]),  "r"(b[2]),  "r"(b[3]),  "r"(b[4]),  "r"(b[5]),  "r"(b[6]),  "r"(b[7])
  );
  #else
  for (u32 i = 0; i < 8; i++)
  {
    const u32 diff = a[i] - b[i] - c;

    if (diff != a[i]) c = (diff > a[i]);

    r[i] = diff;
  }
  #endif

  return c;
}

DECLSPEC u32 curve25519_add (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 c = 0;

  #if defined IS_NV && HAS_ADD == 1 && HAS_ADDC == 1
  asm volatile
  (
    "add.cc.u32   %0,  %9, %17;"
    "addc.cc.u32  %1, %10, %18;"
    "addc.cc.u32  %2, %11, %19;"
    "addc.cc.u32  %3, %12, %20;"
    "addc.cc.u32  %4, %13, %21;"
    "addc.cc.u32  %5, %14, %22;"
    "addc.cc.u32  %6, %15, %23;"
    "addc.cc.u32  %7, %16, %24;"
    "addc.u32     %8,   0,   0;"
    : "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3]), "=r"(r[4]), "=r"(r[5]), "=r"(r[6]), "=r"(r[7]),
      "=r"(c)
    :  "r"(a[0]),  "r"(a[1]),  "r"(a[2]),  "r"(a[3]),  "r"(a[4]),  "r"(a[5]),  "r"(a[6]),  "r"(a[7]),
       "r"(b[0]),  "r"(b[1]),  "r"(b[2]),  "r"(b[3]),  "r"(b[4]),  "r"(b[5]),  "r"(b[6]),  "r"(b[7])
  );
  #else
  for (u32 i = 0; i < 8; i++)
  {
    const u32 t = a[i] + b[i] + c;

    if (t != a[i]) c = (t < a[i]);

    r[i] = t;
  }
  #endif

  return c;
}

DECLSPEC void curve25519_sub_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  const u32 c = curve25519_sub (r, a, b);

  if (c)
  {
    u32 t[8];

    t[0] = CURVE25519_P0;
    t[1] = CURVE25519_P1;
    t[2] = CURVE25519_P2;
    t[3] = CURVE25519_P3;
    t[4] = CURVE25519_P4;
    t[5] = CURVE25519_P5;
    t[6] = CURVE25519_P6;
    t[7] = CURVE25519_P7;

    curve25519_add (r, r, t);
  }
}

DECLSPEC void curve25519_add_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  const u32 c = curve25519_add (r, a, b);

  u32 t[8];

  t[0] = CURVE25519_P0;
  t[1] = CURVE25519_P1;
  t[2] = CURVE25519_P2;
  t[3] = CURVE25519_P3;
  t[4] = CURVE25519_P4;
  t[5] = CURVE25519_P5;
  t[6] = CURVE25519_P6;
  t[7] = CURVE25519_P7;

  u32 mod = 1;

  if (c == 0)
  {
    for (int i = 7; i >= 0; i--)
    {
      if (r[i] < t[i])
      {
        mod = 0;
        break;
      }

      if (r[i] > t[i]) break;
    }
  }

  if (mod == 1)
  {
    curve25519_sub (r, r, t);
  }
}

// --- Modular multiplication for p = 2^255 - 19 ---
// Reduction: 2^256 ≡ 38 (mod p)

DECLSPEC void curve25519_mul_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 t[16] = { 0 };

  // Schoolbook multiplication: a * b -> t[0..15]

  u32 t0 = 0;
  u32 t1 = 0;
  u32 c  = 0;

  for (u32 i = 0; i < 8; i++)
  {
    for (u32 j = 0; j <= i; j++)
    {
      u64 p = ((u64) a[j]) * b[i - j];

      u64 d = ((u64) t1) << 32 | t0;

      d += p;

      t0 = (u32) d;
      t1 = d >> 32;

      c += d < p;
    }

    t[i] = t0;

    t0 = t1;
    t1 = c;

    c = 0;
  }

  for (u32 i = 8; i < 15; i++)
  {
    for (u32 j = i - 7; j < 8; j++)
    {
      u64 p = ((u64) a[j]) * b[i - j];

      u64 d = ((u64) t1) << 32 | t0;

      d += p;

      t0 = (u32) d;
      t1 = d >> 32;

      c += d < p;
    }

    t[i] = t0;

    t0 = t1;
    t1 = c;

    c = 0;
  }

  t[15] = t0;

  // Reduction for p = 2^255 - 19:
  // 2^256 ≡ 38 (mod p), so multiply high 256 bits by 38 and add to low 256 bits

  u64 carry = 0;

  for (u32 i = 0; i < 8; i++)
  {
    carry += (u64) t[i] + (u64) t[i + 8] * 38;

    r[i] = (u32) carry;

    carry >>= 32;
  }

  // carry * 2^256 ≡ carry * 38 (mod p), carry is small (< 64)

  carry *= 38;

  for (u32 i = 0; i < 8; i++)
  {
    carry += (u64) r[i];

    r[i] = (u32) carry;

    carry >>= 32;

    if (carry == 0) break;
  }

  // Final conditional subtraction: if r >= p, subtract p

  u32 pp[8];

  pp[0] = CURVE25519_P0;
  pp[1] = CURVE25519_P1;
  pp[2] = CURVE25519_P2;
  pp[3] = CURVE25519_P3;
  pp[4] = CURVE25519_P4;
  pp[5] = CURVE25519_P5;
  pp[6] = CURVE25519_P6;
  pp[7] = CURVE25519_P7;

  // Check if r >= p (could happen, do at most 2 subtractions)

  for (u32 iter = 0; iter < 2; iter++)
  {
    u32 ge = 1;

    for (int i = 7; i >= 0; i--)
    {
      if (r[i] < pp[i]) { ge = 0; break; }
      if (r[i] > pp[i]) break;
    }

    if (ge)
    {
      curve25519_sub (r, r, pp);
    }
  }
}

// --- Modular inverse using binary extended GCD ---

DECLSPEC void curve25519_inv_mod (PRIVATE_AS u32 *a)
{
  u32 t0[8];

  t0[0] = a[0]; t0[1] = a[1]; t0[2] = a[2]; t0[3] = a[3];
  t0[4] = a[4]; t0[5] = a[5]; t0[6] = a[6]; t0[7] = a[7];

  u32 p[8];

  p[0] = CURVE25519_P0; p[1] = CURVE25519_P1; p[2] = CURVE25519_P2; p[3] = CURVE25519_P3;
  p[4] = CURVE25519_P4; p[5] = CURVE25519_P5; p[6] = CURVE25519_P6; p[7] = CURVE25519_P7;

  u32 t1[8];

  t1[0] = CURVE25519_P0; t1[1] = CURVE25519_P1; t1[2] = CURVE25519_P2; t1[3] = CURVE25519_P3;
  t1[4] = CURVE25519_P4; t1[5] = CURVE25519_P5; t1[6] = CURVE25519_P6; t1[7] = CURVE25519_P7;

  u32 t2[8] = { 0 };
  t2[0] = 0x00000001;

  u32 t3[8] = { 0 };

  u32 b = (t0[0] != t1[0]) | (t0[1] != t1[1]) | (t0[2] != t1[2]) | (t0[3] != t1[3])
        | (t0[4] != t1[4]) | (t0[5] != t1[5]) | (t0[6] != t1[6]) | (t0[7] != t1[7]);

  while (b)
  {
    if ((t0[0] & 1) == 0)
    {
      t0[0] = t0[0] >> 1 | t0[1] << 31; t0[1] = t0[1] >> 1 | t0[2] << 31;
      t0[2] = t0[2] >> 1 | t0[3] << 31; t0[3] = t0[3] >> 1 | t0[4] << 31;
      t0[4] = t0[4] >> 1 | t0[5] << 31; t0[5] = t0[5] >> 1 | t0[6] << 31;
      t0[6] = t0[6] >> 1 | t0[7] << 31; t0[7] = t0[7] >> 1;

      u32 c = 0;
      if (t2[0] & 1) c = curve25519_add (t2, t2, p);

      t2[0] = t2[0] >> 1 | t2[1] << 31; t2[1] = t2[1] >> 1 | t2[2] << 31;
      t2[2] = t2[2] >> 1 | t2[3] << 31; t2[3] = t2[3] >> 1 | t2[4] << 31;
      t2[4] = t2[4] >> 1 | t2[5] << 31; t2[5] = t2[5] >> 1 | t2[6] << 31;
      t2[6] = t2[6] >> 1 | t2[7] << 31; t2[7] = t2[7] >> 1 | c << 31;
    }
    else if ((t1[0] & 1) == 0)
    {
      t1[0] = t1[0] >> 1 | t1[1] << 31; t1[1] = t1[1] >> 1 | t1[2] << 31;
      t1[2] = t1[2] >> 1 | t1[3] << 31; t1[3] = t1[3] >> 1 | t1[4] << 31;
      t1[4] = t1[4] >> 1 | t1[5] << 31; t1[5] = t1[5] >> 1 | t1[6] << 31;
      t1[6] = t1[6] >> 1 | t1[7] << 31; t1[7] = t1[7] >> 1;

      u32 c = 0;
      if (t3[0] & 1) c = curve25519_add (t3, t3, p);

      t3[0] = t3[0] >> 1 | t3[1] << 31; t3[1] = t3[1] >> 1 | t3[2] << 31;
      t3[2] = t3[2] >> 1 | t3[3] << 31; t3[3] = t3[3] >> 1 | t3[4] << 31;
      t3[4] = t3[4] >> 1 | t3[5] << 31; t3[5] = t3[5] >> 1 | t3[6] << 31;
      t3[6] = t3[6] >> 1 | t3[7] << 31; t3[7] = t3[7] >> 1 | c << 31;
    }
    else
    {
      u32 gt = 0;

      for (int i = 7; i >= 0; i--)
      {
        if (t0[i] > t1[i]) { gt = 1; break; }
        if (t0[i] < t1[i]) break;
      }

      if (gt)
      {
        curve25519_sub (t0, t0, t1);

        t0[0] = t0[0] >> 1 | t0[1] << 31; t0[1] = t0[1] >> 1 | t0[2] << 31;
        t0[2] = t0[2] >> 1 | t0[3] << 31; t0[3] = t0[3] >> 1 | t0[4] << 31;
        t0[4] = t0[4] >> 1 | t0[5] << 31; t0[5] = t0[5] >> 1 | t0[6] << 31;
        t0[6] = t0[6] >> 1 | t0[7] << 31; t0[7] = t0[7] >> 1;

        u32 lt = 0;
        for (int i = 7; i >= 0; i--)
        {
          if (t2[i] < t3[i]) { lt = 1; break; }
          if (t2[i] > t3[i]) break;
        }
        if (lt) curve25519_add (t2, t2, p);
        curve25519_sub (t2, t2, t3);

        u32 c = 0;
        if (t2[0] & 1) c = curve25519_add (t2, t2, p);

        t2[0] = t2[0] >> 1 | t2[1] << 31; t2[1] = t2[1] >> 1 | t2[2] << 31;
        t2[2] = t2[2] >> 1 | t2[3] << 31; t2[3] = t2[3] >> 1 | t2[4] << 31;
        t2[4] = t2[4] >> 1 | t2[5] << 31; t2[5] = t2[5] >> 1 | t2[6] << 31;
        t2[6] = t2[6] >> 1 | t2[7] << 31; t2[7] = t2[7] >> 1 | c << 31;
      }
      else
      {
        curve25519_sub (t1, t1, t0);

        t1[0] = t1[0] >> 1 | t1[1] << 31; t1[1] = t1[1] >> 1 | t1[2] << 31;
        t1[2] = t1[2] >> 1 | t1[3] << 31; t1[3] = t1[3] >> 1 | t1[4] << 31;
        t1[4] = t1[4] >> 1 | t1[5] << 31; t1[5] = t1[5] >> 1 | t1[6] << 31;
        t1[6] = t1[6] >> 1 | t1[7] << 31; t1[7] = t1[7] >> 1;

        u32 lt = 0;
        for (int i = 7; i >= 0; i--)
        {
          if (t3[i] < t2[i]) { lt = 1; break; }
          if (t3[i] > t2[i]) break;
        }
        if (lt) curve25519_add (t3, t3, p);
        curve25519_sub (t3, t3, t2);

        u32 c = 0;
        if (t3[0] & 1) c = curve25519_add (t3, t3, p);

        t3[0] = t3[0] >> 1 | t3[1] << 31; t3[1] = t3[1] >> 1 | t3[2] << 31;
        t3[2] = t3[2] >> 1 | t3[3] << 31; t3[3] = t3[3] >> 1 | t3[4] << 31;
        t3[4] = t3[4] >> 1 | t3[5] << 31; t3[5] = t3[5] >> 1 | t3[6] << 31;
        t3[6] = t3[6] >> 1 | t3[7] << 31; t3[7] = t3[7] >> 1 | c << 31;
      }
    }

    b = (t0[0] != t1[0]) | (t0[1] != t1[1]) | (t0[2] != t1[2]) | (t0[3] != t1[3])
      | (t0[4] != t1[4]) | (t0[5] != t1[5]) | (t0[6] != t1[6]) | (t0[7] != t1[7]);
  }

  a[0] = t2[0]; a[1] = t2[1]; a[2] = t2[2]; a[3] = t2[3];
  a[4] = t2[4]; a[5] = t2[5]; a[6] = t2[6]; a[7] = t2[7];
}

// --- Point doubling for y^2 = x^3 + a*x + b (Jacobian coordinates) ---
// Unlike secp256k1 (a=0), Curve25519 Weierstrass has a != 0.
// Formula: m = (3*x^2 + a*z^4) / 2
//          X' = m^2 - 2*x*y^2
//          Y' = m*(x*y^2 - X') - y^4
//          Z' = y*z

DECLSPEC void curve25519_point_double (PRIVATE_AS u32 *x, PRIVATE_AS u32 *y, PRIVATE_AS u32 *z)
{
  u32 t1[8], t2[8], t3[8], t4[8], t5[8], t6[8];
  u32 z2[8], z4[8], az4[8];
  u32 a_curve[8];

  t1[0] = x[0]; t1[1] = x[1]; t1[2] = x[2]; t1[3] = x[3];
  t1[4] = x[4]; t1[5] = x[5]; t1[6] = x[6]; t1[7] = x[7];

  t2[0] = y[0]; t2[1] = y[1]; t2[2] = y[2]; t2[3] = y[3];
  t2[4] = y[4]; t2[5] = y[5]; t2[6] = y[6]; t2[7] = y[7];

  t3[0] = z[0]; t3[1] = z[1]; t3[2] = z[2]; t3[3] = z[3];
  t3[4] = z[4]; t3[5] = z[5]; t3[6] = z[6]; t3[7] = z[7];

  // Compute z^2 and z^4 before modifying z
  curve25519_mul_mod (z2, t3, t3);     // z^2
  curve25519_mul_mod (z4, z2, z2);     // z^4

  // a * z^4
  a_curve[0] = CURVE25519_A0; a_curve[1] = CURVE25519_A1;
  a_curve[2] = CURVE25519_A2; a_curve[3] = CURVE25519_A3;
  a_curve[4] = CURVE25519_A4; a_curve[5] = CURVE25519_A5;
  a_curve[6] = CURVE25519_A6; a_curve[7] = CURVE25519_A7;
  curve25519_mul_mod (az4, a_curve, z4); // a * z^4

  curve25519_mul_mod (t4, t1, t1);     // t4 = x^2
  curve25519_mul_mod (t5, t2, t2);     // t5 = y^2
  curve25519_mul_mod (t1, t1, t5);     // t1 = x*y^2
  curve25519_mul_mod (t5, t5, t5);     // t5 = y^4

  curve25519_mul_mod (t3, t2, t3);     // t3 = y*z = new Z

  curve25519_add_mod (t2, t4, t4);     // t2 = 2*x^2
  curve25519_add_mod (t4, t4, t2);     // t4 = 3*x^2

  curve25519_add_mod (t4, t4, az4);    // t4 = 3*x^2 + a*z^4  <-- KEY DIFFERENCE

  // Half: t4 = t4 / 2 (mod p)
  u32 c = 0;
  if (t4[0] & 1)
  {
    u32 t[8];
    t[0] = CURVE25519_P0; t[1] = CURVE25519_P1; t[2] = CURVE25519_P2; t[3] = CURVE25519_P3;
    t[4] = CURVE25519_P4; t[5] = CURVE25519_P5; t[6] = CURVE25519_P6; t[7] = CURVE25519_P7;
    c = curve25519_add (t4, t4, t);
  }

  t4[0] = t4[0] >> 1 | t4[1] << 31; t4[1] = t4[1] >> 1 | t4[2] << 31;
  t4[2] = t4[2] >> 1 | t4[3] << 31; t4[3] = t4[3] >> 1 | t4[4] << 31;
  t4[4] = t4[4] >> 1 | t4[5] << 31; t4[5] = t4[5] >> 1 | t4[6] << 31;
  t4[6] = t4[6] >> 1 | t4[7] << 31; t4[7] = t4[7] >> 1 | c << 31;

  curve25519_mul_mod (t6, t4, t4);     // t6 = m^2

  curve25519_add_mod (t2, t1, t1);     // t2 = 2 * x*y^2

  curve25519_sub_mod (t6, t6, t2);     // t6 = m^2 - 2*x*y^2 = X'
  curve25519_sub_mod (t1, t1, t6);     // t1 = x*y^2 - X'

  curve25519_mul_mod (t4, t4, t1);     // t4 = m*(x*y^2 - X')

  curve25519_sub_mod (t1, t4, t5);     // t1 = m*(x*y^2 - X') - y^4 = Y'

  x[0] = t6[0]; x[1] = t6[1]; x[2] = t6[2]; x[3] = t6[3];
  x[4] = t6[4]; x[5] = t6[5]; x[6] = t6[6]; x[7] = t6[7];

  y[0] = t1[0]; y[1] = t1[1]; y[2] = t1[2]; y[3] = t1[3];
  y[4] = t1[4]; y[5] = t1[5]; y[6] = t1[6]; y[7] = t1[7];

  z[0] = t3[0]; z[1] = t3[1]; z[2] = t3[2]; z[3] = t3[3];
  z[4] = t3[4]; z[5] = t3[5]; z[6] = t3[6]; z[7] = t3[7];
}

// --- Point addition (mixed: z2 = 1) ---
// Same formula as secp256k1 (madd-2004-hmv), curve parameter 'a' not involved in point_add

DECLSPEC void curve25519_point_add (PRIVATE_AS u32 *x1, PRIVATE_AS u32 *y1, PRIVATE_AS u32 *z1, PRIVATE_AS const u32 *x2, PRIVATE_AS const u32 *y2)
{
  u32 t1[8], t2[8], t3[8], t4[8], t5[8], t6[8], t7[8], t8[8], t9[8];

  t1[0] = x1[0]; t1[1] = x1[1]; t1[2] = x1[2]; t1[3] = x1[3];
  t1[4] = x1[4]; t1[5] = x1[5]; t1[6] = x1[6]; t1[7] = x1[7];

  t2[0] = y1[0]; t2[1] = y1[1]; t2[2] = y1[2]; t2[3] = y1[3];
  t2[4] = y1[4]; t2[5] = y1[5]; t2[6] = y1[6]; t2[7] = y1[7];

  t3[0] = z1[0]; t3[1] = z1[1]; t3[2] = z1[2]; t3[3] = z1[3];
  t3[4] = z1[4]; t3[5] = z1[5]; t3[6] = z1[6]; t3[7] = z1[7];

  t4[0] = x2[0]; t4[1] = x2[1]; t4[2] = x2[2]; t4[3] = x2[3];
  t4[4] = x2[4]; t4[5] = x2[5]; t4[6] = x2[6]; t4[7] = x2[7];

  t5[0] = y2[0]; t5[1] = y2[1]; t5[2] = y2[2]; t5[3] = y2[3];
  t5[4] = y2[4]; t5[5] = y2[5]; t5[6] = y2[6]; t5[7] = y2[7];

  curve25519_mul_mod (t6, t3, t3);     // t6 = z1^2
  curve25519_mul_mod (t7, t6, t3);     // t7 = z1^3
  curve25519_mul_mod (t6, t6, t4);     // t6 = z1^2 * x2
  curve25519_mul_mod (t7, t7, t5);     // t7 = z1^3 * y2

  curve25519_sub_mod (t6, t6, t1);     // t6 = z1^2*x2 - x1
  curve25519_sub_mod (t7, t7, t2);     // t7 = z1^3*y2 - y1

  curve25519_mul_mod (t8, t3, t6);     // t8 = z1*t6 = z3
  curve25519_mul_mod (t4, t6, t6);     // t4 = t6^2
  curve25519_mul_mod (t9, t4, t6);     // t9 = t6^3
  curve25519_mul_mod (t4, t4, t1);     // t4 = t6^2 * x1

  // t6 = 2 * t4 (left shift)
  t6[7] = t4[7] << 1 | t4[6] >> 31;
  t6[6] = t4[6] << 1 | t4[5] >> 31;
  t6[5] = t4[5] << 1 | t4[4] >> 31;
  t6[4] = t4[4] << 1 | t4[3] >> 31;
  t6[3] = t4[3] << 1 | t4[2] >> 31;
  t6[2] = t4[2] << 1 | t4[1] >> 31;
  t6[1] = t4[1] << 1 | t4[0] >> 31;
  t6[0] = t4[0] << 1;

  // Handle overflow: if bit 255 was set, reduce mod p
  // For p = 2^255 - 19: if the top bit overflows, we add 2*19 = 38
  if (t4[7] & 0x80000000)
  {
    u32 a[8] = { 0 };
    a[0] = 38;
    curve25519_add (t6, t6, a);
  }

  // Reduce if >= p
  {
    u32 pp[8];
    pp[0] = CURVE25519_P0; pp[1] = CURVE25519_P1; pp[2] = CURVE25519_P2; pp[3] = CURVE25519_P3;
    pp[4] = CURVE25519_P4; pp[5] = CURVE25519_P5; pp[6] = CURVE25519_P6; pp[7] = CURVE25519_P7;

    u32 ge = 1;
    for (int i = 7; i >= 0; i--)
    {
      if (t6[i] < pp[i]) { ge = 0; break; }
      if (t6[i] > pp[i]) break;
    }
    if (ge) curve25519_sub (t6, t6, pp);
  }

  curve25519_mul_mod (t5, t7, t7);     // t5 = t7^2
  curve25519_sub_mod (t5, t5, t6);     // t5 = t7^2 - 2*t4
  curve25519_sub_mod (t5, t5, t9);     // t5 = t7^2 - 2*t4 - t6^3 = x3
  curve25519_sub_mod (t4, t4, t5);     // t4 = t4 - x3
  curve25519_mul_mod (t4, t4, t7);     // t4 = (t4-x3)*t7
  curve25519_mul_mod (t9, t9, t2);     // t9 = t6^3 * y1
  curve25519_sub_mod (t9, t4, t9);     // t9 = (t4-x3)*t7 - t6^3*y1 = y3

  x1[0] = t5[0]; x1[1] = t5[1]; x1[2] = t5[2]; x1[3] = t5[3];
  x1[4] = t5[4]; x1[5] = t5[5]; x1[6] = t5[6]; x1[7] = t5[7];

  y1[0] = t9[0]; y1[1] = t9[1]; y1[2] = t9[2]; y1[3] = t9[3];
  y1[4] = t9[4]; y1[5] = t9[5]; y1[6] = t9[6]; y1[7] = t9[7];

  z1[0] = t8[0]; z1[1] = t8[1]; z1[2] = t8[2]; z1[3] = t8[3];
  z1[4] = t8[4]; z1[5] = t8[5]; z1[6] = t8[6]; z1[7] = t8[7];
}

// --- Set pre-computed basepoint G (hardcoded constants, window=5: 8 points) ---

DECLSPEC void curve25519_set_precomputed_basepoint_g (PRIVATE_AS curve25519_t *r)
{
  // 1G
  r->xy[  0] = CURVE25519_G_PRE_COMPUTED_00;  r->xy[  1] = CURVE25519_G_PRE_COMPUTED_01;
  r->xy[  2] = CURVE25519_G_PRE_COMPUTED_02;  r->xy[  3] = CURVE25519_G_PRE_COMPUTED_03;
  r->xy[  4] = CURVE25519_G_PRE_COMPUTED_04;  r->xy[  5] = CURVE25519_G_PRE_COMPUTED_05;
  r->xy[  6] = CURVE25519_G_PRE_COMPUTED_06;  r->xy[  7] = CURVE25519_G_PRE_COMPUTED_07;
  r->xy[  8] = CURVE25519_G_PRE_COMPUTED_08;  r->xy[  9] = CURVE25519_G_PRE_COMPUTED_09;
  r->xy[ 10] = CURVE25519_G_PRE_COMPUTED_10;  r->xy[ 11] = CURVE25519_G_PRE_COMPUTED_11;
  r->xy[ 12] = CURVE25519_G_PRE_COMPUTED_12;  r->xy[ 13] = CURVE25519_G_PRE_COMPUTED_13;
  r->xy[ 14] = CURVE25519_G_PRE_COMPUTED_14;  r->xy[ 15] = CURVE25519_G_PRE_COMPUTED_15;
  r->xy[ 16] = CURVE25519_G_PRE_COMPUTED_16;  r->xy[ 17] = CURVE25519_G_PRE_COMPUTED_17;
  r->xy[ 18] = CURVE25519_G_PRE_COMPUTED_18;  r->xy[ 19] = CURVE25519_G_PRE_COMPUTED_19;
  r->xy[ 20] = CURVE25519_G_PRE_COMPUTED_20;  r->xy[ 21] = CURVE25519_G_PRE_COMPUTED_21;
  r->xy[ 22] = CURVE25519_G_PRE_COMPUTED_22;  r->xy[ 23] = CURVE25519_G_PRE_COMPUTED_23;
  // 3G
  r->xy[ 24] = CURVE25519_G_PRE_COMPUTED_24;  r->xy[ 25] = CURVE25519_G_PRE_COMPUTED_25;
  r->xy[ 26] = CURVE25519_G_PRE_COMPUTED_26;  r->xy[ 27] = CURVE25519_G_PRE_COMPUTED_27;
  r->xy[ 28] = CURVE25519_G_PRE_COMPUTED_28;  r->xy[ 29] = CURVE25519_G_PRE_COMPUTED_29;
  r->xy[ 30] = CURVE25519_G_PRE_COMPUTED_30;  r->xy[ 31] = CURVE25519_G_PRE_COMPUTED_31;
  r->xy[ 32] = CURVE25519_G_PRE_COMPUTED_32;  r->xy[ 33] = CURVE25519_G_PRE_COMPUTED_33;
  r->xy[ 34] = CURVE25519_G_PRE_COMPUTED_34;  r->xy[ 35] = CURVE25519_G_PRE_COMPUTED_35;
  r->xy[ 36] = CURVE25519_G_PRE_COMPUTED_36;  r->xy[ 37] = CURVE25519_G_PRE_COMPUTED_37;
  r->xy[ 38] = CURVE25519_G_PRE_COMPUTED_38;  r->xy[ 39] = CURVE25519_G_PRE_COMPUTED_39;
  r->xy[ 40] = CURVE25519_G_PRE_COMPUTED_40;  r->xy[ 41] = CURVE25519_G_PRE_COMPUTED_41;
  r->xy[ 42] = CURVE25519_G_PRE_COMPUTED_42;  r->xy[ 43] = CURVE25519_G_PRE_COMPUTED_43;
  r->xy[ 44] = CURVE25519_G_PRE_COMPUTED_44;  r->xy[ 45] = CURVE25519_G_PRE_COMPUTED_45;
  r->xy[ 46] = CURVE25519_G_PRE_COMPUTED_46;  r->xy[ 47] = CURVE25519_G_PRE_COMPUTED_47;
  // 5G
  r->xy[ 48] = CURVE25519_G_PRE_COMPUTED_48;  r->xy[ 49] = CURVE25519_G_PRE_COMPUTED_49;
  r->xy[ 50] = CURVE25519_G_PRE_COMPUTED_50;  r->xy[ 51] = CURVE25519_G_PRE_COMPUTED_51;
  r->xy[ 52] = CURVE25519_G_PRE_COMPUTED_52;  r->xy[ 53] = CURVE25519_G_PRE_COMPUTED_53;
  r->xy[ 54] = CURVE25519_G_PRE_COMPUTED_54;  r->xy[ 55] = CURVE25519_G_PRE_COMPUTED_55;
  r->xy[ 56] = CURVE25519_G_PRE_COMPUTED_56;  r->xy[ 57] = CURVE25519_G_PRE_COMPUTED_57;
  r->xy[ 58] = CURVE25519_G_PRE_COMPUTED_58;  r->xy[ 59] = CURVE25519_G_PRE_COMPUTED_59;
  r->xy[ 60] = CURVE25519_G_PRE_COMPUTED_60;  r->xy[ 61] = CURVE25519_G_PRE_COMPUTED_61;
  r->xy[ 62] = CURVE25519_G_PRE_COMPUTED_62;  r->xy[ 63] = CURVE25519_G_PRE_COMPUTED_63;
  r->xy[ 64] = CURVE25519_G_PRE_COMPUTED_64;  r->xy[ 65] = CURVE25519_G_PRE_COMPUTED_65;
  r->xy[ 66] = CURVE25519_G_PRE_COMPUTED_66;  r->xy[ 67] = CURVE25519_G_PRE_COMPUTED_67;
  r->xy[ 68] = CURVE25519_G_PRE_COMPUTED_68;  r->xy[ 69] = CURVE25519_G_PRE_COMPUTED_69;
  r->xy[ 70] = CURVE25519_G_PRE_COMPUTED_70;  r->xy[ 71] = CURVE25519_G_PRE_COMPUTED_71;
  // 7G
  r->xy[ 72] = CURVE25519_G_PRE_COMPUTED_72;  r->xy[ 73] = CURVE25519_G_PRE_COMPUTED_73;
  r->xy[ 74] = CURVE25519_G_PRE_COMPUTED_74;  r->xy[ 75] = CURVE25519_G_PRE_COMPUTED_75;
  r->xy[ 76] = CURVE25519_G_PRE_COMPUTED_76;  r->xy[ 77] = CURVE25519_G_PRE_COMPUTED_77;
  r->xy[ 78] = CURVE25519_G_PRE_COMPUTED_78;  r->xy[ 79] = CURVE25519_G_PRE_COMPUTED_79;
  r->xy[ 80] = CURVE25519_G_PRE_COMPUTED_80;  r->xy[ 81] = CURVE25519_G_PRE_COMPUTED_81;
  r->xy[ 82] = CURVE25519_G_PRE_COMPUTED_82;  r->xy[ 83] = CURVE25519_G_PRE_COMPUTED_83;
  r->xy[ 84] = CURVE25519_G_PRE_COMPUTED_84;  r->xy[ 85] = CURVE25519_G_PRE_COMPUTED_85;
  r->xy[ 86] = CURVE25519_G_PRE_COMPUTED_86;  r->xy[ 87] = CURVE25519_G_PRE_COMPUTED_87;
  r->xy[ 88] = CURVE25519_G_PRE_COMPUTED_88;  r->xy[ 89] = CURVE25519_G_PRE_COMPUTED_89;
  r->xy[ 90] = CURVE25519_G_PRE_COMPUTED_90;  r->xy[ 91] = CURVE25519_G_PRE_COMPUTED_91;
  r->xy[ 92] = CURVE25519_G_PRE_COMPUTED_92;  r->xy[ 93] = CURVE25519_G_PRE_COMPUTED_93;
  r->xy[ 94] = CURVE25519_G_PRE_COMPUTED_94;  r->xy[ 95] = CURVE25519_G_PRE_COMPUTED_95;
  // 9G
  r->xy[ 96] = CURVE25519_G_PRE_COMPUTED_96;  r->xy[ 97] = CURVE25519_G_PRE_COMPUTED_97;
  r->xy[ 98] = CURVE25519_G_PRE_COMPUTED_98;  r->xy[ 99] = CURVE25519_G_PRE_COMPUTED_99;
  r->xy[100] = CURVE25519_G_PRE_COMPUTED_100; r->xy[101] = CURVE25519_G_PRE_COMPUTED_101;
  r->xy[102] = CURVE25519_G_PRE_COMPUTED_102; r->xy[103] = CURVE25519_G_PRE_COMPUTED_103;
  r->xy[104] = CURVE25519_G_PRE_COMPUTED_104; r->xy[105] = CURVE25519_G_PRE_COMPUTED_105;
  r->xy[106] = CURVE25519_G_PRE_COMPUTED_106; r->xy[107] = CURVE25519_G_PRE_COMPUTED_107;
  r->xy[108] = CURVE25519_G_PRE_COMPUTED_108; r->xy[109] = CURVE25519_G_PRE_COMPUTED_109;
  r->xy[110] = CURVE25519_G_PRE_COMPUTED_110; r->xy[111] = CURVE25519_G_PRE_COMPUTED_111;
  r->xy[112] = CURVE25519_G_PRE_COMPUTED_112; r->xy[113] = CURVE25519_G_PRE_COMPUTED_113;
  r->xy[114] = CURVE25519_G_PRE_COMPUTED_114; r->xy[115] = CURVE25519_G_PRE_COMPUTED_115;
  r->xy[116] = CURVE25519_G_PRE_COMPUTED_116; r->xy[117] = CURVE25519_G_PRE_COMPUTED_117;
  r->xy[118] = CURVE25519_G_PRE_COMPUTED_118; r->xy[119] = CURVE25519_G_PRE_COMPUTED_119;
  // 11G
  r->xy[120] = CURVE25519_G_PRE_COMPUTED_120; r->xy[121] = CURVE25519_G_PRE_COMPUTED_121;
  r->xy[122] = CURVE25519_G_PRE_COMPUTED_122; r->xy[123] = CURVE25519_G_PRE_COMPUTED_123;
  r->xy[124] = CURVE25519_G_PRE_COMPUTED_124; r->xy[125] = CURVE25519_G_PRE_COMPUTED_125;
  r->xy[126] = CURVE25519_G_PRE_COMPUTED_126; r->xy[127] = CURVE25519_G_PRE_COMPUTED_127;
  r->xy[128] = CURVE25519_G_PRE_COMPUTED_128; r->xy[129] = CURVE25519_G_PRE_COMPUTED_129;
  r->xy[130] = CURVE25519_G_PRE_COMPUTED_130; r->xy[131] = CURVE25519_G_PRE_COMPUTED_131;
  r->xy[132] = CURVE25519_G_PRE_COMPUTED_132; r->xy[133] = CURVE25519_G_PRE_COMPUTED_133;
  r->xy[134] = CURVE25519_G_PRE_COMPUTED_134; r->xy[135] = CURVE25519_G_PRE_COMPUTED_135;
  r->xy[136] = CURVE25519_G_PRE_COMPUTED_136; r->xy[137] = CURVE25519_G_PRE_COMPUTED_137;
  r->xy[138] = CURVE25519_G_PRE_COMPUTED_138; r->xy[139] = CURVE25519_G_PRE_COMPUTED_139;
  r->xy[140] = CURVE25519_G_PRE_COMPUTED_140; r->xy[141] = CURVE25519_G_PRE_COMPUTED_141;
  r->xy[142] = CURVE25519_G_PRE_COMPUTED_142; r->xy[143] = CURVE25519_G_PRE_COMPUTED_143;
  // 13G
  r->xy[144] = CURVE25519_G_PRE_COMPUTED_144; r->xy[145] = CURVE25519_G_PRE_COMPUTED_145;
  r->xy[146] = CURVE25519_G_PRE_COMPUTED_146; r->xy[147] = CURVE25519_G_PRE_COMPUTED_147;
  r->xy[148] = CURVE25519_G_PRE_COMPUTED_148; r->xy[149] = CURVE25519_G_PRE_COMPUTED_149;
  r->xy[150] = CURVE25519_G_PRE_COMPUTED_150; r->xy[151] = CURVE25519_G_PRE_COMPUTED_151;
  r->xy[152] = CURVE25519_G_PRE_COMPUTED_152; r->xy[153] = CURVE25519_G_PRE_COMPUTED_153;
  r->xy[154] = CURVE25519_G_PRE_COMPUTED_154; r->xy[155] = CURVE25519_G_PRE_COMPUTED_155;
  r->xy[156] = CURVE25519_G_PRE_COMPUTED_156; r->xy[157] = CURVE25519_G_PRE_COMPUTED_157;
  r->xy[158] = CURVE25519_G_PRE_COMPUTED_158; r->xy[159] = CURVE25519_G_PRE_COMPUTED_159;
  r->xy[160] = CURVE25519_G_PRE_COMPUTED_160; r->xy[161] = CURVE25519_G_PRE_COMPUTED_161;
  r->xy[162] = CURVE25519_G_PRE_COMPUTED_162; r->xy[163] = CURVE25519_G_PRE_COMPUTED_163;
  r->xy[164] = CURVE25519_G_PRE_COMPUTED_164; r->xy[165] = CURVE25519_G_PRE_COMPUTED_165;
  r->xy[166] = CURVE25519_G_PRE_COMPUTED_166; r->xy[167] = CURVE25519_G_PRE_COMPUTED_167;
  // 15G
  r->xy[168] = CURVE25519_G_PRE_COMPUTED_168; r->xy[169] = CURVE25519_G_PRE_COMPUTED_169;
  r->xy[170] = CURVE25519_G_PRE_COMPUTED_170; r->xy[171] = CURVE25519_G_PRE_COMPUTED_171;
  r->xy[172] = CURVE25519_G_PRE_COMPUTED_172; r->xy[173] = CURVE25519_G_PRE_COMPUTED_173;
  r->xy[174] = CURVE25519_G_PRE_COMPUTED_174; r->xy[175] = CURVE25519_G_PRE_COMPUTED_175;
  r->xy[176] = CURVE25519_G_PRE_COMPUTED_176; r->xy[177] = CURVE25519_G_PRE_COMPUTED_177;
  r->xy[178] = CURVE25519_G_PRE_COMPUTED_178; r->xy[179] = CURVE25519_G_PRE_COMPUTED_179;
  r->xy[180] = CURVE25519_G_PRE_COMPUTED_180; r->xy[181] = CURVE25519_G_PRE_COMPUTED_181;
  r->xy[182] = CURVE25519_G_PRE_COMPUTED_182; r->xy[183] = CURVE25519_G_PRE_COMPUTED_183;
  r->xy[184] = CURVE25519_G_PRE_COMPUTED_184; r->xy[185] = CURVE25519_G_PRE_COMPUTED_185;
  r->xy[186] = CURVE25519_G_PRE_COMPUTED_186; r->xy[187] = CURVE25519_G_PRE_COMPUTED_187;
  r->xy[188] = CURVE25519_G_PRE_COMPUTED_188; r->xy[189] = CURVE25519_G_PRE_COMPUTED_189;
  r->xy[190] = CURVE25519_G_PRE_COMPUTED_190; r->xy[191] = CURVE25519_G_PRE_COMPUTED_191;
}

// --- wNAF conversion (window=5, byte-packed: 4 entries per u32) ---
// Encoding: val is stored as a byte. odd val = positive, even val = negative.
// val=1 -> +1G, val=2 -> -1G, val=3 -> +3G, val=4 -> -3G, ...
// val=15 -> +15G, val=16 -> -15G
// Lookup: odd = val & 1, point_index = ((val - 1 + odd) >> 1), stride = 24

DECLSPEC int curve25519_convert_to_window_naf (PRIVATE_AS u32 *naf, PRIVATE_AS const u32 *k)
{
  int loop_start = 0;

  u32 n[9];

  n[0] =    0;
  n[1] = k[7]; n[2] = k[6]; n[3] = k[5]; n[4] = k[4];
  n[5] = k[3]; n[6] = k[2]; n[7] = k[1]; n[8] = k[0];

  for (int i = 0; i <= 256; i++)
  {
    if (n[8] & 1)
    {
      int diff = n[8] & 0x1f;  // window=5: mask 5 bits
      int val = diff;

      if (diff >= 0x10)         // threshold = 2^(w-1) = 16
      {
        diff -= 0x20;           // subtract 2^w = 32
        val = 0x21 - val;       // encode negative: 33 - val
      }

      // Byte-packed: 4 entries per u32, 8 bits each
      const u32 word_idx = i >> 2;
      const u32 byte_idx = (i & 3) << 3;
      naf[word_idx] |= ((u32) val) << byte_idx;

      u32 t = n[8];
      n[8] -= diff;

      u32 j = 8;

      if (diff > 0)
      {
        while (n[j] > t)
        {
          if (j == 0) break;
          j--;
          t = n[j];
          n[j]--;
        }
      }
      else
      {
        while (t > n[j])
        {
          if (j == 0) break;
          j--;
          t = n[j];
          n[j]++;
        }
      }

      loop_start = i;
    }

    n[8] = n[8] >> 1 | n[7] << 31;
    n[7] = n[7] >> 1 | n[6] << 31;
    n[6] = n[6] >> 1 | n[5] << 31;
    n[5] = n[5] >> 1 | n[4] << 31;
    n[4] = n[4] >> 1 | n[3] << 31;
    n[3] = n[3] >> 1 | n[2] << 31;
    n[2] = n[2] >> 1 | n[1] << 31;
    n[1] = n[1] >> 1 | n[0] << 31;
    n[0] = n[0] >> 1;
  }

  return loop_start;
}

// --- Scalar multiplication: returns affine (x, y) ---

DECLSPEC void curve25519_point_mul_xy (PRIVATE_AS u32 *x1, PRIVATE_AS u32 *y1, PRIVATE_AS const u32 *k, PRIVATE_AS const curve25519_t *tmps)
{
  u32 naf[CURVE25519_NAF_SIZE] = { 0 };

  int loop_start = curve25519_convert_to_window_naf (naf, k);

  // First set from wNAF (byte-packed)
  const u32 multiplier0 = (naf[loop_start >> 2] >> (((u32) loop_start & 3) << 3)) & 0xff;
  const u32 odd0 = multiplier0 & 1;
  const u32 x_pos0 = ((multiplier0 - 1 + odd0) >> 1) * 24;
  const u32 y_pos0 = odd0 ? (x_pos0 + 8) : (x_pos0 + 16);

  x1[0] = tmps->xy[x_pos0 + 0]; x1[1] = tmps->xy[x_pos0 + 1];
  x1[2] = tmps->xy[x_pos0 + 2]; x1[3] = tmps->xy[x_pos0 + 3];
  x1[4] = tmps->xy[x_pos0 + 4]; x1[5] = tmps->xy[x_pos0 + 5];
  x1[6] = tmps->xy[x_pos0 + 6]; x1[7] = tmps->xy[x_pos0 + 7];

  y1[0] = tmps->xy[y_pos0 + 0]; y1[1] = tmps->xy[y_pos0 + 1];
  y1[2] = tmps->xy[y_pos0 + 2]; y1[3] = tmps->xy[y_pos0 + 3];
  y1[4] = tmps->xy[y_pos0 + 4]; y1[5] = tmps->xy[y_pos0 + 5];
  y1[6] = tmps->xy[y_pos0 + 6]; y1[7] = tmps->xy[y_pos0 + 7];

  u32 z1[8] = { 0 };
  z1[0] = 1;

  // Main loop
  for (int pos = loop_start - 1; pos >= 0; pos--)
  {
    curve25519_point_double (x1, y1, z1);

    const u32 multiplier = (naf[pos >> 2] >> (((u32) pos & 3) << 3)) & 0xff;

    if (multiplier)
    {
      const u32 odd = multiplier & 1;
      const u32 x_pos = ((multiplier - 1 + odd) >> 1) * 24;
      const u32 y_pos = odd ? (x_pos + 8) : (x_pos + 16);

      u32 x2[8], y2[8];

      x2[0] = tmps->xy[x_pos + 0]; x2[1] = tmps->xy[x_pos + 1];
      x2[2] = tmps->xy[x_pos + 2]; x2[3] = tmps->xy[x_pos + 3];
      x2[4] = tmps->xy[x_pos + 4]; x2[5] = tmps->xy[x_pos + 5];
      x2[6] = tmps->xy[x_pos + 6]; x2[7] = tmps->xy[x_pos + 7];

      y2[0] = tmps->xy[y_pos + 0]; y2[1] = tmps->xy[y_pos + 1];
      y2[2] = tmps->xy[y_pos + 2]; y2[3] = tmps->xy[y_pos + 3];
      y2[4] = tmps->xy[y_pos + 4]; y2[5] = tmps->xy[y_pos + 5];
      y2[6] = tmps->xy[y_pos + 6]; y2[7] = tmps->xy[y_pos + 7];

      curve25519_point_add (x1, y1, z1, x2, y2);
    }
  }

  // Convert from Jacobian to affine
  curve25519_inv_mod (z1);

  u32 z2[8];

  curve25519_mul_mod (z2, z1, z1);   // z^-2
  curve25519_mul_mod (x1, x1, z2);   // x_affine

  curve25519_mul_mod (z1, z2, z1);   // z^-3
  curve25519_mul_mod (y1, y1, z1);   // y_affine
}
