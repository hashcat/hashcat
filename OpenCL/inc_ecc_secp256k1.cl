/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Furthermore, since elliptic curve operations are highly researched and optimized,
 * we've consulted a lot of online resources to implement this, including several papers and
 * example code.
 *
 * Credits where credits are due: there are a lot of nice projects that explain and/or optimize
 * elliptic curve operations (especially elliptic curve multiplications by a scalar).
 *
 * We want to shout out following projects, which were quite helpful when implementing this:
 * - secp256k1 by Pieter Wuille (https://github.com/bitcoin-core/secp256k1/, MIT)
 * - secp256k1-cl by hhanh00 (https://github.com/hhanh00/secp256k1-cl/, MIT)
 * - ec_pure_c by masterzorag (https://github.com/masterzorag/ec_pure_c/)
 * - ecc-gmp by leivaburto (https://github.com/leivaburto/ecc-gmp)
 * - micro-ecc by Ken MacKay (https://github.com/kmackay/micro-ecc/, BSD)
 * - curve_example by willem (https://gist.github.com/nlitsme/c9031c7b9bf6bb009e5a)
 * - py_ecc by Vitalik Buterin (https://github.com/ethereum/py_ecc/, MIT)
 *
 *
 * Some BigNum operations are implemented similar to micro-ecc which is licensed under these terms:
 *  Copyright 2014 Ken MacKay, 2-Clause BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification, are permitted
 *  provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list of
 *     conditions and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * ATTENTION: this code is NOT meant to be used in security critical environments that are at risk
 * of side-channel or timing attacks etc, it's only purpose is to make it work fast for GPGPU
 * (OpenCL/CUDA). Some attack vectors like side-channel and timing-attacks might be possible,
 * because of some optimizations used within this code (non-constant time etc).
 */

/*
 * Implementation considerations:
 * point double and point add are implemented similar to algorithms mentioned in this 2011 paper:
 * http://eprint.iacr.org/2011/338.pdf
 * (Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves by Matthieu Rivain)
 *
 * In theory we could use the Jacobian Co-Z enhancement to get rid of the larger buffer caused by
 * the z coordinates (and in this way reduce register pressure etc).
 * For the Co-Z improvement there are a lot of fast algorithms, but we might still be faster
 * with this implementation (b/c we allow non-constant time) without the Brier/Joye Montgomery-like
 * ladder. Of course, this claim would need to be verified and tested to see which one is faster
 * for our specific scenario at the end.
 *
 * We accomplish a "little" speedup by using scalars converted to w-NAF (non-adjacent form):
 * The general idea of w-NAF is to pre-compute some zi coefficients like below to reduce the
 * costly point additions by using a non-binary ("signed") number system (values other than just
 * 0 and 1, but ranging from -2^(w-1)-1 to 2^(w-1)-1). This works best with the left-to-right
 * binary algorithm such that we just add zi * P when adding point P (we pre-compute all the
 * possible zi * P values because the x/y coordinates are known before the kernel starts):
 *
 *  // Example with window size w = 2 (i.e. mod 4 => & 3):
 *  // 173 => 1 0 -1 0 -1 0 -1 0 1 = 2^8 - 2^6 - 2^4 - 2^2 + 1
 *  int e = 0b10101101;   // 173
 *  int z[8 + 1] = { 0 }; // our zi/di, we need one extra slot to make the subtraction work
 *
 *  int i = 0;
 *
 *  while (e)
 *  {
 *    if (e & 1)
 *    {
 *      // for window size w = 3 it would be:
 *      // => 2^(w-0) = 2^3 = 8
 *      // => 2^(w-1) = 2^2 = 4
 *
 *      int bit; // = 2 - (e & 3) for w = 2
 *
 *      if ((e & 3) >= 2) // e % 4 == e & 3, use (e & 7) >= 4 for w = 3
 *        bit = (e & 3) - 4; // (e & 7) - 8 for w = 3
 *      else
 *        bit = e & 3; // e & 7 for w = 3
 *
 *      z[i] = bit;
 *      e   -= bit;
 *    }
 *
 *    e >>= 1; // e / 2
 *    i++;
 *  }
*/

#include "inc_ecc_secp256k1.h"

DECLSPEC u32 sub (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 c = 0; // carry/borrow

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
  // HIP doesnt support these so we stick to OpenCL (aka IS_AMD) - is also faster without asm
  //#elif (defined IS_AMD || defined IS_HIP) && HAS_VSUB == 1 && HAS_VSUBB == 1
  #elif 0
  __asm__ __volatile__
  (
    "V_SUB_U32   %0,  %9, %17;"
    "V_SUBB_U32  %1, %10, %18;"
    "V_SUBB_U32  %2, %11, %19;"
    "V_SUBB_U32  %3, %12, %20;"
    "V_SUBB_U32  %4, %13, %21;"
    "V_SUBB_U32  %5, %14, %22;"
    "V_SUBB_U32  %6, %15, %23;"
    "V_SUBB_U32  %7, %16, %24;"
    "V_SUBB_U32  %8,   0,   0;"
    : "=v"(r[0]), "=v"(r[1]), "=v"(r[2]), "=v"(r[3]), "=v"(r[4]), "=v"(r[5]), "=v"(r[6]), "=v"(r[7]),
      "=v"(c)
    :  "v"(a[0]),  "v"(a[1]),  "v"(a[2]),  "v"(a[3]),  "v"(a[4]),  "v"(a[5]),  "v"(a[6]),  "v"(a[7]),
       "v"(b[0]),  "v"(b[1]),  "v"(b[2]),  "v"(b[3]),  "v"(b[4]),  "v"(b[5]),  "v"(b[6]),  "v"(b[7])
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

DECLSPEC u32 add (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  u32 c = 0; // carry/borrow

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
  // HIP doesnt support these so we stick to OpenCL (aka IS_AMD) - is also faster without asm
  //#elif (defined IS_AMD || defined IS_HIP) && HAS_VSUB == 1 && HAS_VSUBB == 1
  #elif 0
  __asm__ __volatile__
  (
    "V_ADD_U32   %0,  %9, %17;"
    "V_ADDC_U32  %1, %10, %18;"
    "V_ADDC_U32  %2, %11, %19;"
    "V_ADDC_U32  %3, %12, %20;"
    "V_ADDC_U32  %4, %13, %21;"
    "V_ADDC_U32  %5, %14, %22;"
    "V_ADDC_U32  %6, %15, %23;"
    "V_ADDC_U32  %7, %16, %24;"
    "V_ADDC_U32  %8,   0,   0;"
    : "=v"(r[0]), "=v"(r[1]), "=v"(r[2]), "=v"(r[3]), "=v"(r[4]), "=v"(r[5]), "=v"(r[6]), "=v"(r[7]),
      "=v"(c)
    :  "v"(a[0]),  "v"(a[1]),  "v"(a[2]),  "v"(a[3]),  "v"(a[4]),  "v"(a[5]),  "v"(a[6]),  "v"(a[7]),
       "v"(b[0]),  "v"(b[1]),  "v"(b[2]),  "v"(b[3]),  "v"(b[4]),  "v"(b[5]),  "v"(b[6]),  "v"(b[7])
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

DECLSPEC void sub_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  const u32 c = sub (r, a, b); // carry

  if (c)
  {
    u32 t[8];

    t[0] = SECP256K1_P0;
    t[1] = SECP256K1_P1;
    t[2] = SECP256K1_P2;
    t[3] = SECP256K1_P3;
    t[4] = SECP256K1_P4;
    t[5] = SECP256K1_P5;
    t[6] = SECP256K1_P6;
    t[7] = SECP256K1_P7;

    add (r, r, t);
  }
}

DECLSPEC void add_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  const u32 c = add (r, a, b); // carry

  /*
   * Modulo operation:
   */

  // note: we could have an early exit in case of c == 1 => sub ()

  u32 t[8];

  t[0] = SECP256K1_P0;
  t[1] = SECP256K1_P1;
  t[2] = SECP256K1_P2;
  t[3] = SECP256K1_P3;
  t[4] = SECP256K1_P4;
  t[5] = SECP256K1_P5;
  t[6] = SECP256K1_P6;
  t[7] = SECP256K1_P7;

  // check if modulo operation is needed

  u32 mod = 1;

  if (c == 0)
  {
    for (int i = 7; i >= 0; i--)
    {
      if (r[i] < t[i])
      {
        mod = 0;

        break; // or return ! (check if faster)
      }

      if (r[i] > t[i]) break;
    }
  }

  if (mod == 1)
  {
    sub (r, r, t);
  }
}

DECLSPEC void mod_512 (PRIVATE_AS u32 *n)
{
  // we need to perform a modulo operation with 512-bit % 256-bit (bignum modulo):
  // the modulus is the secp256k1 group order

  // ATTENTION: for this function the byte-order is reversed (most significant bytes
  // at the left)

  /*
    the general modulo by shift and substract code (a = a % b):

    x = b;

    t = a >> 1;

    while (x <= t) x <<= 1;

    while (a >= b)
    {
      if (a >= x) a -= x;

      x >>= 1;
    }

    return a; // remainder
  */

  u32 a[16];

  a[ 0] = n[ 0];
  a[ 1] = n[ 1];
  a[ 2] = n[ 2];
  a[ 3] = n[ 3];
  a[ 4] = n[ 4];
  a[ 5] = n[ 5];
  a[ 6] = n[ 6];
  a[ 7] = n[ 7];
  a[ 8] = n[ 8];
  a[ 9] = n[ 9];
  a[10] = n[10];
  a[11] = n[11];
  a[12] = n[12];
  a[13] = n[13];
  a[14] = n[14];
  a[15] = n[15];

  u32 b[16];

  b[ 0] = 0x00000000;
  b[ 1] = 0x00000000;
  b[ 2] = 0x00000000;
  b[ 3] = 0x00000000;
  b[ 4] = 0x00000000;
  b[ 5] = 0x00000000;
  b[ 6] = 0x00000000;
  b[ 7] = 0x00000000;
  b[ 8] = SECP256K1_N7;
  b[ 9] = SECP256K1_N6;
  b[10] = SECP256K1_N5;
  b[11] = SECP256K1_N4;
  b[12] = SECP256K1_N3;
  b[13] = SECP256K1_N2;
  b[14] = SECP256K1_N1;
  b[15] = SECP256K1_N0;

  /*
   * Start:
   */

  // x = b (but with a fast "shift" trick to avoid the while loop)

  u32 x[16];

  x[ 0] = b[ 8]; // this is a trick: we just put the group order's most significant bit all the
  x[ 1] = b[ 9]; // way to the top to avoid doing the initial: while (x <= t) x <<= 1
  x[ 2] = b[10];
  x[ 3] = b[11];
  x[ 4] = b[12];
  x[ 5] = b[13];
  x[ 6] = b[14];
  x[ 7] = b[15];
  x[ 8] = 0x00000000;
  x[ 9] = 0x00000000;
  x[10] = 0x00000000;
  x[11] = 0x00000000;
  x[12] = 0x00000000;
  x[13] = 0x00000000;
  x[14] = 0x00000000;
  x[15] = 0x00000000;

  // a >= b

  while (a[0] >= b[0])
  {
    u32 l00 = a[ 0] < b[ 0];
    u32 l01 = a[ 1] < b[ 1];
    u32 l02 = a[ 2] < b[ 2];
    u32 l03 = a[ 3] < b[ 3];
    u32 l04 = a[ 4] < b[ 4];
    u32 l05 = a[ 5] < b[ 5];
    u32 l06 = a[ 6] < b[ 6];
    u32 l07 = a[ 7] < b[ 7];
    u32 l08 = a[ 8] < b[ 8];
    u32 l09 = a[ 9] < b[ 9];
    u32 l10 = a[10] < b[10];
    u32 l11 = a[11] < b[11];
    u32 l12 = a[12] < b[12];
    u32 l13 = a[13] < b[13];
    u32 l14 = a[14] < b[14];
    u32 l15 = a[15] < b[15];

    u32 e00 = a[ 0] == b[ 0];
    u32 e01 = a[ 1] == b[ 1];
    u32 e02 = a[ 2] == b[ 2];
    u32 e03 = a[ 3] == b[ 3];
    u32 e04 = a[ 4] == b[ 4];
    u32 e05 = a[ 5] == b[ 5];
    u32 e06 = a[ 6] == b[ 6];
    u32 e07 = a[ 7] == b[ 7];
    u32 e08 = a[ 8] == b[ 8];
    u32 e09 = a[ 9] == b[ 9];
    u32 e10 = a[10] == b[10];
    u32 e11 = a[11] == b[11];
    u32 e12 = a[12] == b[12];
    u32 e13 = a[13] == b[13];
    u32 e14 = a[14] == b[14];

    if (l00) break;
    if (l01 && e00) break;
    if (l02 && e00 && e01) break;
    if (l03 && e00 && e01 && e02) break;
    if (l04 && e00 && e01 && e02 && e03) break;
    if (l05 && e00 && e01 && e02 && e03 && e04) break;
    if (l06 && e00 && e01 && e02 && e03 && e04 && e05) break;
    if (l07 && e00 && e01 && e02 && e03 && e04 && e05 && e06) break;
    if (l08 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07) break;
    if (l09 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08) break;
    if (l10 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09) break;
    if (l11 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10) break;
    if (l12 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11) break;
    if (l13 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12) break;
    if (l14 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12 && e13) break;
    if (l15 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12 && e13 && e14) break;

    // r = x (copy it to have the original values for the subtraction)

    u32 r[16];

    r[ 0] = x[ 0];
    r[ 1] = x[ 1];
    r[ 2] = x[ 2];
    r[ 3] = x[ 3];
    r[ 4] = x[ 4];
    r[ 5] = x[ 5];
    r[ 6] = x[ 6];
    r[ 7] = x[ 7];
    r[ 8] = x[ 8];
    r[ 9] = x[ 9];
    r[10] = x[10];
    r[11] = x[11];
    r[12] = x[12];
    r[13] = x[13];
    r[14] = x[14];
    r[15] = x[15];

    // x <<= 1

    x[15] = x[15] >> 1 | x[14] << 31;
    x[14] = x[14] >> 1 | x[13] << 31;
    x[13] = x[13] >> 1 | x[12] << 31;
    x[12] = x[12] >> 1 | x[11] << 31;
    x[11] = x[11] >> 1 | x[10] << 31;
    x[10] = x[10] >> 1 | x[ 9] << 31;
    x[ 9] = x[ 9] >> 1 | x[ 8] << 31;
    x[ 8] = x[ 8] >> 1 | x[ 7] << 31;
    x[ 7] = x[ 7] >> 1 | x[ 6] << 31;
    x[ 6] = x[ 6] >> 1 | x[ 5] << 31;
    x[ 5] = x[ 5] >> 1 | x[ 4] << 31;
    x[ 4] = x[ 4] >> 1 | x[ 3] << 31;
    x[ 3] = x[ 3] >> 1 | x[ 2] << 31;
    x[ 2] = x[ 2] >> 1 | x[ 1] << 31;
    x[ 1] = x[ 1] >> 1 | x[ 0] << 31;
    x[ 0] = x[ 0] >> 1;

    // if (a >= r) a -= r;

    l00 = a[ 0] < r[ 0];
    l01 = a[ 1] < r[ 1];
    l02 = a[ 2] < r[ 2];
    l03 = a[ 3] < r[ 3];
    l04 = a[ 4] < r[ 4];
    l05 = a[ 5] < r[ 5];
    l06 = a[ 6] < r[ 6];
    l07 = a[ 7] < r[ 7];
    l08 = a[ 8] < r[ 8];
    l09 = a[ 9] < r[ 9];
    l10 = a[10] < r[10];
    l11 = a[11] < r[11];
    l12 = a[12] < r[12];
    l13 = a[13] < r[13];
    l14 = a[14] < r[14];
    l15 = a[15] < r[15];

    e00 = a[ 0] == r[ 0];
    e01 = a[ 1] == r[ 1];
    e02 = a[ 2] == r[ 2];
    e03 = a[ 3] == r[ 3];
    e04 = a[ 4] == r[ 4];
    e05 = a[ 5] == r[ 5];
    e06 = a[ 6] == r[ 6];
    e07 = a[ 7] == r[ 7];
    e08 = a[ 8] == r[ 8];
    e09 = a[ 9] == r[ 9];
    e10 = a[10] == r[10];
    e11 = a[11] == r[11];
    e12 = a[12] == r[12];
    e13 = a[13] == r[13];
    e14 = a[14] == r[14];

    if (l00) continue;
    if (l01 && e00) continue;
    if (l02 && e00 && e01) continue;
    if (l03 && e00 && e01 && e02) continue;
    if (l04 && e00 && e01 && e02 && e03) continue;
    if (l05 && e00 && e01 && e02 && e03 && e04) continue;
    if (l06 && e00 && e01 && e02 && e03 && e04 && e05) continue;
    if (l07 && e00 && e01 && e02 && e03 && e04 && e05 && e06) continue;
    if (l08 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07) continue;
    if (l09 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08) continue;
    if (l10 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09) continue;
    if (l11 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10) continue;
    if (l12 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11) continue;
    if (l13 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12) continue;
    if (l14 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12 && e13) continue;
    if (l15 && e00 && e01 && e02 && e03 && e04 && e05 && e06 && e07 && e08 && e09 && e10 && e11 && e12 && e13 && e14) continue;

    // substract (a -= r):

    if ((r[ 0] | r[ 1] | r[ 2] | r[ 3] | r[ 4] | r[ 5] | r[ 6] | r[ 7] |
         r[ 8] | r[ 9] | r[10] | r[11] | r[12] | r[13] | r[14] | r[15]) == 0) break;

    r[ 0] = a[ 0] - r[ 0];
    r[ 1] = a[ 1] - r[ 1];
    r[ 2] = a[ 2] - r[ 2];
    r[ 3] = a[ 3] - r[ 3];
    r[ 4] = a[ 4] - r[ 4];
    r[ 5] = a[ 5] - r[ 5];
    r[ 6] = a[ 6] - r[ 6];
    r[ 7] = a[ 7] - r[ 7];
    r[ 8] = a[ 8] - r[ 8];
    r[ 9] = a[ 9] - r[ 9];
    r[10] = a[10] - r[10];
    r[11] = a[11] - r[11];
    r[12] = a[12] - r[12];
    r[13] = a[13] - r[13];
    r[14] = a[14] - r[14];
    r[15] = a[15] - r[15];

    // take care of the "borrow" (we can't do it the other way around 15...1 because r[x] is changed!)

    if (r[ 1] > a[ 1]) r[ 0]--;
    if (r[ 2] > a[ 2]) r[ 1]--;
    if (r[ 3] > a[ 3]) r[ 2]--;
    if (r[ 4] > a[ 4]) r[ 3]--;
    if (r[ 5] > a[ 5]) r[ 4]--;
    if (r[ 6] > a[ 6]) r[ 5]--;
    if (r[ 7] > a[ 7]) r[ 6]--;
    if (r[ 8] > a[ 8]) r[ 7]--;
    if (r[ 9] > a[ 9]) r[ 8]--;
    if (r[10] > a[10]) r[ 9]--;
    if (r[11] > a[11]) r[10]--;
    if (r[12] > a[12]) r[11]--;
    if (r[13] > a[13]) r[12]--;
    if (r[14] > a[14]) r[13]--;
    if (r[15] > a[15]) r[14]--;

    a[ 0] = r[ 0];
    a[ 1] = r[ 1];
    a[ 2] = r[ 2];
    a[ 3] = r[ 3];
    a[ 4] = r[ 4];
    a[ 5] = r[ 5];
    a[ 6] = r[ 6];
    a[ 7] = r[ 7];
    a[ 8] = r[ 8];
    a[ 9] = r[ 9];
    a[10] = r[10];
    a[11] = r[11];
    a[12] = r[12];
    a[13] = r[13];
    a[14] = r[14];
    a[15] = r[15];
  }

  n[ 0] = a[ 0];
  n[ 1] = a[ 1];
  n[ 2] = a[ 2];
  n[ 3] = a[ 3];
  n[ 4] = a[ 4];
  n[ 5] = a[ 5];
  n[ 6] = a[ 6];
  n[ 7] = a[ 7];
  n[ 8] = a[ 8];
  n[ 9] = a[ 9];
  n[10] = a[10];
  n[11] = a[11];
  n[12] = a[12];
  n[13] = a[13];
  n[14] = a[14];
  n[15] = a[15];
}

DECLSPEC void mul_mod (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b) // TODO get rid of u64 ?
{
  u32 t[16] = { 0 }; // we need up to double the space (2 * 8)

  /*
   * First start with the basic a * b multiplication:
   */

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

      c += d < p; // carry
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



  /*
   * Now do the modulo operation:
   * (r = t % p)
   *
   * http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf (p.354 or p.9 in that document)
   */

  u32 tmp[16] = { 0 };

  // c = 0;

  // Note: SECP256K1_P = 2^256 - 2^32 - 977 (0x03d1 = 977)
  // multiply t[8]...t[15] by omega:

  for (u32 i = 0, j = 8; i < 8; i++, j++)
  {
    u64 p = ((u64) 0x03d1) * t[j] + c;

    tmp[i] = (u32) p;

    c = p >> 32;
  }

  tmp[8] = c;

  c = add (tmp + 1, tmp + 1, t + 8); // modifies tmp[1]...tmp[8]

  tmp[9] = c;


  // r = t + tmp

  c = add (r, t, tmp);

  // multiply t[0]...t[7] by omega:

  u32 c2 = 0;

  // memset (t, 0, sizeof (t));

  for (u32 i = 0, j = 8; i < 8; i++, j++)
  {
    u64 p = ((u64) 0x3d1) * tmp[j] + c2;

    t[i] = (u32) p;

    c2 = p >> 32;
  }

  t[8] = c2;

  c2 = add (t + 1, t + 1, tmp + 8); // modifies t[1]...t[8]

  t[9] = c2;


  // r = r + t

  c2 = add (r, r, t);

  c += c2;

  t[0] = SECP256K1_P0;
  t[1] = SECP256K1_P1;
  t[2] = SECP256K1_P2;
  t[3] = SECP256K1_P3;
  t[4] = SECP256K1_P4;
  t[5] = SECP256K1_P5;
  t[6] = SECP256K1_P6;
  t[7] = SECP256K1_P7;

  for (u32 i = c; i > 0; i--)
  {
    sub (r, r, t);
  }

  for (int i = 7; i >= 0; i--)
  {
    if (r[i] < t[i]) break;

    if (r[i] > t[i])
    {
      sub (r, r, t);

      break;
    }
  }
}

DECLSPEC void sqrt_mod (PRIVATE_AS u32 *r)
{
  // Fermat's Little Theorem
  // secp256k1: y^2 = x^3 + 7 % p
  // y ^ (p - 1) = 1
  // y ^ (p - 1) = (y^2) ^ ((p - 1) / 2) = 1 => y^2 = (y^2) ^ (((p - 1) / 2) + 1)
  // => y = (y^2) ^ ((((p - 1) / 2) + 1) / 2)
  // y = (y^2) ^ (((p - 1 + 2) / 2) / 2) = (y^2) ^ ((p + 1) / 4)

  // y1 = (x^3 + 7) ^ ((p + 1) / 4)
  // y2 = p - y1 (or y2 = y1 * -1 % p)

  u32 s[8];

  s[0] = SECP256K1_P0 + 1; //  because of (p + 1) / 4 or use add (s, s, 1)
  s[1] = SECP256K1_P1;
  s[2] = SECP256K1_P2;
  s[3] = SECP256K1_P3;
  s[4] = SECP256K1_P4;
  s[5] = SECP256K1_P5;
  s[6] = SECP256K1_P6;
  s[7] = SECP256K1_P7;

  u32 t[8] = { 0 };

  t[0] = 1;

  for (u32 i = 255; i > 1; i--) // we just skip the last 2 multiplications (=> exp / 4)
  {
    mul_mod (t, t, t); // r * r

    u32 idx  = i >> 5;
    u32 mask = 1 << (i & 0x1f);

    if (s[idx] & mask)
    {
      mul_mod (t, t, r); // t * r
    }
  }

  r[0] = t[0];
  r[1] = t[1];
  r[2] = t[2];
  r[3] = t[3];
  r[4] = t[4];
  r[5] = t[5];
  r[6] = t[6];
  r[7] = t[7];
}

// (inverse (a, p) * a) % p == 1 (or think of a * a^-1 = a / a = 1)

DECLSPEC void inv_mod (PRIVATE_AS u32 *a)
{
  // How often does this really happen? it should "almost" never happen (but would be safer)
  // if ((a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0) return;

  u32 t0[8];

  t0[0] = a[0];
  t0[1] = a[1];
  t0[2] = a[2];
  t0[3] = a[3];
  t0[4] = a[4];
  t0[5] = a[5];
  t0[6] = a[6];
  t0[7] = a[7];

  u32 p[8];

  p[0] = SECP256K1_P0;
  p[1] = SECP256K1_P1;
  p[2] = SECP256K1_P2;
  p[3] = SECP256K1_P3;
  p[4] = SECP256K1_P4;
  p[5] = SECP256K1_P5;
  p[6] = SECP256K1_P6;
  p[7] = SECP256K1_P7;

  u32 t1[8];

  t1[0] = SECP256K1_P0;
  t1[1] = SECP256K1_P1;
  t1[2] = SECP256K1_P2;
  t1[3] = SECP256K1_P3;
  t1[4] = SECP256K1_P4;
  t1[5] = SECP256K1_P5;
  t1[6] = SECP256K1_P6;
  t1[7] = SECP256K1_P7;

  u32 t2[8] = { 0 };

  t2[0] = 0x00000001;

  u32 t3[8] = { 0 };

  u32 b = (t0[0] != t1[0])
        | (t0[1] != t1[1])
        | (t0[2] != t1[2])
        | (t0[3] != t1[3])
        | (t0[4] != t1[4])
        | (t0[5] != t1[5])
        | (t0[6] != t1[6])
        | (t0[7] != t1[7]);

  while (b)
  {
    if ((t0[0] & 1) == 0) // even
    {
      t0[0] = t0[0] >> 1 | t0[1] << 31;
      t0[1] = t0[1] >> 1 | t0[2] << 31;
      t0[2] = t0[2] >> 1 | t0[3] << 31;
      t0[3] = t0[3] >> 1 | t0[4] << 31;
      t0[4] = t0[4] >> 1 | t0[5] << 31;
      t0[5] = t0[5] >> 1 | t0[6] << 31;
      t0[6] = t0[6] >> 1 | t0[7] << 31;
      t0[7] = t0[7] >> 1;

      u32 c = 0;

      if (t2[0] & 1) c = add (t2, t2, p);

      t2[0] = t2[0] >> 1 | t2[1] << 31;
      t2[1] = t2[1] >> 1 | t2[2] << 31;
      t2[2] = t2[2] >> 1 | t2[3] << 31;
      t2[3] = t2[3] >> 1 | t2[4] << 31;
      t2[4] = t2[4] >> 1 | t2[5] << 31;
      t2[5] = t2[5] >> 1 | t2[6] << 31;
      t2[6] = t2[6] >> 1 | t2[7] << 31;
      t2[7] = t2[7] >> 1 | c     << 31;
    }
    else if ((t1[0] & 1) == 0)
    {
      t1[0] = t1[0] >> 1 | t1[1] << 31;
      t1[1] = t1[1] >> 1 | t1[2] << 31;
      t1[2] = t1[2] >> 1 | t1[3] << 31;
      t1[3] = t1[3] >> 1 | t1[4] << 31;
      t1[4] = t1[4] >> 1 | t1[5] << 31;
      t1[5] = t1[5] >> 1 | t1[6] << 31;
      t1[6] = t1[6] >> 1 | t1[7] << 31;
      t1[7] = t1[7] >> 1;

      u32 c = 0;

      if (t3[0] & 1) c = add (t3, t3, p);

      t3[0] = t3[0] >> 1 | t3[1] << 31;
      t3[1] = t3[1] >> 1 | t3[2] << 31;
      t3[2] = t3[2] >> 1 | t3[3] << 31;
      t3[3] = t3[3] >> 1 | t3[4] << 31;
      t3[4] = t3[4] >> 1 | t3[5] << 31;
      t3[5] = t3[5] >> 1 | t3[6] << 31;
      t3[6] = t3[6] >> 1 | t3[7] << 31;
      t3[7] = t3[7] >> 1 | c     << 31;
    }
    else
    {
      u32 gt = 0;

      for (int i = 7; i >= 0; i--)
      {
        if (t0[i] > t1[i])
        {
          gt = 1;

          break;
        }

        if (t0[i] < t1[i]) break;
      }

      if (gt)
      {
        sub (t0, t0, t1);

        t0[0] = t0[0] >> 1 | t0[1] << 31;
        t0[1] = t0[1] >> 1 | t0[2] << 31;
        t0[2] = t0[2] >> 1 | t0[3] << 31;
        t0[3] = t0[3] >> 1 | t0[4] << 31;
        t0[4] = t0[4] >> 1 | t0[5] << 31;
        t0[5] = t0[5] >> 1 | t0[6] << 31;
        t0[6] = t0[6] >> 1 | t0[7] << 31;
        t0[7] = t0[7] >> 1;

        u32 lt = 0;

        for (int i = 7; i >= 0; i--)
        {
          if (t2[i] < t3[i])
          {
            lt = 1;

            break;
          }

          if (t2[i] > t3[i]) break;
        }

        if (lt) add (t2, t2, p);

        sub (t2, t2, t3);

        u32 c = 0;

        if (t2[0] & 1) c = add (t2, t2, p);

        t2[0] = t2[0] >> 1 | t2[1] << 31;
        t2[1] = t2[1] >> 1 | t2[2] << 31;
        t2[2] = t2[2] >> 1 | t2[3] << 31;
        t2[3] = t2[3] >> 1 | t2[4] << 31;
        t2[4] = t2[4] >> 1 | t2[5] << 31;
        t2[5] = t2[5] >> 1 | t2[6] << 31;
        t2[6] = t2[6] >> 1 | t2[7] << 31;
        t2[7] = t2[7] >> 1 | c     << 31;
      }
      else
      {
        sub (t1, t1, t0);

        t1[0] = t1[0] >> 1 | t1[1] << 31;
        t1[1] = t1[1] >> 1 | t1[2] << 31;
        t1[2] = t1[2] >> 1 | t1[3] << 31;
        t1[3] = t1[3] >> 1 | t1[4] << 31;
        t1[4] = t1[4] >> 1 | t1[5] << 31;
        t1[5] = t1[5] >> 1 | t1[6] << 31;
        t1[6] = t1[6] >> 1 | t1[7] << 31;
        t1[7] = t1[7] >> 1;

        u32 lt = 0;

        for (int i = 7; i >= 0; i--)
        {
          if (t3[i] < t2[i])
          {
            lt = 1;

            break;
          }

          if (t3[i] > t2[i]) break;
        }

        if (lt) add (t3, t3, p);

        sub (t3, t3, t2);

        u32 c = 0;

        if (t3[0] & 1) c = add (t3, t3, p);

        t3[0] = t3[0] >> 1 | t3[1] << 31;
        t3[1] = t3[1] >> 1 | t3[2] << 31;
        t3[2] = t3[2] >> 1 | t3[3] << 31;
        t3[3] = t3[3] >> 1 | t3[4] << 31;
        t3[4] = t3[4] >> 1 | t3[5] << 31;
        t3[5] = t3[5] >> 1 | t3[6] << 31;
        t3[6] = t3[6] >> 1 | t3[7] << 31;
        t3[7] = t3[7] >> 1 | c     << 31;
      }
    }

    // update b:

    b = (t0[0] != t1[0])
      | (t0[1] != t1[1])
      | (t0[2] != t1[2])
      | (t0[3] != t1[3])
      | (t0[4] != t1[4])
      | (t0[5] != t1[5])
      | (t0[6] != t1[6])
      | (t0[7] != t1[7]);
  }

  // set result:

  a[0] = t2[0];
  a[1] = t2[1];
  a[2] = t2[2];
  a[3] = t2[3];
  a[4] = t2[4];
  a[5] = t2[5];
  a[6] = t2[6];
  a[7] = t2[7];
}

/*
  // everything from the formulas below of course MOD the prime:

  // we use this formula:

  X = (3/2 * x^2)^2 - 2 * x * y^2
  Y = (3/2 * x^2) * (x * y^2 - X) - y^4
  Z = y * z

  this is identical to the more frequently used form:

  X = (3 * x^2)^2 - 8 * x * y^2
  Y =  3 * x^2 * (4 * x * y^2 - X) - 8 * y^4
  Z =  2 * y * z
*/

DECLSPEC void point_double (PRIVATE_AS u32 *x, PRIVATE_AS u32 *y, PRIVATE_AS u32 *z)
{
  // How often does this really happen? it should "almost" never happen (but would be safer)

  /*
  if ((y[0] | y[1] | y[2] | y[3] | y[4] | y[5] | y[6] | y[7]) == 0)
  {
    x[0] = 0;
    x[1] = 0;
    x[2] = 0;
    x[3] = 0;
    x[4] = 0;
    x[5] = 0;
    x[6] = 0;
    x[7] = 0;

    y[0] = 0;
    y[1] = 0;
    y[2] = 0;
    y[3] = 0;
    y[4] = 0;
    y[5] = 0;
    y[6] = 0;
    y[7] = 0;

    z[0] = 0;
    z[1] = 0;
    z[2] = 0;
    z[3] = 0;
    z[4] = 0;
    z[5] = 0;
    z[6] = 0;
    z[7] = 0;

    return;
  }
  */

  u32 t1[8];

  t1[0] = x[0];
  t1[1] = x[1];
  t1[2] = x[2];
  t1[3] = x[3];
  t1[4] = x[4];
  t1[5] = x[5];
  t1[6] = x[6];
  t1[7] = x[7];

  u32 t2[8];

  t2[0] = y[0];
  t2[1] = y[1];
  t2[2] = y[2];
  t2[3] = y[3];
  t2[4] = y[4];
  t2[5] = y[5];
  t2[6] = y[6];
  t2[7] = y[7];

  u32 t3[8];

  t3[0] = z[0];
  t3[1] = z[1];
  t3[2] = z[2];
  t3[3] = z[3];
  t3[4] = z[4];
  t3[5] = z[5];
  t3[6] = z[6];
  t3[7] = z[7];

  u32 t4[8];
  u32 t5[8];
  u32 t6[8];

  mul_mod (t4, t1, t1); // t4 = x^2

  mul_mod (t5, t2, t2); // t5 = y^2

  mul_mod (t1, t1, t5); // t1 = x*y^2

  mul_mod (t5, t5, t5); // t5 = t5^2 = y^4

  // here the z^2 and z^4 is not needed for a = 0

  mul_mod (t3, t2, t3); // t3 = x * z

  add_mod (t2, t4, t4); // t2 = 2 * t4 = 2 * x^2
  add_mod (t4, t4, t2); // t4 = 3 * t4 = 3 * x^2

  // a * z^4 = 0 * 1^4 = 0

  // don't discard the least significant bit it's important too!

  u32 c = 0;

  if (t4[0] & 1)
  {
    u32 t[8];

    t[0] = SECP256K1_P0;
    t[1] = SECP256K1_P1;
    t[2] = SECP256K1_P2;
    t[3] = SECP256K1_P3;
    t[4] = SECP256K1_P4;
    t[5] = SECP256K1_P5;
    t[6] = SECP256K1_P6;
    t[7] = SECP256K1_P7;

    c = add (t4, t4, t); // t4 + SECP256K1_P
  }

  // right shift (t4 / 2):

  t4[0] = t4[0] >> 1 | t4[1] << 31;
  t4[1] = t4[1] >> 1 | t4[2] << 31;
  t4[2] = t4[2] >> 1 | t4[3] << 31;
  t4[3] = t4[3] >> 1 | t4[4] << 31;
  t4[4] = t4[4] >> 1 | t4[5] << 31;
  t4[5] = t4[5] >> 1 | t4[6] << 31;
  t4[6] = t4[6] >> 1 | t4[7] << 31;
  t4[7] = t4[7] >> 1 | c     << 31;

  mul_mod (t6, t4, t4); // t6 = t4^2 = (3/2 * x^2)^2

  add_mod (t2, t1, t1); // t2 = 2 * t1

  sub_mod (t6, t6, t2); // t6 = t6 - t2
  sub_mod (t1, t1, t6); // t1 = t1 - t6

  mul_mod (t4, t4, t1); // t4 = t4 * t1

  sub_mod (t1, t4, t5); // t1 = t4 - t5

  // => x = t6, y = t1, z = t3:

  x[0] = t6[0];
  x[1] = t6[1];
  x[2] = t6[2];
  x[3] = t6[3];
  x[4] = t6[4];
  x[5] = t6[5];
  x[6] = t6[6];
  x[7] = t6[7];

  y[0] = t1[0];
  y[1] = t1[1];
  y[2] = t1[2];
  y[3] = t1[3];
  y[4] = t1[4];
  y[5] = t1[5];
  y[6] = t1[6];
  y[7] = t1[7];

  z[0] = t3[0];
  z[1] = t3[1];
  z[2] = t3[2];
  z[3] = t3[3];
  z[4] = t3[4];
  z[5] = t3[5];
  z[6] = t3[6];
  z[7] = t3[7];
}

/*
 * madd-2004-hmv:
 * (from https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html)
 * t1 = z1^2
 * t2 = t1*z1
 * t1 = t1*x2
 * t2 = t2*y2
 * t1 = t1-x1
 * t2 = t2-y1
 * z3 = z1*t1
 * t3 = t1^2
 * t4 = t3*t1
 * t3 = t3*x1
 * t1 = 2*t3
 * x3 = t2^2
 * x3 = x3-t1
 * x3 = x3-t4
 * t3 = t3-x3
 * t3 = t3*t2
 * t4 = t4*y1
 * y3 = t3-t4
 */

DECLSPEC void point_add (PRIVATE_AS u32 *x1, PRIVATE_AS u32 *y1, PRIVATE_AS u32 *z1, PRIVATE_AS u32 *x2, PRIVATE_AS u32 *y2) // z2 = 1
{
  // How often does this really happen? it should "almost" never happen (but would be safer)

  /*
  if ((y2[0] | y2[1] | y2[2] | y2[3] | y2[4] | y2[5] | y2[6] | y2[7]) == 0) return;

  if ((y1[0] | y1[1] | y1[2] | y1[3] | y1[4] | y1[5] | y1[6] | y1[7]) == 0)
  {
    x1[0] = x2[0];
    x1[1] = x2[1];
    x1[2] = x2[2];
    x1[3] = x2[3];
    x1[4] = x2[4];
    x1[5] = x2[5];
    x1[6] = x2[6];
    x1[7] = x2[7];

    y1[0] = y2[0];
    y1[1] = y2[1];
    y1[2] = y2[2];
    y1[3] = y2[3];
    y1[4] = y2[4];
    y1[5] = y2[5];
    y1[6] = y2[6];
    y1[7] = y2[7];

    z1[0] = z2[0];
    z1[1] = z2[1];
    z1[2] = z2[2];
    z1[3] = z2[3];
    z1[4] = z2[4];
    z1[5] = z2[5];
    z1[6] = z2[6];
    z1[7] = z2[7];

    return;
  }
  */

  // if x1 == x2 and y2 == y2 and z2 == z2 we need to double instead?

  // x1/y1/z1:

  u32 t1[8];

  t1[0] = x1[0];
  t1[1] = x1[1];
  t1[2] = x1[2];
  t1[3] = x1[3];
  t1[4] = x1[4];
  t1[5] = x1[5];
  t1[6] = x1[6];
  t1[7] = x1[7];

  u32 t2[8];

  t2[0] = y1[0];
  t2[1] = y1[1];
  t2[2] = y1[2];
  t2[3] = y1[3];
  t2[4] = y1[4];
  t2[5] = y1[5];
  t2[6] = y1[6];
  t2[7] = y1[7];

  u32 t3[8];

  t3[0] = z1[0];
  t3[1] = z1[1];
  t3[2] = z1[2];
  t3[3] = z1[3];
  t3[4] = z1[4];
  t3[5] = z1[5];
  t3[6] = z1[6];
  t3[7] = z1[7];

  // x2/y2:

  u32 t4[8];

  t4[0] = x2[0];
  t4[1] = x2[1];
  t4[2] = x2[2];
  t4[3] = x2[3];
  t4[4] = x2[4];
  t4[5] = x2[5];
  t4[6] = x2[6];
  t4[7] = x2[7];

  u32 t5[8];

  t5[0] = y2[0];
  t5[1] = y2[1];
  t5[2] = y2[2];
  t5[3] = y2[3];
  t5[4] = y2[4];
  t5[5] = y2[5];
  t5[6] = y2[6];
  t5[7] = y2[7];

  u32 t6[8];
  u32 t7[8];
  u32 t8[8];
  u32 t9[8];

  mul_mod (t6, t3, t3); // t6 = t3^2

  mul_mod (t7, t6, t3); // t7 = t6*t3
  mul_mod (t6, t6, t4); // t6 = t6*t4
  mul_mod (t7, t7, t5); // t7 = t7*t5

  sub_mod (t6, t6, t1); // t6 = t6-t1
  sub_mod (t7, t7, t2); // t7 = t7-t2

  mul_mod (t8, t3, t6); // t8 = t3*t6
  mul_mod (t4, t6, t6); // t4 = t6^2
  mul_mod (t9, t4, t6); // t9 = t4*t6
  mul_mod (t4, t4, t1); // t4 = t4*t1

  // left shift (t4 * 2):

  t6[7] = t4[7] << 1 | t4[6] >> 31;
  t6[6] = t4[6] << 1 | t4[5] >> 31;
  t6[5] = t4[5] << 1 | t4[4] >> 31;
  t6[4] = t4[4] << 1 | t4[3] >> 31;
  t6[3] = t4[3] << 1 | t4[2] >> 31;
  t6[2] = t4[2] << 1 | t4[1] >> 31;
  t6[1] = t4[1] << 1 | t4[0] >> 31;
  t6[0] = t4[0] << 1;

  // don't discard the most significant bit, it's important too!

  if (t4[7] & 0x80000000)
  {
    // use most significant bit and perform mod P, since we have: t4 * 2 % P

    u32 a[8] = { 0 };

    a[1] = 1;
    a[0] = 0x000003d1; // omega (see: mul_mod ())

    add (t6, t6, a);
  }

  mul_mod (t5, t7, t7); // t5 = t7*t7

  sub_mod (t5, t5, t6); // t5 = t5-t6
  sub_mod (t5, t5, t9); // t5 = t5-t9
  sub_mod (t4, t4, t5); // t4 = t4-t5

  mul_mod (t4, t4, t7); // t4 = t4*t7
  mul_mod (t9, t9, t2); // t9 = t9*t2

  sub_mod (t9, t4, t9); // t9 = t4-t9

  x1[0] = t5[0];
  x1[1] = t5[1];
  x1[2] = t5[2];
  x1[3] = t5[3];
  x1[4] = t5[4];
  x1[5] = t5[5];
  x1[6] = t5[6];
  x1[7] = t5[7];

  y1[0] = t9[0];
  y1[1] = t9[1];
  y1[2] = t9[2];
  y1[3] = t9[3];
  y1[4] = t9[4];
  y1[5] = t9[5];
  y1[6] = t9[6];
  y1[7] = t9[7];

  z1[0] = t8[0];
  z1[1] = t8[1];
  z1[2] = t8[2];
  z1[3] = t8[3];
  z1[4] = t8[4];
  z1[5] = t8[5];
  z1[6] = t8[6];
  z1[7] = t8[7];
}

DECLSPEC void point_get_coords (PRIVATE_AS secp256k1_t *r, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y)
{
  /*
    pre-compute 1/-1, 3/-3, 5/-5, 7/-7 times P (x, y)
    for wNAF with window size 4 (max/min: +/- 2^3-1): -7, -5, -3, -1, 1, 3, 5, 7

    +x1 ( 0)
    +y1 ( 8)
    -y1 (16)

    +x3 (24)
    +y3 (32)
    -y3 (40)

    +x5 (48)
    +y5 (56)
    -y5 (64)

    +x7 (72)
    +y7 (80)
    -y7 (88)
   */

  // note: we use jacobian forms with (x, y, z) for computation, but affine
  // (or just converted to z = 1) for storage

  // 1:

  r->xy[ 0] = x[0];
  r->xy[ 1] = x[1];
  r->xy[ 2] = x[2];
  r->xy[ 3] = x[3];
  r->xy[ 4] = x[4];
  r->xy[ 5] = x[5];
  r->xy[ 6] = x[6];
  r->xy[ 7] = x[7];

  r->xy[ 8] = y[0];
  r->xy[ 9] = y[1];
  r->xy[10] = y[2];
  r->xy[11] = y[3];
  r->xy[12] = y[4];
  r->xy[13] = y[5];
  r->xy[14] = y[6];
  r->xy[15] = y[7];

  // -1:

  u32 p[8];

  p[0] = SECP256K1_P0;
  p[1] = SECP256K1_P1;
  p[2] = SECP256K1_P2;
  p[3] = SECP256K1_P3;
  p[4] = SECP256K1_P4;
  p[5] = SECP256K1_P5;
  p[6] = SECP256K1_P6;
  p[7] = SECP256K1_P7;

  u32 neg[8];

  neg[0] = y[0];
  neg[1] = y[1];
  neg[2] = y[2];
  neg[3] = y[3];
  neg[4] = y[4];
  neg[5] = y[5];
  neg[6] = y[6];
  neg[7] = y[7];

  sub_mod (neg, p, neg); // -y = p - y

  r->xy[16] = neg[0];
  r->xy[17] = neg[1];
  r->xy[18] = neg[2];
  r->xy[19] = neg[3];
  r->xy[20] = neg[4];
  r->xy[21] = neg[5];
  r->xy[22] = neg[6];
  r->xy[23] = neg[7];


  // copy of 1:

  u32 tx[8];

  tx[0] = x[0];
  tx[1] = x[1];
  tx[2] = x[2];
  tx[3] = x[3];
  tx[4] = x[4];
  tx[5] = x[5];
  tx[6] = x[6];
  tx[7] = x[7];

  u32 ty[8];

  ty[0] = y[0];
  ty[1] = y[1];
  ty[2] = y[2];
  ty[3] = y[3];
  ty[4] = y[4];
  ty[5] = y[5];
  ty[6] = y[6];
  ty[7] = y[7];

  u32 rx[8];

  rx[0] = x[0];
  rx[1] = x[1];
  rx[2] = x[2];
  rx[3] = x[3];
  rx[4] = x[4];
  rx[5] = x[5];
  rx[6] = x[6];
  rx[7] = x[7];

  u32 ry[8];

  ry[0] = y[0];
  ry[1] = y[1];
  ry[2] = y[2];
  ry[3] = y[3];
  ry[4] = y[4];
  ry[5] = y[5];
  ry[6] = y[6];
  ry[7] = y[7];

  u32 rz[8] = { 0 };

  rz[0] = 1;


  // 3:

  point_double (rx, ry, rz);          // 2
  point_add    (rx, ry, rz, tx, ty);  // 3

  // to affine:

  inv_mod (rz);

  mul_mod (neg, rz, rz); // neg is temporary variable (z^2)
  mul_mod (rx,  rx, neg);

  mul_mod (rz, neg, rz);
  mul_mod (ry, ry, rz);

  r->xy[24] = rx[0];
  r->xy[25] = rx[1];
  r->xy[26] = rx[2];
  r->xy[27] = rx[3];
  r->xy[28] = rx[4];
  r->xy[29] = rx[5];
  r->xy[30] = rx[6];
  r->xy[31] = rx[7];

  r->xy[32] = ry[0];
  r->xy[33] = ry[1];
  r->xy[34] = ry[2];
  r->xy[35] = ry[3];
  r->xy[36] = ry[4];
  r->xy[37] = ry[5];
  r->xy[38] = ry[6];
  r->xy[39] = ry[7];

  // -3:

  neg[0] = ry[0];
  neg[1] = ry[1];
  neg[2] = ry[2];
  neg[3] = ry[3];
  neg[4] = ry[4];
  neg[5] = ry[5];
  neg[6] = ry[6];
  neg[7] = ry[7];

  sub_mod (neg, p, neg);

  r->xy[40] = neg[0];
  r->xy[41] = neg[1];
  r->xy[42] = neg[2];
  r->xy[43] = neg[3];
  r->xy[44] = neg[4];
  r->xy[45] = neg[5];
  r->xy[46] = neg[6];
  r->xy[47] = neg[7];


  // 5:

  rz[0] = 1; // actually we could take advantage of rz being 1 too (alternative point_add ()),
  rz[1] = 0; // but it is not important because this is performed only once per "hash"
  rz[2] = 0;
  rz[3] = 0;
  rz[4] = 0;
  rz[5] = 0;
  rz[6] = 0;
  rz[7] = 0;

  point_add (rx, ry, rz, tx, ty); // 4
  point_add (rx, ry, rz, tx, ty); // 5

  // to affine:

  inv_mod (rz);

  mul_mod (neg, rz, rz);
  mul_mod (rx,  rx, neg);

  mul_mod (rz, neg, rz);
  mul_mod (ry, ry, rz);

  r->xy[48] = rx[0];
  r->xy[49] = rx[1];
  r->xy[50] = rx[2];
  r->xy[51] = rx[3];
  r->xy[52] = rx[4];
  r->xy[53] = rx[5];
  r->xy[54] = rx[6];
  r->xy[55] = rx[7];

  r->xy[56] = ry[0];
  r->xy[57] = ry[1];
  r->xy[58] = ry[2];
  r->xy[59] = ry[3];
  r->xy[60] = ry[4];
  r->xy[61] = ry[5];
  r->xy[62] = ry[6];
  r->xy[63] = ry[7];

  // -5:

  neg[0] = ry[0];
  neg[1] = ry[1];
  neg[2] = ry[2];
  neg[3] = ry[3];
  neg[4] = ry[4];
  neg[5] = ry[5];
  neg[6] = ry[6];
  neg[7] = ry[7];

  sub_mod (neg, p, neg);

  r->xy[64] = neg[0];
  r->xy[65] = neg[1];
  r->xy[66] = neg[2];
  r->xy[67] = neg[3];
  r->xy[68] = neg[4];
  r->xy[69] = neg[5];
  r->xy[70] = neg[6];
  r->xy[71] = neg[7];


  // 7:

  rz[0] = 1;
  rz[1] = 0;
  rz[2] = 0;
  rz[3] = 0;
  rz[4] = 0;
  rz[5] = 0;
  rz[6] = 0;
  rz[7] = 0;

  point_add (rx, ry, rz, tx, ty); // 6
  point_add (rx, ry, rz, tx, ty); // 7

  // to affine:

  inv_mod (rz);

  mul_mod (neg, rz, rz);
  mul_mod (rx,  rx, neg);

  mul_mod (rz, neg, rz);
  mul_mod (ry, ry, rz);

  r->xy[72] = rx[0];
  r->xy[73] = rx[1];
  r->xy[74] = rx[2];
  r->xy[75] = rx[3];
  r->xy[76] = rx[4];
  r->xy[77] = rx[5];
  r->xy[78] = rx[6];
  r->xy[79] = rx[7];

  r->xy[80] = ry[0];
  r->xy[81] = ry[1];
  r->xy[82] = ry[2];
  r->xy[83] = ry[3];
  r->xy[84] = ry[4];
  r->xy[85] = ry[5];
  r->xy[86] = ry[6];
  r->xy[87] = ry[7];

  // -7:

  neg[0] = ry[0];
  neg[1] = ry[1];
  neg[2] = ry[2];
  neg[3] = ry[3];
  neg[4] = ry[4];
  neg[5] = ry[5];
  neg[6] = ry[6];
  neg[7] = ry[7];

  sub_mod (neg, p, neg);

  r->xy[88] = neg[0];
  r->xy[89] = neg[1];
  r->xy[90] = neg[2];
  r->xy[91] = neg[3];
  r->xy[92] = neg[4];
  r->xy[93] = neg[5];
  r->xy[94] = neg[6];
  r->xy[95] = neg[7];
}

/*
 * Convert the tweak/scalar k to w-NAF (window size is 4).
 * @param naf out: w-NAF form of the tweak/scalar, a pointer to an u32 array with a size of 33.
 * @param k in: tweak/scalar which should be converted, a pointer to an u32 array with a size of 8.
 * @return Returns the loop start index.
 */
DECLSPEC int convert_to_window_naf (PRIVATE_AS u32 *naf, PRIVATE_AS const u32 *k)
{
  int loop_start = 0;

  u32 n[9];

  n[0] =    0; // we need this extra slot sometimes for the subtraction to work
  n[1] = k[7];
  n[2] = k[6];
  n[3] = k[5];
  n[4] = k[4];
  n[5] = k[3];
  n[6] = k[2];
  n[7] = k[1];
  n[8] = k[0];

  for (int i = 0; i <= 256; i++)
  {
    if (n[8] & 1)
    {
      // for window size w = 4:
      // => 2^(w-0) = 2^4 = 16 (0x10)
      // => 2^(w-1) = 2^3 =  8 (0x08)

      int diff = n[8] & 0x0f; // n % 2^w == n & (2^w - 1)

      // convert diff to val according to this table:
      //  1 -> +1 -> 1
      //  3 -> +3 -> 3
      //  5 -> +5 -> 5
      //  7 -> +7 -> 7
      //  9 -> -7 -> 8
      // 11 -> -5 -> 6
      // 13 -> -3 -> 4
      // 15 -> -1 -> 2

      int val = diff;

      if (diff >= 0x08)
      {
        diff -= 0x10;

        val = 0x11 - val;
      }

      naf[i >> 3] |= val << ((i & 7) << 2);

      u32 t = n[8]; // t is the (temporary) old/unmodified value

      n[8] -= diff;

      // we need to take care of the carry/borrow:

      u32 k = 8;

      if (diff > 0)
      {
        while (n[k] > t) // overflow propagation
        {
          if (k == 0) break; // needed ?

          k--;

          t = n[k];

          n[k]--;
        }
      }
      else // if (diff < 0)
      {
        while (t > n[k]) // overflow propagation
        {
          if (k == 0) break;

          k--;

          t = n[k];

          n[k]++;
        }
      }

      // update start:

      loop_start = i;
    }

    // n = n / 2:

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

/*
 * @param x1 out: x coordinate, a pointer to an u32 array with a size of 8.
 * @param y1 out: y coordinate, a pointer to an u32 array with a size of 8.
 * @param k in: tweak/scalar which should be converted, a pointer to an u32 array with a size of 8.
 * @param tmps in: a basepoint for the multiplication.
 * @return Returns the x coordinate with a leading parity/sign (for odd/even y), it is named a compressed coordinate.
 */
DECLSPEC void point_mul_xy (PRIVATE_AS u32 *x1, PRIVATE_AS u32 *y1, PRIVATE_AS const u32 *k, SECP256K1_TMPS_TYPE const secp256k1_t *tmps)
{
  u32 naf[SECP256K1_NAF_SIZE] = { 0 };

  int loop_start = convert_to_window_naf (naf, k);

  // first set:

  const u32 multiplier = (naf[loop_start >> 3] >> ((loop_start & 7) << 2)) & 0x0f; // or use u8 ?

  const u32 odd = multiplier & 1;

  const u32 x_pos = ((multiplier - 1 + odd) >> 1) * 24;
  const u32 y_pos = odd ? (x_pos + 8) : (x_pos + 16);


  x1[0] = tmps->xy[x_pos + 0];
  x1[1] = tmps->xy[x_pos + 1];
  x1[2] = tmps->xy[x_pos + 2];
  x1[3] = tmps->xy[x_pos + 3];
  x1[4] = tmps->xy[x_pos + 4];
  x1[5] = tmps->xy[x_pos + 5];
  x1[6] = tmps->xy[x_pos + 6];
  x1[7] = tmps->xy[x_pos + 7];

  y1[0] = tmps->xy[y_pos + 0];
  y1[1] = tmps->xy[y_pos + 1];
  y1[2] = tmps->xy[y_pos + 2];
  y1[3] = tmps->xy[y_pos + 3];
  y1[4] = tmps->xy[y_pos + 4];
  y1[5] = tmps->xy[y_pos + 5];
  y1[6] = tmps->xy[y_pos + 6];
  y1[7] = tmps->xy[y_pos + 7];

  u32 z1[8] = { 0 };

  z1[0] = 1;

  /*
   * Start:
   */

  // main loop (left-to-right binary algorithm):

  for (int pos = loop_start - 1; pos >= 0; pos--) // -1 because we've set/add the point already
  {
    // always double:

    point_double (x1, y1, z1);

    // add only if needed:

    const u32 multiplier = (naf[pos >> 3] >> ((pos & 7) << 2)) & 0x0f;

    if (multiplier)
    {
      /*
        m ->  y | y = ((m - (m & 1)) / 2) * 24
        ----------------------------------
        1 ->  0 | 1/2 * 24 = 0
        2 -> 16
        3 -> 24 | 3/2 * 24 = 24
        4 -> 40
        5 -> 48 | 5/2 * 24 = 2*24
        6 -> 64
        7 -> 72 | 7/2 * 24 = 3*24
        8 -> 88
       */

      const u32 odd = multiplier & 1;

      const u32 x_pos = ((multiplier - 1 + odd) >> 1) * 24;
      const u32 y_pos = odd ? (x_pos + 8) : (x_pos + 16);

      u32 x2[8];

      x2[0] = tmps->xy[x_pos + 0];
      x2[1] = tmps->xy[x_pos + 1];
      x2[2] = tmps->xy[x_pos + 2];
      x2[3] = tmps->xy[x_pos + 3];
      x2[4] = tmps->xy[x_pos + 4];
      x2[5] = tmps->xy[x_pos + 5];
      x2[6] = tmps->xy[x_pos + 6];
      x2[7] = tmps->xy[x_pos + 7];

      u32 y2[8];

      y2[0] = tmps->xy[y_pos + 0];
      y2[1] = tmps->xy[y_pos + 1];
      y2[2] = tmps->xy[y_pos + 2];
      y2[3] = tmps->xy[y_pos + 3];
      y2[4] = tmps->xy[y_pos + 4];
      y2[5] = tmps->xy[y_pos + 5];
      y2[6] = tmps->xy[y_pos + 6];
      y2[7] = tmps->xy[y_pos + 7];

      // (x1, y1, z1) + multiplier * (x, y, z) = (x1, y1, z1) + (x2, y2, z2)

      point_add (x1, y1, z1, x2, y2);

      // optimization (there can't be any adds after an add for w-1 times):
      // (but it seems to be faster without this manipulation of "pos")

      //for (u32 i = 0; i < 3; i++)
      //{
      //  if (pos == 0) break;
      //  point_double (x1, y1, z1);
      //  pos--;
      //}
    }
  }


  /*
   * Get the corresponding affine coordinates x/y:
   *
   * Note:
   * x1_affine = x1_jacobian / z1^2 = x1_jacobian * z1_inv^2
   * y1_affine = y1_jacobian / z1^2 = y1_jacobian * z1_inv^2
   *
   */

  inv_mod (z1);

  u32 z2[8];

  mul_mod (z2, z1, z1); // z1^2
  mul_mod (x1, x1, z2); // x1_affine

  mul_mod (z1, z2, z1); // z1^3
  mul_mod (y1, y1, z1); // y1_affine

  // return values are already in x1 and y1
}

/*
 * @param r out: x coordinate with leading parity/sign (for odd/even y), a pointer to an u32 array with a size of 9.
 * @param k in: tweak/scalar which should be converted, a pointer to an u32 array with a size of 8.
 * @param tmps in: a basepoint for the multiplication.
 * @return Returns the x coordinate with a leading parity/sign (for odd/even y), it is named a compressed coordinate.
 */
DECLSPEC void point_mul (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *k, SECP256K1_TMPS_TYPE const secp256k1_t *tmps)
{
  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, k, tmps);

  /*
   * output:
   */

  // shift by 1 byte (8 bits) to make room and add the parity/sign (for odd/even y):

  r[8] =               (x[0] << 24);
  r[7] = (x[0] >> 8) | (x[1] << 24);
  r[6] = (x[1] >> 8) | (x[2] << 24);
  r[5] = (x[2] >> 8) | (x[3] << 24);
  r[4] = (x[3] >> 8) | (x[4] << 24);
  r[3] = (x[4] >> 8) | (x[5] << 24);
  r[2] = (x[5] >> 8) | (x[6] << 24);
  r[1] = (x[6] >> 8) | (x[7] << 24);
  r[0] = (x[7] >> 8);

  const u32 type = 0x02 | (y[0] & 1); // (note: 0b10 | 0b01 = 0x03)

  r[0] = r[0] | type << 24; // 0x02 or 0x03
}

/*
 * Transform a x coordinate and separate parity to secp256k1_t.
 * @param r out: x and y coordinates.
 * @param x in: x coordinate which should be converted, a pointer to an u32 array with a size of 8.
 * @param first_byte in: The parity of the y coordinate, a u32.
 * @return Returns 0 if successfull, returns 1 if x is greater than the basepoint.
 */
DECLSPEC u32 transform_public (PRIVATE_AS secp256k1_t *r, PRIVATE_AS const u32 *x, const u32 first_byte)
{
  u32 p[8];

  p[0] = SECP256K1_P0;
  p[1] = SECP256K1_P1;
  p[2] = SECP256K1_P2;
  p[3] = SECP256K1_P3;
  p[4] = SECP256K1_P4;
  p[5] = SECP256K1_P5;
  p[6] = SECP256K1_P6;
  p[7] = SECP256K1_P7;

  // x must be smaller than p (because of y ^ 2 = x ^ 3 % p)

  for (int i = 7; i >= 0; i--)
  {
    if (x[i] < p[i]) break;
    if (x[i] > p[i]) return 1;
  }


  // get y^2 = x^3 + 7:

  u32 b[8] = { 0 };

  b[0] = SECP256K1_B;

  u32 y[8];

  mul_mod (y, x, x);
  mul_mod (y, y, x);
  add_mod (y, y, b);

  // get y = sqrt (y^2):

  sqrt_mod (y);

  // check if it's of the correct parity that we want (odd/even):

  if ((first_byte & 1) != (y[0] & 1))
  {
    // y2 = p - y1 (or y2 = y1 * -1)

    sub_mod (y, p, y);
  }

  // get xy:

  point_get_coords (r, x, y);

  return 0;
}

/*
 * Parse a x coordinate with leading parity to secp256k1_t.
 * @param r out: x and y coordinates.
 * @param k in: x coordinate which should be converted with leading parity, a pointer to an u32 array with a size of 9.
 * @return Returns 0 if successfull, returns 1 if x is greater than the basepoint or the parity has an unexpected value.
 */
DECLSPEC u32 parse_public (PRIVATE_AS secp256k1_t *r, PRIVATE_AS const u32 *k)
{
  // verify:

  const u32 first_byte = k[0] & 0xff;

  if ((first_byte != '\x02') && (first_byte != '\x03'))
  {
    return 1;
  }

  // load k into x without the first byte:

  u32 x[8];

  x[0] = (k[7] & 0xff00) << 16 | (k[7] & 0xff0000) | (k[7] & 0xff000000) >> 16 | (k[8] & 0xff);
  x[1] = (k[6] & 0xff00) << 16 | (k[6] & 0xff0000) | (k[6] & 0xff000000) >> 16 | (k[7] & 0xff);
  x[2] = (k[5] & 0xff00) << 16 | (k[5] & 0xff0000) | (k[5] & 0xff000000) >> 16 | (k[6] & 0xff);
  x[3] = (k[4] & 0xff00) << 16 | (k[4] & 0xff0000) | (k[4] & 0xff000000) >> 16 | (k[5] & 0xff);
  x[4] = (k[3] & 0xff00) << 16 | (k[3] & 0xff0000) | (k[3] & 0xff000000) >> 16 | (k[4] & 0xff);
  x[5] = (k[2] & 0xff00) << 16 | (k[2] & 0xff0000) | (k[2] & 0xff000000) >> 16 | (k[3] & 0xff);
  x[6] = (k[1] & 0xff00) << 16 | (k[1] & 0xff0000) | (k[1] & 0xff000000) >> 16 | (k[2] & 0xff);
  x[7] = (k[0] & 0xff00) << 16 | (k[0] & 0xff0000) | (k[0] & 0xff000000) >> 16 | (k[1] & 0xff);

  return transform_public (r, x, first_byte);
}


/*
 * Set precomputed values of the basepoint g to a secp256k1 structure.
 * @param r out: x and y coordinates. pre-computed points: (x1,y1,-y1),(x3,y3,-y3),(x5,y5,-y5),(x7,y7,-y7)
 */
DECLSPEC void set_precomputed_basepoint_g (PRIVATE_AS secp256k1_t *r)
{
  // x1
  r->xy[ 0] = SECP256K1_G_PRE_COMPUTED_00;
  r->xy[ 1] = SECP256K1_G_PRE_COMPUTED_01;
  r->xy[ 2] = SECP256K1_G_PRE_COMPUTED_02;
  r->xy[ 3] = SECP256K1_G_PRE_COMPUTED_03;
  r->xy[ 4] = SECP256K1_G_PRE_COMPUTED_04;
  r->xy[ 5] = SECP256K1_G_PRE_COMPUTED_05;
  r->xy[ 6] = SECP256K1_G_PRE_COMPUTED_06;
  r->xy[ 7] = SECP256K1_G_PRE_COMPUTED_07;

  // y1
  r->xy[ 8] = SECP256K1_G_PRE_COMPUTED_08;
  r->xy[ 9] = SECP256K1_G_PRE_COMPUTED_09;
  r->xy[10] = SECP256K1_G_PRE_COMPUTED_10;
  r->xy[11] = SECP256K1_G_PRE_COMPUTED_11;
  r->xy[12] = SECP256K1_G_PRE_COMPUTED_12;
  r->xy[13] = SECP256K1_G_PRE_COMPUTED_13;
  r->xy[14] = SECP256K1_G_PRE_COMPUTED_14;
  r->xy[15] = SECP256K1_G_PRE_COMPUTED_15;

  // -y1
  r->xy[16] = SECP256K1_G_PRE_COMPUTED_16;
  r->xy[17] = SECP256K1_G_PRE_COMPUTED_17;
  r->xy[18] = SECP256K1_G_PRE_COMPUTED_18;
  r->xy[19] = SECP256K1_G_PRE_COMPUTED_19;
  r->xy[20] = SECP256K1_G_PRE_COMPUTED_20;
  r->xy[21] = SECP256K1_G_PRE_COMPUTED_21;
  r->xy[22] = SECP256K1_G_PRE_COMPUTED_22;
  r->xy[23] = SECP256K1_G_PRE_COMPUTED_23;

  // x3
  r->xy[24] = SECP256K1_G_PRE_COMPUTED_24;
  r->xy[25] = SECP256K1_G_PRE_COMPUTED_25;
  r->xy[26] = SECP256K1_G_PRE_COMPUTED_26;
  r->xy[27] = SECP256K1_G_PRE_COMPUTED_27;
  r->xy[28] = SECP256K1_G_PRE_COMPUTED_28;
  r->xy[29] = SECP256K1_G_PRE_COMPUTED_29;
  r->xy[30] = SECP256K1_G_PRE_COMPUTED_30;
  r->xy[31] = SECP256K1_G_PRE_COMPUTED_31;

  // y3
  r->xy[32] = SECP256K1_G_PRE_COMPUTED_32;
  r->xy[33] = SECP256K1_G_PRE_COMPUTED_33;
  r->xy[34] = SECP256K1_G_PRE_COMPUTED_34;
  r->xy[35] = SECP256K1_G_PRE_COMPUTED_35;
  r->xy[36] = SECP256K1_G_PRE_COMPUTED_36;
  r->xy[37] = SECP256K1_G_PRE_COMPUTED_37;
  r->xy[38] = SECP256K1_G_PRE_COMPUTED_38;
  r->xy[39] = SECP256K1_G_PRE_COMPUTED_39;

  // -y3
  r->xy[40] = SECP256K1_G_PRE_COMPUTED_40;
  r->xy[41] = SECP256K1_G_PRE_COMPUTED_41;
  r->xy[42] = SECP256K1_G_PRE_COMPUTED_42;
  r->xy[43] = SECP256K1_G_PRE_COMPUTED_43;
  r->xy[44] = SECP256K1_G_PRE_COMPUTED_44;
  r->xy[45] = SECP256K1_G_PRE_COMPUTED_45;
  r->xy[46] = SECP256K1_G_PRE_COMPUTED_46;
  r->xy[47] = SECP256K1_G_PRE_COMPUTED_47;

  // x5
  r->xy[48] = SECP256K1_G_PRE_COMPUTED_48;
  r->xy[49] = SECP256K1_G_PRE_COMPUTED_49;
  r->xy[50] = SECP256K1_G_PRE_COMPUTED_50;
  r->xy[51] = SECP256K1_G_PRE_COMPUTED_51;
  r->xy[52] = SECP256K1_G_PRE_COMPUTED_52;
  r->xy[53] = SECP256K1_G_PRE_COMPUTED_53;
  r->xy[54] = SECP256K1_G_PRE_COMPUTED_54;
  r->xy[55] = SECP256K1_G_PRE_COMPUTED_55;

  // y5
  r->xy[56] = SECP256K1_G_PRE_COMPUTED_56;
  r->xy[57] = SECP256K1_G_PRE_COMPUTED_57;
  r->xy[58] = SECP256K1_G_PRE_COMPUTED_58;
  r->xy[59] = SECP256K1_G_PRE_COMPUTED_59;
  r->xy[60] = SECP256K1_G_PRE_COMPUTED_60;
  r->xy[61] = SECP256K1_G_PRE_COMPUTED_61;
  r->xy[62] = SECP256K1_G_PRE_COMPUTED_62;
  r->xy[63] = SECP256K1_G_PRE_COMPUTED_63;

  // -y5
  r->xy[64] = SECP256K1_G_PRE_COMPUTED_64;
  r->xy[65] = SECP256K1_G_PRE_COMPUTED_65;
  r->xy[66] = SECP256K1_G_PRE_COMPUTED_66;
  r->xy[67] = SECP256K1_G_PRE_COMPUTED_67;
  r->xy[68] = SECP256K1_G_PRE_COMPUTED_68;
  r->xy[69] = SECP256K1_G_PRE_COMPUTED_69;
  r->xy[70] = SECP256K1_G_PRE_COMPUTED_70;
  r->xy[71] = SECP256K1_G_PRE_COMPUTED_71;

  // x7
  r->xy[72] = SECP256K1_G_PRE_COMPUTED_72;
  r->xy[73] = SECP256K1_G_PRE_COMPUTED_73;
  r->xy[74] = SECP256K1_G_PRE_COMPUTED_74;
  r->xy[75] = SECP256K1_G_PRE_COMPUTED_75;
  r->xy[76] = SECP256K1_G_PRE_COMPUTED_76;
  r->xy[77] = SECP256K1_G_PRE_COMPUTED_77;
  r->xy[78] = SECP256K1_G_PRE_COMPUTED_78;
  r->xy[79] = SECP256K1_G_PRE_COMPUTED_79;

  // y7
  r->xy[80] = SECP256K1_G_PRE_COMPUTED_80;
  r->xy[81] = SECP256K1_G_PRE_COMPUTED_81;
  r->xy[82] = SECP256K1_G_PRE_COMPUTED_82;
  r->xy[83] = SECP256K1_G_PRE_COMPUTED_83;
  r->xy[84] = SECP256K1_G_PRE_COMPUTED_84;
  r->xy[85] = SECP256K1_G_PRE_COMPUTED_85;
  r->xy[86] = SECP256K1_G_PRE_COMPUTED_86;
  r->xy[87] = SECP256K1_G_PRE_COMPUTED_87;

  // -y7
  r->xy[88] = SECP256K1_G_PRE_COMPUTED_88;
  r->xy[89] = SECP256K1_G_PRE_COMPUTED_89;
  r->xy[90] = SECP256K1_G_PRE_COMPUTED_90;
  r->xy[91] = SECP256K1_G_PRE_COMPUTED_91;
  r->xy[92] = SECP256K1_G_PRE_COMPUTED_92;
  r->xy[93] = SECP256K1_G_PRE_COMPUTED_93;
  r->xy[94] = SECP256K1_G_PRE_COMPUTED_94;
  r->xy[95] = SECP256K1_G_PRE_COMPUTED_95;
}
