/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_ECC_SECP256K1_H
#define _INC_ECC_SECP256K1_H

// y^2 = x^3 + ax + b with a = 0 and b = 7 => y^2 = x^3 + 7:

#define SECP256K1_B 7

#define SECP256K1_P0 0xfffffc2f
#define SECP256K1_P1 0xfffffffe
#define SECP256K1_P2 0xffffffff
#define SECP256K1_P3 0xffffffff
#define SECP256K1_P4 0xffffffff
#define SECP256K1_P5 0xffffffff
#define SECP256K1_P6 0xffffffff
#define SECP256K1_P7 0xffffffff

#define SECP256K1_N0 0xd0364141
#define SECP256K1_N1 0xbfd25e8c
#define SECP256K1_N2 0xaf48a03b
#define SECP256K1_N3 0xbaaedce6
#define SECP256K1_N4 0xfffffffe
#define SECP256K1_N5 0xffffffff
#define SECP256K1_N6 0xffffffff
#define SECP256K1_N7 0xffffffff

typedef struct secp256k1
{
  u32 xy[96]; // pre-computed points: (x1,y1,-y1),(x3,y3,-y3),(x5,y5,-y5),(x7,y7,-y7)

} secp256k1_t;

DECLSPEC u32  parse_public (secp256k1_t *r, const u32 *k);

DECLSPEC void point_mul (u32 *r, const u32 *k, GLOBAL_AS const secp256k1_t *tmps);

#endif // _INC_ECC_SECP256K1_H
