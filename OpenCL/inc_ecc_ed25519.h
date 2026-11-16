/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_ECC_ED25519_H
#define INC_ECC_ED25519_H

// Ed25519 public key derivation (base point scalar multiplication),
// ported from the public domain ed25519-donna 32-bit implementation
// by Andrew M. <liquidsun@gmail.com>, as adapted to OpenCL by the
// John the Ripper project.

typedef struct ed25519_ge
{
  u32 x[10];
  u32 y[10];
  u32 z[10];
  u32 t[10];

} ed25519_ge_t;

typedef struct ed25519_ge_p1p1
{
  u32 x[10];
  u32 y[10];
  u32 z[10];
  u32 t[10];

} ed25519_ge_p1p1_t;

typedef struct ed25519_ge_niels
{
  u32 ysubx[10];
  u32 xaddy[10];
  u32 t2d[10];

} ed25519_ge_niels_t;

// h64 holds the 8 big-endian u64 words of SHA-512 (seed), as left by
// sha512_final (). pk receives the 32-byte encoded public key.

DECLSPEC void ed25519_publickey (PRIVATE_AS u8 *pk, PRIVATE_AS const u64 *h64);

#endif // INC_ECC_ED25519_H
