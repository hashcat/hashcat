/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha256.h"
#include "inc_hash_ripemd160.h"
#include "inc_bitcoin_address.h"

// HASH160 is RIPEMD-160 (SHA-256 (data)), and every Bitcoin address a mode in this tree compares
// against is one of three things built on it: the hash160 of a compressed public key, the hash160
// of an uncompressed one, or the hash160 of the P2SH redeem script that wraps a P2WPKH.
//
// All three used to be written out again in each kernel that needed them. The word packing is the
// part worth sharing rather than copying: the public key is assembled big endian with the type
// byte in the top byte of the first word, so the SHA-256 that follows takes it without a swap,
// while the RIPEMD-160 takes the SHA-256 state with one.
//
// out holds the RIPEMD-160 state words as the context leaves them, which is what a caller compares
// and what hash160_p2sh_p2wpkh () expects to be handed.

DECLSPEC void hash160_from_sha256_state (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *h)
{
  u32 tmp[16];

  tmp[ 0] = h[0];
  tmp[ 1] = h[1];
  tmp[ 2] = h[2];
  tmp[ 3] = h[3];
  tmp[ 4] = h[4];
  tmp[ 5] = h[5];
  tmp[ 6] = h[6];
  tmp[ 7] = h[7];
  tmp[ 8] = 0;
  tmp[ 9] = 0;
  tmp[10] = 0;
  tmp[11] = 0;
  tmp[12] = 0;
  tmp[13] = 0;
  tmp[14] = 0;
  tmp[15] = 0;

  ripemd160_ctx_t rctx;

  ripemd160_init        (&rctx);
  ripemd160_update_swap (&rctx, tmp, 32);
  ripemd160_final       (&rctx);

  out[0] = rctx.h[0];
  out[1] = rctx.h[1];
  out[2] = rctx.h[2];
  out[3] = rctx.h[3];
  out[4] = rctx.h[4];
}

DECLSPEC void hash160_pubkey_compressed (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y)
{
  // the type byte is 0x02 for an even y and 0x03 for an odd one

  const u32 type = 0x02 | (y[0] & 1);

  u32 pub_key[16] = { 0 };

  pub_key[8] =               (x[0] << 24);
  pub_key[7] = (x[0] >> 8) | (x[1] << 24);
  pub_key[6] = (x[1] >> 8) | (x[2] << 24);
  pub_key[5] = (x[2] >> 8) | (x[3] << 24);
  pub_key[4] = (x[3] >> 8) | (x[4] << 24);
  pub_key[3] = (x[4] >> 8) | (x[5] << 24);
  pub_key[2] = (x[5] >> 8) | (x[6] << 24);
  pub_key[1] = (x[6] >> 8) | (x[7] << 24);
  pub_key[0] = (x[7] >> 8) | (type << 24);

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, pub_key, 33);
  sha256_final  (&ctx);

  hash160_from_sha256_state (out, ctx.h);
}

DECLSPEC void hash160_pubkey_uncompressed (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y)
{
  u32 pub_key[32] = { 0 };

  pub_key[16] =               (y[0] << 24);
  pub_key[15] = (y[0] >> 8) | (y[1] << 24);
  pub_key[14] = (y[1] >> 8) | (y[2] << 24);
  pub_key[13] = (y[2] >> 8) | (y[3] << 24);
  pub_key[12] = (y[3] >> 8) | (y[4] << 24);
  pub_key[11] = (y[4] >> 8) | (y[5] << 24);
  pub_key[10] = (y[5] >> 8) | (y[6] << 24);
  pub_key[ 9] = (y[6] >> 8) | (y[7] << 24);
  pub_key[ 8] = (y[7] >> 8) | (x[0] << 24);
  pub_key[ 7] = (x[0] >> 8) | (x[1] << 24);
  pub_key[ 6] = (x[1] >> 8) | (x[2] << 24);
  pub_key[ 5] = (x[2] >> 8) | (x[3] << 24);
  pub_key[ 4] = (x[3] >> 8) | (x[4] << 24);
  pub_key[ 3] = (x[4] >> 8) | (x[5] << 24);
  pub_key[ 2] = (x[5] >> 8) | (x[6] << 24);
  pub_key[ 1] = (x[6] >> 8) | (x[7] << 24);
  pub_key[ 0] = (x[7] >> 8) | (0x04000000);

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, pub_key, 65);
  sha256_final  (&ctx);

  hash160_from_sha256_state (out, ctx.h);
}

DECLSPEC void hash160_p2sh_p2wpkh (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *hash160)
{
  // the redeem script is OP_0 followed by a 20 byte push of the hash160, so 0x00 0x14 and then the
  // 20 bytes. The words below carry it byte swapped, which is what sha256_update_swap () wants.

  u32 tmp[16];

  tmp[ 0] = (hash160[0] << 16) | (            0x1400);
  tmp[ 1] = (hash160[1] << 16) | (hash160[0] >>   16);
  tmp[ 2] = (hash160[2] << 16) | (hash160[1] >>   16);
  tmp[ 3] = (hash160[3] << 16) | (hash160[2] >>   16);
  tmp[ 4] = (hash160[4] << 16) | (hash160[3] >>   16);
  tmp[ 5] =                      (hash160[4] >>   16);
  tmp[ 6] = 0;
  tmp[ 7] = 0;
  tmp[ 8] = 0;
  tmp[ 9] = 0;
  tmp[10] = 0;
  tmp[11] = 0;
  tmp[12] = 0;
  tmp[13] = 0;
  tmp[14] = 0;
  tmp[15] = 0;

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, tmp, 22);
  sha256_final       (&ctx);

  hash160_from_sha256_state (out, ctx.h);
}
