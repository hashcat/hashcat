/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha512.h"
#include "inc_pbkdf2.h"

// Key and salt use little endian words, matching the password's input format. Bytes beyond their
// lengths must be zero. The derived key uses the same word order: _comp writes dk_len bytes and
// clears the remaining bytes of the last word. PBKDF2 with c iterations runs _init, followed by
// c - 1 total iterations of _loop, and then _comp.

// Compute one HMAC of the previous U using the pad states, as the native PBKDF2 kernels do. The
// message is a single digest, so each half requires one transform.

DECLSPEC void pbkdf2_md5_run (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  for (u32 i = 0; i < 4; i++) dgst[i] = ipad[i];

  md5_transform (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];

  for (u32 i = 0; i < 4; i++) dgst[i] = opad[i];

  md5_transform (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha1_run (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  for (u32 i = 0; i < 5; i++) dgst[i] = ipad[i];

  sha1_transform (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];

  for (u32 i = 0; i < 5; i++) dgst[i] = opad[i];

  sha1_transform (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha256_run (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = dgst[5];
  w1[2] = dgst[6];
  w1[3] = dgst[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  for (u32 i = 0; i < 8; i++) dgst[i] = ipad[i];

  sha256_transform (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = dgst[5];
  w1[2] = dgst[6];
  w1[3] = dgst[7];

  for (u32 i = 0; i < 8; i++) dgst[i] = opad[i];

  sha256_transform (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha512_run (PRIVATE_AS const u64 *ipad, PRIVATE_AS const u64 *opad, PRIVATE_AS u64 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (dgst[0]);
  w0[1] = l32_from_64_S (dgst[0]);
  w0[2] = h32_from_64_S (dgst[1]);
  w0[3] = l32_from_64_S (dgst[1]);
  w1[0] = h32_from_64_S (dgst[2]);
  w1[1] = l32_from_64_S (dgst[2]);
  w1[2] = h32_from_64_S (dgst[3]);
  w1[3] = l32_from_64_S (dgst[3]);
  w2[0] = h32_from_64_S (dgst[4]);
  w2[1] = l32_from_64_S (dgst[4]);
  w2[2] = h32_from_64_S (dgst[5]);
  w2[3] = l32_from_64_S (dgst[5]);
  w3[0] = h32_from_64_S (dgst[6]);
  w3[1] = l32_from_64_S (dgst[6]);
  w3[2] = h32_from_64_S (dgst[7]);
  w3[3] = l32_from_64_S (dgst[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  for (u32 i = 0; i < 8; i++) dgst[i] = ipad[i];

  sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, dgst);

  w0[0] = h32_from_64_S (dgst[0]);
  w0[1] = l32_from_64_S (dgst[0]);
  w0[2] = h32_from_64_S (dgst[1]);
  w0[3] = l32_from_64_S (dgst[1]);
  w1[0] = h32_from_64_S (dgst[2]);
  w1[1] = l32_from_64_S (dgst[2]);
  w1[2] = h32_from_64_S (dgst[3]);
  w1[3] = l32_from_64_S (dgst[3]);
  w2[0] = h32_from_64_S (dgst[4]);
  w2[1] = l32_from_64_S (dgst[4]);
  w2[2] = h32_from_64_S (dgst[5]);
  w2[3] = l32_from_64_S (dgst[5]);
  w3[0] = h32_from_64_S (dgst[6]);
  w3[1] = l32_from_64_S (dgst[6]);
  w3[2] = h32_from_64_S (dgst[7]);
  w3[3] = l32_from_64_S (dgst[7]);

  for (u32 i = 0; i < 8; i++) dgst[i] = opad[i];

  sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, dgst);
}

// The same HMAC for VECT_SIZE candidates at once, for the loop kernel of OpenCL/m04000-pure.cl,
// which gathers their states into vectors.

DECLSPEC void pbkdf2_md5_run_V (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  for (u32 i = 0; i < 4; i++) dgst[i] = ipad[i];

  md5_transform_vector (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];

  for (u32 i = 0; i < 4; i++) dgst[i] = opad[i];

  md5_transform_vector (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha1_run_V (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  for (u32 i = 0; i < 5; i++) dgst[i] = ipad[i];

  sha1_transform_vector (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];

  for (u32 i = 0; i < 5; i++) dgst[i] = opad[i];

  sha1_transform_vector (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha256_run_V (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = dgst[5];
  w1[2] = dgst[6];
  w1[3] = dgst[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  for (u32 i = 0; i < 8; i++) dgst[i] = ipad[i];

  sha256_transform_vector (w0, w1, w2, w3, dgst);

  w0[0] = dgst[0];
  w0[1] = dgst[1];
  w0[2] = dgst[2];
  w0[3] = dgst[3];
  w1[0] = dgst[4];
  w1[1] = dgst[5];
  w1[2] = dgst[6];
  w1[3] = dgst[7];

  for (u32 i = 0; i < 8; i++) dgst[i] = opad[i];

  sha256_transform_vector (w0, w1, w2, w3, dgst);
}

DECLSPEC void pbkdf2_sha512_run_V (PRIVATE_AS const u64x *ipad, PRIVATE_AS const u64x *opad, PRIVATE_AS u64x *dgst)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  w0[0] = h32_from_64 (dgst[0]);
  w0[1] = l32_from_64 (dgst[0]);
  w0[2] = h32_from_64 (dgst[1]);
  w0[3] = l32_from_64 (dgst[1]);
  w1[0] = h32_from_64 (dgst[2]);
  w1[1] = l32_from_64 (dgst[2]);
  w1[2] = h32_from_64 (dgst[3]);
  w1[3] = l32_from_64 (dgst[3]);
  w2[0] = h32_from_64 (dgst[4]);
  w2[1] = l32_from_64 (dgst[4]);
  w2[2] = h32_from_64 (dgst[5]);
  w2[3] = l32_from_64 (dgst[5]);
  w3[0] = h32_from_64 (dgst[6]);
  w3[1] = l32_from_64 (dgst[6]);
  w3[2] = h32_from_64 (dgst[7]);
  w3[3] = l32_from_64 (dgst[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  for (u32 i = 0; i < 8; i++) dgst[i] = ipad[i];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, dgst);

  w0[0] = h32_from_64 (dgst[0]);
  w0[1] = l32_from_64 (dgst[0]);
  w0[2] = h32_from_64 (dgst[1]);
  w0[3] = l32_from_64 (dgst[1]);
  w1[0] = h32_from_64 (dgst[2]);
  w1[1] = l32_from_64 (dgst[2]);
  w1[2] = h32_from_64 (dgst[3]);
  w1[3] = l32_from_64 (dgst[3]);
  w2[0] = h32_from_64 (dgst[4]);
  w2[1] = l32_from_64 (dgst[4]);
  w2[2] = h32_from_64 (dgst[5]);
  w2[3] = l32_from_64 (dgst[5]);
  w3[0] = h32_from_64 (dgst[6]);
  w3[1] = l32_from_64 (dgst[6]);
  w3[2] = h32_from_64 (dgst[7]);
  w3[3] = l32_from_64 (dgst[7]);

  for (u32 i = 0; i < 8; i++) dgst[i] = opad[i];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, dgst);
}

// Initialize the pad states, then compute U1 = HMAC (key, salt . INT (i)) for each
// output block i. Store U1 as both the last U and the running XOR. The block number
// INT (i) uses 4 big endian bytes. The state stores the requested number of blocks, starting
// at block first + 1. This allows a caller that reads only later blocks of the derived key to
// skip the earlier blocks.

DECLSPEC void pbkdf2_md5_init (PRIVATE_AS pbkdf2_md5_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks)
{
  md5_hmac_ctx_t ctx;

  md5_hmac_init (&ctx, key, key_len);

  for (u32 i = 0; i < 4; i++) st->ipad[i] = ctx.ipad.h[i];
  for (u32 i = 0; i < 4; i++) st->opad[i] = ctx.opad.h[i];

  md5_hmac_update (&ctx, salt, salt_len);

  for (u32 b = 0; b < blocks; b++)
  {
    md5_hmac_ctx_t ctx2 = ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = (first + b + 1) << 24;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_hmac_update_64 (&ctx2, w0, w1, w2, w3, 4);

    md5_hmac_final (&ctx2);

    for (u32 i = 0; i < 4; i++) st->dgst[(b * 4) + i] = ctx2.opad.h[i];
    for (u32 i = 0; i < 4; i++) st->out[(b * 4) + i]  = ctx2.opad.h[i];
  }
}

DECLSPEC void pbkdf2_sha1_init (PRIVATE_AS pbkdf2_sha1_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks)
{
  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_swap (&ctx, key, key_len);

  for (u32 i = 0; i < 5; i++) st->ipad[i] = ctx.ipad.h[i];
  for (u32 i = 0; i < 5; i++) st->opad[i] = ctx.opad.h[i];

  sha1_hmac_update_swap (&ctx, salt, salt_len);

  for (u32 b = 0; b < blocks; b++)
  {
    sha1_hmac_ctx_t ctx2 = ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = first + b + 1;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&ctx2);

    for (u32 i = 0; i < 5; i++) st->dgst[(b * 5) + i] = ctx2.opad.h[i];
    for (u32 i = 0; i < 5; i++) st->out[(b * 5) + i]  = ctx2.opad.h[i];
  }
}

DECLSPEC void pbkdf2_sha256_init (PRIVATE_AS pbkdf2_sha256_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks)
{
  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_swap (&ctx, key, key_len);

  for (u32 i = 0; i < 8; i++) st->ipad[i] = ctx.ipad.h[i];
  for (u32 i = 0; i < 8; i++) st->opad[i] = ctx.opad.h[i];

  sha256_hmac_update_swap (&ctx, salt, salt_len);

  for (u32 b = 0; b < blocks; b++)
  {
    sha256_hmac_ctx_t ctx2 = ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = first + b + 1;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&ctx2);

    for (u32 i = 0; i < 8; i++) st->dgst[(b * 8) + i] = ctx2.opad.h[i];
    for (u32 i = 0; i < 8; i++) st->out[(b * 8) + i]  = ctx2.opad.h[i];
  }
}

DECLSPEC void pbkdf2_sha512_init (PRIVATE_AS pbkdf2_sha512_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks)
{
  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_swap (&ctx, key, key_len);

  for (u32 i = 0; i < 8; i++) st->ipad[i] = ctx.ipad.h[i];
  for (u32 i = 0; i < 8; i++) st->opad[i] = ctx.opad.h[i];

  sha512_hmac_update_swap (&ctx, salt, salt_len);

  for (u32 b = 0; b < blocks; b++)
  {
    sha512_hmac_ctx_t ctx2 = ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    w0[0] = first + b + 1;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha512_hmac_update_128 (&ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

    sha512_hmac_final (&ctx2);

    for (u32 i = 0; i < 8; i++) st->dgst[(b * 8) + i] = ctx2.opad.h[i];
    for (u32 i = 0; i < 8; i++) st->out[(b * 8) + i]  = ctx2.opad.h[i];
  }
}

// For each output block, run as many further iterations as the loops argument gives. Each
// iteration computes U = HMAC (key, U) and XORs it into the running XOR of every U.

DECLSPEC void pbkdf2_md5_loop (PRIVATE_AS pbkdf2_md5_state_t *st, const u32 blocks, const u32 loops)
{
  u32 ipad[4];
  u32 opad[4];

  for (u32 i = 0; i < 4; i++) ipad[i] = st->ipad[i];
  for (u32 i = 0; i < 4; i++) opad[i] = st->opad[i];

  for (u32 b = 0; b < blocks; b++)
  {
    u32 dgst[4];
    u32 out[4];

    for (u32 i = 0; i < 4; i++) dgst[i] = st->dgst[(b * 4) + i];
    for (u32 i = 0; i < 4; i++) out[i]  = st->out[(b * 4) + i];

    for (u32 j = 0; j < loops; j++)
    {
      pbkdf2_md5_run (ipad, opad, dgst);

      for (u32 i = 0; i < 4; i++) out[i] ^= dgst[i];
    }

    for (u32 i = 0; i < 4; i++) st->dgst[(b * 4) + i] = dgst[i];
    for (u32 i = 0; i < 4; i++) st->out[(b * 4) + i]  = out[i];
  }
}

DECLSPEC void pbkdf2_sha1_loop (PRIVATE_AS pbkdf2_sha1_state_t *st, const u32 blocks, const u32 loops)
{
  u32 ipad[5];
  u32 opad[5];

  for (u32 i = 0; i < 5; i++) ipad[i] = st->ipad[i];
  for (u32 i = 0; i < 5; i++) opad[i] = st->opad[i];

  for (u32 b = 0; b < blocks; b++)
  {
    u32 dgst[5];
    u32 out[5];

    for (u32 i = 0; i < 5; i++) dgst[i] = st->dgst[(b * 5) + i];
    for (u32 i = 0; i < 5; i++) out[i]  = st->out[(b * 5) + i];

    for (u32 j = 0; j < loops; j++)
    {
      pbkdf2_sha1_run (ipad, opad, dgst);

      for (u32 i = 0; i < 5; i++) out[i] ^= dgst[i];
    }

    for (u32 i = 0; i < 5; i++) st->dgst[(b * 5) + i] = dgst[i];
    for (u32 i = 0; i < 5; i++) st->out[(b * 5) + i]  = out[i];
  }
}

DECLSPEC void pbkdf2_sha256_loop (PRIVATE_AS pbkdf2_sha256_state_t *st, const u32 blocks, const u32 loops)
{
  u32 ipad[8];
  u32 opad[8];

  for (u32 i = 0; i < 8; i++) ipad[i] = st->ipad[i];
  for (u32 i = 0; i < 8; i++) opad[i] = st->opad[i];

  for (u32 b = 0; b < blocks; b++)
  {
    u32 dgst[8];
    u32 out[8];

    for (u32 i = 0; i < 8; i++) dgst[i] = st->dgst[(b * 8) + i];
    for (u32 i = 0; i < 8; i++) out[i]  = st->out[(b * 8) + i];

    for (u32 j = 0; j < loops; j++)
    {
      pbkdf2_sha256_run (ipad, opad, dgst);

      for (u32 i = 0; i < 8; i++) out[i] ^= dgst[i];
    }

    for (u32 i = 0; i < 8; i++) st->dgst[(b * 8) + i] = dgst[i];
    for (u32 i = 0; i < 8; i++) st->out[(b * 8) + i]  = out[i];
  }
}

DECLSPEC void pbkdf2_sha512_loop (PRIVATE_AS pbkdf2_sha512_state_t *st, const u32 blocks, const u32 loops)
{
  u64 ipad[8];
  u64 opad[8];

  for (u32 i = 0; i < 8; i++) ipad[i] = st->ipad[i];
  for (u32 i = 0; i < 8; i++) opad[i] = st->opad[i];

  for (u32 b = 0; b < blocks; b++)
  {
    u64 dgst[8];
    u64 out[8];

    for (u32 i = 0; i < 8; i++) dgst[i] = st->dgst[(b * 8) + i];
    for (u32 i = 0; i < 8; i++) out[i]  = st->out[(b * 8) + i];

    for (u32 j = 0; j < loops; j++)
    {
      pbkdf2_sha512_run (ipad, opad, dgst);

      for (u32 i = 0; i < 8; i++) out[i] ^= dgst[i];
    }

    for (u32 i = 0; i < 8; i++) st->dgst[(b * 8) + i] = dgst[i];
    for (u32 i = 0; i < 8; i++) st->out[(b * 8) + i]  = out[i];
  }
}

// The first dk_len bytes of T1 . T2 . ..., with the rest of the last word cleared.

DECLSPEC void pbkdf2_dk_tail (PRIVATE_AS u32 *dk, const u32 dk_len)
{
  const u32 words = (dk_len + 3) / 4;
  const u32 tail  = dk_len & 3;

  if (tail > 0) dk[words - 1] &= 0xffffffff >> ((4 - tail) * 8);
}

DECLSPEC void pbkdf2_md5_comp (PRIVATE_AS const pbkdf2_md5_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len)
{
  const u32 words = (dk_len + 3) / 4;

  for (u32 i = 0; i < words; i++) dk[i] = st->out[i];

  pbkdf2_dk_tail (dk, dk_len);
}

DECLSPEC void pbkdf2_sha1_comp (PRIVATE_AS const pbkdf2_sha1_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len)
{
  const u32 words = (dk_len + 3) / 4;

  for (u32 i = 0; i < words; i++) dk[i] = hc_swap32_S (st->out[i]);

  pbkdf2_dk_tail (dk, dk_len);
}

DECLSPEC void pbkdf2_sha256_comp (PRIVATE_AS const pbkdf2_sha256_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len)
{
  const u32 words = (dk_len + 3) / 4;

  for (u32 i = 0; i < words; i++) dk[i] = hc_swap32_S (st->out[i]);

  pbkdf2_dk_tail (dk, dk_len);
}

DECLSPEC void pbkdf2_sha512_comp (PRIVATE_AS const pbkdf2_sha512_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len)
{
  const u32 words = (dk_len + 3) / 4;

  for (u32 i = 0; i < words; i++)
  {
    const u64 v = st->out[i / 2];

    const u32 w = ((i & 1) == 0) ? h32_from_64_S (v) : l32_from_64_S (v);

    dk[i] = hc_swap32_S (w);
  }

  pbkdf2_dk_tail (dk, dk_len);
}
