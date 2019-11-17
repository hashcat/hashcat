/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_sha512.cl"
#endif

#define COMPARE_M "inc_comp_multi.cl"

typedef struct electrum
{
  u32 data_buf[4096];
  u32 data_len;

} electrum_t;

typedef struct electrum_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} electrum_tmp_t;

typedef struct
{
  u32 ukey[8];

  u32 pubkey[9]; // 32 + 1 bytes (for sign of the curve point)

  u32 hook_success;

} electrum_hook_t;

DECLSPEC void hmac_sha512_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, u64x *ipad, u64x *opad, u64x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
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

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

KERNEL_FQ void m21700_init (KERN_ATTR_TMPS_HOOKS_ESALT (electrum_tmp_t, electrum_hook_t, electrum_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha512_hmac_ctx.opad.h[7];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = 1;
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

  sha512_hmac_update_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&sha512_hmac_ctx);

  tmps[gid].dgst[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].dgst[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].dgst[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].dgst[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].dgst[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].dgst[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].dgst[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].dgst[7] = sha512_hmac_ctx.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ void m21700_loop (KERN_ATTR_TMPS_HOOKS_ESALT (electrum_tmp_t, electrum_hook_t, electrum_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad, gid, 0);
  ipad[1] = pack64v (tmps, ipad, gid, 1);
  ipad[2] = pack64v (tmps, ipad, gid, 2);
  ipad[3] = pack64v (tmps, ipad, gid, 3);
  ipad[4] = pack64v (tmps, ipad, gid, 4);
  ipad[5] = pack64v (tmps, ipad, gid, 5);
  ipad[6] = pack64v (tmps, ipad, gid, 6);
  ipad[7] = pack64v (tmps, ipad, gid, 7);

  opad[0] = pack64v (tmps, opad, gid, 0);
  opad[1] = pack64v (tmps, opad, gid, 1);
  opad[2] = pack64v (tmps, opad, gid, 2);
  opad[3] = pack64v (tmps, opad, gid, 3);
  opad[4] = pack64v (tmps, opad, gid, 4);
  opad[5] = pack64v (tmps, opad, gid, 5);
  opad[6] = pack64v (tmps, opad, gid, 6);
  opad[7] = pack64v (tmps, opad, gid, 7);

  u64x dgst[8];
  u64x out[8];

  dgst[0] = pack64v (tmps, dgst, gid, 0);
  dgst[1] = pack64v (tmps, dgst, gid, 1);
  dgst[2] = pack64v (tmps, dgst, gid, 2);
  dgst[3] = pack64v (tmps, dgst, gid, 3);
  dgst[4] = pack64v (tmps, dgst, gid, 4);
  dgst[5] = pack64v (tmps, dgst, gid, 5);
  dgst[6] = pack64v (tmps, dgst, gid, 6);
  dgst[7] = pack64v (tmps, dgst, gid, 7);

  out[0] = pack64v (tmps, out, gid, 0);
  out[1] = pack64v (tmps, out, gid, 1);
  out[2] = pack64v (tmps, out, gid, 2);
  out[3] = pack64v (tmps, out, gid, 3);
  out[4] = pack64v (tmps, out, gid, 4);
  out[5] = pack64v (tmps, out, gid, 5);
  out[6] = pack64v (tmps, out, gid, 6);
  out[7] = pack64v (tmps, out, gid, 7);

  for (u32 j = 0; j < loop_cnt; j++)
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

    hmac_sha512_run_V (w0, w1, w2, w3, w4, w5, w6, w7, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  unpack64v (tmps, dgst, gid, 0, dgst[0]);
  unpack64v (tmps, dgst, gid, 1, dgst[1]);
  unpack64v (tmps, dgst, gid, 2, dgst[2]);
  unpack64v (tmps, dgst, gid, 3, dgst[3]);
  unpack64v (tmps, dgst, gid, 4, dgst[4]);
  unpack64v (tmps, dgst, gid, 5, dgst[5]);
  unpack64v (tmps, dgst, gid, 6, dgst[6]);
  unpack64v (tmps, dgst, gid, 7, dgst[7]);

  unpack64v (tmps, out, gid, 0, out[0]);
  unpack64v (tmps, out, gid, 1, out[1]);
  unpack64v (tmps, out, gid, 2, out[2]);
  unpack64v (tmps, out, gid, 3, out[3]);
  unpack64v (tmps, out, gid, 4, out[4]);
  unpack64v (tmps, out, gid, 5, out[5]);
  unpack64v (tmps, out, gid, 6, out[6]);
  unpack64v (tmps, out, gid, 7, out[7]);
}

KERNEL_FQ void m21700_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (electrum_tmp_t, electrum_hook_t, electrum_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u64 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  // we need to perform a modulo operation with 512-bit % 256-bit (bignum modulo):
  // the modulus is the secp256k1 group order

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

  a[ 0] = h32_from_64_S (out[0]);
  a[ 1] = l32_from_64_S (out[0]);
  a[ 2] = h32_from_64_S (out[1]);
  a[ 3] = l32_from_64_S (out[1]);
  a[ 4] = h32_from_64_S (out[2]);
  a[ 5] = l32_from_64_S (out[2]);
  a[ 6] = h32_from_64_S (out[3]);
  a[ 7] = l32_from_64_S (out[3]);
  a[ 8] = h32_from_64_S (out[4]);
  a[ 9] = l32_from_64_S (out[4]);
  a[10] = h32_from_64_S (out[5]);
  a[11] = l32_from_64_S (out[5]);
  a[12] = h32_from_64_S (out[6]);
  a[13] = l32_from_64_S (out[6]);
  a[14] = h32_from_64_S (out[7]);
  a[15] = l32_from_64_S (out[7]);

  u32 b[16];

  b[ 0] = 0x00000000;
  b[ 1] = 0x00000000;
  b[ 2] = 0x00000000;
  b[ 3] = 0x00000000;
  b[ 4] = 0x00000000;
  b[ 5] = 0x00000000;
  b[ 6] = 0x00000000;
  b[ 7] = 0x00000000;
  b[ 8] = 0xffffffff;
  b[ 9] = 0xffffffff;
  b[10] = 0xffffffff;
  b[11] = 0xfffffffe;
  b[12] = 0xbaaedce6;
  b[13] = 0xaf48a03b;
  b[14] = 0xbfd25e8c;
  b[15] = 0xd0364141;

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
    if (a[ 0] == b[ 0]) if (a[ 1] < b[ 1]) break;
    if (a[ 1] == b[ 1]) if (a[ 2] < b[ 2]) break;
    if (a[ 2] == b[ 2]) if (a[ 3] < b[ 3]) break;
    if (a[ 3] == b[ 3]) if (a[ 4] < b[ 4]) break;
    if (a[ 4] == b[ 4]) if (a[ 5] < b[ 5]) break;
    if (a[ 5] == b[ 5]) if (a[ 6] < b[ 6]) break;
    if (a[ 6] == b[ 6]) if (a[ 7] < b[ 7]) break;
    if (a[ 7] == b[ 7]) if (a[ 8] < b[ 8]) break;
    if (a[ 8] == b[ 8]) if (a[ 9] < b[ 9]) break;
    if (a[ 9] == b[ 9]) if (a[10] < b[10]) break;
    if (a[10] == b[10]) if (a[11] < b[11]) break;
    if (a[11] == b[11]) if (a[12] < b[12]) break;
    if (a[12] == b[12]) if (a[13] < b[13]) break;
    if (a[13] == b[13]) if (a[14] < b[14]) break;
    if (a[14] == b[14]) if (a[15] < b[15]) break;

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

    // x >>= 1

    x[15] = x[15] >> 1 | (x[14] & 1) << 31;
    x[14] = x[14] >> 1 | (x[13] & 1) << 31;
    x[13] = x[13] >> 1 | (x[12] & 1) << 31;
    x[12] = x[12] >> 1 | (x[11] & 1) << 31;
    x[11] = x[11] >> 1 | (x[10] & 1) << 31;
    x[10] = x[10] >> 1 | (x[ 9] & 1) << 31;
    x[ 9] = x[ 9] >> 1 | (x[ 8] & 1) << 31;
    x[ 8] = x[ 8] >> 1 | (x[ 7] & 1) << 31;
    x[ 7] = x[ 7] >> 1 | (x[ 6] & 1) << 31;
    x[ 6] = x[ 6] >> 1 | (x[ 5] & 1) << 31;
    x[ 5] = x[ 5] >> 1 | (x[ 4] & 1) << 31;
    x[ 4] = x[ 4] >> 1 | (x[ 3] & 1) << 31;
    x[ 3] = x[ 3] >> 1 | (x[ 2] & 1) << 31;
    x[ 2] = x[ 2] >> 1 | (x[ 1] & 1) << 31;
    x[ 1] = x[ 1] >> 1 | (x[ 0] & 1) << 31;
    x[ 0] = x[ 0] >> 1;

    // if (a >= r) a -= r;

                        if (a[ 0] < r[ 0]) continue;
    if (a[ 0] == r[ 0]) if (a[ 1] < r[ 1]) continue;
    if (a[ 1] == r[ 1]) if (a[ 2] < r[ 2]) continue;
    if (a[ 2] == r[ 2]) if (a[ 3] < r[ 3]) continue;
    if (a[ 3] == r[ 3]) if (a[ 4] < r[ 4]) continue;
    if (a[ 4] == r[ 4]) if (a[ 5] < r[ 5]) continue;
    if (a[ 5] == r[ 5]) if (a[ 6] < r[ 6]) continue;
    if (a[ 6] == r[ 6]) if (a[ 7] < r[ 7]) continue;
    if (a[ 7] == r[ 7]) if (a[ 8] < r[ 8]) continue;
    if (a[ 8] == r[ 8]) if (a[ 9] < r[ 9]) continue;
    if (a[ 9] == r[ 9]) if (a[10] < r[10]) continue;
    if (a[10] == r[10]) if (a[11] < r[11]) continue;
    if (a[11] == r[11]) if (a[12] < r[12]) continue;
    if (a[12] == r[12]) if (a[13] < r[13]) continue;
    if (a[13] == r[13]) if (a[14] < r[14]) continue;
    if (a[14] == r[14]) if (a[15] < r[15]) continue;

    // substract (a -= r):

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

  /**
   * copy the last 256 bit (32 bytes) of modulo (a) to the hook buffer
   */

  hooks[gid].ukey[0] = hc_swap32_S (a[ 8]);
  hooks[gid].ukey[1] = hc_swap32_S (a[ 9]);
  hooks[gid].ukey[2] = hc_swap32_S (a[10]);
  hooks[gid].ukey[3] = hc_swap32_S (a[11]);
  hooks[gid].ukey[4] = hc_swap32_S (a[12]);
  hooks[gid].ukey[5] = hc_swap32_S (a[13]);
  hooks[gid].ukey[6] = hc_swap32_S (a[14]);
  hooks[gid].ukey[7] = hc_swap32_S (a[15]);
}

KERNEL_FQ void m21700_comp (KERN_ATTR_TMPS_HOOKS_ESALT (electrum_tmp_t, electrum_hook_t, electrum_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  if (hooks[gid].hook_success == 0) return;

  u32 pubkey[64] = { 0 };

  pubkey[0] = hooks[gid].pubkey[0];
  pubkey[1] = hooks[gid].pubkey[1];
  pubkey[2] = hooks[gid].pubkey[2];
  pubkey[3] = hooks[gid].pubkey[3];
  pubkey[4] = hooks[gid].pubkey[4];
  pubkey[5] = hooks[gid].pubkey[5];
  pubkey[6] = hooks[gid].pubkey[6];
  pubkey[7] = hooks[gid].pubkey[7];
  pubkey[8] = hooks[gid].pubkey[8];

  sha512_ctx_t sha512_ctx;

  sha512_init        (&sha512_ctx);
  sha512_update_swap (&sha512_ctx, pubkey, 33); // 33 because of 32 byte curve point + sign
  sha512_final       (&sha512_ctx);

  /*
   * sha256-hmac () of the data_buf
   */

  GLOBAL_AS u32 *data_buf = (GLOBAL_AS u32 *) esalt_bufs[digests_offset].data_buf;

  u32 data_len = esalt_bufs[digests_offset].data_len;

  u32 key[16] = { 0 };

  key[0] = h32_from_64_S (sha512_ctx.h[4]);
  key[1] = l32_from_64_S (sha512_ctx.h[4]);
  key[2] = h32_from_64_S (sha512_ctx.h[5]);
  key[3] = l32_from_64_S (sha512_ctx.h[5]);

  key[4] = h32_from_64_S (sha512_ctx.h[6]);
  key[5] = l32_from_64_S (sha512_ctx.h[6]);
  key[6] = h32_from_64_S (sha512_ctx.h[7]);
  key[7] = l32_from_64_S (sha512_ctx.h[7]);

  sha256_hmac_ctx_t sha256_ctx;

  sha256_hmac_init (&sha256_ctx, key, 32);

  sha256_hmac_update_global_swap (&sha256_ctx, data_buf, data_len);

  sha256_hmac_final (&sha256_ctx);

  const u32 r0 = sha256_ctx.opad.h[0];
  const u32 r1 = sha256_ctx.opad.h[1];
  const u32 r2 = sha256_ctx.opad.h[2];
  const u32 r3 = sha256_ctx.opad.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
