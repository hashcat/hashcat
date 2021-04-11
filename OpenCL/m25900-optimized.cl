/**
 * Author......: See docs/credits.txt and Robert Guetzkow
 * License.....: MIT
 */

/*
 * This code implement PBKDF2-HMAC-SHA256 but makes assumptions about the input length for optimizations.
 * Please keep this in mind when trying to reuse code. The comments explain what those assumptions are.
 *
 * The implementation is based on inc_hash_sha256.cl and m10900-pure.cl
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct blocks
{
  u32 b1[4];
  u32 b2[4];
  u32 b3[4];

} blocks_t;

typedef struct pbkdf2_sha256_tmp
{
  u32x ipad_partial_hash[8];
  u32x opad_partial_hash[8];

  u32x digest[32];
  u32x out[32];

} pbkdf2_sha256_tmp_t;

#define SHA256_STEP_NO_Wt(F0,F1,a,b,c,d,e,f,g,h,K)      \
{                                                       \
  h += K;                                               \
  h = hc_add3 (h, SHA256_S3 (e), F1 (e,f,g));           \
  d += h;                                               \
  h = hc_add3 (h, SHA256_S2 (a), F0 (a,b,c));           \
}

/*
 * h = h + Kt + Wt               -x => T1 (with Wt being 0)
 * h + BSIG1(e) + CH(e,f,g)      _|
 * d += h                        -  =>  d + T1 (d is used as e in the next step by switching the arguments.)
 * h = h + BSIG0(a) + MAJ(a,b,c) -  => T1 + T2 (h is used as a in the next step by switching the arguments.)
 */

#define ROUND_EXPAND()                            \
{                                                 \
  w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
  w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
  w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
  w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
  w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
  w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
  w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
  w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
  w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
  w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
  wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
  wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
  wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
  wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
  we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
  wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
}

#define ROUND_STEP(i)                                                                   \
{                                                                                       \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
  SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
}

DECLSPEC void init_sha256_ctx(sha256_ctx_vector_t *ctx)
{
  ctx->h[0] = SHA256M_A;
  ctx->h[1] = SHA256M_B;
  ctx->h[2] = SHA256M_C;
  ctx->h[3] = SHA256M_D;
  ctx->h[4] = SHA256M_E;
  ctx->h[5] = SHA256M_F;
  ctx->h[6] = SHA256M_G;
  ctx->h[7] = SHA256M_H;
}

DECLSPEC void init_ipad(sha256_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3)
{
  init_sha256_ctx(ctx);

  ctx->w0[0] = w0[0] ^ 0x36363636;
  ctx->w0[1] = w0[1] ^ 0x36363636;
  ctx->w0[2] = w0[2] ^ 0x36363636;
  ctx->w0[3] = w0[3] ^ 0x36363636;
  ctx->w1[0] = w1[0] ^ 0x36363636;
  ctx->w1[1] = w1[1] ^ 0x36363636;
  ctx->w1[2] = w1[2] ^ 0x36363636;
  ctx->w1[3] = w1[3] ^ 0x36363636;
  ctx->w2[0] = w2[0] ^ 0x36363636;
  ctx->w2[1] = w2[1] ^ 0x36363636;
  ctx->w2[2] = w2[2] ^ 0x36363636;
  ctx->w2[3] = w2[3] ^ 0x36363636;
  ctx->w3[0] = w3[0] ^ 0x36363636;
  ctx->w3[1] = w3[1] ^ 0x36363636;
  ctx->w3[2] = w3[2] ^ 0x36363636;
  ctx->w3[3] = w3[3] ^ 0x36363636;
}

DECLSPEC void init_opad(sha256_ctx_vector_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3)
{
  init_sha256_ctx(ctx);

  ctx->w0[0] = w0[0] ^ 0x5c5c5c5c;
  ctx->w0[1] = w0[1] ^ 0x5c5c5c5c;
  ctx->w0[2] = w0[2] ^ 0x5c5c5c5c;
  ctx->w0[3] = w0[3] ^ 0x5c5c5c5c;
  ctx->w1[0] = w1[0] ^ 0x5c5c5c5c;
  ctx->w1[1] = w1[1] ^ 0x5c5c5c5c;
  ctx->w1[2] = w1[2] ^ 0x5c5c5c5c;
  ctx->w1[3] = w1[3] ^ 0x5c5c5c5c;
  ctx->w2[0] = w2[0] ^ 0x5c5c5c5c;
  ctx->w2[1] = w2[1] ^ 0x5c5c5c5c;
  ctx->w2[2] = w2[2] ^ 0x5c5c5c5c;
  ctx->w2[3] = w2[3] ^ 0x5c5c5c5c;
  ctx->w3[0] = w3[0] ^ 0x5c5c5c5c;
  ctx->w3[1] = w3[1] ^ 0x5c5c5c5c;
  ctx->w3[2] = w3[2] ^ 0x5c5c5c5c;
  ctx->w3[3] = w3[3] ^ 0x5c5c5c5c;
}

DECLSPEC void sha256_transform_hash(const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest)
{
  /*
   * This function assumes that the input is a hash of length 256 bit with padding applied and that the total length
   * of all blocks is 768 bit. This allows to perform optimizations in the message schedule and hash round since some
   * words are known to be all zero bits, thus not contributing to some of the calculation. Additionally, calculations
   * for words that are known to be constant have been precomputed.
   *
   * The 256 bit hash is located in the first 8 words (index 0 to 7), followed by one word that has one bit set.
   * The length is represented as a 128 bit integer in the last 4 words. However, since for the HMAC calculation
   * the total size of all blocks doesn't exceed 768 bit, including ipad and opad respectively, only the last
   * word (index 15) contains the length bits. Thus the 32 bit words from index 9 to 14 are all zero bits.
   * Whenever these words would be used by the message schedule in
   *   Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(W(t-15)) + W(t-16)   [1]
   * or in the hash round in
   *   T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt                  [1]
   * the calculation can be simplified to remove the operand.
   *
   * The word at index 8, with one bit set, and the word at index 15, containing the length, are know to be constant.
   * Therefore, the operations where they are used as an operand can be partially precomputed. For the message schedule
   * this is possible for SSIG1(W(t-2)) and SSIG0(W(t-15)). In the hash round the Kt + Wt can be precomputed when Wt
   * is constant.
   *
   * Like sha256_transform_vector it performs the message schedule and hash round calculation jointly for 16 of the
   * 32 bit words. This requires fewer variables and thus less memory to hold the state, compared to calculating
   * the whole message schedule first and then performing the hash round.
   *
   * [1] RFC 6234, section 6.2, https://tools.ietf.org/html/rfc6234#section-6.2
   */

  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

  // This assignment is equivalent to the message schedule for the first 16 words.
  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  // The first 16 words have already been assigned, perform the first hash round. Don't use W_t when zero.
  SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[0]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[1]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[2]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[3]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[4]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[5]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[6]);
  SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[7]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, 0x5807aa98);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, k_sha256[9]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, k_sha256[10]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, k_sha256[11]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, k_sha256[12]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, k_sha256[13]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, k_sha256[14]);
  SHA256_STEP_NO_Wt(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, 0xc19bf474);

  // The message schedule for words 16 to 32 can skip calculations when W_t is zero
  w0_t = SHA256_S0(w1_t) + w0_t;
  w1_t = 0x01e00000 + SHA256_S0(w2_t) + w1_t;
  w2_t = SHA256_S1(w0_t) + SHA256_S0(w3_t) + w2_t;
  w3_t = SHA256_S1(w1_t) + SHA256_S0(w4_t) + w3_t;
  w4_t = SHA256_S1(w2_t) + SHA256_S0(w5_t) + w4_t;
  w5_t = SHA256_S1(w3_t) + SHA256_S0(w6_t) + w5_t;
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t;
  w7_t = SHA256_S1(w5_t) + w0_t + 0x11002000 + w7_t;
  w8_t = SHA256_S1(w6_t) + w1_t + w8_t;
  w9_t = SHA256_S1(w7_t) + w2_t;
  wa_t = SHA256_S1(w8_t) + w3_t;
  wb_t = SHA256_S1(w9_t) + w4_t;
  wc_t = SHA256_S1(wa_t) + w5_t;
  wd_t = SHA256_S1(wb_t) + w6_t;
  we_t = SHA256_S1(wc_t) + w7_t + 0x00c00066;
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t;

  // Following rounds do not have words that are guaranteed to be zero or constant, thus perform full calculations.
  ROUND_STEP(16);
  ROUND_EXPAND();
  ROUND_STEP(32);
  ROUND_EXPAND();
  ROUND_STEP(48);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void partial_hashes_ipad_opad(pbkdf2_sha256_tmp *tmp, GLOBAL_AS const u32 *pwd)
{
  /*
   * This functions assumes that passwords are smaller than 512 bit, which is the case for KNX IP Secure as the ETS 5 limits
   * the maximum length to 20 characters.
   *
   * Both ipad and opad remain constant for a given password throughout the PBKDF2 computation. Futhermore they are both
   * 512 bit long, which is exactly the block size of SHA-256. Thus, it is possible to compute a partial hash for both
   * without knowing what will be concatenated to ipad and opad, as the processing in SHA-256 happens in blocks of 512 bit.
   * The resulting intermediate result can be stored and reused in all rounds of the PBKDF.
   */

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = make_u32x (hc_swap32_S (pwd[ 0]));
  w0[1] = make_u32x (hc_swap32_S (pwd[ 1]));
  w0[2] = make_u32x (hc_swap32_S (pwd[ 2]));
  w0[3] = make_u32x (hc_swap32_S (pwd[ 3]));
  w1[0] = make_u32x (hc_swap32_S (pwd[ 4]));
  w1[1] = make_u32x (hc_swap32_S (pwd[ 5]));
  w1[2] = make_u32x (hc_swap32_S (pwd[ 6]));
  w1[3] = make_u32x (hc_swap32_S (pwd[ 7]));
  w2[0] = make_u32x (hc_swap32_S (pwd[ 8]));
  w2[1] = make_u32x (hc_swap32_S (pwd[ 9]));
  w2[2] = make_u32x (hc_swap32_S (pwd[10]));
  w2[3] = make_u32x (hc_swap32_S (pwd[11]));
  w3[0] = make_u32x (hc_swap32_S (pwd[12]));
  w3[1] = make_u32x (hc_swap32_S (pwd[13]));
  w3[2] = make_u32x (hc_swap32_S (pwd[14]));
  w3[3] = make_u32x (hc_swap32_S (pwd[15]));

  sha256_hmac_ctx_vector_t sha256_hmac_ctx_vector;

  // The partial hash is equivalent to computing the hash of just that one block
  init_ipad (&sha256_hmac_ctx_vector.ipad, w0, w1, w2, w3);
  init_opad (&sha256_hmac_ctx_vector.opad, w0, w1, w2, w3);

  sha256_transform_vector (sha256_hmac_ctx_vector.ipad.w0,
                           sha256_hmac_ctx_vector.ipad.w1,
                           sha256_hmac_ctx_vector.ipad.w2,
                           sha256_hmac_ctx_vector.ipad.w3,
                           sha256_hmac_ctx_vector.ipad.h);

  sha256_transform_vector (sha256_hmac_ctx_vector.opad.w0,
                           sha256_hmac_ctx_vector.opad.w1,
                           sha256_hmac_ctx_vector.opad.w2,
                           sha256_hmac_ctx_vector.opad.w3,
                           sha256_hmac_ctx_vector.opad.h);

  tmp->ipad_partial_hash[0] = sha256_hmac_ctx_vector.ipad.h[0];
  tmp->ipad_partial_hash[1] = sha256_hmac_ctx_vector.ipad.h[1];
  tmp->ipad_partial_hash[2] = sha256_hmac_ctx_vector.ipad.h[2];
  tmp->ipad_partial_hash[3] = sha256_hmac_ctx_vector.ipad.h[3];
  tmp->ipad_partial_hash[4] = sha256_hmac_ctx_vector.ipad.h[4];
  tmp->ipad_partial_hash[5] = sha256_hmac_ctx_vector.ipad.h[5];
  tmp->ipad_partial_hash[6] = sha256_hmac_ctx_vector.ipad.h[6];
  tmp->ipad_partial_hash[7] = sha256_hmac_ctx_vector.ipad.h[7];

  tmp->opad_partial_hash[0] = sha256_hmac_ctx_vector.opad.h[0];
  tmp->opad_partial_hash[1] = sha256_hmac_ctx_vector.opad.h[1];
  tmp->opad_partial_hash[2] = sha256_hmac_ctx_vector.opad.h[2];
  tmp->opad_partial_hash[3] = sha256_hmac_ctx_vector.opad.h[3];
  tmp->opad_partial_hash[4] = sha256_hmac_ctx_vector.opad.h[4];
  tmp->opad_partial_hash[5] = sha256_hmac_ctx_vector.opad.h[5];
  tmp->opad_partial_hash[6] = sha256_hmac_ctx_vector.opad.h[6];
  tmp->opad_partial_hash[7] = sha256_hmac_ctx_vector.opad.h[7];
}

DECLSPEC void hmac_sha256(u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad_partial_hash, u32x *opad_partial_hash, u32x *digest)
{
  /*
   * This function assumes that the input has been padded according to RFC 6234 [3].
   *
   * [3] RFC 6234, section 4.1, https://tools.ietf.org/html/rfc6234#section-4.1
   */

  digest[0] = ipad_partial_hash[0];
  digest[1] = ipad_partial_hash[1];
  digest[2] = ipad_partial_hash[2];
  digest[3] = ipad_partial_hash[3];
  digest[4] = ipad_partial_hash[4];
  digest[5] = ipad_partial_hash[5];
  digest[6] = ipad_partial_hash[6];
  digest[7] = ipad_partial_hash[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 768; // 512 bit for they ipad and 256 bit for the previous hash

  digest[0] = opad_partial_hash[0];
  digest[1] = opad_partial_hash[1];
  digest[2] = opad_partial_hash[2];
  digest[3] = opad_partial_hash[3];
  digest[4] = opad_partial_hash[4];
  digest[5] = opad_partial_hash[5];
  digest[6] = opad_partial_hash[6];
  digest[7] = opad_partial_hash[7];

  sha256_transform_hash (w0, w1, w2, w3, digest);
}

DECLSPEC void hmac_sha256_for_hash(u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad_partial_hash, u32x *opad_partial_hash, u32x *digest)
{
  /*
   * This function assumes that the input is the block containing the hash of 256 bit length and has been padded according to RFC 6234 [3]
   *
   * [3] RFC 6234, section 4.1, https://tools.ietf.org/html/rfc6234#section-4.1
   */

  digest[0] = ipad_partial_hash[0];
  digest[1] = ipad_partial_hash[1];
  digest[2] = ipad_partial_hash[2];
  digest[3] = ipad_partial_hash[3];
  digest[4] = ipad_partial_hash[4];
  digest[5] = ipad_partial_hash[5];
  digest[6] = ipad_partial_hash[6];
  digest[7] = ipad_partial_hash[7];

  sha256_transform_hash (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 768; // 512 bit for they ipad and 256 bit for the previous hash

  digest[0] = opad_partial_hash[0];
  digest[1] = opad_partial_hash[1];
  digest[2] = opad_partial_hash[2];
  digest[3] = opad_partial_hash[3];
  digest[4] = opad_partial_hash[4];
  digest[5] = opad_partial_hash[5];
  digest[6] = opad_partial_hash[6];
  digest[7] = opad_partial_hash[7];

  sha256_transform_hash (w0, w1, w2, w3, digest);
}

DECLSPEC void hmac_sha256_first_round(pbkdf2_sha256_tmp *tmp, GLOBAL_AS const u32 *salt, const int len)
{
  /*
   * This function assumes that the salt is less than 56 byte (448 bit), which is the case for
   * KNX IP Secure as the salt is constant and 46 byte (368 bit) long.
   */

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = make_u32x (hc_swap32_S (salt[ 0]));
  w0[1] = make_u32x (hc_swap32_S (salt[ 1]));
  w0[2] = make_u32x (hc_swap32_S (salt[ 2]));
  w0[3] = make_u32x (hc_swap32_S (salt[ 3]));
  w1[0] = make_u32x (hc_swap32_S (salt[ 4]));
  w1[1] = make_u32x (hc_swap32_S (salt[ 5]));
  w1[2] = make_u32x (hc_swap32_S (salt[ 6]));
  w1[3] = make_u32x (hc_swap32_S (salt[ 7]));
  w2[0] = make_u32x (hc_swap32_S (salt[ 8]));
  w2[1] = make_u32x (hc_swap32_S (salt[ 9]));
  w2[2] = make_u32x (hc_swap32_S (salt[10]));
  w2[3] = make_u32x (hc_swap32_S (salt[11]));
  w3[0] = make_u32x (hc_swap32_S (salt[12]));
  w3[1] = make_u32x (hc_swap32_S (salt[13]));
  w3[2] = make_u32x (hc_swap32_S (salt[14]));
  w3[3] = make_u32x (hc_swap32_S (salt[15]));

  /*
   * PBKDF2 requires the one-based 32 bit big-endian block index to be appended to the salt [2].
   * Since the salt is used in the first block, that integer is 1.
   *
   * [2] RFC 8018, section 5.2, item 3, https://tools.ietf.org/html/rfc8018#section-5.2
   */ 

  u32x i0[4];
  u32x i1[4];
  u32x i2[4];
  u32x i3[4];

  i0[0] = 1;
  i0[1] = 0;
  i0[2] = 0;
  i0[3] = 0;
  i1[0] = 0;
  i1[1] = 0;
  i1[2] = 0;
  i1[3] = 0;
  i2[0] = 0;
  i2[1] = 0;
  i2[2] = 0;
  i2[3] = 0;
  i3[0] = 0;
  i3[1] = 0;
  i3[2] = 0;
  i3[3] = 0;

  switch_buffer_by_offset_be(i0, i1, i2, i3, len & 63); // Shift to the correct position after the end of the salt

  w0[0] |= i0[0];
  w0[1] |= i0[1];
  w0[2] |= i0[2];
  w0[3] |= i0[3];
  w1[0] |= i1[0];
  w1[1] |= i1[1];
  w1[2] |= i1[2];
  w1[3] |= i1[3];
  w2[0] |= i2[0];
  w2[1] |= i2[1];
  w2[2] |= i2[2];
  w2[3] |= i2[3];
  w3[0] |= i3[0];
  w3[1] |= i3[1];
  w3[2] |= i3[2];
  w3[3] |= i3[3];

  // Updated length with the 32 bit block index appended
  MAYBE_VOLATILE const int len_updated = len + 4;

  /*
   * Pad salt to 512 bit using the padding scheme described in RFC 6234 [3]
   *
   * [3] RFC 6234, section 4.1, https://tools.ietf.org/html/rfc6234#section-4.1
   */
  append_0x80_4x4 (w0, w1, w2, w3, (len_updated & 63) ^ 3);
  w3[2] = 0;
  w3[3] = len_updated * 8 + 512; // Length in bits, ipad is 512 bit

  hmac_sha256 (w0, w1, w2, w3, tmp->ipad_partial_hash, tmp->opad_partial_hash, tmp->digest);

  tmp->out[0] = tmp->digest[0];
  tmp->out[1] = tmp->digest[1];
  tmp->out[2] = tmp->digest[2];
  tmp->out[3] = tmp->digest[3];
  tmp->out[4] = tmp->digest[4];
  tmp->out[5] = tmp->digest[5];
  tmp->out[6] = tmp->digest[6];
  tmp->out[7] = tmp->digest[7];
}

DECLSPEC void aes128_encrypt_cbc (const u32 *aes_ks, u32 *aes_iv, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 in_s[4];

  in_s[0] = in[0];
  in_s[1] = in[1];
  in_s[2] = in[2];
  in_s[3] = in[3];

  in_s[0] ^= aes_iv[0];
  in_s[1] ^= aes_iv[1];
  in_s[2] ^= aes_iv[2];
  in_s[3] ^= aes_iv[3];

  aes128_encrypt (aes_ks, in_s, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes_iv[0] = out[0];
  aes_iv[1] = out[1];
  aes_iv[2] = out[2];
  aes_iv[3] = out[3];
}

KERNEL_FQ void m25900_init(KERN_ATTR_TMPS(pbkdf2_sha256_tmp_t))
{
  const u64 gid = get_global_id(0);

  if (gid >= gid_max) return;

  partial_hashes_ipad_opad(&tmps[gid], pws[gid].i);

  hmac_sha256_first_round(&tmps[gid], salt_bufs[SALT_POS].salt_buf, salt_bufs[SALT_POS].salt_len);
}

KERNEL_FQ void m25900_loop(KERN_ATTR_TMPS(pbkdf2_sha256_tmp_t))
{
  const u64 gid = get_global_id(0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x* ipad_partial_hash = tmps[gid].ipad_partial_hash;
  u32x* opad_partial_hash = tmps[gid].opad_partial_hash;
  u32x* digest = tmps[gid].digest;
  u32x* out = tmps[gid].out;

  for (u32 j = 0; j < loop_cnt; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    // Pad the 256 bit hash from the previous PBKDF2-HMAC-SHA256 round to 512 bit
    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 768; // 512 bit for they ipad and 256 bit for the previous hash

    hmac_sha256_for_hash (w0, w1, w2, w3, ipad_partial_hash, opad_partial_hash, digest);

    // XOR digest created by HMAC-SHA256 for the PBKDF2 round
    out[0] ^= digest[0];
    out[1] ^= digest[1];
    out[2] ^= digest[2];
    out[3] ^= digest[3];
    out[4] ^= digest[4];
    out[5] ^= digest[5];
    out[6] ^= digest[6];
    out[7] ^= digest[7];
  }
}

KERNEL_FQ void m25900_comp(KERN_ATTR_TMPS_ESALT(pbkdf2_sha256_tmp_t, blocks_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id(0);
  const u64 lid = get_local_id(0);
  const u64 lsz = get_local_size(0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS();

  #else

  CONSTANT_AS u32a* s_td0 = td0;
  CONSTANT_AS u32a* s_td1 = td1;
  CONSTANT_AS u32a* s_td2 = td2;
  CONSTANT_AS u32a* s_td3 = td3;
  CONSTANT_AS u32a* s_td4 = td4;

  CONSTANT_AS u32a* s_te0 = te0;
  CONSTANT_AS u32a* s_te1 = te1;
  CONSTANT_AS u32a* s_te2 = te2;
  CONSTANT_AS u32a* s_te3 = te3;
  CONSTANT_AS u32a* s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  u32 key[4];

  key[0] = tmps[gid].out[DGST_R0];
  key[1] = tmps[gid].out[DGST_R1];
  key[2] = tmps[gid].out[DGST_R2];
  key[3] = tmps[gid].out[DGST_R3];

  u32 aes_ks[44];

  AES128_set_encrypt_key (aes_ks, key, s_te0, s_te1, s_te2, s_te3);

  u32 b0[4] = { 0 };

  u32 aes_cbc_iv[4] = { 0 };

  u32 yn[4];

  aes128_encrypt_cbc (aes_ks, aes_cbc_iv, b0, yn, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_cbc_iv, esalt_bufs[DIGESTS_OFFSET].b1, yn, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_cbc_iv, esalt_bufs[DIGESTS_OFFSET].b2, yn, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_cbc_iv, esalt_bufs[DIGESTS_OFFSET].b3, yn, s_te0, s_te1, s_te2, s_te3, s_te4);
 
  u32 nonce[4];

  nonce[0] = 0;
  nonce[1] = 0;
  nonce[2] = 0;
  nonce[3] = 0x00ff0000;  // already swapped

  u32 s0[4];

  aes128_encrypt(aes_ks, nonce, s0, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = yn[0] ^ s0[0];
  const u32 r1 = yn[1] ^ s0[1];
  const u32 r2 = yn[2] ^ s0[2];
  const u32 r3 = yn[3] ^ s0[3];

#define il_pos 0

#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
}
