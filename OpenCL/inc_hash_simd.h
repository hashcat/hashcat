/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SIMD_H
#define INC_HASH_SIMD_H

// SIMD, the SHA-3 candidate, as sphlib implements it and hx calls it. SIMD-224 and SIMD-256 share
// the small compression function with a 64 byte block, in simd256_ctx_t with a digest length of 28
// or 32 bytes. SIMD-384 and SIMD-512 share the big one with a 128 byte block, in simd512_ctx_t
// with a digest length of 48 or 64 bytes. Input consists of little endian words, as for MD5.
// After simd256_final () or simd512_final (), h[0] to h[dlen / 4 - 1] contain the digest as
// little endian words in digest byte order, so digest word i is h[i] with no byte swap. The
// vector finals leave it in the same words of every lane. The tables are constant and read at
// fixed indices only, so the init functions take no table pointer.

typedef struct simd256_ctx
{
  // The state words A, B, C and D, 4 words each.

  u32 h[16];

  // The block being filled, the number of blocks already compressed, bytes in the block and bytes
  // in the whole message. The last count is -1 after invalid UTF-8.

  u32 m[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} simd256_ctx_t;

typedef struct simd256_ctx_vector
{
  u32x h[16];

  u32x m[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} simd256_ctx_vector_t;

typedef struct simd512_ctx
{
  // The state words A, B, C and D, 8 words each.

  u32 h[32];

  u32 m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} simd512_ctx_t;

typedef struct simd512_ctx_vector
{
  u32x h[32];

  u32x m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} simd512_ctx_vector_t;

// The transforms stay out of line on CPUs, because inlined at every call site, as in hmac_simd512
// of utf16le (pass), they take Intel's CPU compiler a very long time at vector width 8. On a GPU
// the call makes SIMD-256 slower, so there inlining is left to the compiler.

#ifdef IS_CPU
#define SIMDH_NOINLINE HC_NOINLINE_ALWAYS
#else
#define SIMDH_NOINLINE
#endif

DECLSPEC u32 simdh_rev (const u32 v, const u32 bits);

DECLSPEC SIMDH_NOINLINE void simd256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const int last);
DECLSPEC void simd256_init (PRIVATE_AS simd256_ctx_t *ctx, const int dlen);
DECLSPEC void simd256_absorb (PRIVATE_AS simd256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void simd256_update (PRIVATE_AS simd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void simd256_update_utf16le (PRIVATE_AS simd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void simd256_update_global (PRIVATE_AS simd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void simd256_update_global_utf16le (PRIVATE_AS simd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void simd256_final (PRIVATE_AS simd256_ctx_t *ctx);

DECLSPEC SIMDH_NOINLINE void simd256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const int last);
DECLSPEC void simd256_init_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, const int dlen);
DECLSPEC void simd256_absorb_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void simd256_update_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void simd256_update_vector_utf16le (PRIVATE_AS simd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void simd256_final_vector (PRIVATE_AS simd256_ctx_vector_t *ctx);

DECLSPEC SIMDH_NOINLINE void simd512_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const int last);
DECLSPEC void simd512_init (PRIVATE_AS simd512_ctx_t *ctx, const int dlen);
DECLSPEC void simd512_absorb (PRIVATE_AS simd512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void simd512_update (PRIVATE_AS simd512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void simd512_update_utf16le (PRIVATE_AS simd512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void simd512_update_global (PRIVATE_AS simd512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void simd512_update_global_utf16le (PRIVATE_AS simd512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void simd512_final (PRIVATE_AS simd512_ctx_t *ctx);

DECLSPEC SIMDH_NOINLINE void simd512_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const int last);
DECLSPEC void simd512_init_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, const int dlen);
DECLSPEC void simd512_absorb_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void simd512_update_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void simd512_update_vector_utf16le (PRIVATE_AS simd512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void simd512_final_vector (PRIVATE_AS simd512_ctx_vector_t *ctx);

#endif // INC_HASH_SIMD_H
