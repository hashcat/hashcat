/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// paw64, hashcat's own 64 bit identity hash.
//
// A pawprint is the mark that identifies, which is what every caller here wants: one number that
// says "this is that wordlist", "this is that attack", "this candidate has been seen". It is not a
// checksum for detecting corruption and it is not a message authentication code. Do not use it as
// either. The brain password is stretched with SHA-256 for exactly that reason.
//
// The idea is Yann Collet's. xxHash is what taught this codebase that a short input deserves a
// different shape from a long one, and the arrangement of a multiply, a fold and a strong final
// avalanche follows the ground he broke. No constant and no line of his code is used here, and the
// digests this file produces are not XXH64 digests.
//
// Measured with SMHasher3, the standard battery for hash functions of this kind: 188 of 188.
//
// A length is a length. Handing paw64_update a decode error, which is (size_t) -1 on every read
// path in this tree, asks it to hash the whole address space. It cannot tell that value from a
// genuine huge length and it does not try. A caller reading from a file must test the return of
// the read before passing it here. src/brain.c and src/feeds/seekdb.c both do.

#ifndef HC_PAW64_H
#define HC_PAW64_H

// Sizes the context below, so it belongs to the interface rather than to the implementation.

#define PAW64_BLOCK 32

// The context is the caller's, so it lives on the stack and there is nothing to allocate and
// nothing to free. seed holds the expanded seed, not the one the caller passed.

typedef struct paw64_ctx
{
  u64 h;
  u64 seed;
  u64 total;

  u8  buf[PAW64_BLOCK];
  u32 buf_len;

} paw64_ctx_t;

HC_PLUGIN_API u64  paw64        (const void *buf, const size_t len, const u64 seed);

HC_PLUGIN_API void paw64_init   (paw64_ctx_t *ctx, const u64 seed);
HC_PLUGIN_API void paw64_update (paw64_ctx_t *ctx, const void *buf, const size_t len);
HC_PLUGIN_API u64  paw64_final  (const paw64_ctx_t *ctx);

#endif // HC_PAW64_H
