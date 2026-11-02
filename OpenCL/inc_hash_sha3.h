/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SHA3_H
#define INC_HASH_SHA3_H

// SHA-3 and Keccak with any digest size, one context type for both. The rate, the block size of the
// sponge, is 200 bytes minus twice the digest size: 144, 136, 104 and 72 bytes for digests of 28,
// 32, 48 and 64 bytes. SHA-3 pads with 0x06 and Keccak with 0x01. The state holds the digest in its
// first bytes, little endian, after sha3_final ().

#define SHA3_PAD_SHA3   0x06
#define SHA3_PAD_KECCAK 0x01

typedef struct sha3_ctx
{
  u64 st[25];

  // Bytes absorbed into the current block and in the whole message. The second count is -1 after
  // invalid UTF-8.

  int pos;
  int len;

  int rate;
  int dlen;
  u32 pad;

} sha3_ctx_t;

typedef struct sha3_ctx_vector
{
  u64x st[25];

  int pos;
  int len;

  int rate;
  int dlen;
  u32 pad;

} sha3_ctx_vector_t;

DECLSPEC void sha3_transform (PRIVATE_AS u64 *st);
DECLSPEC void sha3_init (PRIVATE_AS sha3_ctx_t *ctx, const int dlen, const u32 pad);
DECLSPEC void sha3_absorb (PRIVATE_AS sha3_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void sha3_update (PRIVATE_AS sha3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha3_update_utf16le (PRIVATE_AS sha3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha3_update_global (PRIVATE_AS sha3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha3_update_global_utf16le (PRIVATE_AS sha3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha3_final (PRIVATE_AS sha3_ctx_t *ctx);

DECLSPEC void sha3_transform_vector (PRIVATE_AS u64x *st);
DECLSPEC void sha3_init_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, const int dlen, const u32 pad);
DECLSPEC void sha3_absorb_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void sha3_update_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha3_update_vector_utf16le (PRIVATE_AS sha3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha3_final_vector (PRIVATE_AS sha3_ctx_vector_t *ctx);

#endif // INC_HASH_SHA3_H
