/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_TIGER_H
#define INC_HASH_TIGER_H

// Tiger uses 3 passes. The pad value is 0x01 for Tiger and 0x80 for Tiger2, which differ only in
// that byte. Input consists of little endian words, as for MD5, in blocks of 64 bytes. After
// tiger_final (), the digest contains the 3 words of h, each in little endian order. The
// tiger_init_tth () function starts the Tiger tree hash of one leaf: Tiger over a 0x00 byte and
// the input. It matches TTH for inputs of up to 1024 bytes. A longer input produces an inverted
// digest, so it cannot crack the TTH of that input.

#define TIGER_PAD_TIGER  0x01
#define TIGER_PAD_TIGER2 0x80

typedef struct tiger_ctx
{
  u64 h[3];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  u32 pad;

  // Maximum number of bytes that produce a real digest.

  int max;

  SHM_TYPE u64a (*s_tiger)[256];

} tiger_ctx_t;

typedef struct tiger_ctx_vector
{
  u64x h[3];
  u32x w[16];

  int pos;
  int len;

  u32 pad;

  int max;

  SHM_TYPE u64a (*s_tiger)[256];

} tiger_ctx_vector_t;

DECLSPEC void tiger_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a (*s_tiger)[256]);
DECLSPEC void tiger_init (PRIVATE_AS tiger_ctx_t *ctx, SHM_TYPE u64a (*s_tiger)[256], const u32 pad);
DECLSPEC void tiger_init_tth (PRIVATE_AS tiger_ctx_t *ctx, SHM_TYPE u64a (*s_tiger)[256]);
DECLSPEC void tiger_block (PRIVATE_AS tiger_ctx_t *ctx);
DECLSPEC void tiger_absorb (PRIVATE_AS tiger_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void tiger_update (PRIVATE_AS tiger_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void tiger_update_utf16le (PRIVATE_AS tiger_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void tiger_update_global (PRIVATE_AS tiger_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void tiger_update_global_utf16le (PRIVATE_AS tiger_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void tiger_final (PRIVATE_AS tiger_ctx_t *ctx);

DECLSPEC void tiger_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a (*s_tiger)[256]);
DECLSPEC void tiger_init_vector (PRIVATE_AS tiger_ctx_vector_t *ctx, SHM_TYPE u64a (*s_tiger)[256], const u32 pad);
DECLSPEC void tiger_init_tth_vector (PRIVATE_AS tiger_ctx_vector_t *ctx, SHM_TYPE u64a (*s_tiger)[256]);
DECLSPEC void tiger_block_vector (PRIVATE_AS tiger_ctx_vector_t *ctx);
DECLSPEC void tiger_absorb_vector (PRIVATE_AS tiger_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void tiger_update_vector (PRIVATE_AS tiger_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void tiger_update_vector_utf16le (PRIVATE_AS tiger_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void tiger_final_vector (PRIVATE_AS tiger_ctx_vector_t *ctx);

#endif // INC_HASH_TIGER_H
