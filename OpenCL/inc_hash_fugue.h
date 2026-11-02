/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_FUGUE_H
#define INC_HASH_FUGUE_H

// Fugue with a digest of 28, 32, 48 or 64 bytes, one context type for all 4. These are what hx
// and sphlib call fugue224 to fugue512. Fugue-224 and Fugue-256 use a state of 30 words, Fugue-384
// and Fugue-512 one of 36 words, and each of the 3 has its own round function. Input consists
// of little endian words, as for MD5. After fugue_final (), h[0] to h[dlen / 4 - 1] contain the
// digest as little endian words in digest byte order. The init takes the digest size and the 4 SMIX
// tables, fugue_mixtab in inc_hash_fugue.cl or a copy of it in shared memory.

typedef struct fugue_ctx
{
  u32 S[36];

  // Fugue absorbs one big endian word at a time, and each word rotates the state by a fixed number
  // of columns. A block is as many words as rotate the state back to where it started: 5 words for
  // Fugue-224 and Fugue-256, 4 for Fugue-384 and 3 for Fugue-512.

  u32 m[5];

  // Bytes in the block, its size and bytes in the whole message. The last count is -1 after
  // invalid UTF-8.

  int pos;
  int bs;
  int len;

  int dlen;

  u32 h[16];

  SHM_TYPE u32a (*s_mixtab)[256];

} fugue_ctx_t;

typedef struct fugue_ctx_vector
{
  u32x S[36];

  u32x m[5];

  int pos;
  int bs;
  int len;

  int dlen;

  u32x h[16];

  SHM_TYPE u32a (*s_mixtab)[256];

} fugue_ctx_vector_t;

DECLSPEC void fugue_init (PRIVATE_AS fugue_ctx_t *ctx, const int dlen, SHM_TYPE u32a (*s_mixtab)[256]);
DECLSPEC void fugue_block (PRIVATE_AS fugue_ctx_t *ctx);
DECLSPEC void fugue_step (PRIVATE_AS fugue_ctx_t *ctx, const u32 q);
DECLSPEC void fugue_close (PRIVATE_AS fugue_ctx_t *ctx);
DECLSPEC void fugue_absorb (PRIVATE_AS fugue_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void fugue_absorb_utf16le (PRIVATE_AS fugue_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void fugue_update (PRIVATE_AS fugue_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void fugue_update_utf16le (PRIVATE_AS fugue_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void fugue_update_global (PRIVATE_AS fugue_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void fugue_update_global_utf16le (PRIVATE_AS fugue_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void fugue_final (PRIVATE_AS fugue_ctx_t *ctx);

DECLSPEC void fugue_init_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const int dlen, SHM_TYPE u32a (*s_mixtab)[256]);
DECLSPEC void fugue_block_vector (PRIVATE_AS fugue_ctx_vector_t *ctx);
DECLSPEC void fugue_step_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const u32x q);
DECLSPEC void fugue_close_vector (PRIVATE_AS fugue_ctx_vector_t *ctx);
DECLSPEC void fugue_absorb_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void fugue_update_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void fugue_update_vector_utf16le (PRIVATE_AS fugue_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void fugue_final_vector (PRIVATE_AS fugue_ctx_vector_t *ctx);

#endif // INC_HASH_FUGUE_H
