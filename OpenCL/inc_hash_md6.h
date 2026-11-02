/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_MD6_H
#define INC_HASH_MD6_H

/* for standard word size */

#define RL00 loop_body(10,11, 0)
#define RL01 loop_body( 5,24, 1)
#define RL02 loop_body(13, 9, 2)
#define RL03 loop_body(10,16, 3)
#define RL04 loop_body(11,15, 4)
#define RL05 loop_body(12, 9, 5)
#define RL06 loop_body( 2,27, 6)
#define RL07 loop_body( 7,15, 7)
#define RL08 loop_body(14, 6, 8)
#define RL09 loop_body(15, 2, 9)
#define RL10 loop_body( 7,29,10)
#define RL11 loop_body(13, 8,11)
#define RL12 loop_body(11,15,12)
#define RL13 loop_body( 7, 5,13)
#define RL14 loop_body( 6,31,14)
#define RL15 loop_body(12, 9,15)

/* n == 89 */

#define  MD6_T0   17     /* index for linear feedback */
#define  MD6_T1   18     /* index for first input to first and */
#define  MD6_T2   21     /* index for second input to first and */
#define  MD6_T3   31     /* index for first input to second and */
#define  MD6_T4   67     /* index for second input to second and */
#define  MD6_T5   89     /* last tap */

#define md6_w 64
#define md6_n 89            /* size of compression input block, in words  */
#define md6_c 16            /* size of compression output, in words       */
#define md6_q 15            /* # Q words in compression block (>=0)       */
#define md6_k  8            /* # key words per compression block (>=0)    */
#define md6_b 64            /* # data words per compression block (>0)    */

#define md6_default_L   64  /* large so that MD6 is fully hierarchical */

#define MD6_256_ROUNDS 104  // default value
#define MD6_256_DLEN   256  // digest len

#define loop_body(rs,ls,step)                                               \
  x  = S;                                       /* feedback constant     */ \
  x ^= A[i+step-MD6_T5];                        /* end-around feedback   */ \
  x ^= A[i+step-MD6_T0];                        /* linear feedback       */ \
  x ^= ( A[i+step-MD6_T1] & A[i+step-MD6_T2] ); /* first quadratic term  */ \
  x ^= ( A[i+step-MD6_T3] & A[i+step-MD6_T4] ); /* second quadratic term */ \
  x ^= (x >> rs);                               /* right-shift           */ \
  A[i+step] = x ^ (x << ls);                    /* left-shift            */

// MD6 with the default parameters: no key, mode L = 64 and 40 + d / 4 rounds for a digest of d
// bits. The digest has dlen bytes, a multiple of 8 up to 64. These are hx's md6 and md6128 (16
// bytes), md6256 (32) and md6512 (64). Input consists of little endian words, as for MD5. MD6
// itself reads big endian 64 bit words.
//
// A compression takes 64 data words, 512 bytes, so a longer message is hashed as a tree of
// compressions, 4 children to a node. The context holds MD6_LEVELS levels of it. With 3 levels a
// message can hold 16 leaves, 8192 bytes. A longer message is marked like invalid UTF-8, so that
// its digest cannot match.
//
// After md6_final (), h[0] to h[dlen / 8 - 1] contain the digest as big endian words: digest byte
// 0 is the high byte of h[0]. The remaining words of h are zero.

#define MD6_LEVELS 3

typedef struct md6_ctx
{
  // Level 0 collects the message bytes, the leaves, as big endian words. Level n > 0 collects
  // the 16 word results of the compressions at level n - 1, up to 4 of them. Per level, the
  // bytes held and the compressions done so far, which number the next node. Top is the highest
  // level that has received data.

  u64 b[MD6_LEVELS][64];

  int fill[MD6_LEVELS];
  int cnt[MD6_LEVELS];

  int top;

  // Rounds and digest bytes. Bytes in the whole message, -1 after invalid UTF-8 or a message too
  // long for the tree.

  int r;
  int dlen;
  int len;

  u64 h[8];

} md6_ctx_t;

typedef struct md6_ctx_vector
{
  u64x b[MD6_LEVELS][64];

  int fill[MD6_LEVELS];
  int cnt[MD6_LEVELS];

  int top;

  int r;
  int dlen;
  int len;

  u64x h[8];

} md6_ctx_vector_t;

DECLSPEC void md6_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 u, const u64 v, const int r);
DECLSPEC void md6_init (PRIVATE_AS md6_ctx_t *ctx, const int dlen);
DECLSPEC void md6_node (PRIVATE_AS md6_ctx_t *ctx, const int l, const int z, PRIVATE_AS u64 *c);
DECLSPEC void md6_push (PRIVATE_AS md6_ctx_t *ctx, const int l);
DECLSPEC void md6_absorb (PRIVATE_AS md6_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void md6_update (PRIVATE_AS md6_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md6_update_utf16le (PRIVATE_AS md6_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md6_update_global (PRIVATE_AS md6_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md6_update_global_utf16le (PRIVATE_AS md6_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md6_final (PRIVATE_AS md6_ctx_t *ctx);

DECLSPEC void md6_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 u, const u64 v, const int r);
DECLSPEC void md6_init_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int dlen);
DECLSPEC void md6_node_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int l, const int z, PRIVATE_AS u64x *c);
DECLSPEC void md6_push_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int l);
DECLSPEC void md6_absorb_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void md6_update_vector (PRIVATE_AS md6_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void md6_update_vector_utf16le (PRIVATE_AS md6_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void md6_final_vector (PRIVATE_AS md6_ctx_vector_t *ctx);

#endif // INC_HASH_MD6_H
