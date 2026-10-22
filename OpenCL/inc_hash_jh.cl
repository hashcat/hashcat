/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_jh.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. The state, the IVs and the round constants are the 64 bit words of
// sphlib's bitslice implementation, read in little endian order. The bitslice operations do not
// depend on the byte order, so the message words go in without a byte swap.

// The initial states for digests of 28, 32, 48 and 64 bytes. Each is a zero block compressed into
// a state whose first 2 bytes hold the digest size in bits, big endian.

CONSTANT_VK u64a jh_iv[4][16] =
{
  { 0xac989af962ddfe2d, 0xe734d619d6ac7cae, 0x161230bc051083a4, 0x941466c9c63860b8,
    0x6f7080259f89d966, 0xdc1a9b1d1ba39ece, 0x106e367b5f32e811, 0xc106fa027f8594f9,
    0xb340c8d85c1b4f1b, 0x9980736e7fa1f697, 0xd3a3eaada593dfdc, 0x689a53c9dee831a4,
    0xe4a186ec8aa9b422, 0xf06ce59c95ac74d5, 0xbf2babb5ea0d9615, 0x6eea64ddf0dc1196 },
  { 0xebd3202c41a398eb, 0xc145b29c7bbecd92, 0xfac7d4609151931c, 0x038a507ed6820026,
    0x45b92677269e23a4, 0x77941ad4481afbe0, 0x7a176b0226abb5cd, 0xa82fff0f4224f056,
    0x754d2e7f8996a371, 0x62e27df70849141d, 0x948f2476f7957627, 0x6c29804757b6d587,
    0x6c0d8eac2d275e5c, 0x0f7a0557c6508451, 0xea12247067d3e47b, 0x69d71cd313abe389 },
  { 0x8a3913d8c63b1e48, 0x9b87de4a895e3b6d, 0x2ead80d468eafa63, 0x67820f4821cb2c33,
    0x28b982904dc8ae98, 0x4942114130ea55d4, 0xec474892b255f536, 0xe13cf4ba930a25c7,
    0x4c45db278a7f9b56, 0x0eaf976349bdfc9e, 0xcd80aa267dc29f58, 0xda2eeb9d8c8bc080,
    0x3a37d5f8e881798a, 0x717ad1ddad6739f4, 0x94d375a4bdd3b4a9, 0x7f734298ba3f6c97 },
  { 0x17aa003e964bd16f, 0x43d5157a052e6a63, 0x0bef970c8d5e228a, 0x61c3b3f2591234e9,
    0x1e806f53c1a01d89, 0x806d2bea6b05a92a, 0xa6ba7520dbcc8e58, 0xf73bf8ba763a0fa9,
    0x694ae34105e66901, 0x5ae66f2e8e8ab546, 0x243c84c1d0a74710, 0x99c15a2db1716e3b,
    0x56f8b19decf657cf, 0x56b116577c8806a7, 0xfb1785e6dffcc2e3, 0x4bdd8ccc78465a54 },
};

// The round constants: for each of the 42 rounds the high and low words for the even state words,
// then the same for the odd state words.

CONSTANT_VK u64a jh_rc[42][4] =
{
  { 0x67f815dfa2ded572, 0x571523b70a15847b, 0xf6875a4d90d6ab81, 0x402bd1c3c54f9f4e },
  { 0x9cfa455ce03a98ea, 0x9a99b26699d2c503, 0x8a53bbf2b4960266, 0x31a2db881a1456b5 },
  { 0xdb0e199a5c5aa303, 0x1044c1870ab23f40, 0x1d959e848019051c, 0xdccde75eadeb336f },
  { 0x416bbf029213ba10, 0xd027bbf7156578dc, 0x5078aa3739812c0a, 0xd3910041d2bf1a3f },
  { 0x907eccf60d5a2d42, 0xce97c0929c9f62dd, 0xac442bc70ba75c18, 0x23fcc663d665dfd1 },
  { 0x1ab8e09e036c6e97, 0xa8ec6c447e450521, 0xfa618e5dbb03f1ee, 0x97818394b29796fd },
  { 0x2f3003db37858e4a, 0x956a9ffb2d8d672a, 0x6c69b8f88173fe8a, 0x14427fc04672c78a },
  { 0xc45ec7bd8f15f4c5, 0x80bb118fa76f4475, 0xbc88e4aeb775de52, 0xf4a3a6981e00b882 },
  { 0x1563a3a9338ff48e, 0x89f9b7d524565faa, 0xfde05a7c20edf1b6, 0x362c42065ae9ca36 },
  { 0x3d98fe4e433529ce, 0xa74b9a7374f93a53, 0x86814e6f591ff5d0, 0x9f5ad8af81ad9d0e },
  { 0x6a6234ee670605a7, 0x2717b96ebe280b8b, 0x3f1080c626077447, 0x7b487ec66f7ea0e0 },
  { 0xc0a4f84aa50a550d, 0x9ef18e979fe7e391, 0xd48d605081727686, 0x62b0e5f3415a9e7e },
  { 0x7a205440ec1f9ffc, 0x84c9f4ce001ae4e3, 0xd895fa9df594d74f, 0xa554c324117e2e55 },
  { 0x286efebd2872df5b, 0xb2c4a50fe27ff578, 0x2ed349eeef7c8905, 0x7f5928eb85937e44 },
  { 0x4a3124b337695f70, 0x65e4d61df128865e, 0xe720b95104771bc7, 0x8a87d423e843fe74 },
  { 0xf2947692a3e8297d, 0xc1d9309b097acbdd, 0xe01bdc5bfb301b1d, 0xbf829cf24f4924da },
  { 0xffbf70b431bae7a4, 0x48bcf8de0544320d, 0x39d3bb5332fcae3b, 0xa08b29e0c1c39f45 },
  { 0x0f09aef7fd05c9e5, 0x34f1904212347094, 0x95ed44e301b771a2, 0x4a982f4f368e3be9 },
  { 0x15f66ca0631d4088, 0xffaf52874b44c147, 0x30c60ae2f14abb7e, 0xe68c6eccc5b67046 },
  { 0x00ca4fbd56a4d5a4, 0xae183ec84b849dda, 0xadd1643045ce5773, 0x67255c1468cea6e8 },
  { 0x16e10ecbf28cdaa3, 0x9a99949a5806e933, 0x7b846fc220b2601f, 0x1885d1a07facced1 },
  { 0xd319dd8da15b5932, 0x46b4a5aac01c9a50, 0xba6b04e467633d9f, 0x7eee560bab19caf6 },
  { 0x742128a9ea79b11f, 0xee51363b35f7bde9, 0x76d350755aac571d, 0x01707da3fec2463a },
  { 0x42d8a498afc135f7, 0x79676b9e20eced78, 0xa8db3aea15638341, 0x832c83324d3bc3fa },
  { 0xf347271c1f3b40a7, 0x9a762db734f04059, 0xfd4f21d26c4e3ee7, 0xef5957dc398dfdb8 },
  { 0xdaeb492b490c9b8d, 0x0d70f36849d7a25b, 0x84558d7ad0ae3b7d, 0x658ef8e4f0e9a5f5 },
  { 0x533b1036f4a2b8a0, 0x5aec3e759e07a80c, 0x4f88e85692946891, 0x4cbcbaf8555cb05b },
  { 0x7b9487f3993bbbe3, 0x5d1c6b72d6f4da75, 0x6db334dc28acae64, 0x71db28b850a5346c },
  { 0x2a518d10f2e261f8, 0xfc75dd593364dbe3, 0xa23fce43f1bcac1c, 0xb043e8023cd1bb67 },
  { 0x75a12988ca5b0a33, 0x5c5316b44d19347f, 0x1e4d790ec3943b92, 0x3fafeeb6d7757479 },
  { 0x21391abef7d4a8ea, 0x5127234c097ef45c, 0xd23c32ba5324a326, 0xadd5a66d4a17a344 },
  { 0x08c9f2afa63e1db5, 0x563c6b91983d5983, 0x4d608672a17cf84c, 0xf6c76e08cc3ee246 },
  { 0x5e76bcb1b333982f, 0x2ae6c4efa566d62b, 0x36d4c1bee8b6f406, 0x6321efbc1582ee74 },
  { 0x69c953f40d4ec1fd, 0x26585806c45a7da7, 0x16fae0061614c17e, 0x3f9d63283daf907e },
  { 0x0cd29b00e3f2c9d2, 0x300cd4b730ceaa5f, 0x9832e0f216512a74, 0x9af8cee3d830eb0d },
  { 0x9279f1b57b9ec54b, 0xd36886046ee651ff, 0x316796e6574d239b, 0x05750a17f3a6e6cc },
  { 0xce6c3213d98176b1, 0x62a205f88452173c, 0x47154778b3cb2bf4, 0x486a9323825446ff },
  { 0x65655e4e0758df38, 0x8e5086fc897cfcf2, 0x86ca0bd0442e7031, 0x4e477830a20940f0 },
  { 0x8338f7d139eea065, 0xbd3a2ce437e95ef7, 0x6ff8130126b29721, 0xe7de9fefd1ed44a3 },
  { 0xd992257615dfa08b, 0xbe42dc12f6f7853c, 0x7eb027ab7ceca7d8, 0xdea83eaada7d8d53 },
  { 0xd86902bd93ce25aa, 0xf908731afd43f65a, 0xa5194a17daef5fc0, 0x6a21fd4c33664d97 },
  { 0x701541db3198b435, 0x9b54cdedbb0f1eea, 0x72409751a163d09a, 0xe26f4791bf9d75f6 },
};

// The S-box layer, bitsliced: bit j of the words X0 to X3 forms one 4 bit S-box input, and bit j
// of the round constant K picks S0 or S1 for it.

#define JH_SB(T,X0,X1,X2,X3,K)                                                  \
{                                                                               \
  X3 = ~X3;                                                                     \
  X0 ^= (K) & ~X2;                                                              \
                                                                                \
  const T t = (K) ^ (X0 & X1);                                                  \
                                                                                \
  X0 ^= X2 & X3;                                                                \
  X3 ^= ~X1 & X2;                                                               \
  X1 ^= X0 & X2;                                                                \
  X2 ^= X0 & ~X3;                                                               \
  X0 ^= X1 | X3;                                                                \
  X3 ^= X1 & X2;                                                                \
  X1 ^= t & X0;                                                                 \
  X2 ^= t;                                                                      \
}

// The linear layer, an MDS code over GF(2^4) applied to pairs of S-box outputs

#define JH_LB(X0,X1,X2,X3,X4,X5,X6,X7)                                          \
{                                                                               \
  X4 ^= X1;                                                                     \
  X5 ^= X2;                                                                     \
  X6 ^= X3 ^ X0;                                                                \
  X7 ^= X0;                                                                     \
  X0 ^= X5;                                                                     \
  X1 ^= X6;                                                                     \
  X2 ^= X7 ^ X4;                                                                \
  X3 ^= X4;                                                                     \
}

// The permutation of round r swaps neighboring groups of 2^(r mod 7) bits in the odd state
// words. A word is the pair of 64 bit halves H and L, so the last one swaps the halves.

#define JH_WZ(T,H,L,M,N)                                                        \
{                                                                               \
  const T th = ((H) & (M)) << (N);                                              \
  const T tl = ((L) & (M)) << (N);                                              \
                                                                                \
  H = (((H) >> (N)) & (M)) | th;                                                \
  L = (((L) >> (N)) & (M)) | tl;                                                \
}

#define JH_W0(T,H,L) JH_WZ (T, H, L, (u64) 0x5555555555555555,  1)
#define JH_W1(T,H,L) JH_WZ (T, H, L, (u64) 0x3333333333333333,  2)
#define JH_W2(T,H,L) JH_WZ (T, H, L, (u64) 0x0f0f0f0f0f0f0f0f,  4)
#define JH_W3(T,H,L) JH_WZ (T, H, L, (u64) 0x00ff00ff00ff00ff,  8)
#define JH_W4(T,H,L) JH_WZ (T, H, L, (u64) 0x0000ffff0000ffff, 16)
#define JH_W5(T,H,L) JH_WZ (T, H, L, (u64) 0x00000000ffffffff, 32)

#define JH_W6(T,H,L)                                                            \
{                                                                               \
  const T t = H;                                                                \
                                                                                \
  H = L;                                                                        \
  L = t;                                                                        \
}

// One round on the state X, where X[2 * i] and X[2 * i + 1] are the high and low halves of state
// word i. C turns a constant into the type T.

#define JH_ROUND(T,C,X,R,W)                                                     \
{                                                                               \
  JH_SB (T, X[ 0], X[ 4], X[ 8], X[12], C (jh_rc[(R)][0]));                     \
  JH_SB (T, X[ 1], X[ 5], X[ 9], X[13], C (jh_rc[(R)][1]));                     \
  JH_SB (T, X[ 2], X[ 6], X[10], X[14], C (jh_rc[(R)][2]));                     \
  JH_SB (T, X[ 3], X[ 7], X[11], X[15], C (jh_rc[(R)][3]));                     \
                                                                                \
  JH_LB (X[ 0], X[ 4], X[ 8], X[12], X[ 2], X[ 6], X[10], X[14]);               \
  JH_LB (X[ 1], X[ 5], X[ 9], X[13], X[ 3], X[ 7], X[11], X[15]);               \
                                                                                \
  W (T, X[ 2], X[ 3]);                                                          \
  W (T, X[ 6], X[ 7]);                                                          \
  W (T, X[10], X[11]);                                                          \
  W (T, X[14], X[15]);                                                          \
}

// The compression function F8: the block M is XORed into the first half of the state, the 42
// rounds of E8 follow, and M is XORed into the second half.

#define JH_TRANSFORM(T,C,H,M)                                                   \
{                                                                               \
  T x[16];                                                                      \
                                                                                \
  for (u32 i = 0; i < 8; i++)                                                   \
  {                                                                             \
    x[0 + i] = H[0 + i] ^ M[i];                                                 \
    x[8 + i] = H[8 + i];                                                        \
  }                                                                             \
                                                                                \
  for (u32 r = 0; r < 42; r += 7)                                               \
  {                                                                             \
    JH_ROUND (T, C, x, r + 0, JH_W0);                                           \
    JH_ROUND (T, C, x, r + 1, JH_W1);                                           \
    JH_ROUND (T, C, x, r + 2, JH_W2);                                           \
    JH_ROUND (T, C, x, r + 3, JH_W3);                                           \
    JH_ROUND (T, C, x, r + 4, JH_W4);                                           \
    JH_ROUND (T, C, x, r + 5, JH_W5);                                           \
    JH_ROUND (T, C, x, r + 6, JH_W6);                                           \
  }                                                                             \
                                                                                \
  for (u32 i = 0; i < 8; i++)                                                   \
  {                                                                             \
    H[0 + i] = x[0 + i];                                                        \
    H[8 + i] = x[8 + i] ^ M[i];                                                 \
  }                                                                             \
}

#define JH_C_S(V) (V)
#define JH_C_V(V) make_u64x (V)

DECLSPEC int jh_iv_index (const int dlen)
{
  if (dlen == 28) return 0;
  if (dlen == 32) return 1;
  if (dlen == 48) return 2;

  return 3;
}

DECLSPEC void jh_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m)
{
  JH_TRANSFORM (u64, JH_C_S, h, m);
}

DECLSPEC void jh_init (PRIVATE_AS jh_ctx_t *ctx, const int dlen)
{
  const int iv = jh_iv_index (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = jh_iv[iv][i];
  for (u32 i = 0; i <  8; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Process the full block in m. The padding always ends in a block of its own, so a full block
// never has to wait for more input.

DECLSPEC void jh_block (PRIVATE_AS jh_ctx_t *ctx)
{
  jh_transform (ctx->h, ctx->m);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->cnt += 1;
  ctx->pos  = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block.

DECLSPEC void jh_absorb (PRIVATE_AS jh_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  jh_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = (u64) (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void jh_update (PRIVATE_AS jh_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    jh_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void jh_absorb_utf16le (PRIVATE_AS jh_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  jh_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) jh_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void jh_update_utf16le (PRIVATE_AS jh_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      jh_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    jh_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void jh_update_global (PRIVATE_AS jh_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    jh_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void jh_update_global_utf16le (PRIVATE_AS jh_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      jh_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    jh_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte, zeros, and the message length in bits as a 128 bit big endian number
// in the last 16 bytes of a block. A message that ends inside a block gets the 0x80 byte in that
// block and the length in a block of zeros after it. A message that ends on a block boundary gets
// one block holding both. A context with invalid UTF-8 input produces a digest with every bit
// flipped, so that no candidate matches it by chance.

DECLSPEC void jh_final (PRIVATE_AS jh_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits_hi = ctx->cnt >> 55;
  const u64 bits_lo = (ctx->cnt << 9) + ((u64) pos << 3);

  ctx->m[pos / 8] |= ((u64) 0x80) << ((pos & 7) * 8);

  if (pos > 0)
  {
    jh_transform (ctx->h, ctx->m);

    for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;
  }

  ctx->m[6] = hc_swap64_S (bits_hi);
  ctx->m[7] = hc_swap64_S (bits_lo);

  jh_transform (ctx->h, ctx->m);

  if (ctx->len < 0)
  {
    for (u32 i = 8; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void jh_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m)
{
  JH_TRANSFORM (u64x, JH_C_V, h, m);
}

DECLSPEC void jh_init_vector (PRIVATE_AS jh_ctx_vector_t *ctx, const int dlen)
{
  const int iv = jh_iv_index (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u64x (jh_iv[iv][i]);
  for (u32 i = 0; i <  8; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void jh_block_vector (PRIVATE_AS jh_ctx_vector_t *ctx)
{
  jh_transform_vector (ctx->h, ctx->m);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->cnt += 1;
  ctx->pos  = 0;
}

DECLSPEC void jh_absorb_vector (PRIVATE_AS jh_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  jh_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = hl32_to_64 (0, v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void jh_update_vector (PRIVATE_AS jh_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    jh_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void jh_update_vector_utf16le (PRIVATE_AS jh_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    jh_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) jh_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void jh_final_vector (PRIVATE_AS jh_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits_hi = ctx->cnt >> 55;
  const u64 bits_lo = (ctx->cnt << 9) + ((u64) pos << 3);

  ctx->m[pos / 8] |= make_u64x (((u64) 0x80) << ((pos & 7) * 8));

  if (pos > 0)
  {
    jh_transform_vector (ctx->h, ctx->m);

    for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;
  }

  ctx->m[6] = make_u64x (hc_swap64_S (bits_hi));
  ctx->m[7] = make_u64x (hc_swap64_S (bits_lo));

  jh_transform_vector (ctx->h, ctx->m);
}
