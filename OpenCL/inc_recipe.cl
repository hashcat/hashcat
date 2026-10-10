/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Mode 4000 compiles --hash-recipe into the kernel. Recipes use the hx expression syntax.
//
// The core supplies macros for an ordered list of steps, each containing one hash call. See
// recipe_jit_build_options () in src/recipe.c for the encoding. Each step names its hash family and
// parts by token.
// The preprocessor emits only the required update calls, leaving unused families and part types
// out of the compiled kernel.
//
// A step hashes parts in sequence: the password, the salt, a literal or an earlier step's output.
// Each part feeds directly into the running hash, avoiding concatenation buffers and separate
// shifts for parts at arbitrary byte offsets.
//
// The same evaluation code builds for vector types, processing VECT_SIZE candidates at once, and
// scalar types. The scalar version is built only for recipes that apply utf16le to pass or salt, and
// for the combinator kernel under RECIPE_TAIL. See recipe_eval () below.

#define RECIPE_FMT_HEX     0
#define RECIPE_FMT_RAW     1
#define RECIPE_FMT_HEXU    2

#ifndef RECIPE_STEPS
#error "mode 4000: no recipe, set --hash-recipe"
#endif

// RECIPE_TAIL: the combinator kernel hands the password over as the base word and the right word,
// and every pass part hashes the one after the other, the right word from global memory, as the
// native combinator kernels do. Assembling the candidate first takes a private copy per candidate,
// which a GPU keeps in scratch memory. The module sets RECIPE_PASS_PLAIN when the recipe uses the
// password only as parts, not as an HMAC key or as the source of a transformed copy, which need it
// in one piece.

#if defined RECIPE_TAIL_KERNEL && defined RECIPE_PASS_PLAIN && (VECT_SIZE == 1)
#define RECIPE_TAIL
#endif

#ifndef RECIPE_L0_LEN
#define RECIPE_L0_LEN 0
#define RECIPE_L0_W0  0
#define RECIPE_L0_W1  0
#define RECIPE_L0_W2  0
#define RECIPE_L0_W3  0
#endif

#ifndef RECIPE_L1_LEN
#define RECIPE_L1_LEN 0
#define RECIPE_L1_W0  0
#define RECIPE_L1_W1  0
#define RECIPE_L1_W2  0
#define RECIPE_L1_W3  0
#endif

#ifndef RECIPE_L2_LEN
#define RECIPE_L2_LEN 0
#define RECIPE_L2_W0  0
#define RECIPE_L2_W1  0
#define RECIPE_L2_W2  0
#define RECIPE_L2_W3  0
#endif

#ifndef RECIPE_L3_LEN
#define RECIPE_L3_LEN 0
#define RECIPE_L3_W0  0
#define RECIPE_L3_W1  0
#define RECIPE_L3_W2  0
#define RECIPE_L3_W3  0
#endif

// Append len bytes from a global buffer to a private buffer containing pos bytes. Return the new
// length. The combinator kernel uses this to assemble a complete candidate for the recipe. Discard
// bytes beyond the usual 256-byte candidate limit.

DECLSPEC u32 recipe_append_global (PRIVATE_AS u32 *buf, const u32 pos, GLOBAL_AS const u32 *src, const u32 len)
{
  const u32 room = (pos >= 256) ? 0 : (256 - pos);
  const u32 cnt  = (len >= room) ? room : len;

  for (u32 i = 0; i < cnt; i++)
  {
    const u32 b = (src[i / 4] >> ((i & 3) * 8)) & 255;

    const u32 at = pos + i;

    buf[at / 4] |= b << ((at & 3) * 8);
  }

  const u32 r = pos + cnt;

  return r;
}

// Convert nibble N to one hex character. The expression (N + 6) >> 4 gives 1 when N is at least 10,
// avoiding a vector comparison that would give -1 per lane. OFF is 39 for lowercase and 7 for
// uppercase. RECIPE_HEX2 stores both hex characters for byte B in a little endian word, with the
// high nibble's character first in memory.

#define RECIPE_HEX1(N,OFF) ((N) + '0' + ((((N) + 6) >> 4) * (OFF)))
#define RECIPE_HEX2(B,OFF) ((RECIPE_HEX1 (((B) >> 4) & 15, OFF) << 0) | (RECIPE_HEX1 (((B) >> 0) & 15, OFF) << 8))

// GPUs use a local-memory hex table, as the native kernels do, to reduce instruction count. CPUs
// use arithmetic because it is faster there. The module sets RECIPE_HEX when a step writes hex.
// Fill the table with RECIPE_HEX_DECL before any work item returns, then bind it to the state with
// RECIPE_HEX_BIND before recipe_prep (). Entry B holds lowercase hex for byte B, and entry 256 + B
// holds uppercase hex.

#if defined IS_GPU && defined RECIPE_HEX
#define RECIPE_HEX_TABLE
#endif

#ifdef RECIPE_HEX_TABLE

#define RECIPE_HEX_DECL                                                         \
  LOCAL_VK u32 s_recipe_hex[512];                                               \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 512; i += (u32) get_local_size (0))  \
  {                                                                             \
    s_recipe_hex[i] = RECIPE_HEX2 (i & 255, (i >= 256) ? 7 : 39);               \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#define RECIPE_HEX_BIND(S) (S)->hex = s_recipe_hex;

#if   VECT_SIZE == 1
#define RECIPE_HEXT(B,UP) make_u32x (st->hex[(B) + (UP)])
#elif VECT_SIZE == 2
#define RECIPE_HEXT(B,UP) make_u32x (st->hex[(B).s0 + (UP)], st->hex[(B).s1 + (UP)])
#elif VECT_SIZE == 4
#define RECIPE_HEXT(B,UP) make_u32x (st->hex[(B).s0 + (UP)], st->hex[(B).s1 + (UP)], st->hex[(B).s2 + (UP)], st->hex[(B).s3 + (UP)])
#elif VECT_SIZE == 8
#define RECIPE_HEXT(B,UP) make_u32x (st->hex[(B).s0 + (UP)], st->hex[(B).s1 + (UP)], st->hex[(B).s2 + (UP)], st->hex[(B).s3 + (UP)], st->hex[(B).s4 + (UP)], st->hex[(B).s5 + (UP)], st->hex[(B).s6 + (UP)], st->hex[(B).s7 + (UP)])
#elif VECT_SIZE == 16
#define RECIPE_HEXT(B,UP) make_u32x (st->hex[(B).s0 + (UP)], st->hex[(B).s1 + (UP)], st->hex[(B).s2 + (UP)], st->hex[(B).s3 + (UP)], st->hex[(B).s4 + (UP)], st->hex[(B).s5 + (UP)], st->hex[(B).s6 + (UP)], st->hex[(B).s7 + (UP)], st->hex[(B).s8 + (UP)], st->hex[(B).s9 + (UP)], st->hex[(B).sa + (UP)], st->hex[(B).sb + (UP)], st->hex[(B).sc + (UP)], st->hex[(B).sd + (UP)], st->hex[(B).se + (UP)], st->hex[(B).sf + (UP)])
#endif

#define RECIPE_HEXT_S(B,UP) st->hex[(B) + (UP)]

#define RECIPE_HEXB(HS,B,OFF) RECIPE_HEXT##HS (B, ((OFF) == 7) ? 256 : 0)

#else

#define RECIPE_HEX_DECL
#define RECIPE_HEX_BIND(S)

#define RECIPE_HEXB(HS,B,OFF) RECIPE_HEX2 (B, OFF)

#endif

// Format step K's output as FMT from the LEN-byte digest in raw, stored as little endian words.
// Comparison uses raw directly for the final step.

#define RECIPE_FORMAT(T,HS,FMT,K,LEN)                                             \
{                                                                                 \
  if ((FMT) == RECIPE_FMT_RAW)                                                    \
  {                                                                               \
    for (u32 i = 0; i < ((LEN) / 4); i++) outs[((K) * 32) + i] = raw[i];          \
                                                                                  \
    out_lens[K] = (LEN);                                                          \
  }                                                                               \
  else                                                                            \
  {                                                                               \
    const u32 off = ((FMT) == RECIPE_FMT_HEXU) ? 7 : 39;                          \
                                                                                  \
    for (u32 i = 0; i < ((LEN) / 4); i++)                                         \
    {                                                                             \
      const T b0 = (raw[i] >>  0) & 255;                                          \
      const T b1 = (raw[i] >>  8) & 255;                                          \
      const T b2 = (raw[i] >> 16) & 255;                                          \
      const T b3 = (raw[i] >> 24) & 255;                                          \
                                                                                  \
      outs[((K) * 32) + (i * 2) + 0] = (RECIPE_HEXB (HS, b0, off) <<  0)          \
                                     | (RECIPE_HEXB (HS, b1, off) << 16);         \
      outs[((K) * 32) + (i * 2) + 1] = (RECIPE_HEXB (HS, b2, off) <<  0)          \
                                     | (RECIPE_HEXB (HS, b3, off) << 16);         \
    }                                                                             \
                                                                                  \
    out_lens[K] = (LEN) * 2;                                                      \
  }                                                                               \
}

// Slice step K's output to LEN bytes starting at START, which the module aligns to a multiple of 4.
// Without a cut, START is 0 and LEN covers the complete output, leaving it unchanged.

#define RECIPE_CUT(K,START,LEN)                                                               \
{                                                                                             \
  const u32 skip = (START) / 4;                                                               \
                                                                                              \
  if (skip > 0)                                                                               \
  {                                                                                           \
    for (u32 i = 0; i < (32 - skip); i++) outs[((K) * 32) + i] = outs[((K) * 32) + i + skip]; \
  }                                                                                           \
                                                                                              \
  out_lens[K] = (LEN);                                                                        \
}

// Recipes can hash transformed copies of pass or salt, such as upper (pass) or pad (salt, 16).
// The module sets RECIPE_XFORMS and names each copy's source and transforms. See
// recipe_jit_build_options (). Password copies are made per candidate in recipe_eval (). Salt
// copies are stored in the state once per salt by recipe_prep (). Each copy contains 64 words and
// stays zeroed past its length L after every transform. Its length depends only on the source
// length, so all vector lanes share the same length.
//
// Each transform modifies copy B and length L using arguments A, BB, H and LL from the module.
// UPPER, LOWER and ROT13 process 4 bytes at a time. A byte is a lowercase letter exactly when bit 7
// is clear, adding 0x1f to its low 7 bits sets bit 7, and adding 0x05 does not. Other transforms
// move individual bytes.

#define RECIPE_XGET(B,I)   ((B[(I) / 4] >> (((I) & 3) * 8)) & 255)
#define RECIPE_XPUT(B,I,V) B[(I) / 4] |= (V) << (((I) & 3) * 8)

// Masks with bit 7 set for each lowercase or uppercase letter in V, respectively.

#define RECIPE_XLC(V,A) (~((A) + 0x05050505) & ((A) + 0x1f1f1f1f) & ~(V) & 0x80808080)
#define RECIPE_XUC(V,A) (~((A) + 0x25252525) & ((A) + 0x3f3f3f3f) & ~(V) & 0x80808080)

// Clear bytes in B from L to the end.

#define RECIPE_XCLIP(B,L)                                                                 \
{                                                                                         \
  for (u32 i = (L) / 4; i < 64; i++)                                                      \
  {                                                                                       \
    const u32 at = i * 4;                                                                 \
                                                                                          \
    B[i] &= (at >= (L)) ? 0 : ((1u << (((L) - at) * 8)) - 1);                             \
  }                                                                                       \
}

#define RECIPE_XOP_NONE(T,HS,B,L,A,BB,H,LL)

#define RECIPE_XOP_UPPER(T,HS,B,L,A,BB,H,LL)                                              \
{                                                                                         \
  for (u32 i = 0; i < (((L) + 3) / 4); i++)                                               \
  {                                                                                       \
    const T v = B[i];                                                                     \
    const T a = v & 0x7f7f7f7f;                                                           \
                                                                                          \
    B[i] = v ^ (RECIPE_XLC (v, a) >> 2);                                                  \
  }                                                                                       \
}

#define RECIPE_XOP_LOWER(T,HS,B,L,A,BB,H,LL)                                              \
{                                                                                         \
  for (u32 i = 0; i < (((L) + 3) / 4); i++)                                               \
  {                                                                                       \
    const T v = B[i];                                                                     \
    const T a = v & 0x7f7f7f7f;                                                           \
                                                                                          \
    B[i] = v ^ (RECIPE_XUC (v, a) >> 2);                                                  \
  }                                                                                       \
}

// Shift letters by 13 in either case: forward for 'a' through 'm', backward for 'n' through 'z'.

#define RECIPE_XOP_ROT13(T,HS,B,L,A,BB,H,LL)                                              \
{                                                                                         \
  for (u32 i = 0; i < (((L) + 3) / 4); i++)                                               \
  {                                                                                       \
    const T v = B[i];                                                                     \
    const T f = (v | 0x20202020) & 0x7f7f7f7f;                                            \
    const T m = RECIPE_XLC (v, f);                                                        \
    const T h = (f + 0x12121212) & 0x80808080;                                            \
                                                                                          \
    const T up = (m & ~h) >> 7;                                                           \
    const T dn = (m &  h) >> 7;                                                           \
                                                                                          \
    B[i] = v + (up * 13) - (dn * 13);                                                     \
  }                                                                                       \
}

#define RECIPE_XOP_HEX(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  const u32 n = ((L) > 128) ? 128 : (L);                                                  \
                                                                                          \
  T t[64];                                                                                \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  for (u32 i = 0; i < ((n + 3) / 4); i++)                                                 \
  {                                                                                       \
    const T b0 = (B[i] >>  0) & 255;                                                      \
    const T b1 = (B[i] >>  8) & 255;                                                      \
    const T b2 = (B[i] >> 16) & 255;                                                      \
    const T b3 = (B[i] >> 24) & 255;                                                      \
                                                                                          \
    t[(i * 2) + 0] = (RECIPE_HEXB (HS, b0, 39) << 0) | (RECIPE_HEXB (HS, b1, 39) << 16);  \
    t[(i * 2) + 1] = (RECIPE_HEXB (HS, b2, 39) << 0) | (RECIPE_HEXB (HS, b3, 39) << 16);  \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = n * 2;                                                                              \
                                                                                          \
  RECIPE_XCLIP (B, L)                                                                     \
}

#define RECIPE_XOP_REV(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  T t[64];                                                                                \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  for (u32 i = 0; i < (L); i++)                                                           \
  {                                                                                       \
    const u32 j = (L) - 1 - i;                                                            \
                                                                                          \
    RECIPE_XPUT (t, i, RECIPE_XGET (B, j));                                               \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
}

// Move the last A bytes to the front. A negative A moves the first -A bytes to the end.

#define RECIPE_XOP_ROTATE(T,HS,B,L,A,BB,H,LL)                                             \
{                                                                                         \
  if ((L) > 0)                                                                            \
  {                                                                                       \
    const int ln = (int) (L);                                                             \
                                                                                          \
    const u32 n = (u32) ((((A) % ln) + ln) % ln);                                         \
                                                                                          \
    T t[64];                                                                              \
                                                                                          \
    for (u32 i = 0; i < 64; i++) t[i] = 0;                                                \
                                                                                          \
    for (u32 i = 0; i < (L); i++)                                                         \
    {                                                                                     \
      u32 j = i + n;                                                                      \
                                                                                          \
      if (j >= (L)) j -= (L);                                                             \
                                                                                          \
      RECIPE_XPUT (t, j, RECIPE_XGET (B, i));                                             \
    }                                                                                     \
                                                                                          \
    for (u32 i = 0; i < 64; i++) B[i] = t[i];                                             \
  }                                                                                       \
}

// Convert the letter at A to uppercase. A negative A selects the first lowercase letter, which
// can differ in position between lanes. The done mask tracks lanes that have found one.

#define RECIPE_XOP_CAP(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  if ((A) >= 0)                                                                           \
  {                                                                                       \
    if ((u32) (A) < (L))                                                                  \
    {                                                                                     \
      const u32 at = (u32) (A);                                                           \
                                                                                          \
      const T v = B[at / 4];                                                              \
      const T a = v & 0x7f7f7f7f;                                                         \
                                                                                          \
      B[at / 4] = v ^ ((RECIPE_XLC (v, a) & (0x80u << ((at & 3) * 8))) >> 2);             \
    }                                                                                     \
  }                                                                                       \
  else                                                                                    \
  {                                                                                       \
    T done = 0;                                                                           \
                                                                                          \
    for (u32 i = 0; i < (((L) + 3) / 4); i++)                                             \
    {                                                                                     \
      const T v = B[i];                                                                   \
      const T a = v & 0x7f7f7f7f;                                                         \
      const T m = RECIPE_XLC (v, a) & ~done;                                              \
      const T f = m & (m * 0xffffffff);                                                   \
                                                                                          \
      B[i] = v ^ (f >> 2);                                                                \
                                                                                          \
      done |= ((f | (f * 0xffffffff)) >> 31) * 0xffffffff;                                \
    }                                                                                     \
  }                                                                                       \
}

// Pad with zero bytes or truncate to A bytes.

#define RECIPE_XOP_PAD(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  if ((L) > (A)) RECIPE_XCLIP (B, (A))                                                    \
                                                                                          \
  L = (A);                                                                                \
}

// Reverse each complete group of 4 bytes and leave trailing bytes unchanged.

#define RECIPE_XOP_BSWAP32(T,HS,B,L,A,BB,H,LL)                                            \
{                                                                                         \
  for (u32 i = 0; i < ((L) / 4); i++) B[i] = hc_swap32##HS (B[i]);                        \
}

// Reorder BB words. The first eight indices use 4 bits each in A, and the rest are stored in H.

#define RECIPE_XOP_WPERM(T,HS,B,L,A,BB,H,LL)                                              \
{                                                                                         \
  T t[16];                                                                                \
                                                                                          \
  for (u32 j = 0; j < (BB); j++)                                                          \
  {                                                                                       \
    const u32 idx = ((j < 8) ? ((A) >> (j * 4)) : ((H) >> ((j - 8) * 4))) & 15;           \
                                                                                          \
    t[j] = B[idx];                                                                        \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = (i < (BB)) ? t[i] : 0;                              \
                                                                                          \
  L = (BB) * 4;                                                                           \
}

// Slice from A, clamped to the copy's bounds. Take BB bytes when LL is set, or the rest otherwise.

#define RECIPE_XOP_CUT(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  int from = (A);                                                                         \
                                                                                          \
  if (from < 0) from += (int) (L);                                                        \
  if (from < 0) from  = 0;                                                                \
                                                                                          \
  if (from > (int) (L)) from = (int) (L);                                                 \
                                                                                          \
  u32 n = (L) - (u32) from;                                                               \
                                                                                          \
  if (((LL) == 1) && (n > (u32) (BB))) n = (u32) (BB);                                    \
                                                                                          \
  T t[64];                                                                                \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  for (u32 i = 0; i < n; i++)                                                             \
  {                                                                                       \
    const u32 j = (u32) from + i;                                                         \
                                                                                          \
    RECIPE_XPUT (t, i, RECIPE_XGET (B, j));                                               \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = n;                                                                                  \
}

#define RECIPE_XOP3(OP,T,HS,B,L,A,BB,H,LL) RECIPE_XOP_##OP (T, HS, B, L, A, BB, H, LL)
#define RECIPE_XOP2(OP,T,HS,B,L,A,BB,H,LL) RECIPE_XOP3 (OP, T, HS, B, L, A, BB, H, LL)
#define RECIPE_XOP(K,J,T,HS,B,L)           RECIPE_XOP2 (RECIPE_X##K##_O##J, T, HS, B, L, RECIPE_X##K##_A##J, RECIPE_X##K##_B##J, RECIPE_X##K##_H##J, RECIPE_X##K##_L##J)

// Make copy K from the SLEN-byte source SRC and apply its transforms, storing its bytes in B and
// its length in L.

#define RECIPE_XRUN(K,T,HS,SRC,SLEN,B,L)       \
{                                              \
  for (u32 i = 0; i < 64; i++) B[i] = SRC[i];  \
                                               \
  L = (SLEN);                                  \
                                               \
  RECIPE_XOP (K, 0, T, HS, B, L)               \
  RECIPE_XOP (K, 1, T, HS, B, L)               \
  RECIPE_XOP (K, 2, T, HS, B, L)               \
  RECIPE_XOP (K, 3, T, HS, B, L)               \
}

// What recipe_eval () and recipe_prep () do for copy K, and the state fields it needs, by its source.

#define RECIPE_XEV_PASS(K,T,HS) T xb##K[64]; u32 xl##K; RECIPE_XRUN (K, T, HS, w, pw_len, xb##K, xl##K)
#define RECIPE_XEV_SALT(K,T,HS)
#define RECIPE_XPR_PASS(K,T,HS)
#define RECIPE_XPR_SALT(K,T,HS) RECIPE_XRUN (K, T, HS, s, salt_len, st->xb##K, st->xl##K)
#define RECIPE_XFLD_PASS(K,T)
#define RECIPE_XFLD_SALT(K,T)   T xb##K[64]; u32 xl##K;

#define RECIPE_XEV3(S,K,T,HS) RECIPE_XEV_##S (K, T, HS)
#define RECIPE_XEV2(S,K,T,HS) RECIPE_XEV3 (S, K, T, HS)
#define RECIPE_XPR3(S,K,T,HS) RECIPE_XPR_##S (K, T, HS)
#define RECIPE_XPR2(S,K,T,HS) RECIPE_XPR3 (S, K, T, HS)
#define RECIPE_XFLD3(S,K,T)   RECIPE_XFLD_##S (K, T)
#define RECIPE_XFLD2(S,K,T)   RECIPE_XFLD3 (S, K, T)

#ifndef RECIPE_XFORMS
#define RECIPE_XFORMS 0
#endif

#if RECIPE_XFORMS > 0
#define RECIPE_XEV_0(T,HS) RECIPE_XEV2  (RECIPE_X0_SRC, 0, T, HS)
#define RECIPE_XPR_0(T,HS) RECIPE_XPR2  (RECIPE_X0_SRC, 0, T, HS)
#define RECIPE_XFLD_0(T)   RECIPE_XFLD2 (RECIPE_X0_SRC, 0, T)
#else
#define RECIPE_XEV_0(T,HS)
#define RECIPE_XPR_0(T,HS)
#define RECIPE_XFLD_0(T)
#endif

#if RECIPE_XFORMS > 1
#define RECIPE_XEV_1(T,HS) RECIPE_XEV2  (RECIPE_X1_SRC, 1, T, HS)
#define RECIPE_XPR_1(T,HS) RECIPE_XPR2  (RECIPE_X1_SRC, 1, T, HS)
#define RECIPE_XFLD_1(T)   RECIPE_XFLD2 (RECIPE_X1_SRC, 1, T)
#else
#define RECIPE_XEV_1(T,HS)
#define RECIPE_XPR_1(T,HS)
#define RECIPE_XFLD_1(T)
#endif

#if RECIPE_XFORMS > 2
#define RECIPE_XEV_2(T,HS) RECIPE_XEV2  (RECIPE_X2_SRC, 2, T, HS)
#define RECIPE_XPR_2(T,HS) RECIPE_XPR2  (RECIPE_X2_SRC, 2, T, HS)
#define RECIPE_XFLD_2(T)   RECIPE_XFLD2 (RECIPE_X2_SRC, 2, T)
#else
#define RECIPE_XEV_2(T,HS)
#define RECIPE_XPR_2(T,HS)
#define RECIPE_XFLD_2(T)
#endif

#if RECIPE_XFORMS > 3
#define RECIPE_XEV_3(T,HS) RECIPE_XEV2  (RECIPE_X3_SRC, 3, T, HS)
#define RECIPE_XPR_3(T,HS) RECIPE_XPR2  (RECIPE_X3_SRC, 3, T, HS)
#define RECIPE_XFLD_3(T)   RECIPE_XFLD2 (RECIPE_X3_SRC, 3, T)
#else
#define RECIPE_XEV_3(T,HS)
#define RECIPE_XPR_3(T,HS)
#define RECIPE_XFLD_3(T)
#endif

#define RECIPE_XEVS(T,HS) RECIPE_XEV_0 (T, HS) RECIPE_XEV_1 (T, HS) RECIPE_XEV_2 (T, HS) RECIPE_XEV_3 (T, HS)
#define RECIPE_XPRS(T,HS) RECIPE_XPR_0 (T, HS) RECIPE_XPR_1 (T, HS) RECIPE_XPR_2 (T, HS) RECIPE_XPR_3 (T, HS)
#define RECIPE_XFLDS(T)   RECIPE_XFLD_0 (T) RECIPE_XFLD_1 (T) RECIPE_XFLD_2 (T) RECIPE_XFLD_3 (T)

// Feed one part into the running hash. U is the plain update and W is the UTF-16LE update. PU and
// PB are the update and buffer for pass. SU and SB are their salt equivalents. See RECIPE_UPDP_*.
// Part tokens are PASS, SALT, LIT0 through LIT3, STEP0 through STEP7, their UTF-16LE variants with
// 16 appended, or NONE for unused slots. PSTEP0 through PSTEP7 read outputs computed once per salt
// by recipe_prep () from the state during per-candidate evaluation. XP0 through XP3 are password
// copies, and XS0 through XS3 are salt copies stored in the state by recipe_prep ().

#define RECIPE_CALL_NONE(U,W,PU,PB,SU,SB,G,WG)
#define RECIPE_CALL_SALT(U,W,PU,PB,SU,SB,G,WG)       SU (&ctx, SB, (int) salt_len);

// In the combinator kernel the password can be the base word followed by the right word, which
// G and WG then hash from global memory, see RECIPE_TAIL below.

#ifdef RECIPE_TAIL
#define RECIPE_CALL_PASS(U,W,PU,PB,SU,SB,G,WG)       PU (&ctx, PB, (int) pw_len); G (&ctx, tail, (int) tail_len);
#define RECIPE_CALL_PASS16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, w, (int) pw_len); WG (&ctx, tail, (int) tail_len);
#else
#define RECIPE_CALL_PASS(U,W,PU,PB,SU,SB,G,WG)       PU (&ctx, PB, (int) pw_len);
#define RECIPE_CALL_PASS16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, w, (int) pw_len);
#endif
#define RECIPE_CALL_SALT16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, s, (int) salt_len);
#define RECIPE_CALL_LIT0(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits +  0, RECIPE_L0_LEN);
#define RECIPE_CALL_LIT1(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits +  4, RECIPE_L1_LEN);
#define RECIPE_CALL_LIT2(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits +  8, RECIPE_L2_LEN);
#define RECIPE_CALL_LIT3(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits + 12, RECIPE_L3_LEN);
#define RECIPE_CALL_STEP0(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (0 * 32), (int) out_lens[0]);
#define RECIPE_CALL_STEP1(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (1 * 32), (int) out_lens[1]);
#define RECIPE_CALL_STEP2(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (2 * 32), (int) out_lens[2]);
#define RECIPE_CALL_STEP3(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (3 * 32), (int) out_lens[3]);
#define RECIPE_CALL_STEP4(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (4 * 32), (int) out_lens[4]);
#define RECIPE_CALL_STEP5(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (5 * 32), (int) out_lens[5]);
#define RECIPE_CALL_STEP6(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (6 * 32), (int) out_lens[6]);
#define RECIPE_CALL_STEP7(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (7 * 32), (int) out_lens[7]);
#define RECIPE_CALL_STEP0_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (0 * 32), (int) out_lens[0]);
#define RECIPE_CALL_STEP1_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (1 * 32), (int) out_lens[1]);
#define RECIPE_CALL_STEP2_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (2 * 32), (int) out_lens[2]);
#define RECIPE_CALL_STEP3_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (3 * 32), (int) out_lens[3]);
#define RECIPE_CALL_STEP4_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (4 * 32), (int) out_lens[4]);
#define RECIPE_CALL_STEP5_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (5 * 32), (int) out_lens[5]);
#define RECIPE_CALL_STEP6_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (6 * 32), (int) out_lens[6]);
#define RECIPE_CALL_STEP7_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (7 * 32), (int) out_lens[7]);
#define RECIPE_CALL_PSTEP0(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (0 * 32), (int) pout_lens[0]);
#define RECIPE_CALL_PSTEP1(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (1 * 32), (int) pout_lens[1]);
#define RECIPE_CALL_PSTEP2(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (2 * 32), (int) pout_lens[2]);
#define RECIPE_CALL_PSTEP3(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (3 * 32), (int) pout_lens[3]);
#define RECIPE_CALL_PSTEP4(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (4 * 32), (int) pout_lens[4]);
#define RECIPE_CALL_PSTEP5(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (5 * 32), (int) pout_lens[5]);
#define RECIPE_CALL_PSTEP6(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (6 * 32), (int) pout_lens[6]);
#define RECIPE_CALL_PSTEP7(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (7 * 32), (int) pout_lens[7]);
#define RECIPE_CALL_PSTEP0_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (0 * 32), (int) pout_lens[0]);
#define RECIPE_CALL_PSTEP1_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (1 * 32), (int) pout_lens[1]);
#define RECIPE_CALL_PSTEP2_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (2 * 32), (int) pout_lens[2]);
#define RECIPE_CALL_PSTEP3_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (3 * 32), (int) pout_lens[3]);
#define RECIPE_CALL_PSTEP4_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (4 * 32), (int) pout_lens[4]);
#define RECIPE_CALL_PSTEP5_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (5 * 32), (int) pout_lens[5]);
#define RECIPE_CALL_PSTEP6_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (6 * 32), (int) pout_lens[6]);
#define RECIPE_CALL_PSTEP7_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (7 * 32), (int) pout_lens[7]);
#define RECIPE_CALL_XP0(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, xb0, (int) xl0);
#define RECIPE_CALL_XP1(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, xb1, (int) xl1);
#define RECIPE_CALL_XP2(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, xb2, (int) xl2);
#define RECIPE_CALL_XP3(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, xb3, (int) xl3);
#define RECIPE_CALL_XP0_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, xb0, (int) xl0);
#define RECIPE_CALL_XP1_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, xb1, (int) xl1);
#define RECIPE_CALL_XP2_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, xb2, (int) xl2);
#define RECIPE_CALL_XP3_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, xb3, (int) xl3);
#define RECIPE_CALL_XS0(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, st->xb0, (int) st->xl0);
#define RECIPE_CALL_XS1(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, st->xb1, (int) st->xl1);
#define RECIPE_CALL_XS2(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, st->xb2, (int) st->xl2);
#define RECIPE_CALL_XS3(U,W,PU,PB,SU,SB,G,WG)        U (&ctx, st->xb3, (int) st->xl3);
#define RECIPE_CALL_XS0_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, st->xb0, (int) st->xl0);
#define RECIPE_CALL_XS1_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, st->xb1, (int) st->xl1);
#define RECIPE_CALL_XS2_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, st->xb2, (int) st->xl2);
#define RECIPE_CALL_XS3_16(U,W,PU,PB,SU,SB,G,WG)     W (&ctx, st->xb3, (int) st->xl3);

#define RECIPE_PART3(TOK,F,X)  RECIPE_CALL_##TOK (RECIPE_UPD_##F (X), RECIPE_UPDW_##F (X), RECIPE_UPDP_##F (X), RECIPE_PBUF_##F, RECIPE_UPDS_##F (X), RECIPE_SBUF_##F, RECIPE_UPDG_##F, RECIPE_UPDWG_##F)
#define RECIPE_PART2(TOK,F,X)  RECIPE_PART3 (TOK, F, X)
#define RECIPE_PART(K,I,F,X)   RECIPE_PART2 (RECIPE_S##K##_P##I, F, X)

#define RECIPE_FEED(K,F,X)  \
  RECIPE_PART (K, 0, F, X)  \
  RECIPE_PART (K, 1, F, X)  \
  RECIPE_PART (K, 2, F, X)  \
  RECIPE_PART (K, 3, F, X)  \
  RECIPE_PART (K, 4, F, X)  \
  RECIPE_PART (K, 5, F, X)  \
  RECIPE_PART (K, 6, F, X)  \
  RECIPE_PART (K, 7, F, X)

// Q slots contain leading parts independent of the candidate, fed once per salt by recipe_prep ().
// P slots contain the remaining parts.

#define RECIPE_QART(K,I,F,X) RECIPE_PART2 (RECIPE_S##K##_Q##I, F, X)

#define RECIPE_FEEDQ(K,F,X) \
  RECIPE_QART (K, 0, F, X)  \
  RECIPE_QART (K, 1, F, X)  \
  RECIPE_QART (K, 2, F, X)  \
  RECIPE_QART (K, 3, F, X)  \
  RECIPE_QART (K, 4, F, X)  \
  RECIPE_QART (K, 5, F, X)  \
  RECIPE_QART (K, 6, F, X)  \
  RECIPE_QART (K, 7, F, X)

// Hash functions for each family. X is _vector for vector evaluation and empty for scalar
// evaluation. HS is empty for vector helpers and _S for scalar helpers.
//
// Scalar UTF-16LE updates decode UTF-8 with the same hc_enc code as the UTF-16 hash modes. Invalid
// UTF-8 leaves the context unusable, preventing a match. Vector updates insert a zero byte after
// each byte, which is correct for ASCII. Vector updates receive only ASCII from recipe_eval ().

#define RECIPE_LEN_md4    16
#define RECIPE_LEN_md5    16
#define RECIPE_LEN_sha1   20
#define RECIPE_LEN_sha224 28
#define RECIPE_LEN_sha256 32
#define RECIPE_LEN_sha384 48
#define RECIPE_LEN_sha512 64

#define RECIPE_LEN_rmd160     20
#define RECIPE_LEN_blake2b512 64
#define RECIPE_LEN_blake2b256 32
#define RECIPE_LEN_blake2s256 32
#define RECIPE_LEN_sm3        32

#define RECIPE_BLOCK_md4    64
#define RECIPE_BLOCK_md5    64
#define RECIPE_BLOCK_sha1   64
#define RECIPE_BLOCK_sha224 64
#define RECIPE_BLOCK_sha256 64
#define RECIPE_BLOCK_sha384 128
#define RECIPE_BLOCK_sha512 128

#define RECIPE_BLOCK_rmd160     64
#define RECIPE_BLOCK_blake2b512 128
#define RECIPE_BLOCK_blake2b256 128
#define RECIPE_BLOCK_blake2s256 64
#define RECIPE_BLOCK_sm3        64

#define RECIPE_UPD_md4(X)    md4_update##X
#define RECIPE_UPD_md5(X)    md5_update##X
#define RECIPE_UPD_sha1(X)   sha1_update##X##_swap
#define RECIPE_UPD_sha224(X) sha224_update##X##_swap
#define RECIPE_UPD_sha256(X) sha256_update##X##_swap
#define RECIPE_UPD_sha384(X) sha384_update##X##_swap
#define RECIPE_UPD_sha512(X) sha512_update##X##_swap

#define RECIPE_UPD_rmd160(X)     ripemd160_update##X
#define RECIPE_UPD_blake2b512(X) blake2b_update##X
#define RECIPE_UPD_blake2b256(X) blake2b_update##X
#define RECIPE_UPD_blake2s256(X) blake2s_update##X
#define RECIPE_UPD_sm3(X)        sm3_update##X##_swap

#define RECIPE_UPDW_md4(X)    md4_update##X##_utf16le
#define RECIPE_UPDW_md5(X)    md5_update##X##_utf16le
#define RECIPE_UPDW_sha1(X)   sha1_update##X##_utf16le_swap
#define RECIPE_UPDW_sha224(X) sha224_update##X##_utf16le_swap
#define RECIPE_UPDW_sha256(X) sha256_update##X##_utf16le_swap
#define RECIPE_UPDW_sha384(X) sha384_update##X##_utf16le_swap
#define RECIPE_UPDW_sha512(X) sha512_update##X##_utf16le_swap

// BLAKE2 has no UTF-16 update, so the module excludes parts that require one.

#define RECIPE_UPDW_rmd160(X)     ripemd160_update##X##_utf16le
#define RECIPE_UPDW_blake2b512(X) recipe_no_utf16_blake2
#define RECIPE_UPDW_blake2b256(X) recipe_no_utf16_blake2
#define RECIPE_UPDW_blake2s256(X) recipe_no_utf16_blake2
#define RECIPE_UPDW_sm3(X)        sm3_update##X##_utf16le_swap

// The plain and the UTF-16LE update from global memory, for the right word of the combinator
// kernel. Only the scalar flavor has them, and RECIPE_TAIL builds only that flavor.

#define RECIPE_UPDG_md4        md4_update_global
#define RECIPE_UPDG_md5        md5_update_global
#define RECIPE_UPDG_sha1       sha1_update_global_swap
#define RECIPE_UPDG_sha224     sha224_update_global_swap
#define RECIPE_UPDG_sha256     sha256_update_global_swap
#define RECIPE_UPDG_sha384     sha384_update_global_swap
#define RECIPE_UPDG_sha512     sha512_update_global_swap
#define RECIPE_UPDG_rmd160     ripemd160_update_global
#define RECIPE_UPDG_blake2b512 blake2b_update_global
#define RECIPE_UPDG_blake2b256 blake2b_update_global
#define RECIPE_UPDG_blake2s256 blake2s_update_global
#define RECIPE_UPDG_sm3        sm3_update_global_swap

#define RECIPE_UPDWG_md4        md4_update_global_utf16le
#define RECIPE_UPDWG_md5        md5_update_global_utf16le
#define RECIPE_UPDWG_sha1       sha1_update_global_utf16le_swap
#define RECIPE_UPDWG_sha224     sha224_update_global_utf16le_swap
#define RECIPE_UPDWG_sha256     sha256_update_global_utf16le_swap
#define RECIPE_UPDWG_sha384     sha384_update_global_utf16le_swap
#define RECIPE_UPDWG_sha512     sha512_update_global_utf16le_swap
#define RECIPE_UPDWG_rmd160     ripemd160_update_global_utf16le
#define RECIPE_UPDWG_blake2b512 recipe_no_utf16_blake2
#define RECIPE_UPDWG_blake2b256 recipe_no_utf16_blake2
#define RECIPE_UPDWG_blake2s256 recipe_no_utf16_blake2
#define RECIPE_UPDWG_sm3        sm3_update_global_utf16le_swap

// Big endian families use converted copies of pass and salt with plain updates when available,
// avoiding repeated byte swaps during updates. The recipe_prep () function stores a converted salt
// copy when the module sets RECIPE_BE_SALT. Password copies require both RECIPE_BE_PASS from the
// module and RECIPE_PASS_COPY from the kernel. Only the mask kernel keeps a password copy, because
// only its first word changes per candidate. It swaps that word instead of the entire password.

#if defined RECIPE_BE_PASS && defined RECIPE_PASS_COPY
#define RECIPE_PB_BE    wb
#define RECIPE_PU_BE(N) N
#define RECIPE_WB       wb
#else
#define RECIPE_PB_BE    w
#define RECIPE_PU_BE(N) N##_swap
#define RECIPE_WB       w
#endif

#ifdef RECIPE_BE_SALT
#define RECIPE_SB_BE    sb
#define RECIPE_SU_BE(N) N
#else
#define RECIPE_SB_BE    s
#define RECIPE_SU_BE(N) N##_swap
#endif

#define RECIPE_UPDP_md4(X)    md4_update##X
#define RECIPE_UPDP_md5(X)    md5_update##X
#define RECIPE_UPDP_sha1(X)   RECIPE_PU_BE (sha1_update##X)
#define RECIPE_UPDP_sha224(X) RECIPE_PU_BE (sha224_update##X)
#define RECIPE_UPDP_sha256(X) RECIPE_PU_BE (sha256_update##X)
#define RECIPE_UPDP_sha384(X) RECIPE_PU_BE (sha384_update##X)
#define RECIPE_UPDP_sha512(X) RECIPE_PU_BE (sha512_update##X)

#define RECIPE_UPDP_rmd160(X)     ripemd160_update##X
#define RECIPE_UPDP_blake2b512(X) blake2b_update##X
#define RECIPE_UPDP_blake2b256(X) blake2b_update##X
#define RECIPE_UPDP_blake2s256(X) blake2s_update##X
#define RECIPE_UPDP_sm3(X)        RECIPE_PU_BE (sm3_update##X)

#define RECIPE_PBUF_md4    w
#define RECIPE_PBUF_md5    w
#define RECIPE_PBUF_sha1   RECIPE_PB_BE
#define RECIPE_PBUF_sha224 RECIPE_PB_BE
#define RECIPE_PBUF_sha256 RECIPE_PB_BE
#define RECIPE_PBUF_sha384 RECIPE_PB_BE
#define RECIPE_PBUF_sha512 RECIPE_PB_BE

#define RECIPE_PBUF_rmd160     w
#define RECIPE_PBUF_blake2b512 w
#define RECIPE_PBUF_blake2b256 w
#define RECIPE_PBUF_blake2s256 w
#define RECIPE_PBUF_sm3        RECIPE_PB_BE

#define RECIPE_UPDS_md4(X)    md4_update##X
#define RECIPE_UPDS_md5(X)    md5_update##X
#define RECIPE_UPDS_sha1(X)   RECIPE_SU_BE (sha1_update##X)
#define RECIPE_UPDS_sha224(X) RECIPE_SU_BE (sha224_update##X)
#define RECIPE_UPDS_sha256(X) RECIPE_SU_BE (sha256_update##X)
#define RECIPE_UPDS_sha384(X) RECIPE_SU_BE (sha384_update##X)
#define RECIPE_UPDS_sha512(X) RECIPE_SU_BE (sha512_update##X)

#define RECIPE_UPDS_rmd160(X)     ripemd160_update##X
#define RECIPE_UPDS_blake2b512(X) blake2b_update##X
#define RECIPE_UPDS_blake2b256(X) blake2b_update##X
#define RECIPE_UPDS_blake2s256(X) blake2s_update##X
#define RECIPE_UPDS_sm3(X)        RECIPE_SU_BE (sm3_update##X)

#define RECIPE_SBUF_md4    s
#define RECIPE_SBUF_md5    s
#define RECIPE_SBUF_sha1   RECIPE_SB_BE
#define RECIPE_SBUF_sha224 RECIPE_SB_BE
#define RECIPE_SBUF_sha256 RECIPE_SB_BE
#define RECIPE_SBUF_sha384 RECIPE_SB_BE
#define RECIPE_SBUF_sha512 RECIPE_SB_BE

#define RECIPE_SBUF_rmd160     s
#define RECIPE_SBUF_blake2b512 s
#define RECIPE_SBUF_blake2b256 s
#define RECIPE_SBUF_blake2s256 s
#define RECIPE_SBUF_sm3        RECIPE_SB_BE

// Contexts and initialization statements for each family. Hash macros accept the statement as INIT,
// allowing a step to start from a context saved during preparation.

#define RECIPE_CTX_md4(X)         md4_ctx##X##_t
#define RECIPE_CTX_md5(X)         md5_ctx##X##_t
#define RECIPE_CTX_sha1(X)        sha1_ctx##X##_t
#define RECIPE_CTX_sha224(X)      sha224_ctx##X##_t
#define RECIPE_CTX_sha256(X)      sha256_ctx##X##_t
#define RECIPE_CTX_sha384(X)      sha384_ctx##X##_t
#define RECIPE_CTX_sha512(X)      sha512_ctx##X##_t
#define RECIPE_CTX_rmd160(X)      ripemd160_ctx##X##_t
#define RECIPE_CTX_blake2b512(X)  blake2b_ctx##X##_t
#define RECIPE_CTX_blake2b256(X)  blake2b_ctx##X##_t
#define RECIPE_CTX_blake2s256(X)  blake2s_ctx##X##_t
#define RECIPE_CTX_sm3(X)         sm3_ctx##X##_t

#define RECIPE_INIT_md4(X)        md4_init##X (&ctx);
#define RECIPE_INIT_md5(X)        md5_init##X (&ctx);
#define RECIPE_INIT_sha1(X)       sha1_init##X (&ctx);
#define RECIPE_INIT_sha224(X)     sha224_init##X (&ctx);
#define RECIPE_INIT_sha256(X)     sha256_init##X (&ctx);
#define RECIPE_INIT_sha384(X)     sha384_init##X (&ctx);
#define RECIPE_INIT_sha512(X)     sha512_init##X (&ctx);
#define RECIPE_INIT_rmd160(X)     ripemd160_init##X (&ctx);
#define RECIPE_INIT_blake2b512(X) blake2b_init##X (&ctx);
#define RECIPE_INIT_blake2b256(X) blake2b_256_init##X (&ctx);
#define RECIPE_INIT_blake2s256(X) blake2s_init##X (&ctx);
#define RECIPE_INIT_sm3(X)        sm3_init##X (&ctx);

#define RECIPE_HASH_md4(X,HS,INIT,FEED)                         \
{                                                               \
  md4_ctx##X##_t ctx;                                           \
                                                                \
  INIT                                                          \
                                                                \
  FEED                                                          \
                                                                \
  md4_final##X (&ctx);                                          \
                                                                \
  for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];                \
}

#define RECIPE_HASH_md5(X,HS,INIT,FEED)                         \
{                                                               \
  md5_ctx##X##_t ctx;                                           \
                                                                \
  INIT                                                          \
                                                                \
  FEED                                                          \
                                                                \
  md5_final##X (&ctx);                                          \
                                                                \
  for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];                \
}

#define RECIPE_HASH_sha1(X,HS,INIT,FEED)                         \
{                                                                \
  sha1_ctx##X##_t ctx;                                           \
                                                                 \
  INIT                                                           \
                                                                 \
  FEED                                                           \
                                                                 \
  sha1_final##X (&ctx);                                          \
                                                                 \
  for (u32 i = 0; i < 5; i++) raw[i] = hc_swap32##HS (ctx.h[i]); \
}

#define RECIPE_HASH_sha224(X,HS,INIT,FEED)                       \
{                                                                \
  sha224_ctx##X##_t ctx;                                         \
                                                                 \
  INIT                                                           \
                                                                 \
  FEED                                                           \
                                                                 \
  sha224_final##X (&ctx);                                        \
                                                                 \
  for (u32 i = 0; i < 7; i++) raw[i] = hc_swap32##HS (ctx.h[i]); \
}

#define RECIPE_HASH_sha256(X,HS,INIT,FEED)                       \
{                                                                \
  sha256_ctx##X##_t ctx;                                         \
                                                                 \
  INIT                                                           \
                                                                 \
  FEED                                                           \
                                                                 \
  sha256_final##X (&ctx);                                        \
                                                                 \
  for (u32 i = 0; i < 8; i++) raw[i] = hc_swap32##HS (ctx.h[i]); \
}

#define RECIPE_HASH_sha384(X,HS,INIT,FEED)                            \
{                                                                     \
  sha384_ctx##X##_t ctx;                                              \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  sha384_final##X (&ctx);                                             \
                                                                      \
  for (u32 i = 0; i < 6; i++)                                         \
  {                                                                   \
    raw[(i * 2) + 0] = hc_swap32##HS (h32_from_64##HS (ctx.h[i]));    \
    raw[(i * 2) + 1] = hc_swap32##HS (l32_from_64##HS (ctx.h[i]));    \
  }                                                                   \
}

#define RECIPE_HASH_sha512(X,HS,INIT,FEED)                            \
{                                                                     \
  sha512_ctx##X##_t ctx;                                              \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  sha512_final##X (&ctx);                                             \
                                                                      \
  for (u32 i = 0; i < 8; i++)                                         \
  {                                                                   \
    raw[(i * 2) + 0] = hc_swap32##HS (h32_from_64##HS (ctx.h[i]));    \
    raw[(i * 2) + 1] = hc_swap32##HS (l32_from_64##HS (ctx.h[i]));    \
  }                                                                   \
}

#define RECIPE_HASH_rmd160(X,HS,INIT,FEED)                      \
{                                                               \
  ripemd160_ctx##X##_t ctx;                                     \
                                                                \
  INIT                                                          \
                                                                \
  FEED                                                          \
                                                                \
  ripemd160_final##X (&ctx);                                    \
                                                                \
  for (u32 i = 0; i < 5; i++) raw[i] = ctx.h[i];                \
}

// BLAKE2b stores little endian 64-bit state words, each as its low word followed by its high word.
// BLAKE2b-256 uses the same function with its own parameter block and a 32-byte digest.

#define RECIPE_HASH_blake2b512(X,HS,INIT,FEED)                        \
{                                                                     \
  blake2b_ctx##X##_t ctx;                                             \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  blake2b_final##X (&ctx);                                            \
                                                                      \
  for (u32 i = 0; i < 8; i++)                                         \
  {                                                                   \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[i]);                    \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[i]);                    \
  }                                                                   \
}

#define RECIPE_HASH_blake2b256(X,HS,INIT,FEED)                        \
{                                                                     \
  blake2b_ctx##X##_t ctx;                                             \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  blake2b_final##X (&ctx);                                            \
                                                                      \
  for (u32 i = 0; i < 4; i++)                                         \
  {                                                                   \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[i]);                    \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[i]);                    \
  }                                                                   \
}

#define RECIPE_HASH_blake2s256(X,HS,INIT,FEED)                  \
{                                                               \
  blake2s_ctx##X##_t ctx;                                       \
                                                                \
  INIT                                                          \
                                                                \
  FEED                                                          \
                                                                \
  blake2s_final##X (&ctx);                                      \
                                                                \
  for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];                \
}

#define RECIPE_HASH_sm3(X,HS,INIT,FEED)                          \
{                                                                \
  sm3_ctx##X##_t ctx;                                            \
                                                                 \
  INIT                                                           \
                                                                 \
  FEED                                                           \
                                                                 \
  sm3_final##X (&ctx);                                           \
                                                                 \
  for (u32 i = 0; i < 8; i++) raw[i] = hc_swap32##HS (ctx.h[i]); \
}

// A step hashes its parts. For f^N, it hashes its output N - 1 more times in the format set by the
// output suffix. The last round is formatted and sliced for the caller, except in the final step,
// whose result is read only from raw. With N = 1, the compiler removes the unused loop. INIT starts the first round from scratch or
// from a prefix context saved during preparation.

#define RECIPE_STEP_HASH(F,K,X,HS,T,INIT)                                                                        \
{                                                                                                                \
  RECIPE_HASH_##F (X, HS, INIT, RECIPE_FEED (K, F, X))                                                           \
                                                                                                                 \
  for (u32 j = 1; j < RECIPE_S##K##_ITER; j++)                                                                   \
  {                                                                                                              \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_CFMT, K, RECIPE_LEN_##F)                                                 \
                                                                                                                 \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_UPD_##F (X) (&ctx, outs + (K * 32), (int) out_lens[K]);) \
  }                                                                                                              \
                                                                                                                 \
  if ((K) < (RECIPE_STEPS - 1))                                                                                  \
  {                                                                                                              \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                  \
                                                                                                                 \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                       \
  }                                                                                                              \
}

// An HMAC key is a single part. Its token selects the buffer and length.

#define RECIPE_KBUF_PASS  w
#define RECIPE_KBUF_SALT  s
#define RECIPE_KBUF_LIT0  (lits +  0)
#define RECIPE_KBUF_LIT1  (lits +  4)
#define RECIPE_KBUF_LIT2  (lits +  8)
#define RECIPE_KBUF_LIT3  (lits + 12)
#define RECIPE_KBUF_STEP0 (outs + (0 * 32))
#define RECIPE_KBUF_STEP1 (outs + (1 * 32))
#define RECIPE_KBUF_STEP2 (outs + (2 * 32))
#define RECIPE_KBUF_STEP3 (outs + (3 * 32))
#define RECIPE_KBUF_STEP4 (outs + (4 * 32))
#define RECIPE_KBUF_STEP5 (outs + (5 * 32))
#define RECIPE_KBUF_STEP6 (outs + (6 * 32))
#define RECIPE_KBUF_STEP7 (outs + (7 * 32))
#define RECIPE_KBUF_PSTEP0 (pouts + (0 * 32))
#define RECIPE_KBUF_PSTEP1 (pouts + (1 * 32))
#define RECIPE_KBUF_PSTEP2 (pouts + (2 * 32))
#define RECIPE_KBUF_PSTEP3 (pouts + (3 * 32))
#define RECIPE_KBUF_PSTEP4 (pouts + (4 * 32))
#define RECIPE_KBUF_PSTEP5 (pouts + (5 * 32))
#define RECIPE_KBUF_PSTEP6 (pouts + (6 * 32))
#define RECIPE_KBUF_PSTEP7 (pouts + (7 * 32))
#define RECIPE_KBUF_XP0    xb0
#define RECIPE_KBUF_XP1    xb1
#define RECIPE_KBUF_XP2    xb2
#define RECIPE_KBUF_XP3    xb3
#define RECIPE_KBUF_XS0    (st->xb0)
#define RECIPE_KBUF_XS1    (st->xb1)
#define RECIPE_KBUF_XS2    (st->xb2)
#define RECIPE_KBUF_XS3    (st->xb3)

#define RECIPE_KLEN_PASS  pw_len
#define RECIPE_KLEN_SALT  salt_len
#define RECIPE_KLEN_LIT0  RECIPE_L0_LEN
#define RECIPE_KLEN_LIT1  RECIPE_L1_LEN
#define RECIPE_KLEN_LIT2  RECIPE_L2_LEN
#define RECIPE_KLEN_LIT3  RECIPE_L3_LEN
#define RECIPE_KLEN_STEP0 out_lens[0]
#define RECIPE_KLEN_STEP1 out_lens[1]
#define RECIPE_KLEN_STEP2 out_lens[2]
#define RECIPE_KLEN_STEP3 out_lens[3]
#define RECIPE_KLEN_STEP4 out_lens[4]
#define RECIPE_KLEN_STEP5 out_lens[5]
#define RECIPE_KLEN_STEP6 out_lens[6]
#define RECIPE_KLEN_STEP7 out_lens[7]
#define RECIPE_KLEN_PSTEP0 pout_lens[0]
#define RECIPE_KLEN_PSTEP1 pout_lens[1]
#define RECIPE_KLEN_PSTEP2 pout_lens[2]
#define RECIPE_KLEN_PSTEP3 pout_lens[3]
#define RECIPE_KLEN_PSTEP4 pout_lens[4]
#define RECIPE_KLEN_PSTEP5 pout_lens[5]
#define RECIPE_KLEN_PSTEP6 pout_lens[6]
#define RECIPE_KLEN_PSTEP7 pout_lens[7]
#define RECIPE_KLEN_XP0    xl0
#define RECIPE_KLEN_XP1    xl1
#define RECIPE_KLEN_XP2    xl2
#define RECIPE_KLEN_XP3    xl3
#define RECIPE_KLEN_XS0    (st->xl0)
#define RECIPE_KLEN_XS1    (st->xl1)
#define RECIPE_KLEN_XS2    (st->xl2)
#define RECIPE_KLEN_XS3    (st->xl3)

#define RECIPE_KBUF2(X) RECIPE_KBUF_##X
#define RECIPE_KBUF(X)  RECIPE_KBUF2 (X)
#define RECIPE_KLEN2(X) RECIPE_KLEN_##X
#define RECIPE_KLEN(X)  RECIPE_KLEN2 (X)

// XOR the HMAC key block with the pad, then feed it as one block of register words through the
// family's block update, as the hash includes' HMAC helpers do. KS converts little endian key
// words to the order required by that block update.

#define RECIPE_KS_md4(HS,V)        (V)
#define RECIPE_KS_md5(HS,V)        (V)
#define RECIPE_KS_rmd160(HS,V)     (V)
#define RECIPE_KS_blake2b512(HS,V) (V)
#define RECIPE_KS_blake2b256(HS,V) (V)
#define RECIPE_KS_blake2s256(HS,V) (V)
#define RECIPE_KS_sha1(HS,V)       hc_swap32##HS (V)
#define RECIPE_KS_sha224(HS,V)     hc_swap32##HS (V)
#define RECIPE_KS_sha256(HS,V)     hc_swap32##HS (V)
#define RECIPE_KS_sha384(HS,V)     hc_swap32##HS (V)
#define RECIPE_KS_sha512(HS,V)     hc_swap32##HS (V)
#define RECIPE_KS_sm3(HS,V)        hc_swap32##HS (V)

#define RECIPE_UB_md4(X)        md4_update##X##_64
#define RECIPE_UB_md5(X)        md5_update##X##_64
#define RECIPE_UB_sha1(X)       sha1_update##X##_64
#define RECIPE_UB_sha224(X)     sha224_update##X##_64
#define RECIPE_UB_sha256(X)     sha256_update##X##_64
#define RECIPE_UB_sha384(X)     sha384_update##X##_128
#define RECIPE_UB_sha512(X)     sha512_update##X##_128
#define RECIPE_UB_rmd160(X)     ripemd160_update##X##_64
#define RECIPE_UB_blake2b512(X) blake2b_update##X##_128
#define RECIPE_UB_blake2b256(X) blake2b_update##X##_128
#define RECIPE_UB_blake2s256(X) blake2s_update##X##_64
#define RECIPE_UB_sm3(X)        sm3_update##X##_64

#define RECIPE_PAD64(F,X,HS,T,XOR)                                                      \
{                                                                                       \
  T p0[4];                                                                              \
  T p1[4];                                                                              \
  T p2[4];                                                                              \
  T p3[4];                                                                              \
                                                                                        \
  for (u32 i = 0; i < 4; i++)                                                           \
  {                                                                                     \
    p0[i] = RECIPE_KS_##F (HS, kb[ 0 + i] ^ (XOR));                                     \
    p1[i] = RECIPE_KS_##F (HS, kb[ 4 + i] ^ (XOR));                                     \
    p2[i] = RECIPE_KS_##F (HS, kb[ 8 + i] ^ (XOR));                                     \
    p3[i] = RECIPE_KS_##F (HS, kb[12 + i] ^ (XOR));                                     \
  }                                                                                     \
                                                                                        \
  RECIPE_UB_##F (X) (&ctx, p0, p1, p2, p3, 64);                                         \
}

#define RECIPE_PAD128(F,X,HS,T,XOR)                                                     \
{                                                                                       \
  T p0[4];                                                                              \
  T p1[4];                                                                              \
  T p2[4];                                                                              \
  T p3[4];                                                                              \
  T p4[4];                                                                              \
  T p5[4];                                                                              \
  T p6[4];                                                                              \
  T p7[4];                                                                              \
                                                                                        \
  for (u32 i = 0; i < 4; i++)                                                           \
  {                                                                                     \
    p0[i] = RECIPE_KS_##F (HS, kb[ 0 + i] ^ (XOR));                                     \
    p1[i] = RECIPE_KS_##F (HS, kb[ 4 + i] ^ (XOR));                                     \
    p2[i] = RECIPE_KS_##F (HS, kb[ 8 + i] ^ (XOR));                                     \
    p3[i] = RECIPE_KS_##F (HS, kb[12 + i] ^ (XOR));                                     \
    p4[i] = RECIPE_KS_##F (HS, kb[16 + i] ^ (XOR));                                     \
    p5[i] = RECIPE_KS_##F (HS, kb[20 + i] ^ (XOR));                                     \
    p6[i] = RECIPE_KS_##F (HS, kb[24 + i] ^ (XOR));                                     \
    p7[i] = RECIPE_KS_##F (HS, kb[28 + i] ^ (XOR));                                     \
  }                                                                                     \
                                                                                        \
  RECIPE_UB_##F (X) (&ctx, p0, p1, p2, p3, p4, p5, p6, p7, 128);                        \
}

// Feed the LEN-byte inner digest in raw to the outer hash as one block of register words.

#define RECIPE_RAW64(F,X,HS,T,LEN)                                                      \
{                                                                                       \
  T p0[4];                                                                              \
  T p1[4];                                                                              \
  T p2[4];                                                                              \
  T p3[4];                                                                              \
                                                                                        \
  for (u32 i = 0; i < 4; i++)                                                           \
  {                                                                                     \
    p0[i] = (( 0 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 0 + i]) : 0;             \
    p1[i] = (( 4 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 4 + i]) : 0;             \
    p2[i] = (( 8 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 8 + i]) : 0;             \
    p3[i] = (( 12 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[12 + i]) : 0;            \
  }                                                                                     \
                                                                                        \
  RECIPE_UB_##F (X) (&ctx, p0, p1, p2, p3, LEN);                                        \
}

#define RECIPE_RAW128(F,X,HS,T,LEN)                                                     \
{                                                                                       \
  T p0[4];                                                                              \
  T p1[4];                                                                              \
  T p2[4];                                                                              \
  T p3[4];                                                                              \
  T p4[4];                                                                              \
  T p5[4];                                                                              \
  T p6[4];                                                                              \
  T p7[4];                                                                              \
                                                                                        \
  for (u32 i = 0; i < 4; i++)                                                           \
  {                                                                                     \
    p0[i] = (( 0 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 0 + i]) : 0;             \
    p1[i] = (( 4 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 4 + i]) : 0;             \
    p2[i] = (( 8 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[ 8 + i]) : 0;             \
    p3[i] = (( 12 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, raw[12 + i]) : 0;            \
    p4[i] = 0;                                                                          \
    p5[i] = 0;                                                                          \
    p6[i] = 0;                                                                          \
    p7[i] = 0;                                                                          \
  }                                                                                     \
                                                                                        \
  RECIPE_UB_##F (X) (&ctx, p0, p1, p2, p3, p4, p5, p6, p7, LEN);                        \
}

#define RECIPE_RAW_md4        RECIPE_RAW64
#define RECIPE_RAW_md5        RECIPE_RAW64
#define RECIPE_RAW_sha1       RECIPE_RAW64
#define RECIPE_RAW_sha224     RECIPE_RAW64
#define RECIPE_RAW_sha256     RECIPE_RAW64
#define RECIPE_RAW_sha384     RECIPE_RAW128
#define RECIPE_RAW_sha512     RECIPE_RAW128
#define RECIPE_RAW_rmd160     RECIPE_RAW64
#define RECIPE_RAW_blake2b512 RECIPE_RAW128
#define RECIPE_RAW_blake2b256 RECIPE_RAW128
#define RECIPE_RAW_blake2s256 RECIPE_RAW64
#define RECIPE_RAW_sm3        RECIPE_RAW64

#define RECIPE_PAD_md4        RECIPE_PAD64
#define RECIPE_PAD_md5        RECIPE_PAD64
#define RECIPE_PAD_sha1       RECIPE_PAD64
#define RECIPE_PAD_sha224     RECIPE_PAD64
#define RECIPE_PAD_sha256     RECIPE_PAD64
#define RECIPE_PAD_sha384     RECIPE_PAD128
#define RECIPE_PAD_sha512     RECIPE_PAD128
#define RECIPE_PAD_rmd160     RECIPE_PAD64
#define RECIPE_PAD_blake2b512 RECIPE_PAD128
#define RECIPE_PAD_blake2b256 RECIPE_PAD128
#define RECIPE_PAD_blake2s256 RECIPE_PAD64
#define RECIPE_PAD_sm3        RECIPE_PAD64

// Compute HMAC from two plain hashes, feeding parts as in a normal hash step. Hash keys longer than
// the block size first, then pad the key to the block size. The result is
// H (key ^ opad . H (key ^ ipad . parts)). The outer hash reads the digest from raw as one block.

// Store HMAC step K's key block in kb. Hash the key first if it exceeds the block size, then pad
// it with zero bytes to the block size.

#define RECIPE_KEYBLOCK(F,K,X,HS,T)                                                                                                                                              \
  T kb[RECIPE_BLOCK_##F / 4];                                                                                                                                                    \
                                                                                                                                                                                 \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) kb[i] = 0;                                                                                                                    \
                                                                                                                                                                                 \
  if (RECIPE_KLEN (RECIPE_S##K##_KEY) > RECIPE_BLOCK_##F)                                                                                                                        \
  {                                                                                                                                                                              \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PART2 (RECIPE_S##K##_KEY, F, X))                                                                                         \
                                                                                                                                                                                 \
    for (u32 i = 0; i < (RECIPE_LEN_##F / 4); i++) kb[i] = raw[i];                                                                                                               \
  }                                                                                                                                                                              \
  else                                                                                                                                                                           \
  {                                                                                                                                                                              \
    for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) kb[i] = hc_bounded_word_le##HS (RECIPE_KBUF (RECIPE_S##K##_KEY), i, (int) RECIPE_KLEN (RECIPE_S##K##_KEY) - (int) (i * 4)); \
  }

#define RECIPE_STEP_HMAC(F,K,X,HS,T,INIT)                                                                                                  \
{                                                                                                                                          \
  RECIPE_KEYBLOCK (F, K, X, HS, T)                                                                                                         \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PAD_##F (F, X, HS, T, 0x36363636) RECIPE_FEED (K, F, X))                             \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PAD_##F (F, X, HS, T, 0x5c5c5c5c) RECIPE_RAW_##F (F, X, HS, T, RECIPE_LEN_##F))      \
                                                                                                                                           \
  if ((K) < (RECIPE_STEPS - 1))                                                                                                            \
  {                                                                                                                                        \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                                            \
                                                                                                                                           \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                                                 \
  }                                                                                                                                        \
}

// An HMAC with a key independent of the candidate starts from the two saved pad contexts. The inner
// context also includes leading parts independent of the candidate.

#define RECIPE_STEP_HMACS(F,K,X,HS,T)                                                                                                      \
{                                                                                                                                          \
  RECIPE_HASH_##F (X, HS, ctx = st->hi##K;, RECIPE_FEED (K, F, X))                                                                         \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, ctx = st->ho##K;, RECIPE_RAW_##F (F, X, HS, T, RECIPE_LEN_##F))                                                  \
                                                                                                                                           \
  if ((K) < (RECIPE_STEPS - 1))                                                                                                            \
  {                                                                                                                                        \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                                            \
                                                                                                                                           \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                                                 \
  }                                                                                                                                        \
}

// The module assigns a phase according to each step's dependence on the candidate:
//
//   P0  Runs per candidate.
//   P1  Uses only salt and strings. Runs once per salt in recipe_prep ().
//   P2  HMAC with a key independent of the candidate. recipe_prep () feeds both pads, adds leading
//       parts independent of the candidate to the inner context, and saves both contexts.
//   P3  Hash call with leading parts independent of the candidate. recipe_prep () feeds those parts
//       and saves the context.
//
// The compiler does not move this work out of the candidate loop. Native kernels do it manually.
// These phases apply the same preparation to every recipe.

#define RECIPE_EV_P0(D,F,K,X,HS,T) RECIPE_STEP_##D (F, K, X, HS, T, RECIPE_INIT_##F (X))
#define RECIPE_EV_P1(D,F,K,X,HS,T)
#define RECIPE_EV_P2(D,F,K,X,HS,T) RECIPE_STEP_HMACS (F, K, X, HS, T)
#define RECIPE_EV_P3(D,F,K,X,HS,T) RECIPE_STEP_HASH (F, K, X, HS, T, ctx = st->hc##K;)

#define RECIPE_PR_P0(D,F,K,X,HS,T)
#define RECIPE_PR_P1(D,F,K,X,HS,T) RECIPE_STEP_##D (F, K, X, HS, T, RECIPE_INIT_##F (X))
#define RECIPE_PR_P2(D,F,K,X,HS,T)                                                                                \
{                                                                                                                 \
  RECIPE_KEYBLOCK (F, K, X, HS, T)                                                                                \
                                                                                                                  \
  {                                                                                                               \
    RECIPE_CTX_##F (X) ctx;                                                                                       \
                                                                                                                  \
    RECIPE_INIT_##F (X)                                                                                           \
                                                                                                                  \
    RECIPE_PAD_##F (F, X, HS, T, 0x36363636)                                                                      \
                                                                                                                  \
    RECIPE_FEEDQ (K, F, X)                                                                                        \
                                                                                                                  \
    st->hi##K = ctx;                                                                                              \
  }                                                                                                               \
                                                                                                                  \
  {                                                                                                               \
    RECIPE_CTX_##F (X) ctx;                                                                                       \
                                                                                                                  \
    RECIPE_INIT_##F (X)                                                                                           \
                                                                                                                  \
    RECIPE_PAD_##F (F, X, HS, T, 0x5c5c5c5c)                                                                      \
                                                                                                                  \
    st->ho##K = ctx;                                                                                              \
  }                                                                                                               \
}
#define RECIPE_PR_P3(D,F,K,X,HS,T)                                                                                \
{                                                                                                                 \
  RECIPE_CTX_##F (X) ctx;                                                                                         \
                                                                                                                  \
  RECIPE_INIT_##F (X)                                                                                             \
                                                                                                                  \
  RECIPE_FEEDQ (K, F, X)                                                                                          \
                                                                                                                  \
  st->hc##K = ctx;                                                                                                \
}

#define RECIPE_EV3(P,D,F,K,X,HS,T) RECIPE_EV_##P (D, F, K, X, HS, T)
#define RECIPE_EV2(P,D,F,K,X,HS,T) RECIPE_EV3 (P, D, F, K, X, HS, T)
#define RECIPE_EV(K,X,HS,T)        RECIPE_EV2 (RECIPE_S##K##_PH, RECIPE_S##K##_KIND, RECIPE_S##K##_FN, K, X, HS, T)

#define RECIPE_PR3(P,D,F,K,X,HS,T) RECIPE_PR_##P (D, F, K, X, HS, T)
#define RECIPE_PR2(P,D,F,K,X,HS,T) RECIPE_PR3 (P, D, F, K, X, HS, T)
#define RECIPE_PR(K,X,HS,T)        RECIPE_PR2 (RECIPE_S##K##_PH, RECIPE_S##K##_KIND, RECIPE_S##K##_FN, K, X, HS, T)

#if   RECIPE_STEPS == 1
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T)
#elif RECIPE_STEPS == 2
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T)
#elif RECIPE_STEPS == 3
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T)
#elif RECIPE_STEPS == 4
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T)
#elif RECIPE_STEPS == 5
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T)
#elif RECIPE_STEPS == 6
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T) R (5, X, HS, T)
#elif RECIPE_STEPS == 7
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T) R (5, X, HS, T) R (6, X, HS, T)
#else
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T) R (5, X, HS, T) R (6, X, HS, T) R (7, X, HS, T)
#endif

// recipe_prep () leaves the P1 outputs and the P2 and P3 contexts in the state, each in its step's
// hash family. Declare only the fields needed by each step.

#define RECIPE_FIELDS_P0(F,K,X)
#define RECIPE_FIELDS_P1(F,K,X)
#define RECIPE_FIELDS_P2(F,K,X) RECIPE_CTX_##F (X) hi##K; RECIPE_CTX_##F (X) ho##K;
#define RECIPE_FIELDS_P3(F,K,X) RECIPE_CTX_##F (X) hc##K;

#define RECIPE_FIELDS3(P,F,K,X) RECIPE_FIELDS_##P (F, K, X)
#define RECIPE_FIELDS2(P,F,K,X) RECIPE_FIELDS3 (P, F, K, X)
#define RECIPE_FIELDS(K,X)      RECIPE_FIELDS2 (RECIPE_S##K##_PH, RECIPE_S##K##_FN, K, X)

#ifdef RECIPE_HEX_TABLE
#define RECIPE_STATE_HEX LOCAL_AS const u32 *hex;
#else
#define RECIPE_STATE_HEX
#endif

#ifdef RECIPE_BE_SALT
#define RECIPE_STATE_SB(T) T sb[64];
#else
#define RECIPE_STATE_SB(T)
#endif

#define RECIPE_STATE(T,X)          \
  T   outs[RECIPE_STEPS * 32];     \
  u32 out_lens[RECIPE_STEPS];      \
                                   \
  RECIPE_STATE_HEX                 \
  RECIPE_STATE_SB (T)              \
  RECIPE_XFLDS (T)

typedef struct recipe_state_vector
{
  RECIPE_STATE (u32x, _vector)

  #if RECIPE_STEPS > 0
  RECIPE_FIELDS (0, _vector)
  #endif
  #if RECIPE_STEPS > 1
  RECIPE_FIELDS (1, _vector)
  #endif
  #if RECIPE_STEPS > 2
  RECIPE_FIELDS (2, _vector)
  #endif
  #if RECIPE_STEPS > 3
  RECIPE_FIELDS (3, _vector)
  #endif
  #if RECIPE_STEPS > 4
  RECIPE_FIELDS (4, _vector)
  #endif
  #if RECIPE_STEPS > 5
  RECIPE_FIELDS (5, _vector)
  #endif
  #if RECIPE_STEPS > 6
  RECIPE_FIELDS (6, _vector)
  #endif
  #if RECIPE_STEPS > 7
  RECIPE_FIELDS (7, _vector)
  #endif

} recipe_state_vector_t;

#if defined RECIPE_WIDE || defined RECIPE_TAIL

typedef struct recipe_state_scalar
{
  RECIPE_STATE (u32, )

  #if RECIPE_STEPS > 0
  RECIPE_FIELDS (0, )
  #endif
  #if RECIPE_STEPS > 1
  RECIPE_FIELDS (1, )
  #endif
  #if RECIPE_STEPS > 2
  RECIPE_FIELDS (2, )
  #endif
  #if RECIPE_STEPS > 3
  RECIPE_FIELDS (3, )
  #endif
  #if RECIPE_STEPS > 4
  RECIPE_FIELDS (4, )
  #endif
  #if RECIPE_STEPS > 5
  RECIPE_FIELDS (5, )
  #endif
  #if RECIPE_STEPS > 6
  RECIPE_FIELDS (6, )
  #endif
  #if RECIPE_STEPS > 7
  RECIPE_FIELDS (7, )
  #endif

} recipe_state_scalar_t;

#endif

// Write the final digest to r. Mode 4000 compares the first 16 bytes in memory order. With
// RECIPE_ROOT_NATIVE, modes using recipe kernels receive the complete digest in their family's
// native word layout: little endian for MD4, MD5, RIPEMD-160 and BLAKE2, big endian for SHA-1,
// SHA-2 and SM3, and each 64-bit SHA-512 word as its low half followed by its high half. DGST_POS
// selects the same comparison words as in the mode's own kernels.

#define RECIPE_NAT_LE(N,HS)  { for (u32 i = 0; i < (N); i++) r[i] = raw[i]; }
#define RECIPE_NAT_BE(N,HS)  { for (u32 i = 0; i < (N); i++) r[i] = hc_swap32##HS (raw[i]); }
#define RECIPE_NAT_BE64(N,HS)                                   \
{                                                               \
  for (u32 i = 0; i < ((N) / 2); i++)                           \
  {                                                             \
    r[(i * 2) + 0] = hc_swap32##HS (raw[(i * 2) + 1]);          \
    r[(i * 2) + 1] = hc_swap32##HS (raw[(i * 2) + 0]);          \
  }                                                             \
}

#define RECIPE_NAT_md4(HS)        RECIPE_NAT_LE   ( 4, HS)
#define RECIPE_NAT_md5(HS)        RECIPE_NAT_LE   ( 4, HS)
#define RECIPE_NAT_rmd160(HS)     RECIPE_NAT_LE   ( 5, HS)
#define RECIPE_NAT_blake2b512(HS) RECIPE_NAT_LE   (16, HS)
#define RECIPE_NAT_blake2b256(HS) RECIPE_NAT_LE   ( 8, HS)
#define RECIPE_NAT_blake2s256(HS) RECIPE_NAT_LE   ( 8, HS)
#define RECIPE_NAT_sha1(HS)       RECIPE_NAT_BE   ( 5, HS)
#define RECIPE_NAT_sha224(HS)     RECIPE_NAT_BE   ( 7, HS)
#define RECIPE_NAT_sha256(HS)     RECIPE_NAT_BE   ( 8, HS)
#define RECIPE_NAT_sm3(HS)        RECIPE_NAT_BE   ( 8, HS)
#define RECIPE_NAT_sha384(HS)     RECIPE_NAT_BE64 (12, HS)
#define RECIPE_NAT_sha512(HS)     RECIPE_NAT_BE64 (16, HS)

#define RECIPE_NAT3(F,HS) RECIPE_NAT_##F (HS)
#define RECIPE_NAT2(F,HS) RECIPE_NAT3 (F, HS)

#ifdef RECIPE_ROOT_NATIVE
#define RECIPE_ROOT(HS) RECIPE_NAT2 (RECIPE_ROOT_FN, HS)
#else
#define RECIPE_ROOT(HS) RECIPE_NAT_LE (4, HS)
#endif

// Store literals in the evaluation's word type. M builds a vector from a constant and is empty
// for scalar evaluation.

#define RECIPE_LITS(T,M)          \
  T lits[16];                     \
                                  \
  lits[ 0] = M (RECIPE_L0_W0);    \
  lits[ 1] = M (RECIPE_L0_W1);    \
  lits[ 2] = M (RECIPE_L0_W2);    \
  lits[ 3] = M (RECIPE_L0_W3);    \
  lits[ 4] = M (RECIPE_L1_W0);    \
  lits[ 5] = M (RECIPE_L1_W1);    \
  lits[ 6] = M (RECIPE_L1_W2);    \
  lits[ 7] = M (RECIPE_L1_W3);    \
  lits[ 8] = M (RECIPE_L2_W0);    \
  lits[ 9] = M (RECIPE_L2_W1);    \
  lits[10] = M (RECIPE_L2_W2);    \
  lits[11] = M (RECIPE_L2_W3);    \
  lits[12] = M (RECIPE_L3_W0);    \
  lits[13] = M (RECIPE_L3_W1);    \
  lits[14] = M (RECIPE_L3_W2);    \
  lits[15] = M (RECIPE_L3_W3);

// Prepare P1 outputs and P2 and P3 contexts once per salt. Their parts read only the salt, strings
// and other P1 outputs, which are stored in this state.

#ifdef RECIPE_BE_SALT
#define RECIPE_PREP_SB(HS) for (u32 i = 0; i < 64; i++) st->sb[i] = hc_swap32##HS (s[i]);
#define RECIPE_SB_DECL(T) PRIVATE_AS const T *sb = st->sb;
#else
#define RECIPE_PREP_SB(HS)
#define RECIPE_SB_DECL(T)
#endif

#define RECIPE_PREP(X,HS,T,M)                   \
{                                               \
  RECIPE_PREP_SB (HS)                           \
                                                \
  RECIPE_SB_DECL (T)                            \
                                                \
  RECIPE_LITS (T, M)                            \
                                                \
  PRIVATE_AS T   *outs     = st->outs;          \
  PRIVATE_AS u32 *out_lens = st->out_lens;      \
                                                \
  T raw[16];                                    \
                                                \
  RECIPE_XPRS (T, HS)                           \
                                                \
  RECIPE_ALL (RECIPE_PR, X, HS, T)              \
}

// Evaluate P0, P2 and P3 steps for one candidate or VECT_SIZE candidates. Store the result in the
// 16-word r buffer. The pouts array holds the outputs recipe_prep () computed, and outs holds the
// candidate's outputs.

#define RECIPE_EVAL(X,HS,T,M)                                 \
{                                                             \
  RECIPE_LITS (T, M)                                          \
                                                              \
  PRIVATE_AS const T   *pouts     = st->outs;                 \
  PRIVATE_AS const u32 *pout_lens = st->out_lens;             \
                                                              \
  RECIPE_SB_DECL (T)                                          \
                                                              \
  T   outs[RECIPE_STEPS * 32];                                \
  u32 out_lens[RECIPE_STEPS];                                 \
                                                              \
  T raw[16];                                                  \
                                                              \
  RECIPE_XEVS (T, HS)                                         \
                                                              \
  RECIPE_ALL (RECIPE_EV, X, HS, T)                            \
                                                              \
  RECIPE_ROOT (HS)                                            \
}

#ifndef RECIPE_TAIL

DECLSPEC HC_INLINE_ALWAYS void recipe_prep_vector (PRIVATE_AS recipe_state_vector_t *st, PRIVATE_AS const u32x *s, const u32 salt_len)
{
  RECIPE_PREP (_vector, , u32x, make_u32x)
}

DECLSPEC HC_INLINE_ALWAYS void recipe_eval_vector (PRIVATE_AS const recipe_state_vector_t *st, PRIVATE_AS const u32x *w, MAYBE_UNUSED PRIVATE_AS const u32x *wb, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len, PRIVATE_AS u32x *r)
{
  RECIPE_EVAL (_vector, , u32x, make_u32x)
}

#endif

#if defined RECIPE_WIDE || defined RECIPE_TAIL

DECLSPEC HC_INLINE_ALWAYS void recipe_prep_scalar (PRIVATE_AS recipe_state_scalar_t *st, PRIVATE_AS const u32 *s, const u32 salt_len)
{
  RECIPE_PREP ( , _S, u32, )
}

#endif

#ifdef RECIPE_TAIL

DECLSPEC HC_INLINE_ALWAYS void recipe_eval_scalar (PRIVATE_AS const recipe_state_scalar_t *st, PRIVATE_AS const u32 *w, MAYBE_UNUSED PRIVATE_AS const u32 *wb, const u32 pw_len, GLOBAL_AS const u32 *tail, const u32 tail_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  RECIPE_EVAL ( , _S, u32, )
}

#elif defined RECIPE_WIDE

DECLSPEC HC_INLINE_ALWAYS void recipe_eval_scalar (PRIVATE_AS const recipe_state_scalar_t *st, PRIVATE_AS const u32 *w, MAYBE_UNUSED PRIVATE_AS const u32 *wb, const u32 pw_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  RECIPE_EVAL ( , _S, u32, )
}

#endif

// RECIPE_WIDE marks recipes that apply utf16le to pass or salt. UTF-8 decoding can give candidates
// different lengths, which a vector context cannot track. Scalar kernels use scalar evaluation
// with UTF-8 decoding. Vector kernels use vector evaluation when every lane is ASCII, checked as
// in the pure UTF-16 mask kernels. Otherwise, they evaluate each lane through recipe_eval_lanes ().
// Kernels call recipe_prep () once per salt and recipe_eval () per candidate.

#if ((VECT_SIZE == 1) && defined (RECIPE_WIDE)) || defined (RECIPE_TAIL)
#define RECIPE_SCALAR_STATE
#endif

#ifdef RECIPE_SCALAR_STATE
typedef recipe_state_scalar_t recipe_state_t;
#else
typedef recipe_state_vector_t recipe_state_t;
#endif

DECLSPEC HC_INLINE_ALWAYS void recipe_prep (PRIVATE_AS recipe_state_t *st, PRIVATE_AS const u32x *s, const u32 salt_len)
{
  #ifdef RECIPE_SCALAR_STATE
  recipe_prep_scalar (st, s, salt_len);
  #else
  recipe_prep_vector (st, s, salt_len);
  #endif
}

// The wb argument is a big endian password copy. Kernels without one pass w. See RECIPE_PASS_COPY.
// The combinator kernel calls RECIPE_EVAL_TAIL instead, which hands over the right word separately
// under RECIPE_TAIL and otherwise expects it appended to w already.

#ifdef RECIPE_TAIL

DECLSPEC HC_INLINE_ALWAYS void recipe_eval_tail (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const u32 *tail, const u32 tail_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  recipe_eval_scalar (st, w, w, pw_len, tail, tail_len, s, salt_len, r);
}

#define RECIPE_EVAL_TAIL(ST,W,LEN,T,TLEN,S,SLEN,R) recipe_eval_tail (ST, W, LEN, T, TLEN, S, SLEN, R)

#else

DECLSPEC HC_INLINE_ALWAYS void recipe_eval (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const u32x *w, PRIVATE_AS const u32x *wb, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len, PRIVATE_AS u32x *r)
{
  #ifdef RECIPE_SCALAR_STATE
  recipe_eval_scalar (st, w, wb, pw_len, s, salt_len, r);
  #else
  recipe_eval_vector (st, w, wb, pw_len, s, salt_len, r);
  #endif
}

#define RECIPE_EVAL_TAIL(ST,W,LEN,T,TLEN,S,SLEN,R) recipe_eval (ST, W, W, LEN, S, SLEN, R)

#endif

#if (VECT_SIZE > 1) && defined (RECIPE_WIDE)

// Prepare scalar state from lane 0 of the salt, which all lanes share. This path runs only when at
// least one candidate in the vector contains non-ASCII bytes.

DECLSPEC void recipe_eval_lanes (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const u32x *w, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len, PRIVATE_AS u32x *r)
{
  u32 st_salt[64] = { 0 };

  hc_vector_get_lane (st_salt, s, salt_len, 0);

  recipe_state_scalar_t sts;

  #ifdef RECIPE_HEX_TABLE
  sts.hex = st->hex;
  #endif

  recipe_prep_scalar (&sts, st_salt, salt_len);

  for (int lane = 0; lane < VECT_SIZE; lane++)
  {
    u32 t[64] = { 0 };

    hc_vector_get_lane (t, w, pw_len, lane);

    #if defined RECIPE_BE_PASS && defined RECIPE_PASS_COPY
    u32 tb[64];

    for (u32 i = 0; i < 64; i++) tb[i] = hc_swap32_S (t[i]);
    #else
    PRIVATE_AS const u32 *tb = t;
    #endif

    u32 lr[16];

    recipe_eval_scalar (&sts, t, tb, pw_len, st_salt, salt_len, lr);

    hc_vector_set_lane (r, lr, 16, lane);
  }
}

#endif
