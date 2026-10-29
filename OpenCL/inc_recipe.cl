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
#define RECIPE_FMT_B64     3

#ifndef RECIPE_STEPS
#error "mode 4000: no recipe, set --hash-recipe"
#endif

// NVRTC ignores always_inline on a function that is not also declared inline (warning 2473, which
// -w hides), and DECLSPEC carries no inline under CUDA. The recipe functions add HC_INLINE there, so
// that NVRTC does not leave one of them out of line.

#ifdef IS_CUDA
#define RECIPE_INLINE HC_INLINE HC_INLINE_ALWAYS
#else
#define RECIPE_INLINE HC_INLINE_ALWAYS
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

// Each string takes RECIPE_LIT_WORDS words: 4, or 8, 12 or 16 when a string is longer than 16
// bytes. src/recipe.c sets every word of the strings a recipe has, and an unused slot is zero.

#ifndef RECIPE_LIT_WORDS
#define RECIPE_LIT_WORDS 4
#endif

#ifndef RECIPE_L0_LEN
#define RECIPE_L0_LEN 0
#define RECIPE_L0_W0  0
#define RECIPE_L0_W1  0
#define RECIPE_L0_W2  0
#define RECIPE_L0_W3  0
#define RECIPE_L0_W4  0
#define RECIPE_L0_W5  0
#define RECIPE_L0_W6  0
#define RECIPE_L0_W7  0
#define RECIPE_L0_W8  0
#define RECIPE_L0_W9  0
#define RECIPE_L0_W10 0
#define RECIPE_L0_W11 0
#define RECIPE_L0_W12 0
#define RECIPE_L0_W13 0
#define RECIPE_L0_W14 0
#define RECIPE_L0_W15 0
#endif

#ifndef RECIPE_L1_LEN
#define RECIPE_L1_LEN 0
#define RECIPE_L1_W0  0
#define RECIPE_L1_W1  0
#define RECIPE_L1_W2  0
#define RECIPE_L1_W3  0
#define RECIPE_L1_W4  0
#define RECIPE_L1_W5  0
#define RECIPE_L1_W6  0
#define RECIPE_L1_W7  0
#define RECIPE_L1_W8  0
#define RECIPE_L1_W9  0
#define RECIPE_L1_W10 0
#define RECIPE_L1_W11 0
#define RECIPE_L1_W12 0
#define RECIPE_L1_W13 0
#define RECIPE_L1_W14 0
#define RECIPE_L1_W15 0
#endif

#ifndef RECIPE_L2_LEN
#define RECIPE_L2_LEN 0
#define RECIPE_L2_W0  0
#define RECIPE_L2_W1  0
#define RECIPE_L2_W2  0
#define RECIPE_L2_W3  0
#define RECIPE_L2_W4  0
#define RECIPE_L2_W5  0
#define RECIPE_L2_W6  0
#define RECIPE_L2_W7  0
#define RECIPE_L2_W8  0
#define RECIPE_L2_W9  0
#define RECIPE_L2_W10 0
#define RECIPE_L2_W11 0
#define RECIPE_L2_W12 0
#define RECIPE_L2_W13 0
#define RECIPE_L2_W14 0
#define RECIPE_L2_W15 0
#endif

#ifndef RECIPE_L3_LEN
#define RECIPE_L3_LEN 0
#define RECIPE_L3_W0  0
#define RECIPE_L3_W1  0
#define RECIPE_L3_W2  0
#define RECIPE_L3_W3  0
#define RECIPE_L3_W4  0
#define RECIPE_L3_W5  0
#define RECIPE_L3_W6  0
#define RECIPE_L3_W7  0
#define RECIPE_L3_W8  0
#define RECIPE_L3_W9  0
#define RECIPE_L3_W10 0
#define RECIPE_L3_W11 0
#define RECIPE_L3_W12 0
#define RECIPE_L3_W13 0
#define RECIPE_L3_W14 0
#define RECIPE_L3_W15 0
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

// AES steps read the tables of inc_cipher_aes.cl from local memory, as the native kernels do, or
// from constant memory where the device has no real shared memory. Fill them with RECIPE_AES_DECL
// before any work item returns, then bind them to the state with RECIPE_AES_BIND. The fast kernels
// run AES steps, and of the slow kernels only comp does. RECIPE_AES_COPY gives the scalar state of
// recipe_eval_lanes () the same tables.

#ifdef RECIPE_AES

#ifdef REAL_SHM

#define RECIPE_AES_DECL                                                         \
  LOCAL_VK u32 s_te0[256];                                                      \
  LOCAL_VK u32 s_te1[256];                                                      \
  LOCAL_VK u32 s_te2[256];                                                      \
  LOCAL_VK u32 s_te3[256];                                                      \
  LOCAL_VK u32 s_te4[256];                                                      \
  LOCAL_VK u32 s_td0[256];                                                      \
  LOCAL_VK u32 s_td1[256];                                                      \
  LOCAL_VK u32 s_td2[256];                                                      \
  LOCAL_VK u32 s_td3[256];                                                      \
  LOCAL_VK u32 s_td4[256];                                                      \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    s_te0[i] = te0[i];                                                          \
    s_te1[i] = te1[i];                                                          \
    s_te2[i] = te2[i];                                                          \
    s_te3[i] = te3[i];                                                          \
    s_te4[i] = te4[i];                                                          \
    s_td0[i] = td0[i];                                                          \
    s_td1[i] = td1[i];                                                          \
    s_td2[i] = td2[i];                                                          \
    s_td3[i] = td3[i];                                                          \
    s_td4[i] = td4[i];                                                          \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_AES_DECL           \
  CONSTANT_AS u32a *s_te0 = te0;  \
  CONSTANT_AS u32a *s_te1 = te1;  \
  CONSTANT_AS u32a *s_te2 = te2;  \
  CONSTANT_AS u32a *s_te3 = te3;  \
  CONSTANT_AS u32a *s_te4 = te4;  \
  CONSTANT_AS u32a *s_td0 = td0;  \
  CONSTANT_AS u32a *s_td1 = td1;  \
  CONSTANT_AS u32a *s_td2 = td2;  \
  CONSTANT_AS u32a *s_td3 = td3;  \
  CONSTANT_AS u32a *s_td4 = td4;

#endif

#define RECIPE_AES_BIND(S)                                                      \
  (S)->aes_te0 = s_te0; (S)->aes_te1 = s_te1; (S)->aes_te2 = s_te2;            \
  (S)->aes_te3 = s_te3; (S)->aes_te4 = s_te4; (S)->aes_td0 = s_td0;            \
  (S)->aes_td1 = s_td1; (S)->aes_td2 = s_td2; (S)->aes_td3 = s_td3;            \
  (S)->aes_td4 = s_td4;

#define RECIPE_AES_COPY(D,S)                                                    \
  (D).aes_te0 = (S)->aes_te0; (D).aes_te1 = (S)->aes_te1;                      \
  (D).aes_te2 = (S)->aes_te2; (D).aes_te3 = (S)->aes_te3;                      \
  (D).aes_te4 = (S)->aes_te4; (D).aes_td0 = (S)->aes_td0;                      \
  (D).aes_td1 = (S)->aes_td1; (D).aes_td2 = (S)->aes_td2;                      \
  (D).aes_td3 = (S)->aes_td3; (D).aes_td4 = (S)->aes_td4;

#define RECIPE_STATE_AES                                                        \
  SHM_TYPE u32 *aes_te0; SHM_TYPE u32 *aes_te1; SHM_TYPE u32 *aes_te2;         \
  SHM_TYPE u32 *aes_te3; SHM_TYPE u32 *aes_te4; SHM_TYPE u32 *aes_td0;         \
  SHM_TYPE u32 *aes_td1; SHM_TYPE u32 *aes_td2; SHM_TYPE u32 *aes_td3;         \
  SHM_TYPE u32 *aes_td4;

#else

#define RECIPE_AES_DECL
#define RECIPE_AES_BIND(S)
#define RECIPE_AES_COPY(D,S)
#define RECIPE_STATE_AES

#endif

// Whirlpool steps read the 8 tables of inc_hash_whirlpool.cl from local memory, as the native
// kernels do, or from constant memory where the device has no real shared memory. The module sets
// RECIPE_WRL when a step hashes with Whirlpool. RECIPE_WRL_COPY gives the scalar state of
// recipe_eval_lanes () the same tables.

#ifdef RECIPE_WRL

#ifdef REAL_SHM

#define RECIPE_WRL_DECL                                                         \
  LOCAL_VK u64 s_wrl0[256];                                                     \
  LOCAL_VK u64 s_wrl1[256];                                                     \
  LOCAL_VK u64 s_wrl2[256];                                                     \
  LOCAL_VK u64 s_wrl3[256];                                                     \
  LOCAL_VK u64 s_wrl4[256];                                                     \
  LOCAL_VK u64 s_wrl5[256];                                                     \
  LOCAL_VK u64 s_wrl6[256];                                                     \
  LOCAL_VK u64 s_wrl7[256];                                                     \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    s_wrl0[i] = MT0[i];                                                         \
    s_wrl1[i] = MT1[i];                                                         \
    s_wrl2[i] = MT2[i];                                                         \
    s_wrl3[i] = MT3[i];                                                         \
    s_wrl4[i] = MT4[i];                                                         \
    s_wrl5[i] = MT5[i];                                                         \
    s_wrl6[i] = MT6[i];                                                         \
    s_wrl7[i] = MT7[i];                                                         \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_WRL_DECL             \
  CONSTANT_AS u64a *s_wrl0 = MT0;   \
  CONSTANT_AS u64a *s_wrl1 = MT1;   \
  CONSTANT_AS u64a *s_wrl2 = MT2;   \
  CONSTANT_AS u64a *s_wrl3 = MT3;   \
  CONSTANT_AS u64a *s_wrl4 = MT4;   \
  CONSTANT_AS u64a *s_wrl5 = MT5;   \
  CONSTANT_AS u64a *s_wrl6 = MT6;   \
  CONSTANT_AS u64a *s_wrl7 = MT7;

#endif

#define RECIPE_WRL_BIND(S)                                                      \
  (S)->wrl0 = s_wrl0; (S)->wrl1 = s_wrl1; (S)->wrl2 = s_wrl2;                  \
  (S)->wrl3 = s_wrl3; (S)->wrl4 = s_wrl4; (S)->wrl5 = s_wrl5;                  \
  (S)->wrl6 = s_wrl6; (S)->wrl7 = s_wrl7;

#define RECIPE_WRL_COPY(D,S)                                                    \
  (D).wrl0 = (S)->wrl0; (D).wrl1 = (S)->wrl1; (D).wrl2 = (S)->wrl2;            \
  (D).wrl3 = (S)->wrl3; (D).wrl4 = (S)->wrl4; (D).wrl5 = (S)->wrl5;            \
  (D).wrl6 = (S)->wrl6; (D).wrl7 = (S)->wrl7;

#define RECIPE_STATE_WRL                                                        \
  SHM_TYPE u64 *wrl0; SHM_TYPE u64 *wrl1; SHM_TYPE u64 *wrl2;                  \
  SHM_TYPE u64 *wrl3; SHM_TYPE u64 *wrl4; SHM_TYPE u64 *wrl5;                  \
  SHM_TYPE u64 *wrl6; SHM_TYPE u64 *wrl7;

#define RECIPE_WRL_TABLES st->wrl0, st->wrl1, st->wrl2, st->wrl3, st->wrl4, st->wrl5, st->wrl6, st->wrl7

#else

#define RECIPE_WRL_DECL
#define RECIPE_WRL_BIND(S)
#define RECIPE_WRL_COPY(D,S)
#define RECIPE_STATE_WRL

#endif

// Streebog-256 and Streebog-512 read the same table, which inc_hash_streebog256.cl and
// inc_hash_streebog512.cl each carry. A recipe that uses both sizes loads it once, from the first
// include, or reads it from constant memory when SBOG_CONSTANT_TABLES is defined. The module sets
// RECIPE_SBOG256 and RECIPE_SBOG512 for the sizes its steps use.

#if defined RECIPE_SBOG256 || defined RECIPE_SBOG512

#ifdef RECIPE_SBOG256
#define RECIPE_SBOG_SRC sbob256_sl64
#else
#define RECIPE_SBOG_SRC sbob512_sl64
#endif

#if defined REAL_SHM && !defined SBOG_CONSTANT_TABLES

#define RECIPE_SBOG_DECL                                                        \
  LOCAL_VK u64a s_sbog[8][256];                                                 \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 8; j++) s_sbog[j][i] = RECIPE_SBOG_SRC[j][i];           \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_SBOG_DECL CONSTANT_AS u64a (*s_sbog)[256] = RECIPE_SBOG_SRC;

#endif

#define RECIPE_SBOG_BIND(S)   (S)->sbog = s_sbog;
#define RECIPE_SBOG_COPY(D,S) (D).sbog = (S)->sbog;
#define RECIPE_STATE_SBOG     SBOG_SHM_TYPE u64a (*sbog)[256];

#else

#define RECIPE_SBOG_DECL
#define RECIPE_SBOG_BIND(S)
#define RECIPE_SBOG_COPY(D,S)
#define RECIPE_STATE_SBOG

#endif

// GOST R 34.11-94 reads the table of its S-box, from inc_hash_gost94.cl: c_tables for the test
// parameter set as gost, c_tables_cryptopro for the CryptoPro parameter set as gost_crypto. The
// module sets RECIPE_GOST94 and RECIPE_GOST94_CP for the tables its steps use.

#ifdef REAL_SHM

#define RECIPE_GOST_LOAD(D,S)                                                   \
  LOCAL_VK u32a D[4][256];                                                      \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 4; j++) D[j][i] = S[j][i];                              \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_GOST_LOAD(D,S) CONSTANT_AS u32a (*D)[256] = S;

#endif

#ifdef RECIPE_GOST94

#define RECIPE_GOST_DECL      RECIPE_GOST_LOAD (s_gost, c_tables)
#define RECIPE_GOST_BIND(S)   (S)->gost = s_gost;
#define RECIPE_GOST_COPY(D,S) (D).gost = (S)->gost;
#define RECIPE_STATE_GOST     SHM_TYPE u32a (*gost)[256];

#else

#define RECIPE_GOST_DECL
#define RECIPE_GOST_BIND(S)
#define RECIPE_GOST_COPY(D,S)
#define RECIPE_STATE_GOST

#endif

#ifdef RECIPE_GOST94_CP

#define RECIPE_GOSTC_DECL      RECIPE_GOST_LOAD (s_gostc, c_tables_cryptopro)
#define RECIPE_GOSTC_BIND(S)   (S)->gostc = s_gostc;
#define RECIPE_GOSTC_COPY(D,S) (D).gostc = (S)->gostc;
#define RECIPE_STATE_GOSTC     SHM_TYPE u32a (*gostc)[256];

#else

#define RECIPE_GOSTC_DECL
#define RECIPE_GOSTC_BIND(S)
#define RECIPE_GOSTC_COPY(D,S)
#define RECIPE_STATE_GOSTC

#endif

// Every kernel fills the shared tables that its recipe needs with RECIPE_SHM_DECL before any work
// item returns, and binds them to the state with RECIPE_SHM_BIND before recipe_prep ().

// Tiger reads its 4 S-boxes as one table, from inc_hash_tiger.cl. The module sets RECIPE_TIGER when a
// step hashes with Tiger or Tiger2.

#ifdef RECIPE_TIGER

#ifdef REAL_SHM

#define RECIPE_TIGER_DECL                                                       \
  LOCAL_VK u64a s_tiger[4][256];                                                \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 4; j++) s_tiger[j][i] = tiger_sbox[j][i];               \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_TIGER_DECL CONSTANT_AS u64a (*s_tiger)[256] = tiger_sbox;

#endif

#define RECIPE_TIGER_BIND(S)   (S)->tiger = s_tiger;
#define RECIPE_TIGER_COPY(D,S) (D).tiger = (S)->tiger;
#define RECIPE_STATE_TIGER     SHM_TYPE u64a (*tiger)[256];

#else

#define RECIPE_TIGER_DECL
#define RECIPE_TIGER_BIND(S)
#define RECIPE_TIGER_COPY(D,S)
#define RECIPE_STATE_TIGER

#endif

// MD2 reads its S-box from inc_hash_md2.cl. The module sets RECIPE_MD2 when a step hashes with MD2.

#ifdef RECIPE_MD2

#ifdef REAL_SHM

#define RECIPE_MD2_DECL                                                                                     \
  LOCAL_VK u32a s_md2[256];                                                                                 \
                                                                                                            \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0)) s_md2[i] = md2_sbox[i];     \
                                                                                                            \
  SYNC_THREADS ();

#else

#define RECIPE_MD2_DECL CONSTANT_AS u32a *s_md2 = md2_sbox;

#endif

#define RECIPE_MD2_BIND(S)   (S)->md2 = s_md2;
#define RECIPE_MD2_COPY(D,S) (D).md2 = (S)->md2;
#define RECIPE_STATE_MD2     SHM_TYPE u32a *md2;

#else

#define RECIPE_MD2_DECL
#define RECIPE_MD2_BIND(S)
#define RECIPE_MD2_COPY(D,S)
#define RECIPE_STATE_MD2

#endif

// Snefru reads its 16 S-boxes as one table, from inc_hash_snefru.cl. The module sets RECIPE_SNEFRU
// when a step hashes with Snefru-128 or Snefru-256.

#ifdef RECIPE_SNEFRU

#ifdef REAL_SHM

#define RECIPE_SNEFRU_DECL                                                      \
  LOCAL_VK u32a s_snefru[16][256];                                              \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 16; j++) s_snefru[j][i] = snefru_sbox[j][i];            \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_SNEFRU_DECL CONSTANT_AS u32a (*s_snefru)[256] = snefru_sbox;

#endif

#define RECIPE_SNEFRU_BIND(S)   (S)->snefru = s_snefru;
#define RECIPE_SNEFRU_COPY(D,S) (D).snefru = (S)->snefru;
#define RECIPE_STATE_SNEFRU     SHM_TYPE u32a (*snefru)[256];

#else

#define RECIPE_SNEFRU_DECL
#define RECIPE_SNEFRU_BIND(S)
#define RECIPE_SNEFRU_COPY(D,S)
#define RECIPE_STATE_SNEFRU

#endif

// DES steps, lm and mdc2 read the 2 tables of inc_cipher_des.cl, as the native DES kernels do. The
// module sets RECIPE_DES when a step uses one of them.

#ifdef RECIPE_DES

#ifdef REAL_SHM

#define RECIPE_DES_DECL                                                         \
  LOCAL_VK u32 s_des_skb[8][64];                                                \
  LOCAL_VK u32 s_des_sptrans[8][64];                                            \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 64; i += (u32) get_local_size (0))   \
  {                                                                             \
    for (u32 j = 0; j < 8; j++)                                                 \
    {                                                                           \
      s_des_skb[j][i]     = c_skb[j][i];                                        \
      s_des_sptrans[j][i] = c_SPtrans[j][i];                                    \
    }                                                                           \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_DES_DECL                                     \
  CONSTANT_AS u32a (*s_des_skb)[64]     = c_skb;            \
  CONSTANT_AS u32a (*s_des_sptrans)[64] = c_SPtrans;

#endif

#define RECIPE_DES_BIND(S)   (S)->des_skb = s_des_skb; (S)->des_sptrans = s_des_sptrans;
#define RECIPE_DES_COPY(D,S) (D).des_skb = (S)->des_skb; (D).des_sptrans = (S)->des_sptrans;
#define RECIPE_STATE_DES     SHM_TYPE u32 (*des_skb)[64]; SHM_TYPE u32 (*des_sptrans)[64];

#else

#define RECIPE_DES_DECL
#define RECIPE_DES_BIND(S)
#define RECIPE_DES_COPY(D,S)
#define RECIPE_STATE_DES

#endif

// ECHO and SHAvite read the tables te0 to te3 of inc_cipher_aes.cl. The module sets RECIPE_ECHO and
// RECIPE_SHAVITE when a step hashes with them. In the fast kernels of a recipe with an AES step they
// bind the copies RECIPE_AES_DECL loads. A slow recipe loads its own, because only its comp kernel
// loads the AES tables.

#if defined RECIPE_ECHO || defined RECIPE_SHAVITE

#if defined RECIPE_AES && !defined RECIPE_LOOP

#define RECIPE_TE_DECL

#define RECIPE_TE_BIND(S)                                                       \
  (S)->hte0 = s_te0; (S)->hte1 = s_te1; (S)->hte2 = s_te2;                     \
  (S)->hte3 = s_te3;

#else

#ifdef REAL_SHM

#define RECIPE_TE_DECL                                                          \
  LOCAL_VK u32a s_hte0[256];                                                    \
  LOCAL_VK u32a s_hte1[256];                                                    \
  LOCAL_VK u32a s_hte2[256];                                                    \
  LOCAL_VK u32a s_hte3[256];                                                    \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    s_hte0[i] = te0[i];                                                         \
    s_hte1[i] = te1[i];                                                         \
    s_hte2[i] = te2[i];                                                         \
    s_hte3[i] = te3[i];                                                         \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_TE_DECL              \
  CONSTANT_AS u32a *s_hte0 = te0;   \
  CONSTANT_AS u32a *s_hte1 = te1;   \
  CONSTANT_AS u32a *s_hte2 = te2;   \
  CONSTANT_AS u32a *s_hte3 = te3;

#endif

#define RECIPE_TE_BIND(S)                                                       \
  (S)->hte0 = s_hte0; (S)->hte1 = s_hte1; (S)->hte2 = s_hte2;                  \
  (S)->hte3 = s_hte3;

#endif

#define RECIPE_TE_COPY(D,S)                                                     \
  (D).hte0 = (S)->hte0; (D).hte1 = (S)->hte1; (D).hte2 = (S)->hte2;            \
  (D).hte3 = (S)->hte3;

#define RECIPE_STATE_TE                                                         \
  SHM_TYPE u32a *hte0; SHM_TYPE u32a *hte1; SHM_TYPE u32a *hte2;               \
  SHM_TYPE u32a *hte3;

#else

#define RECIPE_TE_DECL
#define RECIPE_TE_BIND(S)
#define RECIPE_TE_COPY(D,S)
#define RECIPE_STATE_TE

#endif

// Fugue reads its 4 mix tables as one table, from inc_hash_fugue.cl. The module sets RECIPE_FUGUE
// when a step hashes with Fugue.

#ifdef RECIPE_FUGUE

#ifdef REAL_SHM

#define RECIPE_FUGUE_DECL                                                       \
  LOCAL_VK u32a s_fugue[4][256];                                                \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 4; j++) s_fugue[j][i] = fugue_mixtab[j][i];             \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_FUGUE_DECL CONSTANT_AS u32a (*s_fugue)[256] = fugue_mixtab;

#endif

#define RECIPE_FUGUE_BIND(S)   (S)->fugue = s_fugue;
#define RECIPE_FUGUE_COPY(D,S) (D).fugue = (S)->fugue;
#define RECIPE_STATE_FUGUE     SHM_TYPE u32a (*fugue)[256];

#else

#define RECIPE_FUGUE_DECL
#define RECIPE_FUGUE_BIND(S)
#define RECIPE_FUGUE_COPY(D,S)
#define RECIPE_STATE_FUGUE

#endif

// Groestl reads its table from inc_hash_groestl.cl. The module sets RECIPE_GROESTL when a step
// hashes with Groestl.

#ifdef RECIPE_GROESTL

#ifdef REAL_SHM

#define RECIPE_GROESTL_DECL                                                     \
  LOCAL_VK u64a s_groestl[256];                                                 \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    s_groestl[i] = groestl_t0[i];                                               \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_GROESTL_DECL CONSTANT_AS u64a *s_groestl = groestl_t0;

#endif

#define RECIPE_GROESTL_BIND(S)   (S)->groestl = s_groestl;
#define RECIPE_GROESTL_COPY(D,S) (D).groestl = (S)->groestl;
#define RECIPE_STATE_GROESTL     SHM_TYPE u64a *groestl;

#else

#define RECIPE_GROESTL_DECL
#define RECIPE_GROESTL_BIND(S)
#define RECIPE_GROESTL_COPY(D,S)
#define RECIPE_STATE_GROESTL

#endif

// Whirlpool-0 and Whirlpool-T read one table each, from inc_hash_whirlpool01.cl. The module sets
// RECIPE_WRL01 when a step hashes with either.

#ifdef RECIPE_WRL01

#ifdef REAL_SHM

#define RECIPE_WRL01_DECL                                                       \
  LOCAL_VK u64a s_wrl01[2][256];                                                \
                                                                                \
  for (u32 i = (u32) get_local_id (0); i < 256; i += (u32) get_local_size (0))  \
  {                                                                             \
    for (u32 j = 0; j < 2; j++) s_wrl01[j][i] = whirlpool01_t0[j][i];           \
  }                                                                             \
                                                                                \
  SYNC_THREADS ();

#else

#define RECIPE_WRL01_DECL CONSTANT_AS u64a (*s_wrl01)[256] = whirlpool01_t0;

#endif

#define RECIPE_WRL01_BIND(S)   (S)->wrl01 = s_wrl01;
#define RECIPE_WRL01_COPY(D,S) (D).wrl01 = (S)->wrl01;
#define RECIPE_STATE_WRL01     SHM_TYPE u64a (*wrl01)[256];

#else

#define RECIPE_WRL01_DECL
#define RECIPE_WRL01_BIND(S)
#define RECIPE_WRL01_COPY(D,S)
#define RECIPE_STATE_WRL01

#endif

// The fast kernels load the AES tables with the others. The comp kernel of a slow recipe loads them
// itself, so its init and loop kernels go without.

#ifdef RECIPE_LOOP
#define RECIPE_SHM_AES_DECL
#define RECIPE_SHM_AES_BIND(S)
#else
#define RECIPE_SHM_AES_DECL    RECIPE_AES_DECL
#define RECIPE_SHM_AES_BIND(S) RECIPE_AES_BIND (S)
#endif

#define RECIPE_SHM_DECL    RECIPE_HEX_DECL RECIPE_WRL_DECL RECIPE_SBOG_DECL RECIPE_GOST_DECL RECIPE_GOSTC_DECL RECIPE_TIGER_DECL RECIPE_MD2_DECL RECIPE_SNEFRU_DECL RECIPE_DES_DECL RECIPE_TE_DECL RECIPE_FUGUE_DECL RECIPE_GROESTL_DECL RECIPE_WRL01_DECL RECIPE_SHM_AES_DECL
#define RECIPE_SHM_BIND(S) RECIPE_HEX_BIND (S) RECIPE_WRL_BIND (S) RECIPE_SBOG_BIND (S) RECIPE_GOST_BIND (S) RECIPE_GOSTC_BIND (S) RECIPE_TIGER_BIND (S) RECIPE_MD2_BIND (S) RECIPE_SNEFRU_BIND (S) RECIPE_DES_BIND (S) RECIPE_TE_BIND (S) RECIPE_FUGUE_BIND (S) RECIPE_GROESTL_BIND (S) RECIPE_WRL01_BIND (S) RECIPE_SHM_AES_BIND (S)

// Format step K's output as FMT from the LEN-byte digest in raw, stored as little endian words.
// Comparison uses raw directly for the final step. FMT is a number, so the preprocessor picks the
// body: raw and hex below, base64 in RECIPE_FORMAT_3.

#define RECIPE_FORMAT(T,HS,FMT,K,LEN)  RECIPE_FORMAT2 (T, HS, FMT, K, LEN)
#define RECIPE_FORMAT2(T,HS,FMT,K,LEN) RECIPE_FORMAT_##FMT (T, HS, FMT, K, LEN)

#define RECIPE_FORMAT_0(T,HS,FMT,K,LEN) RECIPE_FORMAT_TXT (T, HS, FMT, K, LEN)
#define RECIPE_FORMAT_1(T,HS,FMT,K,LEN) RECIPE_FORMAT_TXT (T, HS, FMT, K, LEN)
#define RECIPE_FORMAT_2(T,HS,FMT,K,LEN) RECIPE_FORMAT_TXT (T, HS, FMT, K, LEN)

#define RECIPE_FORMAT_TXT(T,HS,FMT,K,LEN)                                         \
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

// The base64 character for the 6-bit value V, computed without a comparison so that it works per
// lane. Each (V + N) >> 8 term is 1 exactly when V exceeds the end of a range in the alphabet.

#define RECIPE_B64C(V) ((V) + 65 + ((((V) + 230) >> 8) * 6) - ((((V) + 204) >> 8) * 75) - ((((V) + 194) >> 8) * 15) + ((((V) + 193) >> 8) * 3))

// The 3 bytes in group g produce the 4 characters of output word g. Bytes beyond the digest's end
// produce = padding in the output. Such a byte is read from index 0 instead, so a digest of 64
// bytes is never read past its end.

#define RECIPE_FORMAT_3(T,HS,FMT,K,LEN)                                           \
{                                                                                 \
  for (u32 g = 0; g < (((LEN) + 2) / 3); g++)                                     \
  {                                                                               \
    const u32 at = g * 3;                                                         \
                                                                                  \
    const u32 k1 = ((at + 1) < (LEN)) ? 1 : 0;                                    \
    const u32 k2 = ((at + 2) < (LEN)) ? 1 : 0;                                    \
                                                                                  \
    const T b0 = RECIPE_XGET (raw, at + 0);                                       \
    const T b1 = RECIPE_XGET (raw, (at + 1) * k1) * k1;                           \
    const T b2 = RECIPE_XGET (raw, (at + 2) * k2) * k2;                           \
                                                                                  \
    const T s0 = (b0 >> 2);                                                       \
    const T s1 = ((b0 << 4) | (b1 >> 4)) & 63;                                    \
    const T s2 = ((b1 << 2) | (b2 >> 6)) & 63;                                    \
    const T s3 = (b2 >> 0) & 63;                                                  \
                                                                                  \
    const T c0 = RECIPE_B64C (s0);                                                \
    const T c1 = RECIPE_B64C (s1);                                                \
    const T c2 = (RECIPE_B64C (s2) * k1) + ('=' * (1 - k1));                      \
    const T c3 = (RECIPE_B64C (s3) * k2) + ('=' * (1 - k2));                      \
                                                                                  \
    outs[((K) * 32) + g] = (c0 << 0) | (c1 << 8) | (c2 << 16) | (c3 << 24);       \
  }                                                                               \
                                                                                  \
  out_lens[K] = (((LEN) + 2) / 3) * 4;                                            \
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
// length, so all lanes in a vector use the same length. The exceptions are utf16be and frombase64,
// whose decoding produces lengths that depend on the input bytes. See RECIPE_XU16BE and
// RECIPE_XOP_FROMB64.
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

// Widen each byte to a unit of 2 bytes. Place the byte first for SH 0 and second for SH 8. Bytes
// beyond L are zero, so the copy remains zeroed beyond its new length.

#define RECIPE_XWIDEN(T,B,L,SH)                                                           \
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
    t[(i * 2) + 0] = (b0 << ((SH) + 0)) | (b1 << ((SH) + 16));                            \
    t[(i * 2) + 1] = (b2 << ((SH) + 0)) | (b3 << ((SH) + 16));                            \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = n * 2;                                                                              \
}

// Decode len bytes from in as UTF-8 and write UTF-16BE, using the same decoding rules as
// recipe_utf8_to_utf16be () in src/recipe.c. Input that is not well-formed UTF-8 produces 0 bytes.
// The out buffer is zeroed and holds 64 words.

DECLSPEC u32 recipe_utf16be (PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out)
{
  const u32 n = (len > 128) ? 128 : len;

  u32 i = 0;
  u32 o = 0;

  while (i < n)
  {
    const u32 c = RECIPE_XGET (in, i);

    u32 cl = 0;

    if      (c < 0x80)                   cl = 1;
    else if ((c >= 0xc2) && (c <= 0xdf)) cl = 2;
    else if ((c >= 0xe0) && (c <= 0xef)) cl = 3;
    else if ((c >= 0xf0) && (c <= 0xf4)) cl = 4;

    if (cl == 0) return 0;

    if ((i + cl) > n) return 0;

    u32 cp = (cl == 1) ? c : (c & (0x7f >> cl));

    for (u32 k = 1; k < cl; k++)
    {
      const u32 cc = RECIPE_XGET (in, i + k);

      if ((cc & 0xc0) != 0x80) return 0;

      cp = (cp << 6) | (cc & 0x3f);
    }

    const u32 least = (cl == 2) ? 0x80 : ((cl == 3) ? 0x800 : 0x10000);

    if ((cl > 1) && (cp < least)) return 0;

    if ((cp >= 0xd800) && (cp <= 0xdfff)) return 0;

    if (cp > 0x10ffff) return 0;

    i += cl;

    if (cp >= 0x10000)
    {
      const u32 hi = 0xd800 + ((cp - 0x10000) >> 10);
      const u32 lo = 0xdc00 + ((cp - 0x10000) & 0x3ff);

      RECIPE_XPUT (out, o + 0, hi >> 8);
      RECIPE_XPUT (out, o + 1, hi & 255);
      RECIPE_XPUT (out, o + 2, lo >> 8);
      RECIPE_XPUT (out, o + 3, lo & 255);

      o += 4;
    }
    else
    {
      RECIPE_XPUT (out, o + 0, cp >> 8);
      RECIPE_XPUT (out, o + 1, cp & 255);

      o += 2;
    }
  }

  return o;
}

#define RECIPE_XOP_ZEXT16(T,HS,B,L,A,BB,H,LL)  RECIPE_XWIDEN (T, B, L, 0)
#define RECIPE_XOP_UTF16BE(T,HS,B,L,A,BB,H,LL) RECIPE_XU16BE##HS (T, B, L)

// The vector state processes utf16be only when every lane is ASCII. See RECIPE_WIDE. It therefore
// widens the bytes directly. The scalar state decodes UTF-8. The clip empties the copy when the
// decoder stops at a byte that is not valid UTF-8.

#define RECIPE_XU16BE(T,B,L) RECIPE_XWIDEN (T, B, L, 8)

#define RECIPE_XU16BE_S(T,B,L)                                                            \
{                                                                                         \
  u32 t[64];                                                                              \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  L = recipe_utf16be (B, L, t);                                                           \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  RECIPE_XCLIP (B, L)                                                                     \
}

// Standard base64 with = padding. Each group of 3 input bytes gives the 4 characters of one output
// word. The module limits the input to 192 bytes, which fill the 64 words of a copy.

#define RECIPE_XOP_B64(T,HS,B,L,A,BB,H,LL)                                                \
{                                                                                         \
  const u32 n = ((L) > 192) ? 192 : (L);                                                  \
                                                                                          \
  T t[64];                                                                                \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  for (u32 g = 0; g < ((n + 2) / 3); g++)                                                 \
  {                                                                                       \
    const u32 at = g * 3;                                                                 \
                                                                                          \
    const u32 k1 = ((at + 1) < n) ? 1 : 0;                                                \
    const u32 k2 = ((at + 2) < n) ? 1 : 0;                                                \
                                                                                          \
    const T b0 = RECIPE_XGET (B, at + 0);                                                 \
    const T b1 = RECIPE_XGET (B, at + 1) * k1;                                            \
    const T b2 = RECIPE_XGET (B, at + 2) * k2;                                            \
                                                                                          \
    const T s0 = (b0 >> 2);                                                               \
    const T s1 = ((b0 << 4) | (b1 >> 4)) & 63;                                            \
    const T s2 = ((b1 << 2) | (b2 >> 6)) & 63;                                            \
    const T s3 = (b2 >> 0) & 63;                                                          \
                                                                                          \
    const T c0 = RECIPE_B64C (s0);                                                        \
    const T c1 = RECIPE_B64C (s1);                                                        \
    const T c2 = (RECIPE_B64C (s2) * k1) + ('=' * (1 - k1));                              \
    const T c3 = (RECIPE_B64C (s3) * k2) + ('=' * (1 - k2));                              \
                                                                                          \
    t[g] = (c0 << 0) | (c1 << 8) | (c2 << 16) | (c3 << 24);                               \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = ((n + 2) / 3) * 4;                                                                  \
}

// Decode hex as hx does: a byte that is not a hex digit counts as 0, and an odd last byte is
// dropped. RECIPE_XATLEAST is 1 when byte C is at least K, without a comparison that would give -1
// per lane. RECIPE_XNIB gives the value of byte C, with X the byte with bit 5 set, which turns the
// uppercase hex letters into lowercase ones and leaves the digits as they are.

#define RECIPE_XATLEAST(C,K) (((C) + (256 - (K))) >> 8)

#define RECIPE_XNIB(C,X) (((RECIPE_XATLEAST (C, 0x30) - RECIPE_XATLEAST (C, 0x3a)) * ((C) - 0x30)) + ((RECIPE_XATLEAST (X, 0x61) - RECIPE_XATLEAST (X, 0x67)) * ((X) - 0x57)))

#define RECIPE_XOP_FROMHEX(T,HS,B,L,A,BB,H,LL)                                            \
{                                                                                         \
  const u32 n = (L) / 2;                                                                  \
                                                                                          \
  T t[64];                                                                                \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  for (u32 i = 0; i < n; i++)                                                             \
  {                                                                                       \
    const T c0 = RECIPE_XGET (B, (i * 2) + 0);                                            \
    const T c1 = RECIPE_XGET (B, (i * 2) + 1);                                            \
                                                                                          \
    const T x0 = c0 | 0x20;                                                               \
    const T x1 = c1 | 0x20;                                                               \
                                                                                          \
    RECIPE_XPUT (t, i, (RECIPE_XNIB (c0, x0) << 4) | RECIPE_XNIB (c1, x1));               \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = n;                                                                                  \
}

// The value of base64 byte c, or 0xff for a byte outside the alphabet. Its low 2 bits are set, as
// those of the -1 hx uses are, which the third byte of a group reads.

DECLSPEC u32 recipe_b64v (const u32 c)
{
  u32 r = 0xff;

  if ((c >= 'A') && (c <= 'Z')) r = c - 'A';
  if ((c >= 'a') && (c <= 'z')) r = c - 'a' + 26;
  if ((c >= '0') && (c <= '9')) r = c - '0' + 52;

  if (c == '+') r = 62;
  if (c == '/') r = 63;

  return r;
}

// Decode len bytes from in as base64 the way hx does, using the same rules as
// recipe_hx_frombase64 () in src/recipe.c. A group of 4 bytes ends early at =, and decoding stops at
// a group whose first or second byte is not base64. The out buffer is zeroed and holds 64 words.

DECLSPEC u32 recipe_frombase64 (PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out)
{
  u32 i = 0;
  u32 o = 0;

  while ((i + 1) < len)
  {
    const u32 a = recipe_b64v (RECIPE_XGET (in, i + 0));
    const u32 b = recipe_b64v (RECIPE_XGET (in, i + 1));

    i += 2;

    u32 c = 0xff;
    u32 d = 0xff;

    if ((i < len) && (RECIPE_XGET (in, i) != '='))
    {
      c = recipe_b64v (RECIPE_XGET (in, i));

      i++;
    }

    if ((i < len) && (RECIPE_XGET (in, i) != '='))
    {
      d = recipe_b64v (RECIPE_XGET (in, i));

      i++;
    }

    if (a > 63) break;
    if (b > 63) break;

    RECIPE_XPUT (out, o, ((a << 2) | (b >> 4)) & 255);

    o++;

    if (c <= 63)
    {
      RECIPE_XPUT (out, o, ((b & 15) << 4) | (c >> 2));

      o++;
    }

    if (d <= 63)
    {
      RECIPE_XPUT (out, o, ((c & 3) << 6) | d);

      o++;
    }
  }

  return o;
}

// The decoded length depends on the bytes, while the lanes of the vector state share one length.
// The vector state therefore decodes each lane on its own and keeps the length of the last one.
// Every lane decodes to the same length where it runs: a field is the same in every lane, and a
// transformed hash output it decodes holds only base64 bytes. The vector mask kernel evaluates a
// frombase64 copy of pass lane by lane, see RECIPE_WIDE_LANES.

#define RECIPE_XOP_FROMB64(T,HS,B,L,A,BB,H,LL) RECIPE_XB64D##HS (T, B, L)

#define RECIPE_XB64D_S(T,B,L)                                                             \
{                                                                                         \
  u32 t[64];                                                                              \
                                                                                          \
  for (u32 i = 0; i < 64; i++) t[i] = 0;                                                  \
                                                                                          \
  L = recipe_frombase64 (B, L, t);                                                        \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
}

#if VECT_SIZE == 1
#define RECIPE_XB64D(T,B,L) RECIPE_XB64D_S (T, B, L)
#else
#define RECIPE_XB64D(T,B,L)                                                               \
{                                                                                         \
  T t[64];                                                                                \
                                                                                          \
  u32 n = 0;                                                                              \
                                                                                          \
  for (int lane = 0; lane < VECT_SIZE; lane++)                                            \
  {                                                                                       \
    u32 a[64];                                                                            \
    u32 d[64];                                                                            \
                                                                                          \
    for (u32 i = 0; i < 64; i++) a[i] = 0;                                                \
    for (u32 i = 0; i < 64; i++) d[i] = 0;                                                \
                                                                                          \
    hc_vector_get_lane (a, B, (int) (L), lane);                                           \
                                                                                          \
    n = recipe_frombase64 (a, L, d);                                                      \
                                                                                          \
    hc_vector_set_lane (t, d, 64, lane);                                                  \
  }                                                                                       \
                                                                                          \
  for (u32 i = 0; i < 64; i++) B[i] = t[i];                                               \
                                                                                          \
  L = n;                                                                                  \
}
#endif

#define RECIPE_XOP3(OP,T,HS,B,L,A,BB,H,LL) RECIPE_XOP_##OP (T, HS, B, L, A, BB, H, LL)
#define RECIPE_XOP2(OP,T,HS,B,L,A,BB,H,LL) RECIPE_XOP3 (OP, T, HS, B, L, A, BB, H, LL)
#define RECIPE_XOP(K,J,T,HS,B,L)           RECIPE_XOP2 (RECIPE_X##K##_O##J, T, HS, B, L, RECIPE_X##K##_A##J, RECIPE_X##K##_B##J, RECIPE_X##K##_H##J, RECIPE_X##K##_L##J)

// Make copy K from the SLEN-byte source SRC, which holds NW words, and apply its transforms,
// storing its bytes in B and its length in L. A field holds fewer words than the copy.

#define RECIPE_XRUN(K,T,HS,SRC,SLEN,NW,B,L)      \
{                                                \
  for (u32 i = 0; i < 64; i++) B[i] = 0;         \
                                                 \
  for (u32 i = 0; i < (NW); i++) B[i] = SRC[i];  \
                                                 \
  L = (SLEN);                                    \
                                               \
  RECIPE_XOP (K, 0, T, HS, B, L)               \
  RECIPE_XOP (K, 1, T, HS, B, L)               \
  RECIPE_XOP (K, 2, T, HS, B, L)               \
  RECIPE_XOP (K, 3, T, HS, B, L)               \
}

// What recipe_eval () and recipe_prep () do for copy K, and the state fields it needs, by its source.

#define RECIPE_XEV_PASS(K,T,HS) T xb##K[64]; u32 xl##K; RECIPE_XRUN (K, T, HS, w, pw_len, 64, xb##K, xl##K)
#define RECIPE_XEV_SALT(K,T,HS)
#define RECIPE_XPR_PASS(K,T,HS)
#define RECIPE_XPR_SALT(K,T,HS) RECIPE_XRUN (K, T, HS, s, salt_len, 64, st->xb##K, st->xl##K)
#define RECIPE_XFLD_PASS(K,T)
#define RECIPE_XFLD_SALT(K,T)   T xb##K[64]; u32 xl##K;

#define RECIPE_XEV_SALTD(K,T,HS)
#define RECIPE_XPR_SALTD(K,T,HS) RECIPE_XRUN (K, T, HS, st->sd, st->sd_len, 64, st->xb##K, st->xl##K)
#define RECIPE_XFLD_SALTD(K,T)   T xb##K[64]; u32 xl##K;

#define RECIPE_XEV_SALT2(K,T,HS)
#define RECIPE_XEV_PEPPER(K,T,HS)
#define RECIPE_XEV_USER(K,T,HS)
#define RECIPE_XPR_SALT2(K,T,HS)  RECIPE_XRUN (K, T, HS, st->fd0, st->fd0_len, RECIPE_FIELD_WORDS, st->xb##K, st->xl##K)
#define RECIPE_XPR_PEPPER(K,T,HS) RECIPE_XRUN (K, T, HS, st->fd1, st->fd1_len, RECIPE_FIELD_WORDS, st->xb##K, st->xl##K)
#define RECIPE_XPR_USER(K,T,HS)   RECIPE_XRUN (K, T, HS, st->fd2, st->fd2_len, RECIPE_FIELD_WORDS, st->xb##K, st->xl##K)
#define RECIPE_XFLD_SALT2(K,T)    T xb##K[64]; u32 xl##K;
#define RECIPE_XFLD_PEPPER(K,T)   T xb##K[64]; u32 xl##K;
#define RECIPE_XFLD_USER(K,T)     T xb##K[64]; u32 xl##K;

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

// Calls to fromhex (salt) and frombase64 (salt) hash a decoded salt copy, represented by part
// SALTD. The module sets RECIPE_SALT_DEC to 1 for hex and 2 for base64. Each work item decodes the
// salt from global memory once with RECIPE_SALTD_BIND, before recipe_prep (). A base64 salt's
// decoded length can depend on its padding. This works because all lanes of a vector share the same
// salt. Bytes outside the alphabet are decoded using the same rules as recipe_decode () in
// src/recipe.c, so the host and device produce the same decoded bytes for every salt.

#ifdef RECIPE_SALT_DEC

DECLSPEC u32 recipe_salt_decode (PRIVATE_AS u32 *out, GLOBAL_AS const u32 *in, const u32 len)
{
  for (u32 i = 0; i < 64; i++) out[i] = 0;

  #if RECIPE_SALT_DEC == 1

  const u32 n = len / 2;

  for (u32 i = 0; i < n; i++)
  {
    const u32 c0 = RECIPE_XGET (in, (i * 2) + 0);
    const u32 c1 = RECIPE_XGET (in, (i * 2) + 1);

    const u32 h0 = ((c0 & 15) + (((c0 >> 6) & 1) * 9)) & 15;
    const u32 h1 = ((c1 & 15) + (((c1 >> 6) & 1) * 9)) & 15;

    RECIPE_XPUT (out, i, (h0 << 4) | h1);
  }

  #else

  // Up to 2 trailing = characters are treated as padding. Any other byte outside the
  // alphabet counts as 0.

  u32 m = len;

  if ((m > 0) && (RECIPE_XGET (in, m - 1) == '=')) m--;
  if ((m > 0) && (RECIPE_XGET (in, m - 1) == '=')) m--;

  const u32 n = (m * 6) / 8;

  for (u32 g = 0; g < ((m + 3) / 4); g++)
  {
    u32 v[4];

    for (u32 j = 0; j < 4; j++)
    {
      const u32 at = (g * 4) + j;

      const u32 c = (at < m) ? RECIPE_XGET (in, at) : 0;

      u32 x = 0;

      if ((c >= 'A') && (c <= 'Z')) x = c - 65;
      if ((c >= 'a') && (c <= 'z')) x = c - 71;
      if ((c >= '0') && (c <= '9')) x = c + 4;

      if (c == '+') x = 62;
      if (c == '/') x = 63;

      v[j] = x;
    }

    const u32 b0 = ((v[0] << 2) | (v[1] >> 4)) & 255;
    const u32 b1 = ((v[1] << 4) | (v[2] >> 2)) & 255;
    const u32 b2 = ((v[2] << 6) | (v[3] >> 0)) & 255;

    const u32 at = g * 3;

    if ((at + 0) < n) RECIPE_XPUT (out, at + 0, b0);
    if ((at + 1) < n) RECIPE_XPUT (out, at + 1, b1);
    if ((at + 2) < n) RECIPE_XPUT (out, at + 2, b2);
  }

  #endif

  return n;
}

#define RECIPE_SALTD_BIND(S,SALT)                                             \
{                                                                             \
  u32 sdt[64];                                                                \
                                                                              \
  const u32 sdl = recipe_salt_decode (sdt, (SALT).salt_buf, (SALT).salt_len); \
                                                                              \
  for (u32 i = 0; i < 64; i++) (S)->sd[i] = sdt[i];                           \
                                                                              \
  (S)->sd_len = sdl;                                                          \
}

#define RECIPE_STATE_SD(T) T sd[64]; u32 sd_len;

#else

#define RECIPE_SALTD_BIND(S,SALT)

#define RECIPE_STATE_SD(T)

#endif

// salt2, pepper and user are represented by the parts SALT2, PEPPER and USER. The module packs the
// fields a recipe reads into salt_buf_pc, each in a slot of RECIPE_FIELD_WORDS words. Their lengths
// occupy the bytes of the word after those slots. See include/recipe.h. Each work item copies them
// into the state once with RECIPE_FIELDS_BIND, before recipe_prep (). The RECIPE_LINE_FIELDS mask
// has bit F set for field F.

#ifdef RECIPE_LINE_FIELDS

#define RECIPE_FIELD_BIND(S,SALT,F)                                                       \
{                                                                                         \
  const u32 o = (F) * RECIPE_FIELD_WORDS;                                                 \
  const u32 l = (SALT).salt_buf_pc[3 * RECIPE_FIELD_WORDS];                               \
                                                                                          \
  for (u32 i = 0; i < RECIPE_FIELD_WORDS; i++) (S)->fd##F[i] = (SALT).salt_buf_pc[o + i]; \
                                                                                          \
  (S)->fd##F##_len = (l >> ((F) * 8)) & 0xff;                                             \
}

// Copy field F from lane 0 of the vector state S into the scalar state D. All vector lanes
// share the same field bytes.

#define RECIPE_FIELD_LANE(D,S,F)                                                \
{                                                                               \
  for (u32 i = 0; i < RECIPE_FIELD_WORDS; i++) (D).fd##F[i] = 0;                \
                                                                                \
  hc_vector_get_lane ((D).fd##F, (S)->fd##F, (int) (S)->fd##F##_len, 0);        \
                                                                                \
  (D).fd##F##_len = (S)->fd##F##_len;                                           \
}

#if (RECIPE_LINE_FIELDS & 1)
#define RECIPE_FD0_BIND(S,SALT) RECIPE_FIELD_BIND (S, SALT, 0)
#define RECIPE_STATE_FD0(T)     T fd0[RECIPE_FIELD_WORDS]; u32 fd0_len;
#else
#define RECIPE_FD0_BIND(S,SALT)
#define RECIPE_STATE_FD0(T)
#endif

#if (RECIPE_LINE_FIELDS & 2)
#define RECIPE_FD1_BIND(S,SALT) RECIPE_FIELD_BIND (S, SALT, 1)
#define RECIPE_STATE_FD1(T)     T fd1[RECIPE_FIELD_WORDS]; u32 fd1_len;
#else
#define RECIPE_FD1_BIND(S,SALT)
#define RECIPE_STATE_FD1(T)
#endif

#if (RECIPE_LINE_FIELDS & 4)
#define RECIPE_FD2_BIND(S,SALT) RECIPE_FIELD_BIND (S, SALT, 2)
#define RECIPE_STATE_FD2(T)     T fd2[RECIPE_FIELD_WORDS]; u32 fd2_len;
#else
#define RECIPE_FD2_BIND(S,SALT)
#define RECIPE_STATE_FD2(T)
#endif

#define RECIPE_FIELDS_BIND(S,SALT) { RECIPE_FD0_BIND (S, SALT) RECIPE_FD1_BIND (S, SALT) RECIPE_FD2_BIND (S, SALT) }
#define RECIPE_STATE_FDS(T)        RECIPE_STATE_FD0 (T) RECIPE_STATE_FD1 (T) RECIPE_STATE_FD2 (T)

#else

#define RECIPE_FIELDS_BIND(S,SALT)
#define RECIPE_STATE_FDS(T)

#endif

// Feed one part into the running hash. U is the plain update and W is the UTF-16LE update. PU and
// PB are the update and buffer for pass. SU and SB are their salt equivalents. See RECIPE_UPDP_*.
// Part tokens are PASS, SALT, LIT0 through LIT3, STEP0 through STEP15, their UTF-16LE variants with
// 16 appended, or NONE for unused slots. SALTD is the decoded salt, see RECIPE_SALT_DEC. PSTEP0
// through PSTEP15 read outputs computed once per salt by recipe_prep () from the state during
// per-candidate evaluation. XP0 through XP3 are password copies, and XS0 through XS3 are salt
// copies stored in the state by recipe_prep ().

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
#define RECIPE_CALL_SALTD(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, st->sd, (int) st->sd_len);

// SALT2, PEPPER and USER are the fields of the hash line, see RECIPE_LINE_FIELDS.

#define RECIPE_CALL_SALT2(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, st->fd0, (int) st->fd0_len);
#define RECIPE_CALL_PEPPER(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, st->fd1, (int) st->fd1_len);
#define RECIPE_CALL_USER(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, st->fd2, (int) st->fd2_len);
#define RECIPE_CALL_SALT2_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, st->fd0, (int) st->fd0_len);
#define RECIPE_CALL_PEPPER_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, st->fd1, (int) st->fd1_len);
#define RECIPE_CALL_USER_16(U,W,PU,PB,SU,SB,G,WG)    W (&ctx, st->fd2, (int) st->fd2_len);

// VAR0 through VAR3 are the carried variables of a loop recipe, see RECIPE_LOOP.

#define RECIPE_CALL_VAR0(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, vb + (0 * 64), (int) vl[0]);
#define RECIPE_CALL_VAR1(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, vb + (1 * 64), (int) vl[1]);
#define RECIPE_CALL_VAR2(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, vb + (2 * 64), (int) vl[2]);
#define RECIPE_CALL_VAR3(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, vb + (3 * 64), (int) vl[3]);
#define RECIPE_CALL_LIT0(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits + (0 * RECIPE_LIT_WORDS), RECIPE_L0_LEN);
#define RECIPE_CALL_LIT1(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits + (1 * RECIPE_LIT_WORDS), RECIPE_L1_LEN);
#define RECIPE_CALL_LIT2(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits + (2 * RECIPE_LIT_WORDS), RECIPE_L2_LEN);
#define RECIPE_CALL_LIT3(U,W,PU,PB,SU,SB,G,WG)       U (&ctx, lits + (3 * RECIPE_LIT_WORDS), RECIPE_L3_LEN);
#define RECIPE_CALL_STEP0(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (0 * 32), (int) out_lens[0]);
#define RECIPE_CALL_STEP1(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (1 * 32), (int) out_lens[1]);
#define RECIPE_CALL_STEP2(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (2 * 32), (int) out_lens[2]);
#define RECIPE_CALL_STEP3(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (3 * 32), (int) out_lens[3]);
#define RECIPE_CALL_STEP4(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (4 * 32), (int) out_lens[4]);
#define RECIPE_CALL_STEP5(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (5 * 32), (int) out_lens[5]);
#define RECIPE_CALL_STEP6(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (6 * 32), (int) out_lens[6]);
#define RECIPE_CALL_STEP7(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (7 * 32), (int) out_lens[7]);
#define RECIPE_CALL_STEP8(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (8 * 32), (int) out_lens[8]);
#define RECIPE_CALL_STEP9(U,W,PU,PB,SU,SB,G,WG)      U (&ctx, outs + (9 * 32), (int) out_lens[9]);
#define RECIPE_CALL_STEP10(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (10 * 32), (int) out_lens[10]);
#define RECIPE_CALL_STEP11(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (11 * 32), (int) out_lens[11]);
#define RECIPE_CALL_STEP12(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (12 * 32), (int) out_lens[12]);
#define RECIPE_CALL_STEP13(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (13 * 32), (int) out_lens[13]);
#define RECIPE_CALL_STEP14(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (14 * 32), (int) out_lens[14]);
#define RECIPE_CALL_STEP15(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, outs + (15 * 32), (int) out_lens[15]);
#define RECIPE_CALL_STEP0_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (0 * 32), (int) out_lens[0]);
#define RECIPE_CALL_STEP1_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (1 * 32), (int) out_lens[1]);
#define RECIPE_CALL_STEP2_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (2 * 32), (int) out_lens[2]);
#define RECIPE_CALL_STEP3_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (3 * 32), (int) out_lens[3]);
#define RECIPE_CALL_STEP4_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (4 * 32), (int) out_lens[4]);
#define RECIPE_CALL_STEP5_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (5 * 32), (int) out_lens[5]);
#define RECIPE_CALL_STEP6_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (6 * 32), (int) out_lens[6]);
#define RECIPE_CALL_STEP7_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (7 * 32), (int) out_lens[7]);
#define RECIPE_CALL_STEP8_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (8 * 32), (int) out_lens[8]);
#define RECIPE_CALL_STEP9_16(U,W,PU,PB,SU,SB,G,WG)   W (&ctx, outs + (9 * 32), (int) out_lens[9]);
#define RECIPE_CALL_STEP10_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (10 * 32), (int) out_lens[10]);
#define RECIPE_CALL_STEP11_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (11 * 32), (int) out_lens[11]);
#define RECIPE_CALL_STEP12_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (12 * 32), (int) out_lens[12]);
#define RECIPE_CALL_STEP13_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (13 * 32), (int) out_lens[13]);
#define RECIPE_CALL_STEP14_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (14 * 32), (int) out_lens[14]);
#define RECIPE_CALL_STEP15_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, outs + (15 * 32), (int) out_lens[15]);
#define RECIPE_CALL_PSTEP0(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (0 * 32), (int) pout_lens[0]);
#define RECIPE_CALL_PSTEP1(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (1 * 32), (int) pout_lens[1]);
#define RECIPE_CALL_PSTEP2(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (2 * 32), (int) pout_lens[2]);
#define RECIPE_CALL_PSTEP3(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (3 * 32), (int) pout_lens[3]);
#define RECIPE_CALL_PSTEP4(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (4 * 32), (int) pout_lens[4]);
#define RECIPE_CALL_PSTEP5(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (5 * 32), (int) pout_lens[5]);
#define RECIPE_CALL_PSTEP6(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (6 * 32), (int) pout_lens[6]);
#define RECIPE_CALL_PSTEP7(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (7 * 32), (int) pout_lens[7]);
#define RECIPE_CALL_PSTEP8(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (8 * 32), (int) pout_lens[8]);
#define RECIPE_CALL_PSTEP9(U,W,PU,PB,SU,SB,G,WG)     U (&ctx, pouts + (9 * 32), (int) pout_lens[9]);
#define RECIPE_CALL_PSTEP10(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (10 * 32), (int) pout_lens[10]);
#define RECIPE_CALL_PSTEP11(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (11 * 32), (int) pout_lens[11]);
#define RECIPE_CALL_PSTEP12(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (12 * 32), (int) pout_lens[12]);
#define RECIPE_CALL_PSTEP13(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (13 * 32), (int) pout_lens[13]);
#define RECIPE_CALL_PSTEP14(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (14 * 32), (int) pout_lens[14]);
#define RECIPE_CALL_PSTEP15(U,W,PU,PB,SU,SB,G,WG)    U (&ctx, pouts + (15 * 32), (int) pout_lens[15]);
#define RECIPE_CALL_PSTEP0_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (0 * 32), (int) pout_lens[0]);
#define RECIPE_CALL_PSTEP1_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (1 * 32), (int) pout_lens[1]);
#define RECIPE_CALL_PSTEP2_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (2 * 32), (int) pout_lens[2]);
#define RECIPE_CALL_PSTEP3_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (3 * 32), (int) pout_lens[3]);
#define RECIPE_CALL_PSTEP4_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (4 * 32), (int) pout_lens[4]);
#define RECIPE_CALL_PSTEP5_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (5 * 32), (int) pout_lens[5]);
#define RECIPE_CALL_PSTEP6_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (6 * 32), (int) pout_lens[6]);
#define RECIPE_CALL_PSTEP7_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (7 * 32), (int) pout_lens[7]);
#define RECIPE_CALL_PSTEP8_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (8 * 32), (int) pout_lens[8]);
#define RECIPE_CALL_PSTEP9_16(U,W,PU,PB,SU,SB,G,WG)  W (&ctx, pouts + (9 * 32), (int) pout_lens[9]);
#define RECIPE_CALL_PSTEP10_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (10 * 32), (int) pout_lens[10]);
#define RECIPE_CALL_PSTEP11_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (11 * 32), (int) pout_lens[11]);
#define RECIPE_CALL_PSTEP12_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (12 * 32), (int) pout_lens[12]);
#define RECIPE_CALL_PSTEP13_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (13 * 32), (int) pout_lens[13]);
#define RECIPE_CALL_PSTEP14_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (14 * 32), (int) pout_lens[14]);
#define RECIPE_CALL_PSTEP15_16(U,W,PU,PB,SU,SB,G,WG) W (&ctx, pouts + (15 * 32), (int) pout_lens[15]);
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
#define RECIPE_LEN_wrl        64

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
#define RECIPE_BLOCK_wrl        64

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
#define RECIPE_UPD_wrl(X)        whirlpool_update##X##_swap

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
#define RECIPE_UPDW_wrl(X)        whirlpool_update##X##_utf16le_swap

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
#define RECIPE_UPDG_wrl        whirlpool_update_global_swap

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
#define RECIPE_UPDWG_wrl        whirlpool_update_global_utf16le_swap

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
#define RECIPE_UPDP_wrl(X)        RECIPE_PU_BE (whirlpool_update##X)

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
#define RECIPE_PBUF_wrl        RECIPE_PB_BE

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
#define RECIPE_UPDS_wrl(X)        RECIPE_SU_BE (whirlpool_update##X)

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
#define RECIPE_SBUF_wrl        RECIPE_SB_BE

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
#define RECIPE_CTX_wrl(X)         whirlpool_ctx##X##_t

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
#define RECIPE_INIT_wrl(X)        whirlpool_init##X (&ctx, RECIPE_WRL_TABLES);

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

#define RECIPE_HASH_wrl(X,HS,INIT,FEED)                           \
{                                                                 \
  whirlpool_ctx##X##_t ctx;                                       \
                                                                  \
  INIT                                                            \
                                                                  \
  FEED                                                            \
                                                                  \
  whirlpool_final##X (&ctx);                                      \
                                                                  \
  for (u32 i = 0; i < 16; i++) raw[i] = hc_swap32##HS (ctx.h[i]); \
}

// SHA-3 and Keccak use the functions from inc_hash_sha3.cl. The 8 families share one context and
// its functions, which take little endian words as MD5 does. They differ only in the digest size
// and padding byte set by their init function in that context. Their HMAC block is the rate, so the
// key pads and inner digest use the plain update rather than a block update of 64 or 128 bytes.

#define RECIPE_HASH_SHA3(X,HS,INIT,FEED,NW)                                                       \
{                                                                                                \
  sha3_ctx##X##_t ctx;                                                                           \
                                                                                                 \
  INIT                                                                                           \
                                                                                                 \
  FEED                                                                                           \
                                                                                                 \
  sha3_final##X (&ctx);                                                                          \
                                                                                                 \
  for (u32 i = 0; i < ((NW) / 2); i++)                                                           \
  {                                                                                              \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.st[i]);                                              \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.st[i]);                                              \
  }                                                                                              \
                                                                                                 \
  if (((NW) & 1) == 1) raw[(NW) - 1] = l32_from_64##HS (ctx.st[(NW) / 2]);                       \
}

// A key hashed to more bytes than the block, as in CubeHash and Luffa with 384 or 512 bits, keeps
// all of them, so its pads are longer than the block. RECIPE_KEYBLOCK gives their length in kpl.

#define RECIPE_PADG(F,X,HS,T,XOR)                                               \
{                                                                               \
  T pk[RECIPE_KBW (F)];                                                         \
                                                                                \
  for (u32 i = 0; i < RECIPE_KBW (F); i++) pk[i] = kb[i] ^ (XOR);               \
                                                                                \
  RECIPE_UPD_##F (X) (&ctx, pk, (int) kpl);                                     \
}

#define RECIPE_RAWG(F,X,HS,T,LEN) RECIPE_UPD_##F (X) (&ctx, raw, LEN);


#define RECIPE_LEN_sha3_224    28
#define RECIPE_BLOCK_sha3_224  144
#define RECIPE_UPD_sha3_224(X)  sha3_update##X
#define RECIPE_UPDW_sha3_224(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_sha3_224    sha3_update_global
#define RECIPE_UPDWG_sha3_224   sha3_update_global_utf16le
#define RECIPE_UPDP_sha3_224(X) sha3_update##X
#define RECIPE_PBUF_sha3_224    w
#define RECIPE_UPDS_sha3_224(X) sha3_update##X
#define RECIPE_SBUF_sha3_224    s
#define RECIPE_CTX_sha3_224(X)  sha3_ctx##X##_t
#define RECIPE_INIT_sha3_224(X) sha3_init##X (&ctx, 28, SHA3_PAD_SHA3);
#define RECIPE_HASH_sha3_224(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 7)
#define RECIPE_KS_sha3_224(HS,V)  (V)
#define RECIPE_RAW_sha3_224       RECIPE_RAWG
#define RECIPE_PAD_sha3_224       RECIPE_PADG

#define RECIPE_LEN_sha3_256    32
#define RECIPE_BLOCK_sha3_256  136
#define RECIPE_UPD_sha3_256(X)  sha3_update##X
#define RECIPE_UPDW_sha3_256(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_sha3_256    sha3_update_global
#define RECIPE_UPDWG_sha3_256   sha3_update_global_utf16le
#define RECIPE_UPDP_sha3_256(X) sha3_update##X
#define RECIPE_PBUF_sha3_256    w
#define RECIPE_UPDS_sha3_256(X) sha3_update##X
#define RECIPE_SBUF_sha3_256    s
#define RECIPE_CTX_sha3_256(X)  sha3_ctx##X##_t
#define RECIPE_INIT_sha3_256(X) sha3_init##X (&ctx, 32, SHA3_PAD_SHA3);
#define RECIPE_HASH_sha3_256(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 8)
#define RECIPE_KS_sha3_256(HS,V)  (V)
#define RECIPE_RAW_sha3_256       RECIPE_RAWG
#define RECIPE_PAD_sha3_256       RECIPE_PADG

#define RECIPE_LEN_sha3_384    48
#define RECIPE_BLOCK_sha3_384  104
#define RECIPE_UPD_sha3_384(X)  sha3_update##X
#define RECIPE_UPDW_sha3_384(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_sha3_384    sha3_update_global
#define RECIPE_UPDWG_sha3_384   sha3_update_global_utf16le
#define RECIPE_UPDP_sha3_384(X) sha3_update##X
#define RECIPE_PBUF_sha3_384    w
#define RECIPE_UPDS_sha3_384(X) sha3_update##X
#define RECIPE_SBUF_sha3_384    s
#define RECIPE_CTX_sha3_384(X)  sha3_ctx##X##_t
#define RECIPE_INIT_sha3_384(X) sha3_init##X (&ctx, 48, SHA3_PAD_SHA3);
#define RECIPE_HASH_sha3_384(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 12)
#define RECIPE_KS_sha3_384(HS,V)  (V)
#define RECIPE_RAW_sha3_384       RECIPE_RAWG
#define RECIPE_PAD_sha3_384       RECIPE_PADG

#define RECIPE_LEN_sha3_512    64
#define RECIPE_BLOCK_sha3_512  72
#define RECIPE_UPD_sha3_512(X)  sha3_update##X
#define RECIPE_UPDW_sha3_512(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_sha3_512    sha3_update_global
#define RECIPE_UPDWG_sha3_512   sha3_update_global_utf16le
#define RECIPE_UPDP_sha3_512(X) sha3_update##X
#define RECIPE_PBUF_sha3_512    w
#define RECIPE_UPDS_sha3_512(X) sha3_update##X
#define RECIPE_SBUF_sha3_512    s
#define RECIPE_CTX_sha3_512(X)  sha3_ctx##X##_t
#define RECIPE_INIT_sha3_512(X) sha3_init##X (&ctx, 64, SHA3_PAD_SHA3);
#define RECIPE_HASH_sha3_512(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 16)
#define RECIPE_KS_sha3_512(HS,V)  (V)
#define RECIPE_RAW_sha3_512       RECIPE_RAWG
#define RECIPE_PAD_sha3_512       RECIPE_PADG

#define RECIPE_LEN_keccak224    28
#define RECIPE_BLOCK_keccak224  144
#define RECIPE_UPD_keccak224(X)  sha3_update##X
#define RECIPE_UPDW_keccak224(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_keccak224    sha3_update_global
#define RECIPE_UPDWG_keccak224   sha3_update_global_utf16le
#define RECIPE_UPDP_keccak224(X) sha3_update##X
#define RECIPE_PBUF_keccak224    w
#define RECIPE_UPDS_keccak224(X) sha3_update##X
#define RECIPE_SBUF_keccak224    s
#define RECIPE_CTX_keccak224(X)  sha3_ctx##X##_t
#define RECIPE_INIT_keccak224(X) sha3_init##X (&ctx, 28, SHA3_PAD_KECCAK);
#define RECIPE_HASH_keccak224(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 7)
#define RECIPE_KS_keccak224(HS,V)  (V)
#define RECIPE_RAW_keccak224       RECIPE_RAWG
#define RECIPE_PAD_keccak224       RECIPE_PADG

#define RECIPE_LEN_keccak256    32
#define RECIPE_BLOCK_keccak256  136
#define RECIPE_UPD_keccak256(X)  sha3_update##X
#define RECIPE_UPDW_keccak256(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_keccak256    sha3_update_global
#define RECIPE_UPDWG_keccak256   sha3_update_global_utf16le
#define RECIPE_UPDP_keccak256(X) sha3_update##X
#define RECIPE_PBUF_keccak256    w
#define RECIPE_UPDS_keccak256(X) sha3_update##X
#define RECIPE_SBUF_keccak256    s
#define RECIPE_CTX_keccak256(X)  sha3_ctx##X##_t
#define RECIPE_INIT_keccak256(X) sha3_init##X (&ctx, 32, SHA3_PAD_KECCAK);
#define RECIPE_HASH_keccak256(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 8)
#define RECIPE_KS_keccak256(HS,V)  (V)
#define RECIPE_RAW_keccak256       RECIPE_RAWG
#define RECIPE_PAD_keccak256       RECIPE_PADG

#define RECIPE_LEN_keccak384    48
#define RECIPE_BLOCK_keccak384  104
#define RECIPE_UPD_keccak384(X)  sha3_update##X
#define RECIPE_UPDW_keccak384(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_keccak384    sha3_update_global
#define RECIPE_UPDWG_keccak384   sha3_update_global_utf16le
#define RECIPE_UPDP_keccak384(X) sha3_update##X
#define RECIPE_PBUF_keccak384    w
#define RECIPE_UPDS_keccak384(X) sha3_update##X
#define RECIPE_SBUF_keccak384    s
#define RECIPE_CTX_keccak384(X)  sha3_ctx##X##_t
#define RECIPE_INIT_keccak384(X) sha3_init##X (&ctx, 48, SHA3_PAD_KECCAK);
#define RECIPE_HASH_keccak384(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 12)
#define RECIPE_KS_keccak384(HS,V)  (V)
#define RECIPE_RAW_keccak384       RECIPE_RAWG
#define RECIPE_PAD_keccak384       RECIPE_PADG

#define RECIPE_LEN_keccak512    64
#define RECIPE_BLOCK_keccak512  72
#define RECIPE_UPD_keccak512(X)  sha3_update##X
#define RECIPE_UPDW_keccak512(X) sha3_update##X##_utf16le
#define RECIPE_UPDG_keccak512    sha3_update_global
#define RECIPE_UPDWG_keccak512   sha3_update_global_utf16le
#define RECIPE_UPDP_keccak512(X) sha3_update##X
#define RECIPE_PBUF_keccak512    w
#define RECIPE_UPDS_keccak512(X) sha3_update##X
#define RECIPE_SBUF_keccak512    s
#define RECIPE_CTX_keccak512(X)  sha3_ctx##X##_t
#define RECIPE_INIT_keccak512(X) sha3_init##X (&ctx, 64, SHA3_PAD_KECCAK);
#define RECIPE_HASH_keccak512(X,HS,INIT,FEED) RECIPE_HASH_SHA3 (X, HS, INIT, FEED, 16)
#define RECIPE_KS_keccak512(HS,V)  (V)
#define RECIPE_RAW_keccak512       RECIPE_RAWG
#define RECIPE_PAD_keccak512       RECIPE_PADG

// Streebog takes little endian words through its swap updates, as SHA-1 does. It returns its digest
// as the little endian words of h, as BLAKE2 does. It has no UTF-16 updates, so the module rejects
// utf16le parts in its steps. The hx names for its sizes are streebog_32 and streebog_64.

#define RECIPE_LEN_streebog_32    32
#define RECIPE_BLOCK_streebog_32  64
#define RECIPE_UPD_streebog_32(X)  streebog256_update##X##_swap
#define RECIPE_UPDW_streebog_32(X) recipe_no_utf16_streebog
#define RECIPE_UPDG_streebog_32    streebog256_update_global_swap
#define RECIPE_UPDWG_streebog_32   recipe_no_utf16_streebog
#define RECIPE_UPDP_streebog_32(X) RECIPE_PU_BE (streebog256_update##X)
#define RECIPE_PBUF_streebog_32    RECIPE_PB_BE
#define RECIPE_UPDS_streebog_32(X) RECIPE_SU_BE (streebog256_update##X)
#define RECIPE_SBUF_streebog_32    RECIPE_SB_BE
#define RECIPE_CTX_streebog_32(X)  streebog256_ctx##X##_t
#define RECIPE_INIT_streebog_32(X) streebog256_init##X (&ctx, st->sbog);
#define RECIPE_HASH_streebog_32(X,HS,INIT,FEED) RECIPE_HASH_SBOG (X, HS, INIT, FEED, 256, 4)
#define RECIPE_KS_streebog_32(HS,V)  hc_swap32##HS (V)
#define RECIPE_UB_streebog_32(X)     streebog256_update##X##_64
#define RECIPE_RAW_streebog_32       RECIPE_RAWREV64
#define RECIPE_PAD_streebog_32       RECIPE_PAD64

#define RECIPE_LEN_streebog_64    64
#define RECIPE_BLOCK_streebog_64  64
#define RECIPE_UPD_streebog_64(X)  streebog512_update##X##_swap
#define RECIPE_UPDW_streebog_64(X) recipe_no_utf16_streebog
#define RECIPE_UPDG_streebog_64    streebog512_update_global_swap
#define RECIPE_UPDWG_streebog_64   recipe_no_utf16_streebog
#define RECIPE_UPDP_streebog_64(X) RECIPE_PU_BE (streebog512_update##X)
#define RECIPE_PBUF_streebog_64    RECIPE_PB_BE
#define RECIPE_UPDS_streebog_64(X) RECIPE_SU_BE (streebog512_update##X)
#define RECIPE_SBUF_streebog_64    RECIPE_SB_BE
#define RECIPE_CTX_streebog_64(X)  streebog512_ctx##X##_t
#define RECIPE_INIT_streebog_64(X) streebog512_init##X (&ctx, st->sbog);
#define RECIPE_HASH_streebog_64(X,HS,INIT,FEED) RECIPE_HASH_SBOG (X, HS, INIT, FEED, 512, 8)
#define RECIPE_KS_streebog_64(HS,V)  hc_swap32##HS (V)
#define RECIPE_UB_streebog_64(X)     streebog512_update##X##_64
#define RECIPE_RAW_streebog_64       RECIPE_RAWREV64
#define RECIPE_PAD_streebog_64       RECIPE_PAD64

#define RECIPE_HASH_SBOG(X,HS,INIT,FEED,B,NL)                         \
{                                                                     \
  streebog##B##_ctx##X##_t ctx;                                       \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  streebog##B##_final##X (&ctx);                                      \
                                                                      \
  for (u32 i = 0; i < (NL); i++)                                      \
  {                                                                   \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[i]);                    \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[i]);                    \
  }                                                                   \
}

// GOST R 34.11-94, see inc_hash_gost94.cl. It takes little endian words as MD5 does and gives its
// digest as h in the same layout. gost and gost_crypto differ only in the table of the S-box. Their
// block for HMAC is 32 bytes, so the key pads and the inner digest go through the plain update.

#define RECIPE_LEN_gost    32
#define RECIPE_BLOCK_gost  32
#define RECIPE_UPD_gost(X)  gost94_update##X
#define RECIPE_UPDW_gost(X) gost94_update##X##_utf16le
#define RECIPE_UPDG_gost    gost94_update_global
#define RECIPE_UPDWG_gost   gost94_update_global_utf16le
#define RECIPE_UPDP_gost(X) gost94_update##X
#define RECIPE_PBUF_gost    w
#define RECIPE_UPDS_gost(X) gost94_update##X
#define RECIPE_SBUF_gost    s
#define RECIPE_CTX_gost(X)  gost94_ctx##X##_t
#define RECIPE_INIT_gost(X) gost94_init##X (&ctx, st->gost);
#define RECIPE_HASH_gost(X,HS,INIT,FEED) RECIPE_HASH_GOST (X, HS, INIT, FEED)
#define RECIPE_KS_gost(HS,V)  (V)
#define RECIPE_RAW_gost       RECIPE_RAWG
#define RECIPE_PAD_gost       RECIPE_PADG

#define RECIPE_LEN_gost_crypto    32
#define RECIPE_BLOCK_gost_crypto  32
#define RECIPE_UPD_gost_crypto(X)  gost94_update##X
#define RECIPE_UPDW_gost_crypto(X) gost94_update##X##_utf16le
#define RECIPE_UPDG_gost_crypto    gost94_update_global
#define RECIPE_UPDWG_gost_crypto   gost94_update_global_utf16le
#define RECIPE_UPDP_gost_crypto(X) gost94_update##X
#define RECIPE_PBUF_gost_crypto    w
#define RECIPE_UPDS_gost_crypto(X) gost94_update##X
#define RECIPE_SBUF_gost_crypto    s
#define RECIPE_CTX_gost_crypto(X)  gost94_ctx##X##_t
#define RECIPE_INIT_gost_crypto(X) gost94_init##X (&ctx, st->gostc);
#define RECIPE_HASH_gost_crypto(X,HS,INIT,FEED) RECIPE_HASH_GOST (X, HS, INIT, FEED)
#define RECIPE_KS_gost_crypto(HS,V)  (V)
#define RECIPE_RAW_gost_crypto       RECIPE_RAWG
#define RECIPE_PAD_gost_crypto       RECIPE_PADG

// RIPEMD-320, see inc_hash_ripemd320.cl, works as RIPEMD-160 does with a 40-byte digest.

#define RECIPE_LEN_rmd320    40
#define RECIPE_BLOCK_rmd320  64
#define RECIPE_UPD_rmd320(X)  ripemd320_update##X
#define RECIPE_UPDW_rmd320(X) ripemd320_update##X##_utf16le
#define RECIPE_UPDG_rmd320    ripemd320_update_global
#define RECIPE_UPDWG_rmd320   ripemd320_update_global_utf16le
#define RECIPE_UPDP_rmd320(X) ripemd320_update##X
#define RECIPE_PBUF_rmd320    w
#define RECIPE_UPDS_rmd320(X) ripemd320_update##X
#define RECIPE_SBUF_rmd320    s
#define RECIPE_CTX_rmd320(X)  ripemd320_ctx##X##_t
#define RECIPE_INIT_rmd320(X) ripemd320_init##X (&ctx);
#define RECIPE_KS_rmd320(HS,V)  (V)
#define RECIPE_UB_rmd320(X)     ripemd320_update##X##_64
#define RECIPE_RAW_rmd320       RECIPE_RAW64
#define RECIPE_PAD_rmd320       RECIPE_PAD64

#define RECIPE_HASH_rmd320(X,HS,INIT,FEED)                            \
{                                                                     \
  ripemd320_ctx##X##_t ctx;                                           \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  ripemd320_final##X (&ctx);                                          \
                                                                      \
  for (u32 i = 0; i < 10; i++) raw[i] = ctx.h[i];                     \
}

// RIPEMD-128 and RIPEMD-256 use inc_hash_ripemd128.cl and inc_hash_ripemd256.cl. Both take little
// endian words as MD5 does and return their digest as h. Their HMAC block contains 64 bytes and
// uses the plain update.

#define RECIPE_LEN_rmd128    16
#define RECIPE_BLOCK_rmd128  64
#define RECIPE_UPD_rmd128(X)  ripemd128_update##X
#define RECIPE_UPDW_rmd128(X) ripemd128_update##X##_utf16le
#define RECIPE_UPDG_rmd128    ripemd128_update_global
#define RECIPE_UPDWG_rmd128   ripemd128_update_global_utf16le
#define RECIPE_UPDP_rmd128(X) ripemd128_update##X
#define RECIPE_PBUF_rmd128    w
#define RECIPE_UPDS_rmd128(X) ripemd128_update##X
#define RECIPE_SBUF_rmd128    s
#define RECIPE_CTX_rmd128(X)  ripemd128_ctx##X##_t
#define RECIPE_INIT_rmd128(X) ripemd128_init##X (&ctx);
#define RECIPE_KS_rmd128(HS,V)  (V)
#define RECIPE_RAW_rmd128       RECIPE_RAWG
#define RECIPE_PAD_rmd128       RECIPE_PADG

#define RECIPE_HASH_rmd128(X,HS,INIT,FEED)                            \
{                                                                     \
  ripemd128_ctx##X##_t ctx;                                           \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  ripemd128_final##X (&ctx);                                          \
                                                                      \
  for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];                      \
}

#define RECIPE_LEN_rmd256    32
#define RECIPE_BLOCK_rmd256  64
#define RECIPE_UPD_rmd256(X)  ripemd256_update##X
#define RECIPE_UPDW_rmd256(X) ripemd256_update##X##_utf16le
#define RECIPE_UPDG_rmd256    ripemd256_update_global
#define RECIPE_UPDWG_rmd256   ripemd256_update_global_utf16le
#define RECIPE_UPDP_rmd256(X) ripemd256_update##X
#define RECIPE_PBUF_rmd256    w
#define RECIPE_UPDS_rmd256(X) ripemd256_update##X
#define RECIPE_SBUF_rmd256    s
#define RECIPE_CTX_rmd256(X)  ripemd256_ctx##X##_t
#define RECIPE_INIT_rmd256(X) ripemd256_init##X (&ctx);
#define RECIPE_KS_rmd256(HS,V)  (V)
#define RECIPE_RAW_rmd256       RECIPE_RAWG
#define RECIPE_PAD_rmd256       RECIPE_PADG

#define RECIPE_HASH_rmd256(X,HS,INIT,FEED)                            \
{                                                                     \
  ripemd256_ctx##X##_t ctx;                                           \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  ripemd256_final##X (&ctx);                                          \
                                                                      \
  for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];                      \
}

// MD2, see inc_hash_md2.cl. It takes little endian words as MD5 does and gives its digest as h.
// Its block, and so its HMAC block, is 16 bytes.

#define RECIPE_LEN_md2    16
#define RECIPE_BLOCK_md2  16
#define RECIPE_UPD_md2(X)  md2_update##X
#define RECIPE_UPDW_md2(X) md2_update##X##_utf16le
#define RECIPE_UPDG_md2    md2_update_global
#define RECIPE_UPDWG_md2   md2_update_global_utf16le
#define RECIPE_UPDP_md2(X) md2_update##X
#define RECIPE_PBUF_md2    w
#define RECIPE_UPDS_md2(X) md2_update##X
#define RECIPE_SBUF_md2    s
#define RECIPE_CTX_md2(X)  md2_ctx##X##_t
#define RECIPE_INIT_md2(X) md2_init##X (&ctx, st->md2);
#define RECIPE_KS_md2(HS,V)  (V)
#define RECIPE_RAW_md2       RECIPE_RAWG
#define RECIPE_PAD_md2       RECIPE_PADG

#define RECIPE_HASH_md2(X,HS,INIT,FEED)                               \
{                                                                     \
  md2_ctx##X##_t ctx;                                                 \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  md2_final##X (&ctx);                                                \
                                                                      \
  for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];                      \
}

// SHA-0 uses inc_hash_sha0.cl. It takes little endian words as MD5 does and swaps them internally.
// Its digest h consists of big endian words, in the same layout as SHA-1's digest.

#define RECIPE_LEN_sha0    20
#define RECIPE_BLOCK_sha0  64
#define RECIPE_UPD_sha0(X)  sha0_update##X
#define RECIPE_UPDW_sha0(X) sha0_update##X##_utf16le
#define RECIPE_UPDG_sha0    sha0_update_global
#define RECIPE_UPDWG_sha0   sha0_update_global_utf16le
#define RECIPE_UPDP_sha0(X) sha0_update##X
#define RECIPE_PBUF_sha0    w
#define RECIPE_UPDS_sha0(X) sha0_update##X
#define RECIPE_SBUF_sha0    s
#define RECIPE_CTX_sha0(X)  sha0_ctx##X##_t
#define RECIPE_INIT_sha0(X) sha0_init##X (&ctx);
#define RECIPE_KS_sha0(HS,V)  (V)
#define RECIPE_RAW_sha0       RECIPE_RAWG
#define RECIPE_PAD_sha0       RECIPE_PADG

#define RECIPE_HASH_sha0(X,HS,INIT,FEED)                              \
{                                                                     \
  sha0_ctx##X##_t ctx;                                                \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  sha0_final##X (&ctx);                                               \
                                                                      \
  for (u32 i = 0; i < 5; i++) raw[i] = hc_swap32##HS (ctx.h[i]);      \
}

// Snefru-128 and Snefru-256 use inc_hash_snefru.cl. They take little endian words as MD5 does and
// swap them internally. Their digest h consists of big endian words. Their message blocks, and
// therefore their HMAC blocks, contain 48 and 32 bytes.

#define RECIPE_HASH_SNEFRU(X,HS,INIT,FEED,NW)                         \
{                                                                     \
  snefru_ctx##X##_t ctx;                                              \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  snefru_final##X (&ctx);                                             \
                                                                      \
  for (u32 i = 0; i < (NW); i++) raw[i] = hc_swap32##HS (ctx.h[i]);   \
}

#define RECIPE_LEN_sne128    16
#define RECIPE_BLOCK_sne128  48
#define RECIPE_UPD_sne128(X)  snefru_update##X
#define RECIPE_UPDW_sne128(X) snefru_update##X##_utf16le
#define RECIPE_UPDG_sne128    snefru_update_global
#define RECIPE_UPDWG_sne128   snefru_update_global_utf16le
#define RECIPE_UPDP_sne128(X) snefru_update##X
#define RECIPE_PBUF_sne128    w
#define RECIPE_UPDS_sne128(X) snefru_update##X
#define RECIPE_SBUF_sne128    s
#define RECIPE_CTX_sne128(X)  snefru_ctx##X##_t
#define RECIPE_INIT_sne128(X) snefru_init##X (&ctx, st->snefru, 16);
#define RECIPE_HASH_sne128(X,HS,INIT,FEED) RECIPE_HASH_SNEFRU (X, HS, INIT, FEED, 4)
#define RECIPE_KS_sne128(HS,V)  (V)
#define RECIPE_RAW_sne128       RECIPE_RAWG
#define RECIPE_PAD_sne128       RECIPE_PADG

#define RECIPE_LEN_sne256    32
#define RECIPE_BLOCK_sne256  32
#define RECIPE_UPD_sne256(X)  snefru_update##X
#define RECIPE_UPDW_sne256(X) snefru_update##X##_utf16le
#define RECIPE_UPDG_sne256    snefru_update_global
#define RECIPE_UPDWG_sne256   snefru_update_global_utf16le
#define RECIPE_UPDP_sne256(X) snefru_update##X
#define RECIPE_PBUF_sne256    w
#define RECIPE_UPDS_sne256(X) snefru_update##X
#define RECIPE_SBUF_sne256    s
#define RECIPE_CTX_sne256(X)  snefru_ctx##X##_t
#define RECIPE_INIT_sne256(X) snefru_init##X (&ctx, st->snefru, 32);
#define RECIPE_HASH_sne256(X,HS,INIT,FEED) RECIPE_HASH_SNEFRU (X, HS, INIT, FEED, 8)
#define RECIPE_KS_sne256(HS,V)  (V)
#define RECIPE_RAW_sne256       RECIPE_RAWG
#define RECIPE_PAD_sne256       RECIPE_PADG

// Skein-512 with the digest sizes of skein224 to skein512 uses inc_hash_skein512.cl. Its functions
// take little endian words as MD5 does, and its digest is the first bytes of h, little endian. Its
// message blocks, and therefore its HMAC blocks, contain 64 bytes.

#define RECIPE_HASH_SKEIN512(X,HS,INIT,FEED,NW)                                \
{                                                                             \
  skein512_ctx##X##_t ctx;                                                    \
                                                                              \
  INIT                                                                        \
                                                                              \
  FEED                                                                        \
                                                                              \
  skein512_final##X (&ctx);                                                   \
                                                                              \
  for (u32 i = 0; i < ((NW) / 2); i++)                                        \
  {                                                                           \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[i]);                            \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[i]);                            \
  }                                                                           \
                                                                              \
  if (((NW) & 1) == 1) raw[(NW) - 1] = l32_from_64##HS (ctx.h[(NW) / 2]);     \
}

#define RECIPE_LEN_skein224    28
#define RECIPE_BLOCK_skein224  64
#define RECIPE_UPD_skein224(X)  skein512_update##X
#define RECIPE_UPDW_skein224(X) skein512_update##X##_utf16le
#define RECIPE_UPDG_skein224    skein512_update_global
#define RECIPE_UPDWG_skein224   skein512_update_global_utf16le
#define RECIPE_UPDP_skein224(X) skein512_update##X
#define RECIPE_PBUF_skein224    w
#define RECIPE_UPDS_skein224(X) skein512_update##X
#define RECIPE_SBUF_skein224    s
#define RECIPE_CTX_skein224(X)  skein512_ctx##X##_t
#define RECIPE_INIT_skein224(X) skein512_init##X (&ctx, 28);
#define RECIPE_HASH_skein224(X,HS,INIT,FEED) RECIPE_HASH_SKEIN512 (X, HS, INIT, FEED, 7)
#define RECIPE_KS_skein224(HS,V)  (V)
#define RECIPE_RAW_skein224       RECIPE_RAWG
#define RECIPE_PAD_skein224       RECIPE_PADG

#define RECIPE_LEN_skein256    32
#define RECIPE_BLOCK_skein256  64
#define RECIPE_UPD_skein256(X)  skein512_update##X
#define RECIPE_UPDW_skein256(X) skein512_update##X##_utf16le
#define RECIPE_UPDG_skein256    skein512_update_global
#define RECIPE_UPDWG_skein256   skein512_update_global_utf16le
#define RECIPE_UPDP_skein256(X) skein512_update##X
#define RECIPE_PBUF_skein256    w
#define RECIPE_UPDS_skein256(X) skein512_update##X
#define RECIPE_SBUF_skein256    s
#define RECIPE_CTX_skein256(X)  skein512_ctx##X##_t
#define RECIPE_INIT_skein256(X) skein512_init##X (&ctx, 32);
#define RECIPE_HASH_skein256(X,HS,INIT,FEED) RECIPE_HASH_SKEIN512 (X, HS, INIT, FEED, 8)
#define RECIPE_KS_skein256(HS,V)  (V)
#define RECIPE_RAW_skein256       RECIPE_RAWG
#define RECIPE_PAD_skein256       RECIPE_PADG

#define RECIPE_LEN_skein384    48
#define RECIPE_BLOCK_skein384  64
#define RECIPE_UPD_skein384(X)  skein512_update##X
#define RECIPE_UPDW_skein384(X) skein512_update##X##_utf16le
#define RECIPE_UPDG_skein384    skein512_update_global
#define RECIPE_UPDWG_skein384   skein512_update_global_utf16le
#define RECIPE_UPDP_skein384(X) skein512_update##X
#define RECIPE_PBUF_skein384    w
#define RECIPE_UPDS_skein384(X) skein512_update##X
#define RECIPE_SBUF_skein384    s
#define RECIPE_CTX_skein384(X)  skein512_ctx##X##_t
#define RECIPE_INIT_skein384(X) skein512_init##X (&ctx, 48);
#define RECIPE_HASH_skein384(X,HS,INIT,FEED) RECIPE_HASH_SKEIN512 (X, HS, INIT, FEED, 12)
#define RECIPE_KS_skein384(HS,V)  (V)
#define RECIPE_RAW_skein384       RECIPE_RAWG
#define RECIPE_PAD_skein384       RECIPE_PADG

#define RECIPE_LEN_skein512    64
#define RECIPE_BLOCK_skein512  64
#define RECIPE_UPD_skein512(X)  skein512_update##X
#define RECIPE_UPDW_skein512(X) skein512_update##X##_utf16le
#define RECIPE_UPDG_skein512    skein512_update_global
#define RECIPE_UPDWG_skein512   skein512_update_global_utf16le
#define RECIPE_UPDP_skein512(X) skein512_update##X
#define RECIPE_PBUF_skein512    w
#define RECIPE_UPDS_skein512(X) skein512_update##X
#define RECIPE_SBUF_skein512    s
#define RECIPE_CTX_skein512(X)  skein512_ctx##X##_t
#define RECIPE_INIT_skein512(X) skein512_init##X (&ctx, 64);
#define RECIPE_HASH_skein512(X,HS,INIT,FEED) RECIPE_HASH_SKEIN512 (X, HS, INIT, FEED, 16)
#define RECIPE_KS_skein512(HS,V)  (V)
#define RECIPE_RAW_skein512       RECIPE_RAWG
#define RECIPE_PAD_skein512       RECIPE_PADG

// PANAMA uses inc_hash_panama.cl. Its functions take little endian words as MD5 does, and its
// digest is state words 9 to 16, little endian. Its blocks, and therefore its HMAC blocks, contain
// 32 bytes.

#define RECIPE_HASH_PANAMA(X,HS,INIT,FEED)                                     \
{                                                                             \
  panama_ctx##X##_t ctx;                                                      \
                                                                              \
  INIT                                                                        \
                                                                              \
  FEED                                                                        \
                                                                              \
  panama_final##X (&ctx);                                                     \
                                                                              \
  for (u32 i = 0; i < 8; i++) raw[i] = ctx.st[9 + i];                         \
}

#define RECIPE_LEN_panama    32
#define RECIPE_BLOCK_panama  32
#define RECIPE_UPD_panama(X)  panama_update##X
#define RECIPE_UPDW_panama(X) panama_update##X##_utf16le
#define RECIPE_UPDG_panama    panama_update_global
#define RECIPE_UPDWG_panama   panama_update_global_utf16le
#define RECIPE_UPDP_panama(X) panama_update##X
#define RECIPE_PBUF_panama    w
#define RECIPE_UPDS_panama(X) panama_update##X
#define RECIPE_SBUF_panama    s
#define RECIPE_CTX_panama(X)  panama_ctx##X##_t
#define RECIPE_INIT_panama(X) panama_init##X (&ctx);
#define RECIPE_HASH_panama(X,HS,INIT,FEED) RECIPE_HASH_PANAMA (X, HS, INIT, FEED)
#define RECIPE_KS_panama(HS,V)  (V)
#define RECIPE_RAW_panama       RECIPE_RAWG
#define RECIPE_PAD_panama       RECIPE_PADG

// The families from BLAKE on copy their digest into raw with one of these macros. P is the prefix
// of the family's functions and context. W32 reads NW little endian words of member M from word
// OFF on, W32S reads big endian words, W64 reads the 64 bit words of h from word OFF on, low half
// first, and W64S reads big endian 64 bit words of h.

#define RECIPE_HASH_W32(P,M,OFF,X,HS,INIT,FEED,NW)                            \
{                                                                             \
  P##_ctx##X##_t ctx;                                                         \
                                                                              \
  INIT                                                                        \
                                                                              \
  FEED                                                                        \
                                                                              \
  P##_final##X (&ctx);                                                        \
                                                                              \
  for (u32 i = 0; i < (NW); i++) raw[i] = ctx.M[(OFF) + i];                   \
}

#define RECIPE_HASH_W32S(P,X,HS,INIT,FEED,NW)                                 \
{                                                                             \
  P##_ctx##X##_t ctx;                                                         \
                                                                              \
  INIT                                                                        \
                                                                              \
  FEED                                                                        \
                                                                              \
  P##_final##X (&ctx);                                                        \
                                                                              \
  for (u32 i = 0; i < (NW); i++) raw[i] = hc_swap32##HS (ctx.h[i]);           \
}

#define RECIPE_HASH_W64(P,OFF,X,HS,INIT,FEED,NW)                                      \
{                                                                                     \
  P##_ctx##X##_t ctx;                                                                 \
                                                                                      \
  INIT                                                                                \
                                                                                      \
  FEED                                                                                \
                                                                                      \
  P##_final##X (&ctx);                                                                \
                                                                                      \
  for (u32 i = 0; i < ((NW) / 2); i++)                                                \
  {                                                                                   \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[(OFF) + i]);                            \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[(OFF) + i]);                            \
  }                                                                                   \
                                                                                      \
  if (((NW) & 1) == 1) raw[(NW) - 1] = l32_from_64##HS (ctx.h[(OFF) + ((NW) / 2)]);   \
}

#define RECIPE_HASH_W64S(P,X,HS,INIT,FEED,NW)                                 \
{                                                                             \
  P##_ctx##X##_t ctx;                                                         \
                                                                              \
  INIT                                                                        \
                                                                              \
  FEED                                                                        \
                                                                              \
  P##_final##X (&ctx);                                                        \
                                                                              \
  for (u32 i = 0; i < ((NW) / 2); i++)                                        \
  {                                                                           \
    raw[(i * 2) + 0] = hc_swap32##HS (h32_from_64##HS (ctx.h[i]));            \
    raw[(i * 2) + 1] = hc_swap32##HS (l32_from_64##HS (ctx.h[i]));            \
  }                                                                           \
}

// BLAKE uses inc_hash_blake.cl, whose 32 bit core serves blake224 and blake256 and whose 64 bit core
// serves blake384 and blake512. Its digest is the first words of h, big endian. Its blocks, and
// therefore its HMAC blocks, contain 64 and 128 bytes.

#define RECIPE_LEN_blake224    28
#define RECIPE_BLOCK_blake224  64
#define RECIPE_UPD_blake224(X)  blake256_update##X
#define RECIPE_UPDW_blake224(X) blake256_update##X##_utf16le
#define RECIPE_UPDG_blake224    blake256_update_global
#define RECIPE_UPDWG_blake224   blake256_update_global_utf16le
#define RECIPE_UPDP_blake224(X) blake256_update##X
#define RECIPE_PBUF_blake224    w
#define RECIPE_UPDS_blake224(X) blake256_update##X
#define RECIPE_SBUF_blake224    s
#define RECIPE_CTX_blake224(X)  blake256_ctx##X##_t
#define RECIPE_INIT_blake224(X) blake256_init##X (&ctx, 28);
#define RECIPE_HASH_blake224(X,HS,INIT,FEED) RECIPE_HASH_W32S (blake256, X, HS, INIT, FEED, 7)
#define RECIPE_KS_blake224(HS,V)  (V)
#define RECIPE_RAW_blake224       RECIPE_RAWG
#define RECIPE_PAD_blake224       RECIPE_PADG

#define RECIPE_LEN_blake256    32
#define RECIPE_BLOCK_blake256  64
#define RECIPE_UPD_blake256(X)  blake256_update##X
#define RECIPE_UPDW_blake256(X) blake256_update##X##_utf16le
#define RECIPE_UPDG_blake256    blake256_update_global
#define RECIPE_UPDWG_blake256   blake256_update_global_utf16le
#define RECIPE_UPDP_blake256(X) blake256_update##X
#define RECIPE_PBUF_blake256    w
#define RECIPE_UPDS_blake256(X) blake256_update##X
#define RECIPE_SBUF_blake256    s
#define RECIPE_CTX_blake256(X)  blake256_ctx##X##_t
#define RECIPE_INIT_blake256(X) blake256_init##X (&ctx, 32);
#define RECIPE_HASH_blake256(X,HS,INIT,FEED) RECIPE_HASH_W32S (blake256, X, HS, INIT, FEED, 8)
#define RECIPE_KS_blake256(HS,V)  (V)
#define RECIPE_RAW_blake256       RECIPE_RAWG
#define RECIPE_PAD_blake256       RECIPE_PADG

#define RECIPE_LEN_blake384    48
#define RECIPE_BLOCK_blake384  128
#define RECIPE_UPD_blake384(X)  blake512_update##X
#define RECIPE_UPDW_blake384(X) blake512_update##X##_utf16le
#define RECIPE_UPDG_blake384    blake512_update_global
#define RECIPE_UPDWG_blake384   blake512_update_global_utf16le
#define RECIPE_UPDP_blake384(X) blake512_update##X
#define RECIPE_PBUF_blake384    w
#define RECIPE_UPDS_blake384(X) blake512_update##X
#define RECIPE_SBUF_blake384    s
#define RECIPE_CTX_blake384(X)  blake512_ctx##X##_t
#define RECIPE_INIT_blake384(X) blake512_init##X (&ctx, 48);
#define RECIPE_HASH_blake384(X,HS,INIT,FEED) RECIPE_HASH_W64S (blake512, X, HS, INIT, FEED, 12)
#define RECIPE_KS_blake384(HS,V)  (V)
#define RECIPE_RAW_blake384       RECIPE_RAWG
#define RECIPE_PAD_blake384       RECIPE_PADG

#define RECIPE_LEN_blake512    64
#define RECIPE_BLOCK_blake512  128
#define RECIPE_UPD_blake512(X)  blake512_update##X
#define RECIPE_UPDW_blake512(X) blake512_update##X##_utf16le
#define RECIPE_UPDG_blake512    blake512_update_global
#define RECIPE_UPDWG_blake512   blake512_update_global_utf16le
#define RECIPE_UPDP_blake512(X) blake512_update##X
#define RECIPE_PBUF_blake512    w
#define RECIPE_UPDS_blake512(X) blake512_update##X
#define RECIPE_SBUF_blake512    s
#define RECIPE_CTX_blake512(X)  blake512_ctx##X##_t
#define RECIPE_INIT_blake512(X) blake512_init##X (&ctx, 64);
#define RECIPE_HASH_blake512(X,HS,INIT,FEED) RECIPE_HASH_W64S (blake512, X, HS, INIT, FEED, 16)
#define RECIPE_KS_blake512(HS,V)  (V)
#define RECIPE_RAW_blake512       RECIPE_RAWG
#define RECIPE_PAD_blake512       RECIPE_PADG

// Blue Midnight Wish uses inc_hash_bmw.cl, with a 32 bit core for bmw224 and bmw256 and a 64 bit
// core for bmw384 and bmw512. Its digest is the first words of h, little endian. Its blocks, and
// therefore its HMAC blocks, contain 64 and 128 bytes.

#define RECIPE_LEN_bmw224    28
#define RECIPE_BLOCK_bmw224  64
#define RECIPE_UPD_bmw224(X)  bmw256_update##X
#define RECIPE_UPDW_bmw224(X) bmw256_update##X##_utf16le
#define RECIPE_UPDG_bmw224    bmw256_update_global
#define RECIPE_UPDWG_bmw224   bmw256_update_global_utf16le
#define RECIPE_UPDP_bmw224(X) bmw256_update##X
#define RECIPE_PBUF_bmw224    w
#define RECIPE_UPDS_bmw224(X) bmw256_update##X
#define RECIPE_SBUF_bmw224    s
#define RECIPE_CTX_bmw224(X)  bmw256_ctx##X##_t
#define RECIPE_INIT_bmw224(X) bmw256_init##X (&ctx, 28);
#define RECIPE_HASH_bmw224(X,HS,INIT,FEED) RECIPE_HASH_W32 (bmw256, h, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_bmw224(HS,V)  (V)
#define RECIPE_RAW_bmw224       RECIPE_RAWG
#define RECIPE_PAD_bmw224       RECIPE_PADG

#define RECIPE_LEN_bmw256    32
#define RECIPE_BLOCK_bmw256  64
#define RECIPE_UPD_bmw256(X)  bmw256_update##X
#define RECIPE_UPDW_bmw256(X) bmw256_update##X##_utf16le
#define RECIPE_UPDG_bmw256    bmw256_update_global
#define RECIPE_UPDWG_bmw256   bmw256_update_global_utf16le
#define RECIPE_UPDP_bmw256(X) bmw256_update##X
#define RECIPE_PBUF_bmw256    w
#define RECIPE_UPDS_bmw256(X) bmw256_update##X
#define RECIPE_SBUF_bmw256    s
#define RECIPE_CTX_bmw256(X)  bmw256_ctx##X##_t
#define RECIPE_INIT_bmw256(X) bmw256_init##X (&ctx, 32);
#define RECIPE_HASH_bmw256(X,HS,INIT,FEED) RECIPE_HASH_W32 (bmw256, h, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_bmw256(HS,V)  (V)
#define RECIPE_RAW_bmw256       RECIPE_RAWG
#define RECIPE_PAD_bmw256       RECIPE_PADG

#define RECIPE_LEN_bmw384    48
#define RECIPE_BLOCK_bmw384  128
#define RECIPE_UPD_bmw384(X)  bmw512_update##X
#define RECIPE_UPDW_bmw384(X) bmw512_update##X##_utf16le
#define RECIPE_UPDG_bmw384    bmw512_update_global
#define RECIPE_UPDWG_bmw384   bmw512_update_global_utf16le
#define RECIPE_UPDP_bmw384(X) bmw512_update##X
#define RECIPE_PBUF_bmw384    w
#define RECIPE_UPDS_bmw384(X) bmw512_update##X
#define RECIPE_SBUF_bmw384    s
#define RECIPE_CTX_bmw384(X)  bmw512_ctx##X##_t
#define RECIPE_INIT_bmw384(X) bmw512_init##X (&ctx, 48);
#define RECIPE_HASH_bmw384(X,HS,INIT,FEED) RECIPE_HASH_W64 (bmw512, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_bmw384(HS,V)  (V)
#define RECIPE_RAW_bmw384       RECIPE_RAWG
#define RECIPE_PAD_bmw384       RECIPE_PADG

#define RECIPE_LEN_bmw512    64
#define RECIPE_BLOCK_bmw512  128
#define RECIPE_UPD_bmw512(X)  bmw512_update##X
#define RECIPE_UPDW_bmw512(X) bmw512_update##X##_utf16le
#define RECIPE_UPDG_bmw512    bmw512_update_global
#define RECIPE_UPDWG_bmw512   bmw512_update_global_utf16le
#define RECIPE_UPDP_bmw512(X) bmw512_update##X
#define RECIPE_PBUF_bmw512    w
#define RECIPE_UPDS_bmw512(X) bmw512_update##X
#define RECIPE_SBUF_bmw512    s
#define RECIPE_CTX_bmw512(X)  bmw512_ctx##X##_t
#define RECIPE_INIT_bmw512(X) bmw512_init##X (&ctx, 64);
#define RECIPE_HASH_bmw512(X,HS,INIT,FEED) RECIPE_HASH_W64 (bmw512, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_bmw512(HS,V)  (V)
#define RECIPE_RAW_bmw512       RECIPE_RAWG
#define RECIPE_PAD_bmw512       RECIPE_PADG

// CubeHash16/32 uses inc_hash_cubehash.cl. Its digest is the first words of x, little endian. Its
// blocks, and therefore its HMAC blocks, contain 32 bytes, fewer than the digests of cube384 and
// cube512. RECIPE_KEYBLOCK keeps all bytes of a hashed key.

#define RECIPE_LEN_cube224    28
#define RECIPE_BLOCK_cube224  32
#define RECIPE_UPD_cube224(X)  cubehash_update##X
#define RECIPE_UPDW_cube224(X) cubehash_update##X##_utf16le
#define RECIPE_UPDG_cube224    cubehash_update_global
#define RECIPE_UPDWG_cube224   cubehash_update_global_utf16le
#define RECIPE_UPDP_cube224(X) cubehash_update##X
#define RECIPE_PBUF_cube224    w
#define RECIPE_UPDS_cube224(X) cubehash_update##X
#define RECIPE_SBUF_cube224    s
#define RECIPE_CTX_cube224(X)  cubehash_ctx##X##_t
#define RECIPE_INIT_cube224(X) cubehash_init##X (&ctx, 28);
#define RECIPE_HASH_cube224(X,HS,INIT,FEED) RECIPE_HASH_W32 (cubehash, x, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_cube224(HS,V)  (V)
#define RECIPE_RAW_cube224       RECIPE_RAWG
#define RECIPE_PAD_cube224       RECIPE_PADG

#define RECIPE_LEN_cube256    32
#define RECIPE_BLOCK_cube256  32
#define RECIPE_UPD_cube256(X)  cubehash_update##X
#define RECIPE_UPDW_cube256(X) cubehash_update##X##_utf16le
#define RECIPE_UPDG_cube256    cubehash_update_global
#define RECIPE_UPDWG_cube256   cubehash_update_global_utf16le
#define RECIPE_UPDP_cube256(X) cubehash_update##X
#define RECIPE_PBUF_cube256    w
#define RECIPE_UPDS_cube256(X) cubehash_update##X
#define RECIPE_SBUF_cube256    s
#define RECIPE_CTX_cube256(X)  cubehash_ctx##X##_t
#define RECIPE_INIT_cube256(X) cubehash_init##X (&ctx, 32);
#define RECIPE_HASH_cube256(X,HS,INIT,FEED) RECIPE_HASH_W32 (cubehash, x, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_cube256(HS,V)  (V)
#define RECIPE_RAW_cube256       RECIPE_RAWG
#define RECIPE_PAD_cube256       RECIPE_PADG

#define RECIPE_LEN_cube384    48
#define RECIPE_BLOCK_cube384  32
#define RECIPE_UPD_cube384(X)  cubehash_update##X
#define RECIPE_UPDW_cube384(X) cubehash_update##X##_utf16le
#define RECIPE_UPDG_cube384    cubehash_update_global
#define RECIPE_UPDWG_cube384   cubehash_update_global_utf16le
#define RECIPE_UPDP_cube384(X) cubehash_update##X
#define RECIPE_PBUF_cube384    w
#define RECIPE_UPDS_cube384(X) cubehash_update##X
#define RECIPE_SBUF_cube384    s
#define RECIPE_CTX_cube384(X)  cubehash_ctx##X##_t
#define RECIPE_INIT_cube384(X) cubehash_init##X (&ctx, 48);
#define RECIPE_HASH_cube384(X,HS,INIT,FEED) RECIPE_HASH_W32 (cubehash, x, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_cube384(HS,V)  (V)
#define RECIPE_RAW_cube384       RECIPE_RAWG
#define RECIPE_PAD_cube384       RECIPE_PADG

#define RECIPE_LEN_cube512    64
#define RECIPE_BLOCK_cube512  32
#define RECIPE_UPD_cube512(X)  cubehash_update##X
#define RECIPE_UPDW_cube512(X) cubehash_update##X##_utf16le
#define RECIPE_UPDG_cube512    cubehash_update_global
#define RECIPE_UPDWG_cube512   cubehash_update_global_utf16le
#define RECIPE_UPDP_cube512(X) cubehash_update##X
#define RECIPE_PBUF_cube512    w
#define RECIPE_UPDS_cube512(X) cubehash_update##X
#define RECIPE_SBUF_cube512    s
#define RECIPE_CTX_cube512(X)  cubehash_ctx##X##_t
#define RECIPE_INIT_cube512(X) cubehash_init##X (&ctx, 64);
#define RECIPE_HASH_cube512(X,HS,INIT,FEED) RECIPE_HASH_W32 (cubehash, x, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_cube512(HS,V)  (V)
#define RECIPE_RAW_cube512       RECIPE_RAWG
#define RECIPE_PAD_cube512       RECIPE_PADG

// ECHO uses inc_hash_echo.cl, with ECHO-256 for echo224 and echo256 and ECHO-512 for echo384 and
// echo512. It reads the AES tables of inc_cipher_aes.cl, see RECIPE_TE. Its digest is the first
// words of v, little endian. Its blocks, and therefore its HMAC blocks, contain 192 and 128
// bytes.

#define RECIPE_LEN_echo224    28
#define RECIPE_BLOCK_echo224  192
#define RECIPE_UPD_echo224(X)  echo256_update##X
#define RECIPE_UPDW_echo224(X) echo256_update##X##_utf16le
#define RECIPE_UPDG_echo224    echo256_update_global
#define RECIPE_UPDWG_echo224   echo256_update_global_utf16le
#define RECIPE_UPDP_echo224(X) echo256_update##X
#define RECIPE_PBUF_echo224    w
#define RECIPE_UPDS_echo224(X) echo256_update##X
#define RECIPE_SBUF_echo224    s
#define RECIPE_CTX_echo224(X)  echo256_ctx##X##_t
#define RECIPE_INIT_echo224(X) echo256_init##X (&ctx, 28, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_echo224(X,HS,INIT,FEED) RECIPE_HASH_W32 (echo256, v, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_echo224(HS,V)  (V)
#define RECIPE_RAW_echo224       RECIPE_RAWG
#define RECIPE_PAD_echo224       RECIPE_PADG

#define RECIPE_LEN_echo256    32
#define RECIPE_BLOCK_echo256  192
#define RECIPE_UPD_echo256(X)  echo256_update##X
#define RECIPE_UPDW_echo256(X) echo256_update##X##_utf16le
#define RECIPE_UPDG_echo256    echo256_update_global
#define RECIPE_UPDWG_echo256   echo256_update_global_utf16le
#define RECIPE_UPDP_echo256(X) echo256_update##X
#define RECIPE_PBUF_echo256    w
#define RECIPE_UPDS_echo256(X) echo256_update##X
#define RECIPE_SBUF_echo256    s
#define RECIPE_CTX_echo256(X)  echo256_ctx##X##_t
#define RECIPE_INIT_echo256(X) echo256_init##X (&ctx, 32, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_echo256(X,HS,INIT,FEED) RECIPE_HASH_W32 (echo256, v, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_echo256(HS,V)  (V)
#define RECIPE_RAW_echo256       RECIPE_RAWG
#define RECIPE_PAD_echo256       RECIPE_PADG

#define RECIPE_LEN_echo384    48
#define RECIPE_BLOCK_echo384  128
#define RECIPE_UPD_echo384(X)  echo512_update##X
#define RECIPE_UPDW_echo384(X) echo512_update##X##_utf16le
#define RECIPE_UPDG_echo384    echo512_update_global
#define RECIPE_UPDWG_echo384   echo512_update_global_utf16le
#define RECIPE_UPDP_echo384(X) echo512_update##X
#define RECIPE_PBUF_echo384    w
#define RECIPE_UPDS_echo384(X) echo512_update##X
#define RECIPE_SBUF_echo384    s
#define RECIPE_CTX_echo384(X)  echo512_ctx##X##_t
#define RECIPE_INIT_echo384(X) echo512_init##X (&ctx, 48, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_echo384(X,HS,INIT,FEED) RECIPE_HASH_W32 (echo512, v, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_echo384(HS,V)  (V)
#define RECIPE_RAW_echo384       RECIPE_RAWG
#define RECIPE_PAD_echo384       RECIPE_PADG

#define RECIPE_LEN_echo512    64
#define RECIPE_BLOCK_echo512  128
#define RECIPE_UPD_echo512(X)  echo512_update##X
#define RECIPE_UPDW_echo512(X) echo512_update##X##_utf16le
#define RECIPE_UPDG_echo512    echo512_update_global
#define RECIPE_UPDWG_echo512   echo512_update_global_utf16le
#define RECIPE_UPDP_echo512(X) echo512_update##X
#define RECIPE_PBUF_echo512    w
#define RECIPE_UPDS_echo512(X) echo512_update##X
#define RECIPE_SBUF_echo512    s
#define RECIPE_CTX_echo512(X)  echo512_ctx##X##_t
#define RECIPE_INIT_echo512(X) echo512_init##X (&ctx, 64, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_echo512(X,HS,INIT,FEED) RECIPE_HASH_W32 (echo512, v, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_echo512(HS,V)  (V)
#define RECIPE_RAW_echo512       RECIPE_RAWG
#define RECIPE_PAD_echo512       RECIPE_PADG

// Fugue uses inc_hash_fugue.cl and its table, see RECIPE_FUGUE. Its digest is the first words of h,
// little endian. It takes 4 bytes at a time and has no hmac_ form.

#define RECIPE_LEN_fugue224    28
#define RECIPE_BLOCK_fugue224  4
#define RECIPE_UPD_fugue224(X)  fugue_update##X
#define RECIPE_UPDW_fugue224(X) fugue_update##X##_utf16le
#define RECIPE_UPDG_fugue224    fugue_update_global
#define RECIPE_UPDWG_fugue224   fugue_update_global_utf16le
#define RECIPE_UPDP_fugue224(X) fugue_update##X
#define RECIPE_PBUF_fugue224    w
#define RECIPE_UPDS_fugue224(X) fugue_update##X
#define RECIPE_SBUF_fugue224    s
#define RECIPE_CTX_fugue224(X)  fugue_ctx##X##_t
#define RECIPE_INIT_fugue224(X) fugue_init##X (&ctx, 28, st->fugue);
#define RECIPE_HASH_fugue224(X,HS,INIT,FEED) RECIPE_HASH_W32 (fugue, h, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_fugue224(HS,V)  (V)
#define RECIPE_RAW_fugue224       RECIPE_RAWG
#define RECIPE_PAD_fugue224       RECIPE_PADG

#define RECIPE_LEN_fugue256    32
#define RECIPE_BLOCK_fugue256  4
#define RECIPE_UPD_fugue256(X)  fugue_update##X
#define RECIPE_UPDW_fugue256(X) fugue_update##X##_utf16le
#define RECIPE_UPDG_fugue256    fugue_update_global
#define RECIPE_UPDWG_fugue256   fugue_update_global_utf16le
#define RECIPE_UPDP_fugue256(X) fugue_update##X
#define RECIPE_PBUF_fugue256    w
#define RECIPE_UPDS_fugue256(X) fugue_update##X
#define RECIPE_SBUF_fugue256    s
#define RECIPE_CTX_fugue256(X)  fugue_ctx##X##_t
#define RECIPE_INIT_fugue256(X) fugue_init##X (&ctx, 32, st->fugue);
#define RECIPE_HASH_fugue256(X,HS,INIT,FEED) RECIPE_HASH_W32 (fugue, h, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_fugue256(HS,V)  (V)
#define RECIPE_RAW_fugue256       RECIPE_RAWG
#define RECIPE_PAD_fugue256       RECIPE_PADG

#define RECIPE_LEN_fugue384    48
#define RECIPE_BLOCK_fugue384  4
#define RECIPE_UPD_fugue384(X)  fugue_update##X
#define RECIPE_UPDW_fugue384(X) fugue_update##X##_utf16le
#define RECIPE_UPDG_fugue384    fugue_update_global
#define RECIPE_UPDWG_fugue384   fugue_update_global_utf16le
#define RECIPE_UPDP_fugue384(X) fugue_update##X
#define RECIPE_PBUF_fugue384    w
#define RECIPE_UPDS_fugue384(X) fugue_update##X
#define RECIPE_SBUF_fugue384    s
#define RECIPE_CTX_fugue384(X)  fugue_ctx##X##_t
#define RECIPE_INIT_fugue384(X) fugue_init##X (&ctx, 48, st->fugue);
#define RECIPE_HASH_fugue384(X,HS,INIT,FEED) RECIPE_HASH_W32 (fugue, h, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_fugue384(HS,V)  (V)
#define RECIPE_RAW_fugue384       RECIPE_RAWG
#define RECIPE_PAD_fugue384       RECIPE_PADG

#define RECIPE_LEN_fugue512    64
#define RECIPE_BLOCK_fugue512  4
#define RECIPE_UPD_fugue512(X)  fugue_update##X
#define RECIPE_UPDW_fugue512(X) fugue_update##X##_utf16le
#define RECIPE_UPDG_fugue512    fugue_update_global
#define RECIPE_UPDWG_fugue512   fugue_update_global_utf16le
#define RECIPE_UPDP_fugue512(X) fugue_update##X
#define RECIPE_PBUF_fugue512    w
#define RECIPE_UPDS_fugue512(X) fugue_update##X
#define RECIPE_SBUF_fugue512    s
#define RECIPE_CTX_fugue512(X)  fugue_ctx##X##_t
#define RECIPE_INIT_fugue512(X) fugue_init##X (&ctx, 64, st->fugue);
#define RECIPE_HASH_fugue512(X,HS,INIT,FEED) RECIPE_HASH_W32 (fugue, h, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_fugue512(HS,V)  (V)
#define RECIPE_RAW_fugue512       RECIPE_RAWG
#define RECIPE_PAD_fugue512       RECIPE_PADG

// Groestl uses inc_hash_groestl.cl and its table, see RECIPE_GROESTL, with the 512 bit permutation
// for groestl224 and groestl256 and the 1024 bit permutation for groestl384 and groestl512. Its
// digest is the first bytes of h, little endian. Its blocks, and therefore its HMAC blocks, contain
// 64 and 128 bytes.

#define RECIPE_LEN_groestl224    28
#define RECIPE_BLOCK_groestl224  64
#define RECIPE_UPD_groestl224(X)  groestl256_update##X
#define RECIPE_UPDW_groestl224(X) groestl256_update##X##_utf16le
#define RECIPE_UPDG_groestl224    groestl256_update_global
#define RECIPE_UPDWG_groestl224   groestl256_update_global_utf16le
#define RECIPE_UPDP_groestl224(X) groestl256_update##X
#define RECIPE_PBUF_groestl224    w
#define RECIPE_UPDS_groestl224(X) groestl256_update##X
#define RECIPE_SBUF_groestl224    s
#define RECIPE_CTX_groestl224(X)  groestl256_ctx##X##_t
#define RECIPE_INIT_groestl224(X) groestl256_init##X (&ctx, 28, st->groestl);
#define RECIPE_HASH_groestl224(X,HS,INIT,FEED) RECIPE_HASH_W64 (groestl256, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_groestl224(HS,V)  (V)
#define RECIPE_RAW_groestl224       RECIPE_RAWG
#define RECIPE_PAD_groestl224       RECIPE_PADG

#define RECIPE_LEN_groestl256    32
#define RECIPE_BLOCK_groestl256  64
#define RECIPE_UPD_groestl256(X)  groestl256_update##X
#define RECIPE_UPDW_groestl256(X) groestl256_update##X##_utf16le
#define RECIPE_UPDG_groestl256    groestl256_update_global
#define RECIPE_UPDWG_groestl256   groestl256_update_global_utf16le
#define RECIPE_UPDP_groestl256(X) groestl256_update##X
#define RECIPE_PBUF_groestl256    w
#define RECIPE_UPDS_groestl256(X) groestl256_update##X
#define RECIPE_SBUF_groestl256    s
#define RECIPE_CTX_groestl256(X)  groestl256_ctx##X##_t
#define RECIPE_INIT_groestl256(X) groestl256_init##X (&ctx, 32, st->groestl);
#define RECIPE_HASH_groestl256(X,HS,INIT,FEED) RECIPE_HASH_W64 (groestl256, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_groestl256(HS,V)  (V)
#define RECIPE_RAW_groestl256       RECIPE_RAWG
#define RECIPE_PAD_groestl256       RECIPE_PADG

#define RECIPE_LEN_groestl384    48
#define RECIPE_BLOCK_groestl384  128
#define RECIPE_UPD_groestl384(X)  groestl512_update##X
#define RECIPE_UPDW_groestl384(X) groestl512_update##X##_utf16le
#define RECIPE_UPDG_groestl384    groestl512_update_global
#define RECIPE_UPDWG_groestl384   groestl512_update_global_utf16le
#define RECIPE_UPDP_groestl384(X) groestl512_update##X
#define RECIPE_PBUF_groestl384    w
#define RECIPE_UPDS_groestl384(X) groestl512_update##X
#define RECIPE_SBUF_groestl384    s
#define RECIPE_CTX_groestl384(X)  groestl512_ctx##X##_t
#define RECIPE_INIT_groestl384(X) groestl512_init##X (&ctx, 48, st->groestl);
#define RECIPE_HASH_groestl384(X,HS,INIT,FEED) RECIPE_HASH_W64 (groestl512, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_groestl384(HS,V)  (V)
#define RECIPE_RAW_groestl384       RECIPE_RAWG
#define RECIPE_PAD_groestl384       RECIPE_PADG

#define RECIPE_LEN_groestl512    64
#define RECIPE_BLOCK_groestl512  128
#define RECIPE_UPD_groestl512(X)  groestl512_update##X
#define RECIPE_UPDW_groestl512(X) groestl512_update##X##_utf16le
#define RECIPE_UPDG_groestl512    groestl512_update_global
#define RECIPE_UPDWG_groestl512   groestl512_update_global_utf16le
#define RECIPE_UPDP_groestl512(X) groestl512_update##X
#define RECIPE_PBUF_groestl512    w
#define RECIPE_UPDS_groestl512(X) groestl512_update##X
#define RECIPE_SBUF_groestl512    s
#define RECIPE_CTX_groestl512(X)  groestl512_ctx##X##_t
#define RECIPE_INIT_groestl512(X) groestl512_init##X (&ctx, 64, st->groestl);
#define RECIPE_HASH_groestl512(X,HS,INIT,FEED) RECIPE_HASH_W64 (groestl512, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_groestl512(HS,V)  (V)
#define RECIPE_RAW_groestl512       RECIPE_RAWG
#define RECIPE_PAD_groestl512       RECIPE_PADG

// Hamsi uses inc_hash_hamsi.cl, with Hamsi-256 for hamsi224 and hamsi256 and Hamsi-512 for hamsi384
// and hamsi512. Its digest is the first words of h, little endian. It takes 4 or 8 bytes at a time
// and has no hmac_ form.

#define RECIPE_LEN_hamsi224    28
#define RECIPE_BLOCK_hamsi224  4
#define RECIPE_UPD_hamsi224(X)  hamsi256_update##X
#define RECIPE_UPDW_hamsi224(X) hamsi256_update##X##_utf16le
#define RECIPE_UPDG_hamsi224    hamsi256_update_global
#define RECIPE_UPDWG_hamsi224   hamsi256_update_global_utf16le
#define RECIPE_UPDP_hamsi224(X) hamsi256_update##X
#define RECIPE_PBUF_hamsi224    w
#define RECIPE_UPDS_hamsi224(X) hamsi256_update##X
#define RECIPE_SBUF_hamsi224    s
#define RECIPE_CTX_hamsi224(X)  hamsi256_ctx##X##_t
#define RECIPE_INIT_hamsi224(X) hamsi256_init##X (&ctx, 28);
#define RECIPE_HASH_hamsi224(X,HS,INIT,FEED) RECIPE_HASH_W32 (hamsi256, h, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_hamsi224(HS,V)  (V)
#define RECIPE_RAW_hamsi224       RECIPE_RAWG
#define RECIPE_PAD_hamsi224       RECIPE_PADG

#define RECIPE_LEN_hamsi256    32
#define RECIPE_BLOCK_hamsi256  4
#define RECIPE_UPD_hamsi256(X)  hamsi256_update##X
#define RECIPE_UPDW_hamsi256(X) hamsi256_update##X##_utf16le
#define RECIPE_UPDG_hamsi256    hamsi256_update_global
#define RECIPE_UPDWG_hamsi256   hamsi256_update_global_utf16le
#define RECIPE_UPDP_hamsi256(X) hamsi256_update##X
#define RECIPE_PBUF_hamsi256    w
#define RECIPE_UPDS_hamsi256(X) hamsi256_update##X
#define RECIPE_SBUF_hamsi256    s
#define RECIPE_CTX_hamsi256(X)  hamsi256_ctx##X##_t
#define RECIPE_INIT_hamsi256(X) hamsi256_init##X (&ctx, 32);
#define RECIPE_HASH_hamsi256(X,HS,INIT,FEED) RECIPE_HASH_W32 (hamsi256, h, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_hamsi256(HS,V)  (V)
#define RECIPE_RAW_hamsi256       RECIPE_RAWG
#define RECIPE_PAD_hamsi256       RECIPE_PADG

#define RECIPE_LEN_hamsi384    48
#define RECIPE_BLOCK_hamsi384  8
#define RECIPE_UPD_hamsi384(X)  hamsi512_update##X
#define RECIPE_UPDW_hamsi384(X) hamsi512_update##X##_utf16le
#define RECIPE_UPDG_hamsi384    hamsi512_update_global
#define RECIPE_UPDWG_hamsi384   hamsi512_update_global_utf16le
#define RECIPE_UPDP_hamsi384(X) hamsi512_update##X
#define RECIPE_PBUF_hamsi384    w
#define RECIPE_UPDS_hamsi384(X) hamsi512_update##X
#define RECIPE_SBUF_hamsi384    s
#define RECIPE_CTX_hamsi384(X)  hamsi512_ctx##X##_t
#define RECIPE_INIT_hamsi384(X) hamsi512_init##X (&ctx, 48);
#define RECIPE_HASH_hamsi384(X,HS,INIT,FEED) RECIPE_HASH_W32 (hamsi512, h, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_hamsi384(HS,V)  (V)
#define RECIPE_RAW_hamsi384       RECIPE_RAWG
#define RECIPE_PAD_hamsi384       RECIPE_PADG

#define RECIPE_LEN_hamsi512    64
#define RECIPE_BLOCK_hamsi512  8
#define RECIPE_UPD_hamsi512(X)  hamsi512_update##X
#define RECIPE_UPDW_hamsi512(X) hamsi512_update##X##_utf16le
#define RECIPE_UPDG_hamsi512    hamsi512_update_global
#define RECIPE_UPDWG_hamsi512   hamsi512_update_global_utf16le
#define RECIPE_UPDP_hamsi512(X) hamsi512_update##X
#define RECIPE_PBUF_hamsi512    w
#define RECIPE_UPDS_hamsi512(X) hamsi512_update##X
#define RECIPE_SBUF_hamsi512    s
#define RECIPE_CTX_hamsi512(X)  hamsi512_ctx##X##_t
#define RECIPE_INIT_hamsi512(X) hamsi512_init##X (&ctx, 64);
#define RECIPE_HASH_hamsi512(X,HS,INIT,FEED) RECIPE_HASH_W32 (hamsi512, h, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_hamsi512(HS,V)  (V)
#define RECIPE_RAW_hamsi512       RECIPE_RAWG
#define RECIPE_PAD_hamsi512       RECIPE_PADG

// JH uses inc_hash_jh.cl. Its digest is the last bytes of the 128 byte state h, little endian. Its
// blocks, and therefore its HMAC blocks, contain 64 bytes.

#define RECIPE_HASH_JH(X,HS,INIT,FEED,NW)                                             \
{                                                                                     \
  jh_ctx##X##_t ctx;                                                                  \
                                                                                      \
  INIT                                                                                \
                                                                                      \
  FEED                                                                                \
                                                                                      \
  jh_final##X (&ctx);                                                                 \
                                                                                      \
  if (((NW) & 1) == 1) raw[0] = h32_from_64##HS (ctx.h[(32 - (NW)) / 2]);             \
                                                                                      \
  for (u32 i = 0; i < ((NW) / 2); i++)                                                \
  {                                                                                   \
    raw[((NW) & 1) + (i * 2) + 0] = l32_from_64##HS (ctx.h[16 - ((NW) / 2) + i]);     \
    raw[((NW) & 1) + (i * 2) + 1] = h32_from_64##HS (ctx.h[16 - ((NW) / 2) + i]);     \
  }                                                                                   \
}

#define RECIPE_LEN_jh224    28
#define RECIPE_BLOCK_jh224  64
#define RECIPE_UPD_jh224(X)  jh_update##X
#define RECIPE_UPDW_jh224(X) jh_update##X##_utf16le
#define RECIPE_UPDG_jh224    jh_update_global
#define RECIPE_UPDWG_jh224   jh_update_global_utf16le
#define RECIPE_UPDP_jh224(X) jh_update##X
#define RECIPE_PBUF_jh224    w
#define RECIPE_UPDS_jh224(X) jh_update##X
#define RECIPE_SBUF_jh224    s
#define RECIPE_CTX_jh224(X)  jh_ctx##X##_t
#define RECIPE_INIT_jh224(X) jh_init##X (&ctx, 28);
#define RECIPE_HASH_jh224(X,HS,INIT,FEED) RECIPE_HASH_JH (X, HS, INIT, FEED, 7)
#define RECIPE_KS_jh224(HS,V)  (V)
#define RECIPE_RAW_jh224       RECIPE_RAWG
#define RECIPE_PAD_jh224       RECIPE_PADG

#define RECIPE_LEN_jh256    32
#define RECIPE_BLOCK_jh256  64
#define RECIPE_UPD_jh256(X)  jh_update##X
#define RECIPE_UPDW_jh256(X) jh_update##X##_utf16le
#define RECIPE_UPDG_jh256    jh_update_global
#define RECIPE_UPDWG_jh256   jh_update_global_utf16le
#define RECIPE_UPDP_jh256(X) jh_update##X
#define RECIPE_PBUF_jh256    w
#define RECIPE_UPDS_jh256(X) jh_update##X
#define RECIPE_SBUF_jh256    s
#define RECIPE_CTX_jh256(X)  jh_ctx##X##_t
#define RECIPE_INIT_jh256(X) jh_init##X (&ctx, 32);
#define RECIPE_HASH_jh256(X,HS,INIT,FEED) RECIPE_HASH_JH (X, HS, INIT, FEED, 8)
#define RECIPE_KS_jh256(HS,V)  (V)
#define RECIPE_RAW_jh256       RECIPE_RAWG
#define RECIPE_PAD_jh256       RECIPE_PADG

#define RECIPE_LEN_jh384    48
#define RECIPE_BLOCK_jh384  64
#define RECIPE_UPD_jh384(X)  jh_update##X
#define RECIPE_UPDW_jh384(X) jh_update##X##_utf16le
#define RECIPE_UPDG_jh384    jh_update_global
#define RECIPE_UPDWG_jh384   jh_update_global_utf16le
#define RECIPE_UPDP_jh384(X) jh_update##X
#define RECIPE_PBUF_jh384    w
#define RECIPE_UPDS_jh384(X) jh_update##X
#define RECIPE_SBUF_jh384    s
#define RECIPE_CTX_jh384(X)  jh_ctx##X##_t
#define RECIPE_INIT_jh384(X) jh_init##X (&ctx, 48);
#define RECIPE_HASH_jh384(X,HS,INIT,FEED) RECIPE_HASH_JH (X, HS, INIT, FEED, 12)
#define RECIPE_KS_jh384(HS,V)  (V)
#define RECIPE_RAW_jh384       RECIPE_RAWG
#define RECIPE_PAD_jh384       RECIPE_PADG

#define RECIPE_LEN_jh512    64
#define RECIPE_BLOCK_jh512  64
#define RECIPE_UPD_jh512(X)  jh_update##X
#define RECIPE_UPDW_jh512(X) jh_update##X##_utf16le
#define RECIPE_UPDG_jh512    jh_update_global
#define RECIPE_UPDWG_jh512   jh_update_global_utf16le
#define RECIPE_UPDP_jh512(X) jh_update##X
#define RECIPE_PBUF_jh512    w
#define RECIPE_UPDS_jh512(X) jh_update##X
#define RECIPE_SBUF_jh512    s
#define RECIPE_CTX_jh512(X)  jh_ctx##X##_t
#define RECIPE_INIT_jh512(X) jh_init##X (&ctx, 64);
#define RECIPE_HASH_jh512(X,HS,INIT,FEED) RECIPE_HASH_JH (X, HS, INIT, FEED, 16)
#define RECIPE_KS_jh512(HS,V)  (V)
#define RECIPE_RAW_jh512       RECIPE_RAWG
#define RECIPE_PAD_jh512       RECIPE_PADG

// Luffa uses inc_hash_luffa.cl. Its digest is the first words of h, big endian. Its blocks, and
// therefore its HMAC blocks, contain 32 bytes, fewer than the digests of luffa384 and luffa512.
// RECIPE_KEYBLOCK keeps all bytes of a hashed key.

#define RECIPE_LEN_luffa224    28
#define RECIPE_BLOCK_luffa224  32
#define RECIPE_UPD_luffa224(X)  luffa_update##X
#define RECIPE_UPDW_luffa224(X) luffa_update##X##_utf16le
#define RECIPE_UPDG_luffa224    luffa_update_global
#define RECIPE_UPDWG_luffa224   luffa_update_global_utf16le
#define RECIPE_UPDP_luffa224(X) luffa_update##X
#define RECIPE_PBUF_luffa224    w
#define RECIPE_UPDS_luffa224(X) luffa_update##X
#define RECIPE_SBUF_luffa224    s
#define RECIPE_CTX_luffa224(X)  luffa_ctx##X##_t
#define RECIPE_INIT_luffa224(X) luffa_init##X (&ctx, 28);
#define RECIPE_HASH_luffa224(X,HS,INIT,FEED) RECIPE_HASH_W32S (luffa, X, HS, INIT, FEED, 7)
#define RECIPE_KS_luffa224(HS,V)  (V)
#define RECIPE_RAW_luffa224       RECIPE_RAWG
#define RECIPE_PAD_luffa224       RECIPE_PADG

#define RECIPE_LEN_luffa256    32
#define RECIPE_BLOCK_luffa256  32
#define RECIPE_UPD_luffa256(X)  luffa_update##X
#define RECIPE_UPDW_luffa256(X) luffa_update##X##_utf16le
#define RECIPE_UPDG_luffa256    luffa_update_global
#define RECIPE_UPDWG_luffa256   luffa_update_global_utf16le
#define RECIPE_UPDP_luffa256(X) luffa_update##X
#define RECIPE_PBUF_luffa256    w
#define RECIPE_UPDS_luffa256(X) luffa_update##X
#define RECIPE_SBUF_luffa256    s
#define RECIPE_CTX_luffa256(X)  luffa_ctx##X##_t
#define RECIPE_INIT_luffa256(X) luffa_init##X (&ctx, 32);
#define RECIPE_HASH_luffa256(X,HS,INIT,FEED) RECIPE_HASH_W32S (luffa, X, HS, INIT, FEED, 8)
#define RECIPE_KS_luffa256(HS,V)  (V)
#define RECIPE_RAW_luffa256       RECIPE_RAWG
#define RECIPE_PAD_luffa256       RECIPE_PADG

#define RECIPE_LEN_luffa384    48
#define RECIPE_BLOCK_luffa384  32
#define RECIPE_UPD_luffa384(X)  luffa_update##X
#define RECIPE_UPDW_luffa384(X) luffa_update##X##_utf16le
#define RECIPE_UPDG_luffa384    luffa_update_global
#define RECIPE_UPDWG_luffa384   luffa_update_global_utf16le
#define RECIPE_UPDP_luffa384(X) luffa_update##X
#define RECIPE_PBUF_luffa384    w
#define RECIPE_UPDS_luffa384(X) luffa_update##X
#define RECIPE_SBUF_luffa384    s
#define RECIPE_CTX_luffa384(X)  luffa_ctx##X##_t
#define RECIPE_INIT_luffa384(X) luffa_init##X (&ctx, 48);
#define RECIPE_HASH_luffa384(X,HS,INIT,FEED) RECIPE_HASH_W32S (luffa, X, HS, INIT, FEED, 12)
#define RECIPE_KS_luffa384(HS,V)  (V)
#define RECIPE_RAW_luffa384       RECIPE_RAWG
#define RECIPE_PAD_luffa384       RECIPE_PADG

#define RECIPE_LEN_luffa512    64
#define RECIPE_BLOCK_luffa512  32
#define RECIPE_UPD_luffa512(X)  luffa_update##X
#define RECIPE_UPDW_luffa512(X) luffa_update##X##_utf16le
#define RECIPE_UPDG_luffa512    luffa_update_global
#define RECIPE_UPDWG_luffa512   luffa_update_global_utf16le
#define RECIPE_UPDP_luffa512(X) luffa_update##X
#define RECIPE_PBUF_luffa512    w
#define RECIPE_UPDS_luffa512(X) luffa_update##X
#define RECIPE_SBUF_luffa512    s
#define RECIPE_CTX_luffa512(X)  luffa_ctx##X##_t
#define RECIPE_INIT_luffa512(X) luffa_init##X (&ctx, 64);
#define RECIPE_HASH_luffa512(X,HS,INIT,FEED) RECIPE_HASH_W32S (luffa, X, HS, INIT, FEED, 16)
#define RECIPE_KS_luffa512(HS,V)  (V)
#define RECIPE_RAW_luffa512       RECIPE_RAWG
#define RECIPE_PAD_luffa512       RECIPE_PADG

// Shabal uses inc_hash_shabal.cl. Its digest is the last words of b, little endian. Its blocks, and
// therefore its HMAC blocks, contain 64 bytes.

#define RECIPE_LEN_shabal224    28
#define RECIPE_BLOCK_shabal224  64
#define RECIPE_UPD_shabal224(X)  shabal_update##X
#define RECIPE_UPDW_shabal224(X) shabal_update##X##_utf16le
#define RECIPE_UPDG_shabal224    shabal_update_global
#define RECIPE_UPDWG_shabal224   shabal_update_global_utf16le
#define RECIPE_UPDP_shabal224(X) shabal_update##X
#define RECIPE_PBUF_shabal224    w
#define RECIPE_UPDS_shabal224(X) shabal_update##X
#define RECIPE_SBUF_shabal224    s
#define RECIPE_CTX_shabal224(X)  shabal_ctx##X##_t
#define RECIPE_INIT_shabal224(X) shabal_init##X (&ctx, 28);
#define RECIPE_HASH_shabal224(X,HS,INIT,FEED) RECIPE_HASH_W32 (shabal, b, 16 - 7, X, HS, INIT, FEED, 7)
#define RECIPE_KS_shabal224(HS,V)  (V)
#define RECIPE_RAW_shabal224       RECIPE_RAWG
#define RECIPE_PAD_shabal224       RECIPE_PADG

#define RECIPE_LEN_shabal256    32
#define RECIPE_BLOCK_shabal256  64
#define RECIPE_UPD_shabal256(X)  shabal_update##X
#define RECIPE_UPDW_shabal256(X) shabal_update##X##_utf16le
#define RECIPE_UPDG_shabal256    shabal_update_global
#define RECIPE_UPDWG_shabal256   shabal_update_global_utf16le
#define RECIPE_UPDP_shabal256(X) shabal_update##X
#define RECIPE_PBUF_shabal256    w
#define RECIPE_UPDS_shabal256(X) shabal_update##X
#define RECIPE_SBUF_shabal256    s
#define RECIPE_CTX_shabal256(X)  shabal_ctx##X##_t
#define RECIPE_INIT_shabal256(X) shabal_init##X (&ctx, 32);
#define RECIPE_HASH_shabal256(X,HS,INIT,FEED) RECIPE_HASH_W32 (shabal, b, 16 - 8, X, HS, INIT, FEED, 8)
#define RECIPE_KS_shabal256(HS,V)  (V)
#define RECIPE_RAW_shabal256       RECIPE_RAWG
#define RECIPE_PAD_shabal256       RECIPE_PADG

#define RECIPE_LEN_shabal384    48
#define RECIPE_BLOCK_shabal384  64
#define RECIPE_UPD_shabal384(X)  shabal_update##X
#define RECIPE_UPDW_shabal384(X) shabal_update##X##_utf16le
#define RECIPE_UPDG_shabal384    shabal_update_global
#define RECIPE_UPDWG_shabal384   shabal_update_global_utf16le
#define RECIPE_UPDP_shabal384(X) shabal_update##X
#define RECIPE_PBUF_shabal384    w
#define RECIPE_UPDS_shabal384(X) shabal_update##X
#define RECIPE_SBUF_shabal384    s
#define RECIPE_CTX_shabal384(X)  shabal_ctx##X##_t
#define RECIPE_INIT_shabal384(X) shabal_init##X (&ctx, 48);
#define RECIPE_HASH_shabal384(X,HS,INIT,FEED) RECIPE_HASH_W32 (shabal, b, 16 - 12, X, HS, INIT, FEED, 12)
#define RECIPE_KS_shabal384(HS,V)  (V)
#define RECIPE_RAW_shabal384       RECIPE_RAWG
#define RECIPE_PAD_shabal384       RECIPE_PADG

#define RECIPE_LEN_shabal512    64
#define RECIPE_BLOCK_shabal512  64
#define RECIPE_UPD_shabal512(X)  shabal_update##X
#define RECIPE_UPDW_shabal512(X) shabal_update##X##_utf16le
#define RECIPE_UPDG_shabal512    shabal_update_global
#define RECIPE_UPDWG_shabal512   shabal_update_global_utf16le
#define RECIPE_UPDP_shabal512(X) shabal_update##X
#define RECIPE_PBUF_shabal512    w
#define RECIPE_UPDS_shabal512(X) shabal_update##X
#define RECIPE_SBUF_shabal512    s
#define RECIPE_CTX_shabal512(X)  shabal_ctx##X##_t
#define RECIPE_INIT_shabal512(X) shabal_init##X (&ctx, 64);
#define RECIPE_HASH_shabal512(X,HS,INIT,FEED) RECIPE_HASH_W32 (shabal, b, 16 - 16, X, HS, INIT, FEED, 16)
#define RECIPE_KS_shabal512(HS,V)  (V)
#define RECIPE_RAW_shabal512       RECIPE_RAWG
#define RECIPE_PAD_shabal512       RECIPE_PADG

// SHAvite-3 uses inc_hash_shavite.cl, with SHAvite-3-256 for shavite224 and shavite256 and
// SHAvite-3-512 for shavite384 and shavite512. It reads the AES tables of inc_cipher_aes.cl, see
// RECIPE_TE. Its digest is the first words of h, little endian. Its blocks, and therefore its HMAC
// blocks, contain 64 and 128 bytes.

#define RECIPE_LEN_shavite224    28
#define RECIPE_BLOCK_shavite224  64
#define RECIPE_UPD_shavite224(X)  shavite256_update##X
#define RECIPE_UPDW_shavite224(X) shavite256_update##X##_utf16le
#define RECIPE_UPDG_shavite224    shavite256_update_global
#define RECIPE_UPDWG_shavite224   shavite256_update_global_utf16le
#define RECIPE_UPDP_shavite224(X) shavite256_update##X
#define RECIPE_PBUF_shavite224    w
#define RECIPE_UPDS_shavite224(X) shavite256_update##X
#define RECIPE_SBUF_shavite224    s
#define RECIPE_CTX_shavite224(X)  shavite256_ctx##X##_t
#define RECIPE_INIT_shavite224(X) shavite256_init##X (&ctx, 28, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_shavite224(X,HS,INIT,FEED) RECIPE_HASH_W32 (shavite256, h, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_shavite224(HS,V)  (V)
#define RECIPE_RAW_shavite224       RECIPE_RAWG
#define RECIPE_PAD_shavite224       RECIPE_PADG

#define RECIPE_LEN_shavite256    32
#define RECIPE_BLOCK_shavite256  64
#define RECIPE_UPD_shavite256(X)  shavite256_update##X
#define RECIPE_UPDW_shavite256(X) shavite256_update##X##_utf16le
#define RECIPE_UPDG_shavite256    shavite256_update_global
#define RECIPE_UPDWG_shavite256   shavite256_update_global_utf16le
#define RECIPE_UPDP_shavite256(X) shavite256_update##X
#define RECIPE_PBUF_shavite256    w
#define RECIPE_UPDS_shavite256(X) shavite256_update##X
#define RECIPE_SBUF_shavite256    s
#define RECIPE_CTX_shavite256(X)  shavite256_ctx##X##_t
#define RECIPE_INIT_shavite256(X) shavite256_init##X (&ctx, 32, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_shavite256(X,HS,INIT,FEED) RECIPE_HASH_W32 (shavite256, h, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_shavite256(HS,V)  (V)
#define RECIPE_RAW_shavite256       RECIPE_RAWG
#define RECIPE_PAD_shavite256       RECIPE_PADG

#define RECIPE_LEN_shavite384    48
#define RECIPE_BLOCK_shavite384  128
#define RECIPE_UPD_shavite384(X)  shavite512_update##X
#define RECIPE_UPDW_shavite384(X) shavite512_update##X##_utf16le
#define RECIPE_UPDG_shavite384    shavite512_update_global
#define RECIPE_UPDWG_shavite384   shavite512_update_global_utf16le
#define RECIPE_UPDP_shavite384(X) shavite512_update##X
#define RECIPE_PBUF_shavite384    w
#define RECIPE_UPDS_shavite384(X) shavite512_update##X
#define RECIPE_SBUF_shavite384    s
#define RECIPE_CTX_shavite384(X)  shavite512_ctx##X##_t
#define RECIPE_INIT_shavite384(X) shavite512_init##X (&ctx, 48, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_shavite384(X,HS,INIT,FEED) RECIPE_HASH_W32 (shavite512, h, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_shavite384(HS,V)  (V)
#define RECIPE_RAW_shavite384       RECIPE_RAWG
#define RECIPE_PAD_shavite384       RECIPE_PADG

#define RECIPE_LEN_shavite512    64
#define RECIPE_BLOCK_shavite512  128
#define RECIPE_UPD_shavite512(X)  shavite512_update##X
#define RECIPE_UPDW_shavite512(X) shavite512_update##X##_utf16le
#define RECIPE_UPDG_shavite512    shavite512_update_global
#define RECIPE_UPDWG_shavite512   shavite512_update_global_utf16le
#define RECIPE_UPDP_shavite512(X) shavite512_update##X
#define RECIPE_PBUF_shavite512    w
#define RECIPE_UPDS_shavite512(X) shavite512_update##X
#define RECIPE_SBUF_shavite512    s
#define RECIPE_CTX_shavite512(X)  shavite512_ctx##X##_t
#define RECIPE_INIT_shavite512(X) shavite512_init##X (&ctx, 64, st->hte0, st->hte1, st->hte2, st->hte3);
#define RECIPE_HASH_shavite512(X,HS,INIT,FEED) RECIPE_HASH_W32 (shavite512, h, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_shavite512(HS,V)  (V)
#define RECIPE_RAW_shavite512       RECIPE_RAWG
#define RECIPE_PAD_shavite512       RECIPE_PADG

// SIMD uses inc_hash_simd.cl, with SIMD-256 for simd224 and simd256 and SIMD-512 for simd384 and
// simd512. Its digest is the first words of h, little endian. Its blocks, and therefore its HMAC
// blocks, contain 64 and 128 bytes.

#define RECIPE_LEN_simd224    28
#define RECIPE_BLOCK_simd224  64
#define RECIPE_UPD_simd224(X)  simd256_update##X
#define RECIPE_UPDW_simd224(X) simd256_update##X##_utf16le
#define RECIPE_UPDG_simd224    simd256_update_global
#define RECIPE_UPDWG_simd224   simd256_update_global_utf16le
#define RECIPE_UPDP_simd224(X) simd256_update##X
#define RECIPE_PBUF_simd224    w
#define RECIPE_UPDS_simd224(X) simd256_update##X
#define RECIPE_SBUF_simd224    s
#define RECIPE_CTX_simd224(X)  simd256_ctx##X##_t
#define RECIPE_INIT_simd224(X) simd256_init##X (&ctx, 28);
#define RECIPE_HASH_simd224(X,HS,INIT,FEED) RECIPE_HASH_W32 (simd256, h, 0, X, HS, INIT, FEED, 7)
#define RECIPE_KS_simd224(HS,V)  (V)
#define RECIPE_RAW_simd224       RECIPE_RAWG
#define RECIPE_PAD_simd224       RECIPE_PADG

#define RECIPE_LEN_simd256    32
#define RECIPE_BLOCK_simd256  64
#define RECIPE_UPD_simd256(X)  simd256_update##X
#define RECIPE_UPDW_simd256(X) simd256_update##X##_utf16le
#define RECIPE_UPDG_simd256    simd256_update_global
#define RECIPE_UPDWG_simd256   simd256_update_global_utf16le
#define RECIPE_UPDP_simd256(X) simd256_update##X
#define RECIPE_PBUF_simd256    w
#define RECIPE_UPDS_simd256(X) simd256_update##X
#define RECIPE_SBUF_simd256    s
#define RECIPE_CTX_simd256(X)  simd256_ctx##X##_t
#define RECIPE_INIT_simd256(X) simd256_init##X (&ctx, 32);
#define RECIPE_HASH_simd256(X,HS,INIT,FEED) RECIPE_HASH_W32 (simd256, h, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_simd256(HS,V)  (V)
#define RECIPE_RAW_simd256       RECIPE_RAWG
#define RECIPE_PAD_simd256       RECIPE_PADG

#define RECIPE_LEN_simd384    48
#define RECIPE_BLOCK_simd384  128
#define RECIPE_UPD_simd384(X)  simd512_update##X
#define RECIPE_UPDW_simd384(X) simd512_update##X##_utf16le
#define RECIPE_UPDG_simd384    simd512_update_global
#define RECIPE_UPDWG_simd384   simd512_update_global_utf16le
#define RECIPE_UPDP_simd384(X) simd512_update##X
#define RECIPE_PBUF_simd384    w
#define RECIPE_UPDS_simd384(X) simd512_update##X
#define RECIPE_SBUF_simd384    s
#define RECIPE_CTX_simd384(X)  simd512_ctx##X##_t
#define RECIPE_INIT_simd384(X) simd512_init##X (&ctx, 48);
#define RECIPE_HASH_simd384(X,HS,INIT,FEED) RECIPE_HASH_W32 (simd512, h, 0, X, HS, INIT, FEED, 12)
#define RECIPE_KS_simd384(HS,V)  (V)
#define RECIPE_RAW_simd384       RECIPE_RAWG
#define RECIPE_PAD_simd384       RECIPE_PADG

#define RECIPE_LEN_simd512    64
#define RECIPE_BLOCK_simd512  128
#define RECIPE_UPD_simd512(X)  simd512_update##X
#define RECIPE_UPDW_simd512(X) simd512_update##X##_utf16le
#define RECIPE_UPDG_simd512    simd512_update_global
#define RECIPE_UPDWG_simd512   simd512_update_global_utf16le
#define RECIPE_UPDP_simd512(X) simd512_update##X
#define RECIPE_PBUF_simd512    w
#define RECIPE_UPDS_simd512(X) simd512_update##X
#define RECIPE_SBUF_simd512    s
#define RECIPE_CTX_simd512(X)  simd512_ctx##X##_t
#define RECIPE_INIT_simd512(X) simd512_init##X (&ctx, 64);
#define RECIPE_HASH_simd512(X,HS,INIT,FEED) RECIPE_HASH_W32 (simd512, h, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_simd512(HS,V)  (V)
#define RECIPE_RAW_simd512       RECIPE_RAWG
#define RECIPE_PAD_simd512       RECIPE_PADG

// HAS-160 uses inc_hash_has160.cl. Its digest is h, little endian. Its blocks, and therefore its
// HMAC blocks, contain 64 bytes.

#define RECIPE_LEN_has160    20
#define RECIPE_BLOCK_has160  64
#define RECIPE_UPD_has160(X)  has160_update##X
#define RECIPE_UPDW_has160(X) has160_update##X##_utf16le
#define RECIPE_UPDG_has160    has160_update_global
#define RECIPE_UPDWG_has160   has160_update_global_utf16le
#define RECIPE_UPDP_has160(X) has160_update##X
#define RECIPE_PBUF_has160    w
#define RECIPE_UPDS_has160(X) has160_update##X
#define RECIPE_SBUF_has160    s
#define RECIPE_CTX_has160(X)  has160_ctx##X##_t
#define RECIPE_INIT_has160(X) has160_init##X (&ctx);
#define RECIPE_HASH_has160(X,HS,INIT,FEED) RECIPE_HASH_W32 (has160, h, 0, X, HS, INIT, FEED, 5)
#define RECIPE_KS_has160(HS,V)  (V)
#define RECIPE_RAW_has160       RECIPE_RAWG
#define RECIPE_PAD_has160       RECIPE_PADG

// EDON-R uses inc_hash_edonr.cl. Its digest is the second half of h, little endian. Its blocks, and
// therefore its HMAC blocks, contain 64 and 128 bytes.

#define RECIPE_LEN_edon256    32
#define RECIPE_BLOCK_edon256  64
#define RECIPE_UPD_edon256(X)  edonr256_update##X
#define RECIPE_UPDW_edon256(X) edonr256_update##X##_utf16le
#define RECIPE_UPDG_edon256    edonr256_update_global
#define RECIPE_UPDWG_edon256   edonr256_update_global_utf16le
#define RECIPE_UPDP_edon256(X) edonr256_update##X
#define RECIPE_PBUF_edon256    w
#define RECIPE_UPDS_edon256(X) edonr256_update##X
#define RECIPE_SBUF_edon256    s
#define RECIPE_CTX_edon256(X)  edonr256_ctx##X##_t
#define RECIPE_INIT_edon256(X) edonr256_init##X (&ctx);
#define RECIPE_HASH_edon256(X,HS,INIT,FEED) RECIPE_HASH_W32 (edonr256, h, 8, X, HS, INIT, FEED, 8)
#define RECIPE_KS_edon256(HS,V)  (V)
#define RECIPE_RAW_edon256       RECIPE_RAWG
#define RECIPE_PAD_edon256       RECIPE_PADG

#define RECIPE_LEN_edon512    64
#define RECIPE_BLOCK_edon512  128
#define RECIPE_UPD_edon512(X)  edonr512_update##X
#define RECIPE_UPDW_edon512(X) edonr512_update##X##_utf16le
#define RECIPE_UPDG_edon512    edonr512_update_global
#define RECIPE_UPDWG_edon512   edonr512_update_global_utf16le
#define RECIPE_UPDP_edon512(X) edonr512_update##X
#define RECIPE_PBUF_edon512    w
#define RECIPE_UPDS_edon512(X) edonr512_update##X
#define RECIPE_SBUF_edon512    s
#define RECIPE_CTX_edon512(X)  edonr512_ctx##X##_t
#define RECIPE_INIT_edon512(X) edonr512_init##X (&ctx);
#define RECIPE_HASH_edon512(X,HS,INIT,FEED) RECIPE_HASH_W64 (edonr512, 8, X, HS, INIT, FEED, 16)
#define RECIPE_KS_edon512(HS,V)  (V)
#define RECIPE_RAW_edon512       RECIPE_RAWG
#define RECIPE_PAD_edon512       RECIPE_PADG

// MD6 with the default parameters uses inc_hash_md6.cl. md6 is md6128, MD6 with 128 bits. Its
// digest is the first words of h, big endian. It is a tree hash and has no hmac_ form.

#define RECIPE_LEN_md6    16
#define RECIPE_BLOCK_md6  512
#define RECIPE_UPD_md6(X)  md6_update##X
#define RECIPE_UPDW_md6(X) md6_update##X##_utf16le
#define RECIPE_UPDG_md6    md6_update_global
#define RECIPE_UPDWG_md6   md6_update_global_utf16le
#define RECIPE_UPDP_md6(X) md6_update##X
#define RECIPE_PBUF_md6    w
#define RECIPE_UPDS_md6(X) md6_update##X
#define RECIPE_SBUF_md6    s
#define RECIPE_CTX_md6(X)  md6_ctx##X##_t
#define RECIPE_INIT_md6(X) md6_init##X (&ctx, 16);
#define RECIPE_HASH_md6(X,HS,INIT,FEED) RECIPE_HASH_W64S (md6, X, HS, INIT, FEED, 4)
#define RECIPE_KS_md6(HS,V)  (V)
#define RECIPE_RAW_md6       RECIPE_RAWG
#define RECIPE_PAD_md6       RECIPE_PADG

#define RECIPE_LEN_md6256    32
#define RECIPE_BLOCK_md6256  512
#define RECIPE_UPD_md6256(X)  md6_update##X
#define RECIPE_UPDW_md6256(X) md6_update##X##_utf16le
#define RECIPE_UPDG_md6256    md6_update_global
#define RECIPE_UPDWG_md6256   md6_update_global_utf16le
#define RECIPE_UPDP_md6256(X) md6_update##X
#define RECIPE_PBUF_md6256    w
#define RECIPE_UPDS_md6256(X) md6_update##X
#define RECIPE_SBUF_md6256    s
#define RECIPE_CTX_md6256(X)  md6_ctx##X##_t
#define RECIPE_INIT_md6256(X) md6_init##X (&ctx, 32);
#define RECIPE_HASH_md6256(X,HS,INIT,FEED) RECIPE_HASH_W64S (md6, X, HS, INIT, FEED, 8)
#define RECIPE_KS_md6256(HS,V)  (V)
#define RECIPE_RAW_md6256       RECIPE_RAWG
#define RECIPE_PAD_md6256       RECIPE_PADG

#define RECIPE_LEN_md6512    64
#define RECIPE_BLOCK_md6512  512
#define RECIPE_UPD_md6512(X)  md6_update##X
#define RECIPE_UPDW_md6512(X) md6_update##X##_utf16le
#define RECIPE_UPDG_md6512    md6_update_global
#define RECIPE_UPDWG_md6512   md6_update_global_utf16le
#define RECIPE_UPDP_md6512(X) md6_update##X
#define RECIPE_PBUF_md6512    w
#define RECIPE_UPDS_md6512(X) md6_update##X
#define RECIPE_SBUF_md6512    s
#define RECIPE_CTX_md6512(X)  md6_ctx##X##_t
#define RECIPE_INIT_md6512(X) md6_init##X (&ctx, 64);
#define RECIPE_HASH_md6512(X,HS,INIT,FEED) RECIPE_HASH_W64S (md6, X, HS, INIT, FEED, 16)
#define RECIPE_KS_md6512(HS,V)  (V)
#define RECIPE_RAW_md6512       RECIPE_RAWG
#define RECIPE_PAD_md6512       RECIPE_PADG

// RadioGatun uses inc_hash_radiogatun.cl. Its digest is h, little endian, 32 bytes for both word
// sizes. radiogatun32 keeps the first 16 bytes, the length hashpipe registers for it and hx
// therefore uses. It takes 12 or 24 bytes at a time and has no hmac_ form.

#define RECIPE_LEN_radiogatun32    16
#define RECIPE_BLOCK_radiogatun32  12
#define RECIPE_UPD_radiogatun32(X)  radiogatun32_update##X
#define RECIPE_UPDW_radiogatun32(X) radiogatun32_update##X##_utf16le
#define RECIPE_UPDG_radiogatun32    radiogatun32_update_global
#define RECIPE_UPDWG_radiogatun32   radiogatun32_update_global_utf16le
#define RECIPE_UPDP_radiogatun32(X) radiogatun32_update##X
#define RECIPE_PBUF_radiogatun32    w
#define RECIPE_UPDS_radiogatun32(X) radiogatun32_update##X
#define RECIPE_SBUF_radiogatun32    s
#define RECIPE_CTX_radiogatun32(X)  radiogatun32_ctx##X##_t
#define RECIPE_INIT_radiogatun32(X) radiogatun32_init##X (&ctx);
#define RECIPE_HASH_radiogatun32(X,HS,INIT,FEED) RECIPE_HASH_W32 (radiogatun32, h, 0, X, HS, INIT, FEED, 4)
#define RECIPE_KS_radiogatun32(HS,V)  (V)
#define RECIPE_RAW_radiogatun32       RECIPE_RAWG
#define RECIPE_PAD_radiogatun32       RECIPE_PADG

#define RECIPE_LEN_radiogatun64    32
#define RECIPE_BLOCK_radiogatun64  24
#define RECIPE_UPD_radiogatun64(X)  radiogatun64_update##X
#define RECIPE_UPDW_radiogatun64(X) radiogatun64_update##X##_utf16le
#define RECIPE_UPDG_radiogatun64    radiogatun64_update_global
#define RECIPE_UPDWG_radiogatun64   radiogatun64_update_global_utf16le
#define RECIPE_UPDP_radiogatun64(X) radiogatun64_update##X
#define RECIPE_PBUF_radiogatun64    w
#define RECIPE_UPDS_radiogatun64(X) radiogatun64_update##X
#define RECIPE_SBUF_radiogatun64    s
#define RECIPE_CTX_radiogatun64(X)  radiogatun64_ctx##X##_t
#define RECIPE_INIT_radiogatun64(X) radiogatun64_init##X (&ctx);
#define RECIPE_HASH_radiogatun64(X,HS,INIT,FEED) RECIPE_HASH_W64 (radiogatun64, 0, X, HS, INIT, FEED, 8)
#define RECIPE_KS_radiogatun64(HS,V)  (V)
#define RECIPE_RAW_radiogatun64       RECIPE_RAWG
#define RECIPE_PAD_radiogatun64       RECIPE_PADG

// The original RIPEMD of 1992 uses inc_hash_ripemd.cl. Its digest is h, little endian. Its blocks,
// and therefore its HMAC blocks, contain 64 bytes.

#define RECIPE_LEN_ripemd    16
#define RECIPE_BLOCK_ripemd  64
#define RECIPE_UPD_ripemd(X)  ripemd_update##X
#define RECIPE_UPDW_ripemd(X) ripemd_update##X##_utf16le
#define RECIPE_UPDG_ripemd    ripemd_update_global
#define RECIPE_UPDWG_ripemd   ripemd_update_global_utf16le
#define RECIPE_UPDP_ripemd(X) ripemd_update##X
#define RECIPE_PBUF_ripemd    w
#define RECIPE_UPDS_ripemd(X) ripemd_update##X
#define RECIPE_SBUF_ripemd    s
#define RECIPE_CTX_ripemd(X)  ripemd_ctx##X##_t
#define RECIPE_INIT_ripemd(X) ripemd_init##X (&ctx);
#define RECIPE_HASH_ripemd(X,HS,INIT,FEED) RECIPE_HASH_W32 (ripemd, h, 0, X, HS, INIT, FEED, 4)
#define RECIPE_KS_ripemd(HS,V)  (V)
#define RECIPE_RAW_ripemd       RECIPE_RAWG
#define RECIPE_PAD_ripemd       RECIPE_PADG

// Whirlpool-0 and Whirlpool-T use inc_hash_whirlpool01.cl and its tables, see RECIPE_WRL01. Their
// digest is h, little endian. Their blocks, and therefore their HMAC blocks, contain 64 bytes.

#define RECIPE_LEN_wrl0    64
#define RECIPE_BLOCK_wrl0  64
#define RECIPE_UPD_wrl0(X)  whirlpool01_update##X
#define RECIPE_UPDW_wrl0(X) whirlpool01_update##X##_utf16le
#define RECIPE_UPDG_wrl0    whirlpool01_update_global
#define RECIPE_UPDWG_wrl0   whirlpool01_update_global_utf16le
#define RECIPE_UPDP_wrl0(X) whirlpool01_update##X
#define RECIPE_PBUF_wrl0    w
#define RECIPE_UPDS_wrl0(X) whirlpool01_update##X
#define RECIPE_SBUF_wrl0    s
#define RECIPE_CTX_wrl0(X)  whirlpool01_ctx##X##_t
#define RECIPE_INIT_wrl0(X) whirlpool01_init##X (&ctx, st->wrl01, WHIRLPOOL01_WRL0);
#define RECIPE_HASH_wrl0(X,HS,INIT,FEED) RECIPE_HASH_W64 (whirlpool01, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_wrl0(HS,V)  (V)
#define RECIPE_RAW_wrl0       RECIPE_RAWG
#define RECIPE_PAD_wrl0       RECIPE_PADG

#define RECIPE_LEN_wrl1    64
#define RECIPE_BLOCK_wrl1  64
#define RECIPE_UPD_wrl1(X)  whirlpool01_update##X
#define RECIPE_UPDW_wrl1(X) whirlpool01_update##X##_utf16le
#define RECIPE_UPDG_wrl1    whirlpool01_update_global
#define RECIPE_UPDWG_wrl1   whirlpool01_update_global_utf16le
#define RECIPE_UPDP_wrl1(X) whirlpool01_update##X
#define RECIPE_PBUF_wrl1    w
#define RECIPE_UPDS_wrl1(X) whirlpool01_update##X
#define RECIPE_SBUF_wrl1    s
#define RECIPE_CTX_wrl1(X)  whirlpool01_ctx##X##_t
#define RECIPE_INIT_wrl1(X) whirlpool01_init##X (&ctx, st->wrl01, WHIRLPOOL01_WRL1);
#define RECIPE_HASH_wrl1(X,HS,INIT,FEED) RECIPE_HASH_W64 (whirlpool01, 0, X, HS, INIT, FEED, 16)
#define RECIPE_KS_wrl1(HS,V)  (V)
#define RECIPE_RAW_wrl1       RECIPE_RAWG
#define RECIPE_PAD_wrl1       RECIPE_PADG

// Tiger uses inc_hash_tiger.cl. It takes little endian words as MD5 does and returns its
// digest as the 3 words of h, each in little endian order. The tiger128 and tiger160 variants
// retain the first 16 and 20 bytes. The tiger2 variant differs from tiger only in the padding
// byte set by its init function.

#define RECIPE_HASH_TIGER(X,HS,INIT,FEED)                             \
{                                                                     \
  tiger_ctx##X##_t ctx;                                               \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  tiger_final##X (&ctx);                                              \
                                                                      \
  for (u32 i = 0; i < 3; i++)                                         \
  {                                                                   \
    raw[(i * 2) + 0] = l32_from_64##HS (ctx.h[i]);                    \
    raw[(i * 2) + 1] = h32_from_64##HS (ctx.h[i]);                    \
  }                                                                   \
}

#define RECIPE_LEN_tiger    24
#define RECIPE_BLOCK_tiger  64
#define RECIPE_UPD_tiger(X)  tiger_update##X
#define RECIPE_UPDW_tiger(X) tiger_update##X##_utf16le
#define RECIPE_UPDG_tiger    tiger_update_global
#define RECIPE_UPDWG_tiger   tiger_update_global_utf16le
#define RECIPE_UPDP_tiger(X) tiger_update##X
#define RECIPE_PBUF_tiger    w
#define RECIPE_UPDS_tiger(X) tiger_update##X
#define RECIPE_SBUF_tiger    s
#define RECIPE_CTX_tiger(X)  tiger_ctx##X##_t
#define RECIPE_INIT_tiger(X) tiger_init##X (&ctx, st->tiger, TIGER_PAD_TIGER);
#define RECIPE_HASH_tiger(X,HS,INIT,FEED) RECIPE_HASH_TIGER (X, HS, INIT, FEED)
#define RECIPE_KS_tiger(HS,V)  (V)
#define RECIPE_RAW_tiger       RECIPE_RAWG
#define RECIPE_PAD_tiger       RECIPE_PADG

#define RECIPE_LEN_tiger128    16
#define RECIPE_BLOCK_tiger128  64
#define RECIPE_UPD_tiger128(X)  tiger_update##X
#define RECIPE_UPDW_tiger128(X) tiger_update##X##_utf16le
#define RECIPE_UPDG_tiger128    tiger_update_global
#define RECIPE_UPDWG_tiger128   tiger_update_global_utf16le
#define RECIPE_UPDP_tiger128(X) tiger_update##X
#define RECIPE_PBUF_tiger128    w
#define RECIPE_UPDS_tiger128(X) tiger_update##X
#define RECIPE_SBUF_tiger128    s
#define RECIPE_CTX_tiger128(X)  tiger_ctx##X##_t
#define RECIPE_INIT_tiger128(X) tiger_init##X (&ctx, st->tiger, TIGER_PAD_TIGER);
#define RECIPE_HASH_tiger128(X,HS,INIT,FEED) RECIPE_HASH_TIGER (X, HS, INIT, FEED)
#define RECIPE_KS_tiger128(HS,V)  (V)
#define RECIPE_RAW_tiger128       RECIPE_RAWG
#define RECIPE_PAD_tiger128       RECIPE_PADG

#define RECIPE_LEN_tiger160    20
#define RECIPE_BLOCK_tiger160  64
#define RECIPE_UPD_tiger160(X)  tiger_update##X
#define RECIPE_UPDW_tiger160(X) tiger_update##X##_utf16le
#define RECIPE_UPDG_tiger160    tiger_update_global
#define RECIPE_UPDWG_tiger160   tiger_update_global_utf16le
#define RECIPE_UPDP_tiger160(X) tiger_update##X
#define RECIPE_PBUF_tiger160    w
#define RECIPE_UPDS_tiger160(X) tiger_update##X
#define RECIPE_SBUF_tiger160    s
#define RECIPE_CTX_tiger160(X)  tiger_ctx##X##_t
#define RECIPE_INIT_tiger160(X) tiger_init##X (&ctx, st->tiger, TIGER_PAD_TIGER);
#define RECIPE_HASH_tiger160(X,HS,INIT,FEED) RECIPE_HASH_TIGER (X, HS, INIT, FEED)
#define RECIPE_KS_tiger160(HS,V)  (V)
#define RECIPE_RAW_tiger160       RECIPE_RAWG
#define RECIPE_PAD_tiger160       RECIPE_PADG

#define RECIPE_LEN_tiger2    24
#define RECIPE_BLOCK_tiger2  64
#define RECIPE_UPD_tiger2(X)  tiger_update##X
#define RECIPE_UPDW_tiger2(X) tiger_update##X##_utf16le
#define RECIPE_UPDG_tiger2    tiger_update_global
#define RECIPE_UPDWG_tiger2   tiger_update_global_utf16le
#define RECIPE_UPDP_tiger2(X) tiger_update##X
#define RECIPE_PBUF_tiger2    w
#define RECIPE_UPDS_tiger2(X) tiger_update##X
#define RECIPE_SBUF_tiger2    s
#define RECIPE_CTX_tiger2(X)  tiger_ctx##X##_t
#define RECIPE_INIT_tiger2(X) tiger_init##X (&ctx, st->tiger, TIGER_PAD_TIGER2);
#define RECIPE_HASH_tiger2(X,HS,INIT,FEED) RECIPE_HASH_TIGER (X, HS, INIT, FEED)
#define RECIPE_KS_tiger2(HS,V)  (V)
#define RECIPE_RAW_tiger2       RECIPE_RAWG
#define RECIPE_PAD_tiger2       RECIPE_PADG

// tth is the Tiger tree hash of one leaf, whose init sets the 0x00 prefix. It has no HMAC form.

#define RECIPE_LEN_tth    24
#define RECIPE_BLOCK_tth  64
#define RECIPE_UPD_tth(X)  tiger_update##X
#define RECIPE_UPDW_tth(X) tiger_update##X##_utf16le
#define RECIPE_UPDG_tth    tiger_update_global
#define RECIPE_UPDWG_tth   tiger_update_global_utf16le
#define RECIPE_UPDP_tth(X) tiger_update##X
#define RECIPE_PBUF_tth    w
#define RECIPE_UPDS_tth(X) tiger_update##X
#define RECIPE_SBUF_tth    s
#define RECIPE_CTX_tth(X)  tiger_ctx##X##_t
#define RECIPE_INIT_tth(X) tiger_init_tth##X (&ctx, st->tiger);
#define RECIPE_HASH_tth(X,HS,INIT,FEED) RECIPE_HASH_TIGER (X, HS, INIT, FEED)
#define RECIPE_KS_tth(HS,V)  (V)
#define RECIPE_RAW_tth       RECIPE_RAWG
#define RECIPE_PAD_tth       RECIPE_PADG

// HAVAL uses inc_hash_haval.cl. The 15 families share one context and its functions, which take
// little endian words as MD5 does. They differ only in the pass count and digest size set by their
// init function in that context. Their HMAC block contains 128 bytes, so the key pads and inner
// digest use the plain update.

#define RECIPE_HASH_HAVAL(X,HS,INIT,FEED,NW)                          \
{                                                                     \
  haval_ctx##X##_t ctx;                                               \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  haval_final##X (&ctx);                                              \
                                                                      \
  for (u32 i = 0; i < (NW); i++) raw[i] = ctx.h[i];                   \
}

#define RECIPE_LEN_hav128    16
#define RECIPE_BLOCK_hav128  128
#define RECIPE_UPD_hav128(X)  haval_update##X
#define RECIPE_UPDW_hav128(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav128    haval_update_global
#define RECIPE_UPDWG_hav128   haval_update_global_utf16le
#define RECIPE_UPDP_hav128(X) haval_update##X
#define RECIPE_PBUF_hav128    w
#define RECIPE_UPDS_hav128(X) haval_update##X
#define RECIPE_SBUF_hav128    s
#define RECIPE_CTX_hav128(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav128(X) haval_init##X (&ctx, 3, 4);
#define RECIPE_HASH_hav128(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 4)
#define RECIPE_KS_hav128(HS,V)  (V)
#define RECIPE_RAW_hav128       RECIPE_RAWG
#define RECIPE_PAD_hav128       RECIPE_PADG

#define RECIPE_LEN_hav128_4    16
#define RECIPE_BLOCK_hav128_4  128
#define RECIPE_UPD_hav128_4(X)  haval_update##X
#define RECIPE_UPDW_hav128_4(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav128_4    haval_update_global
#define RECIPE_UPDWG_hav128_4   haval_update_global_utf16le
#define RECIPE_UPDP_hav128_4(X) haval_update##X
#define RECIPE_PBUF_hav128_4    w
#define RECIPE_UPDS_hav128_4(X) haval_update##X
#define RECIPE_SBUF_hav128_4    s
#define RECIPE_CTX_hav128_4(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav128_4(X) haval_init##X (&ctx, 4, 4);
#define RECIPE_HASH_hav128_4(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 4)
#define RECIPE_KS_hav128_4(HS,V)  (V)
#define RECIPE_RAW_hav128_4       RECIPE_RAWG
#define RECIPE_PAD_hav128_4       RECIPE_PADG

#define RECIPE_LEN_hav128_5    16
#define RECIPE_BLOCK_hav128_5  128
#define RECIPE_UPD_hav128_5(X)  haval_update##X
#define RECIPE_UPDW_hav128_5(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav128_5    haval_update_global
#define RECIPE_UPDWG_hav128_5   haval_update_global_utf16le
#define RECIPE_UPDP_hav128_5(X) haval_update##X
#define RECIPE_PBUF_hav128_5    w
#define RECIPE_UPDS_hav128_5(X) haval_update##X
#define RECIPE_SBUF_hav128_5    s
#define RECIPE_CTX_hav128_5(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav128_5(X) haval_init##X (&ctx, 5, 4);
#define RECIPE_HASH_hav128_5(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 4)
#define RECIPE_KS_hav128_5(HS,V)  (V)
#define RECIPE_RAW_hav128_5       RECIPE_RAWG
#define RECIPE_PAD_hav128_5       RECIPE_PADG

#define RECIPE_LEN_hav160_3    20
#define RECIPE_BLOCK_hav160_3  128
#define RECIPE_UPD_hav160_3(X)  haval_update##X
#define RECIPE_UPDW_hav160_3(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav160_3    haval_update_global
#define RECIPE_UPDWG_hav160_3   haval_update_global_utf16le
#define RECIPE_UPDP_hav160_3(X) haval_update##X
#define RECIPE_PBUF_hav160_3    w
#define RECIPE_UPDS_hav160_3(X) haval_update##X
#define RECIPE_SBUF_hav160_3    s
#define RECIPE_CTX_hav160_3(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav160_3(X) haval_init##X (&ctx, 3, 5);
#define RECIPE_HASH_hav160_3(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 5)
#define RECIPE_KS_hav160_3(HS,V)  (V)
#define RECIPE_RAW_hav160_3       RECIPE_RAWG
#define RECIPE_PAD_hav160_3       RECIPE_PADG

#define RECIPE_LEN_hav160_4    20
#define RECIPE_BLOCK_hav160_4  128
#define RECIPE_UPD_hav160_4(X)  haval_update##X
#define RECIPE_UPDW_hav160_4(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav160_4    haval_update_global
#define RECIPE_UPDWG_hav160_4   haval_update_global_utf16le
#define RECIPE_UPDP_hav160_4(X) haval_update##X
#define RECIPE_PBUF_hav160_4    w
#define RECIPE_UPDS_hav160_4(X) haval_update##X
#define RECIPE_SBUF_hav160_4    s
#define RECIPE_CTX_hav160_4(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav160_4(X) haval_init##X (&ctx, 4, 5);
#define RECIPE_HASH_hav160_4(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 5)
#define RECIPE_KS_hav160_4(HS,V)  (V)
#define RECIPE_RAW_hav160_4       RECIPE_RAWG
#define RECIPE_PAD_hav160_4       RECIPE_PADG

#define RECIPE_LEN_hav160_5    20
#define RECIPE_BLOCK_hav160_5  128
#define RECIPE_UPD_hav160_5(X)  haval_update##X
#define RECIPE_UPDW_hav160_5(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav160_5    haval_update_global
#define RECIPE_UPDWG_hav160_5   haval_update_global_utf16le
#define RECIPE_UPDP_hav160_5(X) haval_update##X
#define RECIPE_PBUF_hav160_5    w
#define RECIPE_UPDS_hav160_5(X) haval_update##X
#define RECIPE_SBUF_hav160_5    s
#define RECIPE_CTX_hav160_5(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav160_5(X) haval_init##X (&ctx, 5, 5);
#define RECIPE_HASH_hav160_5(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 5)
#define RECIPE_KS_hav160_5(HS,V)  (V)
#define RECIPE_RAW_hav160_5       RECIPE_RAWG
#define RECIPE_PAD_hav160_5       RECIPE_PADG

#define RECIPE_LEN_hav192_3    24
#define RECIPE_BLOCK_hav192_3  128
#define RECIPE_UPD_hav192_3(X)  haval_update##X
#define RECIPE_UPDW_hav192_3(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav192_3    haval_update_global
#define RECIPE_UPDWG_hav192_3   haval_update_global_utf16le
#define RECIPE_UPDP_hav192_3(X) haval_update##X
#define RECIPE_PBUF_hav192_3    w
#define RECIPE_UPDS_hav192_3(X) haval_update##X
#define RECIPE_SBUF_hav192_3    s
#define RECIPE_CTX_hav192_3(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav192_3(X) haval_init##X (&ctx, 3, 6);
#define RECIPE_HASH_hav192_3(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 6)
#define RECIPE_KS_hav192_3(HS,V)  (V)
#define RECIPE_RAW_hav192_3       RECIPE_RAWG
#define RECIPE_PAD_hav192_3       RECIPE_PADG

#define RECIPE_LEN_hav192_4    24
#define RECIPE_BLOCK_hav192_4  128
#define RECIPE_UPD_hav192_4(X)  haval_update##X
#define RECIPE_UPDW_hav192_4(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav192_4    haval_update_global
#define RECIPE_UPDWG_hav192_4   haval_update_global_utf16le
#define RECIPE_UPDP_hav192_4(X) haval_update##X
#define RECIPE_PBUF_hav192_4    w
#define RECIPE_UPDS_hav192_4(X) haval_update##X
#define RECIPE_SBUF_hav192_4    s
#define RECIPE_CTX_hav192_4(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav192_4(X) haval_init##X (&ctx, 4, 6);
#define RECIPE_HASH_hav192_4(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 6)
#define RECIPE_KS_hav192_4(HS,V)  (V)
#define RECIPE_RAW_hav192_4       RECIPE_RAWG
#define RECIPE_PAD_hav192_4       RECIPE_PADG

#define RECIPE_LEN_hav192_5    24
#define RECIPE_BLOCK_hav192_5  128
#define RECIPE_UPD_hav192_5(X)  haval_update##X
#define RECIPE_UPDW_hav192_5(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav192_5    haval_update_global
#define RECIPE_UPDWG_hav192_5   haval_update_global_utf16le
#define RECIPE_UPDP_hav192_5(X) haval_update##X
#define RECIPE_PBUF_hav192_5    w
#define RECIPE_UPDS_hav192_5(X) haval_update##X
#define RECIPE_SBUF_hav192_5    s
#define RECIPE_CTX_hav192_5(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav192_5(X) haval_init##X (&ctx, 5, 6);
#define RECIPE_HASH_hav192_5(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 6)
#define RECIPE_KS_hav192_5(HS,V)  (V)
#define RECIPE_RAW_hav192_5       RECIPE_RAWG
#define RECIPE_PAD_hav192_5       RECIPE_PADG

#define RECIPE_LEN_hav224_3    28
#define RECIPE_BLOCK_hav224_3  128
#define RECIPE_UPD_hav224_3(X)  haval_update##X
#define RECIPE_UPDW_hav224_3(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav224_3    haval_update_global
#define RECIPE_UPDWG_hav224_3   haval_update_global_utf16le
#define RECIPE_UPDP_hav224_3(X) haval_update##X
#define RECIPE_PBUF_hav224_3    w
#define RECIPE_UPDS_hav224_3(X) haval_update##X
#define RECIPE_SBUF_hav224_3    s
#define RECIPE_CTX_hav224_3(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav224_3(X) haval_init##X (&ctx, 3, 7);
#define RECIPE_HASH_hav224_3(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 7)
#define RECIPE_KS_hav224_3(HS,V)  (V)
#define RECIPE_RAW_hav224_3       RECIPE_RAWG
#define RECIPE_PAD_hav224_3       RECIPE_PADG

#define RECIPE_LEN_hav224_4    28
#define RECIPE_BLOCK_hav224_4  128
#define RECIPE_UPD_hav224_4(X)  haval_update##X
#define RECIPE_UPDW_hav224_4(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav224_4    haval_update_global
#define RECIPE_UPDWG_hav224_4   haval_update_global_utf16le
#define RECIPE_UPDP_hav224_4(X) haval_update##X
#define RECIPE_PBUF_hav224_4    w
#define RECIPE_UPDS_hav224_4(X) haval_update##X
#define RECIPE_SBUF_hav224_4    s
#define RECIPE_CTX_hav224_4(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav224_4(X) haval_init##X (&ctx, 4, 7);
#define RECIPE_HASH_hav224_4(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 7)
#define RECIPE_KS_hav224_4(HS,V)  (V)
#define RECIPE_RAW_hav224_4       RECIPE_RAWG
#define RECIPE_PAD_hav224_4       RECIPE_PADG

#define RECIPE_LEN_hav224_5    28
#define RECIPE_BLOCK_hav224_5  128
#define RECIPE_UPD_hav224_5(X)  haval_update##X
#define RECIPE_UPDW_hav224_5(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav224_5    haval_update_global
#define RECIPE_UPDWG_hav224_5   haval_update_global_utf16le
#define RECIPE_UPDP_hav224_5(X) haval_update##X
#define RECIPE_PBUF_hav224_5    w
#define RECIPE_UPDS_hav224_5(X) haval_update##X
#define RECIPE_SBUF_hav224_5    s
#define RECIPE_CTX_hav224_5(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav224_5(X) haval_init##X (&ctx, 5, 7);
#define RECIPE_HASH_hav224_5(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 7)
#define RECIPE_KS_hav224_5(HS,V)  (V)
#define RECIPE_RAW_hav224_5       RECIPE_RAWG
#define RECIPE_PAD_hav224_5       RECIPE_PADG

#define RECIPE_LEN_hav256    32
#define RECIPE_BLOCK_hav256  128
#define RECIPE_UPD_hav256(X)  haval_update##X
#define RECIPE_UPDW_hav256(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav256    haval_update_global
#define RECIPE_UPDWG_hav256   haval_update_global_utf16le
#define RECIPE_UPDP_hav256(X) haval_update##X
#define RECIPE_PBUF_hav256    w
#define RECIPE_UPDS_hav256(X) haval_update##X
#define RECIPE_SBUF_hav256    s
#define RECIPE_CTX_hav256(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav256(X) haval_init##X (&ctx, 3, 8);
#define RECIPE_HASH_hav256(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 8)
#define RECIPE_KS_hav256(HS,V)  (V)
#define RECIPE_RAW_hav256       RECIPE_RAWG
#define RECIPE_PAD_hav256       RECIPE_PADG

#define RECIPE_LEN_hav256_4    32
#define RECIPE_BLOCK_hav256_4  128
#define RECIPE_UPD_hav256_4(X)  haval_update##X
#define RECIPE_UPDW_hav256_4(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav256_4    haval_update_global
#define RECIPE_UPDWG_hav256_4   haval_update_global_utf16le
#define RECIPE_UPDP_hav256_4(X) haval_update##X
#define RECIPE_PBUF_hav256_4    w
#define RECIPE_UPDS_hav256_4(X) haval_update##X
#define RECIPE_SBUF_hav256_4    s
#define RECIPE_CTX_hav256_4(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav256_4(X) haval_init##X (&ctx, 4, 8);
#define RECIPE_HASH_hav256_4(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 8)
#define RECIPE_KS_hav256_4(HS,V)  (V)
#define RECIPE_RAW_hav256_4       RECIPE_RAWG
#define RECIPE_PAD_hav256_4       RECIPE_PADG

#define RECIPE_LEN_hav256_5    32
#define RECIPE_BLOCK_hav256_5  128
#define RECIPE_UPD_hav256_5(X)  haval_update##X
#define RECIPE_UPDW_hav256_5(X) haval_update##X##_utf16le
#define RECIPE_UPDG_hav256_5    haval_update_global
#define RECIPE_UPDWG_hav256_5   haval_update_global_utf16le
#define RECIPE_UPDP_hav256_5(X) haval_update##X
#define RECIPE_PBUF_hav256_5    w
#define RECIPE_UPDS_hav256_5(X) haval_update##X
#define RECIPE_SBUF_hav256_5    s
#define RECIPE_CTX_hav256_5(X)  haval_ctx##X##_t
#define RECIPE_INIT_hav256_5(X) haval_init##X (&ctx, 5, 8);
#define RECIPE_HASH_hav256_5(X,HS,INIT,FEED) RECIPE_HASH_HAVAL (X, HS, INIT, FEED, 8)
#define RECIPE_KS_hav256_5(HS,V)  (V)
#define RECIPE_RAW_hav256_5       RECIPE_RAWG
#define RECIPE_PAD_hav256_5       RECIPE_PADG

// mysql3 uses inc_hash_mysql323.cl. It takes bytes in memory order and returns nr and nr2 as big
// endian words. It has no block, so it has no HMAC form.

#define RECIPE_LEN_mysql3    8
#define RECIPE_BLOCK_mysql3  64
#define RECIPE_UPD_mysql3(X)  mysql323_update##X
#define RECIPE_UPDW_mysql3(X) mysql323_update##X##_utf16le
#define RECIPE_UPDG_mysql3    mysql323_update_global
#define RECIPE_UPDWG_mysql3   mysql323_update_global_utf16le
#define RECIPE_UPDP_mysql3(X) mysql323_update##X
#define RECIPE_PBUF_mysql3    w
#define RECIPE_UPDS_mysql3(X) mysql323_update##X
#define RECIPE_SBUF_mysql3    s
#define RECIPE_CTX_mysql3(X)  mysql323_ctx##X##_t
#define RECIPE_INIT_mysql3(X) mysql323_init##X (&ctx);
#define RECIPE_KS_mysql3(HS,V)  (V)

#define RECIPE_HASH_mysql3(X,HS,INIT,FEED)                            \
{                                                                     \
  mysql323_ctx##X##_t ctx;                                            \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  mysql323_final##X (&ctx);                                           \
                                                                      \
  raw[0] = hc_swap32##HS (ctx.nr);                                    \
  raw[1] = hc_swap32##HS (ctx.nr2);                                   \
}

// xxh64 and xxh32 use inc_hash_xxhash.cl, see RECIPE_XXHASH. They take bytes in memory order and
// write the digest big endian, as the canonical form of xxHash does. A call without a seed starts
// from seed 0, and a call with one is a SEED step, see RECIPE_STEP_SEED. They have no HMAC form and
// no utf16le update.

// The type of a seed, so that a call without one can pass 0 in the word type of its context.

#define RECIPE_XXH64_T        u64
#define RECIPE_XXH64_T_vector u64x
#define RECIPE_XXH32_T        u32
#define RECIPE_XXH32_T_vector u32x

#define RECIPE_LEN_xxh64    8
#define RECIPE_BLOCK_xxh64  32
#define RECIPE_UPD_xxh64(X)  xxh64_update##X
#define RECIPE_UPDW_xxh64(X) recipe_no_utf16_xxhash
#define RECIPE_UPDG_xxh64    xxh64_update_global
#define RECIPE_UPDWG_xxh64   recipe_no_utf16_xxhash
#define RECIPE_UPDP_xxh64(X) xxh64_update##X
#define RECIPE_PBUF_xxh64    w
#define RECIPE_UPDS_xxh64(X) xxh64_update##X
#define RECIPE_SBUF_xxh64    s
#define RECIPE_CTX_xxh64(X)  xxh64_ctx##X##_t
#define RECIPE_INIT_xxh64(X) xxh64_init##X (&ctx, (RECIPE_XXH64_T##X) 0);
#define RECIPE_KS_xxh64(HS,V)  (V)

#define RECIPE_HASH_xxh64(X,HS,INIT,FEED)                             \
{                                                                     \
  xxh64_ctx##X##_t ctx;                                               \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  xxh64_final##X (&ctx);                                              \
                                                                      \
  raw[0] = hc_swap32##HS (h32_from_64##HS (ctx.h));                   \
  raw[1] = hc_swap32##HS (l32_from_64##HS (ctx.h));                   \
}

#define RECIPE_LEN_xxh32    4
#define RECIPE_BLOCK_xxh32  16
#define RECIPE_UPD_xxh32(X)  xxh32_update##X
#define RECIPE_UPDW_xxh32(X) recipe_no_utf16_xxhash
#define RECIPE_UPDG_xxh32    xxh32_update_global
#define RECIPE_UPDWG_xxh32   recipe_no_utf16_xxhash
#define RECIPE_UPDP_xxh32(X) xxh32_update##X
#define RECIPE_PBUF_xxh32    w
#define RECIPE_UPDS_xxh32(X) xxh32_update##X
#define RECIPE_SBUF_xxh32    s
#define RECIPE_CTX_xxh32(X)  xxh32_ctx##X##_t
#define RECIPE_INIT_xxh32(X) xxh32_init##X (&ctx, (RECIPE_XXH32_T##X) 0);
#define RECIPE_KS_xxh32(HS,V)  (V)

#define RECIPE_HASH_xxh32(X,HS,INIT,FEED)                             \
{                                                                     \
  xxh32_ctx##X##_t ctx;                                               \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  xxh32_final##X (&ctx);                                              \
                                                                      \
  raw[0] = hc_swap32##HS (ctx.h);                                     \
}

// lm and mdc2 use inc_hash_lm.cl and inc_hash_mdc2.cl with the DES tables, see RECIPE_DES. Both
// take bytes in memory order and return little endian words. They have no hmac_ form: lm keeps only
// 14 bytes of its input, and the block of mdc2 is shorter than its digest.

#define RECIPE_LEN_lm    16
#define RECIPE_BLOCK_lm  8
#define RECIPE_UPD_lm(X)  lm_update##X
#define RECIPE_UPDW_lm(X) lm_update##X##_utf16le
#define RECIPE_UPDG_lm    lm_update_global
#define RECIPE_UPDWG_lm   lm_update_global_utf16le
#define RECIPE_UPDP_lm(X) lm_update##X
#define RECIPE_PBUF_lm    w
#define RECIPE_UPDS_lm(X) lm_update##X
#define RECIPE_SBUF_lm    s
#define RECIPE_CTX_lm(X)  lm_ctx##X##_t
#define RECIPE_INIT_lm(X) lm_init##X (&ctx, st->des_skb, st->des_sptrans);
#define RECIPE_KS_lm(HS,V)  (V)

#define RECIPE_HASH_lm(X,HS,INIT,FEED)                                \
{                                                                     \
  lm_ctx##X##_t ctx;                                                  \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  lm_final##X (&ctx);                                                 \
                                                                      \
  for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];                      \
}

#define RECIPE_LEN_mdc2    16
#define RECIPE_BLOCK_mdc2  8
#define RECIPE_UPD_mdc2(X)  mdc2_update##X
#define RECIPE_UPDW_mdc2(X) mdc2_update##X##_utf16le
#define RECIPE_UPDG_mdc2    mdc2_update_global
#define RECIPE_UPDWG_mdc2   mdc2_update_global_utf16le
#define RECIPE_UPDP_mdc2(X) mdc2_update##X
#define RECIPE_PBUF_mdc2    w
#define RECIPE_UPDS_mdc2(X) mdc2_update##X
#define RECIPE_SBUF_mdc2    s
#define RECIPE_CTX_mdc2(X)  mdc2_ctx##X##_t
#define RECIPE_INIT_mdc2(X) mdc2_init##X (&ctx, st->des_skb, st->des_sptrans);
#define RECIPE_KS_mdc2(HS,V)  (V)

#define RECIPE_HASH_mdc2(X,HS,INIT,FEED)                              \
{                                                                     \
  mdc2_ctx##X##_t ctx;                                                \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  mdc2_final##X (&ctx);                                               \
                                                                      \
  raw[0] = ctx.h[0];                                                  \
  raw[1] = ctx.h[1];                                                  \
  raw[2] = ctx.hh[0];                                                 \
  raw[3] = ctx.hh[1];                                                 \
}

#define RECIPE_HASH_GOST(X,HS,INIT,FEED)                              \
{                                                                     \
  gost94_ctx##X##_t ctx;                                              \
                                                                      \
  INIT                                                                \
                                                                      \
  FEED                                                                \
                                                                      \
  gost94_final##X (&ctx);                                             \
                                                                      \
  for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];                      \
}

// Every step formats its output for the steps after it, except the step whose raw digest is
// compared. Without a loop that is the last step. A loop recipe names it, see RECIPE_LOOP.

#ifdef RECIPE_LOOP
#define RECIPE_FMT_STEP(K) (K) != (RECIPE_ROOT_STEP)
#else
#define RECIPE_FMT_STEP(K) (K) < (RECIPE_STEPS - 1)
#endif

// A step hashes its parts. For f^N, it hashes its output N - 1 more times in the format set by the
// output suffix. The last round is formatted and sliced for the caller, except in the final step,
// whose result is read only from raw. With N = 1, the compiler removes the unused loop. INIT starts the first round from scratch or
// from a prefix context saved during preparation.

#define RECIPE_STEP_HASH(F,K,X,HS,T,INIT) RECIPE_STEP_HASHF (F, K, X, HS, T, INIT, RECIPE_FEED (K, F, X))

#define RECIPE_STEP_HASHF(F,K,X,HS,T,INIT,FEED)                                                                  \
{                                                                                                                \
  RECIPE_HASH_##F (X, HS, INIT, FEED)                                                                            \
                                                                                                                 \
  for (u32 j = 1; j < RECIPE_S##K##_ITER; j++)                                                                   \
  {                                                                                                              \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_CFMT, K, RECIPE_LEN_##F)                                                 \
                                                                                                                 \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_UPD_##F (X) (&ctx, outs + (K * 32), (int) out_lens[K]);) \
  }                                                                                                              \
                                                                                                                 \
  if (RECIPE_FMT_STEP (K))                                                                                       \
  {                                                                                                              \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                  \
                                                                                                                 \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                       \
  }                                                                                                              \
}

// An HMAC key is a single part. Its token selects the buffer and length.

#define RECIPE_KBUF_PASS    w
#define RECIPE_KBUF_SALT    s
#define RECIPE_KBUF_SALTD   (st->sd)
#define RECIPE_KBUF_SALT2   (st->fd0)
#define RECIPE_KBUF_PEPPER  (st->fd1)
#define RECIPE_KBUF_USER    (st->fd2)
#define RECIPE_KBUF_VAR0    (vb + (0 * 64))
#define RECIPE_KBUF_VAR1    (vb + (1 * 64))
#define RECIPE_KBUF_VAR2    (vb + (2 * 64))
#define RECIPE_KBUF_VAR3    (vb + (3 * 64))
#define RECIPE_KBUF_LIT0    (lits + (0 * RECIPE_LIT_WORDS))
#define RECIPE_KBUF_LIT1    (lits + (1 * RECIPE_LIT_WORDS))
#define RECIPE_KBUF_LIT2    (lits + (2 * RECIPE_LIT_WORDS))
#define RECIPE_KBUF_LIT3    (lits + (3 * RECIPE_LIT_WORDS))
#define RECIPE_KBUF_STEP0   (outs + (0 * 32))
#define RECIPE_KBUF_STEP1   (outs + (1 * 32))
#define RECIPE_KBUF_STEP2   (outs + (2 * 32))
#define RECIPE_KBUF_STEP3   (outs + (3 * 32))
#define RECIPE_KBUF_STEP4   (outs + (4 * 32))
#define RECIPE_KBUF_STEP5   (outs + (5 * 32))
#define RECIPE_KBUF_STEP6   (outs + (6 * 32))
#define RECIPE_KBUF_STEP7   (outs + (7 * 32))
#define RECIPE_KBUF_STEP8   (outs + (8 * 32))
#define RECIPE_KBUF_STEP9   (outs + (9 * 32))
#define RECIPE_KBUF_STEP10  (outs + (10 * 32))
#define RECIPE_KBUF_STEP11  (outs + (11 * 32))
#define RECIPE_KBUF_STEP12  (outs + (12 * 32))
#define RECIPE_KBUF_STEP13  (outs + (13 * 32))
#define RECIPE_KBUF_STEP14  (outs + (14 * 32))
#define RECIPE_KBUF_STEP15  (outs + (15 * 32))
#define RECIPE_KBUF_PSTEP0  (pouts + (0 * 32))
#define RECIPE_KBUF_PSTEP1  (pouts + (1 * 32))
#define RECIPE_KBUF_PSTEP2  (pouts + (2 * 32))
#define RECIPE_KBUF_PSTEP3  (pouts + (3 * 32))
#define RECIPE_KBUF_PSTEP4  (pouts + (4 * 32))
#define RECIPE_KBUF_PSTEP5  (pouts + (5 * 32))
#define RECIPE_KBUF_PSTEP6  (pouts + (6 * 32))
#define RECIPE_KBUF_PSTEP7  (pouts + (7 * 32))
#define RECIPE_KBUF_PSTEP8  (pouts + (8 * 32))
#define RECIPE_KBUF_PSTEP9  (pouts + (9 * 32))
#define RECIPE_KBUF_PSTEP10 (pouts + (10 * 32))
#define RECIPE_KBUF_PSTEP11 (pouts + (11 * 32))
#define RECIPE_KBUF_PSTEP12 (pouts + (12 * 32))
#define RECIPE_KBUF_PSTEP13 (pouts + (13 * 32))
#define RECIPE_KBUF_PSTEP14 (pouts + (14 * 32))
#define RECIPE_KBUF_PSTEP15 (pouts + (15 * 32))
#define RECIPE_KBUF_XP0     xb0
#define RECIPE_KBUF_XP1     xb1
#define RECIPE_KBUF_XP2     xb2
#define RECIPE_KBUF_XP3     xb3
#define RECIPE_KBUF_XS0     (st->xb0)
#define RECIPE_KBUF_XS1     (st->xb1)
#define RECIPE_KBUF_XS2     (st->xb2)
#define RECIPE_KBUF_XS3     (st->xb3)

#define RECIPE_KLEN_PASS    pw_len
#define RECIPE_KLEN_SALT    salt_len
#define RECIPE_KLEN_SALTD   (st->sd_len)
#define RECIPE_KLEN_SALT2   (st->fd0_len)
#define RECIPE_KLEN_PEPPER  (st->fd1_len)
#define RECIPE_KLEN_USER    (st->fd2_len)
#define RECIPE_KLEN_VAR0    vl[0]
#define RECIPE_KLEN_VAR1    vl[1]
#define RECIPE_KLEN_VAR2    vl[2]
#define RECIPE_KLEN_VAR3    vl[3]
#define RECIPE_KLEN_LIT0    RECIPE_L0_LEN
#define RECIPE_KLEN_LIT1    RECIPE_L1_LEN
#define RECIPE_KLEN_LIT2    RECIPE_L2_LEN
#define RECIPE_KLEN_LIT3    RECIPE_L3_LEN
#define RECIPE_KLEN_STEP0   out_lens[0]
#define RECIPE_KLEN_STEP1   out_lens[1]
#define RECIPE_KLEN_STEP2   out_lens[2]
#define RECIPE_KLEN_STEP3   out_lens[3]
#define RECIPE_KLEN_STEP4   out_lens[4]
#define RECIPE_KLEN_STEP5   out_lens[5]
#define RECIPE_KLEN_STEP6   out_lens[6]
#define RECIPE_KLEN_STEP7   out_lens[7]
#define RECIPE_KLEN_STEP8   out_lens[8]
#define RECIPE_KLEN_STEP9   out_lens[9]
#define RECIPE_KLEN_STEP10  out_lens[10]
#define RECIPE_KLEN_STEP11  out_lens[11]
#define RECIPE_KLEN_STEP12  out_lens[12]
#define RECIPE_KLEN_STEP13  out_lens[13]
#define RECIPE_KLEN_STEP14  out_lens[14]
#define RECIPE_KLEN_STEP15  out_lens[15]
#define RECIPE_KLEN_PSTEP0  pout_lens[0]
#define RECIPE_KLEN_PSTEP1  pout_lens[1]
#define RECIPE_KLEN_PSTEP2  pout_lens[2]
#define RECIPE_KLEN_PSTEP3  pout_lens[3]
#define RECIPE_KLEN_PSTEP4  pout_lens[4]
#define RECIPE_KLEN_PSTEP5  pout_lens[5]
#define RECIPE_KLEN_PSTEP6  pout_lens[6]
#define RECIPE_KLEN_PSTEP7  pout_lens[7]
#define RECIPE_KLEN_PSTEP8  pout_lens[8]
#define RECIPE_KLEN_PSTEP9  pout_lens[9]
#define RECIPE_KLEN_PSTEP10 pout_lens[10]
#define RECIPE_KLEN_PSTEP11 pout_lens[11]
#define RECIPE_KLEN_PSTEP12 pout_lens[12]
#define RECIPE_KLEN_PSTEP13 pout_lens[13]
#define RECIPE_KLEN_PSTEP14 pout_lens[14]
#define RECIPE_KLEN_PSTEP15 pout_lens[15]
#define RECIPE_KLEN_XP0     xl0
#define RECIPE_KLEN_XP1     xl1
#define RECIPE_KLEN_XP2     xl2
#define RECIPE_KLEN_XP3     xl3
#define RECIPE_KLEN_XS0     (st->xl0)
#define RECIPE_KLEN_XS1     (st->xl1)
#define RECIPE_KLEN_XS2     (st->xl2)
#define RECIPE_KLEN_XS3     (st->xl3)

#define RECIPE_KBUF2(X) RECIPE_KBUF_##X
#define RECIPE_KBUF(X)  RECIPE_KBUF2 (X)
#define RECIPE_KLEN2(X) RECIPE_KLEN_##X
#define RECIPE_KLEN(X)  RECIPE_KLEN2 (X)

// A SEED step is a call such as xxh64 (pass, salt). Its key part holds the seed, read as a big
// endian number from its first 8 bytes, or 4 for xxh32, the way the hex of the seed reads. A
// shorter key gives a smaller number. The step then hashes its parts as a HASH step does.

#ifdef RECIPE_XXHASH

DECLSPEC u64 recipe_seed64_S (PRIVATE_AS const u32 *buf, const u32 len)
{
  u64 seed = 0;

  const u32 cnt = (len < 8) ? len : 8;

  for (u32 i = 0; i < cnt; i++) seed = (seed << 8) | ((buf[i / 4] >> ((i & 3) * 8)) & 0xff);

  return seed;
}

DECLSPEC u32 recipe_seed32_S (PRIVATE_AS const u32 *buf, const u32 len)
{
  u32 seed = 0;

  const u32 cnt = (len < 4) ? len : 4;

  for (u32 i = 0; i < cnt; i++) seed = (seed << 8) | ((buf[i / 4] >> ((i & 3) * 8)) & 0xff);

  return seed;
}

DECLSPEC u64x recipe_seed64 (PRIVATE_AS const u32x *buf, const u32 len)
{
  u64x seed = 0;

  const u32 cnt = (len < 8) ? len : 8;

  for (u32 i = 0; i < cnt; i++) seed = (seed << 8) | hl32_to_64 (make_u32x (0), (buf[i / 4] >> ((i & 3) * 8)) & 0xff);

  return seed;
}

DECLSPEC u32x recipe_seed32 (PRIVATE_AS const u32x *buf, const u32 len)
{
  u32x seed = 0;

  const u32 cnt = (len < 4) ? len : 4;

  for (u32 i = 0; i < cnt; i++) seed = (seed << 8) | ((buf[i / 4] >> ((i & 3) * 8)) & 0xff);

  return seed;
}

#endif

#define RECIPE_SEED_xxh64(X,HS,KEY) xxh64_init##X (&ctx, recipe_seed64##HS (RECIPE_KBUF (KEY), (u32) RECIPE_KLEN (KEY)));
#define RECIPE_SEED_xxh32(X,HS,KEY) xxh32_init##X (&ctx, recipe_seed32##HS (RECIPE_KBUF (KEY), (u32) RECIPE_KLEN (KEY)));

#define RECIPE_SEED3(F,X,HS,KEY) RECIPE_SEED_##F (X, HS, KEY)
#define RECIPE_SEED2(F,X,HS,KEY) RECIPE_SEED3 (F, X, HS, KEY)

#define RECIPE_STEP_SEED(F,K,X,HS,T,INIT) RECIPE_STEP_HASHF (F, K, X, HS, T, RECIPE_SEED2 (F, X, HS, RECIPE_S##K##_KEY), RECIPE_FEED (K, F, X))

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
#define RECIPE_KS_wrl(HS,V)        hc_swap32##HS (V)

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
#define RECIPE_UB_wrl(X)        whirlpool_update##X##_64

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

// Word I of the LEN-byte digest in R, as an HMAC feeds a hashed key or its inner digest back into
// its hash. Streebog feeds them in the reverse byte order of its hex output, as hashcat's
// HMAC-Streebog modes and hx do.

#define RECIPE_KW_md4(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_md5(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_sha1(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_sha224(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_sha256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_sha384(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_sha512(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_rmd160(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_blake2b512(HS,R,I,LEN)  (R)[I]
#define RECIPE_KW_blake2b256(HS,R,I,LEN)  (R)[I]
#define RECIPE_KW_blake2s256(HS,R,I,LEN)  (R)[I]
#define RECIPE_KW_sm3(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_wrl(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_sha3_224(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_sha3_256(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_sha3_384(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_sha3_512(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_keccak224(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_keccak256(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_keccak384(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_keccak512(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_streebog_32(HS,R,I,LEN) hc_swap32##HS ((R)[((LEN) / 4) - 1 - (I)])
#define RECIPE_KW_streebog_64(HS,R,I,LEN) hc_swap32##HS ((R)[((LEN) / 4) - 1 - (I)])
#define RECIPE_KW_gost(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_rmd320(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_rmd128(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_rmd256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_md2(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_sha0(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_sne128(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_sne256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_skein224(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_skein256(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_skein384(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_skein512(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_panama(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_tiger(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_tiger128(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_tiger160(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_tiger2(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_tth(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_hav128(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_hav128_4(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav128_5(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav160_3(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav160_4(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav160_5(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav192_3(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav192_4(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav192_5(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav224_3(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav224_4(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav224_5(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_hav256_4(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_hav256_5(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_gost_crypto(HS,R,I,LEN) (R)[I]

#define RECIPE_KW_blake224(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_blake256(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_blake384(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_blake512(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_bmw224(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_bmw256(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_bmw384(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_bmw512(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_cube224(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_cube256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_cube384(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_cube512(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_echo224(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_echo256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_echo384(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_echo512(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_fugue224(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_fugue256(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_fugue384(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_fugue512(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_groestl224(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_groestl256(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_groestl384(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_groestl512(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_hamsi224(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_hamsi256(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_hamsi384(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_hamsi512(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_jh224(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_jh256(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_jh384(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_jh512(HS,R,I,LEN)        (R)[I]
#define RECIPE_KW_luffa224(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_luffa256(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_luffa384(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_luffa512(HS,R,I,LEN)     (R)[I]
#define RECIPE_KW_shabal224(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_shabal256(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_shabal384(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_shabal512(HS,R,I,LEN)    (R)[I]
#define RECIPE_KW_shavite224(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_shavite256(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_shavite384(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_shavite512(HS,R,I,LEN)   (R)[I]
#define RECIPE_KW_simd224(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_simd256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_simd384(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_simd512(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_has160(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_edon256(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_edon512(HS,R,I,LEN)      (R)[I]
#define RECIPE_KW_md6(HS,R,I,LEN)          (R)[I]
#define RECIPE_KW_md6256(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_md6512(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_radiogatun32(HS,R,I,LEN) (R)[I]
#define RECIPE_KW_radiogatun64(HS,R,I,LEN) (R)[I]
#define RECIPE_KW_ripemd(HS,R,I,LEN)       (R)[I]
#define RECIPE_KW_wrl0(HS,R,I,LEN)         (R)[I]
#define RECIPE_KW_wrl1(HS,R,I,LEN)         (R)[I]

// Feed the LEN-byte inner digest in raw to the outer hash as one block, in reverse byte order.

#define RECIPE_RAWREV64(F,X,HS,T,LEN)                                                                   \
{                                                                                                       \
  T p0[4];                                                                                              \
  T p1[4];                                                                                              \
  T p2[4];                                                                                              \
  T p3[4];                                                                                              \
                                                                                                        \
  for (u32 i = 0; i < 4; i++)                                                                           \
  {                                                                                                     \
    p0[i] = (( 0 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, RECIPE_KW_##F (HS, raw,  0 + i, LEN)) : 0;    \
    p1[i] = (( 4 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, RECIPE_KW_##F (HS, raw,  4 + i, LEN)) : 0;    \
    p2[i] = (( 8 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, RECIPE_KW_##F (HS, raw,  8 + i, LEN)) : 0;    \
    p3[i] = ((12 + i) < ((LEN) / 4)) ? RECIPE_KS_##F (HS, RECIPE_KW_##F (HS, raw, 12 + i, LEN)) : 0;    \
  }                                                                                                     \
                                                                                                        \
  RECIPE_UB_##F (X) (&ctx, p0, p1, p2, p3, LEN);                                                        \
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
#define RECIPE_RAW_wrl        RECIPE_RAW64

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
#define RECIPE_PAD_wrl        RECIPE_PAD64

// Write the UTF-16LE form of the len bytes of UTF-8 in src to the dst_sz bytes of dst, which have to
// be zero, decoded with hc_enc as the utf16le updates decode it. Return its length, or -1 when it is
// not valid UTF-8 or does not fit. ASCII skips the decoder, as in the utf16le updates.

DECLSPEC int recipe_utf16le_S (PRIVATE_AS const u32 *src, const int len, PRIVATE_AS u32 *dst, const int dst_sz)
{
  if (hc_enc_scan (src, len) == 0)
  {
    const int r = len * 2;

    if (r > dst_sz) return -1;

    for (int i = 0; i < ((r + 3) / 4); i++)
    {
      const int j = i / 2;

      const u32 v = hc_bounded_word_le_S (src, j, len - (j * 4));
      const u32 h = ((i & 1) == 0) ? (v >> 0) : (v >> 16);

      dst[i] = ((h >> 0) & 0xff) | ((h << 8) & 0xff0000);
    }

    return r;
  }

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  // hc_enc_next () checks the end of a multi-byte sequence against the source size. A field holds
  // only 84 bytes, so the size is len: a sequence cut off at the end is rejected without reading
  // the word past it.

  const int r = hc_enc_next (&hc_enc, src, len, len, dst, dst_sz);

  if (hc_enc_has_next (&hc_enc, len)) return -1;

  return r;
}

// The families whose context holds a chaining value and a block buffer, RECIPE_S<k>_HT, hash the
// key pads and the outer block of an HMAC with their transform, as the hash includes' HMAC helpers
// do, and so do the block templates of RECIPE_LOOP. Through the block update and the final, nvcc
// keeps the outer hash out of line, with its context in local memory. RECIPE_TBE is 1 for the
// families with big endian block words.

#define RECIPE_TBE_md4    0
#define RECIPE_TBE_md5    0
#define RECIPE_TBE_rmd160 0
#define RECIPE_TBE_sha1   1
#define RECIPE_TBE_sha224 1
#define RECIPE_TBE_sha256 1
#define RECIPE_TBE_sha384 1
#define RECIPE_TBE_sha512 1
#define RECIPE_TBE_sm3    1

#define RECIPE_TX64(N,B,H)  N (B + 0, B + 4, B + 8, B + 12, H);
#define RECIPE_TX128(N,B,H) N (B + 0, B + 4, B + 8, B + 12, B + 16, B + 20, B + 24, B + 28, H);

// The family's transform of the block in B on the digest state H, in flavor X.

#define RECIPE_TXS_md4(X,B,H)    RECIPE_TX64  (md4_transform##X,       B, H)
#define RECIPE_TXS_md5(X,B,H)    RECIPE_TX64  (md5_transform##X,       B, H)
#define RECIPE_TXS_rmd160(X,B,H) RECIPE_TX64  (ripemd160_transform##X, B, H)
#define RECIPE_TXS_sha1(X,B,H)   RECIPE_TX64  (sha1_transform##X,      B, H)
#define RECIPE_TXS_sha224(X,B,H) RECIPE_TX64  (sha224_transform##X,    B, H)
#define RECIPE_TXS_sha256(X,B,H) RECIPE_TX64  (sha256_transform##X,    B, H)
#define RECIPE_TXS_sm3(X,B,H)    RECIPE_TX64  (sm3_transform##X,       B, H)
#define RECIPE_TXS_sha384(X,B,H) RECIPE_TX128 (sha384_transform##X,    B, H)
#define RECIPE_TXS_sha512(X,B,H) RECIPE_TX128 (sha512_transform##X,    B, H)

#define RECIPE_FIN_md4(X)    md4_final##X (&ctx);
#define RECIPE_FIN_md5(X)    md5_final##X (&ctx);
#define RECIPE_FIN_rmd160(X) ripemd160_final##X (&ctx);
#define RECIPE_FIN_sha1(X)   sha1_final##X (&ctx);
#define RECIPE_FIN_sha224(X) sha224_final##X (&ctx);
#define RECIPE_FIN_sha256(X) sha256_final##X (&ctx);
#define RECIPE_FIN_sm3(X)    sm3_final##X (&ctx);
#define RECIPE_FIN_sha384(X) sha384_final##X (&ctx);
#define RECIPE_FIN_sha512(X) sha512_final##X (&ctx);

// The bit length in the last words of the last block: little endian for MD4, MD5 and RIPEMD-160,
// big endian words for the others.

#define RECIPE_TLW_md4(B,NB,M)    B[((NB) * 16) - 2] = (M) * 8;
#define RECIPE_TLW_md5(B,NB,M)    B[((NB) * 16) - 2] = (M) * 8;
#define RECIPE_TLW_rmd160(B,NB,M) B[((NB) * 16) - 2] = (M) * 8;
#define RECIPE_TLW_sha1(B,NB,M)   B[((NB) * 16) - 1] = (M) * 8;
#define RECIPE_TLW_sha224(B,NB,M) B[((NB) * 16) - 1] = (M) * 8;
#define RECIPE_TLW_sha256(B,NB,M) B[((NB) * 16) - 1] = (M) * 8;
#define RECIPE_TLW_sm3(B,NB,M)    B[((NB) * 16) - 1] = (M) * 8;
#define RECIPE_TLW_sha384(B,NB,M) B[((NB) * 32) - 1] = (M) * 8;
#define RECIPE_TLW_sha512(B,NB,M) B[((NB) * 32) - 1] = (M) * 8;

// The digest state as little endian words in raw, as RECIPE_HASH_* leaves it.

#define RECIPE_TRAW_md4(HS)    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];
#define RECIPE_TRAW_md5(HS)    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];
#define RECIPE_TRAW_rmd160(HS) for (u32 i = 0; i < 5; i++) raw[i] = ctx.h[i];
#define RECIPE_TRAW_sha1(HS)   for (u32 i = 0; i < 5; i++) raw[i] = hc_swap32##HS (ctx.h[i]);
#define RECIPE_TRAW_sha224(HS) for (u32 i = 0; i < 7; i++) raw[i] = hc_swap32##HS (ctx.h[i]);
#define RECIPE_TRAW_sha256(HS) for (u32 i = 0; i < 8; i++) raw[i] = hc_swap32##HS (ctx.h[i]);
#define RECIPE_TRAW_sm3(HS)    for (u32 i = 0; i < 8; i++) raw[i] = hc_swap32##HS (ctx.h[i]);
#define RECIPE_TRAW_sha384(HS) for (u32 i = 0; i < 6; i++) { raw[(i * 2) + 0] = hc_swap32##HS (h32_from_64##HS (ctx.h[i])); raw[(i * 2) + 1] = hc_swap32##HS (l32_from_64##HS (ctx.h[i])); }
#define RECIPE_TRAW_sha512(HS) for (u32 i = 0; i < 8; i++) { raw[(i * 2) + 0] = hc_swap32##HS (h32_from_64##HS (ctx.h[i])); raw[(i * 2) + 1] = hc_swap32##HS (l32_from_64##HS (ctx.h[i])); }

// The digest state as the first words of a block in the family's word order, which takes no byte
// swap on the way from the inner hash to the outer one.

#define RECIPE_TOW32(N,HS,B) for (u32 i = 0; i < (N); i++) B[i] = ctx.h[i];
#define RECIPE_TOW64(N,HS,B) for (u32 i = 0; i < (N); i++) { B[(i * 2) + 0] = h32_from_64##HS (ctx.h[i]); B[(i * 2) + 1] = l32_from_64##HS (ctx.h[i]); }

#define RECIPE_TOW_md4(HS,B)    RECIPE_TOW32 (4, HS, B)
#define RECIPE_TOW_md5(HS,B)    RECIPE_TOW32 (4, HS, B)
#define RECIPE_TOW_rmd160(HS,B) RECIPE_TOW32 (5, HS, B)
#define RECIPE_TOW_sha1(HS,B)   RECIPE_TOW32 (5, HS, B)
#define RECIPE_TOW_sha224(HS,B) RECIPE_TOW32 (7, HS, B)
#define RECIPE_TOW_sha256(HS,B) RECIPE_TOW32 (8, HS, B)
#define RECIPE_TOW_sm3(HS,B)    RECIPE_TOW32 (8, HS, B)
#define RECIPE_TOW_sha384(HS,B) RECIPE_TOW64 (6, HS, B)
#define RECIPE_TOW_sha512(HS,B) RECIPE_TOW64 (8, HS, B)

// The outer block of an HMAC in B, from the inner context after its final: the inner digest, the
// 0x80 byte and the bit length of the opad block and the digest.

#define RECIPE_TOB(F,HS,B)                                           \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) B[i] = 0;         \
                                                                     \
  RECIPE_TOW_##F (HS, B)                                             \
                                                                     \
  B[RECIPE_LEN_##F / 4] = (RECIPE_TBE_##F == 1) ? 0x80000000 : 0x80; \
                                                                     \
  RECIPE_TLW_##F (B, 1, RECIPE_BLOCK_##F + RECIPE_LEN_##F)

// Compute HMAC from two plain hashes, feeding parts as in a normal hash step. Hash keys longer than
// the block size first, then pad the key to the block size. The result is
// H (key ^ opad . H (key ^ ipad . parts)). The outer hash reads the digest from raw as one block.

// Store HMAC step K's key block in kb. Hash the key first if it exceeds the block size, then pad
// it with zero bytes to the block size. RECIPE_KBW gives the words of kb, which also hold a hashed
// key longer than the block, and kpl the length of the pads, which cover all bytes of such a key.
// RECIPE_S<k>_KW marks a utf16le key, which RECIPE_S<k>_KEYB names without its utf16le. Scalar
// evaluation decodes it into the block. A key whose UTF-16LE form does not fit, or that is not
// valid UTF-8, is hashed through the utf16le update instead, which also leaves invalid UTF-8 unable
// to match. Vector evaluation handles only ASCII, see recipe_eval (), and inserts a zero byte after
// each byte.

#define RECIPE_KBW(F) (((RECIPE_LEN_##F > RECIPE_BLOCK_##F) ? RECIPE_LEN_##F : RECIPE_BLOCK_##F) / 4)

#define RECIPE_KEYBLOCK3(W,F,K,X,HS,T) RECIPE_KEYBLOCK_##W (F, K, X, HS, T)
#define RECIPE_KEYBLOCK2(W,F,K,X,HS,T) RECIPE_KEYBLOCK3 (W, F, K, X, HS, T)
#define RECIPE_KEYBLOCK(F,K,X,HS,T)    RECIPE_KEYBLOCK2 (RECIPE_S##K##_KW, F, K, X, HS, T)

#define RECIPE_KEYBLOCK_1(F,K,X,HS,T) RECIPE_KEYW##X (F, K, X, HS, T)

#define RECIPE_KEYW(F,K,X,HS,T)                                                                                                \
  T kb[RECIPE_KBW (F)];                                                                                                        \
                                                                                                                               \
  u32 kpl = RECIPE_BLOCK_##F;                                                                                                  \
                                                                                                                               \
  for (u32 i = 0; i < RECIPE_KBW (F); i++) kb[i] = 0;                                                                          \
                                                                                                                               \
  if (recipe_utf16le_S (RECIPE_KBUF (RECIPE_S##K##_KEYB), (int) RECIPE_KLEN (RECIPE_S##K##_KEYB), kb, RECIPE_BLOCK_##F) == -1) \
  {                                                                                                                            \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PART2 (RECIPE_S##K##_KEY, F, X))                                       \
                                                                                                                               \
    for (u32 i = 0; i < RECIPE_KBW (F);       i++) kb[i] = 0;                                                                  \
    for (u32 i = 0; i < (RECIPE_LEN_##F / 4); i++) kb[i] = RECIPE_KW_##F (HS, raw, i, RECIPE_LEN_##F);                         \
                                                                                                                               \
    kpl = RECIPE_KBW (F) * 4;                                                                                                  \
  }

#define RECIPE_KEYW_vector(F,K,X,HS,T)                                                                                            \
  T kb[RECIPE_KBW (F)];                                                                                                           \
                                                                                                                                  \
  u32 kpl = RECIPE_BLOCK_##F;                                                                                                     \
                                                                                                                                  \
  for (u32 i = 0; i < RECIPE_KBW (F); i++) kb[i] = 0;                                                                             \
                                                                                                                                  \
  if ((RECIPE_KLEN (RECIPE_S##K##_KEYB) * 2) > RECIPE_BLOCK_##F)                                                                  \
  {                                                                                                                               \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PART2 (RECIPE_S##K##_KEY, F, X))                                          \
                                                                                                                                  \
    for (u32 i = 0; i < (RECIPE_LEN_##F / 4); i++) kb[i] = RECIPE_KW_##F (HS, raw, i, RECIPE_LEN_##F);                            \
                                                                                                                                  \
    kpl = RECIPE_KBW (F) * 4;                                                                                                     \
  }                                                                                                                               \
  else                                                                                                                            \
  {                                                                                                                               \
    for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++)                                                                              \
    {                                                                                                                             \
      const int j = (int) (i / 2);                                                                                                \
                                                                                                                                  \
      const T v = hc_bounded_word_le##HS (RECIPE_KBUF (RECIPE_S##K##_KEYB), j, (int) RECIPE_KLEN (RECIPE_S##K##_KEYB) - (j * 4)); \
      const T h = ((i & 1) == 0) ? (v >> 0) : (v >> 16);                                                                          \
                                                                                                                                  \
      kb[i] = ((h >> 0) & 0xff) | ((h << 8) & 0xff0000);                                                                          \
    }                                                                                                                             \
  }

#define RECIPE_KEYBLOCK_0(F,K,X,HS,T)                                                                                                                                            \
  T kb[RECIPE_KBW (F)];                                                                                                                                                          \
                                                                                                                                                                                 \
  u32 kpl = RECIPE_BLOCK_##F;                                                                                                                                                    \
                                                                                                                                                                                 \
  for (u32 i = 0; i < RECIPE_KBW (F); i++) kb[i] = 0;                                                                                                                            \
                                                                                                                                                                                 \
  if (RECIPE_KLEN (RECIPE_S##K##_KEY) > RECIPE_BLOCK_##F)                                                                                                                        \
  {                                                                                                                                                                              \
    RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PART2 (RECIPE_S##K##_KEY, F, X))                                                                                         \
                                                                                                                                                                                 \
    for (u32 i = 0; i < (RECIPE_LEN_##F / 4); i++) kb[i] = RECIPE_KW_##F (HS, raw, i, RECIPE_LEN_##F);                                                                           \
                                                                                                                                                                                 \
    kpl = RECIPE_KBW (F) * 4;                                                                                                                                                    \
  }                                                                                                                                                                              \
  else                                                                                                                                                                           \
  {                                                                                                                                                                              \
    for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) kb[i] = hc_bounded_word_le##HS (RECIPE_KBUF (RECIPE_S##K##_KEY), i, (int) RECIPE_KLEN (RECIPE_S##K##_KEY) - (int) (i * 4)); \
  }

#define RECIPE_SHM_0(F,K,X,HS,T)                                                                                                           \
{                                                                                                                                          \
  RECIPE_KEYBLOCK (F, K, X, HS, T)                                                                                                         \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PAD_##F (F, X, HS, T, 0x36363636) RECIPE_FEED (K, F, X))                             \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, RECIPE_INIT_##F (X), RECIPE_PAD_##F (F, X, HS, T, 0x5c5c5c5c) RECIPE_RAW_##F (F, X, HS, T, RECIPE_LEN_##F))      \
                                                                                                                                           \
  if (RECIPE_FMT_STEP (K))                                                                                                                 \
  {                                                                                                                                        \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                                            \
                                                                                                                                           \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                                                 \
  }                                                                                                                                        \
}

// Under RECIPE_S<k>_HT, RECIPE_TPO picks the order per family. With 0, both pads are hashed first,
// as the native kernels do, and the inner hash keeps the opad state live rather than the whole key
// block. With 1, the opad block is hashed after the inner hash, as RECIPE_SHM_0 does, because
// hashing both pads first is slower for SHA-384 and SHA-512 under HIP. With 2, the step takes
// RECIPE_SHM_0 itself, as MD5 does, for which the transform path is slower in either order.

#define RECIPE_TPO_md4    0
#define RECIPE_TPO_md5    2
#define RECIPE_TPO_rmd160 0
#define RECIPE_TPO_sha1   0
#define RECIPE_TPO_sha224 0
#define RECIPE_TPO_sha256 0
#define RECIPE_TPO_sm3    0
#define RECIPE_TPO_sha384 1
#define RECIPE_TPO_sha512 1

#define RECIPE_SHMP_0(F,K,X,HS,T)                                            \
{                                                                            \
  RECIPE_CTX_##F (X) hi;                                                     \
  RECIPE_CTX_##F (X) ho;                                                     \
                                                                             \
  RECIPE_PADS_1 (F, K, X, HS, T, hi, ho, )                                   \
                                                                             \
  RECIPE_HIO_1 (F, K, X, HS, T, ctx = hi;, ctx = ho;, RECIPE_FEED (K, F, X)) \
}

// The pad block of the key block kb in pb, hashed from the initial state.

#define RECIPE_TPAD(F,X,XOR)                                              \
  RECIPE_INIT_##F (X)                                                     \
                                                                          \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) pb[i] = kb[i] ^ (XOR); \
                                                                          \
  RECIPE_TXS_##F (X, pb, ctx.h)                                           \
                                                                          \
  ctx.len = RECIPE_BLOCK_##F;

#define RECIPE_SHMP_1(F,K,X,HS,T)                                                                                     \
{                                                                                                                     \
  RECIPE_KEYBLOCK (F, K, X, HS, T)                                                                                    \
                                                                                                                      \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) kb[i] = RECIPE_KS_##F (HS, kb[i]);                                 \
                                                                                                                      \
  T pb[RECIPE_BLOCK_##F / 4];                                                                                         \
                                                                                                                      \
  RECIPE_HIO_1 (F, K, X, HS, T, RECIPE_TPAD (F, X, 0x36363636), RECIPE_TPAD (F, X, 0x5c5c5c5c), RECIPE_FEED (K, F, X)) \
}

#define RECIPE_SHMP_2(F,K,X,HS,T) RECIPE_SHM_0 (F, K, X, HS, T)

#define RECIPE_SHMP3(O,F,K,X,HS,T) RECIPE_SHMP_##O (F, K, X, HS, T)
#define RECIPE_SHMP2(O,F,K,X,HS,T) RECIPE_SHMP3 (O, F, K, X, HS, T)
#define RECIPE_SHM_1(F,K,X,HS,T)   RECIPE_SHMP2 (RECIPE_TPO_##F, F, K, X, HS, T)

#define RECIPE_SHM3(H,F,K,X,HS,T)         RECIPE_SHM_##H (F, K, X, HS, T)
#define RECIPE_SHM2(H,F,K,X,HS,T)         RECIPE_SHM3 (H, F, K, X, HS, T)
#define RECIPE_STEP_HMAC(F,K,X,HS,T,INIT) RECIPE_SHM2 (RECIPE_S##K##_HT, F, K, X, HS, T)

// An HMAC with a key independent of the candidate starts from the two saved pad contexts. The inner
// context also includes leading parts independent of the candidate.

#define RECIPE_STEP_HMACS(F,K,X,HS,T) RECIPE_STEP_HMACSF (F, K, X, HS, T, ctx = st->hi##K;, RECIPE_FEED (K, F, X))

// An AES step, see OpenCL/inc_cipher_aes-modes.cl and RECIPE_KIND_AES in src/recipe.c. Each data
// part is placed after the one before it with its fixed length, and the bytes beyond a shorter part
// remain zero. A part of the salt's length, with RECIPE_S<k>_PL<i> 0, takes its length at run time,
// up to the room RECIPE_S<k>_AVAR that the other parts leave it. Such data gives an output of its
// own length, or an empty one for a length the operation cannot take, as in hx. The raw buffer
// receives the output in the same format as a hash call's digest. A failed aes_unwrap check leaves
// the output zero. Operation 5 performs the unwrap for length (aes_unwrap (...)) > 0 and gives its
// 8 byte integrity check value. The AES functions take one candidate, so a vector of candidates
// runs them a lane at a time.

#ifdef RECIPE_AES

// An unused part or IV names lits, which recipe_prep () has as well as recipe_eval (), as an AES
// step that does not depend on the candidate runs in recipe_prep ().

#define RECIPE_KBUF_NONE lits
#define RECIPE_KLEN_NONE 0

#define RECIPE_AP3(TOK,PL,ROOM) { const u32 l = (u32) RECIPE_KLEN (TOK); const u32 m = ((PL) > 0) ? (u32) (PL) : (u32) (ROOM); const u32 n = (l > m) ? m : l; for (u32 j = 0; j < n; j++) RECIPE_XPUT (ad, ao + j, RECIPE_XGET (RECIPE_KBUF (TOK), j)); ao += ((PL) > 0) ? (u32) (PL) : n; }
#define RECIPE_AP2(TOK,PL,ROOM) RECIPE_AP3 (TOK, PL, ROOM)
#define RECIPE_AP(K,I)          RECIPE_AP2 (RECIPE_S##K##_P##I, RECIPE_S##K##_PL##I, RECIPE_S##K##_AVAR)

#define RECIPE_AALL(K) RECIPE_AP (K, 0) RECIPE_AP (K, 1) RECIPE_AP (K, 2) RECIPE_AP (K, 3) RECIPE_AP (K, 4) RECIPE_AP (K, 5) RECIPE_AP (K, 6) RECIPE_AP (K, 7)

// The output length for N bytes of data of the salt's length, 0 for a length the operation cannot
// take.

#define RECIPE_ARL_1(N) ((((N) >= 16) && ((N) <= 64) && (((N) % 16) == 0)) ? (N) : 0)
#define RECIPE_ARL_2(N) RECIPE_ARL_1 (N)
#define RECIPE_ARL_3(N) RECIPE_ARL_1 (N)
#define RECIPE_ARL_4(N) ((((N) >= 16) && ((N) <= 72) && (((N) % 8) == 0)) ? ((N) - 8) : 0)
#define RECIPE_ARL_5(N) ((((N) >= 16) && ((N) <= 72) && (((N) % 8) == 0)) ? 8 : 0)

#define RECIPE_ARL3(O,N) RECIPE_ARL_##O (N)
#define RECIPE_ARL2(O,N) RECIPE_ARL3 (O, N)

#define RECIPE_ATE     st->aes_te0, st->aes_te1, st->aes_te2, st->aes_te3, st->aes_te4
#define RECIPE_ATD     st->aes_td0, st->aes_td1, st->aes_td2, st->aes_td3, st->aes_td4
#define RECIPE_ATK     st->aes_te0, st->aes_te1, st->aes_te2, st->aes_te3

// Run operation O of step K with key KB, IV IB and DN bytes of data DB, writing RB.

#define RECIPE_AOP_1(K,KB,IB,DB,DN,RB) aes_ecb_encrypt_swap (KB, RECIPE_S##K##_KLEN, DB, DN, RB, RECIPE_ATE);
#define RECIPE_AOP_2(K,KB,IB,DB,DN,RB) aes_cbc_encrypt_swap (KB, RECIPE_S##K##_KLEN, IB, DB, DN, RB, RECIPE_ATE);
#define RECIPE_AOP_3(K,KB,IB,DB,DN,RB) aes_cbc_decrypt_swap (KB, RECIPE_S##K##_KLEN, IB, DB, DN, RB, RECIPE_ATK, RECIPE_ATD);
#define RECIPE_AOP_4(K,KB,IB,DB,DN,RB) if (aes_unwrap_swap (KB, RECIPE_S##K##_KLEN, DB, DN, RB, RECIPE_ATK, RECIPE_ATD) == 0) { for (u32 i = 0; i < 16; i++) RB[i] = 0; }
#define RECIPE_AOP_5(K,KB,IB,DB,DN,RB) aes_unwrap_iv_swap (KB, RECIPE_S##K##_KLEN, DB, DN, RB, RECIPE_ATK, RECIPE_ATD);

#define RECIPE_AOP3(O,K,KB,IB,DB,DN,RB) RECIPE_AOP_##O (K, KB, IB, DB, DN, RB)
#define RECIPE_AOP2(O,K,KB,IB,DB,DN,RB) RECIPE_AOP3 (O, K, KB, IB, DB, DN, RB)
#define RECIPE_AOP(K,KB,IB,DB,DN,RB)    RECIPE_AOP2 (RECIPE_S##K##_AOP, K, KB, IB, DB, DN, RB)

#define RECIPE_ARUN_S(K,DN) { RECIPE_AOP (K, RECIPE_KBUF (RECIPE_S##K##_KEY), RECIPE_KBUF (RECIPE_S##K##_IV), ad, DN, raw) }

#if VECT_SIZE == 1
#define RECIPE_ARUN(K,DN) RECIPE_ARUN_S (K, DN)
#else
#define RECIPE_ARUN(K,DN)                                                                       \
{                                                                                               \
  for (int lane = 0; lane < VECT_SIZE; lane++)                                                  \
  {                                                                                             \
    u32 lk[8];                                                                                  \
    u32 li[4];                                                                                  \
    u32 ld[18];                                                                                 \
    u32 lr[16];                                                                                 \
                                                                                                \
    hc_vector_get_lane (lk, RECIPE_KBUF (RECIPE_S##K##_KEY), RECIPE_S##K##_KLEN, lane);         \
    hc_vector_get_lane (li, RECIPE_KBUF (RECIPE_S##K##_IV), 16, lane);                          \
    hc_vector_get_lane (ld, ad, (int) (DN), lane);                                              \
                                                                                                \
    for (u32 i = 0; i < 16; i++) lr[i] = 0;                                                     \
                                                                                                \
    RECIPE_AOP (K, lk, li, ld, DN, lr)                                                          \
                                                                                                \
    hc_vector_set_lane (raw, lr, 16, lane);                                                     \
  }                                                                                             \
}
#endif

#define RECIPE_STEP_AES(F,K,X,HS,T,INIT)                                                                                \
{                                                                                                                       \
  T ad[18];                                                                                                             \
                                                                                                                        \
  for (u32 i = 0; i < 18; i++) ad[i] = 0;                                                                               \
                                                                                                                        \
  u32 ao = 0;                                                                                                           \
                                                                                                                        \
  RECIPE_AALL (K)                                                                                                       \
                                                                                                                        \
  for (u32 i = 0; i < 16; i++) raw[i] = 0;                                                                              \
                                                                                                                        \
  const u32 dn = (RECIPE_S##K##_AVAR > 0) ? ao : (u32) RECIPE_S##K##_DLEN;                                              \
  const u32 rn = (RECIPE_S##K##_AVAR > 0) ? (u32) RECIPE_ARL2 (RECIPE_S##K##_AOP, dn) : (u32) RECIPE_S##K##_RLEN;       \
                                                                                                                        \
  if (rn > 0) RECIPE_ARUN##HS (K, dn)                                                                                   \
                                                                                                                        \
  if (RECIPE_FMT_STEP (K))                                                                                              \
  {                                                                                                                     \
    if (RECIPE_S##K##_AVAR > 0)                                                                                         \
    {                                                                                                                   \
      RECIPE_BFMT2 (RECIPE_S##K##_FMT, T, HS, K, rn, RECIPE_S##K##_RLEN)                                                \
    }                                                                                                                   \
    else                                                                                                                \
    {                                                                                                                   \
      RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_S##K##_RLEN)                                                   \
                                                                                                                        \
      RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                            \
    }                                                                                                                   \
  }                                                                                                                     \
}

#endif

// A bitwise step applies xor, and or or. See RECIPE_KIND_BOP in src/recipe.c. It combines its 2
// parts byte by byte into raw. The shorter part repeats to the length of the longer one. An
// empty part produces an empty output. Parts of equal length are combined a word at a time. The
// step formats the output at its current length, up to RECIPE_S<k>_BMAX bytes, and cuts it when
// RECIPE_S<k>_BFIX is set.

#define RECIPE_BOP_1(A,B) ((A) ^ (B))
#define RECIPE_BOP_2(A,B) ((A) & (B))
#define RECIPE_BOP_3(A,B) ((A) | (B))

#define RECIPE_BOP3(O,A,B) RECIPE_BOP_##O (A, B)
#define RECIPE_BOP2(O,A,B) RECIPE_BOP3 (O, A, B)
#define RECIPE_BOP(K,A,B)  RECIPE_BOP2 (RECIPE_S##K##_BOP, A, B)

// Format N bytes of raw according to the format number: hex, raw, uppercase hex or base64. Hex and
// raw convert M bytes, covering the whole words that N can reach, while retaining N as the length.

#define RECIPE_BFMT_0(T,HS,K,N,M) RECIPE_FORMAT_TXT (T, HS, 0, K, M) out_lens[K] = (N) * 2;
#define RECIPE_BFMT_1(T,HS,K,N,M) RECIPE_FORMAT_TXT (T, HS, 1, K, M) out_lens[K] = (N);
#define RECIPE_BFMT_2(T,HS,K,N,M) RECIPE_FORMAT_TXT (T, HS, 2, K, M) out_lens[K] = (N) * 2;
#define RECIPE_BFMT_3(T,HS,K,N,M) RECIPE_FORMAT_3 (T, HS, 3, K, N)

#define RECIPE_BFMT3(F,T,HS,K,N,M) RECIPE_BFMT_##F (T, HS, K, N, M)
#define RECIPE_BFMT2(F,T,HS,K,N,M) RECIPE_BFMT3 (F, T, HS, K, N, M)

#define RECIPE_STEP_BOP(F,K,X,HS,T,INIT)                                                                                         \
{                                                                                                                                \
  const u32 la = (u32) RECIPE_KLEN (RECIPE_S##K##_P0);                                                                           \
  const u32 lb = (u32) RECIPE_KLEN (RECIPE_S##K##_P1);                                                                           \
                                                                                                                                 \
  u32 n = (la > lb) ? la : lb;                                                                                                   \
                                                                                                                                 \
  if (n > 64) n = 64;                                                                                                            \
                                                                                                                                 \
  if ((la == 0) || (lb == 0)) n = 0;                                                                                             \
                                                                                                                                 \
  for (u32 i = 0; i < 16; i++) raw[i] = 0;                                                                                       \
                                                                                                                                 \
  if (la == lb)                                                                                                                  \
  {                                                                                                                              \
    for (u32 i = 0; i < ((n + 3) / 4); i++) raw[i] = RECIPE_BOP (K, RECIPE_KBUF (RECIPE_S##K##_P0)[i], RECIPE_KBUF (RECIPE_S##K##_P1)[i]); \
                                                                                                                                 \
    if ((n & 3) != 0) raw[n / 4] &= (1u << ((n & 3) * 8)) - 1;                                                                   \
  }                                                                                                                              \
  else                                                                                                                           \
  {                                                                                                                              \
    u32 ia = 0;                                                                                                                  \
    u32 ib = 0;                                                                                                                  \
                                                                                                                                 \
    for (u32 i = 0; i < n; i++)                                                                                                  \
    {                                                                                                                            \
      const T a = RECIPE_XGET (RECIPE_KBUF (RECIPE_S##K##_P0), ia);                                                              \
      const T b = RECIPE_XGET (RECIPE_KBUF (RECIPE_S##K##_P1), ib);                                                              \
                                                                                                                                 \
      RECIPE_XPUT (raw, i, RECIPE_BOP (K, a, b));                                                                                \
                                                                                                                                 \
      ia++;                                                                                                                      \
      ib++;                                                                                                                      \
                                                                                                                                 \
      if (ia == la) ia = 0;                                                                                                      \
      if (ib == lb) ib = 0;                                                                                                      \
    }                                                                                                                            \
  }                                                                                                                              \
                                                                                                                                 \
  if (RECIPE_FMT_STEP (K))                                                                                                       \
  {                                                                                                                              \
    RECIPE_BFMT2 (RECIPE_S##K##_FMT, T, HS, K, n, RECIPE_S##K##_BMAX)                                                            \
                                                                                                                                 \
    if (RECIPE_S##K##_BFIX == 1) RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                          \
  }                                                                                                                              \
}

// A DES step encrypts one block of 8 bytes, see RECIPE_KIND_DES in src/recipe.c. Its 2 parts are
// the key and the data. Of the key, des reads 8 bytes, des3 24 bytes and des_block 7 bytes, and of
// the data 8 bytes. Shorter values are padded with zero bytes, as in hx. des3 encrypts with the
// first key, decrypts with the second and encrypts with the third. des_block spreads its 7 bytes
// over the 8 bytes of a DES key, 7 bits each, as lm_key () in inc_hash_lm.cl does. The lowest bit of
// a key byte is its parity bit, which DES ignores.

#ifdef RECIPE_DES

#define RECIPE_DKS   _des_crypt_keysetup_vect
#define RECIPE_DKS_S _des_crypt_keysetup
#define RECIPE_DEN   _des_crypt_encrypt_vect
#define RECIPE_DEN_S _des_crypt_encrypt
#define RECIPE_DDE   _des_crypt_decrypt_vect
#define RECIPE_DDE_S _des_crypt_decrypt

#define RECIPE_DKEY_1 8
#define RECIPE_DKEY_2 24
#define RECIPE_DKEY_3 7

#define RECIPE_DKEY3(O) RECIPE_DKEY_##O
#define RECIPE_DKEY2(O) RECIPE_DKEY3 (O)

#define RECIPE_DES7(T,K0,K1,C,D)                                                \
{                                                                               \
  const T t0 = ((K0) >>  0) & 0xff;                                             \
  const T t1 = ((K0) >>  8) & 0xff;                                             \
  const T t2 = ((K0) >> 16) & 0xff;                                             \
  const T t3 = ((K0) >> 24) & 0xff;                                             \
  const T t4 = ((K1) >>  0) & 0xff;                                             \
  const T t5 = ((K1) >>  8) & 0xff;                                             \
  const T t6 = ((K1) >> 16) & 0xff;                                             \
                                                                                \
  const T k0 =             (t0 >> 0);                                           \
  const T k1 = (t0 << 7) | (t1 >> 1);                                           \
  const T k2 = (t1 << 6) | (t2 >> 2);                                           \
  const T k3 = (t2 << 5) | (t3 >> 3);                                           \
  const T k4 = (t3 << 4) | (t4 >> 4);                                           \
  const T k5 = (t4 << 3) | (t5 >> 5);                                           \
  const T k6 = (t5 << 2) | (t6 >> 6);                                           \
  const T k7 = (t6 << 1);                                                       \
                                                                                \
  C = ((k0 & 0xff) <<  0)                                                       \
    | ((k1 & 0xff) <<  8)                                                       \
    | ((k2 & 0xff) << 16)                                                       \
    | ((k3 & 0xff) << 24);                                                      \
                                                                                \
  D = ((k4 & 0xff) <<  0)                                                       \
    | ((k5 & 0xff) <<  8)                                                       \
    | ((k6 & 0xff) << 16)                                                       \
    | ((k7 & 0xff) << 24);                                                      \
}

#define RECIPE_DOP_1(T,HS)                                                      \
{                                                                               \
  RECIPE_DKS##HS (dk[0], dk[1], kc, kd, st->des_skb);                           \
                                                                                \
  RECIPE_DEN##HS (raw, dp, kc, kd, st->des_sptrans);                            \
}

#define RECIPE_DOP_2(T,HS)                                                      \
{                                                                               \
  T d1[2];                                                                      \
  T d2[2];                                                                      \
                                                                                \
  RECIPE_DKS##HS (dk[0], dk[1], kc, kd, st->des_skb);                           \
                                                                                \
  RECIPE_DEN##HS (d1, dp, kc, kd, st->des_sptrans);                             \
                                                                                \
  RECIPE_DKS##HS (dk[2], dk[3], kc, kd, st->des_skb);                           \
                                                                                \
  RECIPE_DDE##HS (d2, d1, kc, kd, st->des_sptrans);                             \
                                                                                \
  RECIPE_DKS##HS (dk[4], dk[5], kc, kd, st->des_skb);                           \
                                                                                \
  RECIPE_DEN##HS (raw, d2, kc, kd, st->des_sptrans);                            \
}

#define RECIPE_DOP_3(T,HS)                                                      \
{                                                                               \
  T c;                                                                          \
  T d;                                                                          \
                                                                                \
  RECIPE_DES7 (T, dk[0], dk[1], c, d)                                           \
                                                                                \
  RECIPE_DKS##HS (c, d, kc, kd, st->des_skb);                                   \
                                                                                \
  RECIPE_DEN##HS (raw, dp, kc, kd, st->des_sptrans);                            \
}

#define RECIPE_DOP3(O,T,HS) RECIPE_DOP_##O (T, HS)
#define RECIPE_DOP2(O,T,HS) RECIPE_DOP3 (O, T, HS)

#define RECIPE_STEP_DES(F,K,X,HS,T,INIT)                                                                                                       \
{                                                                                                                                              \
  const u32 lk = (u32) RECIPE_KLEN (RECIPE_S##K##_P0);                                                                                         \
  const u32 ld = (u32) RECIPE_KLEN (RECIPE_S##K##_P1);                                                                                         \
                                                                                                                                               \
  const int nk = (int) ((lk > (u32) RECIPE_DKEY2 (RECIPE_S##K##_DOP)) ? (u32) RECIPE_DKEY2 (RECIPE_S##K##_DOP) : lk);                          \
  const int nd = (int) ((ld > 8) ? 8 : ld);                                                                                                    \
                                                                                                                                               \
  T dk[6];                                                                                                                                     \
  T dp[2];                                                                                                                                     \
                                                                                                                                               \
  for (u32 i = 0; i < 6; i++) dk[i] = hc_bounded_word_le##HS (RECIPE_KBUF (RECIPE_S##K##_P0), (int) i, nk - (int) (i * 4));                    \
  for (u32 i = 0; i < 2; i++) dp[i] = hc_bounded_word_le##HS (RECIPE_KBUF (RECIPE_S##K##_P1), (int) i, nd - (int) (i * 4));                    \
                                                                                                                                               \
  T kc[16];                                                                                                                                    \
  T kd[16];                                                                                                                                    \
                                                                                                                                               \
  for (u32 i = 0; i < 16; i++) raw[i] = 0;                                                                                                     \
                                                                                                                                               \
  RECIPE_DOP2 (RECIPE_S##K##_DOP, T, HS)                                                                                                       \
                                                                                                                                               \
  if (RECIPE_FMT_STEP (K))                                                                                                                     \
  {                                                                                                                                            \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, 8)                                                                                             \
                                                                                                                                               \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                                                     \
  }                                                                                                                                            \
}

#endif

// A step applies transforms to a hash output or a carried variable. See RECIPE_KIND_XFRM in
// src/recipe.c. It copies its part into a buffer of 64 words and applies the transforms of a copy,
// specified by RECIPE_S<k>_O<j> in the form of RECIPE_X<k>_O<j>. The bytes are copied to raw for
// the result and for an output format, which uses up to 64 bytes. When the output is raw bytes,
// they are copied straight to the output instead, up to 128 of them. The output retains the length
// produced by the transforms because a carried variable can change length after the first
// iteration.

#define RECIPE_SXOP(K,J,T,HS,B,L) RECIPE_XOP2 (RECIPE_S##K##_O##J, T, HS, B, L, RECIPE_S##K##_A##J, RECIPE_S##K##_B##J, RECIPE_S##K##_H##J, RECIPE_S##K##_L##J)

#define RECIPE_XFMT_0(T,HS,K,N,M,B) RECIPE_BFMT_0 (T, HS, K, N, M)
#define RECIPE_XFMT_1(T,HS,K,N,M,B) { for (u32 i = 0; i < 32; i++) outs[((K) * 32) + i] = B[i]; out_lens[K] = (N); }
#define RECIPE_XFMT_2(T,HS,K,N,M,B) RECIPE_BFMT_2 (T, HS, K, N, M)
#define RECIPE_XFMT_3(T,HS,K,N,M,B) RECIPE_BFMT_3 (T, HS, K, N, M)

#define RECIPE_XFMT3(F,T,HS,K,N,M,B) RECIPE_XFMT_##F (T, HS, K, N, M, B)
#define RECIPE_XFMT2(F,T,HS,K,N,M,B) RECIPE_XFMT3 (F, T, HS, K, N, M, B)

#define RECIPE_STEP_XFRM(F,K,X,HS,T,INIT)                                                    \
{                                                                                            \
  u32 l = (u32) RECIPE_KLEN (RECIPE_S##K##_P0);                                              \
                                                                                             \
  T b[64];                                                                                   \
                                                                                             \
  for (u32 i = 0; i < 64; i++) b[i] = 0;                                                     \
                                                                                             \
  for (u32 i = 0; i < ((l + 3) / 4); i++) b[i] = RECIPE_KBUF (RECIPE_S##K##_P0)[i];          \
                                                                                             \
  RECIPE_XCLIP (b, l)                                                                        \
                                                                                             \
  RECIPE_SXOP (K, 0, T, HS, b, l)                                                            \
  RECIPE_SXOP (K, 1, T, HS, b, l)                                                            \
  RECIPE_SXOP (K, 2, T, HS, b, l)                                                            \
  RECIPE_SXOP (K, 3, T, HS, b, l)                                                            \
                                                                                             \
  for (u32 i = 0; i < 16; i++) raw[i] = b[i];                                                \
                                                                                             \
  if (RECIPE_FMT_STEP (K))                                                                   \
  {                                                                                          \
    RECIPE_XFMT2 (RECIPE_S##K##_FMT, T, HS, K, l, RECIPE_S##K##_BMAX, b)                     \
  }                                                                                          \
}

#define RECIPE_STEP_HMACSF(F,K,X,HS,T,INIT,FEED) RECIPE_STEP_HMACIO (F, K, X, HS, T, INIT, ctx = st->ho##K;, FEED)

// The same HMAC with the outer hash starting from OUTER.

#define RECIPE_HIO_0(F,K,X,HS,T,INIT,OUTER,FEED)                                                                                           \
{                                                                                                                                          \
  RECIPE_HASH_##F (X, HS, INIT, FEED)                                                                                                      \
                                                                                                                                           \
  RECIPE_HASH_##F (X, HS, OUTER, RECIPE_RAW_##F (F, X, HS, T, RECIPE_LEN_##F))                                                             \
                                                                                                                                           \
  if (RECIPE_FMT_STEP (K))                                                                                                                 \
  {                                                                                                                                        \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                                                                            \
                                                                                                                                           \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                                                                 \
  }                                                                                                                                        \
}

// Under RECIPE_S<k>_HT, the outer hash is a single transform of the block RECIPE_TOB builds.

#define RECIPE_HIO_1(F,K,X,HS,T,INIT,OUTER,FEED)                \
{                                                               \
  T ob[RECIPE_BLOCK_##F / 4];                                   \
                                                                \
  {                                                             \
    RECIPE_CTX_##F (X) ctx;                                     \
                                                                \
    INIT                                                        \
                                                                \
    FEED                                                        \
                                                                \
    RECIPE_FIN_##F (X)                                          \
                                                                \
    RECIPE_TOB (F, HS, ob)                                      \
  }                                                             \
                                                                \
  {                                                             \
    RECIPE_CTX_##F (X) ctx;                                     \
                                                                \
    OUTER                                                       \
                                                                \
    RECIPE_TXS_##F (X, ob, ctx.h)                               \
                                                                \
    RECIPE_TRAW_##F (HS)                                        \
  }                                                             \
                                                                \
  if (RECIPE_FMT_STEP (K))                                      \
  {                                                             \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F) \
                                                                \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)      \
  }                                                             \
}

#define RECIPE_HIO3(H,F,K,X,HS,T,INIT,OUTER,FEED)      RECIPE_HIO_##H (F, K, X, HS, T, INIT, OUTER, FEED)
#define RECIPE_HIO2(H,F,K,X,HS,T,INIT,OUTER,FEED)      RECIPE_HIO3 (H, F, K, X, HS, T, INIT, OUTER, FEED)
#define RECIPE_STEP_HMACIO(F,K,X,HS,T,INIT,OUTER,FEED) RECIPE_HIO2 (RECIPE_S##K##_HT, F, K, X, HS, T, INIT, OUTER, FEED)

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

// The key pad contexts of HMAC step K: the key block XOR ipad followed by the parts FEEDQ feeds into
// DI, the key block XOR opad into DO.

#define RECIPE_PADS_0(F,K,X,HS,T,DI,DO,FEEDQ)                                                                     \
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
    FEEDQ                                                                                                         \
                                                                                                                  \
    DI = ctx;                                                                                                     \
  }                                                                                                               \
                                                                                                                  \
  {                                                                                                               \
    RECIPE_CTX_##F (X) ctx;                                                                                       \
                                                                                                                  \
    RECIPE_INIT_##F (X)                                                                                           \
                                                                                                                  \
    RECIPE_PAD_##F (F, X, HS, T, 0x5c5c5c5c)                                                                      \
                                                                                                                  \
    DO = ctx;                                                                                                     \
  }                                                                                                               \
}

// Under RECIPE_S<k>_HT, each pad is one transform from the initial state. The key block takes the
// family's word order once for both pads, since a pad repeats one byte.

#define RECIPE_PADS_1(F,K,X,HS,T,DI,DO,FEEDQ)                                         \
{                                                                                     \
  RECIPE_KEYBLOCK (F, K, X, HS, T)                                                    \
                                                                                      \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) kb[i] = RECIPE_KS_##F (HS, kb[i]); \
                                                                                      \
  T pb[RECIPE_BLOCK_##F / 4];                                                         \
                                                                                      \
  {                                                                                   \
    RECIPE_CTX_##F (X) ctx;                                                           \
                                                                                      \
    RECIPE_INIT_##F (X)                                                               \
                                                                                      \
    for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) pb[i] = kb[i] ^ 0x36363636;      \
                                                                                      \
    RECIPE_TXS_##F (X, pb, ctx.h)                                                     \
                                                                                      \
    ctx.len = RECIPE_BLOCK_##F;                                                       \
                                                                                      \
    FEEDQ                                                                             \
                                                                                      \
    DI = ctx;                                                                         \
  }                                                                                   \
                                                                                      \
  {                                                                                   \
    RECIPE_CTX_##F (X) ctx;                                                           \
                                                                                      \
    RECIPE_INIT_##F (X)                                                               \
                                                                                      \
    for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++) pb[i] = kb[i] ^ 0x5c5c5c5c;      \
                                                                                      \
    RECIPE_TXS_##F (X, pb, ctx.h)                                                     \
                                                                                      \
    ctx.len = RECIPE_BLOCK_##F;                                                       \
                                                                                      \
    DO = ctx;                                                                         \
  }                                                                                   \
}

#define RECIPE_PADS3(H,F,K,X,HS,T,DI,DO,FEEDQ) RECIPE_PADS_##H (F, K, X, HS, T, DI, DO, FEEDQ)
#define RECIPE_PADS2(H,F,K,X,HS,T,DI,DO,FEEDQ) RECIPE_PADS3 (H, F, K, X, HS, T, DI, DO, FEEDQ)
#define RECIPE_PADS(F,K,X,HS,T,DI,DO,FEEDQ)    RECIPE_PADS2 (RECIPE_S##K##_HT, F, K, X, HS, T, DI, DO, FEEDQ)

#define RECIPE_PR_P0(D,F,K,X,HS,T)
#define RECIPE_PR_P1(D,F,K,X,HS,T) RECIPE_STEP_##D (F, K, X, HS, T, RECIPE_INIT_##F (X))
#define RECIPE_PR_P2(D,F,K,X,HS,T) RECIPE_PADS (F, K, X, HS, T, st->hi##K, st->ho##K, RECIPE_FEEDQ (K, F, X))
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

// Under RECIPE_TAIL, the base word is the same for every candidate in a work item. The module
// sets RECIPE_S<k>_BW when the first part of step k not fed by recipe_prep () is the password.
// The recipe_base () function then feeds the base word once per work item and saves the
// context. The recipe_eval_base () function continues from that context with the right word, as
// the native combinator kernels do with ctx0. This preparation works for P0 and P3 hash steps
// and for P2 HMAC steps.

#ifdef RECIPE_TAIL

#define RECIPE_BCALL_PASS(PU,PB,W)   PU (&ctx, PB, (int) pw_len);
#define RECIPE_BCALL_PASS16(PU,PB,W) W (&ctx, w, (int) pw_len);

#define RECIPE_TCALL_PASS(G,WG)      G (&ctx, tail, (int) tail_len);
#define RECIPE_TCALL_PASS16(G,WG)    WG (&ctx, tail, (int) tail_len);

#define RECIPE_BPART3(TOK,F,X) RECIPE_BCALL_##TOK (RECIPE_UPDP_##F (X), RECIPE_PBUF_##F, RECIPE_UPDW_##F (X))
#define RECIPE_BPART2(TOK,F,X) RECIPE_BPART3 (TOK, F, X)

#define RECIPE_TPART3(TOK,F)   RECIPE_TCALL_##TOK (RECIPE_UPDG_##F, RECIPE_UPDWG_##F)
#define RECIPE_TPART2(TOK,F)   RECIPE_TPART3 (TOK, F)

#define RECIPE_FEEDB(K,F,X)            \
  RECIPE_TPART2 (RECIPE_S##K##_P0, F)  \
  RECIPE_PART (K, 1, F, X)             \
  RECIPE_PART (K, 2, F, X)             \
  RECIPE_PART (K, 3, F, X)             \
  RECIPE_PART (K, 4, F, X)             \
  RECIPE_PART (K, 5, F, X)             \
  RECIPE_PART (K, 6, F, X)             \
  RECIPE_PART (K, 7, F, X)

#define RECIPE_BINIT_P0(F,K,X) RECIPE_INIT_##F (X)
#define RECIPE_BINIT_P2(F,K,X) ctx = st->hi##K;
#define RECIPE_BINIT_P3(F,K,X) ctx = st->hc##K;

#define RECIPE_BS_0(P,D,F,K,X,HS,T)
#define RECIPE_BS_1(P,D,F,K,X,HS,T)          \
{                                            \
  RECIPE_CTX_##F (X) ctx;                    \
                                             \
  RECIPE_BINIT_##P (F, K, X)                 \
                                             \
  RECIPE_BPART2 (RECIPE_S##K##_P0, F, X)     \
                                             \
  bst->bc##K = ctx;                          \
}

#define RECIPE_EVB_0(P,D,F,K,X,HS,T) RECIPE_EV_##P (D, F, K, X, HS, T)
#define RECIPE_EVB_1(P,D,F,K,X,HS,T) RECIPE_EVB_##D (F, K, X, HS, T)

#define RECIPE_EVB_HASH(F,K,X,HS,T)  RECIPE_STEP_HASHF  (F, K, X, HS, T, ctx = bst->bc##K;, RECIPE_FEEDB (K, F, X))
#define RECIPE_EVB_HMAC(F,K,X,HS,T)  RECIPE_STEP_HMACSF (F, K, X, HS, T, ctx = bst->bc##K;, RECIPE_FEEDB (K, F, X))

#define RECIPE_BS3(B,P,D,F,K,X,HS,T)  RECIPE_BS_##B (P, D, F, K, X, HS, T)
#define RECIPE_BS2(B,P,D,F,K,X,HS,T)  RECIPE_BS3 (B, P, D, F, K, X, HS, T)
#define RECIPE_BS(K,X,HS,T)           RECIPE_BS2 (RECIPE_S##K##_BW, RECIPE_S##K##_PH, RECIPE_S##K##_KIND, RECIPE_S##K##_FN, K, X, HS, T)

#define RECIPE_EVB3(B,P,D,F,K,X,HS,T) RECIPE_EVB_##B (P, D, F, K, X, HS, T)
#define RECIPE_EVB2(B,P,D,F,K,X,HS,T) RECIPE_EVB3 (B, P, D, F, K, X, HS, T)
#define RECIPE_EVB(K,X,HS,T)          RECIPE_EVB2 (RECIPE_S##K##_BW, RECIPE_S##K##_PH, RECIPE_S##K##_KIND, RECIPE_S##K##_FN, K, X, HS, T)

#define RECIPE_BFLD_0(F,K)
#define RECIPE_BFLD_1(F,K)  RECIPE_CTX_##F ( ) bc##K;
#define RECIPE_BFLD3(B,F,K) RECIPE_BFLD_##B (F, K)
#define RECIPE_BFLD2(B,F,K) RECIPE_BFLD3 (B, F, K)
#define RECIPE_BFLD(K)      RECIPE_BFLD2 (RECIPE_S##K##_BW, RECIPE_S##K##_FN, K)

#endif

// A recipe that is a pbkdf2 call alone has no steps, and an array cannot be empty.

#if RECIPE_STEPS == 0
#define RECIPE_NOUTS 1
#else
#define RECIPE_NOUTS RECIPE_STEPS
#endif

#if   RECIPE_STEPS == 0
#define RECIPE_ALL(R,X,HS,T)
#elif RECIPE_STEPS == 1
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
#elif RECIPE_STEPS == 8
#define RECIPE_ALL(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T) R (5, X, HS, T) R (6, X, HS, T) R (7, X, HS, T)
#elif RECIPE_STEPS == 9
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T)
#elif RECIPE_STEPS == 10
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T)
#elif RECIPE_STEPS == 11
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T)
#elif RECIPE_STEPS == 12
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T) R (11, X, HS, T)
#elif RECIPE_STEPS == 13
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T) R (11, X, HS, T) R (12, X, HS, T)
#elif RECIPE_STEPS == 14
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T) R (11, X, HS, T) R (12, X, HS, T) R (13, X, HS, T)
#elif RECIPE_STEPS == 15
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T) R (11, X, HS, T) R (12, X, HS, T) R (13, X, HS, T) R (14, X, HS, T)
#else
#define RECIPE_ALL(R,X,HS,T) RECIPE_ALL8 (R, X, HS, T) R (8, X, HS, T) R (9, X, HS, T) R (10, X, HS, T) R (11, X, HS, T) R (12, X, HS, T) R (13, X, HS, T) R (14, X, HS, T) R (15, X, HS, T)
#endif

#define RECIPE_ALL8(R,X,HS,T) R (0, X, HS, T) R (1, X, HS, T) R (2, X, HS, T) R (3, X, HS, T) R (4, X, HS, T) R (5, X, HS, T) R (6, X, HS, T) R (7, X, HS, T)

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
  T   outs[RECIPE_NOUTS * 32];     \
  u32 out_lens[RECIPE_NOUTS];      \
                                   \
  RECIPE_STATE_HEX                 \
  RECIPE_STATE_AES                 \
  RECIPE_STATE_WRL                 \
  RECIPE_STATE_SBOG                \
  RECIPE_STATE_GOST                \
  RECIPE_STATE_GOSTC               \
  RECIPE_STATE_TIGER               \
  RECIPE_STATE_MD2                 \
  RECIPE_STATE_SNEFRU              \
  RECIPE_STATE_DES                 \
  RECIPE_STATE_TE                  \
  RECIPE_STATE_FUGUE               \
  RECIPE_STATE_GROESTL             \
  RECIPE_STATE_WRL01               \
  RECIPE_STATE_SB (T)              \
  RECIPE_STATE_SD (T)              \
  RECIPE_STATE_FDS (T)             \
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
  #if RECIPE_STEPS > 8
  RECIPE_FIELDS (8, _vector)
  #endif
  #if RECIPE_STEPS > 9
  RECIPE_FIELDS (9, _vector)
  #endif
  #if RECIPE_STEPS > 10
  RECIPE_FIELDS (10, _vector)
  #endif
  #if RECIPE_STEPS > 11
  RECIPE_FIELDS (11, _vector)
  #endif
  #if RECIPE_STEPS > 12
  RECIPE_FIELDS (12, _vector)
  #endif
  #if RECIPE_STEPS > 13
  RECIPE_FIELDS (13, _vector)
  #endif
  #if RECIPE_STEPS > 14
  RECIPE_FIELDS (14, _vector)
  #endif
  #if RECIPE_STEPS > 15
  RECIPE_FIELDS (15, _vector)
  #endif

} recipe_state_vector_t;

#if defined RECIPE_WIDE || defined RECIPE_TAIL || defined RECIPE_KDF

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
  #if RECIPE_STEPS > 8
  RECIPE_FIELDS (8, )
  #endif
  #if RECIPE_STEPS > 9
  RECIPE_FIELDS (9, )
  #endif
  #if RECIPE_STEPS > 10
  RECIPE_FIELDS (10, )
  #endif
  #if RECIPE_STEPS > 11
  RECIPE_FIELDS (11, )
  #endif
  #if RECIPE_STEPS > 12
  RECIPE_FIELDS (12, )
  #endif
  #if RECIPE_STEPS > 13
  RECIPE_FIELDS (13, )
  #endif
  #if RECIPE_STEPS > 14
  RECIPE_FIELDS (14, )
  #endif
  #if RECIPE_STEPS > 15
  RECIPE_FIELDS (15, )
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
#define RECIPE_NAT_wrl(HS)        RECIPE_NAT_BE   (16, HS)
#define RECIPE_NAT_sha384(HS)     RECIPE_NAT_BE64 (12, HS)
#define RECIPE_NAT_sha512(HS)     RECIPE_NAT_BE64 (16, HS)

// MD6-256 is hash-mode 34600, whose optimized kernels keep the digest as 64-bit big endian words.

#define RECIPE_NAT_md6256(HS)     RECIPE_NAT_BE64 ( 8, HS)

// SHA-3, Keccak, Streebog, GOST R 34.11-94 and RIPEMD-320 modes keep their digest in memory order.
// The 224-bit SHA-3 and Keccak modes compare word 7, which their digest holds as zero.

#define RECIPE_NAT_LE224(HS) { RECIPE_NAT_LE (7, HS); r[7] = 0; }

#define RECIPE_NAT_sha3_224(HS)    RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_sha3_256(HS)    RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_sha3_384(HS)    RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_sha3_512(HS)    RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_keccak224(HS)   RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_keccak256(HS)   RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_keccak384(HS)   RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_keccak512(HS)   RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_streebog_32(HS) RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_streebog_64(HS) RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_gost(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_rmd320(HS)      RECIPE_NAT_LE    (10, HS)

// The raw hash-modes from 40084 on keep their digest in memory order too, a 224-bit one with word 7
// zeroed as above.

#define RECIPE_NAT_md2(HS)             RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_sha0(HS)            RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_rmd128(HS)          RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_rmd256(HS)          RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_gost_crypto(HS)     RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_tiger(HS)           RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_tiger128(HS)        RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_tiger160(HS)        RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_tiger2(HS)          RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_tth(HS)             RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_sne128(HS)          RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_sne256(HS)          RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_skein224(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_skein256(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_skein384(HS)        RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_skein512(HS)        RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_panama(HS)          RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_mdc2(HS)            RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_hav128(HS)          RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_hav128_4(HS)        RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_hav128_5(HS)        RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_hav160_3(HS)        RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_hav160_4(HS)        RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_hav160_5(HS)        RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_hav192_3(HS)        RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_hav192_4(HS)        RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_hav192_5(HS)        RECIPE_NAT_LE    ( 6, HS)
#define RECIPE_NAT_hav224_3(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_hav224_4(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_hav224_5(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_hav256(HS)          RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_hav256_4(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_hav256_5(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_blake224(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_blake256(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_blake384(HS)        RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_blake512(HS)        RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_bmw224(HS)          RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_bmw256(HS)          RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_bmw384(HS)          RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_bmw512(HS)          RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_cube224(HS)         RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_cube256(HS)         RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_cube384(HS)         RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_cube512(HS)         RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_echo224(HS)         RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_echo256(HS)         RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_echo384(HS)         RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_echo512(HS)         RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_fugue224(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_fugue256(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_fugue384(HS)        RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_fugue512(HS)        RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_groestl224(HS)      RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_groestl256(HS)      RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_groestl384(HS)      RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_groestl512(HS)      RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_hamsi224(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_hamsi256(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_hamsi384(HS)        RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_hamsi512(HS)        RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_jh224(HS)           RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_jh256(HS)           RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_jh384(HS)           RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_jh512(HS)           RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_luffa224(HS)        RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_luffa256(HS)        RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_luffa384(HS)        RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_luffa512(HS)        RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_shabal224(HS)       RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_shabal256(HS)       RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_shabal384(HS)       RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_shabal512(HS)       RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_shavite224(HS)      RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_shavite256(HS)      RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_shavite384(HS)      RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_shavite512(HS)      RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_simd224(HS)         RECIPE_NAT_LE224 (HS)
#define RECIPE_NAT_simd256(HS)         RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_simd384(HS)         RECIPE_NAT_LE    (12, HS)
#define RECIPE_NAT_simd512(HS)         RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_has160(HS)          RECIPE_NAT_LE    ( 5, HS)
#define RECIPE_NAT_edon256(HS)         RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_edon512(HS)         RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_md6(HS)             RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_md6512(HS)          RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_radiogatun32(HS)    RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_radiogatun64(HS)    RECIPE_NAT_LE    ( 8, HS)
#define RECIPE_NAT_ripemd(HS)          RECIPE_NAT_LE    ( 4, HS)
#define RECIPE_NAT_wrl0(HS)            RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_wrl1(HS)            RECIPE_NAT_LE    (16, HS)
#define RECIPE_NAT_xxh64(HS)           RECIPE_NAT_BE64  ( 2, HS)
#define RECIPE_NAT_xxh32(HS)           RECIPE_NAT_BE    ( 1, HS)

// The result of xor, and or or belongs to no family and keeps its bytes in memory order. It can be
// up to 64 bytes long, and its step zeroes raw past its length.

#define RECIPE_NAT_bop(HS)         RECIPE_NAT_LE    (16, HS)

#define RECIPE_NAT3(F,HS) RECIPE_NAT_##F (HS)
#define RECIPE_NAT2(F,HS) RECIPE_NAT3 (F, HS)

// A comparison as the result, and a result shorter than 16 bytes such as mysql3 (pass), set
// RECIPE_ROOT_MASK. Each compared word is read at its index, with the bytes past the compared
// length masked off. src/recipe.c gives a word past the end index 0 and mask 0. A result cut from a
// later offset, as in cut (sha1 (pass), 8), starts at word RECIPE_ROOT_OFF.

#ifndef RECIPE_ROOT_OFF
#define RECIPE_ROOT_OFF 0
#endif

#if defined RECIPE_ROOT_MASK
#define RECIPE_ROOT16                           \
{                                               \
  r[0] = raw[RECIPE_ROOT_I0] & RECIPE_ROOT_M0;  \
  r[1] = raw[RECIPE_ROOT_I1] & RECIPE_ROOT_M1;  \
  r[2] = raw[RECIPE_ROOT_I2] & RECIPE_ROOT_M2;  \
  r[3] = raw[RECIPE_ROOT_I3] & RECIPE_ROOT_M3;  \
}
#else
#define RECIPE_ROOT16 { for (u32 i = 0; i < 4; i++) r[i] = raw[RECIPE_ROOT_OFF + i]; }
#endif

// Such a result is not a complete digest. Under RECIPE_ROOT_NATIVE, its 16 compared bytes start an
// otherwise zero digest, which then takes the family's layout. DGST_POS selects words 0 to 3.

#if defined RECIPE_ROOT_NATIVE && (defined RECIPE_ROOT_MASK || (RECIPE_ROOT_OFF > 0))
#define RECIPE_ROOT(HS)                         \
{                                               \
  RECIPE_ROOT16                                 \
                                                \
  for (u32 i = 0; i <  4; i++) raw[i] = r[i];   \
  for (u32 i = 4; i < 16; i++) raw[i] = 0;      \
                                                \
  RECIPE_NAT2 (RECIPE_ROOT_FN, HS)              \
}
#elif defined RECIPE_ROOT_NATIVE
#define RECIPE_ROOT(HS) RECIPE_NAT2 (RECIPE_ROOT_FN, HS)
#else
#define RECIPE_ROOT(HS) RECIPE_ROOT16
#endif

// Store literals in the evaluation's word type. M builds a vector from a constant and is empty
// for scalar evaluation. Words past RECIPE_LIT_WORDS are not stored.

#define RECIPE_LW(N,I,M) lits[((N) * RECIPE_LIT_WORDS) + (I)] = M (RECIPE_L##N##_W##I);

#define RECIPE_LW0(N,M) RECIPE_LW (N,  0, M) RECIPE_LW (N,  1, M) RECIPE_LW (N,  2, M) RECIPE_LW (N,  3, M)

#if RECIPE_LIT_WORDS > 4
#define RECIPE_LW1(N,M) RECIPE_LW (N,  4, M) RECIPE_LW (N,  5, M) RECIPE_LW (N,  6, M) RECIPE_LW (N,  7, M)
#else
#define RECIPE_LW1(N,M)
#endif

#if RECIPE_LIT_WORDS > 8
#define RECIPE_LW2(N,M) RECIPE_LW (N,  8, M) RECIPE_LW (N,  9, M) RECIPE_LW (N, 10, M) RECIPE_LW (N, 11, M)
#else
#define RECIPE_LW2(N,M)
#endif

#if RECIPE_LIT_WORDS > 12
#define RECIPE_LW3(N,M) RECIPE_LW (N, 12, M) RECIPE_LW (N, 13, M) RECIPE_LW (N, 14, M) RECIPE_LW (N, 15, M)
#else
#define RECIPE_LW3(N,M)
#endif

#define RECIPE_LIT(N,M) RECIPE_LW0 (N, M) RECIPE_LW1 (N, M) RECIPE_LW2 (N, M) RECIPE_LW3 (N, M)

#define RECIPE_LITS(T,M)            \
  T lits[4 * RECIPE_LIT_WORDS];     \
                                    \
  RECIPE_LIT (0, M)                 \
  RECIPE_LIT (1, M)                 \
  RECIPE_LIT (2, M)                 \
  RECIPE_LIT (3, M)

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

#define RECIPE_EVAL(X,HS,T,M) RECIPE_EVALR (X, HS, T, M, RECIPE_EV)

#define RECIPE_EVALR(X,HS,T,M,R) RECIPE_EVALS (X, HS, T, M, R, RECIPE_ROOT (HS))

// The same evaluation, with what follows the steps given as AFTER: the result, or the stores into
// the carried variables of the init and loop kernels.

#define RECIPE_EVALS(X,HS,T,M,R,AFTER)                        \
{                                                             \
  RECIPE_LITS (T, M)                                          \
                                                              \
  PRIVATE_AS const T   *pouts     = st->outs;                 \
  PRIVATE_AS const u32 *pout_lens = st->out_lens;             \
                                                              \
  RECIPE_SB_DECL (T)                                          \
                                                              \
  T   outs[RECIPE_NOUTS * 32];                                \
  u32 out_lens[RECIPE_NOUTS];                                 \
                                                              \
  T raw[16];                                                  \
                                                              \
  RECIPE_XEVS (T, HS)                                         \
                                                              \
  RECIPE_ALL (R, X, HS, T)                                    \
                                                              \
  AFTER                                                       \
}

#ifndef RECIPE_TAIL

DECLSPEC RECIPE_INLINE void recipe_prep_vector (PRIVATE_AS recipe_state_vector_t *st, PRIVATE_AS const u32x *s, const u32 salt_len)
{
  RECIPE_PREP (_vector, , u32x, make_u32x)
}

// A loop recipe evaluates steps separately for each kernel. See RECIPE_LOOP. It does not
// evaluate all steps together.

#ifndef RECIPE_LOOP

DECLSPEC RECIPE_INLINE void recipe_eval_vector (PRIVATE_AS const recipe_state_vector_t *st, PRIVATE_AS const u32x *w, MAYBE_UNUSED PRIVATE_AS const u32x *wb, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len, PRIVATE_AS u32x *r)
{
  RECIPE_EVAL (_vector, , u32x, make_u32x)
}

#endif

#endif

#if defined RECIPE_WIDE || defined RECIPE_TAIL || defined RECIPE_KDF

DECLSPEC RECIPE_INLINE void recipe_prep_scalar (PRIVATE_AS recipe_state_scalar_t *st, PRIVATE_AS const u32 *s, const u32 salt_len)
{
  RECIPE_PREP ( , _S, u32, )
}

#endif

#ifdef RECIPE_TAIL

DECLSPEC RECIPE_INLINE void recipe_eval_scalar (PRIVATE_AS const recipe_state_scalar_t *st, PRIVATE_AS const u32 *w, MAYBE_UNUSED PRIVATE_AS const u32 *wb, const u32 pw_len, GLOBAL_AS const u32 *tail, const u32 tail_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  RECIPE_EVAL ( , _S, u32, )
}

#elif defined RECIPE_WIDE

#ifndef RECIPE_LOOP

DECLSPEC RECIPE_INLINE void recipe_eval_scalar (PRIVATE_AS const recipe_state_scalar_t *st, PRIVATE_AS const u32 *w, MAYBE_UNUSED PRIVATE_AS const u32 *wb, const u32 pw_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  RECIPE_EVAL ( , _S, u32, )
}

#endif

#endif

// RECIPE_WIDE marks recipes that apply utf16le to pass or salt. UTF-8 decoding can give candidates
// different lengths, which a vector context cannot track. Scalar kernels use scalar evaluation
// with UTF-8 decoding. Vector kernels use vector evaluation when every lane is ASCII, checked as
// in the pure UTF-16 mask kernels. Otherwise, they evaluate each lane through recipe_eval_lanes ().
// With RECIPE_WIDE_LANES, they always do, as for a recipe that decodes base64 from pass.
// Kernels call recipe_prep () once per salt and recipe_eval () per candidate.
//
// A pbkdf2 recipe builds its slow kernels with NEW_SIMD_CODE so the loop kernel processes VECT_SIZE
// candidates together. Its init and comp kernels still take one candidate each. They therefore
// evaluate using the scalar state and pass candidate words of type RECIPE_VT rather than u32x.

#if ((VECT_SIZE == 1) && defined (RECIPE_WIDE)) || defined (RECIPE_TAIL) || defined (RECIPE_KDF)
#define RECIPE_SCALAR_STATE
#endif

#ifdef RECIPE_SCALAR_STATE
typedef recipe_state_scalar_t recipe_state_t;
#define RECIPE_VT u32
#else
typedef recipe_state_vector_t recipe_state_t;
#define RECIPE_VT u32x
#endif

DECLSPEC RECIPE_INLINE void recipe_prep (PRIVATE_AS recipe_state_t *st, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len)
{
  #ifdef RECIPE_SCALAR_STATE
  recipe_prep_scalar (st, s, salt_len);
  #else
  recipe_prep_vector (st, s, salt_len);
  #endif
}

// The wb argument is a big endian password copy. Kernels without one pass w. See RECIPE_PASS_COPY.
// The combinator kernel calls RECIPE_EVAL_BASE or RECIPE_EVAL_TAIL instead. Under RECIPE_TAIL,
// these receive the right word separately. Otherwise, they expect it to be appended to w
// already. RECIPE_EVAL_BASE also continues from the contexts saved by RECIPE_BASE after
// hashing the base word.

#ifdef RECIPE_TAIL

DECLSPEC RECIPE_INLINE void recipe_eval_tail (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const u32 *tail, const u32 tail_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  recipe_eval_scalar (st, w, w, pw_len, tail, tail_len, s, salt_len, r);
}

#define RECIPE_EVAL_TAIL(ST,W,LEN,T,TLEN,S,SLEN,R) recipe_eval_tail (ST, W, LEN, T, TLEN, S, SLEN, R)

// The contexts recipe_base () saves after the base word, one for each step with RECIPE_S<k>_BW.
// The first member keeps the struct from being empty when no step has one.

typedef struct recipe_base
{
  u32 unused;

  #if RECIPE_STEPS > 0
  RECIPE_BFLD (0)
  #endif
  #if RECIPE_STEPS > 1
  RECIPE_BFLD (1)
  #endif
  #if RECIPE_STEPS > 2
  RECIPE_BFLD (2)
  #endif
  #if RECIPE_STEPS > 3
  RECIPE_BFLD (3)
  #endif
  #if RECIPE_STEPS > 4
  RECIPE_BFLD (4)
  #endif
  #if RECIPE_STEPS > 5
  RECIPE_BFLD (5)
  #endif
  #if RECIPE_STEPS > 6
  RECIPE_BFLD (6)
  #endif
  #if RECIPE_STEPS > 7
  RECIPE_BFLD (7)
  #endif
  #if RECIPE_STEPS > 8
  RECIPE_BFLD (8)
  #endif
  #if RECIPE_STEPS > 9
  RECIPE_BFLD (9)
  #endif
  #if RECIPE_STEPS > 10
  RECIPE_BFLD (10)
  #endif
  #if RECIPE_STEPS > 11
  RECIPE_BFLD (11)
  #endif
  #if RECIPE_STEPS > 12
  RECIPE_BFLD (12)
  #endif
  #if RECIPE_STEPS > 13
  RECIPE_BFLD (13)
  #endif
  #if RECIPE_STEPS > 14
  RECIPE_BFLD (14)
  #endif
  #if RECIPE_STEPS > 15
  RECIPE_BFLD (15)
  #endif

} recipe_base_t;

DECLSPEC RECIPE_INLINE void recipe_base (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS recipe_base_t *bst, PRIVATE_AS const u32 *w, const u32 pw_len)
{
  RECIPE_ALL (RECIPE_BS, , _S, u32)
}

DECLSPEC RECIPE_INLINE void recipe_eval_base (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const recipe_base_t *bst, PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const u32 *tail, const u32 tail_len, PRIVATE_AS const u32 *s, const u32 salt_len, PRIVATE_AS u32 *r)
{
  RECIPE_EVALR ( , _S, u32, , RECIPE_EVB)
}

#define RECIPE_BASE(B,ST,W,LEN)                          recipe_base_t B; recipe_base (ST, &B, W, LEN);
#define RECIPE_EVAL_BASE(ST,B,W,LEN,T,TLEN,S,SLEN,R)     recipe_eval_base (ST, B, W, LEN, T, TLEN, S, SLEN, R)

#else

#ifndef RECIPE_LOOP

DECLSPEC RECIPE_INLINE void recipe_eval (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const u32x *w, PRIVATE_AS const u32x *wb, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len, PRIVATE_AS u32x *r)
{
  #ifdef RECIPE_SCALAR_STATE
  recipe_eval_scalar (st, w, wb, pw_len, s, salt_len, r);
  #else
  recipe_eval_vector (st, w, wb, pw_len, s, salt_len, r);
  #endif
}

#endif

#define RECIPE_EVAL_TAIL(ST,W,LEN,T,TLEN,S,SLEN,R) recipe_eval (ST, W, W, LEN, S, SLEN, R)

#define RECIPE_BASE(B,ST,W,LEN)
#define RECIPE_EVAL_BASE(ST,B,W,LEN,T,TLEN,S,SLEN,R)     RECIPE_EVAL_TAIL (ST, W, LEN, T, TLEN, S, SLEN, R)

#endif

#if (VECT_SIZE > 1) && defined (RECIPE_WIDE) && !defined (RECIPE_LOOP)

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

  RECIPE_WRL_COPY (sts, st)
  RECIPE_SBOG_COPY (sts, st)
  RECIPE_GOST_COPY (sts, st)
  RECIPE_GOSTC_COPY (sts, st)
  RECIPE_TIGER_COPY (sts, st)
  RECIPE_MD2_COPY (sts, st)
  RECIPE_SNEFRU_COPY (sts, st)
  RECIPE_DES_COPY (sts, st)
  RECIPE_AES_COPY (sts, st)
  RECIPE_TE_COPY (sts, st)
  RECIPE_FUGUE_COPY (sts, st)
  RECIPE_GROESTL_COPY (sts, st)
  RECIPE_WRL01_COPY (sts, st)

  #ifdef RECIPE_SALT_DEC
  for (u32 i = 0; i < 64; i++) sts.sd[i] = 0;

  hc_vector_get_lane (sts.sd, st->sd, (int) st->sd_len, 0);

  sts.sd_len = st->sd_len;
  #endif

  #if (RECIPE_LINE_FIELDS & 1)
  RECIPE_FIELD_LANE (sts, st, 0)
  #endif

  #if (RECIPE_LINE_FIELDS & 2)
  RECIPE_FIELD_LANE (sts, st, 1)
  #endif

  #if (RECIPE_LINE_FIELDS & 4)
  RECIPE_FIELD_LANE (sts, st, 2)
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

// A recipe with a for loop runs in the init, loop and comp kernels of OpenCL/m04000-pure.cl. The
// module sets RECIPE_LOOP and assigns each step to INIT, LOOP or COMP through RECIPE_S<k>_SEC. It
// also lists the stores into carried variables: RECIPE_I<n>_TOK into RECIPE_I<n>_SLOT after the
// init steps, and RECIPE_L<n>_TOK into RECIPE_L<n>_SLOT after each iteration of the loop steps. The
// kernels store RECIPE_CARRY carried variables in the tmps, each containing 64 words, and pass them
// to the steps as vb and vl. In every kernel, prepared outputs and contexts continue to come from
// recipe_prep () as they do for recipes without a loop.

#ifdef RECIPE_LOOP

// Under RECIPE_TLOOP, recipe_eval_tloop () runs every iteration the templates cover, so the loop
// steps in recipe_eval_loop () take only the general path. Their templates there would cost the
// loop kernel registers: 247 rather than 167 for h = sha512_bin (pass . h) on sm_89.

#define RECIPE_SEC_INIT_INIT(K,X,HS,T) RECIPE_EV (K, X, HS, T)
#define RECIPE_SEC_INIT_LOOP(K,X,HS,T)
#define RECIPE_SEC_INIT_COMP(K,X,HS,T)
#define RECIPE_SEC_LOOP_INIT(K,X,HS,T)
#if RECIPE_TLOOP == 1
#define RECIPE_SEC_LOOP_LOOP(K,X,HS,T) RECIPE_EVH (K, X, HS, T)
#else
#define RECIPE_SEC_LOOP_LOOP(K,X,HS,T) RECIPE_EVT2 (RECIPE_S##K##_TPL, K, X, HS, T)
#endif
#define RECIPE_SEC_LOOP_COMP(K,X,HS,T)
#define RECIPE_SEC_COMP_INIT(K,X,HS,T)
#define RECIPE_SEC_COMP_LOOP(K,X,HS,T)
#define RECIPE_SEC_COMP_COMP(K,X,HS,T) RECIPE_EV (K, X, HS, T)

// Block templates for the loop kernel. When a loop step's parts keep the same lengths between
// iterations, it hashes the same padded block layout each time. Only the dynamic parts change:
// carried variables and outputs from earlier steps in the iteration. For such a step,
// RECIPE_S<k>_TPL, recipe_tpl_build () lays out the padded block once per launch. It places the
// static parts, the 0x80 byte and the length, using the family's byte order for the words. Each
// iteration then places the dynamic words and runs the family's transform on the block, as native
// slow kernels do. The module ensures that each dynamic part's length is a multiple of 4 bytes. A
// dynamic part that follows the password starts at any byte, so its words are shifted into place,
// see RECIPE_TI_TKD. The general path handles layouts that exceed one block and iterations where a
// carried variable does not yet have the length expected in the loop.

// The families' byte order, transform, length word and raw digest, RECIPE_TBE, RECIPE_TXS,
// RECIPE_TLW and RECIPE_TRAW, are defined with the HMAC steps.

#define RECIPE_TSW_0(V) (V)
#define RECIPE_TSW_1(V) hc_swap32_S (V)

// Word i of a dynamic part moved S bits (0, 8, 16 or 24) toward the end of the block, in the
// family's byte order. A is the part's word i - 1 and B its word i. A move of 0 leaves B.

#define RECIPE_TFS_0(A,B,S) (((S) == 0) ? (B) : (((B) << (S)) | ((A) >> (32 - (S)))))
#define RECIPE_TFS_1(A,B,S) (((S) == 0) ? (B) : (((A) << (32 - (S))) | ((B) >> (S))))

// The chaining value H of a context as RECIPE_SW_<f> words at word O of B, see RECIPE_S<k>_HK.
// RECIPE_HST stores them and RECIPE_HLD loads them. A 64 bit word takes its high half, then its low
// half.

#define RECIPE_SW_md4    4
#define RECIPE_SW_md5    4
#define RECIPE_SW_rmd160 5
#define RECIPE_SW_sha1   5
#define RECIPE_SW_sha224 8
#define RECIPE_SW_sha256 8
#define RECIPE_SW_sm3    8
#define RECIPE_SW_sha384 16
#define RECIPE_SW_sha512 16

#define RECIPE_HST32(N,H,B,O) for (u32 i = 0; i < (N); i++) (B)[(O) + i] = (H)[i];
#define RECIPE_HLD32(N,H,B,O) for (u32 i = 0; i < (N); i++) (H)[i] = (B)[(O) + i];

#define RECIPE_HST64(N,H,B,O) for (u32 i = 0; i < (N); i++) { (B)[(O) + (i * 2) + 0] = h32_from_64_S ((H)[i]); (B)[(O) + (i * 2) + 1] = l32_from_64_S ((H)[i]); }
#define RECIPE_HLD64(N,H,B,O) for (u32 i = 0; i < (N); i++) (H)[i] = hl32_to_64_S ((B)[(O) + (i * 2) + 0], (B)[(O) + (i * 2) + 1]);

#define RECIPE_HST_md4(H,B,O)    RECIPE_HST32 (4, H, B, O)
#define RECIPE_HST_md5(H,B,O)    RECIPE_HST32 (4, H, B, O)
#define RECIPE_HST_rmd160(H,B,O) RECIPE_HST32 (5, H, B, O)
#define RECIPE_HST_sha1(H,B,O)   RECIPE_HST32 (5, H, B, O)
#define RECIPE_HST_sha224(H,B,O) RECIPE_HST32 (8, H, B, O)
#define RECIPE_HST_sha256(H,B,O) RECIPE_HST32 (8, H, B, O)
#define RECIPE_HST_sm3(H,B,O)    RECIPE_HST32 (8, H, B, O)
#define RECIPE_HST_sha384(H,B,O) RECIPE_HST64 (8, H, B, O)
#define RECIPE_HST_sha512(H,B,O) RECIPE_HST64 (8, H, B, O)

#define RECIPE_HLD_md4(H,B,O)    RECIPE_HLD32 (4, H, B, O)
#define RECIPE_HLD_md5(H,B,O)    RECIPE_HLD32 (4, H, B, O)
#define RECIPE_HLD_rmd160(H,B,O) RECIPE_HLD32 (5, H, B, O)
#define RECIPE_HLD_sha1(H,B,O)   RECIPE_HLD32 (5, H, B, O)
#define RECIPE_HLD_sha224(H,B,O) RECIPE_HLD32 (8, H, B, O)
#define RECIPE_HLD_sha256(H,B,O) RECIPE_HLD32 (8, H, B, O)
#define RECIPE_HLD_sm3(H,B,O)    RECIPE_HLD32 (8, H, B, O)
#define RECIPE_HLD_sha384(H,B,O) RECIPE_HLD64 (8, H, B, O)
#define RECIPE_HLD_sha512(H,B,O) RECIPE_HLD64 (8, H, B, O)

// Each part token is classified as static, dynamic or empty: TKS, TKD or TKN. A carried variable is
// dynamic when the loop assigns it, marked by RECIPE_C<c>_DYN, with length RECIPE_C<c>_LEN. A
// step's output in the current iteration has length RECIPE_S<k>_OLEN. The Q slots name prepared
// outputs as STEP<k>, which the loop kernel reads using the corresponding PSTEP<k> tokens.

#define RECIPE_TK_NONE    TKN
#define RECIPE_TK_PASS    TKS
#define RECIPE_TK_SALT    TKS
#define RECIPE_TK_SALTD   TKS
#define RECIPE_TK_SALT2   TKS
#define RECIPE_TK_PEPPER  TKS
#define RECIPE_TK_USER    TKS
#define RECIPE_TK_LIT0    TKS
#define RECIPE_TK_LIT1    TKS
#define RECIPE_TK_LIT2    TKS
#define RECIPE_TK_LIT3    TKS
#define RECIPE_TK_XP0     TKS
#define RECIPE_TK_XP1     TKS
#define RECIPE_TK_XP2     TKS
#define RECIPE_TK_XP3     TKS
#define RECIPE_TK_XS0     TKS
#define RECIPE_TK_XS1     TKS
#define RECIPE_TK_XS2     TKS
#define RECIPE_TK_XS3     TKS
#define RECIPE_TK_PSTEP0  TKS
#define RECIPE_TK_PSTEP1  TKS
#define RECIPE_TK_PSTEP2  TKS
#define RECIPE_TK_PSTEP3  TKS
#define RECIPE_TK_PSTEP4  TKS
#define RECIPE_TK_PSTEP5  TKS
#define RECIPE_TK_PSTEP6  TKS
#define RECIPE_TK_PSTEP7  TKS
#define RECIPE_TK_PSTEP8  TKS
#define RECIPE_TK_PSTEP9  TKS
#define RECIPE_TK_PSTEP10 TKS
#define RECIPE_TK_PSTEP11 TKS
#define RECIPE_TK_PSTEP12 TKS
#define RECIPE_TK_PSTEP13 TKS
#define RECIPE_TK_PSTEP14 TKS
#define RECIPE_TK_PSTEP15 TKS
#define RECIPE_TK_STEP0   TKD
#define RECIPE_TK_STEP1   TKD
#define RECIPE_TK_STEP2   TKD
#define RECIPE_TK_STEP3   TKD
#define RECIPE_TK_STEP4   TKD
#define RECIPE_TK_STEP5   TKD
#define RECIPE_TK_STEP6   TKD
#define RECIPE_TK_STEP7   TKD
#define RECIPE_TK_STEP8   TKD
#define RECIPE_TK_STEP9   TKD
#define RECIPE_TK_STEP10  TKD
#define RECIPE_TK_STEP11  TKD
#define RECIPE_TK_STEP12  TKD
#define RECIPE_TK_STEP13  TKD
#define RECIPE_TK_STEP14  TKD
#define RECIPE_TK_STEP15  TKD
#define RECIPE_TK_VAR0    RECIPE_TKV2 (RECIPE_C0_DYN)
#define RECIPE_TK_VAR1    RECIPE_TKV2 (RECIPE_C1_DYN)
#define RECIPE_TK_VAR2    RECIPE_TKV2 (RECIPE_C2_DYN)
#define RECIPE_TK_VAR3    RECIPE_TKV2 (RECIPE_C3_DYN)

#define RECIPE_TKV3(D)   RECIPE_TKV_##D
#define RECIPE_TKV2(D)   RECIPE_TKV3 (D)
#define RECIPE_TKV_0     TKS
#define RECIPE_TKV_1     TKD

#define RECIPE_TLEN_NONE    0
#define RECIPE_TLEN_PASS    pw_len
#define RECIPE_TLEN_SALT    salt_len
#define RECIPE_TLEN_SALTD   (st->sd_len)
#define RECIPE_TLEN_SALT2   (st->fd0_len)
#define RECIPE_TLEN_PEPPER  (st->fd1_len)
#define RECIPE_TLEN_USER    (st->fd2_len)
#define RECIPE_TLEN_LIT0    RECIPE_L0_LEN
#define RECIPE_TLEN_LIT1    RECIPE_L1_LEN
#define RECIPE_TLEN_LIT2    RECIPE_L2_LEN
#define RECIPE_TLEN_LIT3    RECIPE_L3_LEN
#define RECIPE_TLEN_XP0     xl0
#define RECIPE_TLEN_XP1     xl1
#define RECIPE_TLEN_XP2     xl2
#define RECIPE_TLEN_XP3     xl3
#define RECIPE_TLEN_XS0     (st->xl0)
#define RECIPE_TLEN_XS1     (st->xl1)
#define RECIPE_TLEN_XS2     (st->xl2)
#define RECIPE_TLEN_XS3     (st->xl3)
#define RECIPE_TLEN_PSTEP0  pout_lens[0]
#define RECIPE_TLEN_PSTEP1  pout_lens[1]
#define RECIPE_TLEN_PSTEP2  pout_lens[2]
#define RECIPE_TLEN_PSTEP3  pout_lens[3]
#define RECIPE_TLEN_PSTEP4  pout_lens[4]
#define RECIPE_TLEN_PSTEP5  pout_lens[5]
#define RECIPE_TLEN_PSTEP6  pout_lens[6]
#define RECIPE_TLEN_PSTEP7  pout_lens[7]
#define RECIPE_TLEN_PSTEP8  pout_lens[8]
#define RECIPE_TLEN_PSTEP9  pout_lens[9]
#define RECIPE_TLEN_PSTEP10 pout_lens[10]
#define RECIPE_TLEN_PSTEP11 pout_lens[11]
#define RECIPE_TLEN_PSTEP12 pout_lens[12]
#define RECIPE_TLEN_PSTEP13 pout_lens[13]
#define RECIPE_TLEN_PSTEP14 pout_lens[14]
#define RECIPE_TLEN_PSTEP15 pout_lens[15]
#define RECIPE_TLEN_STEP0   RECIPE_S0_OLEN
#define RECIPE_TLEN_STEP1   RECIPE_S1_OLEN
#define RECIPE_TLEN_STEP2   RECIPE_S2_OLEN
#define RECIPE_TLEN_STEP3   RECIPE_S3_OLEN
#define RECIPE_TLEN_STEP4   RECIPE_S4_OLEN
#define RECIPE_TLEN_STEP5   RECIPE_S5_OLEN
#define RECIPE_TLEN_STEP6   RECIPE_S6_OLEN
#define RECIPE_TLEN_STEP7   RECIPE_S7_OLEN
#define RECIPE_TLEN_STEP8   RECIPE_S8_OLEN
#define RECIPE_TLEN_STEP9   RECIPE_S9_OLEN
#define RECIPE_TLEN_STEP10  RECIPE_S10_OLEN
#define RECIPE_TLEN_STEP11  RECIPE_S11_OLEN
#define RECIPE_TLEN_STEP12  RECIPE_S12_OLEN
#define RECIPE_TLEN_STEP13  RECIPE_S13_OLEN
#define RECIPE_TLEN_STEP14  RECIPE_S14_OLEN
#define RECIPE_TLEN_STEP15  RECIPE_S15_OLEN
#define RECIPE_TLEN_VAR0    RECIPE_TLV2 (RECIPE_C0_DYN, 0)
#define RECIPE_TLEN_VAR1    RECIPE_TLV2 (RECIPE_C1_DYN, 1)
#define RECIPE_TLEN_VAR2    RECIPE_TLV2 (RECIPE_C2_DYN, 2)
#define RECIPE_TLEN_VAR3    RECIPE_TLV2 (RECIPE_C3_DYN, 3)

#define RECIPE_TLV3(D,C)   RECIPE_TLV_##D (C)
#define RECIPE_TLV2(D,C)   RECIPE_TLV3 (D, C)
#define RECIPE_TLV_0(C)    vl[C]
#define RECIPE_TLV_1(C)    RECIPE_C##C##_LEN

#define RECIPE_TQ_NONE   NONE
#define RECIPE_TQ_SALT   SALT
#define RECIPE_TQ_SALTD  SALTD
#define RECIPE_TQ_SALT2  SALT2
#define RECIPE_TQ_PEPPER PEPPER
#define RECIPE_TQ_USER   USER
#define RECIPE_TQ_LIT0   LIT0
#define RECIPE_TQ_LIT1   LIT1
#define RECIPE_TQ_LIT2   LIT2
#define RECIPE_TQ_LIT3   LIT3
#define RECIPE_TQ_XS0    XS0
#define RECIPE_TQ_XS1    XS1
#define RECIPE_TQ_XS2    XS2
#define RECIPE_TQ_XS3    XS3
#define RECIPE_TQ_STEP0  PSTEP0
#define RECIPE_TQ_STEP1  PSTEP1
#define RECIPE_TQ_STEP2  PSTEP2
#define RECIPE_TQ_STEP3  PSTEP3
#define RECIPE_TQ_STEP4  PSTEP4
#define RECIPE_TQ_STEP5  PSTEP5
#define RECIPE_TQ_STEP6  PSTEP6
#define RECIPE_TQ_STEP7  PSTEP7
#define RECIPE_TQ_STEP8  PSTEP8
#define RECIPE_TQ_STEP9  PSTEP9
#define RECIPE_TQ_STEP10 PSTEP10
#define RECIPE_TQ_STEP11 PSTEP11
#define RECIPE_TQ_STEP12 PSTEP12
#define RECIPE_TQ_STEP13 PSTEP13
#define RECIPE_TQ_STEP14 PSTEP14
#define RECIPE_TQ_STEP15 PSTEP15

#define RECIPE_TQ3(TOK) RECIPE_TQ_##TOK
#define RECIPE_TQ2(TOK) RECIPE_TQ3 (TOK)

// The part tokens of step K in hashing order: Q0 to Q7, then P0 to P7.

#define RECIPE_TSL_0(K)  RECIPE_TQ2 (RECIPE_S##K##_Q0)
#define RECIPE_TSL_1(K)  RECIPE_TQ2 (RECIPE_S##K##_Q1)
#define RECIPE_TSL_2(K)  RECIPE_TQ2 (RECIPE_S##K##_Q2)
#define RECIPE_TSL_3(K)  RECIPE_TQ2 (RECIPE_S##K##_Q3)
#define RECIPE_TSL_4(K)  RECIPE_TQ2 (RECIPE_S##K##_Q4)
#define RECIPE_TSL_5(K)  RECIPE_TQ2 (RECIPE_S##K##_Q5)
#define RECIPE_TSL_6(K)  RECIPE_TQ2 (RECIPE_S##K##_Q6)
#define RECIPE_TSL_7(K)  RECIPE_TQ2 (RECIPE_S##K##_Q7)
#define RECIPE_TSL_8(K)  RECIPE_S##K##_P0
#define RECIPE_TSL_9(K)  RECIPE_S##K##_P1
#define RECIPE_TSL_10(K) RECIPE_S##K##_P2
#define RECIPE_TSL_11(K) RECIPE_S##K##_P3
#define RECIPE_TSL_12(K) RECIPE_S##K##_P4
#define RECIPE_TSL_13(K) RECIPE_S##K##_P5
#define RECIPE_TSL_14(K) RECIPE_S##K##_P6
#define RECIPE_TSL_15(K) RECIPE_S##K##_P7

#define RECIPE_TL3(TOK) RECIPE_TLEN_##TOK
#define RECIPE_TL2(TOK) RECIPE_TL3 (TOK)

#define RECIPE_TK3(TOK) RECIPE_TK_##TOK
#define RECIPE_TK2(TOK) RECIPE_TK3 (TOK)

// The byte offset of slot I, from the lengths of the preceding slots. If those lengths are all
// constant, as in h . pass, the offset also folds to a constant.

#define RECIPE_TO_0(K)  0
#define RECIPE_TO_1(K)  (RECIPE_TO_0  (K) + RECIPE_TL2 (RECIPE_TSL_0  (K)))
#define RECIPE_TO_2(K)  (RECIPE_TO_1  (K) + RECIPE_TL2 (RECIPE_TSL_1  (K)))
#define RECIPE_TO_3(K)  (RECIPE_TO_2  (K) + RECIPE_TL2 (RECIPE_TSL_2  (K)))
#define RECIPE_TO_4(K)  (RECIPE_TO_3  (K) + RECIPE_TL2 (RECIPE_TSL_3  (K)))
#define RECIPE_TO_5(K)  (RECIPE_TO_4  (K) + RECIPE_TL2 (RECIPE_TSL_4  (K)))
#define RECIPE_TO_6(K)  (RECIPE_TO_5  (K) + RECIPE_TL2 (RECIPE_TSL_5  (K)))
#define RECIPE_TO_7(K)  (RECIPE_TO_6  (K) + RECIPE_TL2 (RECIPE_TSL_6  (K)))
#define RECIPE_TO_8(K)  (RECIPE_TO_7  (K) + RECIPE_TL2 (RECIPE_TSL_7  (K)))
#define RECIPE_TO_9(K)  (RECIPE_TO_8  (K) + RECIPE_TL2 (RECIPE_TSL_8  (K)))
#define RECIPE_TO_10(K) (RECIPE_TO_9  (K) + RECIPE_TL2 (RECIPE_TSL_9  (K)))
#define RECIPE_TO_11(K) (RECIPE_TO_10 (K) + RECIPE_TL2 (RECIPE_TSL_10 (K)))
#define RECIPE_TO_12(K) (RECIPE_TO_11 (K) + RECIPE_TL2 (RECIPE_TSL_11 (K)))
#define RECIPE_TO_13(K) (RECIPE_TO_12 (K) + RECIPE_TL2 (RECIPE_TSL_12 (K)))
#define RECIPE_TO_14(K) (RECIPE_TO_13 (K) + RECIPE_TL2 (RECIPE_TSL_13 (K)))
#define RECIPE_TO_15(K) (RECIPE_TO_14 (K) + RECIPE_TL2 (RECIPE_TSL_14 (K)))
#define RECIPE_TO_16(K) (RECIPE_TO_15 (K) + RECIPE_TL2 (RECIPE_TSL_15 (K)))

// Per slot: copy a static part's bytes into the template, check a dynamic part's length this
// iteration, and place a dynamic part's words.

#define RECIPE_TB_TKN(TOK,OFF,K,F)
#define RECIPE_TB_TKD(TOK,OFF,K,F)
#define RECIPE_TB_TKS(TOK,OFF,K,F) { const u32 o = (OFF); for (u32 j = 0; j < RECIPE_TL2 (TOK); j++) RECIPE_XPUT (tpl->tb##K, o + j, RECIPE_XGET (RECIPE_KBUF (TOK), j)); }

#define RECIPE_TC_TKN(TOK)
#define RECIPE_TC_TKS(TOK)
#define RECIPE_TC_TKD(TOK)         && (RECIPE_KLEN (TOK) == RECIPE_TL2 (TOK))

#define RECIPE_TZ_TKN(TOK,OFF,K,F)
#define RECIPE_TZ_TKS(TOK,OFF,K,F)
#define RECIPE_TZ_TKD(TOK,OFF,K,F) if (((i * 4) >= (OFF)) && (((i * 4) + 4) <= ((OFF) + RECIPE_TL2 (TOK)))) z = true;

#define RECIPE_TSW4(B,V)     RECIPE_TSW_##B (V)
#define RECIPE_TSW3(B,V)     RECIPE_TSW4 (B, V)
#define RECIPE_TSW2(F,V)     RECIPE_TSW3 (RECIPE_TBE_##F, V)
#define RECIPE_TFS4(B,A,C,S) RECIPE_TFS_##B (A, C, S)
#define RECIPE_TFS3(B,A,C,S) RECIPE_TFS4 (B, A, C, S)
#define RECIPE_TFS2(F,A,C,S) RECIPE_TFS3 (RECIPE_TBE_##F, A, C, S)

// A dynamic part ends before the 0x80 byte and the length, so it starts at word RECIPE_TMO at the
// latest. A part that cannot fit at all never takes the template, and places no words.

#define RECIPE_TLB(F)      ((RECIPE_BLOCK_##F == 128) ? 16 : 8)
#define RECIPE_TFIT(F,TOK) ((RECIPE_BLOCK_##F - 1 - RECIPE_TLB (F)) >= RECIPE_TL2 (TOK))
#define RECIPE_TMO(F,TOK)  (RECIPE_TFIT (F, TOK) ? ((RECIPE_BLOCK_##F - 1 - RECIPE_TLB (F) - RECIPE_TL2 (TOK)) / 4) : 0)

// A dynamic part of n words at byte offset o, which can differ per candidate when the part follows
// the password. Its words move o % 4 bytes along into n + 1 words, then o / 4 words along, one
// masked move per word for each bit of o / 4. No word is indexed at run time, so the block stays in
// registers. The template holds zero bytes where the part goes, RECIPE_TLAY clears the words the
// part covers whole, and the part's words are or'ed in. With a constant offset, all of this folds
// to word moves. A mask rather than a select per bit keeps clang from turning the moves into
// compares of each word's index, which take several times the instructions.

#define RECIPE_TI_TKN(TOK,OFF,K,F)
#define RECIPE_TI_TKS(TOK,OFF,K,F)
#define RECIPE_TI_TKD(TOK,OFF,K,F)                                                                \
{                                                                                                 \
  const u32 o   = (OFF);                                                                          \
  const u32 sh  = (o & 3) * 8;                                                                    \
  const u32 n   = RECIPE_TFIT (F, TOK) ? (RECIPE_TL2 (TOK) / 4) : 0;                              \
  const u32 mo  = RECIPE_TMO (F, TOK);                                                            \
  const u32 top = mo + n;                                                                         \
                                                                                                  \
  u32 e[RECIPE_BLOCK_##F / 4];                                                                    \
                                                                                                  \
  for (u32 i = 0; i <= top; i++)                                                                  \
  {                                                                                               \
    const u32 a = ((i >= 1) && (i <= n)) ? RECIPE_TSW2 (F, RECIPE_KBUF (TOK)[i - 1]) : 0;         \
    const u32 b = (i < n) ? RECIPE_TSW2 (F, RECIPE_KBUF (TOK)[i]) : 0;                            \
                                                                                                  \
    e[i] = RECIPE_TFS2 (F, a, b, sh);                                                             \
  }                                                                                               \
                                                                                                  \
  for (u32 m = 1; m <= mo; m *= 2)                                                                \
  {                                                                                               \
    const u32 k = 0 - (((o / 4) / m) & 1);                                                        \
                                                                                                  \
    for (u32 i = top; i >= m; i--) e[i] = (e[i - m] & k) | (e[i] & ~k);                           \
                                                                                                  \
    for (u32 i = 0; i < m; i++) e[i] = e[i] & ~k;                                                 \
  }                                                                                               \
                                                                                                  \
  for (u32 i = 0; i <= top; i++) tb[i] |= e[i];                                                   \
}

#define RECIPE_TSLOT4(W,KIND,TOK,OFF,K,F) RECIPE_##W##_##KIND (TOK, OFF, K, F)
#define RECIPE_TSLOT3(W,KIND,TOK,OFF,K,F) RECIPE_TSLOT4 (W, KIND, TOK, OFF, K, F)
#define RECIPE_TSLOT2(W,TOK,OFF,K,F)      RECIPE_TSLOT3 (W, RECIPE_TK2 (TOK), TOK, OFF, K, F)
#define RECIPE_TSLOT(W,K,I,F)             RECIPE_TSLOT2 (W, RECIPE_TSL_##I (K), RECIPE_TO_##I (K), K, F)

#define RECIPE_TLC4(KIND,TOK) RECIPE_TC_##KIND (TOK)
#define RECIPE_TLC3(KIND,TOK) RECIPE_TLC4 (KIND, TOK)
#define RECIPE_TLC2(TOK)      RECIPE_TLC3 (RECIPE_TK2 (TOK), TOK)
#define RECIPE_TLC(K,I)       RECIPE_TLC2 (RECIPE_TSL_##I (K))

#define RECIPE_TALL(W,K,F)                                                                                  \
  RECIPE_TSLOT (W, K,  0, F) RECIPE_TSLOT (W, K,  1, F) RECIPE_TSLOT (W, K,  2, F) RECIPE_TSLOT (W, K,  3, F) \
  RECIPE_TSLOT (W, K,  4, F) RECIPE_TSLOT (W, K,  5, F) RECIPE_TSLOT (W, K,  6, F) RECIPE_TSLOT (W, K,  7, F) \
  RECIPE_TSLOT (W, K,  8, F) RECIPE_TSLOT (W, K,  9, F) RECIPE_TSLOT (W, K, 10, F) RECIPE_TSLOT (W, K, 11, F) \
  RECIPE_TSLOT (W, K, 12, F) RECIPE_TSLOT (W, K, 13, F) RECIPE_TSLOT (W, K, 14, F) RECIPE_TSLOT (W, K, 15, F)

#define RECIPE_TLENS(K)                                                                   \
  RECIPE_TLC (K,  0) RECIPE_TLC (K,  1) RECIPE_TLC (K,  2) RECIPE_TLC (K,  3)             \
  RECIPE_TLC (K,  4) RECIPE_TLC (K,  5) RECIPE_TLC (K,  6) RECIPE_TLC (K,  7)             \
  RECIPE_TLC (K,  8) RECIPE_TLC (K,  9) RECIPE_TLC (K, 10) RECIPE_TLC (K, 11)             \
  RECIPE_TLC (K, 12) RECIPE_TLC (K, 13) RECIPE_TLC (K, 14) RECIPE_TLC (K, 15)

// Lay out step K's template for family F once per launch. A template is one block, because every
// word of it stays live across all loop iterations. With room for 2 blocks, SHA-512 spilled 202
// VGPRs on gfx1100. A message that requires a second block therefore uses the general path. The
// bit length of an HMAC's inner message counts the ipad block before it.

#define RECIPE_TPRE_HASH(F) 0
#define RECIPE_TPRE_HMAC(F) RECIPE_BLOCK_##F

#define RECIPE_TPRE3(D,F) RECIPE_TPRE_##D (F)
#define RECIPE_TPRE2(D,F) RECIPE_TPRE3 (D, F)

#define RECIPE_TBUILD3(F,K)                                                               \
{                                                                                         \
  const u32 m  = RECIPE_TO_16 (K);                                                        \
  const u32 lb = RECIPE_TLB (F);                                                          \
  const u32 bw = RECIPE_BLOCK_##F / 4;                                                    \
                                                                                          \
  tpl->ok##K = ((m + 1 + lb) <= RECIPE_BLOCK_##F) ? 1 : 0;                                \
                                                                                          \
  if (tpl->ok##K == 1)                                                                    \
  {                                                                                       \
    for (u32 i = 0; i < bw; i++) tpl->tb##K[i] = 0;                                       \
                                                                                          \
    RECIPE_TALL (TB, K, F)                                                                \
                                                                                          \
    RECIPE_XPUT (tpl->tb##K, m, 0x80);                                                    \
                                                                                          \
    if (RECIPE_TBE_##F == 1)                                                              \
    {                                                                                     \
      for (u32 i = 0; i < bw; i++) tpl->tb##K[i] = hc_swap32_S (tpl->tb##K[i]);           \
    }                                                                                     \
                                                                                          \
    RECIPE_TLW_##F (tpl->tb##K, 1, m + RECIPE_TPRE2 (RECIPE_S##K##_KIND, F))              \
  }                                                                                       \
}

#define RECIPE_TBUILD2(F,K) RECIPE_TBUILD3 (F, K)

#define RECIPE_TBD_0(K)
#define RECIPE_TBD_1(K)        RECIPE_TBUILD2 (RECIPE_S##K##_FN, K)
#define RECIPE_TBD3(B,K)       RECIPE_TBD_##B (K)
#define RECIPE_TBD2(B,K)       RECIPE_TBD3 (B, K)
#define RECIPE_TBUILD(K,X,HS,T) RECIPE_TBD2 (RECIPE_S##K##_TPL, K)

// The block of template step K in this iteration: its template, with each word that a dynamic part
// covers whole cleared, and the dynamic parts placed.

#define RECIPE_TLAY(F,K)                                                                  \
  u32 tb[RECIPE_BLOCK_##F / 4];                                                           \
                                                                                          \
  for (u32 i = 0; i < (RECIPE_BLOCK_##F / 4); i++)                                        \
  {                                                                                       \
    bool z = false;                                                                       \
                                                                                          \
    RECIPE_TALL (TZ, K, F)                                                                \
                                                                                          \
    tb[i] = (z == true) ? 0 : tpl->tb##K[i];                                              \
  }                                                                                       \
                                                                                          \
  RECIPE_TALL (TI, K, F)

// Run one iteration of template step K: lay out its block, apply the transforms, then format the
// output as for any other step. An HMAC starts the inner message from the ipad context and hashes
// the outer block, its inner digest after the opad block, from the opad context. Both contexts come
// from recipe_tpl_build (), see RECIPE_S<k>_HK.

#define RECIPE_TSTEP_HASH(F,K,X,HS,T)                                                     \
{                                                                                         \
  RECIPE_TLAY (F, K)                                                                      \
                                                                                          \
  {                                                                                       \
    RECIPE_CTX_##F ( ) ctx;                                                               \
                                                                                          \
    RECIPE_INIT_##F ( )                                                                   \
                                                                                          \
    RECIPE_TXS_##F ( , tb, ctx.h)                                                         \
                                                                                          \
    RECIPE_TRAW_##F (_S)                                                                  \
  }                                                                                       \
                                                                                          \
  if (RECIPE_FMT_STEP (K))                                                                \
  {                                                                                       \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                           \
                                                                                          \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                \
  }                                                                                       \
}

#define RECIPE_TSTEP_HMAC(F,K,X,HS,T)                                                     \
{                                                                                         \
  RECIPE_TLAY (F, K)                                                                      \
                                                                                          \
  u32 ob[RECIPE_BLOCK_##F / 4];                                                           \
                                                                                          \
  {                                                                                       \
    RECIPE_CTX_##F (X) ctx = tpl->hi##K;                                                  \
                                                                                          \
    RECIPE_TXS_##F ( , tb, ctx.h)                                                         \
                                                                                          \
    RECIPE_TOB (F, _S, ob)                                                                \
  }                                                                                       \
                                                                                          \
  {                                                                                       \
    RECIPE_CTX_##F (X) ctx = tpl->ho##K;                                                  \
                                                                                          \
    RECIPE_TXS_##F ( , ob, ctx.h)                                                         \
                                                                                          \
    RECIPE_TRAW_##F (_S)                                                                  \
  }                                                                                       \
                                                                                          \
  if (RECIPE_FMT_STEP (K))                                                                \
  {                                                                                       \
    RECIPE_FORMAT (T, HS, RECIPE_S##K##_FMT, K, RECIPE_LEN_##F)                           \
                                                                                          \
    RECIPE_CUT (K, RECIPE_S##K##_CUT0, RECIPE_S##K##_CUTN)                                \
  }                                                                                       \
}

#define RECIPE_TSTEP4(D,F,K,X,HS,T) RECIPE_TSTEP_##D (F, K, X, HS, T)
#define RECIPE_TSTEP3(D,F,K,X,HS,T) RECIPE_TSTEP4 (D, F, K, X, HS, T)
#define RECIPE_TSTEP2(F,K,X,HS,T)   RECIPE_TSTEP3 (RECIPE_S##K##_KIND, F, K, X, HS, T)

// An HMAC whose key depends on the candidate but not on the iteration, RECIPE_S<k>_HK, starts its
// inner and outer hash from the key pad contexts of recipe_tpl_build (), as native slow kernels
// start from the ipad and opad states they keep in their tmps. Without that, every iteration
// hashes the key block twice more. Other steps run as outside the loop.

#define RECIPE_STEP_HMACL(F,K,X,HS,T)  RECIPE_STEP_HMACIO (F, K, X, HS, T, ctx = tpl->hi##K;, ctx = tpl->ho##K;, RECIPE_FEED (K, F, X))
#define RECIPE_STEP_HMACL2(F,K,X,HS,T) RECIPE_STEP_HMACL (F, K, X, HS, T)

#define RECIPE_EVH_0(K,X,HS,T)  RECIPE_EV (K, X, HS, T)
#define RECIPE_EVH_1(K,X,HS,T)  RECIPE_STEP_HMACL2 (RECIPE_S##K##_FN, K, X, HS, T)
#define RECIPE_EVH3(H,K,X,HS,T) RECIPE_EVH_##H (K, X, HS, T)
#define RECIPE_EVH2(H,K,X,HS,T) RECIPE_EVH3 (H, K, X, HS, T)
#define RECIPE_EVH(K,X,HS,T)    RECIPE_EVH2 (RECIPE_S##K##_HK, K, X, HS, T)

#define RECIPE_EVT_0(K,X,HS,T) RECIPE_EVH (K, X, HS, T)
#define RECIPE_EVT_1(K,X,HS,T) if ((tpl->ok##K == 1) RECIPE_TLENS (K)) { RECIPE_TSTEP2 (RECIPE_S##K##_FN, K, X, HS, T) } else { RECIPE_EVH (K, X, HS, T) }
#define RECIPE_EVT3(B,K,X,HS,T) RECIPE_EVT_##B (K, X, HS, T)
#define RECIPE_EVT2(B,K,X,HS,T) RECIPE_EVT3 (B, K, X, HS, T)

// The loop kernel evaluates in the word type and flavor of the state, see RECIPE_SCALAR_STATE.

#ifdef RECIPE_SCALAR_STATE
#define RECIPE_THS _S
#define RECIPE_TX
#else
#define RECIPE_THS
#define RECIPE_TX  _vector
#endif

// The templates of the template steps and the key pad contexts of the HK steps. The first member
// keeps the struct from being empty.

#define RECIPE_TFLD_0(K)
#define RECIPE_TFLF2(F,K) u32 tb##K[RECIPE_BLOCK_##F / 4]; u32 ok##K;
#define RECIPE_TFLF(F,K)  RECIPE_TFLF2 (F, K)
#define RECIPE_TFLD_1(K)  RECIPE_TFLF (RECIPE_S##K##_FN, K)
#define RECIPE_TFLD3(B,K) RECIPE_TFLD_##B (K)
#define RECIPE_TFLD2(B,K) RECIPE_TFLD3 (B, K)
#define RECIPE_TFLD(K)    RECIPE_TFLD2 (RECIPE_S##K##_TPL, K)

#define RECIPE_HFLD_0(F,X,K)
#define RECIPE_HFLD_1(F,X,K) RECIPE_CTX_##F (X) hi##K; RECIPE_CTX_##F (X) ho##K;
#define RECIPE_HFLD3(H,F,X,K) RECIPE_HFLD_##H (F, X, K)
#define RECIPE_HFLD2(H,F,X,K) RECIPE_HFLD3 (H, F, X, K)
#define RECIPE_HFLD(K)        RECIPE_HFLD2 (RECIPE_S##K##_HK, RECIPE_S##K##_FN, RECIPE_TX, K)

typedef struct recipe_tpl
{
  u32 unused;

  #if RECIPE_STEPS > 0
  RECIPE_TFLD (0)
  RECIPE_HFLD (0)
  #endif
  #if RECIPE_STEPS > 1
  RECIPE_TFLD (1)
  RECIPE_HFLD (1)
  #endif
  #if RECIPE_STEPS > 2
  RECIPE_TFLD (2)
  RECIPE_HFLD (2)
  #endif
  #if RECIPE_STEPS > 3
  RECIPE_TFLD (3)
  RECIPE_HFLD (3)
  #endif
  #if RECIPE_STEPS > 4
  RECIPE_TFLD (4)
  RECIPE_HFLD (4)
  #endif
  #if RECIPE_STEPS > 5
  RECIPE_TFLD (5)
  RECIPE_HFLD (5)
  #endif
  #if RECIPE_STEPS > 6
  RECIPE_TFLD (6)
  RECIPE_HFLD (6)
  #endif
  #if RECIPE_STEPS > 7
  RECIPE_TFLD (7)
  RECIPE_HFLD (7)
  #endif
  #if RECIPE_STEPS > 8
  RECIPE_TFLD (8)
  RECIPE_HFLD (8)
  #endif
  #if RECIPE_STEPS > 9
  RECIPE_TFLD (9)
  RECIPE_HFLD (9)
  #endif
  #if RECIPE_STEPS > 10
  RECIPE_TFLD (10)
  RECIPE_HFLD (10)
  #endif
  #if RECIPE_STEPS > 11
  RECIPE_TFLD (11)
  RECIPE_HFLD (11)
  #endif
  #if RECIPE_STEPS > 12
  RECIPE_TFLD (12)
  RECIPE_HFLD (12)
  #endif
  #if RECIPE_STEPS > 13
  RECIPE_TFLD (13)
  RECIPE_HFLD (13)
  #endif
  #if RECIPE_STEPS > 14
  RECIPE_TFLD (14)
  RECIPE_HFLD (14)
  #endif
  #if RECIPE_STEPS > 15
  RECIPE_TFLD (15)
  RECIPE_HFLD (15)
  #endif

} recipe_tpl_t;

// The key pad contexts of HK step K. The init kernel computes them from the key as recipe_prep ()
// does for a key that does not depend on the candidate, and stores their chaining values in hk. The
// tmps carry them, and recipe_tpl_build () of the loop kernel puts them back into contexts that
// have hashed one block. RECIPE_S<k>_HKO is the first word of the ipad value. The opad value
// follows it.

#define RECIPE_HB_0(F,K,X,HS,T)
#define RECIPE_HB_1(F,K,X,HS,T)                                                           \
{                                                                                         \
  RECIPE_CTX_##F (X) ctx;                                                                 \
                                                                                          \
  RECIPE_INIT_##F (X)                                                                     \
                                                                                          \
  ctx.len = RECIPE_BLOCK_##F;                                                             \
                                                                                          \
  RECIPE_HLD_##F (ctx.h, hk, RECIPE_S##K##_HKO + 0)                                       \
                                                                                          \
  tpl->hi##K = ctx;                                                                       \
                                                                                          \
  RECIPE_HLD_##F (ctx.h, hk, RECIPE_S##K##_HKO + RECIPE_SW_##F)                           \
                                                                                          \
  tpl->ho##K = ctx;                                                                       \
}
#define RECIPE_HB3(H,F,K,X,HS,T) RECIPE_HB_##H (F, K, X, HS, T)
#define RECIPE_HB2(H,F,K,X,HS,T) RECIPE_HB3 (H, F, K, X, HS, T)
#define RECIPE_HBUILD(K,X,HS,T)  RECIPE_HB2 (RECIPE_S##K##_HK, RECIPE_S##K##_FN, K, X, HS, T)

#define RECIPE_HS_0(F,K,X,HS,T)
#define RECIPE_HS_1(F,K,X,HS,T)                                                           \
{                                                                                         \
  RECIPE_CTX_##F (X) hi;                                                                  \
  RECIPE_CTX_##F (X) ho;                                                                  \
                                                                                          \
  RECIPE_PADS (F, K, X, HS, T, hi, ho, )                                                  \
                                                                                          \
  RECIPE_HST_##F (hi.h, hk, RECIPE_S##K##_HKO + 0)                                        \
  RECIPE_HST_##F (ho.h, hk, RECIPE_S##K##_HKO + RECIPE_SW_##F)                            \
}
#define RECIPE_HS3(H,F,K,X,HS,T) RECIPE_HS_##H (F, K, X, HS, T)
#define RECIPE_HS2(H,F,K,X,HS,T) RECIPE_HS3 (H, F, K, X, HS, T)
#define RECIPE_HSTORE(K,X,HS,T)  RECIPE_HS2 (RECIPE_S##K##_HK, RECIPE_S##K##_FN, K, X, HS, T)

// The words of hk, at least one because an array cannot be empty.

#if RECIPE_HKW > 0
#define RECIPE_HKN RECIPE_HKW
#else
#define RECIPE_HKN 1
#endif

#ifndef RECIPE_KDF

DECLSPEC RECIPE_INLINE void recipe_tpl_build (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS recipe_tpl_t *tpl, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len, PRIVATE_AS const RECIPE_VT *vb, PRIVATE_AS const u32 *vl, PRIVATE_AS const u32 *hk)
{
  RECIPE_LITS (u32x, make_u32x)

  PRIVATE_AS const u32x *pouts     = st->outs;
  PRIVATE_AS const u32  *pout_lens = st->out_lens;

  RECIPE_XEVS (u32x, RECIPE_THS)

  RECIPE_ALL (RECIPE_TBUILD, , , u32x)

  RECIPE_ALL (RECIPE_HBUILD, RECIPE_TX, RECIPE_THS, RECIPE_VT)
}

#endif

#define RECIPE_EVSEC3(S,W,K,X,HS,T) RECIPE_SEC_##S##_##W (K, X, HS, T)
#define RECIPE_EVSEC2(S,W,K,X,HS,T) RECIPE_EVSEC3 (S, W, K, X, HS, T)

#define RECIPE_EVI(K,X,HS,T) RECIPE_EVSEC2 (RECIPE_S##K##_SEC, INIT, K, X, HS, T)
#define RECIPE_EVL(K,X,HS,T) RECIPE_EVSEC2 (RECIPE_S##K##_SEC, LOOP, K, X, HS, T)
#define RECIPE_EVC(K,X,HS,T) RECIPE_EVSEC2 (RECIPE_S##K##_SEC, COMP, K, X, HS, T)

// Copy part TOK into carried variable C. Clear any words beyond the new value that were used
// by its previous value.

#define RECIPE_STORE3(TOK,C)                                                      \
{                                                                                 \
  const u32 n_new = (RECIPE_KLEN (TOK) + 3) / 4;                                  \
  const u32 n_old = (vl[C] + 3) / 4;                                              \
                                                                                  \
  for (u32 i = 0; i < n_new; i++) vb[((C) * 64) + i] = RECIPE_KBUF (TOK)[i];      \
                                                                                  \
  for (u32 i = n_new; i < n_old; i++) vb[((C) * 64) + i] = 0;                     \
                                                                                  \
  vl[C] = RECIPE_KLEN (TOK);                                                      \
}

#define RECIPE_STORE2(TOK,C) RECIPE_STORE3 (TOK, C)

#define RECIPE_IST(I) RECIPE_STORE2 (RECIPE_I##I##_TOK, RECIPE_I##I##_SLOT)
#define RECIPE_LST(I) RECIPE_STORE2 (RECIPE_L##I##_TOK, RECIPE_L##I##_SLOT)

#if   RECIPE_ISTORES == 0
#define RECIPE_ISTS
#elif RECIPE_ISTORES == 1
#define RECIPE_ISTS RECIPE_IST (0)
#elif RECIPE_ISTORES == 2
#define RECIPE_ISTS RECIPE_IST (0) RECIPE_IST (1)
#elif RECIPE_ISTORES == 3
#define RECIPE_ISTS RECIPE_IST (0) RECIPE_IST (1) RECIPE_IST (2)
#else
#define RECIPE_ISTS RECIPE_IST (0) RECIPE_IST (1) RECIPE_IST (2) RECIPE_IST (3)
#endif

#if   RECIPE_LSTORES == 0
#define RECIPE_LSTS
#elif RECIPE_LSTORES == 1
#define RECIPE_LSTS RECIPE_LST (0)
#elif RECIPE_LSTORES == 2
#define RECIPE_LSTS RECIPE_LST (0) RECIPE_LST (1)
#elif RECIPE_LSTORES == 3
#define RECIPE_LSTS RECIPE_LST (0) RECIPE_LST (1) RECIPE_LST (2)
#else
#define RECIPE_LSTS RECIPE_LST (0) RECIPE_LST (1) RECIPE_LST (2) RECIPE_LST (3)
#endif

// For a carried variable as the result, take the 16 compared bytes from the start of its stored
// value. RECIPE_ROOT_VFMT selects raw, hex or base64. The comp kernel evaluates one candidate per
// work item, so the words are u32 and the comparisons below operate on one candidate at a time.

#ifdef RECIPE_ROOT_VAR

#define RECIPE_RVB (vb + (RECIPE_ROOT_VAR * 64))

#if RECIPE_ROOT_VFMT == 1

#define RECIPE_ROOTV(HS)                                                          \
{                                                                                 \
  for (u32 i = 0; i < 4; i++) r[i] = RECIPE_RVB[i];                               \
}

#elif RECIPE_ROOT_VFMT == 3

#define RECIPE_ROOTV(HS)                                                          \
{                                                                                 \
  for (u32 i = 0; i < 4; i++) r[i] = 0;                                           \
                                                                                  \
  for (u32 g = 0; g < 6; g++)                                                     \
  {                                                                               \
    u32 v[4];                                                                     \
                                                                                  \
    for (u32 j = 0; j < 4; j++)                                                   \
    {                                                                             \
      const u32 c = RECIPE_XGET (RECIPE_RVB, (g * 4) + j);                        \
                                                                                  \
      u32 x = 0;                                                                  \
                                                                                  \
      if ((c >= 'A') && (c <= 'Z')) x = c - 65;                                   \
      if ((c >= 'a') && (c <= 'z')) x = c - 71;                                   \
      if ((c >= '0') && (c <= '9')) x = c + 4;                                    \
                                                                                  \
      if (c == '+') x = 62;                                                       \
      if (c == '/') x = 63;                                                       \
                                                                                  \
      v[j] = x;                                                                   \
    }                                                                             \
                                                                                  \
    const u32 b0 = ((v[0] << 2) | (v[1] >> 4)) & 255;                             \
    const u32 b1 = ((v[1] << 4) | (v[2] >> 2)) & 255;                             \
    const u32 b2 = ((v[2] << 6) | (v[3] >> 0)) & 255;                             \
                                                                                  \
    const u32 at = g * 3;                                                         \
                                                                                  \
    if ((at + 0) < 16) RECIPE_XPUT (r, at + 0, b0);                               \
    if ((at + 1) < 16) RECIPE_XPUT (r, at + 1, b1);                               \
    if ((at + 2) < 16) RECIPE_XPUT (r, at + 2, b2);                               \
  }                                                                               \
}

#else

#define RECIPE_ROOTV(HS)                                                          \
{                                                                                 \
  for (u32 i = 0; i < 4; i++) r[i] = 0;                                           \
                                                                                  \
  for (u32 i = 0; i < 16; i++)                                                    \
  {                                                                               \
    const u32 c0 = RECIPE_XGET (RECIPE_RVB, (i * 2) + 0);                         \
    const u32 c1 = RECIPE_XGET (RECIPE_RVB, (i * 2) + 1);                         \
                                                                                  \
    const u32 h0 = ((c0 & 15) + (((c0 >> 6) & 1) * 9)) & 15;                      \
    const u32 h1 = ((c1 & 15) + (((c1 >> 6) & 1) * 9)) & 15;                      \
                                                                                  \
    RECIPE_XPUT (r, i, (h0 << 4) | h1);                                           \
  }                                                                               \
}

#endif

// A carried variable shorter than 16 bytes as the result masks off the bytes past its length, as
// RECIPE_ROOT does.

#ifdef RECIPE_ROOT_MASK
#define RECIPE_ROOTV_MASK { r[0] &= RECIPE_ROOT_M0; r[1] &= RECIPE_ROOT_M1; r[2] &= RECIPE_ROOT_M2; r[3] &= RECIPE_ROOT_M3; }
#else
#define RECIPE_ROOTV_MASK
#endif

// A mode whose kernels run as a stored recipe compares in its own word layout through
// RECIPE_ROOT_NATIVE, as RECIPE_ROOT does for a hash call. If the result is a carried variable,
// such as the derived key of pbkdf2, the 4 compared words take the layout of the family that
// produced that value. The bytes past a shorter value are masked off first. A value from xor, and
// or or keeps memory order.

#ifdef RECIPE_ROOT_NATIVE

#define RECIPE_NATV_LE(HS)
#define RECIPE_NATV_BE(HS)   { for (u32 i = 0; i < 4; i++) r[i] = hc_swap32##HS (r[i]); }
#define RECIPE_NATV_BE64(HS) { const u32 t0 = r[0]; const u32 t2 = r[2]; r[0] = hc_swap32##HS (r[1]); r[1] = hc_swap32##HS (t0); r[2] = hc_swap32##HS (r[3]); r[3] = hc_swap32##HS (t2); }

#define RECIPE_NATV_md4(HS)        RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_md5(HS)        RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_rmd160(HS)     RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_blake2b512(HS) RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_blake2b256(HS) RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_blake2s256(HS) RECIPE_NATV_LE   (HS)
#define RECIPE_NATV_sha1(HS)       RECIPE_NATV_BE   (HS)
#define RECIPE_NATV_sha224(HS)     RECIPE_NATV_BE   (HS)
#define RECIPE_NATV_sha256(HS)     RECIPE_NATV_BE   (HS)
#define RECIPE_NATV_sm3(HS)        RECIPE_NATV_BE   (HS)
#define RECIPE_NATV_wrl(HS)        RECIPE_NATV_BE   (HS)
#define RECIPE_NATV_sha384(HS)     RECIPE_NATV_BE64 (HS)
#define RECIPE_NATV_sha512(HS)     RECIPE_NATV_BE64 (HS)
#define RECIPE_NATV_bop(HS)        RECIPE_NATV_LE   (HS)

#define RECIPE_NATV3(F,HS) RECIPE_NATV_##F (HS)
#define RECIPE_NATV2(F,HS) RECIPE_NATV3 (F, HS)

#define RECIPE_COMP_AFTER(HS) { RECIPE_ROOTV (HS) RECIPE_ROOTV_MASK RECIPE_NATV2 (RECIPE_ROOT_FN, HS) }

#else

#define RECIPE_COMP_AFTER(HS) { RECIPE_ROOTV (HS) RECIPE_ROOTV_MASK }

#endif

#else

#define RECIPE_COMP_AFTER(HS) RECIPE_ROOT (HS)

#endif

// The init, loop and comp kernels evaluate their own steps, each followed by its stores or the
// result. The init kernel then stores the chaining values of the key pads of the RECIPE_S<k>_HK
// steps, from the carried variables it has just stored.

#ifndef RECIPE_KDF

DECLSPEC RECIPE_INLINE void recipe_eval_init (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len, PRIVATE_AS RECIPE_VT *vb, PRIVATE_AS u32 *vl, PRIVATE_AS u32 *hk)
{
  #ifdef RECIPE_SCALAR_STATE
  RECIPE_EVALS ( , _S, u32, , RECIPE_EVI, RECIPE_ISTS RECIPE_ALL (RECIPE_HSTORE, , _S, u32))
  #else
  RECIPE_EVALS (_vector, , u32x, make_u32x, RECIPE_EVI, RECIPE_ISTS RECIPE_ALL (RECIPE_HSTORE, _vector, , u32x))
  #endif
}

DECLSPEC RECIPE_INLINE void recipe_eval_loop (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const recipe_tpl_t *tpl, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len, PRIVATE_AS RECIPE_VT *vb, PRIVATE_AS u32 *vl)
{
  #ifdef RECIPE_SCALAR_STATE
  RECIPE_EVALS ( , _S, u32, , RECIPE_EVL, RECIPE_LSTS)
  #else
  RECIPE_EVALS (_vector, , u32x, make_u32x, RECIPE_EVL, RECIPE_LSTS)
  #endif
}

#endif

// The template loop, RECIPE_TLOOP, for a recipe whose loop steps all hash from block templates. Once
// every template fits and every carried variable the loop assigns has the length its step gives it,
// that stays true for the remaining iterations. The loop kernel then leaves recipe_eval_loop () for
// recipe_eval_tloop (), which runs those iterations with template steps only. It copies the carried
// variables the loop assigns, the templates and the key pad contexts into private arrays that only
// constants index. These stay in registers, as the state of a native slow kernel does, rather than
// in memory that every iteration reads and writes.

#if RECIPE_TLOOP == 1

#define RECIPE_SEC_INIT_TPL(K,X,HS,T)
#define RECIPE_SEC_LOOP_TPL(K,X,HS,T) RECIPE_TSTEP2 (RECIPE_S##K##_FN, K, X, HS, T)
#define RECIPE_SEC_COMP_TPL(K,X,HS,T)

#define RECIPE_EVTL(K,X,HS,T) RECIPE_EVSEC2 (RECIPE_S##K##_SEC, TPL, K, X, HS, T)

#define RECIPE_TRDY_INIT(K)
#define RECIPE_TRDY_LOOP(K)   if (tpl->ok##K == 0) ok = false;
#define RECIPE_TRDY_COMP(K)
#define RECIPE_TRDY3(S,K)     RECIPE_TRDY_##S (K)
#define RECIPE_TRDY2(S,K)     RECIPE_TRDY3 (S, K)
#define RECIPE_TRDY(K,X,HS,T) RECIPE_TRDY2 (RECIPE_S##K##_SEC, K)

// Per carried variable C: check its length, copy it in and out. Only a variable the loop assigns,
// RECIPE_C<c>_DYN, is copied. The others are static parts the templates already hold.

#define RECIPE_TCV_0(C,W)
#define RECIPE_TCV_1(C,W)  RECIPE_TCV_##W (C)
#define RECIPE_TCV3(D,C,W) RECIPE_TCV_##D (C, W)
#define RECIPE_TCV2(D,C,W) RECIPE_TCV3 (D, C, W)
#define RECIPE_TCV(C,W)    RECIPE_TCV2 (RECIPE_C##C##_DYN, C, W)

#define RECIPE_TCV_RDY(C)  if (vl[C] != RECIPE_C##C##_LEN) ok = false;
#define RECIPE_TCV_IN(C)   { for (u32 i = 0; i < ((RECIPE_C##C##_LEN + 3) / 4); i++) vb[((C) * 64) + i] = vm[((C) * 64) + i]; vl[C] = RECIPE_C##C##_LEN; }
#define RECIPE_TCV_OUT(C)  for (u32 i = 0; i < ((RECIPE_C##C##_LEN + 3) / 4); i++) vm[((C) * 64) + i] = vb[((C) * 64) + i];

#if   RECIPE_CARRY == 1
#define RECIPE_TCVS(W) RECIPE_TCV (0, W)
#elif RECIPE_CARRY == 2
#define RECIPE_TCVS(W) RECIPE_TCV (0, W) RECIPE_TCV (1, W)
#elif RECIPE_CARRY == 3
#define RECIPE_TCVS(W) RECIPE_TCV (0, W) RECIPE_TCV (1, W) RECIPE_TCV (2, W)
#else
#define RECIPE_TCVS(W) RECIPE_TCV (0, W) RECIPE_TCV (1, W) RECIPE_TCV (2, W) RECIPE_TCV (3, W)
#endif

DECLSPEC RECIPE_INLINE bool recipe_tpl_ready (PRIVATE_AS const recipe_tpl_t *tpl, PRIVATE_AS const u32 *vl)
{
  bool ok = true;

  RECIPE_ALL (RECIPE_TRDY, , , )

  RECIPE_TCVS (RDY)

  return ok;
}

// N iterations of the template steps, in the word type and flavor of the state.

#define RECIPE_TEVALS(X,HS,T,M)                               \
{                                                             \
  RECIPE_LITS (T, M)                                          \
                                                              \
  PRIVATE_AS const T   *pouts     = st->outs;                 \
  PRIVATE_AS const u32 *pout_lens = st->out_lens;             \
                                                              \
  RECIPE_SB_DECL (T)                                          \
                                                              \
  RECIPE_XEVS (T, HS)                                         \
                                                              \
  for (u32 it = 0; it < n; it++)                              \
  {                                                           \
    T   outs[RECIPE_NOUTS * 32];                              \
    u32 out_lens[RECIPE_NOUTS];                               \
                                                              \
    T raw[16];                                                \
                                                              \
    RECIPE_ALL (RECIPE_EVTL, X, HS, T)                        \
                                                              \
    RECIPE_LSTS                                               \
  }                                                           \
}

DECLSPEC RECIPE_INLINE void recipe_eval_tloop (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const recipe_tpl_t *tpm, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len, PRIVATE_AS RECIPE_VT *vm, PRIVATE_AS u32 *vlm, const u32 n)
{
  const recipe_tpl_t tc = *tpm;

  PRIVATE_AS const recipe_tpl_t *tpl = &tc;

  RECIPE_VT vb[RECIPE_CARRY * 64];
  u32       vl[RECIPE_CARRY];

  for (u32 i = 0; i < RECIPE_CARRY; i++) vl[i] = vlm[i];

  RECIPE_TCVS (IN)

  #ifdef RECIPE_SCALAR_STATE
  RECIPE_TEVALS ( , _S, u32, )
  #else
  RECIPE_TEVALS (_vector, , u32x, make_u32x)
  #endif

  RECIPE_TCVS (OUT)
}

#endif

DECLSPEC RECIPE_INLINE void recipe_eval_comp (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len, PRIVATE_AS RECIPE_VT *vb, PRIVATE_AS u32 *vl, PRIVATE_AS RECIPE_VT *r)
{
  #ifdef RECIPE_SCALAR_STATE
  RECIPE_EVALS ( , _S, u32, , RECIPE_EVC, RECIPE_COMP_AFTER (_S))
  #else
  RECIPE_EVALS (_vector, , u32x, make_u32x, RECIPE_EVC, RECIPE_COMP_AFTER ( ))
  #endif
}

// A pbkdf2 recipe, see OpenCL/inc_pbkdf2.cl. The init kernel runs its steps and starts pbkdf2 from
// the key and salt parts, read in the same way as a step's parts. It computes only
// RECIPE_KDF_BLOCKS blocks, starting at block RECIPE_KDF_FIRST + 1, from the first to the last
// block that the recipe reads. The comp kernel formats the derived key into a carried variable in the same way as a
// step's output. It does this under RECIPE_KDF_WHOLE for steps that read the key. Under
// RECIPE_KDF_RAW, the whole key is used only as the result, and the variable receives the 16
// compared bytes as raw bytes. Each cut of the raw derived key, RECIPE_KDF_SL<i>, receives its
// slice's words in a carried variable of its own.

#ifdef RECIPE_KDF

#define RECIPE_KDF_T2(F)    pbkdf2_##F##_state_t
#define RECIPE_KDF_T1(F)    RECIPE_KDF_T2 (F)
#define RECIPE_KDF_STATE    RECIPE_KDF_T1 (RECIPE_KDF)

#define RECIPE_KDF_FN2(F,N) pbkdf2_##F##_##N
#define RECIPE_KDF_FN1(F,N) RECIPE_KDF_FN2 (F, N)
#define RECIPE_KDF_FN(N)    RECIPE_KDF_FN1 (RECIPE_KDF, N)

// A utf16le key or salt, RECIPE_KDF_KEYW or RECIPE_KDF_SALTW, is decoded into a buffer of its own
// first. Up to 256 bytes of UTF-8 give up to 512 bytes. Invalid UTF-8 inverts the derived key, so
// that it cannot match.

#define RECIPE_KDF_BUF_0(TOK,B)
#define RECIPE_KDF_BUF_1(TOK,B)                                                              \
  u32 B[128] = { 0 };                                                                        \
                                                                                             \
  const int B##_len = recipe_utf16le_S (RECIPE_KBUF (TOK), (int) RECIPE_KLEN (TOK), B, 512); \
                                                                                             \
  if (B##_len == -1) bad = true;

#define RECIPE_KDF_ARG_0(TOK,B) RECIPE_KBUF (TOK), (int) RECIPE_KLEN (TOK)
#define RECIPE_KDF_ARG_1(TOK,B) B, (B##_len == -1) ? 0 : B##_len

#define RECIPE_KDF_BUF3(W,TOK,B) RECIPE_KDF_BUF_##W (TOK, B)
#define RECIPE_KDF_BUF2(W,TOK,B) RECIPE_KDF_BUF3 (W, TOK, B)
#define RECIPE_KDF_ARG3(W,TOK,B) RECIPE_KDF_ARG_##W (TOK, B)
#define RECIPE_KDF_ARG2(W,TOK,B) RECIPE_KDF_ARG3 (W, TOK, B)

#define RECIPE_KDF_START                                                                                                                                                                   \
{                                                                                                                                                                                          \
  bool bad = false;                                                                                                                                                                        \
                                                                                                                                                                                           \
  RECIPE_KDF_BUF2 (RECIPE_KDF_KEYW,  RECIPE_KDF_KEY,  kdf_kw)                                                                                                                              \
  RECIPE_KDF_BUF2 (RECIPE_KDF_SALTW, RECIPE_KDF_SALT, kdf_sw)                                                                                                                              \
                                                                                                                                                                                           \
  RECIPE_KDF_FN (init) (kdf, RECIPE_KDF_ARG2 (RECIPE_KDF_KEYW, RECIPE_KDF_KEY, kdf_kw), RECIPE_KDF_ARG2 (RECIPE_KDF_SALTW, RECIPE_KDF_SALT, kdf_sw), RECIPE_KDF_FIRST, RECIPE_KDF_BLOCKS); \
                                                                                                                                                                                           \
  if (bad == true)                                                                                                                                                                         \
  {                                                                                                                                                                                        \
    for (u32 i = 0; i < (sizeof (kdf->out) / sizeof (kdf->out[0])); i++) kdf->out[i] = ~kdf->out[i];                                                                                       \
  }                                                                                                                                                                                        \
}

DECLSPEC RECIPE_INLINE void recipe_kdf_init (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS RECIPE_KDF_STATE *kdf, PRIVATE_AS const RECIPE_VT *w, const u32 pw_len, PRIVATE_AS const RECIPE_VT *s, const u32 salt_len)
{
  #ifdef RECIPE_SCALAR_STATE
  RECIPE_EVALS ( , _S, u32, , RECIPE_EVI, RECIPE_KDF_START)
  #else
  RECIPE_EVALS (_vector, , u32x, make_u32x, RECIPE_EVI, RECIPE_KDF_START)
  #endif
}

#define RECIPE_KDF_SLICE(I)                                                       \
{                                                                                 \
  const u32 v = RECIPE_KDF_SL##I##_V;                                             \
  const u32 w = RECIPE_KDF_SL##I##_W;                                             \
                                                                                  \
  for (u32 i = 0; i < RECIPE_KDF_SL##I##_N; i++) vb[(v * 64) + i] = raw[w + i];   \
                                                                                  \
  vl[v] = RECIPE_KDF_SL##I##_N * 4;                                               \
}

DECLSPEC RECIPE_INLINE void recipe_kdf_comp (PRIVATE_AS const recipe_state_t *st, PRIVATE_AS const RECIPE_KDF_STATE *kdf, PRIVATE_AS u32 *vb, PRIVATE_AS u32 *vl)
{
  u32 raw[16];

  RECIPE_KDF_FN (comp) (kdf, raw, RECIPE_KDF_DKLEN);

  #ifdef RECIPE_KDF_WHOLE

  u32 outs[32];
  u32 out_lens[1];

  RECIPE_FORMAT (u32, _S, RECIPE_KDF_FMT, 0, RECIPE_KDF_DKLEN)

  const u32 n = (out_lens[0] + 3) / 4;

  for (u32 i = 0; i < n; i++) vb[(RECIPE_KDF_OUT * 64) + i] = outs[i];

  vl[RECIPE_KDF_OUT] = out_lens[0];

  #endif

  #ifdef RECIPE_KDF_RAW

  for (u32 i = 0; i < 4; i++) vb[(RECIPE_KDF_OUT * 64) + i] = raw[i];

  vl[RECIPE_KDF_OUT] = 16;

  #endif

  #if RECIPE_KDF_SLICES > 0
  RECIPE_KDF_SLICE (0)
  #endif

  #if RECIPE_KDF_SLICES > 1
  RECIPE_KDF_SLICE (1)
  #endif

  #if RECIPE_KDF_SLICES > 2
  RECIPE_KDF_SLICE (2)
  #endif
}

#endif

#endif
