/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_inc_hash_md4.h"
#include "emu_inc_hash_md5.h"
#include "emu_inc_hash_sha1.h"
#include "emu_inc_hash_sha256.h"
#include "emu_inc_hash_sha512.h"
#include "emu_inc_hash_ripemd160.h"
#include "emu_inc_hash_ripemd320.h"
#include "emu_inc_hash_ripemd128.h"
#include "emu_inc_hash_md2.h"
#include "emu_inc_hash_sha0.h"
#include "emu_inc_hash_snefru.h"
#include "emu_inc_hash_ripemd256.h"
#include "emu_inc_hash_mysql323.h"
#include "emu_inc_hash_haval.h"
#include "emu_inc_hash_tiger.h"
#include "emu_inc_hash_blake2b.h"
#include "emu_inc_hash_blake2s.h"
#include "emu_inc_hash_sm3.h"
#include "emu_inc_hash_whirlpool.h"
#include "emu_inc_hash_sha3.h"

// The Whirlpool and Streebog headers each define the table lookup macros BOX and BOX_S for their own
// code, with different arguments.

#undef BOX
#undef BOX_S

#include "emu_inc_hash_streebog256.h"

#undef BOX
#undef BOX_S

#include "emu_inc_hash_streebog512.h"
#include "emu_inc_hash_gost94.h"

// The GOST R 34.11-94 header defines its step function macros under short names such as X, P and C.
// These macros are not needed in this file.

#undef _round
#undef R
#undef X
#undef P
#undef A
#undef AA
#undef C
#undef SHIFT12
#undef SHIFT16
#undef SHIFT61
#undef PASS0
#undef PASS2
#undef PASS4
#undef PASS6

#include "emu_inc_cipher_aes.h"
#include "inc_pbkdf2.h"
#include "recipe.h"

// Parse the recipe into a small tree, then convert it to steps. The tree preserves the position of
// each transform. Step generation resolves how the transforms affect each hash call or literal.

#define RECIPE_MAX_NODES  64
#define RECIPE_MAX_KIDS   8
#define RECIPE_MAX_WRAP   8

// The rounds of lowering the loop body before the final, conservative round. See
// recipe_lower_loop (). A change in what one carried variable holds can take a round to reach each
// variable that reads it. A chain of RECIPE_MAX_CARRY variables therefore needs that many rounds
// and one more to settle. Guesses only expand, so this provides a safe margin rather than a bound
// that needs to be tight.

#define RECIPE_LOOP_ROUNDS 16
#define RECIPE_MAX_SRCLIT 64
#define RECIPE_MAX_VARS   16

typedef enum recipe_node_kind
{
  RECIPE_NODE_PASS     = 1,
  RECIPE_NODE_SALT     = 2,
  RECIPE_NODE_LIT      = 3,
  RECIPE_NODE_HASH     = 4,
  RECIPE_NODE_CAT      = 5,
  RECIPE_NODE_UPPER    = 6,
  RECIPE_NODE_LOWER    = 7,
  RECIPE_NODE_HEX      = 8,
  RECIPE_NODE_CUT      = 9,
  RECIPE_NODE_UTF16    = 10,
  RECIPE_NODE_HMAC     = 11,
  RECIPE_NODE_XOP      = 12,
  RECIPE_NODE_B64      = 13,
  RECIPE_NODE_VAR      = 14,
  RECIPE_NODE_KDF      = 15,
  RECIPE_NODE_AES      = 16,
  RECIPE_NODE_EQ       = 17,
  RECIPE_NODE_LENGTH   = 18,
  RECIPE_NODE_NONEMPTY = 19,
  RECIPE_NODE_FIELD    = 20,
  RECIPE_NODE_BOP      = 21,

} recipe_node_kind_t;

// Where the parser is relative to the for loop. A recipe without a loop stays in RECIPE_PSEC_PRE.

typedef enum recipe_psec
{
  RECIPE_PSEC_PRE  = 0,
  RECIPE_PSEC_BODY = 1,
  RECIPE_PSEC_POST = 2,

} recipe_psec_t;

typedef struct recipe_node
{
  u32 kind;
  u32 pos;

  // HASH and HMAC

  u32 algo;
  u32 role;
  u32 iter;

  // CUT

  i64  cut_start;
  i64  cut_len;
  bool cut_has_len;

  // XOP, a string transform supported only for pass, salt and strings.

  recipe_xop_entry_t xop;

  // LIT

  u8  lit[RECIPE_MAX_SRCLIT];
  u32 lit_len;

  // CAT stores its elements here. Other node kinds store their argument in kids[0].

  u32 kids[RECIPE_MAX_KIDS];
  u32 kids_cnt;

  // VAR, the carried variable it reads. FIELD, the field it reads, see recipe_field_t.

  u32 slot;

  // KDF, pbkdf2 with algo, role and iter as for a hash call, and the derived key's length

  u32 dklen;

  // AES, the operation, see recipe_aes_op_t. role is the output format as for a hash call. BOP,
  // the operation, see recipe_bop_op_t, and role is RECIPE_FMT_RAW.

  u32 aop;

} recipe_node_t;

typedef struct recipe_parser
{
  recipe_prog_t *prog;

  const char *src;
  u32 pos;

  recipe_node_t nodes[RECIPE_MAX_NODES];
  u32         nodes_cnt;

  // The latest run of whitespace, so a line break can end a statement. See recipe_skip_ws ().

  u32 ws_start;
  u32 ws_end;

  // For each variable, its last assigned expression and the recipe section that assigned it. Also
  // its value before the loop, its last value in the loop body, and its carried variable index
  // plus 1, or 0 if it has no carried variable.

  char var_names[RECIPE_MAX_VARS][32];
  u32  var_ids[RECIPE_MAX_VARS];
  u32  var_sec[RECIPE_MAX_VARS];
  u32  var_pre[RECIPE_MAX_VARS];
  u32  var_body[RECIPE_MAX_VARS];
  u32  var_slot[RECIPE_MAX_VARS];
  u32  vars_cnt;

  // The for loop: where the parser is relative to it, the counter name and the iteration count. For
  // each carried variable, its variable and the position of its first read. The need_init flag
  // marks a variable that the body reads before assigning it a value.

  u32  sec;
  char counter[32];
  u32  loop_cnt;

  u32  slot_var[RECIPE_MAX_CARRY];
  u32  slot_pos[RECIPE_MAX_CARRY];
  bool slot_need_init[RECIPE_MAX_CARRY];
  u32  carry_cnt;

  // An iteration count from the hash line, see line_iter in recipe_prog_t.

  u32 line_iter;
  u32 iter_min;
  i32 iter_sub;

  // The pbkdf2 call's node and, after the call is lowered, its derived key's carried variable
  // index plus 1.

  u32 kdf;
  u32 kdf_slot;

  // The kernel assigned to the steps currently being lowered. See recipe_sec_t for the sections.

  u32 cur_sec;

  // While the loop body is lowered, the results of earlier rounds for each carried variable's
  // value from the body: its fixed length or 0, the maximum number of bytes it holds and whether
  // those bytes are ASCII. See recipe_lower_loop ().

  bool guess_ok;
  u32  guess_len[RECIPE_MAX_CARRY];
  u32  guess_most[RECIPE_MAX_CARRY];
  bool guess_ascii[RECIPE_MAX_CARRY];

  // The xor node a comparison was lowered to, or 0. See recipe_compile ().

  u32 eq_bop;

} recipe_parser_t;

// Hash families use their hx names. HMAC pads keys to the family's block size. BLAKE2 has no
// UTF-16 update functions in the kernel includes, so it cannot accept utf16le yet. The be flag
// marks families that read input as big endian words. The aes entry identifies AES steps in the
// kernel. It has no digest and therefore does not represent a hash call.

typedef struct recipe_algo_entry
{
  const char *name;
  u32 algo;
  u32 digest_len;
  u32 block_len;
  bool utf16;
  bool be;

} recipe_algo_entry_t;

static const recipe_algo_entry_t RECIPE_ALGOS[] =
{
  { "md2",         RECIPE_ALGO_MD2,        16,  16, true,  false },
  { "md4",         RECIPE_ALGO_MD4,        16,  64, true,  false },
  { "ed2k",        RECIPE_ALGO_MD4,        16,  64, true,  false },
  { "md5",         RECIPE_ALGO_MD5,        16,  64, true,  false },
  { "sha0",        RECIPE_ALGO_SHA0,       20,  64, true,  false },
  { "sha1",        RECIPE_ALGO_SHA1,       20,  64, true,  true  },
  { "aich",        RECIPE_ALGO_SHA1,       20,  64, true,  true  },
  { "sha224",      RECIPE_ALGO_SHA224,     28,  64, true,  true  },
  { "sha256",      RECIPE_ALGO_SHA256,     32,  64, true,  true  },
  { "sha384",      RECIPE_ALGO_SHA384,     48, 128, true,  true  },
  { "sha512",      RECIPE_ALGO_SHA512,     64, 128, true,  true  },
  { "rmd128",      RECIPE_ALGO_RMD128,     16,  64, true,  false },
  { "rmd160",      RECIPE_ALGO_RMD160,     20,  64, true,  false },
  { "rmd256",      RECIPE_ALGO_RMD256,     32,  64, true,  false },
  { "rmd320",      RECIPE_ALGO_RMD320,     40,  64, true,  false },
  { "blake2b512",  RECIPE_ALGO_BLAKE2B512, 64, 128, false, false },
  { "blake2b256",  RECIPE_ALGO_BLAKE2B256, 32, 128, false, false },
  { "blake2s256",  RECIPE_ALGO_BLAKE2S256, 32,  64, false, false },
  { "sm3",         RECIPE_ALGO_SM3,        32,  64, true,  true  },
  { "wrl",         RECIPE_ALGO_WRL,        64,  64, true,  true  },
  { "whirlpool",   RECIPE_ALGO_WRL,        64,  64, true,  true  },
  { "sha3_224",    RECIPE_ALGO_SHA3_224,   28, 144, true,  false },
  { "sha3_256",    RECIPE_ALGO_SHA3_256,   32, 136, true,  false },
  { "sha3_384",    RECIPE_ALGO_SHA3_384,   48, 104, true,  false },
  { "sha3_512",    RECIPE_ALGO_SHA3_512,   64,  72, true,  false },
  { "keccak224",   RECIPE_ALGO_KECCAK224,  28, 144, true,  false },
  { "keccak256",   RECIPE_ALGO_KECCAK256,  32, 136, true,  false },
  { "keccak384",   RECIPE_ALGO_KECCAK384,  48, 104, true,  false },
  { "keccak512",   RECIPE_ALGO_KECCAK512,  64,  72, true,  false },
  { "streebog_32", RECIPE_ALGO_SBOG256,    32,  64, false, true  },
  { "streebog256", RECIPE_ALGO_SBOG256,    32,  64, false, true  },
  { "streebog_64", RECIPE_ALGO_SBOG512,    64,  64, false, true  },
  { "streebog512", RECIPE_ALGO_SBOG512,    64,  64, false, true  },
  { "gost2012_32", RECIPE_ALGO_SBOG256,    32,  64, false, true  },
  { "gost2012_64", RECIPE_ALGO_SBOG512,    64,  64, false, true  },
  { "gost",        RECIPE_ALGO_GOST94,     32,  32, true,  false },
  { "gost_crypto", RECIPE_ALGO_GOST94_CP,  32,  32, true,  false },
  { "mysql3",      RECIPE_ALGO_MYSQL323,    8,  64, true,  false },
  { "tiger",       RECIPE_ALGO_TIGER,      24,  64, true,  false },
  { "tiger192",    RECIPE_ALGO_TIGER,      24,  64, true,  false },
  { "tiger128",    RECIPE_ALGO_TIGER128,   16,  64, true,  false },
  { "tiger160",    RECIPE_ALGO_TIGER160,   20,  64, true,  false },
  { "tiger2",      RECIPE_ALGO_TIGER2,     24,  64, true,  false },
  { "tth",         RECIPE_ALGO_TTH,        24,  64, true,  false },
  { "sne128",      RECIPE_ALGO_SNE128,     16,  48, true,  false },
  { "snefru128",   RECIPE_ALGO_SNE128,     16,  48, true,  false },
  { "sne256",      RECIPE_ALGO_SNE256,     32,  32, true,  false },
  { "snefru256",   RECIPE_ALGO_SNE256,     32,  32, true,  false },
  { "hav128",      RECIPE_ALGO_HAV128_3,   16, 128, true,  false },
  { "hav128_3",    RECIPE_ALGO_HAV128_3,   16, 128, true,  false },
  { "hav128_4",    RECIPE_ALGO_HAV128_4,   16, 128, true,  false },
  { "hav128_5",    RECIPE_ALGO_HAV128_5,   16, 128, true,  false },
  { "hav160_3",    RECIPE_ALGO_HAV160_3,   20, 128, true,  false },
  { "hav160_4",    RECIPE_ALGO_HAV160_4,   20, 128, true,  false },
  { "hav160_5",    RECIPE_ALGO_HAV160_5,   20, 128, true,  false },
  { "hav160",      RECIPE_ALGO_HAV160_3,   20, 128, true,  false },
  { "hav192_3",    RECIPE_ALGO_HAV192_3,   24, 128, true,  false },
  { "hav192_4",    RECIPE_ALGO_HAV192_4,   24, 128, true,  false },
  { "hav192_5",    RECIPE_ALGO_HAV192_5,   24, 128, true,  false },
  { "hav192",      RECIPE_ALGO_HAV192_3,   24, 128, true,  false },
  { "hav224_3",    RECIPE_ALGO_HAV224_3,   28, 128, true,  false },
  { "hav224_4",    RECIPE_ALGO_HAV224_4,   28, 128, true,  false },
  { "hav224_5",    RECIPE_ALGO_HAV224_5,   28, 128, true,  false },
  { "hav224",      RECIPE_ALGO_HAV224_3,   28, 128, true,  false },
  { "hav256",      RECIPE_ALGO_HAV256_3,   32, 128, true,  false },
  { "hav256_3",    RECIPE_ALGO_HAV256_3,   32, 128, true,  false },
  { "hav256_4",    RECIPE_ALGO_HAV256_4,   32, 128, true,  false },
  { "hav256_5",    RECIPE_ALGO_HAV256_5,   32, 128, true,  false },
  { "aes",         RECIPE_ALGO_AES,         0,  16, false, false },
  { "bop",         RECIPE_ALGO_BOP,         0,   0, false, false },
  { "xfrm",        RECIPE_ALGO_XFRM,        0,   0, false, false },
};

static const u32 RECIPE_ALGOS_CNT = sizeof (RECIPE_ALGOS) / sizeof (recipe_algo_entry_t);

// Kernel names for transforms on a copy. See RECIPE_XOP_* in the kernel include.

static const char *RECIPE_XOP_NAMES[] = { "NONE", "UPPER", "LOWER", "HEX", "REV", "ROTATE", "CAP", "ROT13", "PAD", "BSWAP32", "WPERM", "CUT", "FROMHEX", "FROMB64", "ZEXT16", "UTF16BE" };

static const char *RECIPE_KNOWN = "mode 4000 supports md2, md4 (also ed2k), md5, sha0, sha1 (also aich), sha224, sha256, sha384, sha512, rmd128, rmd160, rmd256, rmd320, blake2b512, blake2b256, blake2s256, sm3, wrl (also whirlpool), sha3_224, sha3_256, sha3_384, sha3_512, keccak224, keccak256, keccak384, keccak512, streebog_32 and streebog_64 (also streebog256, streebog512, gost2012_32 and gost2012_64), gost, gost_crypto, hav128_3 to hav256_5 (HAVAL with 3, 4 or 5 passes, also hav128, hav160, hav192, hav224 and hav256 for 3), tiger (also tiger192), tiger128, tiger160, tiger2, tth, sne128 and sne256 (also snefru128 and snefru256), their hmac_ forms except for tth, mysql3, pbkdf2_md5, pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512, aes_ecb_encrypt, aes_cbc_encrypt, aes_cbc_decrypt, aes_unwrap, xor, and, or, upper, lower, hex, cut, trunc, rev, rotate, cap, rot13, pad, bswap32, wperm, base64, fromhex, frombase64, utf16le, utf16be, zext16 and length";

const char *recipe_algo_name (const u32 algo)
{
  for (u32 i = 0; i < RECIPE_ALGOS_CNT; i++)
  {
    if (RECIPE_ALGOS[i].algo == algo) return RECIPE_ALGOS[i].name;
  }

  return NULL;
}

static const recipe_algo_entry_t *recipe_algo (const u32 algo)
{
  for (u32 i = 0; i < RECIPE_ALGOS_CNT; i++)
  {
    if (RECIPE_ALGOS[i].algo == algo) return &RECIPE_ALGOS[i];
  }

  return NULL;
}

static u32 recipe_digest_len (const u32 algo)
{
  const recipe_algo_entry_t *entry = recipe_algo (algo);

  const u32 r = (entry == NULL) ? 0 : entry->digest_len;

  return r;
}

// HAVAL, the 15 families of inc_hash_haval.cl: 3, 4 or 5 passes for each digest size of 4 to 8 words

// Tiger, Tiger2, their truncations and the Tiger tree hash of one leaf, the families of inc_hash_tiger.cl

static bool recipe_algo_is_tiger (const u32 algo)
{
  const bool r = ((algo >= RECIPE_ALGO_TIGER) && (algo <= RECIPE_ALGO_TIGER2)) || (algo == RECIPE_ALGO_TTH);

  return r;
}

static bool recipe_algo_is_haval (const u32 algo)
{
  const bool r = (algo >= RECIPE_ALGO_HAV128_3) && (algo <= RECIPE_ALGO_HAV256_5);

  return r;
}

// SHA-3 and Keccak, the families of inc_hash_sha3.cl

static bool recipe_algo_is_sha3 (const u32 algo)
{
  const bool r = (algo >= RECIPE_ALGO_SHA3_224) && (algo <= RECIPE_ALGO_KECCAK512);

  return r;
}

static bool recipe_fail_at (recipe_parser_t *p, const u32 pos, const char *error)
{
  if (p->prog->error == NULL)
  {
    p->prog->error     = error;
    p->prog->error_pos = pos;
  }

  return false;
}

static bool recipe_fail (recipe_parser_t *p, const char *error)
{
  return recipe_fail_at (p, p->pos, error);
}

// Whitespace includes line breaks, and a # starts a comment that runs to the end of the line.
// A line break separates statements, so the parser records the start of the latest run of
// whitespace between them. A second call at the end of that same whitespace run preserves the
// original start position.

static void recipe_skip_ws (recipe_parser_t *p)
{
  if (p->pos != p->ws_end) p->ws_start = p->pos;

  while (true)
  {
    const char c = p->src[p->pos];

    if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r'))
    {
      p->pos++;

      continue;
    }

    if (c == '#')
    {
      while ((p->src[p->pos] != 0) && (p->src[p->pos] != '\n')) p->pos++;

      continue;
    }

    break;
  }

  p->ws_end = p->pos;
}

static bool recipe_accept (recipe_parser_t *p, const char c)
{
  recipe_skip_ws (p);

  if (p->src[p->pos] != c) return false;

  p->pos++;

  return true;
}

static bool recipe_is_word (const char c)
{
  if ((c >= 'a') && (c <= 'z')) return true;
  if ((c >= 'A') && (c <= 'Z')) return true;
  if ((c >= '0') && (c <= '9')) return true;
  if (c == '_')                 return true;

  return false;
}

// Return the length of the complete word, which can exceed the number of bytes that buf can hold.

static u32 recipe_ident (recipe_parser_t *p, char *buf, const u32 buf_size)
{
  recipe_skip_ws (p);

  u32 len = 0;

  while (recipe_is_word (p->src[p->pos]) == true)
  {
    if (len < (buf_size - 1)) buf[len] = p->src[p->pos];

    len++;

    p->pos++;
  }

  buf[MIN (len, buf_size - 1)] = 0;

  return len;
}

static u32 recipe_new_node (recipe_parser_t *p, const u32 kind, const u32 pos)
{
  if (p->nodes_cnt >= RECIPE_MAX_NODES) return 0;

  const u32 idx = p->nodes_cnt;

  recipe_node_t *node = &p->nodes[idx];

  memset (node, 0, sizeof (recipe_node_t));

  node->kind = kind;
  node->pos  = pos;

  p->nodes_cnt++;

  // Index 0 is reserved to indicate failure.

  const u32 r = idx + 1;

  return r;
}

static recipe_node_t *recipe_node (recipe_parser_t *p, const u32 id)
{
  recipe_node_t *node = &p->nodes[id - 1];

  return node;
}

// Single-quoted strings preserve every byte. Double-quoted strings also support backslash
// escapes, including \xHH for a byte in hex.

static u32 recipe_parse_string (recipe_parser_t *p)
{
  const u32 start = p->pos;

  const char quote = p->src[p->pos];

  p->pos++;

  const u32 id = recipe_new_node (p, RECIPE_NODE_LIT, start);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  while (p->src[p->pos] != quote)
  {
    if (p->src[p->pos] == 0) { recipe_fail_at (p, start, "unterminated string"); return 0; }

    if (node->lit_len >= RECIPE_MAX_SRCLIT) { recipe_fail_at (p, start, "string longer than 64 bytes"); return 0; }

    u8 b = (u8) p->src[p->pos];

    if ((quote == '"') && (b == '\\'))
    {
      const char e = p->src[p->pos + 1];

      switch (e)
      {
        case '\\': b = '\\'; break;
        case '"':  b = '"';  break;
        case '\'': b = '\''; break;
        case 'n':  b = '\n'; break;
        case 'r':  b = '\r'; break;
        case 't':  b = '\t'; break;
        case '0':  b = 0;    break;
        case 'x':
          if (is_valid_hex_char ((const u8) p->src[p->pos + 2]) == false) { recipe_fail (p, "\\x needs two hex digits"); return 0; }
          if (is_valid_hex_char ((const u8) p->src[p->pos + 3]) == false) { recipe_fail (p, "\\x needs two hex digits"); return 0; }

          b = hex_to_u8 ((const u8 *) p->src + p->pos + 2);

          p->pos += 2;

          break;
        default:
          recipe_fail (p, "unknown escape, known are \\\\ \\\" \\' \\n \\r \\t \\0 and \\xHH");

          return 0;
      }

      p->pos++;
    }

    node->lit[node->lit_len] = b;

    node->lit_len++;

    p->pos++;
  }

  p->pos++;

  return id;
}

static u32 recipe_parse_expr (recipe_parser_t *p);

// Split a hash function name into its family and output suffix: md5, md5_hex, md5_bin, md5_uc or
// md5_b64. The suffix _mcf applies only to families that mode 4000 does not support.

static bool recipe_hash_name (const char *name, u32 *algo, u32 *role)
{
  for (u32 i = 0; i < RECIPE_ALGOS_CNT; i++)
  {
    if (RECIPE_ALGOS[i].digest_len == 0) continue;

    const char *base = RECIPE_ALGOS[i].name;

    const size_t base_len = strlen (base);

    if (strncmp (name, base, base_len) != 0) continue;

    const char *suffix = name + base_len;

    bool found = true;

    if      (strcmp (suffix, "")     == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_hex") == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_bin") == 0) *role = RECIPE_FMT_RAW;
    else if (strcmp (suffix, "_uc")  == 0) *role = RECIPE_FMT_HEXU;
    else if (strcmp (suffix, "_b64") == 0) *role = RECIPE_FMT_B64;
    else                                   found = false;

    if (found == false) continue;

    *algo = RECIPE_ALGOS[i].algo;

    return true;
  }

  return false;
}

static bool recipe_parse_int (recipe_parser_t *p, i64 *out)
{
  recipe_skip_ws (p);

  bool neg = false;

  if (p->src[p->pos] == '-')
  {
    neg = true;

    p->pos++;
  }

  if ((p->src[p->pos] < '0') || (p->src[p->pos] > '9')) return recipe_fail (p, "expected a number");

  i64 v = 0;

  while ((p->src[p->pos] >= '0') && (p->src[p->pos] <= '9'))
  {
    v = (v * 10) + (p->src[p->pos] - '0');

    if (v > 1000000000) return recipe_fail (p, "number too large");

    p->pos++;
  }

  *out = (neg == true) ? -v : v;

  return true;
}

// Transforms on pass, salt and strings can take arguments: rotate (x, N), cap (x), cap (x, N),
// pad (x, N) and wperm (x, w0, w1, ...). The transforms rev, rot13, bswap32, fromhex and
// frombase64 take only x.

static u32 recipe_parse_xop (recipe_parser_t *p, const u32 xop, const char *name, const u32 name_pos)
{
  if (p->src[p->pos] == '^') { recipe_fail (p, "only a hash call can take ^"); return 0; }

  if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

  const u32 arg = recipe_parse_expr (p);

  if (arg == 0) return 0;

  const u32 id = recipe_new_node (p, RECIPE_NODE_XOP, name_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->kids[0]  = arg;
  node->kids_cnt = 1;

  node->xop.op      = xop;
  node->xop.a       = 0;
  node->xop.b       = 0;
  node->xop.has_len = false;

  if (xop == RECIPE_XOP_ROTATE)
  {
    if (recipe_accept (p, ',') == false) { recipe_fail (p, "rotate needs a count"); return 0; }

    if (recipe_parse_int (p, &node->xop.a) == false) return 0;
  }
  else if (xop == RECIPE_XOP_CAP)
  {
    node->xop.a = -1;

    if (recipe_accept (p, ',') == true)
    {
      const u32 pos = p->pos;

      if (recipe_parse_int (p, &node->xop.a) == false) return 0;

      if (node->xop.a < 0) { recipe_fail_at (p, pos, "the position of cap must not be negative"); return 0; }
    }
  }
  else if (xop == RECIPE_XOP_PAD)
  {
    if (recipe_accept (p, ',') == false) { recipe_fail (p, "pad needs a length"); return 0; }

    const u32 pos = p->pos;

    if (recipe_parse_int (p, &node->xop.a) == false) return 0;

    if ((node->xop.a < 0) || (node->xop.a > RECIPE_MAX_XBYTES)) { recipe_fail_at (p, pos, "pad takes a length from 0 to 256"); return 0; }
  }
  else if (xop == RECIPE_XOP_WPERM)
  {
    if (recipe_accept (p, ',') == false) { recipe_fail (p, "wperm needs at least one word index"); return 0; }

    do
    {
      const u32 pos = p->pos;

      i64 idx = 0;

      if (recipe_parse_int (p, &idx) == false) return 0;

      if ((idx < 0) || (idx > 15)) { recipe_fail_at (p, pos, "mode 4000 takes wperm word indices from 0 to 15"); return 0; }

      if (node->xop.b >= 16) { recipe_fail_at (p, pos, "mode 4000 takes at most 16 wperm word indices"); return 0; }

      node->xop.a |= idx << (node->xop.b * 4);

      node->xop.b++;

    } while (recipe_accept (p, ',') == true);
  }
  else if (recipe_accept (p, ',') == true)
  {
    recipe_prog_t *prog = p->prog;

    snprintf (prog->error_buf, sizeof (prog->error_buf), "%s takes one argument", name);

    recipe_fail (p, prog->error_buf);

    return 0;
  }

  if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected )"); return 0; }

  return id;
}

// A call can be a hash function with optional ^N repetition, an HMAC or a transform.

// Parse pbkdf2_<family> (key, salt, iterations, length) with the output suffixes of a hash
// call. The iteration count is a fixed number or iter, the count from each hash line. The
// derived key's length is a whole number of words, allowing the comp kernel to format it in the
// same way as a digest.

static u32 recipe_parse_kdf (recipe_parser_t *p, const u32 algo, const u32 role, const u32 name_pos)
{
  if ((algo != RECIPE_ALGO_MD5) && (algo != RECIPE_ALGO_SHA1) && (algo != RECIPE_ALGO_SHA256) && (algo != RECIPE_ALGO_SHA512)) { recipe_fail_at (p, name_pos, "pbkdf2 supports md5, sha1, sha256 and sha512"); return 0; }

  if (p->src[p->pos] == '^') { recipe_fail (p, "^ applies to hash calls, not to pbkdf2"); return 0; }

  if (p->kdf != 0) { recipe_fail_at (p, name_pos, "mode 4000 supports one pbkdf2 call"); return 0; }

  if (p->loop_cnt > 0) { recipe_fail_at (p, name_pos, "a recipe can have a for loop or a pbkdf2 call, not both"); return 0; }

  if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

  const u32 key = recipe_parse_expr (p);

  if (key == 0) return 0;

  if (recipe_accept (p, ',') == false) { recipe_fail (p, "pbkdf2 takes a key, a salt, an iteration count and a length"); return 0; }

  const u32 salt = recipe_parse_expr (p);

  if (salt == 0) return 0;

  if (recipe_accept (p, ',') == false) { recipe_fail (p, "pbkdf2 takes a key, a salt, an iteration count and a length"); return 0; }

  // The self-test counts up to RECIPE_ITER_ST when the hash lines give the count.

  recipe_skip_ws (p);

  const u32 cnt_pos = p->pos;

  const char c = p->src[cnt_pos];

  const bool named = (recipe_is_word (c) == true) && ((c < '0') || (c > '9'));

  i64 cnt = RECIPE_ITER_ST;

  if (named == true)
  {
    char word[8];

    recipe_ident (p, word, sizeof (word));

    if (strcmp (word, "iter") != 0) { recipe_fail_at (p, cnt_pos, "the iteration count of pbkdf2 is a number or iter"); return 0; }

    p->line_iter = 1;
    p->iter_min  = 1;
    p->iter_sub  = 1;
  }
  else
  {
    if (recipe_parse_int (p, &cnt) == false) return 0;

    if ((cnt < 1) || (cnt > RECIPE_MAX_LOOP)) { recipe_fail_at (p, cnt_pos, "pbkdf2 runs from 1 to 10000000 iterations"); return 0; }
  }

  if (recipe_accept (p, ',') == false) { recipe_fail (p, "pbkdf2 takes a key, a salt, an iteration count and a length"); return 0; }

  recipe_skip_ws (p);

  const u32 len_pos = p->pos;

  i64 dklen = 0;

  if (recipe_parse_int (p, &dklen) == false) return 0;

  if ((dklen < 4) || (dklen > 64) || ((dklen % 4) != 0)) { recipe_fail_at (p, len_pos, "the derived key of pbkdf2 has to be 4 to 64 bytes, a multiple of 4"); return 0; }

  if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected )"); return 0; }

  const u32 id = recipe_new_node (p, RECIPE_NODE_KDF, name_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->algo     = algo;
  node->role     = role;
  node->iter     = (u32) cnt;
  node->dklen    = (u32) dklen;
  node->kids[0]  = key;
  node->kids[1]  = salt;
  node->kids_cnt = 2;

  p->kdf = id;

  return id;
}

// aes_ecb_encrypt (key, pt), aes_cbc_encrypt (key, iv, pt), aes_cbc_decrypt (key, iv, ct) and
// aes_unwrap (kek, wrapped), with the output suffixes of a hash call. The key's length picks
// AES-128, AES-192 or AES-256.

// An AES step's raw output length is its data length, minus the 8 byte check for aes_unwrap. For
// the unwrap in length (aes_unwrap (...)) > 0, the output contains only that check value.

static u32 recipe_aes_out_len (const recipe_step_t *step)
{
  u32 len = step->data_len;

  if (step->aop == RECIPE_AES_UNWRAP)   len = step->data_len - 8;
  if (step->aop == RECIPE_AES_UNWRAP_A) len = 8;

  return len;
}

static bool recipe_aes_name (const char *name, u32 *aop, u32 *role)
{
  const char *ops[]  = { "aes_ecb_encrypt", "aes_cbc_encrypt", "aes_cbc_decrypt", "aes_unwrap" };
  const u32   aops[] = { RECIPE_AES_ECB_ENC, RECIPE_AES_CBC_ENC, RECIPE_AES_CBC_DEC, RECIPE_AES_UNWRAP };

  for (u32 i = 0; i < 4; i++)
  {
    const size_t len = strlen (ops[i]);

    if (strncmp (name, ops[i], len) != 0) continue;

    const char *suffix = name + len;

    bool found = true;

    if      (strcmp (suffix, "")     == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_hex") == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_bin") == 0) *role = RECIPE_FMT_RAW;
    else if (strcmp (suffix, "_uc")  == 0) *role = RECIPE_FMT_HEXU;
    else if (strcmp (suffix, "_b64") == 0) *role = RECIPE_FMT_B64;
    else                                   found = false;

    if (found == false) continue;

    *aop = aops[i];

    return true;
  }

  return false;
}

static u32 recipe_parse_aes (recipe_parser_t *p, const u32 aop, const u32 role, const u32 name_pos)
{
  if (p->src[p->pos] == '^') { recipe_fail (p, "^ applies to hash calls, not to aes"); return 0; }

  if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

  const bool cbc = (aop == RECIPE_AES_CBC_ENC) || (aop == RECIPE_AES_CBC_DEC);

  const char *usage = "an aes call takes a key and the data, aes_cbc_ calls a key, an iv and the data";

  const u32 id = recipe_new_node (p, RECIPE_NODE_AES, name_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  const u32 args = (cbc == true) ? 3 : 2;

  u32 kids[3];

  for (u32 i = 0; i < args; i++)
  {
    if ((i > 0) && (recipe_accept (p, ',') == false)) { recipe_fail (p, usage); return 0; }

    kids[i] = recipe_parse_expr (p);

    if (kids[i] == 0) return 0;
  }

  if (recipe_accept (p, ')') == false) { recipe_fail (p, (p->src[p->pos] == ',') ? usage : "expected ) or ."); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->aop  = aop;
  node->role = role;
  node->iter = 1;

  for (u32 i = 0; i < args; i++) node->kids[i] = kids[i];

  node->kids_cnt = args;

  return id;
}

// xor (a, b), and (a, b) and or (a, b), whose result is raw bytes. See recipe_bop_op_t.

static u32 recipe_parse_bop (recipe_parser_t *p, const u32 op, const u32 name_pos)
{
  if (p->src[p->pos] == '^') { recipe_fail (p, "^ applies to hash calls, not to xor, and or or"); return 0; }

  if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

  const u32 a = recipe_parse_expr (p);

  if (a == 0) return 0;

  if (recipe_accept (p, ',') == false) { recipe_fail (p, "xor, and and or take two values"); return 0; }

  const u32 b = recipe_parse_expr (p);

  if (b == 0) return 0;

  if (recipe_accept (p, ')') == false) { recipe_fail (p, (p->src[p->pos] == ',') ? "xor, and and or take two values" : "expected ) or ."); return 0; }

  const u32 id = recipe_new_node (p, RECIPE_NODE_BOP, name_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->aop      = op;
  node->role     = RECIPE_FMT_RAW;
  node->iter     = 1;
  node->kids[0]  = a;
  node->kids[1]  = b;
  node->kids_cnt = 2;

  return id;
}

static u32 recipe_parse_call (recipe_parser_t *p, const char *name, const u32 name_pos)
{
  u32 algo = 0;
  u32 role = 0;

  if (strcmp (name, "xor") == 0) return recipe_parse_bop (p, RECIPE_BOP_XOR, name_pos);
  if (strcmp (name, "and") == 0) return recipe_parse_bop (p, RECIPE_BOP_AND, name_pos);
  if (strcmp (name, "or")  == 0) return recipe_parse_bop (p, RECIPE_BOP_OR,  name_pos);

  if ((strncmp (name, "pbkdf2_", 7) == 0) && (recipe_hash_name (name + 7, &algo, &role) == true)) return recipe_parse_kdf (p, algo, role, name_pos);

  u32 aop = 0;

  if (recipe_aes_name (name, &aop, &role) == true) return recipe_parse_aes (p, aop, role, name_pos);

  // HMAC calls, such as hmac_md5 (key, message), use the same output suffixes as hash calls.

  const bool hmac_blake2s = (strcmp (name, "hmac_blake2s") == 0);

  if (hmac_blake2s == true)
  {
    algo = RECIPE_ALGO_BLAKE2S256;
    role = RECIPE_FMT_HEX;
  }

  if ((hmac_blake2s == true) || ((strncmp (name, "hmac_", 5) == 0) && (recipe_hash_name (name + 5, &algo, &role) == true)))
  {
    if (algo == RECIPE_ALGO_MYSQL323) { recipe_fail_at (p, name_pos, "mysql3 has no block size, so it has no hmac_ form"); return 0; }

    if (algo == RECIPE_ALGO_TTH) { recipe_fail_at (p, name_pos, "tth is a tree hash, so it has no hmac_ form"); return 0; }

    if (p->src[p->pos] == '^') { recipe_fail (p, "^ applies to hash calls, not to hmac"); return 0; }

    if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

    const u32 key = recipe_parse_expr (p);

    if (key == 0) return 0;

    if (recipe_accept (p, ',') == false) { recipe_fail (p, "hmac takes a key and a message"); return 0; }

    const u32 msg = recipe_parse_expr (p);

    if (msg == 0) return 0;

    if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected ) or ."); return 0; }

    const u32 id = recipe_new_node (p, RECIPE_NODE_HMAC, name_pos);

    if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

    recipe_node_t *node = recipe_node (p, id);

    node->algo     = algo;
    node->role     = role;
    node->iter     = 1;
    node->kids[0]  = key;
    node->kids[1]  = msg;
    node->kids_cnt = 2;

    return id;
  }

  if (recipe_hash_name (name, &algo, &role) == true)
  {
    i64 iter = 1;

    if (recipe_accept (p, '^') == true)
    {
      const u32 iter_pos = p->pos;

      if (recipe_parse_int (p, &iter) == false) return 0;

      if ((iter < 1) || (iter > RECIPE_MAX_ITER)) { recipe_fail_at (p, iter_pos, "the count after ^ must be from 1 to 100000"); return 0; }
    }

    if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

    const u32 arg = recipe_parse_expr (p);

    if (arg == 0) return 0;

    if (recipe_accept (p, ',') == true) { recipe_fail (p, "a hash call takes one argument, join its parts with ."); return 0; }

    if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected ) or ."); return 0; }

    const u32 id = recipe_new_node (p, RECIPE_NODE_HASH, name_pos);

    if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

    recipe_node_t *node = recipe_node (p, id);

    node->algo     = algo;
    node->role     = role;
    node->iter     = (u32) iter;
    node->kids[0]  = arg;
    node->kids_cnt = 1;

    return id;
  }

  u32 kind = 0;

  if      (strcmp (name, "upper") == 0) kind = RECIPE_NODE_UPPER;
  else if (strcmp (name, "lower") == 0) kind = RECIPE_NODE_LOWER;
  else if (strcmp (name, "hex")   == 0) kind = RECIPE_NODE_HEX;
  else if (strcmp (name, "base64") == 0) kind = RECIPE_NODE_B64;
  else if (strcmp (name, "cut")   == 0) kind = RECIPE_NODE_CUT;
  else if (strcmp (name, "trunc") == 0) kind = RECIPE_NODE_CUT;
  else if (strcmp (name, "utf16le") == 0) kind = RECIPE_NODE_UTF16;
  else if (strcmp (name, "length") == 0) kind = RECIPE_NODE_LENGTH;

  u32 xop = 0;

  if      (strcmp (name, "rev")        == 0) xop = RECIPE_XOP_REV;
  else if (strcmp (name, "rotate")     == 0) xop = RECIPE_XOP_ROTATE;
  else if (strcmp (name, "cap")        == 0) xop = RECIPE_XOP_CAP;
  else if (strcmp (name, "rot13")      == 0) xop = RECIPE_XOP_ROT13;
  else if (strcmp (name, "pad")        == 0) xop = RECIPE_XOP_PAD;
  else if (strcmp (name, "bswap32")    == 0) xop = RECIPE_XOP_BSWAP32;
  else if (strcmp (name, "wperm")      == 0) xop = RECIPE_XOP_WPERM;
  else if (strcmp (name, "fromhex")    == 0) xop = RECIPE_XOP_FROMHEX;
  else if (strcmp (name, "frombase64") == 0) xop = RECIPE_XOP_FROMB64;
  else if (strcmp (name, "zext16")     == 0) xop = RECIPE_XOP_ZEXT16;
  else if (strcmp (name, "utf16be")    == 0) xop = RECIPE_XOP_UTF16BE;

  if (xop != 0) return recipe_parse_xop (p, xop, name, name_pos);

  if (strcmp (name, "emit") == 0) { recipe_fail_at (p, name_pos, "emit is not supported, mode 4000 compares the result of the last statement"); return 0; }

  if (kind == 0)
  {
    recipe_prog_t *prog = p->prog;

    snprintf (prog->error_buf, sizeof (prog->error_buf), "unsupported function %s, %s", name, RECIPE_KNOWN);

    recipe_fail_at (p, name_pos, prog->error_buf);

    return 0;
  }

  if (p->src[p->pos] == '^') { recipe_fail (p, "only a hash call can take ^"); return 0; }

  if (recipe_accept (p, '(') == false) { recipe_fail (p, "expected ("); return 0; }

  const u32 arg = recipe_parse_expr (p);

  if (arg == 0) return 0;

  const u32 id = recipe_new_node (p, kind, name_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->kids[0]  = arg;
  node->kids_cnt = 1;

  // Supported forms: cut (x), cut (x, start), cut (x, start, length) and trunc (x, length).

  if (kind == RECIPE_NODE_CUT)
  {
    const bool is_trunc = (strcmp (name, "trunc") == 0);

    node->cut_start   = 0;
    node->cut_len     = 0;
    node->cut_has_len = false;

    if (is_trunc == true)
    {
      if (recipe_accept (p, ',') == false) { recipe_fail (p, "trunc needs a length"); return 0; }

      if (recipe_parse_int (p, &node->cut_len) == false) return 0;

      node->cut_has_len = true;
    }
    else if (recipe_accept (p, ',') == true)
    {
      if (recipe_parse_int (p, &node->cut_start) == false) return 0;

      if (recipe_accept (p, ',') == true)
      {
        if (recipe_parse_int (p, &node->cut_len) == false) return 0;

        node->cut_has_len = true;
      }
    }

    if ((node->cut_has_len == true) && (node->cut_len < 0)) { recipe_fail (p, "the length must not be negative"); return 0; }
  }
  else if (recipe_accept (p, ',') == true)
  {
    recipe_fail (p, "takes one argument");

    return 0;
  }

  if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected ) or ."); return 0; }

  return id;
}

// A variable read before the loop, or after assignment in the same recipe section, resolves to
// its assigned expression. Inside the loop body, a variable assigned before the loop is
// carried. It contains the previous iteration's value, or its value from before the loop on the
// first iteration. After the loop, a variable assigned by the body is also carried and contains
// its final value. Read an already carried variable from that stored value instead of computing
// its expression again.

static u32 recipe_carry (recipe_parser_t *p, const u32 v, const u32 pos)
{
  if (p->var_slot[v] == 0)
  {
    if (p->carry_cnt >= RECIPE_MAX_CARRY) { recipe_fail_at (p, pos, "more than 4 variables pass through the loop"); return 0; }

    const u32 c = p->carry_cnt;

    p->slot_var[c]       = v;
    p->slot_pos[c]       = pos;
    p->slot_need_init[c] = false;
    p->var_slot[v]       = c + 1;

    p->carry_cnt++;
  }

  const u32 c = p->var_slot[v] - 1;

  if (p->sec == RECIPE_PSEC_BODY) p->slot_need_init[c] = true;

  const u32 id = recipe_new_node (p, RECIPE_NODE_VAR, pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node (p, id)->slot = c;

  return id;
}

static u32 recipe_var_ref (recipe_parser_t *p, const u32 v, const u32 pos)
{
  if (p->sec == RECIPE_PSEC_PRE) return p->var_ids[v];

  if (p->var_sec[v] == p->sec) return p->var_ids[v];

  if ((p->sec == RECIPE_PSEC_POST) && (p->var_sec[v] == RECIPE_PSEC_PRE) && (p->var_slot[v] == 0)) return p->var_ids[v];

  const u32 id = recipe_carry (p, v, pos);

  return id;
}

static u32 recipe_parse_term (recipe_parser_t *p)
{
  recipe_skip_ws (p);

  const u32 start = p->pos;

  const char c = p->src[p->pos];

  if ((c == '"') || (c == '\'')) return recipe_parse_string (p);

  if (c == '(')
  {
    p->pos++;

    const u32 id = recipe_parse_expr (p);

    if (id == 0) return 0;

    if (recipe_accept (p, ')') == false) { recipe_fail (p, "expected ) or ."); return 0; }

    return id;
  }

  if (c == '$') { recipe_fail (p, "variables have no $ in hx, write pass or salt"); return 0; }

  if (((c >= '0') && (c <= '9')) || (c == '-')) { recipe_fail (p, "a number can only be the count of cut or trunc"); return 0; }

  char name[32];

  const u32 name_len = recipe_ident (p, name, sizeof (name));

  if (name_len == 0) { recipe_fail (p, "expected a hash call, pass, salt or a string"); return 0; }

  if (name_len >= sizeof (name)) { recipe_fail_at (p, start, "a name can be at most 31 characters long"); return 0; }

  recipe_skip_ws (p);

  if ((p->src[p->pos] == '(') || (p->src[p->pos] == '^')) return recipe_parse_call (p, name, start);

  if ((p->sec != RECIPE_PSEC_PRE) && (strcmp (name, p->counter) == 0)) { recipe_fail_at (p, start, "the loop counter cannot be used yet"); return 0; }

  // A variable represents its assigned expression. Each separate use is lowered on its own, and
  // recipe_lower_hash () merges any identical hash calls produced by those separate uses.

  for (u32 v = 0; v < p->vars_cnt; v++)
  {
    if (strcmp (p->var_names[v], name) == 0) return recipe_var_ref (p, v, start);
  }

  u32 kind  = 0;
  u32 field = 0;

  if      (strcmp (name, "pass")   == 0) kind = RECIPE_NODE_PASS;
  else if (strcmp (name, "salt")   == 0) kind = RECIPE_NODE_SALT;
  else if (strcmp (name, "salt2")  == 0) kind = RECIPE_NODE_FIELD;
  else if (strcmp (name, "pepper") == 0) kind = RECIPE_NODE_FIELD;
  else if (strcmp (name, "user")   == 0) kind = RECIPE_NODE_FIELD;

  if (strcmp (name, "pepper") == 0) field = RECIPE_FIELD_PEPPER;
  if (strcmp (name, "user")   == 0) field = RECIPE_FIELD_USER;

  if (kind == 0)
  {
    if (strcmp (name, "iter") == 0)
    {
      recipe_fail_at (p, start, "iter can only be the last value of a for loop or the iteration count of pbkdf2");
    }
    else
    {
      recipe_fail_at (p, start, "unknown variable, mode 4000 has pass, salt, salt2, pepper, user and variables assigned before");
    }

    return 0;
  }

  const u32 id = recipe_new_node (p, kind, start);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node (p, id)->slot = field;

  return id;
}

// A concatenation contains one or more terms. Return a single term unchanged.

static u32 recipe_parse_expr (recipe_parser_t *p)
{
  const u32 first = recipe_parse_term (p);

  if (first == 0) return 0;

  recipe_skip_ws (p);

  if (p->src[p->pos] != '.') return first;

  const u32 id = recipe_new_node (p, RECIPE_NODE_CAT, recipe_node (p, first)->pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node (p, id)->kids[0]  = first;
  recipe_node (p, id)->kids_cnt = 1;

  while (recipe_accept (p, '.') == true)
  {
    const u32 kid = recipe_parse_term (p);

    if (kid == 0) return 0;

    recipe_node_t *node = recipe_node (p, id);

    if (node->kids_cnt >= RECIPE_MAX_KIDS) { recipe_fail (p, "more than 8 parts in one concatenation"); return 0; }

    node->kids[node->kids_cnt] = kid;

    node->kids_cnt++;
  }

  return id;
}

static bool recipe_parse_for (recipe_parser_t *p, const u32 start);

// The result can be a comparison: a == b, or length (x) > 0. lhs is the expression before it. Return
// the comparison's node, lhs itself when no comparison follows, or 0 after an error.

static u32 recipe_parse_cmp (recipe_parser_t *p, const u32 lhs)
{
  recipe_skip_ws (p);

  const u32 op_pos = p->pos;

  const char c0 = p->src[p->pos];
  const char c1 = (c0 == 0) ? 0 : p->src[p->pos + 1];

  if ((c0 == '!') && (c1 == '=')) { recipe_fail (p, "!= would match almost every candidate, mode 4000 compares with =="); return 0; }

  if ((c0 == '>') && (c1 != '=') && (recipe_node (p, lhs)->kind == RECIPE_NODE_LENGTH))
  {
    p->pos++;

    i64 v = 0;

    if (recipe_parse_int (p, &v) == false) return 0;

    if (v != 0) { recipe_fail_at (p, op_pos, "length can only be compared with > 0, as in length (aes_unwrap (kek, x)) > 0"); return 0; }

    const u32 id = recipe_new_node (p, RECIPE_NODE_NONEMPTY, op_pos);

    if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

    recipe_node_t *node = recipe_node (p, id);

    node->kids[0]  = recipe_node (p, lhs)->kids[0];
    node->kids_cnt = 1;

    return id;
  }

  if ((c0 == '<') || (c0 == '>')) { recipe_fail (p, "mode 4000 compares with ==, and length (aes_unwrap (kek, x)) with > 0"); return 0; }

  if ((c0 != '=') || (c1 != '=')) return lhs;

  p->pos += 2;

  const u32 rhs = recipe_parse_expr (p);

  if (rhs == 0) return 0;

  const u32 id = recipe_new_node (p, RECIPE_NODE_EQ, op_pos);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

  recipe_node_t *node = recipe_node (p, id);

  node->kids[0]  = lhs;
  node->kids[1]  = rhs;
  node->kids_cnt = 2;

  return id;
}

// A statement can be a variable assignment, a for loop or an expression. The final statement's
// expression is the recipe's result, so set result for an expression and clear it for other
// statements. A later assignment to a variable name replaces the earlier assignment for all
// statements that follow it.

static bool recipe_parse_stmt (recipe_parser_t *p, u32 *result)
{
  recipe_skip_ws (p);

  const u32 start = p->pos;

  char name[32];

  const u32 name_len = recipe_ident (p, name, sizeof (name));

  if (name_len >= sizeof (name)) return recipe_fail_at (p, start, "a name can be at most 31 characters long");

  if ((name_len > 0) && (strcmp (name, "for") == 0))
  {
    *result = 0;

    const bool r = recipe_parse_for (p, start);

    return r;
  }

  if ((name_len > 0) && (strcmp (name, "if") == 0)) return recipe_fail_at (p, start, "mode 4000 does not support if yet");

  recipe_skip_ws (p);

  const bool assign = (name_len > 0) && (p->src[p->pos] == '=') && (p->src[p->pos + 1] != '=');

  if (assign == false)
  {
    p->pos = start;

    const u32 expr = recipe_parse_expr (p);

    if (expr == 0) return false;

    const u32 id = recipe_parse_cmp (p, expr);

    if (id == 0) return false;

    *result = id;

    return true;
  }

  const char *reserved[] = { "pass", "salt", "salt2", "pepper", "user", "iter", "for", "to", "if", "else" };

  for (u32 i = 0; i < (sizeof (reserved) / sizeof (reserved[0])); i++)
  {
    if (strcmp (name, reserved[i]) == 0) return recipe_fail_at (p, start, "pass, salt, salt2, pepper, user, iter, for, to, if and else cannot be assigned");
  }

  p->pos++;

  const u32 id = recipe_parse_expr (p);

  if (id == 0) return false;

  recipe_skip_ws (p);

  const char c = p->src[p->pos];

  if (((c == '=') && (p->src[p->pos + 1] == '=')) || (c == '<') || (c == '>') || (c == '!')) return recipe_fail (p, "a comparison cannot be assigned, it has to be the result");

  u32 v = 0;

  while ((v < p->vars_cnt) && (strcmp (p->var_names[v], name) != 0)) v++;

  if (v == p->vars_cnt)
  {
    if (p->vars_cnt >= RECIPE_MAX_VARS) return recipe_fail_at (p, start, "more than 16 variables");

    snprintf (p->var_names[v], sizeof (p->var_names[v]), "%s", name);

    p->var_pre[v]  = 0;
    p->var_slot[v] = 0;

    p->vars_cnt++;
  }

  if ((p->sec == RECIPE_PSEC_BODY) && (strcmp (name, p->counter) == 0)) return recipe_fail_at (p, start, "the loop counter cannot be assigned");

  p->var_ids[v] = id;
  p->var_sec[v] = p->sec;

  if (p->sec == RECIPE_PSEC_PRE) p->var_pre[v] = id;

  *result = 0;

  return true;
}

// Check whether the latest run of whitespace contains a line break, which separates 2 statements.

static bool recipe_ws_newline (const recipe_parser_t *p)
{
  if (p->ws_end <= p->ws_start) return false;

  const bool r = (memchr (p->src + p->ws_start, '\n', p->ws_end - p->ws_start) != NULL);

  return r;
}

// Parse for i = first to last { statements }. Statements are separated by semicolons or line
// breaks, as at the top level. Mode 4000 supports one loop with integer bounds. Its body may only
// assign variables.

static bool recipe_parse_for (recipe_parser_t *p, const u32 start)
{
  if (p->sec != RECIPE_PSEC_PRE) return recipe_fail_at (p, start, "mode 4000 supports one for loop, not a second or a nested one");

  if (p->kdf != 0) return recipe_fail_at (p, start, "a recipe can have a for loop or a pbkdf2 call, not both");

  char name[32];

  recipe_skip_ws (p);

  const u32 name_pos = p->pos;

  const u32 name_len = recipe_ident (p, name, sizeof (name));

  if (name_len == 0) return recipe_fail (p, "expected the loop counter after for");

  if (name_len >= sizeof (name)) return recipe_fail_at (p, name_pos, "a name can be at most 31 characters long");

  if (recipe_accept (p, '=') == false) return recipe_fail (p, "expected = after the loop counter");

  i64 first = 0;

  if (recipe_parse_int (p, &first) == false) return false;

  recipe_skip_ws (p);

  const u32 to_pos = p->pos;

  char to[8];

  if ((recipe_ident (p, to, sizeof (to)) == 0) || (strcmp (to, "to") != 0)) return recipe_fail_at (p, to_pos, "expected to after the first value of the loop counter");

  // The last value can be iter, the iteration count on each hash line. The self-test counts up to
  // RECIPE_ITER_ST instead.

  recipe_skip_ws (p);

  const u32 last_pos = p->pos;

  const char c = p->src[last_pos];

  // A word that starts with a digit is a number, since words include digits.

  const bool named = (recipe_is_word (c) == true) && ((c < '0') || (c > '9'));

  char bound[8];

  i64 last = 0;

  if (named == true)
  {
    recipe_ident (p, bound, sizeof (bound));

    if (strcmp (bound, "iter") != 0) return recipe_fail_at (p, last_pos, "the last value of a loop is a number or iter");

    if ((first != 0) && (first != 1)) return recipe_fail_at (p, start, "a loop up to iter has to start at 0 or 1");

    p->line_iter = 1;
    p->iter_min  = (u32) first;
    p->iter_sub  = (i32) first - 1;

    last = RECIPE_ITER_ST;
  }
  else
  {
    if (recipe_parse_int (p, &last) == false) return false;
  }

  const i64 cnt = last - first + 1;

  if (cnt < 1)               return recipe_fail_at (p, start, "a loop has to run at least once");
  if (cnt > RECIPE_MAX_LOOP) return recipe_fail_at (p, start, "a loop can run at most 10000000 times");

  if (recipe_accept (p, '{') == false) return recipe_fail (p, "expected { to start the loop body");

  snprintf (p->counter, sizeof (p->counter), "%s", name);

  p->loop_cnt = (u32) cnt;
  p->sec      = RECIPE_PSEC_BODY;

  u32 stmts = 0;

  while (true)
  {
    recipe_skip_ws (p);

    bool sep = (stmts == 0) || (recipe_ws_newline (p) == true);

    while (p->src[p->pos] == ';')
    {
      p->pos++;

      recipe_skip_ws (p);

      sep = true;
    }

    if (p->src[p->pos] == '}')
    {
      p->pos++;

      break;
    }

    if (p->src[p->pos] == 0) return recipe_fail_at (p, start, "expected } to end the loop");

    if (sep == false) return recipe_fail (p, "expected ; or a line break between statements");

    const u32 stmt_pos = p->pos;

    u32 r = 0;

    if (recipe_parse_stmt (p, &r) == false) return false;

    if (r != 0) return recipe_fail_at (p, stmt_pos, "a statement in a loop has to assign a variable");

    stmts++;
  }

  if (stmts == 0) return recipe_fail_at (p, start, "the loop body is empty");

  for (u32 v = 0; v < p->vars_cnt; v++)
  {
    p->var_body[v] = (p->var_sec[v] == RECIPE_PSEC_BODY) ? p->var_ids[v] : 0;
  }

  p->sec = RECIPE_PSEC_POST;

  return true;
}

// The transforms between a hash call or a literal and its caller, outermost first, as the lowering
// walks down to them. They apply innermost first.

typedef struct recipe_wrap
{
  u32 ids[RECIPE_MAX_WRAP];
  u32 cnt;

} recipe_wrap_t;

// Resolve cut (start, length) for len bytes using hx's bounds: clamp start to either end, and
// limit length to the remaining bytes.

static void recipe_resolve_cut (const recipe_node_t *cut, const u32 len, u32 *start_out, u32 *len_out)
{
  i64 s = cut->cut_start;

  if (s < 0) s += (i64) len;
  if (s < 0) s  = 0;

  if (s > (i64) len) s = (i64) len;

  i64 l = (i64) len - s;

  if (cut->cut_has_len == true) l = MIN (l, cut->cut_len);

  *start_out = (u32) s;
  *len_out   = (u32) l;
}

// Decode hex or base64 using the same rules as recipe_salt_decode () in the kernel include,
// including bytes outside the alphabet. This makes the host self-test hash the same bytes as the
// device. Up to 2 trailing = characters are base64 padding. The out buffer holds RECIPE_MAX_XBYTES
// bytes and is zeroed beyond the decoded result.

static u32 recipe_decode (const u32 dec, const u8 *in, const u32 len, u8 *out)
{
  memset (out, 0, RECIPE_MAX_XBYTES);

  if (dec == RECIPE_DEC_HEX)
  {
    const u32 n = MIN (len / 2, RECIPE_MAX_XBYTES);

    for (u32 i = 0; i < n; i++)
    {
      const u32 c0 = in[(i * 2) + 0];
      const u32 c1 = in[(i * 2) + 1];

      const u32 h0 = ((c0 & 15) + (((c0 >> 6) & 1) * 9)) & 15;
      const u32 h1 = ((c1 & 15) + (((c1 >> 6) & 1) * 9)) & 15;

      out[i] = (u8) ((h0 << 4) | h1);
    }

    return n;
  }

  u32 m = len;

  if ((m > 0) && (in[m - 1] == '=')) m--;
  if ((m > 0) && (in[m - 1] == '=')) m--;

  const u32 n = MIN ((m * 6) / 8, RECIPE_MAX_XBYTES);

  for (u32 g = 0; g < ((m + 3) / 4); g++)
  {
    u32 v[4];

    for (u32 j = 0; j < 4; j++)
    {
      const u32 at = (g * 4) + j;

      const u32 c = (at < m) ? in[at] : 0;

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

    if ((at + 0) < n) out[at + 0] = (u8) b0;
    if ((at + 1) < n) out[at + 1] = (u8) b1;
    if ((at + 2) < n) out[at + 2] = (u8) b2;
  }

  return n;
}

// Standard base64 with = padding, as RECIPE_FORMAT in the kernel include writes it.

static u32 recipe_b64_len (const u32 len)
{
  const u32 r = ((len + 2) / 3) * 4;

  return r;
}

static u32 recipe_b64_encode (const u8 *in, const u32 len, u8 *out)
{
  const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for (u32 g = 0; g < ((len + 2) / 3); g++)
  {
    const u32 at = g * 3;

    const u32 b0 = in[at];
    const u32 b1 = ((at + 1) < len) ? in[at + 1] : 0;
    const u32 b2 = ((at + 2) < len) ? in[at + 2] : 0;

    out[(g * 4) + 0] = tbl[(b0 >> 2) & 63];
    out[(g * 4) + 1] = tbl[((b0 << 4) | (b1 >> 4)) & 63];
    out[(g * 4) + 2] = ((at + 1) < len) ? tbl[((b1 << 2) | (b2 >> 6)) & 63] : '=';
    out[(g * 4) + 3] = ((at + 2) < len) ? tbl[(b2 >> 0) & 63] : '=';
  }

  const u32 r = recipe_b64_len (len);

  return r;
}

// A string is decoded at compile time, so a malformed string is reported as an error. A malformed
// salt instead decodes to bytes that cannot match.

static bool recipe_decode_valid (const u32 dec, const u8 *in, const u32 len)
{
  if (dec == RECIPE_DEC_HEX)
  {
    if ((len % 2) != 0) return false;

    for (u32 i = 0; i < len; i++)
    {
      if (is_valid_hex_char (in[i]) == false) return false;
    }

    return true;
  }

  u32 m = len;

  if ((m > 0) && (in[m - 1] == '=')) m--;
  if ((m > 0) && (in[m - 1] == '=')) m--;

  if ((m % 4) == 1) return false;

  for (u32 i = 0; i < m; i++)
  {
    const u8 c = in[i];

    if ((c >= 'A') && (c <= 'Z')) continue;
    if ((c >= 'a') && (c <= 'z')) continue;
    if ((c >= '0') && (c <= '9')) continue;

    if ((c == '+') || (c == '/')) continue;

    return false;
  }

  return true;
}

// Apply byte transforms to string literals at compile time and to copies during the host self-test.
// The buffer holds RECIPE_MAX_XBYTES bytes and remains zeroed past len. Return the new length.

// Decode the UTF-8 in buffer as UTF-16BE, using the same strict rules as utf8_to_utf32 () in
// mdxfind, which hx follows. These require a lead byte from 0xc2 to 0xf4 and continuation bytes,
// with no overlong form, no surrogate and no code point above U+10FFFF. Code points from U+10000
// onward become surrogate pairs. Input that is not well-formed produces 0 bytes. The out buffer
// holds RECIPE_MAX_XBYTES, which 2 * len never exceeds. The recipe_utf16be () function in the
// kernel include uses the same decoder.

static u32 recipe_utf8_to_utf16be (const u8 *in, const u32 len, u8 *out)
{
  u32 i = 0;
  u32 o = 0;

  while (i < len)
  {
    const u32 c = in[i];

    u32 cl = 0;

    if      (c < 0x80)                   cl = 1;
    else if ((c >= 0xc2) && (c <= 0xdf)) cl = 2;
    else if ((c >= 0xe0) && (c <= 0xef)) cl = 3;
    else if ((c >= 0xf0) && (c <= 0xf4)) cl = 4;

    if (cl == 0) return 0;

    if ((i + cl) > len) return 0;

    u32 cp = (cl == 1) ? c : (c & (0x7f >> cl));

    for (u32 k = 1; k < cl; k++)
    {
      const u32 cc = in[i + k];

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

      out[o + 0] = (u8) (hi >> 8);
      out[o + 1] = (u8) (hi & 255);
      out[o + 2] = (u8) (lo >> 8);
      out[o + 3] = (u8) (lo & 255);

      o += 4;
    }
    else
    {
      out[o + 0] = (u8) (cp >> 8);
      out[o + 1] = (u8) (cp & 255);

      o += 2;
    }
  }

  return o;
}

static u32 recipe_xop_apply (const recipe_xop_entry_t *op, u8 *buf, const u32 len)
{
  u8 tmp[RECIPE_MAX_XBYTES];

  memset (tmp, 0, sizeof (tmp));

  u32 r = len;

  if ((op->op == RECIPE_XOP_UPPER) || (op->op == RECIPE_XOP_LOWER) || (op->op == RECIPE_XOP_ROT13))
  {
    for (u32 i = 0; i < len; i++)
    {
      const u8 b = buf[i];

      if (op->op == RECIPE_XOP_UPPER)
      {
        if ((b >= 'a') && (b <= 'z')) buf[i] = b - 32;
      }
      else if (op->op == RECIPE_XOP_LOWER)
      {
        if ((b >= 'A') && (b <= 'Z')) buf[i] = b + 32;
      }
      else
      {
        if (((b >= 'a') && (b <= 'm')) || ((b >= 'A') && (b <= 'M'))) buf[i] = b + 13;
        if (((b >= 'n') && (b <= 'z')) || ((b >= 'N') && (b <= 'Z'))) buf[i] = b - 13;
      }
    }
  }
  else if (op->op == RECIPE_XOP_HEX)
  {
    const u32 n = MIN (len, RECIPE_MAX_XBYTES / 2);

    for (u32 i = 0; i < n; i++)
    {
      tmp[(i * 2) + 0] = "0123456789abcdef"[(buf[i] >> 4) & 15];
      tmp[(i * 2) + 1] = "0123456789abcdef"[(buf[i] >> 0) & 15];
    }

    memcpy (buf, tmp, RECIPE_MAX_XBYTES);

    r = n * 2;
  }
  else if (op->op == RECIPE_XOP_ZEXT16)
  {
    const u32 n = MIN (len, RECIPE_MAX_XBYTES / 2);

    for (u32 i = 0; i < n; i++)
    {
      tmp[(i * 2) + 0] = buf[i];
      tmp[(i * 2) + 1] = 0;
    }

    memcpy (buf, tmp, RECIPE_MAX_XBYTES);

    r = n * 2;
  }
  else if (op->op == RECIPE_XOP_UTF16BE)
  {
    r = recipe_utf8_to_utf16be (buf, MIN (len, RECIPE_MAX_XBYTES / 2), tmp);

    // Clear what the decoder wrote before it stopped, so the copy stays zeroed past its length.

    if (r == 0) memset (tmp, 0, sizeof (tmp));

    memcpy (buf, tmp, RECIPE_MAX_XBYTES);
  }
  else if (op->op == RECIPE_XOP_REV)
  {
    for (u32 i = 0; i < len; i++) tmp[i] = buf[len - 1 - i];

    memcpy (buf, tmp, RECIPE_MAX_XBYTES);
  }
  else if (op->op == RECIPE_XOP_ROTATE)
  {
    // Move the last a bytes to the front. A negative a moves the first -a bytes to the end.

    if (len > 0)
    {
      const i64 n = (((op->a % (i64) len) + (i64) len) % (i64) len);

      for (u32 i = 0; i < len; i++) tmp[(i + n) % len] = buf[i];

      memcpy (buf, tmp, RECIPE_MAX_XBYTES);
    }
  }
  else if (op->op == RECIPE_XOP_CAP)
  {
    if (op->a < 0)
    {
      for (u32 i = 0; i < len; i++)
      {
        if ((buf[i] < 'a') || (buf[i] > 'z')) continue;

        buf[i] -= 32;

        break;
      }
    }
    else if ((op->a < (i64) len) && (buf[op->a] >= 'a') && (buf[op->a] <= 'z'))
    {
      buf[op->a] -= 32;
    }
  }
  else if (op->op == RECIPE_XOP_PAD)
  {
    // Pad with zero bytes or truncate to the requested length.

    const u32 n = (u32) op->a;

    if (len > n) memset (buf + n, 0, RECIPE_MAX_XBYTES - n);

    r = n;
  }
  else if (op->op == RECIPE_XOP_BSWAP32)
  {
    // Reverse each complete group of 4 bytes and leave trailing bytes unchanged.

    for (u32 i = 0; (i + 4) <= len; i += 4)
    {
      const u8 b0 = buf[i + 0];
      const u8 b1 = buf[i + 1];

      buf[i + 0] = buf[i + 3];
      buf[i + 1] = buf[i + 2];
      buf[i + 2] = b1;
      buf[i + 3] = b0;
    }
  }
  else if (op->op == RECIPE_XOP_WPERM)
  {
    const u32 cnt = (u32) op->b;

    for (u32 j = 0; j < cnt; j++)
    {
      const u32 w = (u32) ((op->a >> (j * 4)) & 15);

      memcpy (tmp + (j * 4), buf + (w * 4), 4);
    }

    memcpy (buf, tmp, RECIPE_MAX_XBYTES);

    r = cnt * 4;
  }
  else if (op->op == RECIPE_XOP_CUT)
  {
    i64 st = op->a;

    if (st < 0) st += (i64) len;
    if (st < 0) st  = 0;

    if (st > (i64) len) st = (i64) len;

    i64 l = (i64) len - st;

    if (op->has_len == true) l = MIN (l, op->b);

    memcpy (tmp, buf + st, (size_t) l);
    memcpy (buf, tmp, RECIPE_MAX_XBYTES);

    r = (u32) l;
  }

  return r;
}

u32 recipe_xform_apply (const recipe_xform_t *xform, u8 *buf, const u32 len)
{
  u32 r = len;

  for (u32 i = 0; i < xform->ops_cnt; i++) r = recipe_xop_apply (&xform->ops[i], buf, r);

  return r;
}

// Compute the transformed length to determine the maximum password and salt sizes a copy can hold.

static u32 recipe_xop_len (const recipe_xop_entry_t *op, const u32 len)
{
  u8 buf[RECIPE_MAX_XBYTES];

  memset (buf, 'a', sizeof (buf));

  if (len < RECIPE_MAX_XBYTES) memset (buf + len, 0, RECIPE_MAX_XBYTES - len);

  const u32 r = recipe_xop_apply (op, buf, len);

  return r;
}

// The length after a list of transforms, innermost first.

static u32 recipe_xops_len (const recipe_xop_entry_t *ops, const u32 ops_cnt, const u32 len)
{
  u32 r = len;

  for (u32 i = 0; i < ops_cnt; i++) r = recipe_xop_len (&ops[i], r);

  return r;
}

// A wrapping transform as an entry of a transformed copy. This covers the XOP nodes and the upper,
// lower, hex and cut nodes, which have node kinds of their own.

static bool recipe_xop_of (const recipe_node_t *t, recipe_xop_entry_t *op)
{
  memset (op, 0, sizeof (recipe_xop_entry_t));

  if (t->kind == RECIPE_NODE_XOP)   { *op = t->xop; return true; }
  if (t->kind == RECIPE_NODE_UPPER) { op->op = RECIPE_XOP_UPPER; return true; }
  if (t->kind == RECIPE_NODE_LOWER) { op->op = RECIPE_XOP_LOWER; return true; }
  if (t->kind == RECIPE_NODE_HEX)   { op->op = RECIPE_XOP_HEX;   return true; }

  if (t->kind == RECIPE_NODE_CUT)
  {
    op->op      = RECIPE_XOP_CUT;
    op->a       = t->cut_start;
    op->b       = t->cut_len;
    op->has_len = t->cut_has_len;

    return true;
  }

  return false;
}

static bool recipe_xform_eq (const recipe_xform_t *a, const recipe_xform_t *b)
{
  if (a->src     != b->src)     return false;
  if (a->ops_cnt != b->ops_cnt) return false;

  for (u32 i = 0; i < a->ops_cnt; i++)
  {
    if (a->ops[i].op      != b->ops[i].op)      return false;
    if (a->ops[i].a       != b->ops[i].a)       return false;
    if (a->ops[i].b       != b->ops[i].b)       return false;
    if (a->ops[i].has_len != b->ops[i].has_len) return false;
  }

  return true;
}

// Check that a copy of len bytes fits RECIPE_MAX_XBYTES after every transform. Only hex, zext16 and
// utf16be grow it with its length, each to at most twice its input. pad sets a length of its own,
// which the parser keeps within RECIPE_MAX_XBYTES.

static bool recipe_xform_fits (const recipe_xform_t *xform, const u32 len)
{
  u32 r = len;

  for (u32 i = 0; i < xform->ops_cnt; i++)
  {
    const u32 o = xform->ops[i].op;

    if (((o == RECIPE_XOP_HEX) || (o == RECIPE_XOP_ZEXT16) || (o == RECIPE_XOP_UTF16BE)) && (r > (RECIPE_MAX_XBYTES / 2))) return false;

    r = recipe_xop_len (&xform->ops[i], r);
  }

  return true;
}

// Produce a string's bytes after applying its transforms from innermost to outermost. The buf
// buffer holds RECIPE_MAX_XBYTES.

static bool recipe_lit_bytes (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, u8 *buf, u32 *len_out)
{
  u32 len = node->lit_len;

  memset (buf, 0, RECIPE_MAX_XBYTES);
  memcpy (buf, node->lit, len);

  for (u32 w = wrap->cnt; w > 0; w--)
  {
    const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

    if (t->kind == RECIPE_NODE_UTF16)
    {
      // For ASCII, UTF-16LE adds a zero byte after each input byte.

      if ((len * 2) > RECIPE_MAX_XBYTES) return recipe_fail_at (p, node->pos, "string too long for utf16le");

      for (u32 i = 0; i < len; i++)
      {
        if (buf[i] >= 0x80) return recipe_fail_at (p, t->pos, "mode 4000 takes utf16le of ASCII strings only");
      }

      for (u32 i = len; i > 0; i--)
      {
        const u8 b = buf[i - 1];

        buf[((i - 1) * 2) + 0] = b;
        buf[((i - 1) * 2) + 1] = 0;
      }

      len *= 2;

      continue;
    }

    if (t->kind == RECIPE_NODE_B64)
    {
      if (recipe_b64_len (len) > RECIPE_MAX_XBYTES) return recipe_fail_at (p, node->pos, "string too long for base64");

      u8 tmp[RECIPE_MAX_XBYTES];

      memset (tmp, 0, sizeof (tmp));

      len = recipe_b64_encode (buf, len, tmp);

      memcpy (buf, tmp, RECIPE_MAX_XBYTES);

      continue;
    }

    if ((t->kind == RECIPE_NODE_XOP) && ((t->xop.op == RECIPE_XOP_FROMHEX) || (t->xop.op == RECIPE_XOP_FROMB64)))
    {
      const u32 dec = (t->xop.op == RECIPE_XOP_FROMHEX) ? RECIPE_DEC_HEX : RECIPE_DEC_B64;

      if (recipe_decode_valid (dec, buf, len) == false) return recipe_fail_at (p, t->pos, (dec == RECIPE_DEC_HEX) ? "fromhex needs a string of hex digit pairs" : "frombase64 needs a base64 string");

      u8 tmp[RECIPE_MAX_XBYTES];

      len = recipe_decode (dec, buf, len, tmp);

      memcpy (buf, tmp, RECIPE_MAX_XBYTES);

      continue;
    }

    recipe_xop_entry_t op;

    recipe_xop_of (t, &op);

    if ((op.op == RECIPE_XOP_HEX) && ((len * 2) > RECIPE_MAX_XBYTES)) return recipe_fail_at (p, node->pos, "string too long for hex");

    if (((op.op == RECIPE_XOP_ZEXT16) || (op.op == RECIPE_XOP_UTF16BE)) && ((len * 2) > RECIPE_MAX_XBYTES)) return recipe_fail_at (p, node->pos, "string too long for zext16 or utf16be");

    const u32 in_len = len;

    len = recipe_xop_apply (&op, buf, len);

    if ((op.op == RECIPE_XOP_UTF16BE) && (in_len > 0) && (len == 0)) return recipe_fail_at (p, t->pos, "utf16be needs a string of well-formed UTF-8");
  }

  *len_out = len;

  return true;
}

static bool recipe_lower_lit (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, recipe_step_t *step)
{
  u8  buf[RECIPE_MAX_XBYTES];
  u32 len = 0;

  if (recipe_lit_bytes (p, node, wrap, buf, &len) == false) return false;

  if (len > RECIPE_MAX_LIT) return recipe_fail_at (p, node->pos, "string longer than 16 bytes");

  recipe_prog_t *prog = p->prog;

  if (prog->lits_cnt >= RECIPE_MAX_LITS) return recipe_fail_at (p, node->pos, "more than 4 strings");

  const u32 lit_idx = prog->lits_cnt;

  memcpy (prog->lits[lit_idx], buf, len);

  prog->lit_lens[lit_idx] = len;

  prog->lits_cnt++;

  if (step->parts_cnt >= RECIPE_MAX_PARTS) return recipe_fail_at (p, node->pos, "more than 8 parts in one hash call");

  step->parts[step->parts_cnt].kind = RECIPE_PART_LIT;
  step->parts[step->parts_cnt].idx  = lit_idx;

  step->parts_cnt++;

  return true;
}

static bool recipe_lower_hash (recipe_parser_t *p, const u32 id, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out);
static bool recipe_lower_kdf  (recipe_parser_t *p, const u32 id, u32 *slot);
static bool recipe_kdf_slice  (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, u32 *slot);
static bool recipe_lower_one  (recipe_parser_t *p, const u32 id, recipe_part_t *out, const char *what);

static bool recipe_kdf_slice_ok   (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap);
static bool recipe_lower_var_xfrm (recipe_parser_t *p, const u32 c, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out);

// A value's length when it is the same for every candidate, salt and iteration, or 0. Unlike
// recipe_part_len (), a copy such as cut (pass, 0, 16) has no fixed length here: AES pads it to
// 16 bytes, but the other steps take it as it is.

static u32  recipe_part_fixed (const recipe_parser_t *p, const recipe_part_t *part);
static u32  recipe_part_most  (const recipe_parser_t *p, const recipe_part_t *part);
static void recipe_var_shape  (const recipe_parser_t *p, const u32 c, u32 *len_out, u32 *most_out, bool *ascii_out);

// Append expression parts to the current step. The transforms upper, lower, hex, rot13, zext16 and
// utf16le apply to each element of a concatenation. Other transforms accept only a single element.

static bool recipe_lower_parts (recipe_parser_t *p, const u32 id, const recipe_wrap_t *wrap, recipe_step_t *step)
{
  const recipe_node_t *node = recipe_node (p, id);

  if (node->kind == RECIPE_NODE_LENGTH) return recipe_fail_at (p, node->pos, "length can only be compared, as in length (aes_unwrap (kek, x)) > 0");

  if (node->kind == RECIPE_NODE_CAT)
  {
    for (u32 w = 0; w < wrap->cnt; w++)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w]);

      if (t->kind == RECIPE_NODE_CUT) return recipe_fail_at (p, t->pos, "cut and trunc of a concatenation are not supported");

      if (t->kind == RECIPE_NODE_B64) return recipe_fail_at (p, t->pos, "base64 of a concatenation is not supported");

      if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op != RECIPE_XOP_ROT13) && (t->xop.op != RECIPE_XOP_ZEXT16)) return recipe_fail_at (p, t->pos, "rev, rotate, cap, pad, bswap32, wperm, fromhex, frombase64 and utf16be of a concatenation are not supported");
    }

    for (u32 i = 0; i < node->kids_cnt; i++)
    {
      if (recipe_lower_parts (p, node->kids[i], wrap, step) == false) return false;
    }

    return true;
  }

  if ((node->kind == RECIPE_NODE_UPPER) || (node->kind == RECIPE_NODE_LOWER) || (node->kind == RECIPE_NODE_HEX) || (node->kind == RECIPE_NODE_CUT) || (node->kind == RECIPE_NODE_UTF16) || (node->kind == RECIPE_NODE_XOP) || (node->kind == RECIPE_NODE_B64))
  {
    if (wrap->cnt >= RECIPE_MAX_WRAP) return recipe_fail_at (p, node->pos, "too many nested transforms");

    recipe_wrap_t inner = *wrap;

    inner.ids[inner.cnt] = id;

    inner.cnt++;

    return recipe_lower_parts (p, node->kids[0], &inner, step);
  }

  if (node->kind == RECIPE_NODE_LIT) return recipe_lower_lit (p, node, wrap, step);

  if (step->parts_cnt >= RECIPE_MAX_PARTS) return recipe_fail_at (p, node->pos, "more than 8 parts in one hash call");

  recipe_part_t *part = &step->parts[step->parts_cnt];

  // Read a pbkdf2 call from the carried variable containing its derived key. For a cut of its _bin
  // form that starts and ends on word boundaries, read the carried variable assigned to that slice.
  // Other transforms read the whole key in a step of their own.

  if (node->kind == RECIPE_NODE_KDF)
  {
    u32 slot = 0;

    if (recipe_lower_kdf (p, id, &slot) == false) return false;

    if ((wrap->cnt > 0) && (recipe_kdf_slice_ok (p, node, wrap) == false))
    {
      p->prog->kdf_whole = 1;

      u32  k    = 0;
      bool wide = false;

      if (recipe_lower_var_xfrm (p, slot, wrap, &k, &wide) == false) return false;

      part->kind = RECIPE_PART_STEP;
      part->idx  = k;
      part->wide = (wide == true) ? 1 : 0;

      step->parts_cnt++;

      return true;
    }

    if ((wrap->cnt > 0) && (recipe_kdf_slice (p, node, wrap, &slot) == false)) return false;

    if (wrap->cnt == 0) p->prog->kdf_whole = 1;

    part->kind = RECIPE_PART_VAR;
    part->idx  = slot;
    part->wide = 0;

    step->parts_cnt++;

    return true;
  }

  // Read a carried variable using its stored output format. See RECIPE_PART_VAR for the part type.
  // Alternatively, transform that value in a step of its own.

  if (node->kind == RECIPE_NODE_VAR)
  {
    if (wrap->cnt > 0)
    {
      u32  k    = 0;
      bool wide = false;

      if (recipe_lower_var_xfrm (p, node->slot, wrap, &k, &wide) == false) return false;

      part->kind = RECIPE_PART_STEP;
      part->idx  = k;
      part->wide = (wide == true) ? 1 : 0;

      step->parts_cnt++;

      return true;
    }

    part->kind = RECIPE_PART_VAR;
    part->idx  = node->slot;
    part->wide = 0;

    step->parts_cnt++;

    return true;
  }

  // Transforming pass, salt or a field creates a copy. See recipe_xform_t. The kernel decodes UTF-8
  // while hashing the copy, so utf16le must be the outermost transform.

  if ((node->kind == RECIPE_NODE_PASS) || (node->kind == RECIPE_NODE_SALT) || (node->kind == RECIPE_NODE_FIELD))
  {
    u32 src = (node->kind == RECIPE_NODE_PASS) ? RECIPE_PART_PASS : RECIPE_PART_SALT;

    if (node->kind == RECIPE_NODE_FIELD) src = RECIPE_PART_SALT2 + node->slot;

    if (node->kind == RECIPE_NODE_SALT)  p->prog->salt_read = 1;
    if (node->kind == RECIPE_NODE_FIELD) p->prog->fields   |= 1u << node->slot;

    // Applying fromhex or frombase64 to the salt itself produces the decoded salt. Other transforms
    // can then use that decoded value as their source.

    u32 inner = wrap->cnt;

    for (u32 w = 0; w < wrap->cnt; w++)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w]);

      if (t->kind == RECIPE_NODE_B64) return recipe_fail_at (p, t->pos, "base64 of pass, salt or a field is not supported yet, it takes a _bin hash call or a string");

      if (t->kind != RECIPE_NODE_XOP) continue;

      if ((t->xop.op != RECIPE_XOP_FROMHEX) && (t->xop.op != RECIPE_XOP_FROMB64)) continue;

      if (src != RECIPE_PART_SALT) return recipe_fail_at (p, t->pos, "fromhex and frombase64 apply to salt and strings, not to pass, salt2, pepper or user yet");

      if (w != (wrap->cnt - 1)) return recipe_fail_at (p, t->pos, "fromhex and frombase64 have to apply to salt itself");

      const u32 dec = (t->xop.op == RECIPE_XOP_FROMHEX) ? RECIPE_DEC_HEX : RECIPE_DEC_B64;

      recipe_prog_t *prog = p->prog;

      if ((prog->salt_dec != RECIPE_DEC_NONE) && (prog->salt_dec != dec)) return recipe_fail_at (p, t->pos, "mode 4000 decodes the salt one way per recipe");

      prog->salt_dec = dec;

      src   = RECIPE_PART_SALTD;
      inner = w;
    }

    bool wide  = false;
    u32  outer = 0;

    if ((wrap->cnt > 0) && (recipe_node (p, wrap->ids[0])->kind == RECIPE_NODE_UTF16))
    {
      if (src == RECIPE_PART_SALTD) return recipe_fail_at (p, recipe_node (p, wrap->ids[0])->pos, "utf16le of a decoded salt is not supported");

      wide  = true;
      outer = 1;
    }

    part->wide = (wide == true) ? 1 : 0;

    if (inner == outer)
    {
      part->kind = src;
      part->idx  = 0;

      step->parts_cnt++;

      return true;
    }

    recipe_xform_t xf;

    memset (&xf, 0, sizeof (xf));

    xf.src = src;

    for (u32 w = inner; w > outer; w--)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

      if (t->kind == RECIPE_NODE_UTF16) return recipe_fail_at (p, t->pos, "utf16le of pass or salt has to be the outermost transform");

      if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op == RECIPE_XOP_UTF16BE) && (src == RECIPE_PART_SALTD)) return recipe_fail_at (p, t->pos, "utf16be of a decoded salt is not supported");

      if (xf.ops_cnt >= RECIPE_MAX_XOPS) return recipe_fail_at (p, t->pos, "more than 4 transforms of pass or salt");

      recipe_xop_of (t, &xf.ops[xf.ops_cnt]);

      xf.ops_cnt++;
    }

    // Reuse an existing copy with the same transforms.

    recipe_prog_t *prog = p->prog;

    u32 idx = 0;

    while ((idx < prog->xforms_cnt) && (recipe_xform_eq (&prog->xforms[idx], &xf) == false)) idx++;

    if (idx == prog->xforms_cnt)
    {
      if (prog->xforms_cnt >= RECIPE_MAX_XFORMS) return recipe_fail_at (p, node->pos, "more than 4 transformed copies of pass and salt");

      prog->xforms[idx] = xf;

      prog->xforms_cnt++;
    }

    part->kind = RECIPE_PART_XFORM;
    part->idx  = idx;

    step->parts_cnt++;

    return true;
  }

  u32  step_idx = 0;
  bool wide     = false;

  if (recipe_lower_hash (p, id, wrap, &step_idx, &wide) == false) return false;

  part->kind = RECIPE_PART_STEP;
  part->idx  = step_idx;
  part->wide = (wide == true) ? 1 : 0;

  step->parts_cnt++;

  return true;
}

// A hash call or HMAC becomes one step. Convert its parts first so nested calls receive lower step
// numbers and run earlier. An HMAC key must be a single part. Transforms around the call determine
// the output format and slice. For utf16le of hex output, keep hex in this step and set wide_out
// so the caller inserts zero bytes while hashing it.

// Return a transformed copy's length when it does not depend on the source length, as with a cut
// that specifies a length or a pad as the last transform. The length is the same for sources of 255
// and 256 bytes. Return 0 otherwise.

static u32 recipe_xform_fixed_len (const recipe_xform_t *xform)
{
  u32 a = RECIPE_MAX_XBYTES - 0;
  u32 b = RECIPE_MAX_XBYTES - 1;

  for (u32 i = 0; i < xform->ops_cnt; i++)
  {
    a = recipe_xop_len (&xform->ops[i], a);
    b = recipe_xop_len (&xform->ops[i], b);
  }

  const u32 r = (a == b) ? a : 0;

  return r;
}

// The length of the derived key of pbkdf2 as its carried variable holds it.

static u32 recipe_kdf_text_len (const recipe_prog_t *prog)
{
  u32 len = prog->kdf_dklen * 2;

  if (prog->kdf_fmt == RECIPE_FMT_RAW) len = prog->kdf_dklen;
  if (prog->kdf_fmt == RECIPE_FMT_B64) len = recipe_b64_len (prog->kdf_dklen);

  return len;
}

// Return a part's length when it is fixed for every candidate and salt. This includes a string,
// hash output, a pbkdf2 derived key or a cut of that key, a transformed copy such as
// cut (fromhex (salt), 16, 32), or a variable carried through a loop that contains any of these
// values. Return 0 when the part's length is not fixed.

static u32 recipe_part_len (const recipe_parser_t *p, const recipe_part_t *part)
{
  const recipe_prog_t *prog = p->prog;

  u32 len = 0;

  if (part->kind == RECIPE_PART_LIT)   len = prog->lit_lens[part->idx];
  if (part->kind == RECIPE_PART_STEP)  len = prog->steps[part->idx].cut_len;
  if (part->kind == RECIPE_PART_XFORM) len = recipe_xform_fixed_len (&prog->xforms[part->idx]);

  if ((part->kind == RECIPE_PART_VAR) && (p->kdf_slot == (part->idx + 1))) len = recipe_kdf_text_len (prog);

  for (u32 i = 0; i < prog->kdf_slices_cnt; i++)
  {
    if ((part->kind == RECIPE_PART_VAR) && (prog->kdf_slice_var[i] == part->idx)) len = prog->kdf_slice_len[i];
  }

  // After the loop, which runs at least once, a carried variable holds the step the body assigns
  // it, or the value it started with when the body only reads it.

  if ((part->kind == RECIPE_PART_VAR) && (p->kdf_slot == 0) && (part->idx < prog->carry_cnt))
  {
    const u32 c = part->idx;

    if      (prog->carry_has_loop[c] == 1) len = recipe_part_len (p, &prog->carry_loop[c]);
    else if (prog->carry_has_init[c] == 1) len = recipe_part_len (p, &prog->carry_init[c]);
  }

  if (part->wide == 1) len = 0;

  return len;
}

// An AES call runs in the comp kernel, which stores the AES tables. It therefore requires a pbkdf2
// call or a loop before it. Its key, IV and data have fixed lengths, so the kernel and host use the
// same layout regardless of the salt's contents.

static bool recipe_lower_aes (recipe_parser_t *p, const recipe_node_t *node, recipe_step_t *step)
{
  if (p->cur_sec == RECIPE_SEC_MAIN) return recipe_fail_at (p, node->pos, "an aes call needs a pbkdf2 call or a for loop in the recipe, mode 4000 runs it in the slow kernels");

  if (p->cur_sec != RECIPE_SEC_COMP) return recipe_fail_at (p, node->pos, "an aes call cannot be inside a loop or feed pbkdf2 yet");

  step->aop = node->aop;

  const u32 key_pos = recipe_node (p, node->kids[0])->pos;

  if (recipe_lower_one (p, node->kids[0], &step->key, "the key of an aes call") == false) return false;

  step->key_len = recipe_part_len (p, &step->key);

  if ((step->key_len != 16) && (step->key_len != 24) && (step->key_len != 32)) return recipe_fail_at (p, key_pos, "the key of an aes call needs a fixed length of 16, 24 or 32 bytes, such as a _bin hash call or pbkdf2");

  const bool cbc = (step->aop == RECIPE_AES_CBC_ENC) || (step->aop == RECIPE_AES_CBC_DEC);

  if (cbc == true)
  {
    const u32 iv_pos = recipe_node (p, node->kids[1])->pos;

    if (recipe_lower_one (p, node->kids[1], &step->iv, "the iv of an aes call") == false) return false;

    if (recipe_part_len (p, &step->iv) != 16) return recipe_fail_at (p, iv_pos, "the iv of an aes call needs a fixed length of 16 bytes, such as cut(fromhex(salt), 0, 16)");
  }

  const u32 data_id = node->kids[node->kids_cnt - 1];

  const u32 data_pos = recipe_node (p, data_id)->pos;

  const recipe_wrap_t none = { .cnt = 0 };

  if (recipe_lower_parts (p, data_id, &none, step) == false) return false;

  u32 total = 0;

  for (u32 i = 0; i < step->parts_cnt; i++)
  {
    if (step->parts[i].wide == 1) return recipe_fail_at (p, data_pos, "the data of an aes call cannot be utf16le yet");

    const u32 len = recipe_part_len (p, &step->parts[i]);

    if (len == 0) return recipe_fail_at (p, data_pos, "each part of the data of an aes call needs a fixed length, such as a _bin hash call, a string or cut(fromhex(salt), 16, 32)");

    step->part_lens[i] = len;

    total += len;
  }

  step->data_len = total;

  if ((step->aop == RECIPE_AES_UNWRAP) || (step->aop == RECIPE_AES_UNWRAP_A))
  {
    if ((total < 16) || (total > (RECIPE_MAX_AES + 8)) || ((total % 8) != 0)) return recipe_fail_at (p, data_pos, "aes_unwrap takes 16 to 72 bytes, a multiple of 8");
  }
  else
  {
    if ((total < 16) || (total > RECIPE_MAX_AES) || ((total % 16) != 0)) return recipe_fail_at (p, data_pos, "the data of an aes call has to be 16 to 64 bytes, a multiple of 16");
  }

  return true;
}

// Return the maximum number of bytes a step's output can hold. This is its length when
// fixed. Otherwise, it is the bound of an xor, and or or call or of transforms, expressed in
// the step's output format.

static u32 recipe_step_most (const recipe_step_t *step)
{
  if (step->cut_len > 0) return step->cut_len;

  u32 most = step->data_len;

  if ((step->fmt == RECIPE_FMT_HEX) || (step->fmt == RECIPE_FMT_HEXU)) most = step->data_len * 2;

  if (step->fmt == RECIPE_FMT_B64) most = recipe_b64_len (step->data_len);

  return most;
}

// Whether the output of a BOP step is cut, rather than kept whole at the length it has at run time.
// A carried variable among its values can change that length after the first iteration.

static bool recipe_bop_cuts (const recipe_step_t *step)
{
  if (step->cut_len == 0) return false;

  const u32 n = MAX (step->part_lens[0], step->part_lens[1]);

  u32 full = n;

  if ((step->fmt == RECIPE_FMT_HEX) || (step->fmt == RECIPE_FMT_HEXU)) full = n * 2;

  if (step->fmt == RECIPE_FMT_B64) full = recipe_b64_len (n);

  const bool r = (step->cut_start != 0) || (step->cut_len != full);

  return r;
}

// Add a step, or reuse an earlier one that is the same. A hash call can appear more than once, for
// example through a variable, and it gives the same output each time.

static bool recipe_add_step (recipe_parser_t *p, const recipe_step_t *step, const u32 pos, u32 *step_out)
{
  recipe_prog_t *prog = p->prog;

  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    if (memcmp (&prog->steps[k], step, sizeof (recipe_step_t)) != 0) continue;

    *step_out = k;

    return true;
  }

  if (prog->steps_cnt >= RECIPE_MAX_STEPS) return recipe_fail_at (p, pos, "more than 8 hash and aes calls");

  prog->steps[prog->steps_cnt] = *step;

  *step_out = prog->steps_cnt;

  prog->steps_cnt++;

  return true;
}

// An xor, and or or call combines two single values of up to RECIPE_MAX_BOP bytes. Pass, salt, a
// field or a copy of one can vary in length, and the module limits their lengths so that they fit,
// see recipe_bop_limit (). A result has a fixed length when both values do, which a cut of it and
// a comparison of it need.

static bool recipe_lower_bop (recipe_parser_t *p, const recipe_node_t *node, recipe_step_t *step)
{
  step->aop = node->aop;

  const bool eq = (p->eq_bop != 0) && (recipe_node (p, p->eq_bop) == node);

  u32 most = 0;

  for (u32 i = 0; i < 2; i++)
  {
    const u32 pos = recipe_node (p, node->kids[i])->pos;

    if (recipe_lower_one (p, node->kids[i], &step->parts[i], (eq == true) ? "a side of ==" : "a value of xor, and or or") == false) return false;

    const recipe_part_t *part = &step->parts[i];

    const u32 len = recipe_part_fixed (p, part);

    // The limits for pass, the salt, fields and their copies ensure that they fit. See
    // recipe_bop_limit (). A step output or a carried variable is bounded by what it can hold
    // instead, see recipe_part_most ().

    u32 bound = (len == 0) ? RECIPE_MAX_BOP : len;

    if ((len == 0) && ((part->kind == RECIPE_PART_STEP) || (part->kind == RECIPE_PART_VAR))) bound = recipe_part_most (p, part);

    if (bound > RECIPE_MAX_BOP) return recipe_fail_at (p, pos, (eq == true) ? "== compares values of up to 64 bytes" : "xor, and and or take values of up to 64 bytes");

    step->part_lens[i] = len;

    most = MAX (most, bound);
  }

  step->parts_cnt = 2;
  step->data_len  = most;

  return true;
}

// Transforms of a hash output, such as rev (md5 (pass)) or pad (md5_bin (pass), 32), require a step
// of their own. So do encodings that cannot be expressed by the output format, such as
// hex (md5 (pass)), and transforms of a variable carried through a loop or of a pbkdf2 key. The
// step copies its source part src. This is either a step output after the wraps inside the first
// such wrap, or a carried variable. It applies the cnt outer wraps of wrap as the transforms of a
// copy. The src_len value is the source's fixed length or 0. The src_most value is the maximum
// number of bytes it holds, and src_ascii indicates whether its bytes are ASCII. A final hex, upper
// or lower of hex, or base64 wrap becomes the step's output format instead. This allows a
// transformed value to be the result. As for a hash call, utf16le can only be the outermost wrap.

static bool recipe_lower_xfrm (recipe_parser_t *p, const recipe_wrap_t *wrap, const u32 cnt, const recipe_part_t *src, const u32 src_len, const u32 src_most, const bool src_ascii, u32 *step_out, bool *wide_out)
{
  const recipe_node_t *list[RECIPE_MAX_WRAP];

  for (u32 i = 0; i < cnt; i++) list[i] = recipe_node (p, wrap->ids[cnt - 1 - i]);

  recipe_step_t step;

  memset (&step, 0, sizeof (step));

  step.sec       = p->cur_sec;
  step.kind      = RECIPE_KIND_XFRM;
  step.algo      = RECIPE_ALGO_XFRM;
  step.chain_fmt = RECIPE_FMT_RAW;
  step.fmt       = RECIPE_FMT_RAW;
  step.iter      = 1;

  step.parts[0].kind = src->kind;
  step.parts[0].idx  = src->idx;

  step.parts_cnt = 1;

  u32 n = cnt;

  bool wide = false;

  if ((n > 0) && (list[n - 1]->kind == RECIPE_NODE_UTF16))
  {
    wide = true;

    n--;
  }

  const u32 last = (n > 0) ? list[n - 1]->kind : 0;

  if (last == RECIPE_NODE_B64)
  {
    step.fmt = RECIPE_FMT_B64;

    n--;
  }
  else if (((last == RECIPE_NODE_UPPER) || (last == RECIPE_NODE_LOWER)) && (n > 1) && (list[n - 2]->kind == RECIPE_NODE_HEX))
  {
    step.fmt = (last == RECIPE_NODE_UPPER) ? RECIPE_FMT_HEXU : RECIPE_FMT_HEX;

    n -= 2;
  }
  else if (last == RECIPE_NODE_HEX)
  {
    step.fmt = RECIPE_FMT_HEX;

    n--;
  }

  // Raw bytes need not be ASCII. The transforms keep bytes as they are, except hex, whose output is
  // ASCII.

  bool ascii = src_ascii;

  for (u32 i = 0; i < n; i++)
  {
    const recipe_node_t *t = list[i];

    if (t->kind == RECIPE_NODE_UTF16) return recipe_fail_at (p, t->pos, "utf16le of a transformed value has to be the outermost transform");

    if (t->kind == RECIPE_NODE_B64) return recipe_fail_at (p, t->pos, "base64 of a value that is not a whole _bin output has to be the outermost transform");

    if ((t->kind == RECIPE_NODE_XOP) && ((t->xop.op == RECIPE_XOP_FROMHEX) || (t->xop.op == RECIPE_XOP_FROMB64))) return recipe_fail_at (p, t->pos, "fromhex and frombase64 of a transformed value are not supported");

    if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op == RECIPE_XOP_UTF16BE) && (ascii == false)) return recipe_fail_at (p, t->pos, "utf16be of raw bytes, or of a variable that can hold them, is not supported");

    if (t->kind == RECIPE_NODE_HEX) ascii = true;

    if (step.xops_cnt >= RECIPE_MAX_XOPS) return recipe_fail_at (p, t->pos, "more than 4 transforms of a hash output or variable");

    recipe_xop_of (t, &step.xops[step.xops_cnt]);

    step.xops_cnt++;
  }

  if ((wide == true) && (step.fmt == RECIPE_FMT_RAW) && (ascii == false)) return recipe_fail_at (p, list[cnt - 1]->pos, "utf16le of raw bytes is not supported");

  // The length is fixed when the source has a fixed length or when the final transform imposes one,
  // as pad does. The kernel and host still use the length produced by the transforms at run time.
  // See RECIPE_STEP_XFRM for that behavior.

  const u32 most = recipe_xops_len (step.xops, step.xops_cnt, src_most);

  u32 fixed = (src_len > 0) ? most : 0;

  if (recipe_xops_len (step.xops, step.xops_cnt, 0) == most) fixed = most;

  const u32 cap = (step.fmt == RECIPE_FMT_RAW) ? 128 : RECIPE_MAX_BOP;

  if (most > cap) return recipe_fail_at (p, list[0]->pos, "a transformed hash output or variable can have up to 128 bytes, or 64 bytes before hex or base64");

  u32 len = fixed;

  if ((step.fmt == RECIPE_FMT_HEX) || (step.fmt == RECIPE_FMT_HEXU)) len = fixed * 2;

  if (step.fmt == RECIPE_FMT_B64) len = (fixed > 0) ? recipe_b64_len (fixed) : 0;

  step.data_len  = most;
  step.cut_start = 0;
  step.cut_len   = len;

  *wide_out = wide;

  const bool rc = recipe_add_step (p, &step, list[0]->pos, step_out);

  return rc;
}

// Determine the maximum number of bytes a value can hold and whether they are ASCII. The value can
// initialize a carried variable or be assigned to it: a string, a step output, or pass, the salt, a
// field or a copy of one.

static u32 recipe_part_most (const recipe_parser_t *p, const recipe_part_t *part)
{
  const u32 len = recipe_part_fixed (p, part);

  if (len > 0) return len;

  if (part->kind == RECIPE_PART_STEP) return recipe_step_most (&p->prog->steps[part->idx]);

  if (part->kind == RECIPE_PART_XFORM)
  {
    const recipe_xform_t *xform = &p->prog->xforms[part->idx];

    const u32 r = recipe_xops_len (xform->ops, xform->ops_cnt, RECIPE_MAX_XBYTES);

    return r;
  }

  if (part->kind == RECIPE_PART_VAR)
  {
    u32  fixed = 0;
    u32  most  = 0;
    bool ascii = false;

    recipe_var_shape (p, part->idx, &fixed, &most, &ascii);

    return most;
  }

  return RECIPE_MAX_XBYTES;
}

static bool recipe_part_ascii (const recipe_parser_t *p, const recipe_part_t *part)
{
  const recipe_prog_t *prog = p->prog;

  if (part->kind == RECIPE_PART_STEP)
  {
    const bool r = (prog->steps[part->idx].fmt != RECIPE_FMT_RAW);

    return r;
  }

  if (part->kind != RECIPE_PART_LIT) return false;

  for (u32 i = 0; i < prog->lit_lens[part->idx]; i++)
  {
    if (prog->lits[part->idx][i] >= 0x80) return false;
  }

  return true;
}

// Describe carried variable c: its fixed length or 0, the maximum number of bytes and whether
// they are ASCII. The derived key of pbkdf2 and its slices have fixed lengths. A variable
// carried through the loop contains its value from before the loop during the first
// iteration. Later iterations use its value from the body, so its shape inside the loop must
// cover both values. After the loop, it contains the value from the body. That value can
// still be unknown while the body is lowered. The guesses from recipe_lower_loop () are used
// in its place until it is determined.

static void recipe_var_shape (const recipe_parser_t *p, const u32 c, u32 *len_out, u32 *most_out, bool *ascii_out)
{
  const recipe_prog_t *prog = p->prog;

  if (p->kdf_slot == (c + 1))
  {
    const u32 len = recipe_kdf_text_len (prog);

    *len_out   = len;
    *most_out  = len;
    *ascii_out = (prog->kdf_fmt != RECIPE_FMT_RAW);

    return;
  }

  for (u32 i = 0; i < prog->kdf_slices_cnt; i++)
  {
    if (prog->kdf_slice_var[i] != c) continue;

    *len_out   = prog->kdf_slice_len[i];
    *most_out  = prog->kdf_slice_len[i];
    *ascii_out = false;

    return;
  }

  // The values the variable can hold here, each described by its fixed length, maximum number
  // of bytes and ASCII flag.

  u32  lens[2];
  u32  mosts[2];
  bool asciis[2];
  u32  cnt = 0;

  const bool in_loop = (p->cur_sec == RECIPE_SEC_LOOP);

  if ((prog->carry_has_init[c] == 1) && ((in_loop == true) || (prog->carry_has_loop[c] == 0)))
  {
    lens[cnt]   = recipe_part_fixed (p, &prog->carry_init[c]);
    mosts[cnt]  = recipe_part_most  (p, &prog->carry_init[c]);
    asciis[cnt] = recipe_part_ascii (p, &prog->carry_init[c]);

    cnt++;
  }

  if (prog->carry_has_loop[c] == 1)
  {
    lens[cnt]   = recipe_part_fixed (p, &prog->carry_loop[c]);
    mosts[cnt]  = recipe_part_most  (p, &prog->carry_loop[c]);
    asciis[cnt] = recipe_part_ascii (p, &prog->carry_loop[c]);

    cnt++;
  }
  else if ((p->var_body[p->slot_var[c]] != 0) && (p->guess_ok == true))
  {
    lens[cnt]   = p->guess_len[c];
    mosts[cnt]  = p->guess_most[c];
    asciis[cnt] = p->guess_ascii[c];

    cnt++;
  }

  u32  len   = (cnt > 0) ? lens[0] : 0;
  u32  most  = 0;
  bool ascii = (cnt > 0);

  for (u32 i = 0; i < cnt; i++)
  {
    if (lens[i] != len) len = 0;

    most = MAX (most, mosts[i]);

    if (asciis[i] == false) ascii = false;
  }

  *len_out   = len;
  *most_out  = most;
  *ascii_out = ascii;
}

static u32 recipe_part_fixed (const recipe_parser_t *p, const recipe_part_t *part)
{
  if (part->kind == RECIPE_PART_XFORM)
  {
    const recipe_xform_t *xform = &p->prog->xforms[part->idx];

    const u32 a = recipe_xops_len (xform->ops, xform->ops_cnt, 0);
    const u32 b = recipe_xops_len (xform->ops, xform->ops_cnt, RECIPE_MAX_XBYTES);

    const u32 r = (a == b) ? a : 0;

    return r;
  }

  if (part->kind == RECIPE_PART_VAR)
  {
    u32  len   = 0;
    u32  most  = 0;
    bool ascii = false;

    recipe_var_shape (p, part->idx, &len, &most, &ascii);

    return len;
  }

  const u32 r = recipe_part_len (p, part);

  return r;
}

// Transforms of carried variable c, a variable carried through the loop or the derived key of
// pbkdf2, see recipe_lower_xfrm ().

static bool recipe_lower_var_xfrm (recipe_parser_t *p, const u32 c, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out)
{
  u32  len   = 0;
  u32  most  = 0;
  bool ascii = false;

  recipe_var_shape (p, c, &len, &most, &ascii);

  const recipe_part_t src = { .kind = RECIPE_PART_VAR, .idx = c, .wide = 0 };

  const bool rc = recipe_lower_xfrm (p, wrap, wrap->cnt, &src, len, most, ascii, step_out, wide_out);

  return rc;
}

static bool recipe_lower_hash (recipe_parser_t *p, const u32 id, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out)
{
  const recipe_node_t *node = recipe_node (p, id);

  recipe_step_t step;

  memset (&step, 0, sizeof (step));

  step.sec       = p->cur_sec;
  step.kind      = RECIPE_KIND_HASH;
  step.algo      = node->algo;
  step.chain_fmt = node->role;
  step.iter      = node->iter;

  if (node->kind == RECIPE_NODE_HMAC) step.kind = RECIPE_KIND_HMAC;

  if (node->kind == RECIPE_NODE_AES)
  {
    step.kind = RECIPE_KIND_AES;
    step.algo = RECIPE_ALGO_AES;
  }

  if (node->kind == RECIPE_NODE_BOP)
  {
    step.kind = RECIPE_KIND_BOP;
    step.algo = RECIPE_ALGO_BOP;
  }

  const recipe_wrap_t none = { .cnt = 0 };

  // An AES call's raw output has the same length as its data, minus the 8 byte check for
  // aes_unwrap. When returning only the check value, the output contains those 8 bytes.

  u32 digest_len = recipe_digest_len (node->algo);

  // An xor, and or or call with a value of no fixed length produces an output whose length is
  // determined by the kernel only per candidate or per salt.

  bool bop_var = false;

  if (step.kind == RECIPE_KIND_AES)
  {
    if (recipe_lower_aes (p, node, &step) == false) return false;

    digest_len = recipe_aes_out_len (&step);
  }
  else if (step.kind == RECIPE_KIND_BOP)
  {
    if (recipe_lower_bop (p, node, &step) == false) return false;

    bop_var = (step.part_lens[0] == 0) || (step.part_lens[1] == 0);

    digest_len = (bop_var == true) ? step.data_len : MAX (step.part_lens[0], step.part_lens[1]);
  }
  else if (step.kind == RECIPE_KIND_HMAC)
  {
    recipe_step_t key;

    memset (&key, 0, sizeof (key));

    if (recipe_lower_parts (p, node->kids[0], &none, &key) == false) return false;

    const u32 key_pos = recipe_node (p, node->kids[0])->pos;

    if (key.parts_cnt != 1) return recipe_fail_at (p, key_pos, "the key of an hmac has to be a single part, such as pass, salt, a string or a hash call");

    if (key.parts[0].wide == 1) return recipe_fail_at (p, key_pos, "an hmac key cannot be utf16le yet");

    step.key = key.parts[0];

    if (recipe_lower_parts (p, node->kids[1], &none, &step) == false) return false;
  }
  else
  {
    if (recipe_lower_parts (p, node->kids[0], &none, &step) == false) return false;
  }

  if ((step.kind != RECIPE_KIND_AES) && (step.kind != RECIPE_KIND_BOP) && (recipe_algo (node->algo)->utf16 == false))
  {
    for (u32 i = 0; i < step.parts_cnt; i++)
    {
      if (step.parts[i].wide == 1) return recipe_fail_at (p, node->pos, "utf16le cannot feed blake2 or streebog yet");
    }
  }

  // The kernel moves a step's output a word at a time. A cut performed by the step must
  // therefore start at a multiple of 4 bytes. If a cut would start elsewhere, a second lowering
  // round stops at the innermost cut. That cut and its outer wraps then become the transforms of
  // a separate step, as below.

  u32  fmt   = node->role;
  u32  start = 0;
  u32  len   = 0;
  bool wide  = false;

  // The wraps outside the first transform, applied by recipe_lower_xfrm (), and the innermost cut.
  // Both are the wrap index plus 1.

  u32 rest      = 0;
  u32 inner_cut = 0;
  u32 stop      = 0;

  for (u32 attempt = 0; attempt < 2; attempt++)
  {
    fmt   = node->role;
    start = 0;
    len   = (fmt == RECIPE_FMT_RAW) ? digest_len : (digest_len * 2);
    wide  = false;
    rest  = 0;

    if (fmt == RECIPE_FMT_B64) len = recipe_b64_len (digest_len);

    for (u32 w = wrap->cnt; w > 0; w--)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

      if (t->kind == RECIPE_NODE_CUT)
      {
        if (bop_var == true) return recipe_fail_at (p, t->pos, "a cut of xor, and or or needs two values of fixed length");

        if (w == stop)
        {
          rest = w;

          break;
        }

        if (inner_cut == 0) inner_cut = w;

        u32 s = 0;
        u32 l = 0;

        recipe_resolve_cut (t, len, &s, &l);

        start += s;
        len    = l;
      }
      else if (t->kind == RECIPE_NODE_B64)
      {
        // A cut of the digest is not a cut of its base64, so base64 of anything but the whole raw
        // digest is a transform, see below.

        if ((fmt != RECIPE_FMT_RAW) || (start != 0) || (len != digest_len))
        {
          rest = w;

          break;
        }

        fmt = RECIPE_FMT_B64;
        len = recipe_b64_len (digest_len);
      }
      else if (t->kind == RECIPE_NODE_HEX)
      {
        if (fmt != RECIPE_FMT_RAW)
        {
          rest = w;

          break;
        }

        fmt    = RECIPE_FMT_HEX;
        start *= 2;
        len   *= 2;
      }
      else if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op == RECIPE_XOP_FROMHEX))
      {
        // fromhex of hex output gives the raw digest bytes.

        if (fmt == RECIPE_FMT_RAW) return recipe_fail_at (p, t->pos, "fromhex takes a hex hash call, not a _bin one");

        if (fmt == RECIPE_FMT_B64) return recipe_fail_at (p, t->pos, "fromhex of base64 output is not supported");

        if (wide == true) return recipe_fail_at (p, t->pos, "fromhex of utf16le is not supported");

        if (((start % 2) != 0) || ((len % 2) != 0)) return recipe_fail_at (p, t->pos, "fromhex needs a cut that keeps whole hex pairs");

        fmt    = RECIPE_FMT_RAW;
        start /= 2;
        len   /= 2;
      }
      else if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op == RECIPE_XOP_FROMB64))
      {
        return recipe_fail_at (p, t->pos, "frombase64 of a hash output is not supported, the output is hex");
      }
      else if (t->kind == RECIPE_NODE_XOP)
      {
        // rev, pad and the other transforms of a copy apply to the current step output in a step of
        // their own. See recipe_lower_xfrm (). The same holds for the encodings above that cannot
        // change the output format, such as hex of a hex string.

        rest = w;

        break;
      }
      else if (t->kind == RECIPE_NODE_UTF16)
      {
        if (fmt == RECIPE_FMT_RAW) return recipe_fail_at (p, t->pos, "utf16le of raw bytes is not supported");

        if (wide == true) return recipe_fail_at (p, t->pos, "utf16le of utf16le is not supported");

        wide   = true;
        start *= 2;
        len   *= 2;
      }
      else
      {
        if ((fmt == RECIPE_FMT_RAW) || (fmt == RECIPE_FMT_B64))
        {
          rest = w;

          break;
        }

        fmt = (t->kind == RECIPE_NODE_UPPER) ? RECIPE_FMT_HEXU : RECIPE_FMT_HEX;
      }
    }

    // A UTF-16LE slice must preserve whole characters to map back to the hex output.

    if (wide == true)
    {
      if (((start % 2) != 0) || ((len % 2) != 0)) return recipe_fail_at (p, node->pos, "a cut of utf16le output has to keep whole characters");

      start /= 2;
      len   /= 2;
    }

    if ((start % 4) == 0) break;

    stop = inner_cut;
  }

  if (bop_var == true) len = 0;

  step.fmt       = fmt;
  step.cut_start = start;
  step.cut_len   = len;

  u32 k = 0;

  if (recipe_add_step (p, &step, node->pos, &k) == false) return false;

  if (rest == 0)
  {
    *step_out = k;
    *wide_out = wide;

    return true;
  }

  if (wide == true) return recipe_fail_at (p, recipe_node (p, wrap->ids[rest - 1])->pos, "a transform of utf16le output is not supported, utf16le has to be the outermost transform");

  const recipe_step_t *from = &p->prog->steps[k];

  const recipe_part_t src = { .kind = RECIPE_PART_STEP, .idx = k, .wide = 0 };

  const bool rc = recipe_lower_xfrm (p, wrap, rest, &src, from->cut_len, recipe_step_most (from), (from->fmt != RECIPE_FMT_RAW), step_out, wide_out);

  return rc;
}

// Whether a part kind is one of the fields from the hash line, salt2, pepper and user.

static bool recipe_is_field (const u32 kind)
{
  const bool r = (kind == RECIPE_PART_SALT2) || (kind == RECIPE_PART_PEPPER) || (kind == RECIPE_PART_USER);

  return r;
}

// Return the length of a transformed copy whose source contains len bytes.

static u32 recipe_xform_out_len (const recipe_xform_t *xform, const u32 len)
{
  const u32 r = recipe_xops_len (xform->ops, xform->ops_cnt, len);

  return r;
}

// Each input value of xor, and or or can hold up to RECIPE_MAX_BOP bytes. Limit the length of pass,
// the salt or a field when it is such an input value, or when its transformed copy is used as one.

static void recipe_bop_limit (recipe_prog_t *prog, const recipe_part_t *part)
{
  u32 src = part->kind;
  u32 len = RECIPE_MAX_BOP;

  if (part->kind == RECIPE_PART_XFORM)
  {
    const recipe_xform_t *xform = &prog->xforms[part->idx];

    src = xform->src;
    len = RECIPE_MAX_XBYTES;

    while ((len > 0) && (recipe_xform_out_len (xform, len) > RECIPE_MAX_BOP)) len--;
  }

  if (src == RECIPE_PART_PASS) prog->pw_max   = MIN (prog->pw_max,   len);
  if (src == RECIPE_PART_SALT) prog->salt_max = MIN (prog->salt_max, len);

  if (recipe_is_field (src) == true) prog->field_max = MIN (prog->field_max, len);

  if (src == RECIPE_PART_SALTD) prog->salt_max = MIN (prog->salt_max, (prog->salt_dec == RECIPE_DEC_HEX) ? (len * 2) : ((len * 4) / 3));
}

// A part depends on the candidate if it is pass, a transformed copy of pass, a carried variable, or
// the output of a step that depends on pass.

static bool recipe_part_dep_on (const recipe_prog_t *prog, const recipe_part_t *part, const bool *dep)
{
  if (part->kind == RECIPE_PART_PASS) return true;
  if (part->kind == RECIPE_PART_VAR)  return true;

  if ((part->kind == RECIPE_PART_XFORM) && (prog->xforms[part->idx].src == RECIPE_PART_PASS)) return true;

  if ((part->kind == RECIPE_PART_STEP) && (dep[part->idx] == true)) return true;

  return false;
}

// A step depends on the candidate if one of its parts does: pass, a copy of it, a carried variable
// or the output of a step that does. An HMAC also depends on it through its key, and an AES step
// always does, see below. Other steps use only the salt, the fields and strings.

static void recipe_deps (const recipe_prog_t *prog, bool *dep)
{
  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    const recipe_step_t *step = &prog->steps[k];

    bool d = false;

    for (u32 i = 0; i < step->parts_cnt; i++)
    {
      const recipe_part_t *part = &step->parts[i];

      if (recipe_part_dep_on (prog, part, dep) == true) d = true;
    }

    if (step->kind == RECIPE_KIND_HMAC)
    {
      if (recipe_part_dep_on (prog, &step->key, dep) == true) d = true;
    }

    // An AES step runs per candidate in the comp kernel, the only one with the tables.

    if (step->kind == RECIPE_KIND_AES) d = true;

    dep[k] = d;
  }
}

static bool recipe_part_is_pass (const recipe_prog_t *prog, const recipe_part_t *part)
{
  if (part->kind == RECIPE_PART_PASS) return true;

  if ((part->kind == RECIPE_PART_XFORM) && (prog->xforms[part->idx].src == RECIPE_PART_PASS)) return true;

  return false;
}

// Whether pass or a transformed copy of it appears anywhere in the recipe: in the parts of a step,
// as an HMAC or AES key or an IV, as the value a carried variable starts from, or as the key or salt
// of pbkdf2. A loop replaces a carried variable with a hash call only, a step of its own.

static bool recipe_uses_pass (const recipe_prog_t *prog)
{
  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    const recipe_step_t *step = &prog->steps[k];

    for (u32 i = 0; i < step->parts_cnt; i++)
    {
      if (recipe_part_is_pass (prog, &step->parts[i]) == true) return true;
    }

    if ((step->kind == RECIPE_KIND_HMAC) && (recipe_part_is_pass (prog, &step->key) == true)) return true;

    if (step->kind == RECIPE_KIND_AES)
    {
      if (recipe_part_is_pass (prog, &step->key) == true) return true;
      if (recipe_part_is_pass (prog, &step->iv)  == true) return true;
    }
  }

  for (u32 c = 0; c < prog->carry_cnt; c++)
  {
    if (prog->carry_has_init[c] == 0) continue;

    if (recipe_part_is_pass (prog, &prog->carry_init[c]) == true) return true;
  }

  if (prog->kdf_blocks > 0)
  {
    if (recipe_part_is_pass (prog, &prog->kdf_key)  == true) return true;
    if (recipe_part_is_pass (prog, &prog->kdf_salt) == true) return true;
  }

  return false;
}

// A carried variable holds a single value: a hash call, pass, salt, a string or a transformed copy.
// The what argument identifies that value in an error message.

static bool recipe_lower_one (recipe_parser_t *p, const u32 id, recipe_part_t *out, const char *what)
{
  recipe_prog_t *prog = p->prog;

  recipe_step_t tmp;

  memset (&tmp, 0, sizeof (tmp));

  const recipe_wrap_t none = { .cnt = 0 };

  if (recipe_lower_parts (p, id, &none, &tmp) == false) return false;

  const u32 pos = recipe_node (p, id)->pos;

  if (tmp.parts_cnt != 1)
  {
    snprintf (prog->error_buf, sizeof (prog->error_buf), "%s has to hold a single value, such as a hash call, pass, salt or a string", what);

    return recipe_fail_at (p, pos, prog->error_buf);
  }

  if (tmp.parts[0].wide == 1)
  {
    snprintf (prog->error_buf, sizeof (prog->error_buf), "%s cannot hold utf16le yet", what);

    return recipe_fail_at (p, pos, prog->error_buf);
  }

  *out = tmp.parts[0];

  return true;
}

// A pbkdf2 call's key and salt are single values the init kernel reads, as a step reads a part. The
// comp kernel fills a carried variable with the derived key, in the format of the call's suffix,
// and every use of the call reads it.

static bool recipe_lower_kdf (recipe_parser_t *p, const u32 id, u32 *slot)
{
  if (p->kdf_slot > 0)
  {
    *slot = p->kdf_slot - 1;

    return true;
  }

  recipe_prog_t *prog = p->prog;

  const recipe_node_t *node = recipe_node (p, id);

  const u32 sec = p->cur_sec;

  p->cur_sec = RECIPE_SEC_INIT;

  if (recipe_lower_one (p, node->kids[0], &prog->kdf_key,  "the key of pbkdf2")  == false) return false;
  if (recipe_lower_one (p, node->kids[1], &prog->kdf_salt, "the salt of pbkdf2") == false) return false;

  p->cur_sec = sec;

  // A recipe with pbkdf2 has no for loop, so this is the first carried variable.

  const u32 co = p->carry_cnt;

  p->carry_cnt += 1;

  const u32 hlen = recipe_digest_len (node->algo);

  prog->slow       = 1;
  prog->loop_cnt   = node->iter - 1;
  prog->line_iter  = p->line_iter;
  prog->iter_min   = p->iter_min;
  prog->iter_sub   = p->iter_sub;
  prog->carry_cnt  = p->carry_cnt;
  prog->kdf_algo   = node->algo;
  prog->kdf_fmt    = node->role;
  prog->kdf_dklen  = node->dklen;
  prog->kdf_blocks = (node->dklen + hlen - 1) / hlen;
  prog->kdf_out    = co;

  p->kdf_slot = co + 1;

  *slot = co;

  return true;
}

// Return the carried variable for a slice of the derived key starting at byte start and spanning
// len bytes. Reading the same slice twice uses one shared variable.

static bool recipe_kdf_slot (recipe_parser_t *p, const u32 pos, const u32 start, const u32 len, u32 *slot)
{
  recipe_prog_t *prog = p->prog;

  for (u32 i = 0; i < prog->kdf_slices_cnt; i++)
  {
    if (prog->kdf_slice_start[i] != start) continue;
    if (prog->kdf_slice_len[i]   != len)   continue;

    *slot = prog->kdf_slice_var[i];

    return true;
  }

  if ((prog->kdf_slices_cnt >= RECIPE_MAX_KDF_SLICES) || (p->carry_cnt >= RECIPE_MAX_CARRY)) return recipe_fail_at (p, pos, "more than 3 different cuts of a pbkdf2 key");

  const u32 v = p->carry_cnt;
  const u32 k = prog->kdf_slices_cnt;

  p->carry_cnt += 1;

  prog->carry_cnt          = p->carry_cnt;
  prog->kdf_slice_var[k]   = v;
  prog->kdf_slice_start[k] = start;
  prog->kdf_slice_len[k]   = len;

  prog->kdf_slices_cnt++;

  *slot = v;

  return true;
}

// The slice a raw derived key's cuts select, as its start and length in bytes.

static void recipe_kdf_cuts (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, u32 *start_out, u32 *len_out)
{
  u32 start = 0;
  u32 len   = node->dklen;

  for (u32 w = wrap->cnt; w > 0; w--)
  {
    u32 s = 0;
    u32 l = 0;

    recipe_resolve_cut (recipe_node (p, wrap->ids[w - 1]), len, &s, &l);

    start += s;
    len    = l;
  }

  *start_out = start;
  *len_out   = len;
}

// Whether the wraps of a pbkdf2 call select a slice: cuts alone of its _bin form, starting and
// ending at multiples of 4 bytes.

static bool recipe_kdf_slice_ok (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap)
{
  if (node->role != RECIPE_FMT_RAW) return false;

  for (u32 w = 0; w < wrap->cnt; w++)
  {
    if (recipe_node (p, wrap->ids[w])->kind != RECIPE_NODE_CUT) return false;
  }

  u32 start = 0;
  u32 len   = 0;

  recipe_kdf_cuts (p, node, wrap, &start, &len);

  if ((start % 4) != 0) return false;
  if ((len   % 4) != 0) return false;

  if (len == 0) return false;

  return true;
}

// A cut of a raw derived key selects a slice, such as cut (dk, 32, 16) for an IV after the key.
// Each distinct slice has its own carried variable, filled by the comp kernel from the derived key.
// The slice has a fixed length and can be used as an AES key, IV or data part. The caller checks
// with recipe_kdf_slice_ok () that the cuts select one.

static bool recipe_kdf_slice (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, u32 *slot)
{
  const u32 pos = recipe_node (p, wrap->ids[0])->pos;

  u32 start = 0;
  u32 len   = 0;

  recipe_kdf_cuts (p, node, wrap, &start, &len);

  const bool rc = recipe_kdf_slot (p, pos, start, len, slot);

  return rc;
}

// Lower each carried variable's final assignment from the body for the loop kernel. Every variable
// assigned by the body must be assigned a step's output: a hash call, an xor, and or or call, or a
// transformed value such as rev (h). After each iteration, the loop kernel copies that step's
// output into the carried variable.

static bool recipe_lower_body (recipe_parser_t *p)
{
  recipe_prog_t *prog = p->prog;

  bool any = false;

  for (u32 c = 0; c < p->carry_cnt; c++)
  {
    const u32 body = p->var_body[p->slot_var[c]];

    if (body == 0) continue;

    if (recipe_lower_one (p, body, &prog->carry_loop[c], "a variable carried through the loop") == false) return false;

    if (prog->carry_loop[c].kind != RECIPE_PART_STEP) return recipe_fail_at (p, recipe_node (p, body)->pos, "a variable assigned in the loop has to be assigned a hash call");

    prog->carry_has_loop[c] = 1;

    any = true;
  }

  if (any == false) return recipe_fail_at (p, 0, "the loop assigns no variable that the next iteration or the result reads");

  return true;
}

// Lower each carried variable's values: its value before the loop in the init kernel, and its
// final assignment from the body in the loop kernel. See recipe_lower_body () for that lowering.

static bool recipe_lower_loop (recipe_parser_t *p)
{
  recipe_prog_t *prog = p->prog;

  prog->slow      = 1;
  prog->loop_cnt  = p->loop_cnt;
  prog->line_iter = p->line_iter;
  prog->iter_min  = p->iter_min;
  prog->iter_sub  = p->iter_sub;
  prog->carry_cnt = p->carry_cnt;

  p->cur_sec = RECIPE_SEC_INIT;

  for (u32 c = 0; c < p->carry_cnt; c++)
  {
    const u32 pre = p->var_pre[p->slot_var[c]];

    if (pre == 0)
    {
      if (p->slot_need_init[c] == true) return recipe_fail_at (p, p->slot_pos[c], "the loop reads this variable before it has a value");

      continue;
    }

    if (recipe_lower_one (p, pre, &prog->carry_init[c], "a variable carried through the loop") == false) return false;

    prog->carry_has_init[c] = 1;
  }

  p->cur_sec = RECIPE_SEC_LOOP;

  // A loop body can read a carried variable before assigning it, as in t = xor (t, u). How that
  // read is lowered depends on what the variable can hold. See recipe_var_shape (). The first round
  // uses the shape of the value before the loop as its guess for the value from the body. Each
  // later round restarts from the program produced by init lowering. Its guesses combine the
  // results of earlier rounds. Lowering stops when a round produces values matching its guesses. If
  // no round does, a final round guesses the values that any hash call can produce.

  recipe_prog_t   *prog0 = (recipe_prog_t *)   hcmalloc (sizeof (recipe_prog_t));
  recipe_parser_t *p0    = (recipe_parser_t *) hcmalloc (sizeof (recipe_parser_t));

  memcpy (prog0, prog, sizeof (recipe_prog_t));
  memcpy (p0,    p,    sizeof (recipe_parser_t));

  bool rc = true;

  for (u32 round = 0; round <= RECIPE_LOOP_ROUNDS; round++)
  {
    if (recipe_lower_body (p) == false)
    {
      rc = false;

      break;
    }

    bool same = (p->guess_ok == true);

    u32  lens[RECIPE_MAX_CARRY];
    u32  mosts[RECIPE_MAX_CARRY];
    bool asciis[RECIPE_MAX_CARRY];

    for (u32 c = 0; c < p->carry_cnt; c++)
    {
      lens[c]   = 0;
      mosts[c]  = 0;
      asciis[c] = false;

      if (prog->carry_has_loop[c] == 0) continue;

      lens[c]   = recipe_part_fixed (p, &prog->carry_loop[c]);
      mosts[c]  = recipe_part_most  (p, &prog->carry_loop[c]);
      asciis[c] = recipe_part_ascii (p, &prog->carry_loop[c]);

      if (p->guess_ok == true)
      {
        if (lens[c] != p->guess_len[c]) lens[c] = 0;

        mosts[c] = MAX (mosts[c], p->guess_most[c]);

        if (p->guess_ascii[c] == false) asciis[c] = false;
      }

      if ((lens[c] != p->guess_len[c]) || (mosts[c] != p->guess_most[c]) || (asciis[c] != p->guess_ascii[c])) same = false;
    }

    if (same == true) break;

    // A step output holds up to 128 bytes, see recipe_lower_xfrm ().

    if (round == (RECIPE_LOOP_ROUNDS - 1))
    {
      for (u32 c = 0; c < p->carry_cnt; c++)
      {
        if (prog->carry_has_loop[c] == 0) continue;

        lens[c]   = 0;
        mosts[c]  = 128;
        asciis[c] = false;
      }
    }

    if (round == RECIPE_LOOP_ROUNDS) break;

    memcpy (prog, prog0, sizeof (recipe_prog_t));
    memcpy (p,    p0,    sizeof (recipe_parser_t));

    p->guess_ok = true;

    for (u32 c = 0; c < p->carry_cnt; c++)
    {
      p->guess_len[c]   = lens[c];
      p->guess_most[c]  = mosts[c];
      p->guess_ascii[c] = asciis[c];
    }
  }

  hcfree (prog0);
  hcfree (p0);

  return rc;
}

// Identify the step whose output is the result: a call, or transforms of a carried variable or of
// the key of pbkdf2. In the pbkdf2 case, the transforms read the whole key.

static bool recipe_lower_root_step (recipe_parser_t *p, const u32 id, const recipe_node_t *node, const bool var_xfrm, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out)
{
  if (var_xfrm == false)
  {
    const bool rc = recipe_lower_hash (p, id, wrap, step_out, wide_out);

    return rc;
  }

  if (p->kdf_slot == (node->slot + 1)) p->prog->kdf_whole = 1;

  const bool rc = recipe_lower_var_xfrm (p, node->slot, wrap, step_out, wide_out);

  return rc;
}

// The result can be a carried variable, as in h = sha512 (salt . pass); for ... { h = ... }; h.
// The comp kernel takes the 16 compared bytes from the start of that stored value. Wrapping the
// result in hex () or base64 () for raw bytes, or upper () or lower () for hex, changes the format
// written to the hash line.

static bool recipe_lower_root_var (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap)
{
  recipe_prog_t *prog = p->prog;

  u32 c = node->slot;

  // The derived key of pbkdf2 is stored in the format of its suffix, and its length decides
  // whether it holds the 16 compared bytes.

  u32  vfmt  = prog->kdf_fmt;
  bool keeps = (prog->kdf_dklen >= 16);

  if (p->kdf_slot != (c + 1))
  {
    const recipe_part_t *part = (prog->carry_has_loop[c] == 1) ? &prog->carry_loop[c] : &prog->carry_init[c];

    if (((prog->carry_has_loop[c] == 0) && (prog->carry_has_init[c] == 0)) || (part->kind != RECIPE_PART_STEP)) return recipe_fail_at (p, node->pos, "the result has to be a hash call or a variable that holds one");

    const recipe_step_t *step = &prog->steps[part->idx];

    vfmt = step->fmt;

    u32 need = 32;

    if (vfmt == RECIPE_FMT_RAW) need = 16;
    if (vfmt == RECIPE_FMT_B64) need = 22;

    keeps = (step->cut_start == 0) && (step->cut_len >= need);
  }

  u32 fmt = vfmt;

  // The innermost transforms of the derived key can cut it using bytes of its _bin form or
  // characters of its hex form. The cut reads a separate slice, stored by the comp kernel as raw
  // bytes. See recipe_kdf_slot () for that slice.

  u32 outer = wrap->cnt;

  if (p->kdf_slot == (c + 1))
  {
    while ((outer > 0) && (recipe_node (p, wrap->ids[outer - 1])->kind == RECIPE_NODE_CUT)) outer--;
  }

  if (outer < wrap->cnt)
  {
    const u32 pos = recipe_node (p, wrap->ids[outer])->pos;

    if (vfmt == RECIPE_FMT_B64) return recipe_fail_at (p, pos, "a cut of a pbkdf2 key needs its _bin or hex form");

    const u32 unit = (vfmt == RECIPE_FMT_RAW) ? 1 : 2;

    u32 start = 0;
    u32 len   = prog->kdf_dklen * unit;

    for (u32 w = wrap->cnt; w > outer; w--)
    {
      u32 s = 0;
      u32 l = 0;

      recipe_resolve_cut (recipe_node (p, wrap->ids[w - 1]), len, &s, &l);

      start += s;
      len    = l;
    }

    if (((start % (unit * 4)) != 0) || ((len % (unit * 4)) != 0)) return recipe_fail_at (p, pos, "a cut of a pbkdf2 key has to start and end at a multiple of 4 bytes");

    if (len < (unit * 16)) return recipe_fail_at (p, pos, "a cut of a pbkdf2 key as the result has to keep at least 16 bytes");

    if (recipe_kdf_slot (p, pos, start / unit, len / unit, &c) == false) return false;

    vfmt  = RECIPE_FMT_RAW;
    keeps = true;
  }
  else if ((p->kdf_slot == (c + 1)) && (prog->kdf_whole == 0))
  {
    // The whole derived key, used only as the result and read by no call, is stored as raw bytes.
    // The device compares its first 16 bytes. The host writes the hash line in its required format.

    prog->kdf_raw = 1;

    vfmt = RECIPE_FMT_RAW;
  }

  for (u32 w = outer; w > 0; w--)
  {
    const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

    const bool is_hex = (fmt == RECIPE_FMT_HEX) || (fmt == RECIPE_FMT_HEXU);

    if ((t->kind == RECIPE_NODE_HEX)   && (fmt == RECIPE_FMT_RAW)) { fmt = RECIPE_FMT_HEX;  continue; }
    if ((t->kind == RECIPE_NODE_B64)   && (fmt == RECIPE_FMT_RAW)) { fmt = RECIPE_FMT_B64;  continue; }
    if ((t->kind == RECIPE_NODE_UPPER) && (is_hex == true))        { fmt = RECIPE_FMT_HEXU; continue; }
    if ((t->kind == RECIPE_NODE_LOWER) && (is_hex == true))        { fmt = RECIPE_FMT_HEX;  continue; }

    return recipe_fail_at (p, t->pos, "a variable as the result takes only hex and base64 of raw bytes, and upper and lower of hex");
  }

  if (fmt == RECIPE_FMT_RAW) return recipe_fail_at (p, node->pos, "the result must be hex or base64, the hash line holds it as text");

  if (keeps == false) return recipe_fail_at (p, node->pos, "the result has to keep the first 16 bytes of the digest");

  prog->root_var  = c + 1;
  prog->root_vfmt = vfmt;
  prog->root_fmt  = fmt;
  prog->root_step = RECIPE_MAX_STEPS;

  return true;
}

// The right side of a comparison: a string, as it is or under transforms such as fromhex. Its
// bytes are what a hash line without a digest is compared with.

// Whether the side of a comparison at id is a string, possibly under transforms such as fromhex.

static bool recipe_is_lit (recipe_parser_t *p, const u32 id)
{
  u32 at = id;

  for (u32 i = 0; i <= RECIPE_MAX_WRAP; i++)
  {
    const recipe_node_t *node = recipe_node (p, at);

    if (node->kind == RECIPE_NODE_LIT) return true;

    if ((node->kind != RECIPE_NODE_UPPER) && (node->kind != RECIPE_NODE_LOWER) && (node->kind != RECIPE_NODE_HEX) && (node->kind != RECIPE_NODE_CUT) && (node->kind != RECIPE_NODE_UTF16) && (node->kind != RECIPE_NODE_B64) && (node->kind != RECIPE_NODE_XOP)) return false;

    at = node->kids[0];
  }

  return false;
}

// Whether the left side of a comparison at id is a variable carried through a loop or a pbkdf2 key
// without an outer transform such as rev. A direct comparison with a string cannot accept that kind
// of value.

static bool recipe_is_var_side (recipe_parser_t *p, const u32 id)
{
  u32 at = id;

  for (u32 i = 0; i <= RECIPE_MAX_WRAP; i++)
  {
    const recipe_node_t *node = recipe_node (p, at);

    if ((node->kind == RECIPE_NODE_VAR) || (node->kind == RECIPE_NODE_KDF)) return true;

    if (node->kind == RECIPE_NODE_XOP) return false;

    if ((node->kind != RECIPE_NODE_UPPER) && (node->kind != RECIPE_NODE_LOWER) && (node->kind != RECIPE_NODE_HEX) && (node->kind != RECIPE_NODE_CUT) && (node->kind != RECIPE_NODE_UTF16) && (node->kind != RECIPE_NODE_B64)) return false;

    at = node->kids[0];
  }

  return false;
}

static bool recipe_cmp_const (recipe_parser_t *p, const u32 id, u8 *buf, u32 *len)
{
  recipe_wrap_t wrap = { .cnt = 0 };

  u32 at = id;

  while (true)
  {
    const recipe_node_t *node = recipe_node (p, at);

    if ((node->kind != RECIPE_NODE_UPPER) && (node->kind != RECIPE_NODE_LOWER) && (node->kind != RECIPE_NODE_HEX) && (node->kind != RECIPE_NODE_CUT) && (node->kind != RECIPE_NODE_UTF16) && (node->kind != RECIPE_NODE_B64) && (node->kind != RECIPE_NODE_XOP)) break;

    if (wrap.cnt >= RECIPE_MAX_WRAP) return recipe_fail_at (p, node->pos, "too many nested transforms");

    wrap.ids[wrap.cnt] = at;

    wrap.cnt++;

    at = node->kids[0];
  }

  const recipe_node_t *node = recipe_node (p, at);

  if (node->kind != RECIPE_NODE_LIT) return recipe_fail_at (p, recipe_node (p, id)->pos, "the right side of == has to be a string, such as fromhex('0c0c0c0c0c0c0c0c')");

  return recipe_lit_bytes (p, node, &wrap, buf, len);
}

// The left side of a comparison is the result step's raw bytes. Any cut of a step starts on a
// word boundary. See recipe_lower_hash (). Starting there, the kernel compares the constant's
// length, up to 16 bytes.

static bool recipe_cmp_root (recipe_parser_t *p, const u32 pos, const recipe_step_t *step, const bool wide, const u8 *cbuf, const u32 clen)
{
  recipe_prog_t *prog = p->prog;

  if ((step->fmt != RECIPE_FMT_RAW) || (wide == true)) return recipe_fail_at (p, pos, "a comparison takes raw bytes, such as a _bin or aes call or a cut of one");

  if (step->cut_len != clen)
  {
    snprintf (prog->error_buf, sizeof (prog->error_buf), "the two sides of == differ in length, %u and %u bytes", step->cut_len, clen);

    return recipe_fail_at (p, pos, prog->error_buf);
  }

  if (clen < 8) return recipe_fail_at (p, pos, "a comparison needs at least 8 bytes on each side");

  prog->cmp       = 1;
  prog->cmp_start = step->cut_start;
  prog->cmp_len   = MIN (clen, 16);

  memset (prog->cmp_digest, 0, sizeof (prog->cmp_digest));
  memcpy (prog->cmp_digest, cbuf, prog->cmp_len);

  return true;
}

bool recipe_compile (recipe_prog_t *prog, const char *src)
{
  memset (prog, 0, sizeof (recipe_prog_t));

  // The parser takes about 10 kB of stack.

  recipe_parser_t parser;

  memset (&parser, 0, sizeof (parser));

  recipe_parser_t *p = &parser;

  p->prog = prog;
  p->src  = src;
  p->pos  = 0;

  bool rc = false;

  // Statements are separated by semicolons or line breaks, and empty statements are allowed.

  u32  root     = 0;
  u32  stmts    = 0;
  bool parsed   = true;
  bool cmp_seen = false;

  while (true)
  {
    recipe_skip_ws (p);

    bool sep = (stmts == 0) || (recipe_ws_newline (p) == true);

    while (p->src[p->pos] == ';')
    {
      p->pos++;

      recipe_skip_ws (p);

      sep = true;
    }

    if (p->src[p->pos] == 0) break;

    if (sep == false)
    {
      recipe_fail (p, "expected ; or a line break between statements");

      parsed = false;

      break;
    }

    if (cmp_seen == true)
    {
      recipe_fail (p, "a comparison has to be the last statement");

      parsed = false;

      break;
    }

    if (recipe_parse_stmt (p, &root) == false)
    {
      parsed = false;

      break;
    }

    if ((root != 0) && ((recipe_node (p, root)->kind == RECIPE_NODE_EQ) || (recipe_node (p, root)->kind == RECIPE_NODE_NONEMPTY))) cmp_seen = true;

    stmts++;
  }

  if (parsed == false)
  {
    // The parser has already recorded the error.
  }
  else if (stmts == 0)
  {
    recipe_fail (p, "expected a hash call, pass, salt or a string");
  }
  else if (root == 0)
  {
    recipe_fail (p, "the last statement has to be the result, such as sha1(h)");
  }
  else if ((p->loop_cnt > 0) && (recipe_lower_loop (p) == false))
  {
    // The lowering has already recorded the error.
  }
  else
  {
    p->cur_sec = ((p->loop_cnt > 0) || (p->kdf != 0)) ? RECIPE_SEC_COMP : RECIPE_SEC_MAIN;

    // The result must be a hash call, optionally wrapped in transforms, with hex or base64 output
    // for the hash line. Comparison uses the first 16 digest bytes, which any cut must preserve: 32
    // hex characters or 22 base64 characters.

    // For a comparison result, use its left side as the result's value. In the case of
    // length (aes_unwrap (...)) > 0, that value is the unwrap's integrity check value. Compare it
    // with A6A6A6A6A6A6A6A6.

    u8   cmp_buf[RECIPE_MAX_XBYTES];
    u32  cmp_len = 0;
    bool cmp     = false;
    bool cmp_ok  = true;

    u32 id = root;

    if (recipe_node (p, root)->kind == RECIPE_NODE_EQ)
    {
      const u32 lhs = recipe_node (p, root)->kids[0];
      const u32 rhs = recipe_node (p, root)->kids[1];

      cmp = true;

      // A string on the right is the digest assigned to every hash line. For 2 computed values, or
      // a carried variable or pbkdf2 key on the left, equality means their xor is all zeros. That
      // zero value becomes the digest for the comparison instead.

      if ((recipe_is_lit (p, rhs) == true) && (recipe_is_var_side (p, lhs) == false))
      {
        cmp_ok = recipe_cmp_const (p, rhs, cmp_buf, &cmp_len);
        id     = lhs;
      }
      else
      {
        const u32 x = recipe_new_node (p, RECIPE_NODE_BOP, recipe_node (p, root)->pos);

        if (x == 0)
        {
          cmp_ok = recipe_fail (p, "the recipe is too long");
        }
        else
        {
          recipe_node_t *bop = recipe_node (p, x);

          bop->aop      = RECIPE_BOP_XOR;
          bop->role     = RECIPE_FMT_RAW;
          bop->iter     = 1;
          bop->kids[0]  = lhs;
          bop->kids[1]  = rhs;
          bop->kids_cnt = 2;

          p->eq_bop = x;

          id = x;
        }
      }
    }
    else if (recipe_node (p, root)->kind == RECIPE_NODE_NONEMPTY)
    {
      recipe_node_t *x = recipe_node (p, recipe_node (p, root)->kids[0]);

      cmp = true;
      id  = recipe_node (p, root)->kids[0];

      if ((x->kind != RECIPE_NODE_AES) || (x->aop != RECIPE_AES_UNWRAP))
      {
        cmp_ok = recipe_fail_at (p, x->pos, "length can only be compared for aes_unwrap, as in length (aes_unwrap (kek, x)) > 0");
      }
      else
      {
        x->aop  = RECIPE_AES_UNWRAP_A;
        x->role = RECIPE_FMT_RAW;

        memset (cmp_buf, 0xa6, 8);

        cmp_len = 8;
      }
    }

    recipe_wrap_t wrap = { .cnt = 0 };

    while (true)
    {
      const recipe_node_t *node = recipe_node (p, id);

      if ((node->kind != RECIPE_NODE_UPPER) && (node->kind != RECIPE_NODE_LOWER) && (node->kind != RECIPE_NODE_HEX) && (node->kind != RECIPE_NODE_CUT) && (node->kind != RECIPE_NODE_UTF16) && (node->kind != RECIPE_NODE_B64) && (node->kind != RECIPE_NODE_XOP)) break;

      if (wrap.cnt >= RECIPE_MAX_WRAP) break;

      wrap.ids[wrap.cnt] = id;

      wrap.cnt++;

      id = node->kids[0];
    }

    const recipe_node_t *node = recipe_node (p, id);

    u32  root_step = 0;
    bool root_wide = false;

    // A pbkdf2 call as the result is its derived key's carried variable.

    recipe_node_t kdf_var;

    bool kdf_ok = true;

    if (node->kind == RECIPE_NODE_KDF)
    {
      u32 slot = 0;

      kdf_ok = recipe_lower_kdf (p, id, &slot);

      kdf_var = *node;

      kdf_var.kind = RECIPE_NODE_VAR;
      kdf_var.slot = slot;

      node = &kdf_var;
    }

    // A carried variable or the key of pbkdf2 under a transform such as rev is the output of a step
    // of its own, see recipe_lower_xfrm ().

    bool var_xfrm = false;

    if (node->kind == RECIPE_NODE_VAR)
    {
      for (u32 w = 0; w < wrap.cnt; w++)
      {
        if (recipe_node (p, wrap.ids[w])->kind == RECIPE_NODE_XOP) var_xfrm = true;
      }
    }

    if ((kdf_ok == false) || (cmp_ok == false))
    {
      // The lowering has already recorded the error.
    }
    else if (node->kind == RECIPE_NODE_LENGTH)
    {
      recipe_fail_at (p, node->pos, "length can only be compared, as in length (aes_unwrap (kek, x)) > 0");
    }
    else if ((cmp == true) && (node->kind == RECIPE_NODE_VAR) && (var_xfrm == false))
    {
      recipe_fail_at (p, node->pos, "this left side of == cannot be compared with a string yet");
    }
    else if ((node->kind == RECIPE_NODE_VAR) && (var_xfrm == false))
    {
      if (recipe_lower_root_var (p, node, &wrap) == true)
      {
        if (recipe_uses_pass (prog) == false)
        {
          recipe_fail_at (p, node->pos, "the recipe does not use pass, so every candidate gives the same hash");
        }
        else
        {
          rc = true;
        }
      }
    }
    else if ((node->kind != RECIPE_NODE_HASH) && (node->kind != RECIPE_NODE_HMAC) && (node->kind != RECIPE_NODE_AES) && (node->kind != RECIPE_NODE_BOP) && (var_xfrm == false))
    {
      recipe_fail_at (p, node->pos, "the result must be a hash, aes, xor, and or or call, possibly inside upper, lower, hex, base64, cut, trunc or another transform");
    }
    else if (recipe_lower_root_step (p, id, node, var_xfrm, &wrap, &root_step, &root_wide) == true)
    {
      const recipe_step_t *step = &prog->steps[root_step];

      const bool b64 = (step->fmt == RECIPE_FMT_B64);

      bool fmt_ok = false;

      const bool eq_bop = (p->eq_bop != 0) && (recipe_node (p, p->eq_bop) == node);

      if ((eq_bop == true) && ((step->part_lens[0] == 0) || (step->part_lens[0] != step->part_lens[1])))
      {
        recipe_fail_at (p, node->pos, "the two sides of == need the same fixed length, such as two _bin calls of one family or a cut of each");
      }
      else if ((step->kind == RECIPE_KIND_BOP) && (step->cut_len == 0))
      {
        recipe_fail_at (p, node->pos, "xor, and or or as the result needs two values of fixed length, the hash line holds a digest of one length");
      }
      else if ((step->kind == RECIPE_KIND_XFRM) && (step->cut_len == 0))
      {
        recipe_fail_at (p, node->pos, "a transformed hash output or variable as the result needs a fixed length, the hash line holds a digest of one length");
      }
      else if (cmp == true)
      {
        if (eq_bop == true)
        {
          cmp_len = step->part_lens[0];

          memset (cmp_buf, 0, cmp_len);
        }

        fmt_ok = recipe_cmp_root (p, node->pos, step, root_wide, cmp_buf, cmp_len);
      }
      else if ((step->fmt == RECIPE_FMT_RAW) || (root_wide == true))
      {
        recipe_fail_at (p, node->pos, "the result must be hex or base64, the hash line holds it as text");
      }
      else if ((b64 == false) && ((step->cut_start != 0) || (step->cut_len < 32)))
      {
        recipe_fail_at (p, node->pos, "the result must keep its first 32 hex characters, mode 4000 compares 16 bytes");
      }
      else if ((b64 == true) && ((step->cut_start != 0) || (step->cut_len < 22)))
      {
        recipe_fail_at (p, node->pos, "the result must keep its first 22 base64 characters, mode 4000 compares 16 bytes");
      }
      else
      {
        fmt_ok = true;
      }

      if (fmt_ok == true)
      {
        bool dep[RECIPE_MAX_STEPS];

        recipe_deps (prog, dep);

        // A comparison's hash line holds the 16 compared bytes in hex, when it holds them at all.

        prog->root_fmt  = (cmp == true) ? (u32) RECIPE_FMT_HEX : step->fmt;
        prog->root_step = root_step;

        // In a loop recipe, a carried variable makes the result depend on the candidate even when
        // pass never appears in its step, so look for pass itself. The result still has to read
        // pass or a carried variable.

        const bool uses_pass = (prog->slow == 1) ? recipe_uses_pass (prog) : dep[root_step];

        if (uses_pass == false)
        {
          recipe_fail_at (p, node->pos, "the recipe does not use pass, so every candidate gives the same hash");
        }
        else if (dep[root_step] == false)
        {
          recipe_fail_at (p, node->pos, "the result depends neither on pass nor on a loop variable, so every candidate gives the same hash");
        }
        else
        {
          rc = true;
        }
      }
    }
  }

  // Assigning a pbkdf2 call to an unread variable would leave a slow recipe without
  // a pbkdf2 call to run.

  if ((rc == true) && (p->kdf != 0) && (p->kdf_slot == 0))
  {
    recipe_fail_at (p, recipe_node (p, p->kdf)->pos, "the result does not use the pbkdf2 call");

    rc = false;
  }

  // Find the maximum password and salt lengths that fit all transformed copies.

  prog->pw_max    = RECIPE_MAX_XBYTES;
  prog->salt_max  = RECIPE_MAX_XBYTES;
  prog->field_max = RECIPE_FIELD_MAX;

  for (u32 x = 0; x < prog->xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog->xforms[x];

    u32 len = RECIPE_MAX_XBYTES;

    while ((len > 0) && (recipe_xform_fits (xform, len) == false)) len--;

    if (xform->src == RECIPE_PART_PASS) prog->pw_max   = MIN (prog->pw_max,   len);
    if (xform->src == RECIPE_PART_SALT) prog->salt_max = MIN (prog->salt_max, len);

    if (recipe_is_field (xform->src) == true) prog->field_max = MIN (prog->field_max, len);

    // The decoded salt is half as long as a hex salt and 3/4 as long as a base64 salt.

    if (xform->src == RECIPE_PART_SALTD) prog->salt_max = MIN (prog->salt_max, (prog->salt_dec == RECIPE_DEC_HEX) ? (len * 2) : ((len * 4) / 3));
  }

  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    const recipe_step_t *step = &prog->steps[k];

    if (step->kind != RECIPE_KIND_BOP) continue;

    recipe_bop_limit (prog, &step->parts[0]);
    recipe_bop_limit (prog, &step->parts[1]);
  }

  return rc;
}

// Kernel token for a part. During recipe_prep (), all input steps were computed in that phase and
// use STEPn. Per-candidate evaluation uses PSTEPn to read prepared step outputs from the state.

static const char *recipe_part_token (const recipe_prog_t *prog, const recipe_part_t *part, const bool in_prep, const bool *dep, char *buf, const size_t buf_size)
{
  const char *wide = (part->wide == 1) ? "16" : "";

  if (part->kind == RECIPE_PART_PASS) snprintf (buf, buf_size, "PASS%s", wide);
  if (part->kind == RECIPE_PART_SALT) snprintf (buf, buf_size, "SALT%s", wide);
  if (part->kind == RECIPE_PART_LIT)  snprintf (buf, buf_size, "LIT%u",  part->idx);

  if (part->kind == RECIPE_PART_SALTD) snprintf (buf, buf_size, "SALTD");
  if (part->kind == RECIPE_PART_VAR)   snprintf (buf, buf_size, "VAR%u", part->idx);

  if (part->kind == RECIPE_PART_SALT2)  snprintf (buf, buf_size, "SALT2%s",  (part->wide == 1) ? "_16" : "");
  if (part->kind == RECIPE_PART_PEPPER) snprintf (buf, buf_size, "PEPPER%s", (part->wide == 1) ? "_16" : "");
  if (part->kind == RECIPE_PART_USER)   snprintf (buf, buf_size, "USER%s",   (part->wide == 1) ? "_16" : "");

  // Password copies are made per candidate. Salt copies are stored in the state once per salt.

  if (part->kind == RECIPE_PART_XFORM) snprintf (buf, buf_size, "X%s%u%s", (prog->xforms[part->idx].src == RECIPE_PART_PASS) ? "P" : "S", part->idx, (part->wide == 1) ? "_16" : "");

  if (part->kind == RECIPE_PART_STEP)
  {
    const bool prepared = (in_prep == false) && (dep[part->idx] == false);

    snprintf (buf, buf_size, "%sSTEP%u%s", (prepared == true) ? "P" : "", part->idx, (part->wide == 1) ? "_16" : "");
  }

  return buf;
}

// Check whether loop step k can hash from a block template. See RECIPE_S<k>_TPL in the kernel
// include. It must be a plain hash run once, in a family with a transform function, without
// utf16le. Every part that changes per iteration must be a multiple of 4 bytes long. Those
// changing parts are the carried variables assigned by the loop and the outputs of earlier
// steps in the iteration.

// Check whether step k's output length can change between candidates, salts or iterations. This
// applies to the output of xor, and or or, or of transforms, when it has no fixed length or has a
// carried variable among its sources.

static bool recipe_step_len_moves (const recipe_prog_t *prog, const u32 k)
{
  const recipe_step_t *step = &prog->steps[k];

  if ((step->kind != RECIPE_KIND_BOP) && (step->kind != RECIPE_KIND_XFRM)) return false;

  if (step->cut_len == 0) return true;

  for (u32 i = 0; i < step->parts_cnt; i++)
  {
    const recipe_part_t *part = &step->parts[i];

    if (part->kind == RECIPE_PART_VAR) return true;

    if ((part->kind == RECIPE_PART_STEP) && (recipe_step_len_moves (prog, part->idx) == true)) return true;
  }

  return false;
}

static bool recipe_tpl_ok (const recipe_prog_t *prog, const u32 k, const bool *dep)
{
  const recipe_step_t *step = &prog->steps[k];

  if (step->sec  != RECIPE_SEC_LOOP)  return false;
  if (step->kind != RECIPE_KIND_HASH) return false;
  if (step->iter != 1)                return false;

  if ((step->algo == RECIPE_ALGO_BLAKE2B512) || (step->algo == RECIPE_ALGO_BLAKE2B256) || (step->algo == RECIPE_ALGO_BLAKE2S256)) return false;

  if (step->algo == RECIPE_ALGO_WRL) return false;

  if (recipe_algo_is_sha3 (step->algo) == true) return false;

  if ((step->algo == RECIPE_ALGO_SBOG256) || (step->algo == RECIPE_ALGO_SBOG512)) return false;

  if ((step->algo == RECIPE_ALGO_GOST94) || (step->algo == RECIPE_ALGO_GOST94_CP)) return false;

  if (step->algo == RECIPE_ALGO_RMD320) return false;

  if ((step->algo == RECIPE_ALGO_RMD128) || (step->algo == RECIPE_ALGO_RMD256)) return false;

  if (step->algo == RECIPE_ALGO_MD2) return false;

  if (step->algo == RECIPE_ALGO_SHA0) return false;

  if ((step->algo == RECIPE_ALGO_SNE128) || (step->algo == RECIPE_ALGO_SNE256)) return false;

  if (step->algo == RECIPE_ALGO_MYSQL323) return false;

  if (recipe_algo_is_haval (step->algo) == true) return false;

  if (recipe_algo_is_tiger (step->algo) == true) return false;

  for (u32 i = 0; i < step->parts_cnt; i++)
  {
    const recipe_part_t *part = &step->parts[i];

    if (part->wide == 1) return false;

    // The output of xor, and or or, or of transforms, can have no fixed length to lay out.

    if ((part->kind == RECIPE_PART_STEP) && (recipe_step_len_moves (prog, part->idx) == true)) return false;

    if ((part->kind == RECIPE_PART_STEP) && (dep[part->idx] == true) && ((prog->steps[part->idx].cut_len % 4) != 0)) return false;

    if ((part->kind == RECIPE_PART_VAR) && (prog->carry_has_loop[part->idx] == 1) && (recipe_step_len_moves (prog, prog->carry_loop[part->idx].idx) == true)) return false;

    if ((part->kind == RECIPE_PART_VAR) && (prog->carry_has_loop[part->idx] == 1) && ((prog->steps[prog->carry_loop[part->idx].idx].cut_len % 4) != 0)) return false;
  }

  return true;
}

// Write the transforms of a copy (PRE is X) or of an XFRM step (PRE is S) as
// RECIPE_<PRE><k>_O<j>, together with their arguments. See RECIPE_XOP in the kernel include.
// Return the new length of buf.

static int recipe_jit_xops (char *buf, const size_t size, int len, const char *pre, const u32 k, const recipe_xop_entry_t *ops, const u32 ops_cnt)
{
  for (u32 i = 0; i < RECIPE_MAX_XOPS; i++)
  {
    if (i >= ops_cnt)
    {
      len += snprintf (buf + len, size - len, " -D RECIPE_%s%u_O%u=NONE", pre, k, i);

      continue;
    }

    const recipe_xop_entry_t *op = &ops[i];

    const u64 a = (u64) op->a;

    const u32 a_lo = (u32) (a >>  0);
    const u32 a_hi = (u32) (a >> 32);

    len += snprintf (buf + len, size - len, " -D RECIPE_%s%u_O%u=%s", pre, k, i, RECIPE_XOP_NAMES[op->op]);

    if (op->op == RECIPE_XOP_WPERM)
    {
      len += snprintf (buf + len, size - len, " -D RECIPE_%s%u_A%u=0x%08x -D RECIPE_%s%u_H%u=0x%08x", pre, k, i, a_lo, pre, k, i, a_hi);
    }
    else
    {
      len += snprintf (buf + len, size - len, " -D RECIPE_%s%u_A%u=%d -D RECIPE_%s%u_H%u=0", pre, k, i, (int) op->a, pre, k, i);
    }

    len += snprintf (buf + len, size - len, " -D RECIPE_%s%u_B%u=%d -D RECIPE_%s%u_L%u=%u", pre, k, i, (int) op->b, pre, k, i, (op->has_len == true) ? 1 : 0);
  }

  return len;
}

// Kernel build options for OpenCL/inc_recipe.cl. Each step names its hash family and eight part
// slots by token, with NONE for unused slots. The preprocessor emits only required update calls.
// See RECIPE_CALL_* in the kernel include.
//
// With root_native, r holds the complete final digest in the family's native word layout. This
// lets modes use recipe kernels while keeping their digest layout and DGST_POS. Without this flag,
// r holds the first 16 bytes in mode 4000's byte order.

char *recipe_jit_build_options (const char *src, const bool root_native)
{
  recipe_prog_t prog;

  if (recipe_compile (&prog, src) == false) return NULL;

  char buf[16384];

  // RECIPE_ROOT_FN applies only to RECIPE_ROOT_NATIVE, which compares in the word layout of the
  // family that produced the result. That is the last hash call or, for a carried variable as the
  // result, the pbkdf2 call or the hash call that the loop assigns to it. A recipe can also consist
  // of a pbkdf2 call alone.

  u32 root_algo = (prog.steps_cnt > 0) ? prog.steps[prog.steps_cnt - 1].algo : prog.kdf_algo;

  if (prog.root_var > 0)
  {
    const u32 c = prog.root_var - 1;

    bool kdf_var = (c == prog.kdf_out);

    for (u32 i = 0; i < prog.kdf_slices_cnt; i++)
    {
      if (prog.kdf_slice_var[i] == c) kdf_var = true;
    }

    if      ((prog.kdf_blocks > 0) && (kdf_var == true)) root_algo = prog.kdf_algo;
    else if (prog.carry_has_loop[c] == 1)                root_algo = prog.steps[prog.carry_loop[c].idx].algo;
  }

  int len = snprintf (buf, sizeof (buf), "-D RECIPE_STEPS=%u -D RECIPE_ROOT_FN=%s", prog.steps_cnt, recipe_algo_name (root_algo));

  if (root_native == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_ROOT_NATIVE");

  // A comparison result reads the compared bytes from the root step's raw output. Each of the 4
  // compared words has an index and a mask. A word beyond the compared length reads word 0 under a
  // zero mask, so it contributes no bytes to the comparison.

  if (prog.cmp == 1)
  {
    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_CMP");

    for (u32 i = 0; i < 4; i++)
    {
      const u32 have = (prog.cmp_len > (i * 4)) ? MIN (prog.cmp_len - (i * 4), 4) : 0;
      const u32 mask = (have == 4) ? 0xffffffff : ((1u << (have * 8)) - 1);
      const u32 idx  = (have == 0) ? 0 : ((prog.cmp_start / 4) + i);

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_CMP_I%u=%u -D RECIPE_CMP_M%u=0x%08xu", i, idx, i, mask);
    }
  }

  // UTF-16LE conversion can give candidates different lengths. See recipe_eval () in the kernel
  // include for how the kernels handle this.

  bool wide_pass  = false;
  bool wide_salt  = false;
  bool wide_field = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    for (u32 i = 0; i < prog.steps[k].parts_cnt; i++)
    {
      const recipe_part_t *part = &prog.steps[k].parts[i];

      if (part->wide == 0) continue;

      u32 src = part->kind;

      if (part->kind == RECIPE_PART_XFORM) src = prog.xforms[part->idx].src;

      if (src == RECIPE_PART_PASS) wide_pass = true;
      if (src == RECIPE_PART_SALT) wide_salt = true;

      if (recipe_is_field (src) == true) wide_field = true;
    }
  }

  // utf16be copies decode UTF-8 as well, so their length can differ between lanes too.

  for (u32 x = 0; x < prog.xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog.xforms[x];

    bool be16 = false;

    for (u32 j = 0; j < xform->ops_cnt; j++)
    {
      if (xform->ops[j].op == RECIPE_XOP_UTF16BE) be16 = true;
    }

    if (be16 == false) continue;

    if (xform->src == RECIPE_PART_PASS) wide_pass = true;

    if ((xform->src == RECIPE_PART_SALT) || (xform->src == RECIPE_PART_SALTD)) wide_salt = true;

    if (recipe_is_field (xform->src) == true) wide_field = true;
  }

  if ((wide_pass == true) || (wide_salt == true) || (wide_field == true)) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE");

  if (wide_pass  == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_PASS");
  if (wide_salt  == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_SALT");
  if (wide_field == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_FIELDS");

  // A wide recipe with a Whirlpool step evaluates each lane of a vector mask kernel on its own.
  // Compiling its vector code alongside the per lane path took Intel's CPU compiler over 20
  // minutes at vector width 8, compared with 5 seconds at width 1. hashcat also builds mode
  // 6100 at width 1 on CPUs.

  bool wide_wrl = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_WRL) wide_wrl = true;
  }

  if ((wide_wrl == true) && ((wide_pass == true) || (wide_salt == true) || (wide_field == true))) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_LANES");

  // GPUs read hex output from a table when a later step or round needs it. See RECIPE_HEX_TABLE in
  // the kernel include.

  bool hex = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    const recipe_step_t *step = &prog.steps[k];

    const bool fmt_hex   = (step->fmt       == RECIPE_FMT_HEX) || (step->fmt       == RECIPE_FMT_HEXU);
    const bool chain_hex = (step->chain_fmt == RECIPE_FMT_HEX) || (step->chain_fmt == RECIPE_FMT_HEXU);

    if ((k != prog.root_step) && (fmt_hex == true)) hex = true;

    if ((step->iter > 1) && (chain_hex == true)) hex = true;
  }

  for (u32 x = 0; x < prog.xforms_cnt; x++)
  {
    for (u32 i = 0; i < prog.xforms[x].ops_cnt; i++)
    {
      if (prog.xforms[x].ops[i].op == RECIPE_XOP_HEX) hex = true;
    }
  }

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    for (u32 i = 0; i < prog.steps[k].xops_cnt; i++)
    {
      if (prog.steps[k].xops[i].op == RECIPE_XOP_HEX) hex = true;
    }
  }

  if (hex == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_HEX");

  // Big endian families can use a converted copy of pass or salt. See RECIPE_BE_PASS in the kernel
  // include.

  bool be_pass = false;
  bool be_salt = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    const recipe_step_t *step = &prog.steps[k];

    if (recipe_algo (step->algo)->be == false) continue;

    for (u32 i = 0; i < step->parts_cnt; i++)
    {
      const recipe_part_t *part = &step->parts[i];

      if (part->wide == 1) continue;

      if (part->kind == RECIPE_PART_PASS) be_pass = true;
      if (part->kind == RECIPE_PART_SALT) be_salt = true;
    }
  }

  if (be_pass == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_BE_PASS");
  if (be_salt == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_BE_SALT");

  // fromhex (salt) and frombase64 (salt), see RECIPE_SALT_DEC in the kernel include.

  if (prog.salt_dec != RECIPE_DEC_NONE) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SALT_DEC=%u", prog.salt_dec);

  // The fields the recipe reads, as a bit mask, and the size of each one's slot in salt_buf_pc.

  if (prog.fields != 0) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_LINE_FIELDS=%u -D RECIPE_FIELD_WORDS=%u", prog.fields, RECIPE_FIELD_WORDS);

  // Whether the password is only hashed as parts, so the combinator kernel can hand it over as the
  // base word and the right word. See RECIPE_TAIL in the kernel include. An HMAC key, the source of
  // a transformed copy and a value of xor, and or or require the password in one piece.

  bool pass_plain = true;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if ((prog.steps[k].kind == RECIPE_KIND_HMAC) && (prog.steps[k].key.kind == RECIPE_PART_PASS)) pass_plain = false;

    if (prog.steps[k].kind != RECIPE_KIND_BOP) continue;

    for (u32 i = 0; i < prog.steps[k].parts_cnt; i++)
    {
      if (prog.steps[k].parts[i].kind == RECIPE_PART_PASS) pass_plain = false;
    }
  }

  for (u32 x = 0; x < prog.xforms_cnt; x++)
  {
    if (prog.xforms[x].src == RECIPE_PART_PASS) pass_plain = false;
  }

  if (pass_plain == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_PASS_PLAIN");

  // Step phases are defined by RECIPE_EV_* in the kernel include. P1 runs once per salt. P2 and P3
  // start from contexts prepared once per salt with parts independent of the candidate. P0 runs per
  // candidate. The Q slots contain parts fed by recipe_prep (), and the P slots contain the rest.

  bool dep[RECIPE_MAX_STEPS];

  recipe_deps (&prog, dep);

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    const recipe_step_t *step = &prog.steps[k];

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_FN=%s -D RECIPE_S%u_CFMT=%u -D RECIPE_S%u_FMT=%u -D RECIPE_S%u_ITER=%u -D RECIPE_S%u_CUT0=%u -D RECIPE_S%u_CUTN=%u", k, recipe_algo_name (step->algo), k, step->chain_fmt, k, step->fmt, k, step->iter, k, step->cut_start, k, step->cut_len);

    const bool is_hmac = (step->kind == RECIPE_KIND_HMAC);
    const bool is_aes  = (step->kind == RECIPE_KIND_AES);
    const bool is_bop  = (step->kind == RECIPE_KIND_BOP);
    const bool is_xfrm = (step->kind == RECIPE_KIND_XFRM);

    u32 lead = 0;

    while ((lead < step->parts_cnt) && (recipe_part_dep_on (&prog, &step->parts[lead], dep) == false)) lead++;

    // An AES step always runs per candidate, see recipe_deps (). A BOP or XFRM step runs per
    // candidate or, when its parts do not depend on it, once per salt.

    u32 phase = 0;

    if (is_aes == true)
    {
      phase = 0;
    }
    else if ((is_bop == true) || (is_xfrm == true))
    {
      phase = (dep[k] == true) ? 0 : 1;
    }
    else if (dep[k] == false)
    {
      phase = 1;
    }
    else if ((is_hmac == true) && (recipe_part_dep_on (&prog, &step->key, dep) == false))
    {
      phase = 2;
    }
    else if ((is_hmac == false) && (lead > 0))
    {
      phase = 3;
    }

    // Only P2 and P3 need leading parts independent of the candidate to be fed by recipe_prep ().

    const u32 q_cnt = ((phase == 2) || (phase == 3)) ? lead : 0;

    const bool parts_in_prep = (phase == 1);
    const bool key_in_prep   = (phase == 1) || (phase == 2);

    char key[16];

    if ((is_hmac == true) || (is_aes == true))
    {
      recipe_part_token (&prog, &step->key, key_in_prep, dep, key, sizeof (key));
    }
    else
    {
      snprintf (key, sizeof (key), "NONE");
    }

    const char *kind = "HASH";

    if (is_hmac == true) kind = "HMAC";
    if (is_aes  == true) kind = "AES";
    if (is_bop  == true) kind = "BOP";
    if (is_xfrm == true) kind = "XFRM";

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_KIND=%s -D RECIPE_S%u_KEY=%s -D RECIPE_S%u_PH=P%u", k, kind, k, key, k, phase);

    // An AES step specifies its operation, IV, raw output length, and the fixed lengths of
    // its key, data and each part within that data. See RECIPE_STEP_AES in the kernel
    // include for those fields.

    if (is_aes == true)
    {
      char iv[16];

      const bool cbc = (step->aop == RECIPE_AES_CBC_ENC) || (step->aop == RECIPE_AES_CBC_DEC);

      if (cbc == true)
      {
        recipe_part_token (&prog, &step->iv, false, dep, iv, sizeof (iv));
      }
      else
      {
        snprintf (iv, sizeof (iv), "NONE");
      }

      const u32 raw_len = recipe_aes_out_len (step);

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_AOP=%u -D RECIPE_S%u_IV=%s -D RECIPE_S%u_RLEN=%u -D RECIPE_S%u_KLEN=%u -D RECIPE_S%u_DLEN=%u", k, step->aop, k, iv, k, raw_len, k, step->key_len, k, step->data_len);

      for (u32 i = 0; i < RECIPE_MAX_PARTS; i++)
      {
        const u32 pl = (i < step->parts_cnt) ? step->part_lens[i] : 0;

        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_PL%u=%u", k, i, pl);
      }
    }

    // A BOP step specifies its operation, its maximum number of output bytes rounded up to whole
    // words, and whether its output is cut. See RECIPE_STEP_BOP in the kernel include.

    if (is_bop == true)
    {
      const u32 most = (step->data_len + 3) & ~3u;

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_BOP=%u -D RECIPE_S%u_BMAX=%u -D RECIPE_S%u_BFIX=%u", k, step->aop, k, most, k, (recipe_bop_cuts (step) == true) ? 1 : 0);
    }

    // An XFRM step specifies its transforms in the form used for a copy, and the maximum number of
    // bytes before applying its output format. See RECIPE_STEP_XFRM in the kernel include.

    if (is_xfrm == true)
    {
      const u32 most = (MIN (step->data_len, RECIPE_MAX_BOP) + 3) & ~3u;

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_BMAX=%u", k, most);

      len = recipe_jit_xops (buf, sizeof (buf), len, "S", k, step->xops, step->xops_cnt);
    }

    // A step whose first P slot is the password can start from the base word, which the combinator
    // kernel then feeds once per work item. See RECIPE_S<k>_BW in the kernel include.

    const bool bw_phase = (is_aes == false) && (is_bop == false) && (is_xfrm == false) && (((is_hmac == false) && ((phase == 0) || (phase == 3))) || ((is_hmac == true) && (phase == 2)));

    const bool bw = (bw_phase == true) && (q_cnt < step->parts_cnt) && (step->parts[q_cnt].kind == RECIPE_PART_PASS);

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_BW=%u", k, (bw == true) ? 1 : 0);

    // The kernel of a loop recipe that runs the step, see RECIPE_LOOP in the kernel include.

    if (prog.slow == 1)
    {
      const char *sec = "COMP";

      if (step->sec == RECIPE_SEC_INIT) sec = "INIT";
      if (step->sec == RECIPE_SEC_LOOP) sec = "LOOP";

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_SEC=%s", k, sec);

      const bool tpl = recipe_tpl_ok (&prog, k, dep);

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_TPL=%u -D RECIPE_S%u_OLEN=%u", k, (tpl == true) ? 1 : 0, k, step->cut_len);
    }

    for (u32 i = 0; i < RECIPE_MAX_PARTS; i++)
    {
      char token[16];

      const u32 src = q_cnt + i;

      if (src >= step->parts_cnt)
      {
        snprintf (token, sizeof (token), "NONE");
      }
      else
      {
        recipe_part_token (&prog, &step->parts[src], parts_in_prep, dep, token, sizeof (token));
      }

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_P%u=%s", k, i, token);
    }

    for (u32 i = 0; i < RECIPE_MAX_PARTS; i++)
    {
      char token[16];

      if (i >= q_cnt)
      {
        snprintf (token, sizeof (token), "NONE");
      }
      else
      {
        recipe_part_token (&prog, &step->parts[i], true, dep, token, sizeof (token));
      }

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_Q%u=%s", k, i, token);
    }
  }

  // A loop recipe names its carried variables, which part fills each one in the init kernel and
  // after each iteration of the loop kernel, the step whose digest is compared, and a carried
  // variable that is the result. A pbkdf2 recipe also names the family, the derived key's length,
  // blocks and format, its key and salt, and the carried variable of the derived key. RECIPE_AES has
  // the comp kernel load the AES tables.

  bool aes = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].kind == RECIPE_KIND_AES) aes = true;
  }

  if (aes == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_AES");

  // A Whirlpool step needs inc_hash_whirlpool.cl and its tables. See RECIPE_WRL
  // in the kernel include.

  bool wrl = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_WRL) wrl = true;
  }

  if (wrl == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WRL");

  // A SHA-3 or Keccak step needs inc_hash_sha3.cl.

  bool sha3 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (recipe_algo_is_sha3 (prog.steps[k].algo) == true) sha3 = true;
  }

  if (sha3 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SHA3");

  // A Streebog step needs its include and the table that both sizes share. See RECIPE_SBOG
  // in the kernel include.

  bool sbog256 = false;
  bool sbog512 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_SBOG256) sbog256 = true;
    if (prog.steps[k].algo == RECIPE_ALGO_SBOG512) sbog512 = true;
  }

  if (sbog256 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SBOG256");
  if (sbog512 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SBOG512");

  // A GOST R 34.11-94 step needs inc_hash_gost94.cl and the table of its S-box. See RECIPE_GOST94
  // in the kernel include.

  bool gost94    = false;
  bool gost94_cp = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_GOST94)    gost94    = true;
    if (prog.steps[k].algo == RECIPE_ALGO_GOST94_CP) gost94_cp = true;
  }

  if (gost94    == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_GOST94");
  if (gost94_cp == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_GOST94_CP");

  // A RIPEMD-320 step needs inc_hash_ripemd320.cl.

  bool rmd320 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_RMD320) rmd320 = true;
  }

  if (rmd320 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_RMD320");

  // RIPEMD-128 and RIPEMD-256 steps need inc_hash_ripemd128.cl and inc_hash_ripemd256.cl.

  bool rmd128 = false;
  bool rmd256 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_RMD128) rmd128 = true;
    if (prog.steps[k].algo == RECIPE_ALGO_RMD256) rmd256 = true;
  }

  if (rmd128 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_RMD128");
  if (rmd256 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_RMD256");

  // An MD2 step needs inc_hash_md2.cl and its table. See RECIPE_MD2 in the kernel include.

  bool md2 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_MD2) md2 = true;
  }

  if (md2 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_MD2");

  // A SHA-0 step needs inc_hash_sha0.cl.

  bool sha0 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_SHA0) sha0 = true;
  }

  if (sha0 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SHA0");

  // A Snefru step needs inc_hash_snefru.cl and its table. See RECIPE_SNEFRU in the kernel include.

  bool snefru = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if ((prog.steps[k].algo == RECIPE_ALGO_SNE128) || (prog.steps[k].algo == RECIPE_ALGO_SNE256)) snefru = true;
  }

  if (snefru == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_SNEFRU");

  // A mysql3 step needs inc_hash_mysql323.cl.

  bool mysql323 = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (prog.steps[k].algo == RECIPE_ALGO_MYSQL323) mysql323 = true;
  }

  if (mysql323 == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_MYSQL323");

  // A HAVAL step needs inc_hash_haval.cl.

  bool haval = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (recipe_algo_is_haval (prog.steps[k].algo) == true) haval = true;
  }

  if (haval == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_HAVAL");

  // A Tiger step needs inc_hash_tiger.cl and its table. See RECIPE_TIGER in the kernel include.

  bool tiger = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if (recipe_algo_is_tiger (prog.steps[k].algo) == true) tiger = true;
  }

  if (tiger == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_TIGER");

  if (prog.slow == 1)
  {
    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_LOOP -D RECIPE_CARRY=%u -D RECIPE_ROOT_STEP=%u", prog.carry_cnt, prog.root_step);

    if (prog.kdf_blocks > 0)
    {
      char key_tok[16];
      char salt_tok[16];

      recipe_part_token (&prog, &prog.kdf_key,  false, dep, key_tok,  sizeof (key_tok));
      recipe_part_token (&prog, &prog.kdf_salt, false, dep, salt_tok, sizeof (salt_tok));

      // PBKDF2 computes each block on its own, so the device computes only the blocks from the
      // first to the last one that is read: the whole key for a call that reads it, its first 16
      // bytes for the whole key as the result, and each slice. The comp kernel writes them from the first of those blocks on, as
      // RECIPE_KDF_DKLEN bytes.

      const u32 hlen = recipe_digest_len (prog.kdf_algo);

      u32 lo = (prog.kdf_whole == 1) ? 0 : prog.kdf_dklen;
      u32 hi = (prog.kdf_whole == 1) ? prog.kdf_dklen : 0;

      if (prog.kdf_raw == 1) lo = 0;
      if (prog.kdf_raw == 1) hi = MAX (hi, 16);

      for (u32 i = 0; i < prog.kdf_slices_cnt; i++)
      {
        lo = MIN (lo, prog.kdf_slice_start[i]);
        hi = MAX (hi, prog.kdf_slice_start[i] + prog.kdf_slice_len[i]);
      }

      const u32 first  = lo / hlen;
      const u32 blocks = ((hi + hlen - 1) / hlen) - first;
      const u32 skip   = first * hlen;
      const u32 dklen  = MIN (prog.kdf_dklen, (first + blocks) * hlen) - skip;

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_KDF=%s -D RECIPE_KDF_FIRST=%u -D RECIPE_KDF_BLOCKS=%u -D RECIPE_KDF_DKLEN=%u -D RECIPE_KDF_FMT=%u -D RECIPE_KDF_KEY=%s -D RECIPE_KDF_SALT=%s -D RECIPE_KDF_OUT=%u", recipe_algo_name (prog.kdf_algo), first, blocks, dklen, prog.kdf_fmt, key_tok, salt_tok, prog.kdf_out);

      if (prog.kdf_whole == 1) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_KDF_WHOLE");
      if (prog.kdf_raw   == 1) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_KDF_RAW");

      // Each slice of the derived key specifies its carried variable, its first word counted from
      // the first computed block, and the number of words it contains.

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_KDF_SLICES=%u", prog.kdf_slices_cnt);

      for (u32 i = 0; i < prog.kdf_slices_cnt; i++)
      {
        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_KDF_SL%u_V=%u -D RECIPE_KDF_SL%u_W=%u -D RECIPE_KDF_SL%u_N=%u", i, prog.kdf_slice_var[i], i, (prog.kdf_slice_start[i] - skip) / 4, i, prog.kdf_slice_len[i] / 4);
      }
    }

    u32 istores = 0;
    u32 lstores = 0;

    for (u32 c = 0; c < prog.carry_cnt; c++)
    {
      char token[16];

      if (prog.carry_has_init[c] == 1)
      {
        recipe_part_token (&prog, &prog.carry_init[c], false, dep, token, sizeof (token));

        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_I%u_SLOT=%u -D RECIPE_I%u_TOK=%s", istores, c, istores, token);

        istores++;
      }

      if (prog.carry_has_loop[c] == 1)
      {
        recipe_part_token (&prog, &prog.carry_loop[c], false, dep, token, sizeof (token));

        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_L%u_SLOT=%u -D RECIPE_L%u_TOK=%s", lstores, c, lstores, token);

        lstores++;
      }
    }

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_ISTORES=%u -D RECIPE_LSTORES=%u", istores, lstores);

    // A carried variable the loop assigns changes every iteration, at the length of its step's
    // output. One it only reads is a static part of the block templates.

    for (u32 c = 0; c < prog.carry_cnt; c++)
    {
      const bool dyn = (prog.carry_has_loop[c] == 1);

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_C%u_DYN=%u", c, (dyn == true) ? 1 : 0);

      if (dyn == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_C%u_LEN=%u", c, prog.steps[prog.carry_loop[c].idx].cut_len);
    }

    if (prog.root_var > 0) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_ROOT_VAR=%u -D RECIPE_ROOT_VFMT=%u", prog.root_var - 1, prog.root_vfmt);
  }

  for (u32 l = 0; l < prog.lits_cnt; l++)
  {
    u32 words[RECIPE_MAX_LIT / 4];

    memset (words, 0, sizeof (words));
    memcpy (words, prog.lits[l], prog.lit_lens[l]);

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_L%u_LEN=%u -D RECIPE_L%u_W0=0x%08x -D RECIPE_L%u_W1=0x%08x -D RECIPE_L%u_W2=0x%08x -D RECIPE_L%u_W3=0x%08x", l, prog.lit_lens[l], l, words[0], l, words[1], l, words[2], l, words[3]);
  }

  // Transformed copies of pass and salt name their source and four transform slots, using NONE for
  // unused slots. A and B are arguments, H holds wperm indices beyond the eighth, and L indicates
  // whether a cut has a length. See RECIPE_XRUN in the kernel include.

  if (prog.xforms_cnt > 0) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_XFORMS=%u", prog.xforms_cnt);

  for (u32 x = 0; x < prog.xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog.xforms[x];

    const char *src = "SALT";

    if (xform->src == RECIPE_PART_PASS)   src = "PASS";
    if (xform->src == RECIPE_PART_SALTD)  src = "SALTD";
    if (xform->src == RECIPE_PART_SALT2)  src = "SALT2";
    if (xform->src == RECIPE_PART_PEPPER) src = "PEPPER";
    if (xform->src == RECIPE_PART_USER)   src = "USER";

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_SRC=%s", x, src);

    len = recipe_jit_xops (buf, sizeof (buf), len, "X", x, xform->ops, xform->ops_cnt);
  }

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "%s", buf);

  return jit_build_options;
}

// Hash the parts and write the digest to raw as little endian words. Wide parts use the UTF-16LE
// update, which decodes UTF-8 as the kernel does. SHA-224 and SHA-384 use the SHA-256 and SHA-512
// code with their own initial values. Return the digest length.

static u32 recipe_hash_parts (const u32 algo, const u32 **bufs, const u32 *lens, const u32 *wides, const u32 cnt, u32 *raw)
{
  memset (raw, 0, 64);

  u32 raw_len = 0;

  if (algo == RECIPE_ALGO_MD4)
  {
    md4_ctx_t ctx;

    md4_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) md4_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               md4_update         (&ctx, bufs[i], (int) lens[i]);
    }

    md4_final (&ctx);

    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];

    raw_len = 16;
  }
  else if (algo == RECIPE_ALGO_MD5)
  {
    md5_ctx_t ctx;

    md5_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) md5_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               md5_update         (&ctx, bufs[i], (int) lens[i]);
    }

    md5_final (&ctx);

    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];

    raw_len = 16;
  }
  else if (algo == RECIPE_ALGO_SHA1)
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sha1_update_utf16le_swap (&ctx, bufs[i], (int) lens[i]);
      else               sha1_update_swap         (&ctx, bufs[i], (int) lens[i]);
    }

    sha1_final (&ctx);

    for (u32 i = 0; i < 5; i++) raw[i] = byte_swap_32 (ctx.h[i]);

    raw_len = 20;
  }
  else if ((algo == RECIPE_ALGO_SHA224) || (algo == RECIPE_ALGO_SHA256))
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    if (algo == RECIPE_ALGO_SHA224)
    {
      ctx.h[0] = SHA224M_A;
      ctx.h[1] = SHA224M_B;
      ctx.h[2] = SHA224M_C;
      ctx.h[3] = SHA224M_D;
      ctx.h[4] = SHA224M_E;
      ctx.h[5] = SHA224M_F;
      ctx.h[6] = SHA224M_G;
      ctx.h[7] = SHA224M_H;
    }

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sha256_update_utf16le_swap (&ctx, bufs[i], (int) lens[i]);
      else               sha256_update_swap         (&ctx, bufs[i], (int) lens[i]);
    }

    sha256_final (&ctx);

    raw_len = (algo == RECIPE_ALGO_SHA224) ? 28 : 32;

    for (u32 i = 0; i < (raw_len / 4); i++) raw[i] = byte_swap_32 (ctx.h[i]);
  }
  else if (algo == RECIPE_ALGO_RMD160)
  {
    ripemd160_ctx_t ctx;

    ripemd160_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) ripemd160_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               ripemd160_update         (&ctx, bufs[i], (int) lens[i]);
    }

    ripemd160_final (&ctx);

    for (u32 i = 0; i < 5; i++) raw[i] = ctx.h[i];

    raw_len = 20;
  }
  else if (algo == RECIPE_ALGO_RMD128)
  {
    ripemd128_ctx_t ctx;

    ripemd128_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) ripemd128_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               ripemd128_update         (&ctx, bufs[i], (int) lens[i]);
    }

    ripemd128_final (&ctx);

    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];

    raw_len = 16;
  }
  else if (algo == RECIPE_ALGO_RMD256)
  {
    ripemd256_ctx_t ctx;

    ripemd256_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) ripemd256_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               ripemd256_update         (&ctx, bufs[i], (int) lens[i]);
    }

    ripemd256_final (&ctx);

    for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];

    raw_len = 32;
  }
  else if (algo == RECIPE_ALGO_RMD320)
  {
    ripemd320_ctx_t ctx;

    ripemd320_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) ripemd320_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               ripemd320_update         (&ctx, bufs[i], (int) lens[i]);
    }

    ripemd320_final (&ctx);

    for (u32 i = 0; i < 10; i++) raw[i] = ctx.h[i];

    raw_len = 40;
  }
  else if ((algo == RECIPE_ALGO_SNE128) || (algo == RECIPE_ALGO_SNE256))
  {
    const u32 dlen = recipe_digest_len (algo);

    snefru_ctx_t ctx;

    snefru_init (&ctx, snefru_sbox, (int) dlen);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) snefru_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               snefru_update         (&ctx, bufs[i], (int) lens[i]);
    }

    snefru_final (&ctx);

    for (u32 i = 0; i < (dlen / 4); i++) raw[i] = byte_swap_32 (ctx.h[i]);

    raw_len = dlen;
  }
  else if (algo == RECIPE_ALGO_SHA0)
  {
    sha0_ctx_t ctx;

    sha0_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sha0_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               sha0_update         (&ctx, bufs[i], (int) lens[i]);
    }

    sha0_final (&ctx);

    for (u32 i = 0; i < 5; i++) raw[i] = byte_swap_32 (ctx.h[i]);

    raw_len = 20;
  }
  else if (algo == RECIPE_ALGO_MD2)
  {
    md2_ctx_t ctx;

    md2_init (&ctx, md2_sbox);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) md2_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               md2_update         (&ctx, bufs[i], (int) lens[i]);
    }

    md2_final (&ctx);

    for (u32 i = 0; i < 4; i++) raw[i] = ctx.h[i];

    raw_len = 16;
  }
  else if (recipe_algo_is_tiger (algo) == true)
  {
    tiger_ctx_t ctx;

    if (algo == RECIPE_ALGO_TTH) tiger_init_tth (&ctx, tiger_sbox);
    else                         tiger_init     (&ctx, tiger_sbox, (algo == RECIPE_ALGO_TIGER2) ? TIGER_PAD_TIGER2 : TIGER_PAD_TIGER);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) tiger_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               tiger_update         (&ctx, bufs[i], (int) lens[i]);
    }

    tiger_final (&ctx);

    for (u32 i = 0; i < 3; i++)
    {
      raw[(i * 2) + 0] = (u32) (ctx.h[i] >>  0);
      raw[(i * 2) + 1] = (u32) (ctx.h[i] >> 32);
    }

    raw_len = recipe_digest_len (algo);
  }
  else if (recipe_algo_is_haval (algo) == true)
  {
    const u32 idx = algo - RECIPE_ALGO_HAV128_3;

    haval_ctx_t ctx;

    haval_init (&ctx, (int) (3 + (idx % 3)), (int) (4 + (idx / 3)));

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) haval_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               haval_update         (&ctx, bufs[i], (int) lens[i]);
    }

    haval_final (&ctx);

    raw_len = 4 * (4 + (idx / 3));

    for (u32 i = 0; i < (raw_len / 4); i++) raw[i] = ctx.h[i];
  }
  else if (algo == RECIPE_ALGO_MYSQL323)
  {
    mysql323_ctx_t ctx;

    mysql323_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) mysql323_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               mysql323_update         (&ctx, bufs[i], (int) lens[i]);
    }

    mysql323_final (&ctx);

    raw[0] = byte_swap_32 (ctx.nr);
    raw[1] = byte_swap_32 (ctx.nr2);

    raw_len = 8;
  }
  else if ((algo == RECIPE_ALGO_BLAKE2B512) || (algo == RECIPE_ALGO_BLAKE2B256))
  {
    blake2b_ctx_t ctx;

    if (algo == RECIPE_ALGO_BLAKE2B256)
    {
      blake2b_256_init (&ctx);
    }
    else
    {
      blake2b_init (&ctx);
    }

    for (u32 i = 0; i < cnt; i++) blake2b_update (&ctx, bufs[i], (int) lens[i]);

    blake2b_final (&ctx);

    raw_len = (algo == RECIPE_ALGO_BLAKE2B256) ? 32 : 64;

    for (u32 i = 0; i < (raw_len / 8); i++)
    {
      raw[(i * 2) + 0] = (u32) (ctx.h[i] >>  0);
      raw[(i * 2) + 1] = (u32) (ctx.h[i] >> 32);
    }
  }
  else if (algo == RECIPE_ALGO_BLAKE2S256)
  {
    blake2s_ctx_t ctx;

    blake2s_init (&ctx);

    for (u32 i = 0; i < cnt; i++) blake2s_update (&ctx, bufs[i], (int) lens[i]);

    blake2s_final (&ctx);

    for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];

    raw_len = 32;
  }
  else if (algo == RECIPE_ALGO_SM3)
  {
    sm3_ctx_t ctx;

    sm3_init (&ctx);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sm3_update_utf16le_swap (&ctx, bufs[i], (int) lens[i]);
      else               sm3_update_swap         (&ctx, bufs[i], (int) lens[i]);
    }

    sm3_final (&ctx);

    for (u32 i = 0; i < 8; i++) raw[i] = byte_swap_32 (ctx.h[i]);

    raw_len = 32;
  }
  else if (recipe_algo_is_sha3 (algo) == true)
  {
    const u32 dlen = recipe_digest_len (algo);
    const u32 pad  = (algo >= RECIPE_ALGO_KECCAK224) ? SHA3_PAD_KECCAK : SHA3_PAD_SHA3;

    sha3_ctx_t ctx;

    sha3_init (&ctx, (int) dlen, pad);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sha3_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               sha3_update         (&ctx, bufs[i], (int) lens[i]);
    }

    sha3_final (&ctx);

    for (u32 i = 0; i < (dlen / 4); i++) raw[i] = (u32) (ctx.st[i / 2] >> ((i & 1) * 32));

    raw_len = dlen;
  }
  else if (algo == RECIPE_ALGO_SBOG256)
  {
    streebog256_ctx_t ctx;

    streebog256_init (&ctx, sbob256_sl64);

    for (u32 i = 0; i < cnt; i++) streebog256_update_swap (&ctx, bufs[i], (int) lens[i]);

    streebog256_final (&ctx);

    for (u32 i = 0; i < 4; i++)
    {
      raw[(i * 2) + 0] = (u32) (ctx.h[i] >>  0);
      raw[(i * 2) + 1] = (u32) (ctx.h[i] >> 32);
    }

    raw_len = 32;
  }
  else if (algo == RECIPE_ALGO_SBOG512)
  {
    streebog512_ctx_t ctx;

    streebog512_init (&ctx, sbob512_sl64);

    for (u32 i = 0; i < cnt; i++) streebog512_update_swap (&ctx, bufs[i], (int) lens[i]);

    streebog512_final (&ctx);

    for (u32 i = 0; i < 8; i++)
    {
      raw[(i * 2) + 0] = (u32) (ctx.h[i] >>  0);
      raw[(i * 2) + 1] = (u32) (ctx.h[i] >> 32);
    }

    raw_len = 64;
  }
  else if ((algo == RECIPE_ALGO_GOST94) || (algo == RECIPE_ALGO_GOST94_CP))
  {
    gost94_ctx_t ctx;

    gost94_init (&ctx, (algo == RECIPE_ALGO_GOST94) ? c_tables : c_tables_cryptopro);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) gost94_update_utf16le (&ctx, bufs[i], (int) lens[i]);
      else               gost94_update         (&ctx, bufs[i], (int) lens[i]);
    }

    gost94_final (&ctx);

    for (u32 i = 0; i < 8; i++) raw[i] = ctx.h[i];

    raw_len = 32;
  }
  else if (algo == RECIPE_ALGO_WRL)
  {
    whirlpool_ctx_t ctx;

    whirlpool_init (&ctx, MT0, MT1, MT2, MT3, MT4, MT5, MT6, MT7);

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) whirlpool_update_utf16le_swap (&ctx, bufs[i], (int) lens[i]);
      else               whirlpool_update_swap         (&ctx, bufs[i], (int) lens[i]);
    }

    whirlpool_final (&ctx);

    for (u32 i = 0; i < 16; i++) raw[i] = byte_swap_32 (ctx.h[i]);

    raw_len = 64;
  }
  else
  {
    sha512_ctx_t ctx;

    sha512_init (&ctx);

    if (algo == RECIPE_ALGO_SHA384)
    {
      ctx.h[0] = SHA384M_A;
      ctx.h[1] = SHA384M_B;
      ctx.h[2] = SHA384M_C;
      ctx.h[3] = SHA384M_D;
      ctx.h[4] = SHA384M_E;
      ctx.h[5] = SHA384M_F;
      ctx.h[6] = SHA384M_G;
      ctx.h[7] = SHA384M_H;
    }

    for (u32 i = 0; i < cnt; i++)
    {
      if (wides[i] == 1) sha512_update_utf16le_swap (&ctx, bufs[i], (int) lens[i]);
      else               sha512_update_swap         (&ctx, bufs[i], (int) lens[i]);
    }

    sha512_final (&ctx);

    raw_len = (algo == RECIPE_ALGO_SHA384) ? 48 : 64;

    for (u32 i = 0; i < (raw_len / 8); i++)
    {
      raw[(i * 2) + 0] = byte_swap_32 ((u32) (ctx.h[i] >> 32));
      raw[(i * 2) + 1] = byte_swap_32 ((u32) (ctx.h[i] >>  0));
    }
  }

  return raw_len;
}

// Compute HMAC from two hashes: H (key ^ opad . H (key ^ ipad . parts)). Hash keys longer than
// the block size first, then pad the key to the block size.

// Reverse the len bytes in buf, which HMAC-Streebog does to a hashed key and to its inner digest.
// See RECIPE_KW_streebog_32 in the kernel include.

static void recipe_rev_bytes (u32 *buf, const u32 len)
{
  u8 *b = (u8 *) buf;

  for (u32 i = 0; i < (len / 2); i++)
  {
    const u8 t = b[i];

    b[i] = b[len - 1 - i];

    b[len - 1 - i] = t;
  }
}

static u32 recipe_hmac_parts (const u32 algo, const u32 *key_buf, const u32 key_len, const u32 **bufs, const u32 *lens, const u32 *wides, const u32 cnt, u32 *raw)
{
  const u32 block = recipe_algo (algo)->block_len;

  const bool rev = (algo == RECIPE_ALGO_SBOG256) || (algo == RECIPE_ALGO_SBOG512);

  // up to the 144 bytes of the SHA3-224 rate

  u32 kb[36];

  memset (kb, 0, sizeof (kb));

  if (key_len > block)
  {
    const u32 zero = 0;

    const u32 key_digest_len = recipe_hash_parts (algo, &key_buf, &key_len, &zero, 1, raw);

    memcpy (kb, raw, key_digest_len);

    if (rev == true) recipe_rev_bytes (kb, key_digest_len);
  }
  else
  {
    memcpy (kb, key_buf, key_len);
  }

  u32 ipad[36];
  u32 opad[36];

  for (u32 i = 0; i < 36; i++)
  {
    ipad[i] = kb[i] ^ 0x36363636;
    opad[i] = kb[i] ^ 0x5c5c5c5c;
  }

  const u32 *ibufs[RECIPE_MAX_PARTS + 1];
  u32        ilens[RECIPE_MAX_PARTS + 1];
  u32        iwides[RECIPE_MAX_PARTS + 1];

  ibufs[0]  = ipad;
  ilens[0]  = block;
  iwides[0] = 0;

  for (u32 i = 0; i < cnt; i++)
  {
    ibufs[i + 1]  = bufs[i];
    ilens[i + 1]  = lens[i];
    iwides[i + 1] = wides[i];
  }

  const u32 inner_len = recipe_hash_parts (algo, ibufs, ilens, iwides, cnt + 1, raw);

  u32 inner[16];

  memcpy (inner, raw, sizeof (inner));

  if (rev == true) recipe_rev_bytes (inner, inner_len);

  const u32 *obufs[2]  = { opad, inner };
  const u32  olens[2]  = { block, inner_len };
  const u32  owides[2] = { 0, 0 };

  const u32 r = recipe_hash_parts (algo, obufs, olens, owides, 2, raw);

  return r;
}

// The size of the kernel's pbkdf2 state, the first member of the tmps in OpenCL/m04000-pure.cl.

u32 recipe_kdf_state_size (const recipe_prog_t *prog)
{
  u32 size = 0;

  if (prog->kdf_blocks == 0) return size;

  if (prog->kdf_algo == RECIPE_ALGO_MD5)    size = sizeof (pbkdf2_md5_state_t);
  if (prog->kdf_algo == RECIPE_ALGO_SHA1)   size = sizeof (pbkdf2_sha1_state_t);
  if (prog->kdf_algo == RECIPE_ALGO_SHA256) size = sizeof (pbkdf2_sha256_state_t);
  if (prog->kdf_algo == RECIPE_ALGO_SHA512) size = sizeof (pbkdf2_sha512_state_t);

  return size;
}

// A slow recipe's tmps use recipe_tmp_t in OpenCL/m04000-pure.cl. They contain either the pbkdf2
// state alone or carried variables, each with 64 words and a length. The pbkdf2_sha512 state has 64
// bit members, so round the size up to a multiple of 8 bytes, at least the size required by the
// kernel's struct. Return 0 for a fast recipe, which has no tmps of its own.

u64 recipe_tmp_size (const recipe_prog_t *prog)
{
  if (prog->slow == 0) return 0;

  const u64 carry_size = (prog->kdf_blocks > 0) ? 0 : ((u64) prog->carry_cnt * (64 + 1) * sizeof (u32));

  const u64 tmp_size = ((recipe_kdf_state_size (prog) + carry_size + 7) / 8) * 8;

  return tmp_size;
}

// Whether a salt from a hash line suits the recipe: valid hex or base64 if the recipe decodes it.

bool recipe_salt_valid (const recipe_prog_t *prog, const u8 *salt, const u32 salt_len)
{
  if (prog->salt_dec == RECIPE_DEC_NONE) return true;

  const bool r = recipe_decode_valid (prog->salt_dec, salt, salt_len);

  return r;
}

// Write the digest in the requested format to the 128-byte out buffer and return its length.

static u32 recipe_format (const u32 fmt, const u32 *raw, const u32 raw_len, u32 *out)
{
  memset (out, 0, 128);

  if (fmt == RECIPE_FMT_RAW)
  {
    memcpy (out, raw, raw_len);

    return raw_len;
  }

  if (fmt == RECIPE_FMT_B64)
  {
    const u32 r = recipe_b64_encode ((const u8 *) raw, raw_len, (u8 *) out);

    return r;
  }

  const char *digits = (fmt == RECIPE_FMT_HEXU) ? "0123456789ABCDEF" : "0123456789abcdef";

  const u8 *src = (const u8 *) raw;

  u8 *dst = (u8 *) out;

  for (u32 i = 0; i < raw_len; i++)
  {
    dst[(i * 2) + 0] = digits[(src[i] >> 4) & 15];
    dst[(i * 2) + 1] = digits[(src[i] >> 0) & 15];
  }

  const u32 r = raw_len * 2;

  return r;
}

// Everything a step can read on the host: pass, salt, the decoded salt, strings, step outputs,
// transformed copies and carried variables, as little endian words.

typedef struct recipe_env
{
  u32 w[RECIPE_MAX_XBYTES / 4];
  u32 pw_len;

  u32 s[RECIPE_MAX_XBYTES / 4];
  u32 salt_len;

  u32 sd[RECIPE_MAX_XBYTES / 4];
  u32 sd_len;

  u32 f[RECIPE_MAX_FIELDS][RECIPE_MAX_XBYTES / 4];
  u32 fl[RECIPE_MAX_FIELDS];

  u32 lits[RECIPE_MAX_LITS][RECIPE_MAX_LIT / 4];

  u32 outs[RECIPE_MAX_STEPS][32];
  u32 out_lens[RECIPE_MAX_STEPS];

  u32 xbufs[RECIPE_MAX_XFORMS][RECIPE_MAX_XBYTES / 4];
  u32 xlens[RECIPE_MAX_XFORMS];

  u32 vb[RECIPE_MAX_CARRY][RECIPE_MAX_XBYTES / 4];
  u32 vl[RECIPE_MAX_CARRY];

  u32 raw[16];
  u32 raw_len;

} recipe_env_t;

static void recipe_env_part (const recipe_prog_t *prog, const recipe_env_t *env, const recipe_part_t *part, const u32 **buf, u32 *len)
{
  *buf = env->w;
  *len = 0;

  if (part->kind == RECIPE_PART_PASS)  { *buf = env->w;               *len = env->pw_len;                 }
  if (part->kind == RECIPE_PART_SALT)  { *buf = env->s;               *len = env->salt_len;               }
  if (part->kind == RECIPE_PART_SALTD) { *buf = env->sd;              *len = env->sd_len;                 }
  if (part->kind == RECIPE_PART_LIT)   { *buf = env->lits[part->idx]; *len = prog->lit_lens[part->idx];   }
  if (part->kind == RECIPE_PART_STEP)  { *buf = env->outs[part->idx]; *len = env->out_lens[part->idx];    }
  if (part->kind == RECIPE_PART_XFORM) { *buf = env->xbufs[part->idx]; *len = env->xlens[part->idx];      }
  if (part->kind == RECIPE_PART_VAR)   { *buf = env->vb[part->idx];   *len = env->vl[part->idx];          }

  if (recipe_is_field (part->kind) == true)
  {
    const u32 f = part->kind - RECIPE_PART_SALT2;

    *buf = env->f[f];
    *len = env->fl[f];
  }
}

// Copy a part into carried variable c, as the init and loop kernels do.

static void recipe_env_store (const recipe_prog_t *prog, recipe_env_t *env, const recipe_part_t *part, const u32 c)
{
  const u32 *buf = NULL;
  u32        len = 0;

  recipe_env_part (prog, env, part, &buf, &len);

  u32 tmp[RECIPE_MAX_XBYTES / 4];

  memset (tmp, 0, sizeof (tmp));
  memcpy (tmp, buf, MIN (len, RECIPE_MAX_XBYTES));

  memcpy (env->vb[c], tmp, sizeof (tmp));

  env->vl[c] = len;
}

// Host AES for the self-test uses the core's own block functions in emu_inc_cipher_aes.c. The AES
// modes are written out here instead of taken from OpenCL/inc_cipher_aes-modes.cl, so a fault in
// the kernel's mode implementation causes a self-test failure. The uppercase block functions take
// their input as big endian words.

static void recipe_aes_key (u32 *ks, const u32 *ukey, const u32 key_len, const bool dec)
{
  if (dec == false)
  {
    if      (key_len == 16) AES128_set_encrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3);
    else if (key_len == 24) AES192_set_encrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3);
    else                    AES256_set_encrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3);
  }
  else
  {
    if      (key_len == 16) AES128_set_decrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);
    else if (key_len == 24) AES192_set_decrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);
    else                    AES256_set_decrypt_key (ks, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);
  }
}

static void recipe_aes_block (const u32 *ks, const u32 key_len, const bool dec, const u32 *in, u32 *out)
{
  if (dec == false)
  {
    if      (key_len == 16) AES128_encrypt (ks, in, out, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) te4);
    else if (key_len == 24) AES192_encrypt (ks, in, out, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) te4);
    else                    AES256_encrypt (ks, in, out, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) te4);
  }
  else
  {
    if      (key_len == 16) AES128_decrypt (ks, in, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);
    else if (key_len == 24) AES192_decrypt (ks, in, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);
    else                    AES256_decrypt (ks, in, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);
  }
}

// For an AES step, place each data part at its fixed length and pad it with zero bytes. Prepare the
// key and IV in the same way. The raw buffer receives output as little endian words. A failed
// aes_unwrap check leaves the output zero, as in the kernel. Return the length of the output.

// Compute the bytes of an xor, and or or call in the same way as RECIPE_STEP_BOP in the kernel
// include. The raw buffer holds RECIPE_MAX_BOP bytes.

static u32 recipe_env_bop (const recipe_step_t *step, const u32 **bufs, const u32 *lens, u32 *raw)
{
  const u8 *a = (const u8 *) bufs[0];
  const u8 *b = (const u8 *) bufs[1];

  const u32 la = lens[0];
  const u32 lb = lens[1];

  u32 n = MIN (MAX (la, lb), RECIPE_MAX_BOP);

  if ((la == 0) || (lb == 0)) n = 0;

  memset (raw, 0, RECIPE_MAX_BOP);

  u8 *r = (u8 *) raw;

  for (u32 i = 0; i < n; i++)
  {
    const u8 x = a[i % la];
    const u8 y = b[i % lb];

    u8 v = x ^ y;

    if (step->aop == RECIPE_BOP_AND) v = x & y;
    if (step->aop == RECIPE_BOP_OR)  v = x | y;

    r[i] = v;
  }

  return n;
}

static u32 recipe_env_aes (const recipe_prog_t *prog, const recipe_env_t *env, const recipe_step_t *step, const u32 **bufs, const u32 *lens, u32 *raw)
{
  u32 dw[(RECIPE_MAX_AES + 8) / 4];

  memset (dw, 0, sizeof (dw));

  u32 off = 0;

  for (u32 i = 0; i < step->parts_cnt; i++)
  {
    memcpy ((u8 *) dw + off, bufs[i], MIN (lens[i], step->part_lens[i]));

    off += step->part_lens[i];
  }

  const u32 *key     = NULL;
  u32        key_len = 0;

  recipe_env_part (prog, env, &step->key, &key, &key_len);

  u32 kw[8];

  memset (kw, 0, sizeof (kw));
  memcpy (kw, key, MIN (key_len, step->key_len));

  u32 ivw[4];

  memset (ivw, 0, sizeof (ivw));

  const bool cbc = (step->aop == RECIPE_AES_CBC_ENC) || (step->aop == RECIPE_AES_CBC_DEC);

  if (cbc == true)
  {
    const u32 *iv     = NULL;
    u32        iv_len = 0;

    recipe_env_part (prog, env, &step->iv, &iv, &iv_len);

    memcpy (ivw, iv, MIN (iv_len, 16));
  }

  u32 ukey[8];

  for (u32 i = 0; i < 8; i++) ukey[i] = byte_swap_32 (kw[i]);

  const bool unwrap = (step->aop == RECIPE_AES_UNWRAP) || (step->aop == RECIPE_AES_UNWRAP_A);

  const bool dec = (step->aop == RECIPE_AES_CBC_DEC) || (unwrap == true);

  u32 ks[60];

  recipe_aes_key (ks, ukey, step->key_len, dec);

  memset (raw, 0, 64);

  if (unwrap == true)
  {
    const u32 n = (step->data_len / 8) - 1;

    u32 a0 = byte_swap_32 (dw[0]);
    u32 a1 = byte_swap_32 (dw[1]);

    u32 r[(RECIPE_MAX_AES / 4)];

    for (u32 i = 0; i < (n * 2); i++) r[i] = byte_swap_32 (dw[i + 2]);

    for (u32 round = 0; round < 6; round++)
    {
      const u32 j = 5 - round;

      for (u32 i = n; i >= 1; i--)
      {
        const u32 x[4] = { a0, a1 ^ ((n * j) + i), r[((i - 1) * 2) + 0], r[((i - 1) * 2) + 1] };

        u32 y[4];

        recipe_aes_block (ks, step->key_len, true, x, y);

        a0 = y[0];
        a1 = y[1];

        r[((i - 1) * 2) + 0] = y[2];
        r[((i - 1) * 2) + 1] = y[3];
      }
    }

    if (step->aop == RECIPE_AES_UNWRAP_A)
    {
      raw[0] = byte_swap_32 (a0);
      raw[1] = byte_swap_32 (a1);

      return 8;
    }

    if ((a0 == 0xa6a6a6a6) && (a1 == 0xa6a6a6a6))
    {
      for (u32 i = 0; i < (n * 2); i++) raw[i] = byte_swap_32 (r[i]);
    }

    const u32 r_len = n * 8;

    return r_len;
  }

  u32 c[4];

  for (u32 i = 0; i < 4; i++) c[i] = byte_swap_32 (ivw[i]);

  for (u32 b = 0; b < (step->data_len / 16); b++)
  {
    u32 x[4];

    for (u32 i = 0; i < 4; i++) x[i] = byte_swap_32 (dw[(b * 4) + i]);

    u32 y[4];

    if (step->aop == RECIPE_AES_CBC_ENC)
    {
      for (u32 i = 0; i < 4; i++) x[i] ^= c[i];

      recipe_aes_block (ks, step->key_len, false, x, y);

      for (u32 i = 0; i < 4; i++) c[i] = y[i];
    }
    else if (step->aop == RECIPE_AES_CBC_DEC)
    {
      recipe_aes_block (ks, step->key_len, true, x, y);

      for (u32 i = 0; i < 4; i++) y[i] ^= c[i];

      for (u32 i = 0; i < 4; i++) c[i] = x[i];
    }
    else
    {
      recipe_aes_block (ks, step->key_len, false, x, y);
    }

    for (u32 i = 0; i < 4; i++) raw[(b * 4) + i] = byte_swap_32 (y[i]);
  }

  const u32 r_len = step->data_len;

  return r_len;
}

// Run the steps of one kernel in order. RECIPE_SEC_MAIN runs a recipe without a loop.

static void recipe_eval_sec (const recipe_prog_t *prog, recipe_env_t *env, const u32 sec)
{
  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    const recipe_step_t *step = &prog->steps[k];

    if (step->sec != sec) continue;

    const u32 *bufs[RECIPE_MAX_PARTS];
    u32        lens[RECIPE_MAX_PARTS];
    u32        wides[RECIPE_MAX_PARTS];

    for (u32 i = 0; i < step->parts_cnt; i++)
    {
      recipe_env_part (prog, env, &step->parts[i], &bufs[i], &lens[i]);

      wides[i] = step->parts[i].wide;
    }

    if (step->kind == RECIPE_KIND_AES)
    {
      env->raw_len = recipe_env_aes (prog, env, step, bufs, lens, env->raw);
    }
    else if (step->kind == RECIPE_KIND_BOP)
    {
      env->raw_len = recipe_env_bop (step, bufs, lens, env->raw);
    }
    else if (step->kind == RECIPE_KIND_XFRM)
    {
      // As in RECIPE_STEP_XFRM in the kernel include, raw receives the first 64 bytes. The output
      // in raw bytes can contain up to 128 bytes.

      u8 x[RECIPE_MAX_XBYTES];

      memset (x, 0, sizeof (x));
      memcpy (x, bufs[0], lens[0]);

      u32 l = lens[0];

      for (u32 i = 0; i < step->xops_cnt; i++) l = recipe_xop_apply (&step->xops[i], x, l);

      memcpy (env->raw, x, sizeof (env->raw));

      env->raw_len = MIN (l, (u32) sizeof (env->raw));

      if (step->fmt == RECIPE_FMT_RAW)
      {
        memcpy (env->outs[k], x, sizeof (env->outs[k]));

        env->out_lens[k] = l;

        continue;
      }
    }
    else if (step->kind == RECIPE_KIND_HMAC)
    {
      const u32 *key_buf = NULL;
      u32        key_len = 0;

      recipe_env_part (prog, env, &step->key, &key_buf, &key_len);

      env->raw_len = recipe_hmac_parts (step->algo, key_buf, key_len, bufs, lens, wides, step->parts_cnt, env->raw);
    }
    else
    {
      env->raw_len = recipe_hash_parts (step->algo, bufs, lens, wides, step->parts_cnt, env->raw);
    }

    // Repetition with ^N hashes each round's output in the format set by the output suffix.

    for (u32 j = 1; j < step->iter; j++)
    {
      const u32 chain_len = recipe_format (step->chain_fmt, env->raw, env->raw_len, env->outs[k]);

      const u32 *chain_buf = env->outs[k];

      const u32 chain_wide = 0;

      env->raw_len = recipe_hash_parts (step->algo, &chain_buf, &chain_len, &chain_wide, 1, env->raw);
    }

    const u32 out_len = recipe_format (step->fmt, env->raw, env->raw_len, env->outs[k]);

    // The output of xor, and or or that is not cut, and the output of transforms, retain their
    // current lengths at run time.

    if (((step->kind == RECIPE_KIND_BOP) && (recipe_bop_cuts (step) == false)) || (step->kind == RECIPE_KIND_XFRM))
    {
      env->out_lens[k] = out_len;

      continue;
    }

    u8 *o = (u8 *) env->outs[k];

    memmove (o, o + step->cut_start, step->cut_len);
    memset  (o + step->cut_len, 0, 128 - step->cut_len);

    env->out_lens[k] = step->cut_len;
  }
}

// Host pbkdf2 is built from recipe_hmac_parts () instead of OpenCL/inc_pbkdf2.cl so a fault in
// either implementation causes a self-test failure. Store the derived key in its carried variable
// using the call's output format, matching the format stored by the comp kernel.

static void recipe_env_kdf (const recipe_prog_t *prog, recipe_env_t *env)
{
  const u32 *key     = NULL;
  u32        key_len = 0;

  recipe_env_part (prog, env, &prog->kdf_key, &key, &key_len);

  const u32 *salt     = NULL;
  u32        salt_len = 0;

  recipe_env_part (prog, env, &prog->kdf_salt, &salt, &salt_len);

  const u32 hlen = recipe_digest_len (prog->kdf_algo);

  // The salt, then the block number as 4 big endian bytes.

  u32 msg[(RECIPE_MAX_XBYTES / 4) + 1];

  memset (msg, 0, sizeof (msg));
  memcpy (msg, salt, salt_len);

  const u32 msg_len = salt_len + 4;

  u8 *m = (u8 *) msg;

  u32 dk[32];

  memset (dk, 0, sizeof (dk));

  for (u32 b = 0; b < prog->kdf_blocks; b++)
  {
    const u32 bn = b + 1;

    m[msg_len - 4] = (bn >> 24) & 255;
    m[msg_len - 3] = (bn >> 16) & 255;
    m[msg_len - 2] = (bn >>  8) & 255;
    m[msg_len - 1] = (bn >>  0) & 255;

    const u32 *bufs[1]  = { msg };
    const u32  lens[1]  = { msg_len };
    const u32  wides[1] = { 0 };

    u32 u[16];

    recipe_hmac_parts (prog->kdf_algo, key, key_len, bufs, lens, wides, 1, u);

    u32 t[16];

    memcpy (t, u, sizeof (t));

    for (u32 n = 0; n < prog->loop_cnt; n++)
    {
      const u32 *ubufs[1] = { u };
      const u32  ulens[1] = { hlen };

      u32 next[16];

      recipe_hmac_parts (prog->kdf_algo, key, key_len, ubufs, ulens, wides, 1, next);

      memcpy (u, next, sizeof (u));

      for (u32 i = 0; i < 16; i++) t[i] ^= u[i];
    }

    memcpy ((u8 *) dk + (b * hlen), t, hlen);
  }

  u32 text[32];

  const u32 fmt      = (prog->kdf_raw == 1) ? RECIPE_FMT_RAW : prog->kdf_fmt;
  const u32 text_len = recipe_format (fmt, dk, prog->kdf_dklen, text);

  memset (env->vb[prog->kdf_out], 0, sizeof (env->vb[prog->kdf_out]));
  memcpy (env->vb[prog->kdf_out], text, text_len);

  env->vl[prog->kdf_out] = text_len;

  for (u32 i = 0; i < prog->kdf_slices_cnt; i++)
  {
    const u32 v = prog->kdf_slice_var[i];

    memset (env->vb[v], 0, sizeof (env->vb[v]));
    memcpy (env->vb[v], (const u8 *) dk + prog->kdf_slice_start[i], prog->kdf_slice_len[i]);

    env->vl[v] = prog->kdf_slice_len[i];
  }
}

// Pack field into its slot of salt_buf_pc, specified by RECIPE_FIELD_WORDS, and pack its length
// into the last word. The caller must keep len at or below RECIPE_FIELD_MAX.

void recipe_field_set (u32 *fields, const u32 field, const u8 *buf, const u32 len)
{
  u8 *slot = (u8 *) (fields + (field * RECIPE_FIELD_WORDS));

  memset (slot, 0, RECIPE_FIELD_MAX);
  memcpy (slot, buf, len);

  u8 *lens = (u8 *) (fields + RECIPE_FIELD_LENS);

  lens[field] = (u8) len;
}

// Unpack field into buf, which holds RECIPE_FIELD_MAX bytes, and return its length.

u32 recipe_field_get (const u32 *fields, const u32 field, u8 *buf)
{
  const u8 *lens = (const u8 *) (fields + RECIPE_FIELD_LENS);

  const u32 len = MIN (lens[field], RECIPE_FIELD_MAX);

  memcpy (buf, fields + (field * RECIPE_FIELD_WORDS), len);

  return len;
}

// Evaluate the recipe on the host for the self-test, using emulated kernel functions. A device
// self-test failure therefore points at that device's build of the kernel rather than at the recipe.
// The raw buffer receives the final digest as little endian words, up to 64 bytes. Return its
// length. The out buffer receives up to 128 bytes in the hash line's format. A loop runs the same
// number of iterations here as on the device. Its count therefore determines the self-test's
// running time on one CPU core.

u32 recipe_eval (const recipe_prog_t *prog, const u8 *pw, const u32 pw_len, const u8 *salt, const u32 salt_len, const u32 *fields, u32 *raw, u8 *out, u32 *out_len)
{
  recipe_env_t *env = (recipe_env_t *) hccalloc (1, sizeof (recipe_env_t));

  env->pw_len   = MIN (pw_len,   RECIPE_MAX_XBYTES);
  env->salt_len = MIN (salt_len, RECIPE_MAX_XBYTES);

  memcpy (env->w, pw,   env->pw_len);
  memcpy (env->s, salt, env->salt_len);

  // salt2, pepper and user, packed as in salt_buf_pc.

  if (fields != NULL)
  {
    for (u32 f = 0; f < RECIPE_MAX_FIELDS; f++) env->fl[f] = recipe_field_get (fields, f, (u8 *) env->f[f]);
  }

  for (u32 l = 0; l < prog->lits_cnt; l++) memcpy (env->lits[l], prog->lits[l], prog->lit_lens[l]);

  // The decoded salt of fromhex (salt) and frombase64 (salt).

  if (prog->salt_dec != RECIPE_DEC_NONE) env->sd_len = recipe_decode (prog->salt_dec, salt, env->salt_len, (u8 *) env->sd);

  // Prepare transformed copies of pass and salt.

  for (u32 x = 0; x < prog->xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog->xforms[x];

    const u32 *src     = env->s;
    u32        src_len = env->salt_len;

    if (xform->src == RECIPE_PART_PASS)  { src = env->w;  src_len = env->pw_len; }
    if (xform->src == RECIPE_PART_SALTD) { src = env->sd; src_len = env->sd_len; }

    if (recipe_is_field (xform->src) == true)
    {
      src     = env->f[xform->src - RECIPE_PART_SALT2];
      src_len = env->fl[xform->src - RECIPE_PART_SALT2];
    }

    memcpy (env->xbufs[x], src, RECIPE_MAX_XBYTES);

    env->xlens[x] = recipe_xform_apply (xform, (u8 *) env->xbufs[x], src_len);
  }

  if (prog->slow == 0)
  {
    recipe_eval_sec (prog, env, RECIPE_SEC_MAIN);
  }
  else
  {
    recipe_eval_sec (prog, env, RECIPE_SEC_INIT);

    for (u32 c = 0; c < prog->carry_cnt; c++)
    {
      if (prog->carry_has_init[c] == 1) recipe_env_store (prog, env, &prog->carry_init[c], c);
    }

    // A pbkdf2 recipe runs its iterations in recipe_env_kdf () and has no loop steps.

    if (prog->kdf_blocks > 0)
    {
      recipe_env_kdf (prog, env);
    }
    else
    {
      for (u32 n = 0; n < prog->loop_cnt; n++)
      {
        recipe_eval_sec (prog, env, RECIPE_SEC_LOOP);

        for (u32 c = 0; c < prog->carry_cnt; c++)
        {
          if (prog->carry_has_loop[c] == 1) recipe_env_store (prog, env, &prog->carry_loop[c], c);
        }
      }
    }

    recipe_eval_sec (prog, env, RECIPE_SEC_COMP);
  }

  if (prog->root_var > 0)
  {
    // The result is a carried variable: decode its stored text to the digest bytes, then write
    // them as the hash line does.

    const u32 c = prog->root_var - 1;

    u32 dig[RECIPE_MAX_XBYTES / 4];

    memset (dig, 0, sizeof (dig));

    u32 dig_len = MIN (env->vl[c], 64);

    if (prog->root_vfmt == RECIPE_FMT_RAW) memcpy (dig, env->vb[c], dig_len);

    if ((prog->root_vfmt == RECIPE_FMT_HEX) || (prog->root_vfmt == RECIPE_FMT_HEXU)) dig_len = recipe_decode (RECIPE_DEC_HEX, (const u8 *) env->vb[c], env->vl[c], (u8 *) dig);

    if (prog->root_vfmt == RECIPE_FMT_B64) dig_len = recipe_decode (RECIPE_DEC_B64, (const u8 *) env->vb[c], env->vl[c], (u8 *) dig);

    dig_len = MIN (dig_len, 64);

    memcpy (env->raw, dig, 64);

    env->raw_len = dig_len;

    u32 text[32];

    *out_len = recipe_format (prog->root_fmt, dig, dig_len, text);

    memcpy (out, text, *out_len);
  }
  else
  {
    const u32 last = prog->root_step;

    memcpy (out, env->outs[last], env->out_lens[last]);

    *out_len = env->out_lens[last];
  }

  memcpy (raw, env->raw, sizeof (env->raw));

  const u32 r = env->raw_len;

  hcfree (env);

  return r;
}
