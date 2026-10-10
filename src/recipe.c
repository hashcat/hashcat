/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "emu_inc_hash_md4.h"
#include "emu_inc_hash_md5.h"
#include "emu_inc_hash_sha1.h"
#include "emu_inc_hash_sha256.h"
#include "emu_inc_hash_sha512.h"
#include "emu_inc_hash_ripemd160.h"
#include "emu_inc_hash_blake2b.h"
#include "emu_inc_hash_blake2s.h"
#include "emu_inc_hash_sm3.h"
#include "recipe.h"

// Parse the recipe into a small tree, then convert it to steps. The tree preserves the position of
// each transform. Step generation resolves how the transforms affect each hash call or literal.

#define RECIPE_MAX_NODES  64
#define RECIPE_MAX_KIDS   8
#define RECIPE_MAX_WRAP   8
#define RECIPE_MAX_SRCLIT 64

typedef enum recipe_node_kind
{
  RECIPE_NODE_PASS  = 1,
  RECIPE_NODE_SALT  = 2,
  RECIPE_NODE_LIT   = 3,
  RECIPE_NODE_HASH  = 4,
  RECIPE_NODE_CAT   = 5,
  RECIPE_NODE_UPPER = 6,
  RECIPE_NODE_LOWER = 7,
  RECIPE_NODE_HEX   = 8,
  RECIPE_NODE_CUT   = 9,
  RECIPE_NODE_UTF16 = 10,
  RECIPE_NODE_HMAC  = 11,
  RECIPE_NODE_XOP   = 12,

} recipe_node_kind_t;

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

} recipe_node_t;

typedef struct recipe_parser
{
  recipe_prog_t *prog;

  const char *src;
  u32 pos;

  recipe_node_t nodes[RECIPE_MAX_NODES];
  u32         nodes_cnt;

} recipe_parser_t;

// Hash families use their hx names. HMAC pads keys to the family's block size. BLAKE2 has no
// UTF-16 update functions in the kernel includes, so it cannot accept utf16le yet. The be flag
// marks families that read input as big endian words.

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
  { "md4",        RECIPE_ALGO_MD4,        16,  64, true,  false },
  { "md5",        RECIPE_ALGO_MD5,        16,  64, true,  false },
  { "sha1",       RECIPE_ALGO_SHA1,       20,  64, true,  true  },
  { "sha224",     RECIPE_ALGO_SHA224,     28,  64, true,  true  },
  { "sha256",     RECIPE_ALGO_SHA256,     32,  64, true,  true  },
  { "sha384",     RECIPE_ALGO_SHA384,     48, 128, true,  true  },
  { "sha512",     RECIPE_ALGO_SHA512,     64, 128, true,  true  },
  { "rmd160",     RECIPE_ALGO_RMD160,     20,  64, true,  false },
  { "blake2b512", RECIPE_ALGO_BLAKE2B512, 64, 128, false, false },
  { "blake2b256", RECIPE_ALGO_BLAKE2B256, 32, 128, false, false },
  { "blake2s256", RECIPE_ALGO_BLAKE2S256, 32,  64, false, false },
  { "sm3",        RECIPE_ALGO_SM3,        32,  64, true,  true  },
};

static const u32 RECIPE_ALGOS_CNT = sizeof (RECIPE_ALGOS) / sizeof (recipe_algo_entry_t);

// Kernel names for transforms on a copy. See RECIPE_XOP_* in the kernel include.

static const char *RECIPE_XOP_NAMES[] = { "NONE", "UPPER", "LOWER", "HEX", "REV", "ROTATE", "CAP", "ROT13", "PAD", "BSWAP32", "WPERM", "CUT" };

static const char *RECIPE_KNOWN = "mode 4000 supports md4, md5, sha1, sha224, sha256, sha384, sha512, rmd160, blake2b512, blake2b256, blake2s256, sm3, their hmac_ forms, upper, lower, hex, cut, trunc, rev, rotate, cap, rot13, pad, bswap32, wperm and utf16le";

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

static void recipe_skip_ws (recipe_parser_t *p)
{
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

static u32 recipe_ident (recipe_parser_t *p, char *buf, const u32 buf_size)
{
  recipe_skip_ws (p);

  u32 len = 0;

  while (recipe_is_word (p->src[p->pos]) == true)
  {
    if (len < (buf_size - 1))
    {
      buf[len] = p->src[p->pos];

      len++;
    }

    p->pos++;
  }

  buf[len] = 0;

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

// Split a hash function name into its family and output suffix: md5, md5_hex, md5_bin or md5_uc.
// The suffixes _b64 and _mcf apply only to families that mode 4000 does not support.

static bool recipe_hash_name (const char *name, u32 *algo, u32 *role)
{
  for (u32 i = 0; i < RECIPE_ALGOS_CNT; i++)
  {
    const char *base = RECIPE_ALGOS[i].name;

    const size_t base_len = strlen (base);

    if (strncmp (name, base, base_len) != 0) continue;

    const char *suffix = name + base_len;

    bool found = true;

    if      (strcmp (suffix, "")     == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_hex") == 0) *role = RECIPE_FMT_HEX;
    else if (strcmp (suffix, "_bin") == 0) *role = RECIPE_FMT_RAW;
    else if (strcmp (suffix, "_uc")  == 0) *role = RECIPE_FMT_HEXU;
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
// pad (x, N) and wperm (x, w0, w1, ...). The transforms rev, rot13 and bswap32 take only x.

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

static u32 recipe_parse_call (recipe_parser_t *p, const char *name, const u32 name_pos)
{
  u32 algo = 0;
  u32 role = 0;

  // HMAC calls, such as hmac_md5 (key, message), use the same output suffixes as hash calls.

  const bool hmac_blake2s = (strcmp (name, "hmac_blake2s") == 0);

  if (hmac_blake2s == true)
  {
    algo = RECIPE_ALGO_BLAKE2S256;
    role = RECIPE_FMT_HEX;
  }

  if ((hmac_blake2s == true) || ((strncmp (name, "hmac_", 5) == 0) && (recipe_hash_name (name + 5, &algo, &role) == true)))
  {
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
  else if (strcmp (name, "cut")   == 0) kind = RECIPE_NODE_CUT;
  else if (strcmp (name, "trunc") == 0) kind = RECIPE_NODE_CUT;
  else if (strcmp (name, "utf16le") == 0) kind = RECIPE_NODE_UTF16;

  u32 xop = 0;

  if      (strcmp (name, "rev")     == 0) xop = RECIPE_XOP_REV;
  else if (strcmp (name, "rotate")  == 0) xop = RECIPE_XOP_ROTATE;
  else if (strcmp (name, "cap")     == 0) xop = RECIPE_XOP_CAP;
  else if (strcmp (name, "rot13")   == 0) xop = RECIPE_XOP_ROT13;
  else if (strcmp (name, "pad")     == 0) xop = RECIPE_XOP_PAD;
  else if (strcmp (name, "bswap32") == 0) xop = RECIPE_XOP_BSWAP32;
  else if (strcmp (name, "wperm")   == 0) xop = RECIPE_XOP_WPERM;

  if (xop != 0) return recipe_parse_xop (p, xop, name, name_pos);

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

  recipe_skip_ws (p);

  if ((p->src[p->pos] == '(') || (p->src[p->pos] == '^')) return recipe_parse_call (p, name, start);

  u32 kind = 0;

  if      (strcmp (name, "pass") == 0) kind = RECIPE_NODE_PASS;
  else if (strcmp (name, "salt") == 0) kind = RECIPE_NODE_SALT;

  if (kind == 0)
  {
    if ((strcmp (name, "salt2") == 0) || (strcmp (name, "pepper") == 0) || (strcmp (name, "user") == 0))
    {
      recipe_fail_at (p, start, "mode 4000 has no salt2, pepper or user, only pass and salt");
    }
    else
    {
      recipe_fail_at (p, start, "unknown variable, mode 4000 has pass and salt");
    }

    return 0;
  }

  const u32 id = recipe_new_node (p, kind, start);

  if (id == 0) { recipe_fail (p, "the recipe is too long"); return 0; }

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

// Apply byte transforms to string literals at compile time and to copies during the host self-test.
// The buffer holds RECIPE_MAX_XBYTES bytes and remains zeroed past len. Return the new length.

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

// Check that a copy of len bytes fits RECIPE_MAX_XBYTES after every transform. Only hex grows it.

static bool recipe_xform_fits (const recipe_xform_t *xform, const u32 len)
{
  u32 r = len;

  for (u32 i = 0; i < xform->ops_cnt; i++)
  {
    if ((xform->ops[i].op == RECIPE_XOP_HEX) && (r > (RECIPE_MAX_XBYTES / 2))) return false;

    r = recipe_xop_len (&xform->ops[i], r);
  }

  return true;
}

static bool recipe_lower_lit (recipe_parser_t *p, const recipe_node_t *node, const recipe_wrap_t *wrap, recipe_step_t *step)
{
  u8  buf[RECIPE_MAX_XBYTES];
  u32 len = node->lit_len;

  memset (buf, 0, sizeof (buf));
  memcpy (buf, node->lit, len);

  for (u32 w = wrap->cnt; w > 0; w--)
  {
    const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

    if (t->kind == RECIPE_NODE_UTF16)
    {
      // For ASCII, UTF-16LE adds a zero byte after each input byte.

      if ((len * 2) > sizeof (buf)) return recipe_fail_at (p, node->pos, "string too long for utf16le");

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

    recipe_xop_entry_t op;

    recipe_xop_of (t, &op);

    if ((op.op == RECIPE_XOP_HEX) && ((len * 2) > sizeof (buf))) return recipe_fail_at (p, node->pos, "string too long for hex");

    len = recipe_xop_apply (&op, buf, len);
  }

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

// Append expression parts to the current step. The transforms upper, lower, hex, rot13 and utf16le
// apply to each element of a concatenation. Other transforms accept only a single element.

static bool recipe_lower_parts (recipe_parser_t *p, const u32 id, const recipe_wrap_t *wrap, recipe_step_t *step)
{
  const recipe_node_t *node = recipe_node (p, id);

  if (node->kind == RECIPE_NODE_CAT)
  {
    for (u32 w = 0; w < wrap->cnt; w++)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w]);

      if (t->kind == RECIPE_NODE_CUT) return recipe_fail_at (p, t->pos, "cut and trunc of a concatenation are not supported");

      if ((t->kind == RECIPE_NODE_XOP) && (t->xop.op != RECIPE_XOP_ROT13)) return recipe_fail_at (p, t->pos, "rev, rotate, cap, pad, bswap32 and wperm of a concatenation are not supported");
    }

    for (u32 i = 0; i < node->kids_cnt; i++)
    {
      if (recipe_lower_parts (p, node->kids[i], wrap, step) == false) return false;
    }

    return true;
  }

  if ((node->kind == RECIPE_NODE_UPPER) || (node->kind == RECIPE_NODE_LOWER) || (node->kind == RECIPE_NODE_HEX) || (node->kind == RECIPE_NODE_CUT) || (node->kind == RECIPE_NODE_UTF16) || (node->kind == RECIPE_NODE_XOP))
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

  // Transforming pass or salt creates a copy. See recipe_xform_t. The kernel decodes UTF-8 while
  // hashing the copy, so utf16le must be the outermost transform.

  if ((node->kind == RECIPE_NODE_PASS) || (node->kind == RECIPE_NODE_SALT))
  {
    const u32 src = (node->kind == RECIPE_NODE_PASS) ? RECIPE_PART_PASS : RECIPE_PART_SALT;

    bool wide  = false;
    u32  outer = 0;

    if ((wrap->cnt > 0) && (recipe_node (p, wrap->ids[0])->kind == RECIPE_NODE_UTF16))
    {
      wide  = true;
      outer = 1;
    }

    part->wide = (wide == true) ? 1 : 0;

    if (wrap->cnt == outer)
    {
      part->kind = src;
      part->idx  = 0;

      step->parts_cnt++;

      return true;
    }

    recipe_xform_t xf;

    memset (&xf, 0, sizeof (xf));

    xf.src = src;

    for (u32 w = wrap->cnt; w > outer; w--)
    {
      const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

      if (t->kind == RECIPE_NODE_UTF16) return recipe_fail_at (p, t->pos, "utf16le of pass or salt has to be the outermost transform");

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

static bool recipe_lower_hash (recipe_parser_t *p, const u32 id, const recipe_wrap_t *wrap, u32 *step_out, bool *wide_out)
{
  const recipe_node_t *node = recipe_node (p, id);

  recipe_step_t step;

  memset (&step, 0, sizeof (step));

  step.kind      = (node->kind == RECIPE_NODE_HMAC) ? RECIPE_KIND_HMAC : RECIPE_KIND_HASH;
  step.algo      = node->algo;
  step.chain_fmt = node->role;
  step.iter      = node->iter;

  const recipe_wrap_t none = { .cnt = 0 };

  if (step.kind == RECIPE_KIND_HMAC)
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

  if (recipe_algo (node->algo)->utf16 == false)
  {
    for (u32 i = 0; i < step.parts_cnt; i++)
    {
      if (step.parts[i].wide == 1) return recipe_fail_at (p, node->pos, "utf16le cannot feed blake2 yet");
    }
  }

  const u32 digest_len = recipe_digest_len (node->algo);

  u32  fmt   = node->role;
  u32  start = 0;
  u32  len   = (fmt == RECIPE_FMT_RAW) ? digest_len : (digest_len * 2);
  bool wide  = false;

  for (u32 w = wrap->cnt; w > 0; w--)
  {
    const recipe_node_t *t = recipe_node (p, wrap->ids[w - 1]);

    if (t->kind == RECIPE_NODE_CUT)
    {
      u32 s = 0;
      u32 l = 0;

      recipe_resolve_cut (t, len, &s, &l);

      start += s;
      len    = l;
    }
    else if (t->kind == RECIPE_NODE_HEX)
    {
      if (fmt != RECIPE_FMT_RAW) return recipe_fail_at (p, t->pos, "hex of a hex string is not supported, hex takes a _bin hash call");

      fmt    = RECIPE_FMT_HEX;
      start *= 2;
      len   *= 2;
    }
    else if (t->kind == RECIPE_NODE_XOP)
    {
      return recipe_fail_at (p, t->pos, "mode 4000 applies rev, rotate, cap, rot13, pad, bswap32 and wperm to pass, salt and strings, not yet to a hash output");
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
      if (fmt == RECIPE_FMT_RAW) return recipe_fail_at (p, t->pos, "upper and lower of raw bytes are not supported");

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

  // The kernel passes slices as words, so the start must be word-aligned.

  if ((start % 4) != 0) return recipe_fail_at (p, node->pos, "mode 4000 needs cut to start at a multiple of 4 bytes");

  step.fmt       = fmt;
  step.cut_start = start;
  step.cut_len   = len;

  *wide_out = wide;

  recipe_prog_t *prog = p->prog;

  if (prog->steps_cnt >= RECIPE_MAX_STEPS) return recipe_fail_at (p, node->pos, "more than 8 hash calls");

  prog->steps[prog->steps_cnt] = step;

  *step_out = prog->steps_cnt;

  prog->steps_cnt++;

  return true;
}

// A part depends on the candidate if it is pass, a transformed copy of pass, or the output of a
// step that depends on pass.

static bool recipe_part_dep_on (const recipe_prog_t *prog, const recipe_part_t *part, const bool *dep)
{
  if (part->kind == RECIPE_PART_PASS) return true;

  if ((part->kind == RECIPE_PART_XFORM) && (prog->xforms[part->idx].src == RECIPE_PART_PASS)) return true;

  if ((part->kind == RECIPE_PART_STEP) && (dep[part->idx] == true)) return true;

  return false;
}

// A step depends on the candidate if it hashes pass or the output of a step that does, or if it is
// an HMAC whose key does. Other steps use only the salt and strings.

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

    dep[k] = d;
  }
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

  const u32 root = recipe_parse_expr (p);

  recipe_skip_ws (p);

  if (root == 0)
  {
    // The parser has already recorded the error.
  }
  else if ((p->src[p->pos] == ';') || (p->src[p->pos] == '=') || (p->src[p->pos] == '{'))
  {
    recipe_fail (p, "mode 4000 takes a single expression, not statements");
  }
  else if (p->src[p->pos] != 0)
  {
    recipe_fail (p, "unexpected characters after the recipe");
  }
  else
  {
    // The result must be a hash call, optionally wrapped in transforms, with hex output for the
    // hash line. Comparison uses the first 16 digest bytes, which any cut must preserve.

    recipe_wrap_t wrap = { .cnt = 0 };

    u32 id = root;

    while (true)
    {
      const recipe_node_t *node = recipe_node (p, id);

      if ((node->kind != RECIPE_NODE_UPPER) && (node->kind != RECIPE_NODE_LOWER) && (node->kind != RECIPE_NODE_HEX) && (node->kind != RECIPE_NODE_CUT) && (node->kind != RECIPE_NODE_UTF16)) break;

      if (wrap.cnt >= RECIPE_MAX_WRAP) break;

      wrap.ids[wrap.cnt] = id;

      wrap.cnt++;

      id = node->kids[0];
    }

    const recipe_node_t *node = recipe_node (p, id);

    u32  root_step = 0;
    bool root_wide = false;

    if ((node->kind != RECIPE_NODE_HASH) && (node->kind != RECIPE_NODE_HMAC))
    {
      recipe_fail_at (p, node->pos, "the result must be a hash call, possibly inside upper, lower, hex, cut or trunc");
    }
    else if (recipe_lower_hash (p, id, &wrap, &root_step, &root_wide) == true)
    {
      const recipe_step_t *step = &prog->steps[root_step];

      if ((step->fmt == RECIPE_FMT_RAW) || (root_wide == true))
      {
        recipe_fail_at (p, node->pos, "the result must be hex, the hash line holds hex");
      }
      else if ((step->cut_start != 0) || (step->cut_len < 32))
      {
        recipe_fail_at (p, node->pos, "the result must keep its first 32 hex characters, mode 4000 compares 16 bytes");
      }
      else
      {
        bool dep[RECIPE_MAX_STEPS];

        recipe_deps (prog, dep);

        if (dep[root_step] == false)
        {
          recipe_fail_at (p, node->pos, "the recipe does not use pass, so every candidate gives the same hash");
        }
        else
        {
          rc = true;
        }
      }
    }
  }

  // Find the maximum password and salt lengths that fit all transformed copies.

  prog->pw_max   = RECIPE_MAX_XBYTES;
  prog->salt_max = RECIPE_MAX_XBYTES;

  for (u32 x = 0; x < prog->xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog->xforms[x];

    u32 len = RECIPE_MAX_XBYTES;

    while ((len > 0) && (recipe_xform_fits (xform, len) == false)) len--;

    if (xform->src == RECIPE_PART_PASS) prog->pw_max   = MIN (prog->pw_max,   len);
    if (xform->src == RECIPE_PART_SALT) prog->salt_max = MIN (prog->salt_max, len);
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

  // Password copies are made per candidate. Salt copies are stored in the state once per salt.

  if (part->kind == RECIPE_PART_XFORM) snprintf (buf, buf_size, "X%s%u%s", (prog->xforms[part->idx].src == RECIPE_PART_PASS) ? "P" : "S", part->idx, (part->wide == 1) ? "_16" : "");

  if (part->kind == RECIPE_PART_STEP)
  {
    const bool prepared = (in_prep == false) && (dep[part->idx] == false);

    snprintf (buf, buf_size, "%sSTEP%u%s", (prepared == true) ? "P" : "", part->idx, (part->wide == 1) ? "_16" : "");
  }

  return buf;
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

  int len = snprintf (buf, sizeof (buf), "-D RECIPE_STEPS=%u -D RECIPE_ROOT_FN=%s", prog.steps_cnt, recipe_algo_name (prog.steps[prog.steps_cnt - 1].algo));

  if (root_native == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_ROOT_NATIVE");

  // UTF-16LE conversion can give candidates different lengths. See recipe_eval () in the kernel
  // include for how the kernels handle this.

  bool wide_pass = false;
  bool wide_salt = false;

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
    }
  }

  if ((wide_pass == true) || (wide_salt == true)) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE");

  if (wide_pass == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_PASS");
  if (wide_salt == true) len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_WIDE_SALT");

  // GPUs read hex output from a table when a later step or round needs it. See RECIPE_HEX_TABLE in
  // the kernel include.

  bool hex = false;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    const recipe_step_t *step = &prog.steps[k];

    if ((k < (prog.steps_cnt - 1)) && (step->fmt != RECIPE_FMT_RAW)) hex = true;

    if ((step->iter > 1) && (step->chain_fmt != RECIPE_FMT_RAW)) hex = true;
  }

  for (u32 x = 0; x < prog.xforms_cnt; x++)
  {
    for (u32 i = 0; i < prog.xforms[x].ops_cnt; i++)
    {
      if (prog.xforms[x].ops[i].op == RECIPE_XOP_HEX) hex = true;
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

  // Whether the password is only hashed as parts, so the combinator kernel can hand it over as the
  // base word and the right word, see RECIPE_TAIL in the kernel include. An HMAC key and the source
  // of a transformed copy need it in one piece.

  bool pass_plain = true;

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    if ((prog.steps[k].kind == RECIPE_KIND_HMAC) && (prog.steps[k].key.kind == RECIPE_PART_PASS)) pass_plain = false;
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

    u32 lead = 0;

    while ((lead < step->parts_cnt) && (recipe_part_dep_on (&prog, &step->parts[lead], dep) == false)) lead++;

    u32 phase = 0;

    if (dep[k] == false)
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

    if (is_hmac == true)
    {
      recipe_part_token (&prog, &step->key, key_in_prep, dep, key, sizeof (key));
    }
    else
    {
      snprintf (key, sizeof (key), "NONE");
    }

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_S%u_KIND=%s -D RECIPE_S%u_KEY=%s -D RECIPE_S%u_PH=P%u", k, (is_hmac == true) ? "HMAC" : "HASH", k, key, k, phase);

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

    len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_SRC=%s", x, (xform->src == RECIPE_PART_PASS) ? "PASS" : "SALT");

    for (u32 i = 0; i < RECIPE_MAX_XOPS; i++)
    {
      if (i >= xform->ops_cnt)
      {
        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_O%u=NONE", x, i);

        continue;
      }

      const recipe_xop_entry_t *op = &xform->ops[i];

      const u64 a = (u64) op->a;

      const u32 a_lo = (u32) (a >>  0);
      const u32 a_hi = (u32) (a >> 32);

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_O%u=%s", x, i, RECIPE_XOP_NAMES[op->op]);

      if (op->op == RECIPE_XOP_WPERM)
      {
        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_A%u=0x%08x -D RECIPE_X%u_H%u=0x%08x", x, i, a_lo, x, i, a_hi);
      }
      else
      {
        len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_A%u=%d -D RECIPE_X%u_H%u=0", x, i, (int) op->a, x, i);
      }

      len += snprintf (buf + len, sizeof (buf) - len, " -D RECIPE_X%u_B%u=%d -D RECIPE_X%u_L%u=%u", x, i, (int) op->b, x, i, (op->has_len == true) ? 1 : 0);
    }
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

static u32 recipe_hmac_parts (const u32 algo, const u32 *key_buf, const u32 key_len, const u32 **bufs, const u32 *lens, const u32 *wides, const u32 cnt, u32 *raw)
{
  const u32 block = recipe_algo (algo)->block_len;

  u32 kb[32];

  memset (kb, 0, sizeof (kb));

  if (key_len > block)
  {
    const u32 zero = 0;

    const u32 key_digest_len = recipe_hash_parts (algo, &key_buf, &key_len, &zero, 1, raw);

    memcpy (kb, raw, key_digest_len);
  }
  else
  {
    memcpy (kb, key_buf, key_len);
  }

  u32 ipad[32];
  u32 opad[32];

  for (u32 i = 0; i < 32; i++)
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

  const u32 *obufs[2]  = { opad, inner };
  const u32  olens[2]  = { block, inner_len };
  const u32  owides[2] = { 0, 0 };

  const u32 r = recipe_hash_parts (algo, obufs, olens, owides, 2, raw);

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

// Evaluate the recipe on the host for the self-test, using emulated kernel functions. A device
// self-test failure therefore points at that device's build of the kernel rather than at the recipe.
// The raw buffer receives the final digest as little endian words, up to 64 bytes. Return its
// length. The out buffer receives up to 128 bytes in the hash line's format.

u32 recipe_eval (const recipe_prog_t *prog, const u8 *pw, const u32 pw_len, const u8 *salt, const u32 salt_len, u32 *raw, u8 *out, u32 *out_len)
{
  u32 w[64];
  u32 s[64];

  memset (w, 0, sizeof (w));
  memset (s, 0, sizeof (s));

  memcpy (w, pw,   MIN (pw_len,   sizeof (w)));
  memcpy (s, salt, MIN (salt_len, sizeof (s)));

  u32 lits[RECIPE_MAX_LITS][RECIPE_MAX_LIT / 4];

  memset (lits, 0, sizeof (lits));

  for (u32 l = 0; l < prog->lits_cnt; l++) memcpy (lits[l], prog->lits[l], prog->lit_lens[l]);

  u32 outs[RECIPE_MAX_STEPS][32];
  u32 out_lens[RECIPE_MAX_STEPS];

  memset (outs,     0, sizeof (outs));
  memset (out_lens, 0, sizeof (out_lens));

  // Prepare transformed copies of pass and salt.

  u32 xbufs[RECIPE_MAX_XFORMS][RECIPE_MAX_XBYTES / 4];
  u32 xlens[RECIPE_MAX_XFORMS];

  memset (xbufs, 0, sizeof (xbufs));
  memset (xlens, 0, sizeof (xlens));

  for (u32 x = 0; x < prog->xforms_cnt; x++)
  {
    const recipe_xform_t *xform = &prog->xforms[x];

    const bool from_pass = (xform->src == RECIPE_PART_PASS);

    memcpy (xbufs[x], (from_pass == true) ? w : s, RECIPE_MAX_XBYTES);

    const u32 len = (from_pass == true) ? pw_len : salt_len;

    xlens[x] = recipe_xform_apply (xform, (u8 *) xbufs[x], MIN (len, RECIPE_MAX_XBYTES));
  }

  u32 raw_len = 0;

  for (u32 k = 0; k < prog->steps_cnt; k++)
  {
    const recipe_step_t *step = &prog->steps[k];

    const u32 *bufs[RECIPE_MAX_PARTS];
    u32        lens[RECIPE_MAX_PARTS];
    u32        wides[RECIPE_MAX_PARTS];

    for (u32 i = 0; i < step->parts_cnt; i++)
    {
      const recipe_part_t *part = &step->parts[i];

      wides[i] = part->wide;

      if (part->kind == RECIPE_PART_PASS) { bufs[i] = w;               lens[i] = pw_len;                    }
      if (part->kind == RECIPE_PART_SALT) { bufs[i] = s;               lens[i] = salt_len;                  }
      if (part->kind == RECIPE_PART_LIT)  { bufs[i] = lits[part->idx]; lens[i] = prog->lit_lens[part->idx]; }
      if (part->kind == RECIPE_PART_STEP) { bufs[i] = outs[part->idx]; lens[i] = out_lens[part->idx];       }

      if (part->kind == RECIPE_PART_XFORM) { bufs[i] = xbufs[part->idx]; lens[i] = xlens[part->idx]; }
    }

    if (step->kind == RECIPE_KIND_HMAC)
    {
      const recipe_part_t *key = &step->key;

      const u32 *key_buf = NULL;
      u32        key_len = 0;

      if (key->kind == RECIPE_PART_PASS) { key_buf = w;              key_len = pw_len;                  }
      if (key->kind == RECIPE_PART_SALT) { key_buf = s;              key_len = salt_len;                }
      if (key->kind == RECIPE_PART_LIT)  { key_buf = lits[key->idx]; key_len = prog->lit_lens[key->idx]; }
      if (key->kind == RECIPE_PART_STEP) { key_buf = outs[key->idx]; key_len = out_lens[key->idx];       }

      if (key->kind == RECIPE_PART_XFORM) { key_buf = xbufs[key->idx]; key_len = xlens[key->idx]; }

      raw_len = recipe_hmac_parts (step->algo, key_buf, key_len, bufs, lens, wides, step->parts_cnt, raw);
    }
    else
    {
      raw_len = recipe_hash_parts (step->algo, bufs, lens, wides, step->parts_cnt, raw);
    }

    // Repetition with ^N hashes each round's output in the format set by the output suffix.

    for (u32 j = 1; j < step->iter; j++)
    {
      const u32 chain_len = recipe_format (step->chain_fmt, raw, raw_len, outs[k]);

      const u32 *chain_buf = outs[k];

      const u32 chain_wide = 0;

      raw_len = recipe_hash_parts (step->algo, &chain_buf, &chain_len, &chain_wide, 1, raw);
    }

    recipe_format (step->fmt, raw, raw_len, outs[k]);

    u8 *o = (u8 *) outs[k];

    memmove (o, o + step->cut_start, step->cut_len);
    memset  (o + step->cut_len, 0, 128 - step->cut_len);

    out_lens[k] = step->cut_len;
  }

  const u32 last = prog->steps_cnt - 1;

  memcpy (out, outs[last], out_lens[last]);

  *out_len = out_lens[last];

  return raw_len;
}
