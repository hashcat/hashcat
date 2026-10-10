/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_RECIPE_H
#define HC_RECIPE_H

// Hash-mode 4000 accepts a recipe through --hash-recipe, using a subset of hx expression syntax.
// Each step is one hash call, ordered from innermost to outermost. A step hashes a list of parts:
// the password, salt, a literal or an earlier step's output. The last step is the outermost call.
// See docs/hashcat-hash-recipe.md for the syntax.

#define RECIPE_MAX_STEPS  8
#define RECIPE_MAX_PARTS  8
#define RECIPE_MAX_LITS   4
#define RECIPE_MAX_LIT    16
#define RECIPE_MAX_ITER   100000
#define RECIPE_MAX_XFORMS 4
#define RECIPE_MAX_XOPS   4
#define RECIPE_MAX_XBYTES 256

// Kernel type for the recipe kernels in OpenCL/m04000_*-pure.cl.

#define RECIPE_KERN_TYPE  4000

typedef enum recipe_algo
{
  RECIPE_ALGO_MD4    = 1,
  RECIPE_ALGO_MD5    = 2,
  RECIPE_ALGO_SHA1   = 3,
  RECIPE_ALGO_SHA224 = 4,
  RECIPE_ALGO_SHA256 = 5,
  RECIPE_ALGO_SHA384 = 6,
  RECIPE_ALGO_SHA512 = 7,

  RECIPE_ALGO_RMD160     = 8,
  RECIPE_ALGO_BLAKE2B512 = 9,
  RECIPE_ALGO_BLAKE2B256 = 10,
  RECIPE_ALGO_BLAKE2S256 = 11,
  RECIPE_ALGO_SM3        = 12,

} recipe_algo_t;

typedef enum recipe_fmt
{
  RECIPE_FMT_HEX  = 0,
  RECIPE_FMT_RAW  = 1,
  RECIPE_FMT_HEXU = 2,

} recipe_fmt_t;

// A step is a plain hash call or an HMAC. An HMAC step hashes key ^ ipad followed by its parts.
// It then hashes key ^ opad followed by that digest.

typedef enum recipe_step_kind
{
  RECIPE_KIND_HASH = 0,
  RECIPE_KIND_HMAC = 1,

} recipe_step_kind_t;

typedef enum recipe_part_kind
{
  RECIPE_PART_PASS  = 1,
  RECIPE_PART_SALT  = 2,
  RECIPE_PART_LIT   = 3,
  RECIPE_PART_STEP  = 4,
  RECIPE_PART_XFORM = 5,

} recipe_part_kind_t;

// Supported hx string transforms for pass and salt. Each runs on a copy, allowing a recipe to
// hash both pass and upper (pass).

typedef enum recipe_xop
{
  RECIPE_XOP_UPPER   = 1,
  RECIPE_XOP_LOWER   = 2,
  RECIPE_XOP_HEX     = 3,
  RECIPE_XOP_REV     = 4,
  RECIPE_XOP_ROTATE  = 5,
  RECIPE_XOP_CAP     = 6,
  RECIPE_XOP_ROT13   = 7,
  RECIPE_XOP_PAD     = 8,
  RECIPE_XOP_BSWAP32 = 9,
  RECIPE_XOP_WPERM   = 10,
  RECIPE_XOP_CUT     = 11,

} recipe_xop_t;

// Arguments a and b store the rotation offset, cap position (-1 for the first lowercase letter),
// padding length, word indices and count, or cut start and length. Word indices use 4 bits each,
// starting at the lowest bits. For cut, has_len distinguishes explicit and omitted lengths.

typedef struct recipe_xop_entry
{
  u32  op;
  i64  a;
  i64  b;
  bool has_len;

} recipe_xop_entry_t;

// A transformed copy of pass or salt. The src field is RECIPE_PART_PASS or RECIPE_PART_SALT.
// Transforms apply in order, innermost first.

typedef struct recipe_xform
{
  u32 src;

  recipe_xop_entry_t ops[RECIPE_MAX_XOPS];
  u32                ops_cnt;

} recipe_xform_t;

// The wide flag marks a part hashed as UTF-16LE. Passwords and salts are decoded from UTF-8.
// Hex output is widened by inserting zero bytes.

typedef struct recipe_part
{
  u32 kind;
  u32 idx;
  u32 wide;

} recipe_part_t;

// A call such as md5_uc^3(pass) hashes its parts, then hashes its output iter - 1 more times.
// The output suffix sets chain_fmt, the format passed between rounds. The fmt field sets the final
// format, which upper (), lower () and hex () can change. The caller gets cut_len bytes starting
// at cut_start.

typedef struct recipe_step
{
  u32 kind;
  u32 algo;
  u32 chain_fmt;
  u32 fmt;
  u32 iter;

  u32 cut_start;
  u32 cut_len;

  recipe_part_t parts[RECIPE_MAX_PARTS];
  u32         parts_cnt;

  // An HMAC key must be a single part.

  recipe_part_t key;

} recipe_step_t;

typedef struct recipe_prog
{
  recipe_step_t steps[RECIPE_MAX_STEPS];
  u32         steps_cnt;

  u8  lits[RECIPE_MAX_LITS][RECIPE_MAX_LIT];
  u32 lit_lens[RECIPE_MAX_LITS];
  u32 lits_cnt;

  recipe_xform_t xforms[RECIPE_MAX_XFORMS];
  u32            xforms_cnt;

  // Maximum password and salt lengths whose transformed copies fit RECIPE_MAX_XBYTES.

  u32 pw_max;
  u32 salt_max;

  // Parser error position and reason. The error pointer may refer to error_buf.

  u32         error_pos;
  const char *error;
  char        error_buf[384];

} recipe_prog_t;

HC_PLUGIN_API bool        recipe_compile   (recipe_prog_t *prog, const char *src);
HC_PLUGIN_API u32         recipe_eval      (const recipe_prog_t *prog, const u8 *pw, const u32 pw_len, const u8 *salt, const u32 salt_len, u32 *raw, u8 *out, u32 *out_len);
HC_PLUGIN_API const char *recipe_algo_name (const u32 algo);
HC_PLUGIN_API u32         recipe_xform_apply (const recipe_xform_t *xform, u8 *buf, const u32 len);
HC_PLUGIN_API char       *recipe_jit_build_options (const char *src, const bool root_native);

#endif // HC_RECIPE_H
