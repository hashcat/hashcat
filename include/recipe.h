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
#define RECIPE_MAX_CARRY  4
#define RECIPE_MAX_LOOP   10000000

// A loop ending at iter reads its last bound from the hash line, up to RECIPE_MAX_LINE_ITER. The
// self-test hash uses RECIPE_ITER_ST for that bound.

#define RECIPE_MAX_LINE_ITER 999999999
#define RECIPE_ITER_ST       1000

// AES call data can contain up to RECIPE_MAX_AES bytes, with 8 additional bytes for aes_unwrap.

#define RECIPE_MAX_AES 64

// A cut of a raw derived key, such as cut (dk, 32, 16), uses its own carried variable. The derived
// key occupies one of the RECIPE_MAX_CARRY variables, and its slices occupy the others.

#define RECIPE_MAX_KDF_SLICES 3

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
  RECIPE_ALGO_AES        = 13,

} recipe_algo_t;

typedef enum recipe_fmt
{
  RECIPE_FMT_HEX  = 0,
  RECIPE_FMT_RAW  = 1,
  RECIPE_FMT_HEXU = 2,
  RECIPE_FMT_B64  = 3,

} recipe_fmt_t;

// A step is a plain hash call, an HMAC or an AES call. An HMAC step hashes key ^ ipad followed by
// its parts. It then hashes key ^ opad followed by that digest. An AES step encrypts or decrypts
// its parts using its key. See recipe_aes_op_t for the AES operations.

typedef enum recipe_step_kind
{
  RECIPE_KIND_HASH = 0,
  RECIPE_KIND_HMAC = 1,
  RECIPE_KIND_AES  = 2,

} recipe_step_kind_t;

// aes_ecb_encrypt (key, pt), aes_cbc_encrypt (key, iv, pt), aes_cbc_decrypt (key, iv, ct) and
// aes_unwrap (kek, wrapped), see OpenCL/inc_cipher_aes-modes.cl. RECIPE_AES_UNWRAP_A is the unwrap
// of length (aes_unwrap (kek, wrapped)) > 0, which gives the 8 byte integrity check value instead
// of the key.

typedef enum recipe_aes_op
{
  RECIPE_AES_ECB_ENC   = 1,
  RECIPE_AES_CBC_ENC   = 2,
  RECIPE_AES_CBC_DEC   = 3,
  RECIPE_AES_UNWRAP    = 4,
  RECIPE_AES_UNWRAP_A  = 5,

} recipe_aes_op_t;

typedef enum recipe_part_kind
{
  RECIPE_PART_PASS  = 1,
  RECIPE_PART_SALT  = 2,
  RECIPE_PART_LIT   = 3,
  RECIPE_PART_STEP  = 4,
  RECIPE_PART_XFORM = 5,
  RECIPE_PART_SALTD = 6,
  RECIPE_PART_VAR   = 7,

} recipe_part_kind_t;

// A recipe with a for loop runs as a slow hash using 3 kernels. The init kernel computes values
// needed before the loop, the loop kernel runs the body once per iteration, and the comp kernel
// computes the result. Each step belongs to one of these kernels. Values passed between kernels are
// carried variables, RECIPE_PART_VAR, stored in the tmps. A pbkdf2 call splits the recipe the same
// way: init computes its key and salt, loop runs its iterations, and comp evaluates calls that use
// the derived key. A recipe with neither a loop nor pbkdf2 has only RECIPE_SEC_MAIN steps.

typedef enum recipe_sec
{
  RECIPE_SEC_MAIN = 0,
  RECIPE_SEC_INIT = 1,
  RECIPE_SEC_LOOP = 2,
  RECIPE_SEC_COMP = 3,

} recipe_sec_t;

// fromhex (salt) and frombase64 (salt) give the decoded salt, RECIPE_PART_SALTD. A recipe decodes
// the salt one way only.

typedef enum recipe_dec
{
  RECIPE_DEC_NONE = 0,
  RECIPE_DEC_HEX  = 1,
  RECIPE_DEC_B64  = 2,

} recipe_dec_t;

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

  // The compiler resolves decoding according to the input. Decoding salt gives RECIPE_PART_SALTD,
  // a string is decoded itself, and fromhex of a hex hash call gives its raw bytes. Decoding is
  // never stored as a transform on a copy.

  RECIPE_XOP_FROMHEX = 12,
  RECIPE_XOP_FROMB64 = 13,

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

// A transformed copy of pass or salt. The src field is RECIPE_PART_PASS, RECIPE_PART_SALT or
// RECIPE_PART_SALTD. Transforms apply in order, innermost first.

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
  u32 sec;
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

  // An AES step stores its operation, its IV for CBC, and the fixed lengths of its key, data and
  // each part within the data. If a part is shorter than its fixed length at run time, it is padded
  // with zero bytes to that length.

  u32           aop;
  recipe_part_t iv;
  u32           key_len;
  u32           data_len;
  u32           part_lens[RECIPE_MAX_PARTS];

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

  // The salt decoding method selected by the recipe. See recipe_dec_t.

  u32 salt_dec;

  // The encoding of the result on the hash line: RECIPE_FMT_HEX, RECIPE_FMT_HEXU or RECIPE_FMT_B64.

  u32 root_fmt;

  // A recipe with a for loop or a pbkdf2 call runs as a slow hash. The loop_cnt field specifies how
  // often the loop kernel runs its body: the loop's iteration count, or the pbkdf2 count minus 1.

  u32 slow;
  u32 loop_cnt;

  // The count iter from each hash line gives the loop kernel iter - iter_sub iterations. It must be
  // at least iter_min. In this case, loop_cnt contains the count for RECIPE_ITER_ST, used by the
  // self-test instead of a count from the hash line.

  u32 line_iter;
  u32 iter_min;
  i32 iter_sub;

  // A pbkdf2 call stores its family, output format, derived key length and required block count. It
  // also stores the key and salt read by the init kernel, and the carried variable that the comp
  // kernel fills with the derived key after the loop finishes.

  u32 kdf_algo;
  u32 kdf_fmt;
  u32 kdf_dklen;
  u32 kdf_blocks;

  recipe_part_t kdf_key;
  recipe_part_t kdf_salt;

  u32 kdf_out;

  // The slices of the derived key: the carried variable each one fills, and its start and length in
  // bytes, both multiples of 4.

  u32 kdf_slices_cnt;
  u32 kdf_slice_var[RECIPE_MAX_KDF_SLICES];
  u32 kdf_slice_start[RECIPE_MAX_KDF_SLICES];
  u32 kdf_slice_len[RECIPE_MAX_KDF_SLICES];

  // The carried variables, the part each one starts from in the init kernel and the part the loop
  // body replaces it with, if any. For a result that is a carried variable, root_var is its index
  // plus 1 and root_vfmt its format.

  u32           carry_cnt;
  recipe_part_t carry_init[RECIPE_MAX_CARRY];
  u32           carry_has_init[RECIPE_MAX_CARRY];
  recipe_part_t carry_loop[RECIPE_MAX_CARRY];
  u32           carry_has_loop[RECIPE_MAX_CARRY];

  u32 root_var;
  u32 root_vfmt;

  // The step whose raw digest is compared, or RECIPE_MAX_STEPS for a carried variable as the result.
  // Every other step formats its output for the steps after it.

  u32 root_step;

  // A comparison result, either a == b with constant b or length (aes_unwrap (...)) > 0, compares
  // cmp_len bytes of the root step's raw output starting at byte cmp_start. A hash line without a
  // digest gets b in cmp_digest, padded with zeros to 16 bytes.

  u32 cmp;
  u32 cmp_start;
  u32 cmp_len;
  u8  cmp_digest[16];

  // Maximum password and salt lengths whose transformed copies fit RECIPE_MAX_XBYTES.

  u32 pw_max;
  u32 salt_max;

  // Parser error position and reason. The error pointer may refer to error_buf.

  u32         error_pos;
  const char *error;
  char        error_buf[512];

} recipe_prog_t;

HC_PLUGIN_API bool        recipe_compile   (recipe_prog_t *prog, const char *src);
HC_PLUGIN_API u32         recipe_eval      (const recipe_prog_t *prog, const u8 *pw, const u32 pw_len, const u8 *salt, const u32 salt_len, u32 *raw, u8 *out, u32 *out_len);
HC_PLUGIN_API const char *recipe_algo_name (const u32 algo);
HC_PLUGIN_API u32         recipe_xform_apply (const recipe_xform_t *xform, u8 *buf, const u32 len);
HC_PLUGIN_API char       *recipe_jit_build_options (const char *src, const bool root_native);
HC_PLUGIN_API bool        recipe_salt_valid (const recipe_prog_t *prog, const u8 *salt, const u32 salt_len);
HC_PLUGIN_API u32         recipe_kdf_state_size (const recipe_prog_t *prog);
HC_PLUGIN_API u64         recipe_tmp_size  (const recipe_prog_t *prog);

#endif // HC_RECIPE_H
