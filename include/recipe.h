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

#define RECIPE_MAX_STEPS  16
#define RECIPE_MAX_PARTS  8
#define RECIPE_MAX_LITS   4
#define RECIPE_MAX_LIT    64
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

// The strings before and after the result can contain up to RECIPE_MAX_AFFIX bytes each.

#define RECIPE_MAX_AFFIX 64

// The hash line parser undoes up to RECIPE_MAX_ROOT_XOPS transforms around the result.

#define RECIPE_MAX_ROOT_XOPS 8

// AES call data can contain up to RECIPE_MAX_AES bytes, with 8 additional bytes for aes_unwrap.

#define RECIPE_MAX_AES 64

// The values produced by xor, and and or can contain up to RECIPE_MAX_BOP bytes, which fit
// in a step's raw output.

#define RECIPE_MAX_BOP 64

// A cut of a raw derived key, such as cut (dk, 32, 16), uses its own carried variable. The derived
// key occupies one of the RECIPE_MAX_CARRY variables, and its slices occupy the others.

#define RECIPE_MAX_KDF_SLICES 3

// The derived key of pbkdf2 can be up to RECIPE_MAX_KDF bytes long. The device computes only the
// blocks from the first to the last one that the recipe reads, which must fit the state of
// OpenCL/inc_pbkdf2.h and lie within 64 bytes. A whole key as the result is written to the hash
// line in full, which takes up to RECIPE_MAX_TEXT characters.

#define RECIPE_MAX_KDF  256
#define RECIPE_MAX_TEXT 512

// The backend builds a kernel with up to 16384 bytes of options, up to 4096 of which are its own.
// A recipe whose options do not fit in the rest is refused.

#define RECIPE_MAX_JIT 12000

// The hash line supplies salt2, pepper and user. Each field occupies a slot of RECIPE_FIELD_WORDS
// words in salt_buf_pc. The final word of salt_buf_pc stores their lengths, using 1 byte per field.
// The sort_by_salt () call compares the whole buffer. This keeps lines separate even when their
// only difference is how the bytes are split between the fields.

#define RECIPE_MAX_FIELDS  3
#define RECIPE_FIELD_WORDS 21
#define RECIPE_FIELD_MAX   (RECIPE_FIELD_WORDS * 4)
#define RECIPE_FIELD_LENS  (RECIPE_MAX_FIELDS * RECIPE_FIELD_WORDS)

typedef enum recipe_field
{
  RECIPE_FIELD_SALT2  = 0,
  RECIPE_FIELD_PEPPER = 1,
  RECIPE_FIELD_USER   = 2,

} recipe_field_t;

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
  RECIPE_ALGO_BOP        = 14,
  RECIPE_ALGO_XFRM       = 15,
  RECIPE_ALGO_WRL        = 16,
  RECIPE_ALGO_SHA3_224   = 17,
  RECIPE_ALGO_SHA3_256   = 18,
  RECIPE_ALGO_SHA3_384   = 19,
  RECIPE_ALGO_SHA3_512   = 20,
  RECIPE_ALGO_KECCAK224  = 21,
  RECIPE_ALGO_KECCAK256  = 22,
  RECIPE_ALGO_KECCAK384  = 23,
  RECIPE_ALGO_KECCAK512  = 24,
  RECIPE_ALGO_SBOG256    = 25,
  RECIPE_ALGO_SBOG512    = 26,
  RECIPE_ALGO_GOST94     = 27,
  RECIPE_ALGO_GOST94_CP  = 28,
  RECIPE_ALGO_RMD320     = 29,
  RECIPE_ALGO_MYSQL323   = 30,
  RECIPE_ALGO_HAV128_3   = 31,
  RECIPE_ALGO_HAV128_4   = 32,
  RECIPE_ALGO_HAV128_5   = 33,
  RECIPE_ALGO_HAV160_3   = 34,
  RECIPE_ALGO_HAV160_4   = 35,
  RECIPE_ALGO_HAV160_5   = 36,
  RECIPE_ALGO_HAV192_3   = 37,
  RECIPE_ALGO_HAV192_4   = 38,
  RECIPE_ALGO_HAV192_5   = 39,
  RECIPE_ALGO_HAV224_3   = 40,
  RECIPE_ALGO_HAV224_4   = 41,
  RECIPE_ALGO_HAV224_5   = 42,
  RECIPE_ALGO_HAV256_3   = 43,
  RECIPE_ALGO_HAV256_4   = 44,
  RECIPE_ALGO_HAV256_5   = 45,
  RECIPE_ALGO_TIGER      = 46,
  RECIPE_ALGO_TIGER128   = 47,
  RECIPE_ALGO_TIGER160   = 48,
  RECIPE_ALGO_TIGER2     = 49,
  RECIPE_ALGO_RMD128     = 50,
  RECIPE_ALGO_RMD256     = 51,
  RECIPE_ALGO_MD2        = 52,
  RECIPE_ALGO_SHA0       = 53,
  RECIPE_ALGO_TTH        = 54,
  RECIPE_ALGO_SNE128     = 55,
  RECIPE_ALGO_SNE256     = 56,
  RECIPE_ALGO_SKEIN224   = 57,
  RECIPE_ALGO_SKEIN256   = 58,
  RECIPE_ALGO_SKEIN384   = 59,
  RECIPE_ALGO_SKEIN512   = 60,
  RECIPE_ALGO_PANAMA     = 61,
  RECIPE_ALGO_LM         = 62,
  RECIPE_ALGO_MDC2       = 63,
  RECIPE_ALGO_DES        = 64,

  RECIPE_ALGO_BLAKE224     = 65,
  RECIPE_ALGO_BLAKE256     = 66,
  RECIPE_ALGO_BLAKE384     = 67,
  RECIPE_ALGO_BLAKE512     = 68,
  RECIPE_ALGO_BMW224       = 69,
  RECIPE_ALGO_BMW256       = 70,
  RECIPE_ALGO_BMW384       = 71,
  RECIPE_ALGO_BMW512       = 72,
  RECIPE_ALGO_CUBE224      = 73,
  RECIPE_ALGO_CUBE256      = 74,
  RECIPE_ALGO_CUBE384      = 75,
  RECIPE_ALGO_CUBE512      = 76,
  RECIPE_ALGO_ECHO224      = 77,
  RECIPE_ALGO_ECHO256      = 78,
  RECIPE_ALGO_ECHO384      = 79,
  RECIPE_ALGO_ECHO512      = 80,
  RECIPE_ALGO_FUGUE224     = 81,
  RECIPE_ALGO_FUGUE256     = 82,
  RECIPE_ALGO_FUGUE384     = 83,
  RECIPE_ALGO_FUGUE512     = 84,
  RECIPE_ALGO_GROESTL224   = 85,
  RECIPE_ALGO_GROESTL256   = 86,
  RECIPE_ALGO_GROESTL384   = 87,
  RECIPE_ALGO_GROESTL512   = 88,
  RECIPE_ALGO_HAMSI224     = 89,
  RECIPE_ALGO_HAMSI256     = 90,
  RECIPE_ALGO_HAMSI384     = 91,
  RECIPE_ALGO_HAMSI512     = 92,
  RECIPE_ALGO_JH224        = 93,
  RECIPE_ALGO_JH256        = 94,
  RECIPE_ALGO_JH384        = 95,
  RECIPE_ALGO_JH512        = 96,
  RECIPE_ALGO_LUFFA224     = 97,
  RECIPE_ALGO_LUFFA256     = 98,
  RECIPE_ALGO_LUFFA384     = 99,
  RECIPE_ALGO_LUFFA512     = 100,
  RECIPE_ALGO_SHABAL224    = 101,
  RECIPE_ALGO_SHABAL256    = 102,
  RECIPE_ALGO_SHABAL384    = 103,
  RECIPE_ALGO_SHABAL512    = 104,
  RECIPE_ALGO_SHAVITE224   = 105,
  RECIPE_ALGO_SHAVITE256   = 106,
  RECIPE_ALGO_SHAVITE384   = 107,
  RECIPE_ALGO_SHAVITE512   = 108,
  RECIPE_ALGO_SIMD224      = 109,
  RECIPE_ALGO_SIMD256      = 110,
  RECIPE_ALGO_SIMD384      = 111,
  RECIPE_ALGO_SIMD512      = 112,
  RECIPE_ALGO_HAS160       = 113,
  RECIPE_ALGO_EDON256      = 114,
  RECIPE_ALGO_EDON512      = 115,
  RECIPE_ALGO_MD6128       = 116,
  RECIPE_ALGO_MD6256       = 117,
  RECIPE_ALGO_MD6512       = 118,
  RECIPE_ALGO_RADIOGATUN32 = 119,
  RECIPE_ALGO_RADIOGATUN64 = 120,
  RECIPE_ALGO_RIPEMD       = 121,
  RECIPE_ALGO_WRL0         = 122,
  RECIPE_ALGO_WRL1         = 123,

} recipe_algo_t;

typedef enum recipe_fmt
{
  RECIPE_FMT_HEX  = 0,
  RECIPE_FMT_RAW  = 1,
  RECIPE_FMT_HEXU = 2,
  RECIPE_FMT_B64  = 3,

} recipe_fmt_t;

// A step is a plain hash call, an HMAC, an AES call, a bitwise call, transforms of a hash output or
// a DES call. The bitwise calls are xor, and, and or. An HMAC step hashes key ^ ipad followed by its
// parts. It then hashes key ^ opad followed by that digest. An AES step encrypts or decrypts its
// parts using its key. See recipe_aes_op_t for the AES operations. A BOP step combines its 2 parts
// byte by byte. See recipe_bop_op_t. An XFRM step applies the transforms of a copy to another
// step's output, as in rev (md5 (pass)). A DES step encrypts one block, its second part, with the
// key in its first part. See recipe_des_op_t.

typedef enum recipe_step_kind
{
  RECIPE_KIND_HASH = 0,
  RECIPE_KIND_HMAC = 1,
  RECIPE_KIND_AES  = 2,
  RECIPE_KIND_BOP  = 3,
  RECIPE_KIND_XFRM = 4,
  RECIPE_KIND_DES  = 5,

} recipe_step_kind_t;

// xor (a, b), and (a, b) and or (a, b). The shorter value repeats to the length of the longer one,
// and an empty value gives an empty result, as in hx. Each value is at most RECIPE_MAX_BOP bytes.

typedef enum recipe_bop_op
{
  RECIPE_BOP_XOR = 1,
  RECIPE_BOP_AND = 2,
  RECIPE_BOP_OR  = 3,

} recipe_bop_op_t;

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

// des (key, pt), des3 (key, pt) and des_block (key, pt), as in hx. Each encrypts the first 8 bytes
// of pt, padded with zero bytes. des takes the first 8 bytes of key as a DES key, and des3 the first
// 24 bytes as 3 keys for encrypt, decrypt and encrypt. des_block spreads the first 7 bytes of key
// over the 8 bytes of a DES key, as NetNTLMv1 does. A shorter key is padded with zero bytes.

typedef enum recipe_des_op
{
  RECIPE_DES_ECB   = 1,
  RECIPE_DES3_ECB  = 2,
  RECIPE_DES_BLOCK = 3,

} recipe_des_op_t;

typedef enum recipe_part_kind
{
  RECIPE_PART_PASS   = 1,
  RECIPE_PART_SALT   = 2,
  RECIPE_PART_LIT    = 3,
  RECIPE_PART_STEP   = 4,
  RECIPE_PART_XFORM  = 5,
  RECIPE_PART_SALTD  = 6,
  RECIPE_PART_VAR    = 7,
  RECIPE_PART_SALT2  = 8,
  RECIPE_PART_PEPPER = 9,
  RECIPE_PART_USER   = 10,

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
  // a string is decoded itself, and fromhex of a hex hash call gives its raw bytes. Decoding pass, a
  // field or a transformed hash output is a transform, which accepts any input, as hx does.

  RECIPE_XOP_FROMHEX = 12,
  RECIPE_XOP_FROMB64 = 13,

  // zext16 appends a zero byte after each input byte. utf16be decodes UTF-8 and writes UTF-16BE. It
  // returns an empty result for input that is not well-formed UTF-8, as hx does.

  RECIPE_XOP_ZEXT16  = 14,
  RECIPE_XOP_UTF16BE = 15,

  // base64 writes standard base64 with = padding, 4 bytes for every 3 input bytes or part of them.

  RECIPE_XOP_B64     = 16,

  // xor with a string appears only among the transforms around the result, see root_xops in
  // recipe_prog_t. Its argument a is the index of the string.

  RECIPE_XOP_XOR     = 17,

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
// Hex output is widened by inserting zero bytes. An HMAC key and the key and salt of pbkdf2 can
// be wide as well.

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
  // with zero bytes to that length. One data part can be of the salt's length, with part length 0,
  // and data_len is then the most the data can hold. A BOP step stores its operation and the fixed
  // lengths of its 2 parts, or 0 for a length that is not fixed. The data_len member stores the
  // maximum number of bytes it produces. Its cut_len is 0 when its length is not fixed.

  u32           aop;
  recipe_part_t iv;
  u32           key_len;
  u32           data_len;
  u32           part_lens[RECIPE_MAX_PARTS];

  // An XFRM step stores its transforms from innermost to outermost. Its one part is the output to
  // transform. As for a BOP step, data_len stores the maximum number of bytes before applying its
  // output format. The cut_len member is 0 when its length is not fixed.

  recipe_xop_entry_t xops[RECIPE_MAX_XOPS];
  u32                xops_cnt;

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

  // Whether the recipe reads the salt, and the fields it reads as a bit mask of
  // recipe_field_t.

  u32 salt_read;
  u32 fields;

  // The encoding of the result on the hash line: RECIPE_FMT_HEX, RECIPE_FMT_HEXU or RECIPE_FMT_B64.

  u32 root_fmt;

  // Strings before and after the result, as in "{SHA}" . sha1_b64 (pass). The hash line carries
  // them around the computed text, and the module checks and strips them.

  u8  root_pre[RECIPE_MAX_AFFIX];
  u32 root_pre_len;
  u8  root_suf[RECIPE_MAX_AFFIX];
  u32 root_suf_len;

  // cap, upper and lower around a hex result, as in cap (md5 (pass)). They do not change the bytes
  // compared, because hex compares in either case, so only the self-test hash applies them.

  recipe_xop_entry_t root_case[RECIPE_MAX_XOPS];
  u32                root_case_cnt;

  // root_hex is set for a result of raw bytes, which the hash line holds in hex, as hx writes
  // binary output. A result such as base64 (sha1_bin (pass . salt) . salt) holds root_tail bytes of
  // the root step followed by the salt, so a hash line can carry its salt in that text alone.

  u32 root_hex;
  u32 root_tail;

  // The word of the root step's raw output from which the bytes are compared, for a result cut
  // from a later offset, as in cut (sha1 (pass), 8).

  u32 root_off;

  // The number of result bytes compared: 16, or 8 to 15 for a shorter result such as mysql3 (pass).
  // The device and the hash line parser both zero the bytes past it.

  u32 root_len;

  // Transforms around the root step's raw output that keep its length and can be undone, as in
  // hex (rev (md5_bin (pass))), innermost first. The hash line holds all root_xlen bytes of their
  // output. The parser undoes them once per line, see recipe_root_undo (), so the device compares
  // the root step's own output.

  recipe_xop_entry_t root_xops[RECIPE_MAX_ROOT_XOPS];
  u32                root_xops_cnt;
  u32                root_xlen;

  // The longest text a hash line can hold for the result, without the strings around it: 128
  // characters, or more for a long derived key of pbkdf2 as the result.

  u32 root_text;

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

  // kdf_whole is set when a call reads the whole derived key. The kdf_raw flag is set when the
  // whole key is used only as the result. In that case, kdf_out contains the raw bytes, of
  // which the device compares the first 16. The device computes only the blocks from the
  // first to the last one that these reads and the slices cover.

  u32 kdf_whole;
  u32 kdf_raw;

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

  // A comparison result, either a == b or length (aes_unwrap (...)) > 0, compares cmp_len bytes of
  // the root step's raw output starting at byte cmp_start. A hash line without a digest gets a
  // constant b in cmp_digest, padded with zeros to 16 bytes. Two computed sides become their xor,
  // compared with zeros.

  u32 cmp;
  u32 cmp_start;
  u32 cmp_len;
  u8  cmp_digest[16];

  // Maximum password, salt and field lengths whose transformed copies fit RECIPE_MAX_XBYTES.

  u32 pw_max;
  u32 salt_max;
  u32 field_max;

  // Parser error position and reason. The error pointer may refer to error_buf.

  u32         error_pos;
  const char *error;
  char        error_buf[2048];

} recipe_prog_t;

HC_PLUGIN_API bool        recipe_compile   (recipe_prog_t *prog, const char *src);
HC_PLUGIN_API u32         recipe_eval      (const recipe_prog_t *prog, const u8 *pw, const u32 pw_len, const u8 *salt, const u32 salt_len, const u32 *fields, u32 *raw, u8 *out, u32 *out_len);
HC_PLUGIN_API void        recipe_field_set (u32 *fields, const u32 field, const u8 *buf, const u32 len);
HC_PLUGIN_API u32         recipe_field_get (const u32 *fields, const u32 field, u8 *buf);
HC_PLUGIN_API const char *recipe_algo_name (const u32 algo);
HC_PLUGIN_API u32         recipe_xform_apply (const recipe_xform_t *xform, u8 *buf, const u32 len);
HC_PLUGIN_API void        recipe_root_undo (const recipe_prog_t *prog, u8 *buf);
HC_PLUGIN_API char       *recipe_jit_build_options (const char *src, const bool root_native);
HC_PLUGIN_API bool        recipe_salt_valid (const recipe_prog_t *prog, const u8 *salt, const u32 salt_len);
HC_PLUGIN_API bool        recipe_salt_fits (const recipe_prog_t *prog, const u8 *salt, const u32 salt_len);
HC_PLUGIN_API u32         recipe_st_salt_len (const recipe_prog_t *prog);
HC_PLUGIN_API u32         recipe_kdf_state_size (const recipe_prog_t *prog);
HC_PLUGIN_API u64         recipe_tmp_size  (const recipe_prog_t *prog);

#endif // HC_RECIPE_H
