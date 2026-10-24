/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "recipe.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_USER_DEFINED;
static const char *HASH_NAME      = "Hash Recipe, see --hash-recipe";
static const u64   KERN_TYPE      = 4000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUTODETECT_DISABLE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_SALT        = "hashcat";

// ST_SALT in hex and in base64, for a recipe that decodes the salt.

static const char *ST_SALT_HEX    = "68617368636174";
static const char *ST_SALT_B64    = "aGFzaGNhdA==";

// The self-test values for salt2, pepper and user. Their capital letter distinguishes the
// effects of upper and lower.

static const char *ST_FIELDS[RECIPE_MAX_FIELDS] = { "hashcat2", "pepper", "Admin" };

u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }

// A recipe using a family with 64 bit words reports OPTI_TYPE_USES_BITS_64 so CPUs use their
// preferred vector width for 64 bit words. Otherwise, SHA-512 would build at the width for 32 bit
// words, which is twice as wide, and its kernels would take twice as long to build.

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  if (user_options->hash_recipe == NULL) return OPTI_TYPE;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return OPTI_TYPE;

  bool bits_64 = (prog.kdf_blocks > 0) && (prog.kdf_algo == RECIPE_ALGO_SHA512);

  for (u32 k = 0; k < prog.steps_cnt; k++)
  {
    const u32 algo = prog.steps[k].algo;

    if ((algo == RECIPE_ALGO_SHA384) || (algo == RECIPE_ALGO_SHA512) || (algo == RECIPE_ALGO_BLAKE2B512) || (algo == RECIPE_ALGO_BLAKE2B256) || (algo == RECIPE_ALGO_WRL) || ((algo >= RECIPE_ALGO_SHA3_224) && (algo <= RECIPE_ALGO_KECCAK512)) || (algo == RECIPE_ALGO_SBOG256) || (algo == RECIPE_ALGO_SBOG512) || ((algo >= RECIPE_ALGO_TIGER) && (algo <= RECIPE_ALGO_TIGER2)) || (algo == RECIPE_ALGO_TTH) || ((algo >= RECIPE_ALGO_SKEIN224) && (algo <= RECIPE_ALGO_SKEIN512))) bits_64 = true;
    if ((algo == RECIPE_ALGO_BLAKE384) || (algo == RECIPE_ALGO_BLAKE512) || (algo == RECIPE_ALGO_BMW384) || (algo == RECIPE_ALGO_BMW512) || ((algo >= RECIPE_ALGO_GROESTL224) && (algo <= RECIPE_ALGO_GROESTL512)) || ((algo >= RECIPE_ALGO_JH224) && (algo <= RECIPE_ALGO_JH512)) || (algo == RECIPE_ALGO_EDON512) || ((algo >= RECIPE_ALGO_MD6128) && (algo <= RECIPE_ALGO_MD6512)) || (algo == RECIPE_ALGO_RADIOGATUN64) || (algo == RECIPE_ALGO_WRL0) || (algo == RECIPE_ALGO_WRL1)) bits_64 = true;
  }

  u32 opti_type = (bits_64 == true) ? (OPTI_TYPE | OPTI_TYPE_USES_BITS_64) : OPTI_TYPE;

  // The loop kernel of pbkdf2 takes VECT_SIZE candidates per work item, see OpenCL/m04000-pure.cl.

  if (prog.kdf_blocks > 0) opti_type |= OPTI_TYPE_SLOW_HASH_SIMD_LOOP;

  return opti_type;
}

// A recipe with a for loop or pbkdf2 call runs as a slow hash in OpenCL/m04000-pure.cl. The
// salt stores the loop kernel's iteration count, and the tmps store carried variables, each
// with 64 words and a length. Without either a loop or pbkdf2, the recipe runs in each attack
// mode's fast kernels.

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  if (user_options->hash_recipe == NULL) return ATTACK_EXEC;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return ATTACK_EXEC;

  const u32 attack_exec = (prog.slow == 1) ? ATTACK_EXEC_OUTSIDE_KERNEL : ATTACK_EXEC;

  return attack_exec;
}

// Without a loop or pbkdf2, the tmps are unused. They receive the core's default size
// because a device buffer cannot be empty. Otherwise, recipe_tmp_size () returns the size
// required by the slow kernel.

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_none = sizeof (u32);

  if (user_options->hash_recipe == NULL) return tmp_none;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return tmp_none;

  if (prog.slow == 0) return tmp_none;

  const u64 tmp_size = recipe_tmp_size (&prog);

  return tmp_size;
}

// The --hash-recipe option defines the hash compiled into the kernel. The core parses the recipe in
// src/recipe.c and turns it into macros for OpenCL/inc_recipe.cl. The host evaluates the recipe to
// produce the self-test hash. See docs/hashcat-hash-recipe.md.

// The recipe supplies -D options for the kernel build. See recipe_jit_build_options (). Mode 4000
// compares the first 16 bytes of the result in its own byte order.

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // user_options_sanity () refuses a missing or invalid recipe before any kernel is built, so a
  // failure here cannot happen in a run that got this far.

  if (user_options->hash_recipe == NULL) return NULL;

  char *recipe_options = recipe_jit_build_options (user_options->hash_recipe, false);

  if (recipe_options == NULL) return NULL;

  // Fast kernels build only the session's entry point, either m04000_sxx or m04000_mxx, because
  // each entry point contains the complete recipe. Slow kernels use neither of these entry points.

  recipe_prog_t prog;

  if ((recipe_compile (&prog, user_options->hash_recipe) == false) || (prog.slow == 1)) return recipe_options;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "%s -D %s", recipe_options, (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH) ? "RECIPE_SXX_ONLY" : "RECIPE_MXX_ONLY");

  hcfree (recipe_options);

  return jit_build_options;
}

// Evaluate the supplied recipe with ST_PASS and ST_SALT to generate the self-test hash in the
// recipe's output case and length. For a recipe using fromhex (salt) or frombase64 (salt), encode
// ST_SALT in that format. An iteration count specified by iter uses RECIPE_ITER_ST. Without a
// recipe, the mode has no self-test or example hash.

const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  static char st_hash_buf[1024];

  if (user_options->hash_recipe == NULL) return NULL;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return NULL;

  const char *st_salt = ST_SALT;

  if (prog.salt_dec == RECIPE_DEC_HEX) st_salt = ST_SALT_HEX;
  if (prog.salt_dec == RECIPE_DEC_B64) st_salt = ST_SALT_B64;

  // An aes call on data of the salt's length takes ST_SALT repeated to a length it can encrypt,
  // encoded as above.

  char st_salt_buf[256];

  const u32 st_salt_len = recipe_st_salt_len (&prog);

  if (st_salt_len > 0)
  {
    u8 st_raw[128];

    const u32 st_base_len = (u32) strlen (ST_SALT);

    for (u32 i = 0; i < st_salt_len; i++) st_raw[i] = (u8) ST_SALT[i % st_base_len];

    u32 st_text_len = st_salt_len;

    if (prog.salt_dec == RECIPE_DEC_HEX)
    {
      for (u32 i = 0; i < st_salt_len; i++) u8_to_hex (st_raw[i], (u8 *) &st_salt_buf[i * 2]);

      st_text_len = st_salt_len * 2;
    }
    else if (prog.salt_dec == RECIPE_DEC_B64)
    {
      st_text_len = (u32) base64_encode (int_to_base64, st_raw, st_salt_len, (u8 *) st_salt_buf);
    }
    else
    {
      memcpy (st_salt_buf, st_raw, st_salt_len);
    }

    st_salt_buf[st_text_len] = 0;

    st_salt = st_salt_buf;
  }

  u32 st_fields[64];

  memset (st_fields, 0, sizeof (st_fields));

  for (u32 f = 0; f < RECIPE_MAX_FIELDS; f++) recipe_field_set (st_fields, f, (const u8 *) ST_FIELDS[f], (u32) strlen (ST_FIELDS[f]));

  u32 raw[16];

  u8  out[RECIPE_MAX_TEXT];
  u32 out_len = 0;

  recipe_eval (&prog, (const u8 *) ST_PASS, (u32) strlen (ST_PASS), (const u8 *) st_salt, (u32) strlen (st_salt), st_fields, raw, out, &out_len);

  // A comparison's self-test line contains the bytes compared by the host rather than the constant.
  // Store the result's compared bytes in hex, padded with zeros to 16 bytes.

  if (prog.cmp == 1)
  {
    u8 cmp[16];

    memset (cmp, 0, sizeof (cmp));
    memcpy (cmp, (const u8 *) raw + prog.cmp_start, prog.cmp_len);

    for (u32 i = 0; i < 16; i++) snprintf ((char *) out + (i * 2), 3, "%02x", cmp[i]);

    out_len = 32;
  }

  int st_len = snprintf (st_hash_buf, sizeof (st_hash_buf), "%.*s%.*s%.*s", (int) prog.root_pre_len, (const char *) prog.root_pre, (int) out_len, (const char *) out, (int) prog.root_suf_len, (const char *) prog.root_suf);

  // A result such as base64 (sha1_bin (pass . salt) . salt) carries the salt in its text, so the line
  // leaves the salt field empty, and leaves it out when no field or count follows.

  const bool tail = (prog.root_tail > 0);
  const bool more = (prog.fields != 0) || (prog.line_iter == 1);

  if ((tail == false) || (more == true)) st_len += snprintf (st_hash_buf + st_len, sizeof (st_hash_buf) - st_len, "*%s", (tail == true) ? "" : st_salt);

  for (u32 f = 0; f < RECIPE_MAX_FIELDS; f++)
  {
    if ((prog.fields & (1u << f)) == 0) continue;

    st_len += snprintf (st_hash_buf + st_len, sizeof (st_hash_buf) - st_len, "*%s", ST_FIELDS[f]);
  }

  if (prog.line_iter == 1) snprintf (st_hash_buf + st_len, sizeof (st_hash_buf) - st_len, "*%u", RECIPE_ITER_ST);

  return st_hash_buf;
}

const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_PASS;
}

// A transformed copy of pass or salt holds 256 bytes. hex () doubles the length, so a recipe that
// applies it to either takes at most 128 bytes of it.

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  if (user_options->hash_recipe == NULL) return PW_MAX;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return PW_MAX;

  const u32 pw_max = MIN (prog.pw_max, PW_MAX);

  return pw_max;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  if (user_options->hash_recipe == NULL) return SALT_MAX;

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false) return SALT_MAX;

  const u32 salt_max = MIN (prog.salt_max, SALT_MAX);

  return salt_max;
}

// The hash line uses mode 74000's format: the recipe's output in hex or base64, a star and the
// salt, which a result such as base64 (sha1_bin (pass . salt) . salt) carries in its own text
// instead. A loop up to iter adds a star and the iteration count. Mode 4000 compares up to 16 bytes
// of the result, see root_len and root_off in recipe.h. The esalt preserves the original text for
// the outfile, potfile and --show, including its case. The kernel does not read this stored text.
// The strings a recipe puts around its result are the same on every line, so the esalt leaves them
// out.

typedef struct recipe_hash
{
  u32 hash_len;

  // The original line contained only the digest. See module_hash_decode ().

  u32 bare;

  // The salt came from the hash text rather than from the salt field, see root_tail in recipe.h.

  u32 salt_tail;

  // The result text, up to root_text bytes of the recipe, see module_esalt_size ().

  u32 hash_buf[];

} recipe_hash_t;

// Most results take up to 128 characters. A long derived key of pbkdf2 as the result takes more,
// and only a recipe that has one pays for the room in every esalt.

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u32 text = 128;

  recipe_prog_t prog;

  if ((user_options->hash_recipe != NULL) && (recipe_compile (&prog, user_options->hash_recipe) == true)) text = prog.root_text;

  const u64 esalt_size = (const u64) sizeof (recipe_hash_t) + (((text + 3) / 4) * 4);

  return esalt_size;
}

// Parsing a hash line requires the compiled recipe to determine the result and salt encodings.
// Compiling it for each line would dominate the time spent loading a large hash file, so retain the
// last compiled recipe. Several threads parse a large hash file at once, so each thread keeps its
// own compiled recipe.

static const recipe_prog_t *module_recipe (const hashconfig_t *hashconfig)
{
  static __thread recipe_prog_t prog;
  static __thread char          src[4096];
  static __thread bool          have = false;

  const char *want = hashconfig->hash_recipe_option;

  if (want == NULL) return NULL;

  if ((have == true) && (strcmp (src, want) == 0)) return &prog;

  have = false;

  if (recipe_compile (&prog, want) == false) return NULL;

  if (strlen (want) < sizeof (src))
  {
    snprintf (src, sizeof (src), "%s", want);

    have = true;
  }

  return &prog;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_in, MAYBE_UNUSED const int line_in_len)
{
  u32 *digest = (u32 *) digest_buf;

  recipe_hash_t *recipe_hash = (recipe_hash_t *) esalt_buf;

  // A recipe producing base64, such as md5_b64 (pass), uses a base64 hash line. At least 22
  // characters are required for the 16 bytes compared by mode 4000, with or without padding. A
  // result shorter than 16 bytes, such as mysql3 (pass), compares only its own bytes, and the rest
  // of the digest stays zero, as on the device. A recipe whose result is a comparison can leave the
  // digest field empty. In that case, the comparison uses the constant from the recipe.

  const recipe_prog_t *prog = module_recipe (hashconfig);

  const bool b64 = (prog != NULL) && (prog->root_fmt == RECIPE_FMT_B64);
  const bool cmp = (prog != NULL) && (prog->cmp == 1);

  const u32 root_len = (prog != NULL) ? prog->root_len : 16;

  // Transforms around the result, as in hex (rev (sha1_bin (pass))), are undone here rather than
  // applied to every candidate. Undoing them needs all of their output, see recipe_root_undo ().

  const u32 xlen = (prog != NULL) ? prog->root_xlen : 0;
  const u32 need = MAX (root_len, xlen);

  // A string before the result, as in "*" . upper (sha1 (sha1_bin (pass))), starts every line. The
  // rest of the line is parsed without it, since the string can contain a star.

  const int pre_len = (prog != NULL) ? (int) prog->root_pre_len : 0;

  if (line_in_len < pre_len) return (PARSER_SIGNATURE_UNMATCHED);

  if ((pre_len > 0) && (memcmp (line_in, prog->root_pre, pre_len) != 0)) return (PARSER_SIGNATURE_UNMATCHED);

  const char *line_buf = &line_in[pre_len];
  const int   line_len = line_in_len - pre_len;

  // A line without a star contains only the digest, as supplied by hash lists such as
  // user:hash, passwd and pwdump, provided the recipe does not read a salt. A recipe that
  // reads the salt, a field from the hash line or iter rejects that line below because its
  // required separator is missing. A result such as base64 (sha1_bin (pass . salt) . salt) holds
  // the salt itself, so its line can contain only that text.

  const bool salt_free = (prog != NULL) && ((prog->salt_read == 0) || (prog->root_tail > 0));

  const bool bare = (salt_free == true) && (memchr (line_buf, '*', line_len) == NULL);

  // A recipe using iter reads the iteration count from the final field of the hash line. A salt can
  // contain a star, so the count field starts after the last star.

  int parse_len = line_len;

  u32 iter = 0;

  if ((prog != NULL) && (prog->line_iter == 1))
  {
    int iter_pos = line_len - 1;

    while ((iter_pos >= 0) && (line_buf[iter_pos] != '*')) iter_pos--;

    if (iter_pos < 0) return (PARSER_SEPARATOR_UNMATCHED);

    const int iter_len = line_len - (iter_pos + 1);

    if ((iter_len < 1) || (iter_len > 10)) return (PARSER_SALT_ITERATION);

    // Reject a leading zero so the outfile and --show preserve the count as
    // written on the hash line.

    if ((iter_len > 1) && (line_buf[iter_pos + 1] == '0')) return (PARSER_SALT_ITERATION);

    u64 iter_val = 0;

    for (int i = iter_pos + 1; i < line_len; i++)
    {
      if ((line_buf[i] < '0') || (line_buf[i] > '9')) return (PARSER_SALT_ITERATION);

      iter_val = (iter_val * 10) + (u64) (line_buf[i] - '0');
    }

    if (iter_val > RECIPE_MAX_LINE_ITER) return (PARSER_SALT_ITERATION);

    // A loop ending at iter starts from its first bound. A pbkdf2 call must run at least once.

    if (prog->iter_min > iter_val) return (PARSER_SALT_ITERATION);

    iter = (u32) iter_val;

    parse_len = iter_pos;
  }

  // salt2, pepper and user follow the salt in that order, each included only if the recipe reads
  // it. These fields cannot contain a star, so each is the text after the last star in the
  // remaining input. With --username, the user comes from the hash list instead. The hlfmt code
  // splits it off the line, which then has no user field. The potfile has no hash list, so its
  // lines always include that field.

  const bool user_listed = (hash_info != NULL) && (hash_info->user != NULL);

  if (prog != NULL)
  {
    for (int f = RECIPE_MAX_FIELDS - 1; f >= 0; f--)
    {
      if ((prog->fields & (1u << f)) == 0) continue;

      if ((f == RECIPE_FIELD_USER) && (user_listed == true)) continue;

      int field_pos = parse_len - 1;

      while ((field_pos >= 0) && (line_buf[field_pos] != '*')) field_pos--;

      if (field_pos < 0) return (PARSER_SEPARATOR_UNMATCHED);

      const int field_len = parse_len - (field_pos + 1);

      if (field_len > (int) prog->field_max) return (PARSER_SALT_LENGTH);

      recipe_field_set (salt->salt_buf_pc, (u32) f, (const u8 *) &line_buf[field_pos + 1], (u32) field_len);

      parse_len = field_pos;
    }

    if (((prog->fields & (1u << RECIPE_FIELD_USER)) != 0) && (user_listed == true))
    {
      const user_t *user = hash_info->user;

      if (user->user_len > prog->field_max) return (PARSER_SALT_LENGTH);

      recipe_field_set (salt->salt_buf_pc, RECIPE_FIELD_USER, (const u8 *) user->user_name, user->user_len);
    }
  }

  // A string after the result, which cannot contain a star, ends the first field. Its alphabet is
  // checked once that string is stripped.

  const int suf_len = (prog != NULL) ? (int) prog->root_suf_len : 0;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = (bare == true) ? 1 : 2;

  token.sep[0]     = '*';
  token.len_min[0] = ((cmp == true) ? 0 : ((b64 == true) ? (((need * 4) + 2) / 3) : (need * 2))) + suf_len;
  token.len_max[0] = ((prog != NULL) ? (int) prog->root_text : 128) + suf_len;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (suf_len == 0) token.attr[0] |= (b64 == true) ? TOKEN_ATTR_VERIFY_BASE64A : TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = '*';
  token.len_min[1] = 0;
  token.len_max[1] = 256;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, parse_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];
  const int hash_len = token.len[0] - suf_len;

  if (suf_len > 0)
  {
    if (memcmp (&hash_pos[hash_len], prog->root_suf, suf_len) != 0) return (PARSER_SIGNATURE_UNMATCHED);

    if ((b64 == false) && ((hash_len % 2) != 0)) return (PARSER_TOKEN_LENGTH);

    const bool valid = (b64 == true) ? is_valid_base64a_string (hash_pos, hash_len) : is_valid_hex_string (hash_pos, hash_len);

    if (valid == false) return (PARSER_TOKEN_ENCODING);
  }

  // The bytes after the hash output in a result such as base64 (sha1_bin (pass . salt) . salt).

  u8  tail_buf[128];
  int tail_len = 0;

  if ((cmp == true) && (hash_len == 0))
  {
    memcpy (digest, prog->cmp_digest, 16);
  }
  else if ((cmp == true) && (hash_len < 32))
  {
    return (PARSER_HASH_LENGTH);
  }
  else if (b64 == true)
  {
    u8 tmp[(RECIPE_MAX_TEXT / 4) * 3];

    const size_t tmp_len = base64_decode (base64_to_int, hash_pos, (size_t) hash_len, tmp);

    if (tmp_len < need) return (PARSER_HASH_LENGTH);

    if (tmp_len < prog->root_tail) return (PARSER_HASH_LENGTH);

    if (xlen > 0) recipe_root_undo (prog, tmp);

    memset (digest, 0, 16);

    memcpy (digest, tmp, root_len);

    if (prog->root_tail > 0)
    {
      tail_len = (int) (tmp_len - prog->root_tail);

      memcpy (tail_buf, &tmp[prog->root_tail], tail_len);
    }
  }
  else
  {
    if ((hash_len % 2) != 0) return (PARSER_HASH_LENGTH);

    u8 dig[64];

    memset (dig, 0, sizeof (dig));

    for (u32 i = 0; i < need; i++) dig[i] = hex_to_u8 (&hash_pos[i * 2]);

    if (xlen > 0) recipe_root_undo (prog, dig);

    memset (digest, 0, 16);

    memcpy (digest, dig, root_len);
  }

  memcpy (recipe_hash->hash_buf, hash_pos, hash_len);

  recipe_hash->hash_len = hash_len;
  recipe_hash->bare     = (bare == true) ? 1 : 0;

  const u8 *salt_pos = token.buf[1];
  int       salt_len = (bare == true) ? 0 : token.len[1];

  // A result that holds the salt after its hash output takes the salt from there when the salt field
  // is empty or missing. A salt field that is given has to agree with it.

  recipe_hash->salt_tail = 0;

  if ((prog != NULL) && (prog->root_tail > 0))
  {
    if (salt_len == 0)
    {
      salt_pos = tail_buf;
      salt_len = tail_len;

      recipe_hash->salt_tail = 1;
    }
    else if ((salt_len != tail_len) || (memcmp (salt_pos, tail_buf, salt_len) != 0))
    {
      return (PARSER_SALT_VALUE);
    }
  }

  if (salt_len > (int) hashconfig->salt_max) return (PARSER_SALT_LENGTH);

  // Calls to fromhex (salt) and frombase64 (salt) require a salt in the corresponding encoding.

  if ((prog != NULL) && (recipe_salt_valid (prog, salt_pos, (u32) salt_len) == false)) return (PARSER_SALT_ENCODING);

  // An aes call on data of the salt's length needs a salt that gives it a length it can take.

  if ((prog != NULL) && (recipe_salt_fits (prog, salt_pos, (u32) salt_len) == false)) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  // This count sets how often the loop kernel runs its body. See module_attack_exec (). For pbkdf2,
  // use the iteration count minus 1 because the init kernel computes the first iteration.

  if ((prog != NULL) && (prog->line_iter == 1))
  {
    salt->salt_iter = (u32) ((i64) iter - prog->iter_sub);
  }
  else if ((prog != NULL) && (prog->slow == 1))
  {
    salt->salt_iter = prog->loop_cnt;
  }

  return (PARSER_OK);
}

// Write the hash line: only the digest if that was its original form, otherwise the digest, salt,
// fields and iteration count. The user field supplied by --username is omitted from the line, so
// the outfile and --show preserve the line's original form. The potfile has no hash list from which
// to obtain the user, so its lines always include the salt field and every other field. The strings
// around the result come from the recipe.

static int module_line_write (const hashconfig_t *hashconfig, const salt_t *salt, const recipe_hash_t *recipe_hash, const hashinfo_t *hash_info, char *line_buf, const int line_size, const bool potfile)
{
  const recipe_prog_t *prog = module_recipe (hashconfig);

  const bool user_listed = (potfile == false) && (hash_info != NULL) && (hash_info->user != NULL);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  if (prog != NULL)
  {
    memcpy (out_buf + out_len, prog->root_pre, prog->root_pre_len);

    out_len += prog->root_pre_len;
  }

  memcpy (out_buf + out_len, recipe_hash->hash_buf, recipe_hash->hash_len);

  out_len += recipe_hash->hash_len;

  if (prog != NULL)
  {
    memcpy (out_buf + out_len, prog->root_suf, prog->root_suf_len);

    out_len += prog->root_suf_len;
  }

  out_buf[out_len] = 0;

  if ((recipe_hash->bare == 1) && (potfile == false)) return out_len;

  out_buf[out_len] = '*';

  out_len += 1;

  // A salt taken from the hash text was not in the salt field, which stays empty.

  if (recipe_hash->salt_tail == 0)
  {
    memcpy (out_buf + out_len, salt->salt_buf, salt->salt_len);

    out_len += salt->salt_len;
  }

  out_buf[out_len] = 0;

  for (u32 f = 0; f < RECIPE_MAX_FIELDS; f++)
  {
    if ((prog == NULL) || ((prog->fields & (1u << f)) == 0)) continue;

    if ((f == RECIPE_FIELD_USER) && (user_listed == true)) continue;

    out_buf[out_len] = '*';

    out_len += 1;

    out_len += recipe_field_get (salt->salt_buf_pc, f, out_buf + out_len);

    out_buf[out_len] = 0;
  }

  if ((prog != NULL) && (prog->line_iter == 1))
  {
    const u32 iter = (u32) ((i64) salt->salt_iter + prog->iter_sub);

    out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "*%u", iter);
  }

  return out_len;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = module_line_write (hashconfig, salt, (const recipe_hash_t *) esalt_buf, hash_info, line_buf, line_size, false);

  return line_len;
}

int module_hash_encode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size, MAYBE_UNUSED const void *tmps)
{
  const int line_len = module_line_write (hashconfig, salt, (const recipe_hash_t *) esalt_buf, hash_info, line_buf, line_size, true);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = module_hash_encode_potfile;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_length_sort              = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_register_options         = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
