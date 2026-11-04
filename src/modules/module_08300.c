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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 4;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "DNSSEC (NSEC3)";
static const u64   KERN_TYPE      = 8300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_LOWER
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_ST_ADD80;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1";

#include "hooks_common.c"

static const char *module_advice_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "When using the optimized-kernel: the length byte, the candidate, the domain name, the root that ends it and the salt share a single 55 byte block, so a candidate longer than what the domain and the salt leave of that block is never found. The pure-kernel takes the name a block at a time and does not have this limit.";
}

static int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  // A rule runs on the device, after the host folded, and src/outfile.c rebuilds a cracked plaintext
  // by replaying that rule rather than the fold. What went into the digest is the folded name, so
  // that is the name reported.

  const u8 *ptr_src = (const u8 *) src_buf;

  u8 *ptr_dst = (u8 *) dst_buf;

  memcpy (ptr_dst, ptr_src, src_len);

  lowercase (ptr_dst, src_len);

  return src_len;
}

static u32 module_combined_len_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the optimized kernels keep the candidate, the domain and the salt in one block

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 combined_len_max = (optimized_kernel == true) ? 55 : 0;

  return combined_len_max;
}

static u32 module_combined_len_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const salt_t *salt, MAYBE_UNUSED const void *esalt)
{
  // the length byte of the candidate, the domain, the root that ends it and the salt

  const u32 combined_len_salt = 1 + salt->salt_len_pc + 1 + salt->salt_len;

  return combined_len_salt;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u32 pw_max = 63;

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    pw_max = 32;
  }

  return pw_max;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.sep[0]     = ':';
  token.len[0]     = 32;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE32A;

  // The optimized kernels read seven words of the domain and force the eighth to zero, so 28 bytes
  // of it is all they hash. RFC 1035 2.3.4 holds a name to 255 bytes, and the shortest name a
  // domain can be part of is the one an empty candidate makes, the domain and the root that ends
  // it, so 254 is the longest domain that can belong to a name at all.

  token.sep[1]     = ':';
  token.len_min[1] = 0;
  token.len_max[1] = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? 28 : 254;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // RFC 5155 3.1.5 carries the salt behind a one byte length field, so 255 bytes, written in hex.

  token.sep[2]     = ':';
  token.len_min[2] = 0;
  token.len_max[2] = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? 32 : 510;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = ':';
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // ok, the plan for this algorithm is the following:
  // we have 2 salts here, the domain-name and a random salt
  // while both are used in the initial transformation,
  // only the random salt is used in the following iterations
  // so we create two buffer, one that includes domain-name (stored into salt_buf_pc[])
  // and one that includes only the real salt (stored into salt_buf[]).
  // the domain-name length is put into array position 7 of salt_buf_pc[] since there is not salt_pc_len

  const u8 *hash_pos = token.buf[0];
  const int hash_len = token.len[0];

  u8 tmp_buf[100] = { 0 };

  base32_decode (itoa32_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // domain

  const u8 *domain_pos = token.buf[1];
  const int domain_len = token.len[1];

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  if (domain_len > 0)
  {
    if (domain_pos[0] != '.') return (PARSER_SALT_VALUE);

    memcpy (salt_buf_pc_ptr, domain_pos, domain_len);

    // RFC 4034 6.2 hashes the name in its canonical form, where an ASCII letter is lower case. The
    // candidate is folded by OPTS_TYPE_PT_LOWER, and the domain is the rest of the same name.

    lowercase (salt_buf_pc_ptr, domain_len);
  }

  u8 *len_ptr = salt_buf_pc_ptr;

  *len_ptr = 0;

  for (int i = 1; i < domain_len; i++)
  {
    if (salt_buf_pc_ptr[i] == '.')
    {
      len_ptr = salt_buf_pc_ptr + i;

      *len_ptr = 0;
    }
    else
    {
      *len_ptr += 1;
    }
  }

  // RFC 1035 2.3.4 holds a label to 63 bytes, and 4.1.4 reserves the two top bits of a length byte
  // for a compression pointer, so a longer label cannot be written at all. An empty label is what
  // ends a name, so one before the end is not part of a name either.

  for (int i = 0; i < domain_len; i += salt_buf_pc_ptr[i] + 1)
  {
    if (salt_buf_pc_ptr[i] == 0) return (PARSER_SALT_VALUE);
    if (salt_buf_pc_ptr[i] > 63) return (PARSER_SALT_VALUE);
  }

  salt->salt_len_pc = domain_len;

  // "real" salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // The one block the optimized kernels hash has to hold the length byte, a candidate, the domain,
  // the root and the salt. A hash that leaves no room for a candidate at all cannot be found there.

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    if ((1 + 1 + domain_len + 1 + (int) salt->salt_len) > PW_MAX_OLD) return (PARSER_SALT_LENGTH);
  }

  // iteration

  const u8 *iter_pos = token.buf[3];

  // RFC 5155 3.1.3 carries the iteration count in a 16 bit field, so a record cannot ask for more.

  const u64 salt_iter = hc_strtoull ((const char *) iter_pos, NULL, 10);

  if (salt_iter > 65535) return (PARSER_SALT_ITERATION);

  salt->salt_iter = (u32) salt_iter;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 tmp[5];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);

  char digest_buf_c[34];

  base32_encode (int_to_itoa32, (const u8 *) tmp, 20, (u8 *) digest_buf_c);

  digest_buf_c[32] = 0;

  // domain

  const u32 salt_pc_len = salt->salt_len_pc;

  char domain_buf_c[256 + 1] = { 0 };

  memcpy (domain_buf_c, (const char *) salt->salt_buf_pc, salt_pc_len);

  for (u32 i = 0; i < salt_pc_len; i++)
  {
    const char next = domain_buf_c[i];

    domain_buf_c[i] = '.';

    i += next;
  }

  domain_buf_c[salt_pc_len] = 0;

  // final

  char tmp_salt[(SALT_MAX * 2) + 1];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s:%s:%s:%u", digest_buf_c, domain_buf_c, tmp_salt, salt->salt_iter);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_advice_notice            = module_advice_notice;
  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_combined_len_max         = module_combined_len_max;
  module_ctx->module_combined_len_salt        = module_combined_len_salt;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
