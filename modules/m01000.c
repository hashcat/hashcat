/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "convert.h"
#include "interface.h"
#include "inc_hash_constants.h"

static const char *HASH_NAME    = "NTLM";
static const u32   SALT_TYPE    = SALT_TYPE_NONE;
static const u32   ATTACK_EXEC  = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   OPTS_TYPE    = OPTS_TYPE_PT_GENERATE_LE
                                | OPTS_TYPE_PT_ADD80
                                | OPTS_TYPE_PT_ADDBITS14
                                | OPTS_TYPE_PT_UTF16LE;
static const u32   DGST_SIZE    = DGST_SIZE_4_4;
static const u32   OPTI_TYPE    = OPTI_TYPE_ZERO_BYTE
                                | OPTI_TYPE_PRECOMPUTE_INIT
                                | OPTI_TYPE_PRECOMPUTE_MERKLE
                                | OPTI_TYPE_MEET_IN_MIDDLE
                                | OPTI_TYPE_EARLY_SKIP
                                | OPTI_TYPE_NOT_ITERATED
                                | OPTI_TYPE_NOT_SALTED
                                | OPTI_TYPE_RAW_HASH;
static const u32   DGST_POS0    = 0;
static const u32   DGST_POS1    = 3;
static const u32   DGST_POS2    = 2;
static const u32   DGST_POS3    = 1;
static const char *ST_HASH      = "b4b9b02e6f09a9bd760f388b67351e2b";
static const char *ST_PASS      = "hashcat";
static const char *SIGNATURE    = NULL;

const char *module_hash_name   () { return HASH_NAME;   }
u32         module_salt_type   () { return SALT_TYPE;   }
u32         module_attack_exec () { return ATTACK_EXEC; }
u64         module_opts_type   () { return OPTS_TYPE;   }
u32         module_dgst_size   () { return DGST_SIZE;   }
u32         module_opti_type   () { return OPTI_TYPE;   }
u32         module_dgst_pos0   () { return DGST_POS0;   }
u32         module_dgst_pos1   () { return DGST_POS1;   }
u32         module_dgst_pos2   () { return DGST_POS2;   }
u32         module_dgst_pos3   () { return DGST_POS3;   }
const char *module_st_hash     () { return ST_HASH;     }
const char *module_st_pass     () { return ST_PASS;     }

u32 module_salt_min (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  return hashconfig_salt_min (hashcat_ctx, optimized_kernel);
}

u32 module_salt_max (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  return hashconfig_salt_max (hashcat_ctx, optimized_kernel);
}

u32 module_pw_min (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  return hashconfig_pw_min (hashcat_ctx, optimized_kernel);
}

u32 module_pw_max (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  return hashconfig_pw_max (hashcat_ctx, optimized_kernel);
}

int module_hash_decode (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx, const u8 *input_buf, const int input_len, hash_t *hash_buf)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *digest, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt, u8 *output_buf, const size_t output_size)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  u32 *digest_u32 = (u32 *) digest;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 digest_buf[4];

  digest_buf[0] = digest_u32[0];
  digest_buf[1] = digest_u32[1];
  digest_buf[2] = digest_u32[2];
  digest_buf[3] = digest_u32[3];

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest_buf[0] += MD4M_A;
    digest_buf[1] += MD4M_B;
    digest_buf[2] += MD4M_C;
    digest_buf[3] += MD4M_D;
  }

  const int output_len = snprintf ((char *) output_buf, output_size - 1, "%08x%08x%08x%08x",
    digest_buf[0],
    digest_buf[1],
    digest_buf[2],
    digest_buf[3]);

  return output_len;
}

void module_register (hashcat_module_t *hashcat_module)
{
  hashcat_module->module_hash_name   = module_hash_name;
  hashcat_module->module_salt_type   = module_salt_type;
  hashcat_module->module_attack_exec = module_attack_exec;
  hashcat_module->module_opts_type   = module_opts_type;
  hashcat_module->module_dgst_size   = module_dgst_size;
  hashcat_module->module_opti_type   = module_opti_type;
  hashcat_module->module_dgst_pos0   = module_dgst_pos0;
  hashcat_module->module_dgst_pos1   = module_dgst_pos1;
  hashcat_module->module_dgst_pos2   = module_dgst_pos2;
  hashcat_module->module_dgst_pos3   = module_dgst_pos3;
  hashcat_module->module_st_hash     = module_st_hash;
  hashcat_module->module_st_pass     = module_st_pass;
  hashcat_module->module_salt_min    = module_salt_min;
  hashcat_module->module_salt_max    = module_salt_max;
  hashcat_module->module_pw_min      = module_pw_min;
  hashcat_module->module_pw_max      = module_pw_max;
  hashcat_module->module_hash_decode = module_hash_decode;
  hashcat_module->module_hash_encode = module_hash_encode;
}
