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
#include "emu_inc_hash_base58.h"
#include "emu_inc_hash_md5.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "BIP39 Passphrase Recovery (ASCII, P2SH/P2PKH/P2WPKH)";
static const u64   KERN_TYPE      = 36000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "testpass";
static const char *ST_HASH        = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about:33747aCmUp8PkWmWWY8epR1Cph8Tf9Aozt:m/49'/0'/0'/0/0";

#define BIP39_MAX_PASSPHRASE_LEN 256u

#include "hooks_common.c"

// The derivation path parser, the address decoders and the tuning bounds are shared with mode
// 36001 through bip39_common.c, the way the scrypt modules share scrypt_common.c.

#include "bip39_common.c"

typedef struct bip39_skeleton
{
  u32 mnemonic_len;
  u32 address_len;
  u32 path_len;
  u32 path_depth;
  u32 target_type;
  u32 reserved;

  u32 path_indices[BIP39_MAX_PATH_DEPTH];
  u32 path_kind[BIP39_MAX_PATH_DEPTH];
  u32 path_dynamic_count;
  u32 dynamic_value_total;
  u64 path_combo_total;
  bip39_dynamic_segment_t dynamic_segments[BIP39_MAX_DYNAMIC_SEGMENTS];
  u32 dynamic_values[BIP39_MAX_DYNAMIC_VALUES];
  u32 target_hash[5];

  u8 mnemonic[1024];
  u8 address[64];
  u8 path[64];
  u32 mnemonic_raw_len;
  u8 mnemonic_raw[1024];

} bip39_skeleton_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39_skeleton_t);
}

typedef struct bip39_tmp
{
  u64 master[8];

  u32 prefix_key[8];
  u32 prefix_chain[8];

  u32 prefix_pub_x[8];
  u32 prefix_pub_tag;

  u32 hit[BIP39_MAX_HITS];
  u32 hit_cnt;

  u32 valid;

} bip39_tmp_t;

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39_tmp_t);
}

// Hashes that share a mnemonic, a target type and a derivation path share a salt, and the address
// is deliberately left out so one run covers several addresses of the same wallet. Those three are
// also the only esalt fields the kernels read, which is what makes OPTS_TYPE_MULTIHASH_DESPITE_ESALT
// safe here. The per-address target lives in the digest, not the esalt.

static void bip39_set_salt_key (const bip39_skeleton_t *bip39, salt_t *salt)
{
  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);
  md5_update (&md5_ctx, &bip39->target_type, sizeof (bip39->target_type));
  md5_update (&md5_ctx, &bip39->mnemonic_raw_len, sizeof (bip39->mnemonic_raw_len));
  md5_update (&md5_ctx, (const u32 *) bip39->mnemonic_raw, bip39->mnemonic_raw_len);
  md5_update (&md5_ctx, &bip39->path_len, sizeof (bip39->path_len));
  md5_update (&md5_ctx, (const u32 *) bip39->path, bip39->path_len);
  md5_final (&md5_ctx);

  salt->salt_buf[0] = md5_ctx.h[0];
  salt->salt_buf[1] = md5_ctx.h[1];
  salt->salt_buf[2] = md5_ctx.h[2];
  salt->salt_buf[3] = md5_ctx.h[3];
  salt->salt_len = 16;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, void *digest_buf, salt_t *salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  bip39_skeleton_t *bip39 = (bip39_skeleton_t *) esalt_buf;

  bip39->path_depth = 0;
  bip39->target_type = BIP39_TARGET_IL_HEX;
  bip39->reserved = 0;

  memset (bip39->path_indices, 0, sizeof (bip39->path_indices));
  memset (bip39->path_kind, 0, sizeof (bip39->path_kind));
  bip39->path_dynamic_count = 0;
  bip39->dynamic_value_total = 0;
  bip39->path_combo_total = 0ULL;
  memset (bip39->dynamic_segments, 0, sizeof (bip39->dynamic_segments));
  memset (bip39->dynamic_values, 0, sizeof (bip39->dynamic_values));
  memset (bip39->target_hash, 0, sizeof (bip39->target_hash));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;
  token.sep[0] = ':';
  token.sep[1] = ':';

  token.len_min[0] = 1;
  token.len_max[0] = sizeof (bip39->mnemonic) - 1;
  token.len_min[1] = 1;
  token.len_max[1] = sizeof (bip39->address) - 1;
  token.len_min[2] = 1;
  token.len_max[2] = sizeof (bip39->path) - 1;

  token.attr[0] = TOKEN_ATTR_VERIFY_LENGTH;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
  token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return rc_tokenizer;

  const u8 *mnemonic_pos = token.buf[0];
  const u8 *address_pos = token.buf[1];
  const u8 *path_pos = token.buf[2];

  bip39->mnemonic_len = 0;
  bip39->address_len = token.len[1];
  bip39->path_len = token.len[2];

  memset (bip39->mnemonic, 0, sizeof (bip39->mnemonic));
  memset (bip39->mnemonic_raw, 0, sizeof (bip39->mnemonic_raw));
  bip39->mnemonic_raw_len = 0;

  // ASCII-only: copy mnemonic as-is (BIP39 wordlist is English ASCII)
  const u32 mnemonic_len = (u32) token.len[0];

  if (mnemonic_len >= (u32) sizeof (bip39->mnemonic))
  {
    return PARSER_SALT_LENGTH;
  }

  memcpy (bip39->mnemonic, mnemonic_pos, mnemonic_len);
  bip39->mnemonic[mnemonic_len] = 0;
  bip39->mnemonic_len = mnemonic_len;

  const u32 raw_len = (u32) token.len[0];

  if (raw_len >= (u32) sizeof (bip39->mnemonic_raw))
  {
    return PARSER_HASH_LENGTH;
  }

  memcpy (bip39->mnemonic_raw, mnemonic_pos, raw_len);
  bip39->mnemonic_raw[raw_len] = 0;
  bip39->mnemonic_raw_len = raw_len;

  memset (bip39->address, 0, sizeof (bip39->address));
  memcpy (bip39->address, address_pos, token.len[1]);
  bip39->address[token.len[1]] = 0;

  memset (bip39->path, 0, sizeof (bip39->path));
  memcpy (bip39->path, path_pos, token.len[2]);
  bip39->path[token.len[2]] = 0;

  if (bip39_parse_derivation_path ((const char *) bip39->path, bip39->path_indices, bip39->path_kind, bip39->dynamic_segments, bip39->dynamic_values, &bip39->path_depth, &bip39->path_dynamic_count, &bip39->dynamic_value_total) == false)
  {
    return PARSER_HASH_VALUE;
  }

  const u64 combo_total = bip39_path_combo_total (bip39->dynamic_segments, bip39->path_dynamic_count);

  if (combo_total == 0) return (PARSER_HASH_VALUE);

  bip39->path_combo_total = combo_total;

  // The path combinations are the inner keyspace of a candidate, which is what salt_iter means to
  // the backend. It launches the loop kernel over windows of this count, so autotune sees the real
  // work and can pick a loop count for it.

  if (combo_total > 0xffffffffULL)
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter = (u32) combo_total;
  salt->salt_iter2 = 0;

  const int rc_target = bip39_decode_target (address_pos, token.len[1], bip39->target_hash, &bip39->target_type, digest);

  if (rc_target != PARSER_OK) return rc_target;

  bip39_set_salt_key (bip39, salt);

  return PARSER_OK;
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  const bip39_skeleton_t *bip39 = (const bip39_skeleton_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s:%s:%s",
                                 (const char *) bip39->mnemonic_raw,
                                 (const char *) bip39->address,
                                 (const char *) bip39->path);

  return line_len;
}

static int module_hash_encode_status (const hashconfig_t *hashconfig, const void *digest_buf, const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  int line_len = module_hash_encode (hashconfig, digest_buf, salt, esalt_buf, NULL, NULL, line_buf, line_size);

  if ((line_len < 0) || (line_len >= line_size))
  {
    return line_len;
  }

  const bip39_skeleton_t *bip39 = (const bip39_skeleton_t *) esalt_buf;

  if (bip39 == 0)
  {
    return line_len;
  }

  return bip39_append_combo_status (bip39->path_combo_total, line_buf, line_size, line_len);
}

static u32         module_pw_max         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BIP39_MAX_PASSPHRASE_LEN;}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_tuningdb_block     = bip39_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = module_hash_encode_status;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_accel_max         = bip39_module_kernel_accel_max;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
