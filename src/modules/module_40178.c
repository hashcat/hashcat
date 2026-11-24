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
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_EAS;
static const char *HASH_NAME      = "Microsoft ConfigMgr (SCCM) Media Variables (AES-256)";
static const char *HASH_RECIPE    = "h = sha1_bin(utf16le(pass)); k0 = sha1_bin(xor(pad(h, 64), fromhex('36'))); k1 = sha1_bin(xor(pad(h, 64), fromhex('5c'))); aes_ecb_encrypt(or(pad(k0, 32), wperm(k1, 5, 5, 5, 5, 5, 0, 1, 2)), fromhex('3c003f0078006d006c00200076006500'))";
static const u64   KERN_TYPE      = 40178;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sccm$aes256$0000edec14000000c61a0000d01a00001066000000000000dfdc644bc4119438157122cd8b2213ed";

#include "hooks_common.c"

// The line decoder is shared with mode 40177 through sccm_common.c, the way the BIP39 modes share
// bip39_common.c.

#include "sccm_common.c"

static const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

// CryptDeriveKey for AES-256: h is the sha1 of the UTF-16LE password, k0 and k1 the sha1 of h zero
// extended to 64 bytes and xor 0x36 for k0 and 0x5c for k1, and the key is the 20 bytes of k0
// followed by the first 12 bytes of k1. An aes key cannot be a concatenation, so wperm moves those
// 12 bytes of k1 to bytes 20 to 31 and or merges them into k0.

#define SCCM_ALG_ID 0x6610

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  const int rc = sccm_hash_decode (digest, SCCM_ALG_ID, line_buf, line_len);

  return (rc);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
