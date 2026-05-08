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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Meshtastic LoRa frame (AES-128-CTR PSK)";
static const u64   KERN_TYPE      = 99001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_EARLY_SKIP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$meshtastic$1*00*efbeadde*efbeadde*68617368636174*56c09c1c6132ed37ce376f95a350b133";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

#define MESHTASTIC_NAME_MAX 64
#define MESHTASTIC_CT_MAX   256

typedef struct meshtastic
{
  u32 chash;
  u32 name_xor;
  u32 packet_id;
  u32 from_node;
  u32 name_len;
  u32 ct_len;
  u32 name_buf[MESHTASTIC_NAME_MAX / 4];
  u32 ct_buf[MESHTASTIC_CT_MAX / 4];

} meshtastic_t;

static const char *SIGNATURE_MESHTASTIC = "$meshtastic$";

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // Meshtastic PSK is 16 bytes for AES-128, 32 for AES-256. Anything longer is truncated by the kernel.
  return 32;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (meshtastic_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  meshtastic_t *meshtastic = (meshtastic_t *) esalt_buf;

  memset (meshtastic, 0, sizeof (meshtastic_t));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MESHTASTIC;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // version

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // chash byte (frame[13])

  token.sep[2]     = '*';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // packet id (4 LE bytes)

  token.sep[3]     = '*';
  token.len[3]     = 8;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // from node (4 LE bytes)

  token.sep[4]     = '*';
  token.len[4]     = 8;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // channel name (variable hex, may be empty)

  token.sep[5]     = '*';
  token.len_min[5] = 0;
  token.len_max[5] = MESHTASTIC_NAME_MAX * 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // ciphertext: at minimum the 4-byte protobuf header so the kernel can verify the shape

  token.sep[6]     = '*';
  token.len_min[6] = 8;
  token.len_max[6] = MESHTASTIC_CT_MAX * 2;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u32 version = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (version != 1) return (PARSER_SALT_VALUE);

  // chash

  const u8 chash = hex_to_u8 (token.buf[2]);

  meshtastic->chash = (u32) chash;

  // packet_id and from_node are 4-byte LE on the wire; hex_to_u32 reads
  // them into a host integer that already matches the LE byte order.

  meshtastic->packet_id = hex_to_u32 (token.buf[3]);
  meshtastic->from_node = hex_to_u32 (token.buf[4]);

  // channel name -- copied raw (LE-packed in u32) for the encoder, plus
  // a precomputed xor-byte for the kernel-side prefilter.

  const int name_hex_len = token.len[5];

  if ((name_hex_len & 1) != 0) return (PARSER_SALT_VALUE);

  const u32 name_len = (u32) (name_hex_len / 2);

  if (name_len > MESHTASTIC_NAME_MAX) return (PARSER_SALT_LENGTH);

  u8 *name_ptr = (u8 *) meshtastic->name_buf;

  u8 name_xor = 0;

  for (u32 i = 0; i < name_len; i++)
  {
    const u8 b = hex_to_u8 (token.buf[5] + (i * 2));

    name_ptr[i] = b;
    name_xor   ^= b;
  }

  meshtastic->name_len = name_len;
  meshtastic->name_xor = (u32) name_xor;

  // ciphertext -- byte-swap to BE so the kernel can XOR directly with AES output.

  const int ct_hex_len = token.len[6];

  if ((ct_hex_len & 1) != 0) return (PARSER_SALT_VALUE);

  const u32 ct_len = (u32) (ct_hex_len / 2);

  if (ct_len > MESHTASTIC_CT_MAX) return (PARSER_SALT_LENGTH);

  // LE-packed: byte i of ct lands in byte (i % 4) of ct_buf[i / 4].
  // Matches hashcat's hex_to_u32 convention and the AES helper's u32
  // I/O byte order, so the kernel can XOR ct_buf[0] with the AES output
  // directly.
  for (u32 i = 0; i < ct_len; i++)
  {
    const u8 b = hex_to_u8 (token.buf[6] + (i * 2));

    meshtastic->ct_buf[i / 4] |= ((u32) b) << ((i & 3) * 8);
  }

  meshtastic->ct_len = ct_len;

  // make the salt unique per frame so multiple frames in the same hash
  // file each get their own _comp pass.

  salt->salt_buf[0] = meshtastic->packet_id;
  salt->salt_buf[1] = meshtastic->from_node;
  salt->salt_buf[2] = meshtastic->chash;
  salt->salt_len    = 12;

  // there is no traditional digest here; the verifier matches by
  // decrypting and checking a protobuf shape. fill a stable sentinel so
  // the dispatch keeps each frame distinct.

  digest[0] = meshtastic->packet_id;
  digest[1] = meshtastic->from_node;
  digest[2] = meshtastic->ct_buf[0];
  digest[3] = (meshtastic->chash << 24) | (meshtastic->name_xor << 16) | (meshtastic->ct_len & 0xffff);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const meshtastic_t *meshtastic = (const meshtastic_t *) esalt_buf;

  // packet_id and from_node round-trip through hex_to_u32 which reads
  // the file hex as little-endian on-wire bytes; print them swapped so
  // we re-emit those same on-wire bytes.
  int line_len = snprintf (line_buf, line_size, "%s1*%02x*%08x*%08x*",
    SIGNATURE_MESHTASTIC,
    meshtastic->chash & 0xff,
    byte_swap_32 (meshtastic->packet_id),
    byte_swap_32 (meshtastic->from_node));

  const u8 *name_ptr = (const u8 *) meshtastic->name_buf;

  for (u32 i = 0; i < meshtastic->name_len; i++)
  {
    line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", name_ptr[i]);
  }

  line_len += snprintf (line_buf + line_len, line_size - line_len, "*");

  for (u32 i = 0; i < meshtastic->ct_len; i++)
  {
    const u32 w  = meshtastic->ct_buf[i / 4];
    const u32 sh = (i % 4) * 8; // ct_buf is LE-packed
    const u8  b  = (u8) (w >> sh);

    line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", b);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
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
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
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
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
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
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
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
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
