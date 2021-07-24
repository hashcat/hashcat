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
#include "memory.h"
#include "emu_inc_hash_sha1.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_6;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "SNMPv3 HMAC-SHA256-192";
static const u64   KERN_TYPE      = 26800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$SNMPv3$4$45889431$7585276599737564090383620785875362679570918402799211895350192983610621799047885344685052349746498170004419679809998081225537660774711595828022661503055854170724959205864916200803943987403894797803763481363727292279225961510615959487947720856537753019855530297295056779122144350124168183779842820374286984757533892647079640573333153143396873669433866800344639810381298050168882378150279566459307666090519521322815302807234891775832544445039651641425655552560443188806182642324260074431487445313192652657250751370429453104201042515913762789378530433301986580350004818693362476848691871673675659445549903680506046990324666901673291971652166488315974132495137618778248693199870322191689838829962702758419523119691721384156190269307593610430479672423773038949589918013851098014826303025169209691104391100698448756709167376495619227358406074004239019720054426442537351811110592798309899798157050114783730510485144587168960689222637040407284798304089491802615462370291323816279667792138184578665760500558880678181062362046229800381787440035656017470040087753144990921393458116599087055670067264879913812409968391970564185904377677084151443486003356616003528495750605129080488541279404701230256406769537633540790538993840001994448667033186814369838617950258925646831255009214425619864849786889274339803369923741038433445561276156132523400238192914216432204256425467734206133901586319913209169130225239005197164649118976947815053973991620162266974447853858458256357645692359369654447975747053244194895693264221530053171833268878231470099223799325721243415613411630825573731881407172997796505669046572568259071354047006445465146935309155702401448180827618102265276619554321281052975592010657285138946619551041266741457855926885313703662453134087502628246081150904608404970922549555759053744598264595885136892607797491556352245712414920090723217166690761677377687465170467631650187720861675760594906517486491314827635367948111347039584630077862097594777930458637889773296564015874734165862197875708654799960975367561065172801085838166681751675400275453999727992053489914032314886557511524110138141979947589094776031663264570900816201631633824654762248248805668317229291634483443458068978054635356784996769204180557000130172957152232863885190742315631622924490109766525818157610765334992830472354779514002105972270348518900692627110569460386663373886093497721570793034577661081462364460595701381729848934496026709342082328056794518778135826722253064384012917235631760724232491981271285825679491501595672776041021574940931247613127644522568100929407514262962178762077109203680576767235733058$8f58b2$5f38e6b85a1921eb118de1bcd1d8673848a657753ba97615";

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

static const char *SIGNATURE_SNMPV3 = "$SNMPv3$4$";

#define SNMPV3_SALT_MAX             1500
#define SNMPV3_ENGINEID_MAX         32
#define SNMPV3_MSG_AUTH_PARAMS_MAX  24
#define SNMPV3_ROUNDS               1048576
#define SNMPV3_MAX_PW_LENGTH        64

#define SNMPV3_TMP_ELEMS            4096 // 4096 = (256 (max pw length) * 64) / sizeof (u32)
#define SNMPV3_HASH_ELEMS           8

#define SNMPV3_MAX_SALT_ELEMS       512 // 512 * 4 = 2048 > 1500, also has to be multiple of 64
#define SNMPV3_MAX_ENGINE_ELEMS     16  // 16 * 4 = 64 > 32, also has to be multiple of 64
#define SNMPV3_MAX_PNUM_ELEMS       4   // 4 * 4 = 16 > 9

typedef struct hmac_sha224_tmp
{
  u32 tmp[SNMPV3_TMP_ELEMS];
  u32 h[SNMPV3_HASH_ELEMS];

} hmac_sha224_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_MAX_SALT_ELEMS];
  u32 salt_len;

  u32 engineID_buf[SNMPV3_MAX_ENGINE_ELEMS];
  u32 engineID_len;

  u32 packet_number[SNMPV3_MAX_PNUM_ELEMS];

} snmpv3_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (snmpv3_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (hmac_sha224_tmp_t);

  return tmp_size;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // we need to fix iteration count to guarantee the loop count is a multiple of 64
  // 2k calls to sha256_transform typically is enough to overtime pcie bottleneck

  const u32 kernel_loops_min = 2048 * 64;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 2048 * 64;

  return kernel_loops_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  snmpv3_t *snmpv3 = (snmpv3_t *) esalt_buf;

  token_t token;

  token.token_cnt  = 5;
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SNMPV3;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // packet number
  token.len_min[1] = 1;
  token.len_max[1] = 8;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;
  // salt
  token.len_min[2] = 24 * 2;
  token.len_max[2] = SNMPV3_SALT_MAX * 2;
  token.sep[2]     = '$';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // engineid
  token.len_min[3] = 5;
  token.len_max[3] = SNMPV3_ENGINEID_MAX;
  token.sep[3]     = '$';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // digest
  token.len_min[4] = SNMPV3_MSG_AUTH_PARAMS_MAX * 2;
  token.len_max[4] = SNMPV3_MSG_AUTH_PARAMS_MAX * 2;
  token.sep[4]     = '$';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // packet number

  const u8 *packet_number_pos = token.buf[1];
  const int packet_number_len = token.len[1];

  memset (snmpv3->packet_number, 0, sizeof (snmpv3->packet_number));

  strncpy ((char *) snmpv3->packet_number, (char *) packet_number_pos, packet_number_len);

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  u8 *salt_ptr = (u8 *) snmpv3->salt_buf;

  snmpv3->salt_len = hex_decode (salt_pos, salt_len, salt_ptr);

  salt->salt_iter = SNMPV3_ROUNDS;

  // handle unique salts detection

  sha1_ctx_t sha1_ctx;

  sha1_init   (&sha1_ctx);
  sha1_update (&sha1_ctx, snmpv3->salt_buf, snmpv3->salt_len);
  sha1_final  (&sha1_ctx);

  // store sha1(snmpv3->salt_buf) in salt_buf

  salt->salt_len = 20;

  memcpy (salt->salt_buf, sha1_ctx.h, salt->salt_len);

  // engineid

  const u8 *engineID_pos = token.buf[3];
  const int engineID_len = token.len[3];

  u8 *engineID_ptr = (u8 *) snmpv3->engineID_buf;

  snmpv3->engineID_len = hex_decode (engineID_pos, engineID_len, engineID_ptr);

  // digest

  const u8 *hash_pos = token.buf[4];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  snmpv3_t *snmpv3 = (snmpv3_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf (line_buf, line_size, "%s%s$", SIGNATURE_SNMPV3, (char *) snmpv3->packet_number);

  out_len += hex_encode ((u8 *) snmpv3->salt_buf, snmpv3->salt_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  out_len += hex_encode ((u8 *) snmpv3->engineID_buf, snmpv3->engineID_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  u32 digest_tmp[6];

  digest_tmp[0] = byte_swap_32 (digest[0]);
  digest_tmp[1] = byte_swap_32 (digest[1]);
  digest_tmp[2] = byte_swap_32 (digest[2]);
  digest_tmp[3] = byte_swap_32 (digest[3]);
  digest_tmp[4] = byte_swap_32 (digest[4]);
  digest_tmp[5] = byte_swap_32 (digest[5]);

  u32_to_hex (digest_tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (digest_tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (digest_tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (digest_tmp[3], out_buf + out_len); out_len += 8;
  u32_to_hex (digest_tmp[4], out_buf + out_len); out_len += 8;
  u32_to_hex (digest_tmp[5], out_buf + out_len); out_len += 8;

  out_buf[out_len] = 0;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
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
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
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
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
