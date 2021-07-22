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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // 4_3
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "SNMPv3 HMAC-SHA1-96";
static const u64   KERN_TYPE      = 25200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$SNMPv3$2$66763052$13981919518623358902340156831753173612320956749283824166083320737667668557830898783481876963136410266762758410322896320705075044221495960812100760230106803899899467077793703068392752686845035561487927252457444567685389901239388468830507087105054207914325254376053788152029716918450770264047103676562621965276752797029332926039166807829108367446173251908238116020942421323633620301312478670302264165059728208402342845743839533979473825394866704960428648622730299023225638967097578710279784722583947877561544154219162080289188160001741612377820114739093961409809862173307722539556954826052612794054060797358016549602977742745078911393042420821004243620362464971828700104979572910001640083882586179153483503492341163054930853321963503411228241996417991605003371264529827508426941919673592574025732354318435733211018917539824570724324796232199960952117561108106623865308577977944499366806697863259301760429786001824121720055893438673268643594146796410437039466462606490272723136671298529920486664067752007564122205089571790718437001200506203464426405927405102300269665189637001279369690218157456566218400534722049383049029139069701182053729830585217732347396312967325628046845068493719801191260136945971516486442056102815519090214442808707545803919529217103430588641187558031052830941742920355893755319896626873275796534820394248837050567688575113833311009595128372820474678989203565094681918285106102363272728922586582037066265522397748326630668375500179630717875844561081542915676557961288028298248995547031274515608973804660067065502484039882958958452781062725550260382637592283691962996228392332833626159043179186189904614052189303508782635840692436969244901198720814518$79f7b1$57e964c7cb117647004cf132";

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

static const char *SIGNATURE_SNMPV3 = "$SNMPv3$2$";

#define SNMPV3_SALT_MAX 1500
#define SNMPV3_SALT_MAX_BIN 752
#define SNMPV3_ENGINEID_MAX 32
#define SNMPV3_MSG_AUTH_PARAMS_MAX 12

typedef struct hmac_sha1_tmp
{
  u32 idx;
  sha1_ctx_t ctx;

} hmac_sha1_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_SALT_MAX_BIN];
  u32 salt_len;

  u8 engineID_buf[SNMPV3_ENGINEID_MAX];
  u32 engineID_len;

  u8 packet_number[8+1];

} snmpv3_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (snmpv3_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (hmac_sha1_tmp_t);

  return tmp_size;
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
  token.len_min[2] = 12 * 2;
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

  for (int i = 0; i < salt_len / 4; i++)
  {
    snmpv3->salt_buf[i] = byte_swap_32 (snmpv3->salt_buf[i]);
  }

  salt->salt_iter = 16384 - 1;

  // handle unique salts detection

  sha1_ctx_t sha1_ctx;

  sha1_init   (&sha1_ctx);
  sha1_update (&sha1_ctx, snmpv3->salt_buf, snmpv3->salt_len);
  sha1_final  (&sha1_ctx);

  // store sha1(snmpv3->salt_buf) in salt_buf

  memcpy (salt->salt_buf, sha1_ctx.h, 20);

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

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);

  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  snmpv3_t *snmpv3 = (snmpv3_t *) esalt_buf;

  int line_len = snprintf (line_buf, 10 + strlen ((char *) snmpv3->packet_number) + 1 + 1, "%s%s$", SIGNATURE_SNMPV3, snmpv3->packet_number);

  uint i;

  u32 salt_buf_32[SNMPV3_SALT_MAX_BIN] = { 0 };

  for (i = 0; i < SNMPV3_SALT_MAX_BIN; i++) salt_buf_32[i] = byte_swap_32 (snmpv3->salt_buf[i]);

  const u8 *salt_buf_ptr = (u8 *) salt_buf_32;

  for (i = 0; i < snmpv3->salt_len; i++)
  {
    line_len += snprintf (line_buf+line_len, 3, "%02x", salt_buf_ptr[i]);
  }

  line_len += snprintf (line_buf+line_len, 2, "$");

  line_len += hex_encode (snmpv3->engineID_buf, snmpv3->engineID_len, (u8 *) line_buf+line_len);

  line_len += snprintf (line_buf+line_len, 2, "$");

  line_len += snprintf (line_buf+line_len, 9, "%08x", digest[0]);
  line_len += snprintf (line_buf+line_len, 9, "%08x", digest[1]);
  line_len += snprintf (line_buf+line_len, 9, "%08x", digest[2]);

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
