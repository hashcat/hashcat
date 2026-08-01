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
static const char *HASH_NAME      = "Meshtastic LoRa frame (AES-128/256-CTR PSK)";
static const u64   KERN_TYPE      = 99001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_EARLY_SKIP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "0123456789abcdef0123456789abcdef";
static const char *ST_HASH        = "$meshtastic$1*0a*efbeadde*efbeadde*4c6f6e6746617374*e9886af9b78d2bdd9c52f492cc999e04";

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

#define MESHTASTIC_NAME_MAX  64
#define MESHTASTIC_CT_MAX    256
#define MESHTASTIC_FRAMES_MAX 16   /* matches sniffer-side --hashcat-export-merge cap */

/* Per-frame portion of the hash. v1 lines populate a single entry; v2 lines
 * populate nframes entries (2..16) sharing the same chash and channel name. */
typedef struct meshtastic_frame
{
  u32 packet_id;
  u32 from_node;
  u32 ct_len;
  u32 ct_buf[MESHTASTIC_CT_MAX / 4];

} meshtastic_frame_t;

typedef struct meshtastic
{
  u32 chash;
  u32 name_xor;
  u32 name_len;
  u32 nframes;        /* 1 for v1, 2..16 for v2 */
  u32 name_buf[MESHTASTIC_NAME_MAX / 4];

  meshtastic_frame_t frames[MESHTASTIC_FRAMES_MAX];

} meshtastic_t;

static const char *SIGNATURE_MESHTASTIC = "$meshtastic$";

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // Meshtastic PSK length selects the cipher: <=16 byte candidate -> AES-128 (zero-padded to 16),
  // 17..32 byte candidate -> AES-256 (zero-padded to 32). Anything longer is truncated to 32 by the kernel.
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

  // Detect format version by peeking at the digit after the signature.
  // We need "$meshtastic$" (12 chars) plus one digit, so line_len >= 13.
  if (line_len < 14) return (PARSER_SALT_LENGTH);

  const char version_char = line_buf[12];

  if (version_char != '1' && version_char != '2') return (PARSER_SALT_VALUE);

  u32 nframes = 1;

  // For v2 we have to know N (the frame count) before configuring the
  // tokenizer, since the token count grows with N. Walk the line to read
  // it: skip "$meshtastic$2*", skip chash + '*', skip name + '*', then
  // read the decimal N up to the next '*'.
  if (version_char == '2')
  {
    int p = 13;                                  // index of '*' after the '2'
    if (p >= line_len || line_buf[p] != '*') return (PARSER_SALT_VALUE);
    p++;

    // chash field: exactly 2 hex chars then '*'
    if (p + 3 > line_len) return (PARSER_SALT_LENGTH);
    if (line_buf[p + 2] != '*') return (PARSER_SALT_VALUE);
    p += 3;

    // name field: variable, terminated by '*'
    while (p < line_len && line_buf[p] != '*') p++;
    if (p >= line_len) return (PARSER_SALT_VALUE);
    p++;

    // N field: 1..2 decimal digits, terminated by '*'
    int n_start = p;
    while (p < line_len && line_buf[p] != '*')
    {
      if (line_buf[p] < '0' || line_buf[p] > '9') return (PARSER_SALT_VALUE);
      p++;
    }
    if (p >= line_len) return (PARSER_SALT_VALUE);

    int n_len = p - n_start;
    if (n_len < 1 || n_len > 2) return (PARSER_SALT_VALUE);

    nframes = (u32) hc_strtoul ((const char *) (line_buf + n_start), NULL, 10);
    if (nframes < 2 || nframes > MESHTASTIC_FRAMES_MAX) return (PARSER_SALT_VALUE);
  }

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MESHTASTIC;

  // token 0: signature
  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // token 1: version digit
  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // token 2: chash byte (frame[13])
  token.sep[2]     = '*';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  u32 name_token_idx;
  u32 frames_first_token_idx;

  if (version_char == '1')
  {
    // v1 layout: signature | 1 | chash | pkt | from | name | ct
    token.token_cnt = 7;

    // token 3: packet_id (4 LE bytes)
    token.sep[3]     = '*';
    token.len[3]     = 8;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // token 4: from_node (4 LE bytes)
    token.sep[4]     = '*';
    token.len[4]     = 8;
    token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // token 5: channel name (variable hex, may be empty)
    token.sep[5]     = '*';
    token.len_min[5] = 0;
    token.len_max[5] = MESHTASTIC_NAME_MAX * 2;
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // token 6: ciphertext (>= 4 bytes so the kernel can check the protobuf header)
    token.sep[6]     = '*';
    token.len_min[6] = 8;
    token.len_max[6] = MESHTASTIC_CT_MAX * 2;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    name_token_idx         = 5;
    frames_first_token_idx = 3;  // pkt at +0, from at +1, ct at +3 (after name)
  }
  else
  {
    // v2 layout: signature | 2 | chash | name | N | (pkt | from | ct){N}
    token.token_cnt = 5 + 3 * nframes;

    // token 3: channel name (variable hex)
    token.sep[3]     = '*';
    token.len_min[3] = 0;
    token.len_max[3] = MESHTASTIC_NAME_MAX * 2;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // token 4: N (1..2 decimal digits)
    token.sep[4]     = '*';
    token.len_min[4] = 1;
    token.len_max[4] = 2;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    // tokens 5..(5 + 3*N - 1): N consecutive (pkt, from, ct) triples
    for (u32 f = 0; f < nframes; f++)
    {
      const u32 base = 5 + 3 * f;

      token.sep[base + 0]     = '*';
      token.len[base + 0]     = 8;
      token.attr[base + 0]    = TOKEN_ATTR_FIXED_LENGTH
                              | TOKEN_ATTR_VERIFY_HEX;

      token.sep[base + 1]     = '*';
      token.len[base + 1]     = 8;
      token.attr[base + 1]    = TOKEN_ATTR_FIXED_LENGTH
                              | TOKEN_ATTR_VERIFY_HEX;

      token.sep[base + 2]     = '*';
      token.len_min[base + 2] = 8;
      token.len_max[base + 2] = MESHTASTIC_CT_MAX * 2;
      token.attr[base + 2]    = TOKEN_ATTR_VERIFY_LENGTH
                              | TOKEN_ATTR_VERIFY_HEX;
    }

    name_token_idx         = 3;
    frames_first_token_idx = 5;  // each frame triple lives at (5 + 3*f, 6 + 3*f, 7 + 3*f)
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version sanity (tokenizer enforces digit, we enforce value)
  const u32 version = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  if (version_char == '1' && version != 1) return (PARSER_SALT_VALUE);
  if (version_char == '2' && version != 2) return (PARSER_SALT_VALUE);

  // chash
  meshtastic->chash   = (u32) hex_to_u8 (token.buf[2]);
  meshtastic->nframes = nframes;

  // channel name -- copied raw (LE-packed in u32) for the encoder, plus
  // a precomputed xor-byte for the kernel-side prefilter.
  const int name_hex_len = token.len[name_token_idx];

  if ((name_hex_len & 1) != 0) return (PARSER_SALT_VALUE);

  const u32 name_len = (u32) (name_hex_len / 2);

  if (name_len > MESHTASTIC_NAME_MAX) return (PARSER_SALT_LENGTH);

  u8 *name_ptr = (u8 *) meshtastic->name_buf;
  u8 name_xor = 0;

  for (u32 i = 0; i < name_len; i++)
  {
    const u8 b = hex_to_u8 (token.buf[name_token_idx] + (i * 2));

    name_ptr[i] = b;
    name_xor   ^= b;
  }

  meshtastic->name_len = name_len;
  meshtastic->name_xor = (u32) name_xor;

  // Per-frame triples. In v1 there's a single triple at tokens [3, 4, 6]
  // (with name sandwiched at 5); in v2 the triples start at token 5 and
  // are contiguous (pkt, from, ct repeated).
  for (u32 f = 0; f < nframes; f++)
  {
    u32 pkt_idx, from_idx, ct_idx;

    if (version_char == '1')
    {
      pkt_idx  = 3;
      from_idx = 4;
      ct_idx   = 6;
    }
    else
    {
      pkt_idx  = frames_first_token_idx + 3 * f + 0;
      from_idx = frames_first_token_idx + 3 * f + 1;
      ct_idx   = frames_first_token_idx + 3 * f + 2;
    }

    meshtastic_frame_t *fr = &meshtastic->frames[f];

    fr->packet_id = hex_to_u32 (token.buf[pkt_idx]);
    fr->from_node = hex_to_u32 (token.buf[from_idx]);

    const int ct_hex_len = token.len[ct_idx];

    if ((ct_hex_len & 1) != 0) return (PARSER_SALT_VALUE);

    const u32 ct_len = (u32) (ct_hex_len / 2);

    if (ct_len > MESHTASTIC_CT_MAX) return (PARSER_SALT_LENGTH);

    // LE-packed: byte i of ct lands in byte (i % 4) of ct_buf[i / 4].
    // Matches hashcat's hex_to_u32 convention and the AES helper's u32
    // I/O byte order, so the kernel can XOR ct_buf[0] with the AES output
    // directly.
    for (u32 i = 0; i < ct_len; i++)
    {
      const u8 b = hex_to_u8 (token.buf[ct_idx] + (i * 2));

      fr->ct_buf[i / 4] |= ((u32) b) << ((i & 3) * 8);
    }

    fr->ct_len = ct_len;
  }

  // Aggregate identity across every frame so two v2 lines that share their
  // first frame but differ in later frames do not collide on the same salt
  // (which would make hashcat dedupe them). Plain XOR is enough: real captures
  // never reuse identical (packet_id, from_node, ct_buf[0], ct_len) tuples
  // across frames of a single channel.
  u32 agg_packet_id = 0;
  u32 agg_from_node = 0;
  u32 agg_ct_first  = 0;
  u32 agg_ct_len    = 0;

  for (u32 f = 0; f < nframes; f++)
  {
    agg_packet_id ^= meshtastic->frames[f].packet_id;
    agg_from_node ^= meshtastic->frames[f].from_node;
    agg_ct_first  ^= meshtastic->frames[f].ct_buf[0];
    agg_ct_len    ^= meshtastic->frames[f].ct_len;
  }

  salt->salt_buf[0] = agg_packet_id;
  salt->salt_buf[1] = agg_from_node;
  salt->salt_buf[2] = (meshtastic->chash << 16) | (meshtastic->nframes & 0xffff);
  salt->salt_buf[3] = agg_ct_first;
  salt->salt_len    = 16;

  // Digest sentinel (verifier is structural, not a real hash).
  digest[0] = agg_packet_id;
  digest[1] = agg_from_node;
  digest[2] = agg_ct_first;
  digest[3] = (meshtastic->chash << 24)
            | (meshtastic->name_xor << 16)
            | ((meshtastic->nframes & 0xff) << 8)
            |  (agg_ct_len & 0xff);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const meshtastic_t *meshtastic = (const meshtastic_t *) esalt_buf;

  const u8 *name_ptr = (const u8 *) meshtastic->name_buf;

  int line_len = 0;

  if (meshtastic->nframes <= 1)
  {
    // v1: signature * chash * pkt * from * name * ct
    // packet_id and from_node round-trip through hex_to_u32 which reads
    // the file hex as little-endian on-wire bytes; print them swapped so
    // we re-emit those same on-wire bytes.
    line_len = snprintf (line_buf, line_size, "%s1*%02x*%08x*%08x*",
      SIGNATURE_MESHTASTIC,
      meshtastic->chash & 0xff,
      byte_swap_32 (meshtastic->frames[0].packet_id),
      byte_swap_32 (meshtastic->frames[0].from_node));

    for (u32 i = 0; i < meshtastic->name_len; i++)
    {
      line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", name_ptr[i]);
    }

    line_len += snprintf (line_buf + line_len, line_size - line_len, "*");

    for (u32 i = 0; i < meshtastic->frames[0].ct_len; i++)
    {
      const u32 w  = meshtastic->frames[0].ct_buf[i / 4];
      const u32 sh = (i % 4) * 8; // ct_buf is LE-packed
      const u8  b  = (u8) (w >> sh);

      line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", b);
    }
  }
  else
  {
    // v2: signature * chash * name * N * (pkt * from * ct){N}
    line_len = snprintf (line_buf, line_size, "%s2*%02x*",
      SIGNATURE_MESHTASTIC,
      meshtastic->chash & 0xff);

    for (u32 i = 0; i < meshtastic->name_len; i++)
    {
      line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", name_ptr[i]);
    }

    line_len += snprintf (line_buf + line_len, line_size - line_len, "*%u", meshtastic->nframes);

    for (u32 f = 0; f < meshtastic->nframes; f++)
    {
      const meshtastic_frame_t *fr = &meshtastic->frames[f];

      line_len += snprintf (line_buf + line_len, line_size - line_len, "*%08x*%08x*",
        byte_swap_32 (fr->packet_id),
        byte_swap_32 (fr->from_node));

      for (u32 i = 0; i < fr->ct_len; i++)
      {
        const u32 w  = fr->ct_buf[i / 4];
        const u32 sh = (i % 4) * 8;
        const u8  b  = (u8) (w >> sh);

        line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", b);
      }
    }
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
