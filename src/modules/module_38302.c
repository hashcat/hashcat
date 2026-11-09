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
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "Apple DMG (encrcdsa v2-legacy, PBKDF2-HMAC-SHA1 + 3DES key wrap)";
static const u64   KERN_TYPE      = 38302;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "vilefault";
static const char *ST_HASH        = "$dmg$2*20*f99cef1a60c70a9b890077478b576d55e0c407d0*32*a4270592d3ba90ad4fab01a689b5014f56ed2f2086cd60b25303f598917817a1*64*5a0efc19b406834c35019f254868ae63d436f2a04f99a0b2a035b4b7f0b65f61bb9ffcb6df4bd476c828890c51e6840d3ec3e92209e28b977e21919154502544*14*64*f16b266e8ea297338c7bfea61574f66383b10c7f1df77a6d3aeaf85aa50381f8a122a8dc51bc9d33f6234bb1f31d93bd784a82a5bcade304c0f4081f057a4feb*0*1000";

#include "hooks_common.c"

typedef struct dmg_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} dmg_tmp_t;

typedef struct dmg
{
  u32 iv[8];         // 32 bytes (only the first 8 are used by the format)

  u32 keyblob[16];   // 48 or 64 bytes
  int keyblob_len;

  u32 cno;
  u32 data_size;

  u32 chunk[2048];   // data chunk, up to 8192 bytes

  u32 zchunk[1024];  // zero chunk, up to 4096 bytes
  int zchunk_len;    // 0 if scp == 0

} dmg_t;

static const char *SIGNATURE_DMG = "$dmg$2";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (dmg_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (dmg_tmp_t);

  return tmp_size;
}

static u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }
static u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 48; }

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dmg_t *dmg = (dmg_t *) esalt_buf;

  // dmg2john appends "::::filename" to the line; that suffix is not part of the hash

  int input_len = line_len;

  for (int i = 0; i + 4 <= line_len; i++)
  {
    if (memcmp (line_buf + i, "::::", 4) == 0)
    {
      input_len = i;

      break;
    }
  }

  // the zero chunk (scp == 1) and the iterations field are optional, so the line
  // carries 10, 11 or 12 separators. with 11 separators the last field is either
  // the zero chunk (scp == 1) or the iterations (scp == 0); the scp field itself
  // is a single digit right after the 10th separator, so peek at it.

  int sep_cnt = 0;

  int scp_peek = -1;

  for (int i = 0; i < input_len; i++)
  {
    if (line_buf[i] == '*')
    {
      sep_cnt++;

      if (sep_cnt == 10)
      {
        if (i + 1 < input_len)
        {
          if (line_buf[i + 1] == '0') scp_peek = 0;
          if (line_buf[i + 1] == '1') scp_peek = 1;
        }
      }
    }
  }

  if ((sep_cnt < 10) || (sep_cnt > 12)) return (PARSER_SEPARATOR_UNMATCHED);

  if (scp_peek == -1) return (PARSER_SEPARATOR_UNMATCHED);

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = sep_cnt + 1;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DMG;

  token.sep[0]     = '*';
  token.len[0]     = 6; // "$dmg$2"
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';   // salt len (bytes)
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';   // salt hex (up to 48 bytes)
  token.len_min[2] = 2;
  token.len_max[2] = 96;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';   // iv len (bytes)
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';   // iv hex (up to 32 bytes)
  token.len_min[4] = 16;
  token.len_max[4] = 64;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';   // keyblob len (bytes)
  token.len_min[5] = 2;
  token.len_max[5] = 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';   // keyblob hex (48 or 64 bytes)
  token.len_min[6] = 96;
  token.len_max[6] = 128;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '*';   // chunk number
  token.len_min[7] = 1;
  token.len_max[7] = 10;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '*';   // data size (bytes)
  token.len_min[8] = 2;
  token.len_max[8] = 4;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]     = '*';   // data chunk hex (up to 8192 bytes)
  token.len_min[9] = 32;
  token.len_max[9] = 16384;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[10]    = (sep_cnt == 10) ? 0 : '*'; // scp flag
  token.len_min[10] = 1;
  token.len_max[10] = 1;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  if (sep_cnt == 11)
  {
    if (scp_peek == 0)
    {
      token.len_min[11] = 1;  // iterations (last token, no separator)
      token.len_max[11] = 8;
      token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
    }
    else
    {
      token.len_min[11] = 32; // zero chunk hex (up to 4096 bytes, last token)
      token.len_max[11] = 8192;
      token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
    }
  }
  else if (sep_cnt == 12)
  {
    token.sep[11]     = '*';  // zero chunk hex (up to 4096 bytes)
    token.len_min[11] = 32;
    token.len_max[11] = 8192;
    token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[12] = 1;    // iterations (last token, no separator)
    token.len_max[12] = 8;
    token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // validate declared fields against the actual tokens

  const u32 declared_salt_len = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 declared_iv_len   = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 declared_blob_len = hc_strtoul ((const char *) token.buf[5], NULL, 10);

  if (declared_salt_len < 1 || declared_salt_len > 48) return (PARSER_SALT_LENGTH);
  if ((u32) token.len[2] / 2 != declared_salt_len)     return (PARSER_SALT_LENGTH);

  if (declared_iv_len < 8 || declared_iv_len > 32)   return (PARSER_IV_LENGTH);
  if ((u32) token.len[4] / 2 != declared_iv_len)     return (PARSER_IV_LENGTH);

  if (declared_blob_len != 48 && declared_blob_len != 64) return (PARSER_HASH_LENGTH);
  if ((u32) token.len[6] / 2 != declared_blob_len)        return (PARSER_HASH_LENGTH);

  const u32 data_size = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if (data_size < 16 || data_size > 8192)        return (PARSER_HASH_LENGTH);
  if ((u32) token.len[9] / 2 != data_size)       return (PARSER_HASH_LENGTH);

  const u32 scp = hc_strtoul ((const char *) token.buf[10], NULL, 10);

  if (scp > 1) return (PARSER_HASH_VALUE);

  if (scp != (u32) scp_peek) return (PARSER_SEPARATOR_UNMATCHED);

  int zchunk_idx = -1;
  int iter_idx   = -1;

  if (sep_cnt == 11)
  {
    if (scp == 1) zchunk_idx = 11;
    else          iter_idx   = 11;
  }
  else if (sep_cnt == 12)
  {
    zchunk_idx = 11;
    iter_idx   = 12;
  }

  if (scp == 1)
  {
    if (zchunk_idx == -1) return (PARSER_SEPARATOR_UNMATCHED);

    const u32 zchunk_len = (u32) token.len[zchunk_idx] / 2;

    if (zchunk_len < 16 || zchunk_len > 4096) return (PARSER_HASH_LENGTH);
    if (zchunk_len % 16 != 0)                 return (PARSER_HASH_LENGTH);
  }
  else
  {
    if (zchunk_idx != -1) return (PARSER_SEPARATOR_UNMATCHED);
  }

  // salt

  salt->salt_len = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);

  // iterations

  u32 iter = 1000;

  if (iter_idx != -1)
  {
    iter = hc_strtoul ((const char *) token.buf[iter_idx], NULL, 10);
  }

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // esalt

  hex_decode (token.buf[4], token.len[4], (u8 *) dmg->iv);

  dmg->keyblob_len = hex_decode (token.buf[6], token.len[6], (u8 *) dmg->keyblob);

  dmg->cno       = hc_strtoul ((const char *) token.buf[7], NULL, 10);
  dmg->data_size = data_size;

  hex_decode (token.buf[9], token.len[9], (u8 *) dmg->chunk);

  dmg->zchunk_len = 0;

  if (zchunk_idx != -1)
  {
    dmg->zchunk_len = hex_decode (token.buf[zchunk_idx], token.len[zchunk_idx], (u8 *) dmg->zchunk);
  }

  // identity digest = MD5 of the key blob, so distinct blobs that share a salt
  // still get distinct identities for dedup/potfile. The kernel reports the same
  // MD5 on a match; the real password check is the 3DES unwrap + chunk scan.

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, dmg->keyblob, dmg->keyblob_len);

  md5_final (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const dmg_t *dmg = (const dmg_t *) esalt_buf;

  char salt_buf[97] = { 0 };
  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  char iv_buf[65] = { 0 };
  hex_encode ((const u8 *) dmg->iv, 32, (u8 *) iv_buf);

  char blob_buf[129] = { 0 };
  hex_encode ((const u8 *) dmg->keyblob, dmg->keyblob_len, (u8 *) blob_buf);

  char chunk_buf[16385] = { 0 };
  hex_encode ((const u8 *) dmg->chunk, dmg->data_size, (u8 *) chunk_buf);

  int out_len;

  if (dmg->zchunk_len > 0)
  {
    char zchunk_buf[8193] = { 0 };
    hex_encode ((const u8 *) dmg->zchunk, dmg->zchunk_len, (u8 *) zchunk_buf);

    out_len = snprintf (line_buf, line_size, "%s*%d*%s*32*%s*%d*%s*%u*%u*%s*1*%s*%u",
      SIGNATURE_DMG,
      salt->salt_len,
      salt_buf,
      iv_buf,
      dmg->keyblob_len,
      blob_buf,
      dmg->cno,
      dmg->data_size,
      chunk_buf,
      zchunk_buf,
      salt->salt_iter + 1);
  }
  else
  {
    out_len = snprintf (line_buf, line_size, "%s*%d*%s*32*%s*%d*%s*%u*%u*%s*0*%u",
      SIGNATURE_DMG,
      salt->salt_len,
      salt_buf,
      iv_buf,
      dmg->keyblob_len,
      blob_buf,
      dmg->cno,
      dmg->data_size,
      chunk_buf,
      salt->salt_iter + 1);
  }

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
