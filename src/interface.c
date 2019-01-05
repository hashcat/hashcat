/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "memory.h"
#include "convert.h"
#include "event.h"
#include "shared.h"
#include "opencl.h"
#include "interface.h"
#include "filehandling.h"
#include "ext_lzma.h"
#include "modules.h"
#include "dynloader.h"
#include "cpu_crc32.h"

static const char *ST_PASS_HASHCAT_PLAIN = "hashcat";
static const char *ST_PASS_HASHCAT_EXCL  = "hashcat!";
static const char *ST_PASS_HASHCAT_EXCL3 = "hashcat!!!";
static const char *ST_PASS_HASHCAT_ONE   = "hashcat1";
static const char *ST_PASS_HASHCAT_ONET3 = "hashcat1hashcat1hashcat1";

static const char *OPTI_STR_OPTIMIZED_KERNEL     = "Optimized-Kernel";
static const char *OPTI_STR_ZERO_BYTE            = "Zero-Byte";
static const char *OPTI_STR_PRECOMPUTE_INIT      = "Precompute-Init";
static const char *OPTI_STR_PRECOMPUTE_MERKLE    = "Precompute-Merkle-Demgard";
static const char *OPTI_STR_PRECOMPUTE_PERMUT    = "Precompute-Final-Permutation";
static const char *OPTI_STR_MEET_IN_MIDDLE       = "Meet-In-The-Middle";
static const char *OPTI_STR_EARLY_SKIP           = "Early-Skip";
static const char *OPTI_STR_NOT_SALTED           = "Not-Salted";
static const char *OPTI_STR_NOT_ITERATED         = "Not-Iterated";
static const char *OPTI_STR_PREPENDED_SALT       = "Prepended-Salt";
static const char *OPTI_STR_APPENDED_SALT        = "Appended-Salt";
static const char *OPTI_STR_SINGLE_HASH          = "Single-Hash";
static const char *OPTI_STR_SINGLE_SALT          = "Single-Salt";
static const char *OPTI_STR_BRUTE_FORCE          = "Brute-Force";
static const char *OPTI_STR_RAW_HASH             = "Raw-Hash";
static const char *OPTI_STR_SLOW_HASH_SIMD_INIT  = "Slow-Hash-SIMD-INIT";
static const char *OPTI_STR_SLOW_HASH_SIMD_LOOP  = "Slow-Hash-SIMD-LOOP";
static const char *OPTI_STR_SLOW_HASH_SIMD_COMP  = "Slow-Hash-SIMD-COMP";
static const char *OPTI_STR_USES_BITS_8          = "Uses-8-Bit";
static const char *OPTI_STR_USES_BITS_16         = "Uses-16-Bit";
static const char *OPTI_STR_USES_BITS_32         = "Uses-32-Bit";
static const char *OPTI_STR_USES_BITS_64         = "Uses-64-Bit";

/**
 * parser
 */

static int sort_by_src_len (const void *p1, const void *p2)
{
  const keyboard_layout_mapping_t *k1 = (const keyboard_layout_mapping_t *) p1;
  const keyboard_layout_mapping_t *k2 = (const keyboard_layout_mapping_t *) p2;

  return k1->src_len < k2->src_len;
}

bool initialize_keyboard_layout_mapping (hashcat_ctx_t *hashcat_ctx, const char *filename, keyboard_layout_mapping_t *keyboard_layout_mapping, int *keyboard_layout_mapping_cnt)
{
  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  FILE *fp = fopen (filename, "r");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

    return false;
  }

  int maps_cnt = 0;

  while (!feof (fp))
  {
    const size_t line_len = fgetl (fp, line_buf);

    if (line_len == 0) continue;

    token_t token;

    token.token_cnt  = 2;

    token.len_min[0] = 1;
    token.len_max[0] = 4;
    token.sep[0]     = 0x09;
    token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len_min[1] = 0;
    token.len_max[1] = 4;
    token.sep[1]     = 0x09;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, (const int) line_len, &token);

    if (rc_tokenizer != PARSER_OK)
    {
      event_log_error (hashcat_ctx, "%s: Syntax error: %s", filename, line_buf);

      fclose (fp);

      free (line_buf);

      return false;
    }

    memcpy (&keyboard_layout_mapping[maps_cnt].src_char, token.buf[0], token.len[0]);
    memcpy (&keyboard_layout_mapping[maps_cnt].dst_char, token.buf[1], token.len[1]);

    keyboard_layout_mapping[maps_cnt].src_len = token.len[0];
    keyboard_layout_mapping[maps_cnt].dst_len = token.len[1];

    if (maps_cnt == 256)
    {
      event_log_error (hashcat_ctx, "%s: too many entries", filename);

      fclose (fp);

      free (line_buf);

      return false;
    }

    maps_cnt++;
  }

  *keyboard_layout_mapping_cnt = maps_cnt;

  fclose (fp);

  free (line_buf);

  // we need to sort this by length to ensure the largest blocks come first in mapping

  qsort (keyboard_layout_mapping, maps_cnt, sizeof (keyboard_layout_mapping_t), sort_by_src_len);

  return true;
}

static bool parse_and_store_generic_salt (u8 *out_buf, int *out_len, const u8 *in_buf, const int in_len, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 tmp_u32[(64 * 2) + 1] = { 0 };

  if (in_len > 512) return false; // 512 = 2 * 256 -- (2 * because of hex), 256 because of maximum salt length in salt_t

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if (in_len < (int) (hashconfig->salt_min * 2)) return false;
    if (in_len > (int) (hashconfig->salt_max * 2)) return false;
  }
  else
  {
    if (in_len < (int) hashconfig->salt_min) return false;
    if (in_len > (int) hashconfig->salt_max) return false;
  }

  u8 *tmp_buf = (u8 *) tmp_u32;

  int tmp_len = 0;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if (tmp_len & 1) return false;

    tmp_len = in_len / 2;

    for (int i = 0, j = 0; i < tmp_len; i += 1, j += 2)
    {
      u8 p0 = in_buf[j + 0];
      u8 p1 = in_buf[j + 1];

      tmp_buf[i]  = hex_convert (p1) << 0;
      tmp_buf[i] |= hex_convert (p0) << 4;
    }
  }
  else if (hashconfig->opts_type & OPTS_TYPE_ST_BASE64)
  {
    tmp_len = base64_decode (base64_to_int, (const u8 *) in_buf, in_len, tmp_buf);
  }
  else
  {
    if (in_len) memcpy (tmp_buf, in_buf, in_len);

    tmp_len = in_len;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE)
  {
    if (tmp_len >= 128) return false;

    for (int i = 64 - 1; i >= 1; i -= 2)
    {
      const u32 v = tmp_u32[i / 2];

      tmp_u32[i - 0] = ((v >> 8) & 0x00FF0000) | ((v >> 16) & 0x000000FF);
      tmp_u32[i - 1] = ((v << 8) & 0x00FF0000) | ((v >>  0) & 0x000000FF);
    }

    tmp_len = tmp_len * 2;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_LOWER)
  {
    lowercase (tmp_buf, tmp_len);
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UPPER)
  {
    uppercase (tmp_buf, tmp_len);
  }

  int tmp2_len = tmp_len;

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    if (tmp2_len >= 256) return false;

    tmp_buf[tmp2_len++] = 0x80;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD01)
  {
    if (tmp2_len >= 256) return false;

    tmp_buf[tmp2_len++] = 0x01;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_GENERATE_LE)
  {
    u32 max = tmp2_len / 4;

    if (tmp2_len % 4) max++;

    for (u32 i = 0; i < max; i++)
    {
      tmp_u32[i] = byte_swap_32 (tmp_u32[i]);
    }

    // Important: we may need to increase the length of memcpy since
    // we don't want to "loose" some swapped bytes (could happen if
    // they do not perfectly fit in the 4-byte blocks)
    // Memcpy does always copy the bytes in the BE order, but since
    // we swapped them, some important bytes could be in positions
    // we normally skip with the original len

    if (tmp2_len % 4) tmp2_len += 4 - (tmp2_len % 4);
  }

  memcpy (out_buf, tmp_buf, tmp2_len);

  *out_len = tmp_len;

  return true;
}

/**
 * output
 */

const char *stroptitype (const u32 opti_type)
{
  switch (opti_type)
  {
    case OPTI_TYPE_OPTIMIZED_KERNEL:    return OPTI_STR_OPTIMIZED_KERNEL;
    case OPTI_TYPE_ZERO_BYTE:           return OPTI_STR_ZERO_BYTE;
    case OPTI_TYPE_PRECOMPUTE_INIT:     return OPTI_STR_PRECOMPUTE_INIT;
    case OPTI_TYPE_PRECOMPUTE_MERKLE:   return OPTI_STR_PRECOMPUTE_MERKLE;
    case OPTI_TYPE_PRECOMPUTE_PERMUT:   return OPTI_STR_PRECOMPUTE_PERMUT;
    case OPTI_TYPE_MEET_IN_MIDDLE:      return OPTI_STR_MEET_IN_MIDDLE;
    case OPTI_TYPE_EARLY_SKIP:          return OPTI_STR_EARLY_SKIP;
    case OPTI_TYPE_NOT_SALTED:          return OPTI_STR_NOT_SALTED;
    case OPTI_TYPE_NOT_ITERATED:        return OPTI_STR_NOT_ITERATED;
    case OPTI_TYPE_PREPENDED_SALT:      return OPTI_STR_PREPENDED_SALT;
    case OPTI_TYPE_APPENDED_SALT:       return OPTI_STR_APPENDED_SALT;
    case OPTI_TYPE_SINGLE_HASH:         return OPTI_STR_SINGLE_HASH;
    case OPTI_TYPE_SINGLE_SALT:         return OPTI_STR_SINGLE_SALT;
    case OPTI_TYPE_BRUTE_FORCE:         return OPTI_STR_BRUTE_FORCE;
    case OPTI_TYPE_RAW_HASH:            return OPTI_STR_RAW_HASH;
    case OPTI_TYPE_SLOW_HASH_SIMD_INIT: return OPTI_STR_SLOW_HASH_SIMD_INIT;
    case OPTI_TYPE_SLOW_HASH_SIMD_LOOP: return OPTI_STR_SLOW_HASH_SIMD_LOOP;
    case OPTI_TYPE_SLOW_HASH_SIMD_COMP: return OPTI_STR_SLOW_HASH_SIMD_COMP;
    case OPTI_TYPE_USES_BITS_8:         return OPTI_STR_USES_BITS_8;
    case OPTI_TYPE_USES_BITS_16:        return OPTI_STR_USES_BITS_16;
    case OPTI_TYPE_USES_BITS_32:        return OPTI_STR_USES_BITS_32;
    case OPTI_TYPE_USES_BITS_64:        return OPTI_STR_USES_BITS_64;
  }

  return NULL;
}

int ascii_digest (const hashconfig_t *hashconfig, const hashes_t *hashes, const module_ctx_t *module_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  void        *digests_buf = hashes->digests_buf;
  salt_t      *salts_buf   = hashes->salts_buf;
  void        *esalts_buf  = hashes->esalts_buf;
  hashinfo_t **hash_info   = hashes->hash_info;
  const char  *hashfile    = hashes->hashfile;

  const u32 dgst_size  = hashconfig->dgst_size;
  const u64 esalt_size = hashconfig->esalt_size;

  //const u32 hash_type  = hashconfig->hash_type;
  //const u32 hash_mode  = hashconfig->hash_mode;
  //const u32 salt_type  = hashconfig->salt_type;

  //const u32 digest_cur = salts_buf[salt_pos].digests_offset + digest_pos;

  //u8 datax[256] = { 0 };

  //u64 *digest_buf64 = (u64 *) datax;
  //u32 *digest_buf   = (u32 *) datax;

  char *digests_buf_ptr = (char *) digests_buf;

  //memcpy (digest_buf, digests_buf_ptr + (salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

  char *esalts_buf_ptr = (char *) esalts_buf;

  //salt_t salt;

  /*
  if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
  {
    u32 tt;

    switch (hash_type)
    {
      case HASH_TYPE_DES:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_DESCRYPT:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_DESRACF:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_LM:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_NETNTLM:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);
        digest_buf[2] = rotl32 (digest_buf[2], 29);
        digest_buf[3] = rotl32 (digest_buf[3], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        FP (digest_buf[3], digest_buf[2], tt);
        break;

      case HASH_TYPE_BSDICRYPT:
        digest_buf[0] = rotl32 (digest_buf[0], 31);
        digest_buf[1] = rotl32 (digest_buf[1], 31);

        FP (digest_buf[1], digest_buf[0], tt);
        break;
    }
  }

  if (opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    switch (hash_type)
    {
      case HASH_TYPE_MD4:
        digest_buf[0] += MD4M_A;
        digest_buf[1] += MD4M_B;
        digest_buf[2] += MD4M_C;
        digest_buf[3] += MD4M_D;
        break;

      case HASH_TYPE_MD5:
        digest_buf[0] += MD5M_A;
        digest_buf[1] += MD5M_B;
        digest_buf[2] += MD5M_C;
        digest_buf[3] += MD5M_D;
        break;

      case HASH_TYPE_SHA1:
        digest_buf[0] += SHA1M_A;
        digest_buf[1] += SHA1M_B;
        digest_buf[2] += SHA1M_C;
        digest_buf[3] += SHA1M_D;
        digest_buf[4] += SHA1M_E;
        break;

      case HASH_TYPE_SHA224:
        digest_buf[0] += SHA224M_A;
        digest_buf[1] += SHA224M_B;
        digest_buf[2] += SHA224M_C;
        digest_buf[3] += SHA224M_D;
        digest_buf[4] += SHA224M_E;
        digest_buf[5] += SHA224M_F;
        digest_buf[6] += SHA224M_G;
        break;

      case HASH_TYPE_SHA256:
        digest_buf[0] += SHA256M_A;
        digest_buf[1] += SHA256M_B;
        digest_buf[2] += SHA256M_C;
        digest_buf[3] += SHA256M_D;
        digest_buf[4] += SHA256M_E;
        digest_buf[5] += SHA256M_F;
        digest_buf[6] += SHA256M_G;
        digest_buf[7] += SHA256M_H;
        break;

      case HASH_TYPE_SHA384:
        digest_buf64[0] += SHA384M_A;
        digest_buf64[1] += SHA384M_B;
        digest_buf64[2] += SHA384M_C;
        digest_buf64[3] += SHA384M_D;
        digest_buf64[4] += SHA384M_E;
        digest_buf64[5] += SHA384M_F;
        digest_buf64[6] += 0;
        digest_buf64[7] += 0;
        break;

      case HASH_TYPE_SHA512:
        digest_buf64[0] += SHA512M_A;
        digest_buf64[1] += SHA512M_B;
        digest_buf64[2] += SHA512M_C;
        digest_buf64[3] += SHA512M_D;
        digest_buf64[4] += SHA512M_E;
        digest_buf64[5] += SHA512M_F;
        digest_buf64[6] += SHA512M_G;
        digest_buf64[7] += SHA512M_H;
        break;
    }
  }

  if (opts_type & OPTS_TYPE_PT_GENERATE_LE)
  {
    if (dgst_size == DGST_SIZE_4_2)
    {
      for (int i = 0; i < 2; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_4)
    {
      for (int i = 0; i < 4; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_5)
    {
      for (int i = 0; i < 5; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_6)
    {
      for (int i = 0; i < 6; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_7)
    {
      for (int i = 0; i < 7; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_8)
    {
      for (int i = 0; i < 8; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if ((dgst_size == DGST_SIZE_4_16) || (dgst_size == DGST_SIZE_8_8)) // same size, same result :)
    {
      if (hash_type == HASH_TYPE_WHIRLPOOL)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
      else if (hash_type == HASH_TYPE_SHA384)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_SHA512)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_GOST)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
    }
    else if (dgst_size == DGST_SIZE_4_64)
    {
      for (int i = 0; i < 64; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_8_25)
    {
      for (int i = 0; i < 25; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
    }
  }

  const bool isSalted = ((hashconfig->salt_type == SALT_TYPE_GENERIC)
                      |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED));

  if (isSalted == true)
  {
    memcpy (&salt, &salts_buf[salt_pos], sizeof (salt_t));

    char *ptr = (char *) salt.salt_buf;

    if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
    {
      switch (hash_type)
      {
        case HASH_TYPE_NETNTLM:

          salt.salt_buf[0] = rotr32 (salt.salt_buf[0], 3);
          salt.salt_buf[1] = rotr32 (salt.salt_buf[1], 3);

          u32 tt;

          FP (salt.salt_buf[1], salt.salt_buf[0], tt);

          break;
      }
    }

    u32 salt_len = salt.salt_len;

    if (opts_type & OPTS_TYPE_ST_UTF16LE)
    {
      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        ptr[i] = ptr[j];
      }

      salt_len = salt_len / 2;
    }

    if (opts_type & OPTS_TYPE_ST_GENERATE_LE)
    {
      u32 max = salt.salt_len / 4;

      if (salt_len % 4) max++;

      for (u32 i = 0; i < max; i++)
      {
        salt.salt_buf[i] = byte_swap_32 (salt.salt_buf[i]);
      }
    }

    if (opts_type & OPTS_TYPE_ST_HEX)
    {
      char tmp[64] = { 0 };

      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        sprintf (tmp + j, "%02x", (unsigned char) ptr[i]);
      }

      salt_len = salt_len * 2;

      memcpy (ptr, tmp, salt_len);
    }

    u32 memset_size = ((SALT_MAX - (int) salt_len) > 0) ? (SALT_MAX - salt_len) : 0;

    memset (ptr + salt_len, 0, memset_size);

    salt.salt_len = salt_len;
  }
  else
  {
    memset (&salt, 0, sizeof (salt_t));
  }
  */

  //
  // some modes require special encoding
  //

  //u32 out_buf_plain[256] = { 0 };
  //u32 out_buf_salt[256]  = { 0 };

  //char tmp_buf[1024] = { 0 };

  //char *ptr_plain = (char *) out_buf_plain;
  //u8   *ptr_salt  = (u8 *)   out_buf_salt;

  const int out_len = module_ctx->module_hash_encode
  (
    hashconfig,
    digests_buf_ptr + (salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size),
    salts_buf + salt_pos,
    esalts_buf_ptr + (salts_buf[salt_pos].digests_offset * esalt_size) + (digest_pos * esalt_size),
    out_buf,
    out_size
  );

  return out_len;

  /*
  if (salt_type == SALT_TYPE_GENERIC)
  {
    size_t pos = strlen (out_buf);

    out_buf[pos] = hashconfig->separator;

    char *ptr = (char *) salt.salt_buf;

    memcpy (out_buf + pos + 1, ptr, salt.salt_len);

    out_buf[pos + 1 + salt.salt_len] = 0;
  }
  */

}

static bool module_load (hashcat_ctx_t *hashcat_ctx, module_ctx_t *module_ctx, const u32 hash_mode)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  char *module_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  #if defined (_WIN)
  snprintf (module_file, HCBUFSIZ_TINY, "%s/modules/module_%05d.dll", folder_config->shared_dir, hash_mode);
  #else
  snprintf (module_file, HCBUFSIZ_TINY, "%s/modules/module_%05d.so", folder_config->shared_dir, hash_mode);
  #endif

  module_ctx->module_handle = hc_dlopen (module_file);

  if (module_ctx->module_handle == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot load module %s", module_file);

    #if defined (_WIN)

    #else
    event_log_error (hashcat_ctx, "%s", dlerror ());
    #endif

    return false;
  }

  module_ctx->module_init = hc_dlsym (module_ctx->module_handle, "module_init");

  if (module_ctx->module_init == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot load symbol 'module_init' in module %s", module_file);

    return false;
  }

  free (module_file);

  return true;
}

static void module_unload (module_ctx_t *module_ctx)
{
  hc_dlclose (module_ctx->module_handle);
}

int hashconfig_init (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t      *folder_config      = hashcat_ctx->folder_config;
        hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
        module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // set some boring defaults

  hashconfig->attack_exec             = default_attack_exec             (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos0               = default_dgst_pos0               (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos1               = default_dgst_pos1               (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos2               = default_dgst_pos2               (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos3               = default_dgst_pos3               (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_size               = default_dgst_size               (hashconfig, user_options, user_options_extra);
  hashconfig->dictstat_disable        = default_dictstat_disable        (hashconfig, user_options, user_options_extra);
  hashconfig->esalt_size              = default_esalt_size              (hashconfig, user_options, user_options_extra);
  hashconfig->forced_outfile_format   = default_forced_outfile_format   (hashconfig, user_options, user_options_extra);
  hashconfig->hash_category           = default_hash_category           (hashconfig, user_options, user_options_extra);
  hashconfig->hash_mode               = default_hash_mode               (hashconfig, user_options, user_options_extra);
  hashconfig->hash_name               = default_hash_name               (hashconfig, user_options, user_options_extra);
  hashconfig->hash_type               = default_hash_type               (hashconfig, user_options, user_options_extra);
  hashconfig->hlfmt_disable           = default_hlfmt_disable           (hashconfig, user_options, user_options_extra);
  hashconfig->hook_salt_size          = default_hook_salt_size          (hashconfig, user_options, user_options_extra);
  hashconfig->hook_size               = default_hook_size               (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_min        = default_kernel_accel_min        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_max        = default_kernel_accel_max        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_min        = default_kernel_loops_min        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_max        = default_kernel_loops_max        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_min      = default_kernel_threads_min      (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_max      = default_kernel_threads_max      (hashconfig, user_options, user_options_extra);
  hashconfig->kern_type               = default_kern_type               (hashconfig, user_options, user_options_extra);
  hashconfig->opti_type               = default_opti_type               (hashconfig, user_options, user_options_extra);
  hashconfig->opts_type               = default_opts_type               (hashconfig, user_options, user_options_extra);
  hashconfig->outfile_check_disable   = default_outfile_check_disable   (hashconfig, user_options, user_options_extra);
  hashconfig->outfile_check_nocomp    = default_outfile_check_nocomp    (hashconfig, user_options, user_options_extra);
  hashconfig->potfile_disable         = default_potfile_disable         (hashconfig, user_options, user_options_extra);
  hashconfig->potfile_keep_all_hashes = default_potfile_keep_all_hashes (hashconfig, user_options, user_options_extra);
  hashconfig->pwdump_column           = default_pwdump_column           (hashconfig, user_options, user_options_extra);
  hashconfig->salt_type               = default_salt_type               (hashconfig, user_options, user_options_extra);
  hashconfig->separator               = default_separator               (hashconfig, user_options, user_options_extra);
  hashconfig->st_hash                 = default_st_hash                 (hashconfig, user_options, user_options_extra);
  hashconfig->st_pass                 = default_st_pass                 (hashconfig, user_options, user_options_extra);
  hashconfig->tmp_size                = default_tmp_size                (hashconfig, user_options, user_options_extra);
  hashconfig->unstable_warning        = default_unstable_warning        (hashconfig, user_options, user_options_extra);
  hashconfig->warmup_disable          = default_warmup_disable          (hashconfig, user_options, user_options_extra);

  // finally, the real stuff

  const bool rc_load = module_load (hashcat_ctx, module_ctx, user_options->hash_mode);

  if (rc_load == false) return -1;

  module_ctx->module_init (module_ctx);

  if (module_ctx->module_version_current < MODULE_VERSION_MINIMUM)
  {
    event_log_error (hashcat_ctx, "module version current (%u) older than minimum (%u)", module_ctx->module_version_current, MODULE_VERSION_MINIMUM);

    return -1;
  }

  if (module_ctx->module_attack_exec              != MODULE_DEFAULT) hashconfig->attack_exec             = module_ctx->module_attack_exec              (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos0                != MODULE_DEFAULT) hashconfig->dgst_pos0               = module_ctx->module_dgst_pos0                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos1                != MODULE_DEFAULT) hashconfig->dgst_pos1               = module_ctx->module_dgst_pos1                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos2                != MODULE_DEFAULT) hashconfig->dgst_pos2               = module_ctx->module_dgst_pos2                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos3                != MODULE_DEFAULT) hashconfig->dgst_pos3               = module_ctx->module_dgst_pos3                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_size                != MODULE_DEFAULT) hashconfig->dgst_size               = module_ctx->module_dgst_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dictstat_disable         != MODULE_DEFAULT) hashconfig->dictstat_disable        = module_ctx->module_dictstat_disable         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_esalt_size               != MODULE_DEFAULT) hashconfig->esalt_size              = module_ctx->module_esalt_size               (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_forced_outfile_format    != MODULE_DEFAULT) hashconfig->forced_outfile_format   = module_ctx->module_forced_outfile_format    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_category            != MODULE_DEFAULT) hashconfig->hash_category           = module_ctx->module_hash_category            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_mode                != MODULE_DEFAULT) hashconfig->hash_mode               = module_ctx->module_hash_mode                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_name                != MODULE_DEFAULT) hashconfig->hash_name               = module_ctx->module_hash_name                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_type                != MODULE_DEFAULT) hashconfig->hash_type               = module_ctx->module_hash_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hlfmt_disable            != MODULE_DEFAULT) hashconfig->hlfmt_disable           = module_ctx->module_hlfmt_disable            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_salt_size           != MODULE_DEFAULT) hashconfig->hook_salt_size          = module_ctx->module_hook_salt_size           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_size                != MODULE_DEFAULT) hashconfig->hook_size               = module_ctx->module_hook_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_min         != MODULE_DEFAULT) hashconfig->kernel_accel_min        = module_ctx->module_kernel_accel_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_max         != MODULE_DEFAULT) hashconfig->kernel_accel_max        = module_ctx->module_kernel_accel_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_min         != MODULE_DEFAULT) hashconfig->kernel_loops_min        = module_ctx->module_kernel_loops_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_max         != MODULE_DEFAULT) hashconfig->kernel_loops_max        = module_ctx->module_kernel_loops_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_min       != MODULE_DEFAULT) hashconfig->kernel_threads_min      = module_ctx->module_kernel_threads_min       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_max       != MODULE_DEFAULT) hashconfig->kernel_threads_max      = module_ctx->module_kernel_threads_max       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kern_type                != MODULE_DEFAULT) hashconfig->kern_type               = module_ctx->module_kern_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_opti_type                != MODULE_DEFAULT) hashconfig->opti_type               = module_ctx->module_opti_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_opts_type                != MODULE_DEFAULT) hashconfig->opts_type               = module_ctx->module_opts_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_disable    != MODULE_DEFAULT) hashconfig->outfile_check_disable   = module_ctx->module_outfile_check_disable    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_nocomp     != MODULE_DEFAULT) hashconfig->outfile_check_nocomp    = module_ctx->module_outfile_check_nocomp     (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_disable          != MODULE_DEFAULT) hashconfig->potfile_disable         = module_ctx->module_potfile_disable          (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_keep_all_hashes  != MODULE_DEFAULT) hashconfig->potfile_keep_all_hashes = module_ctx->module_potfile_keep_all_hashes  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pwdump_column            != MODULE_DEFAULT) hashconfig->pwdump_column           = module_ctx->module_pwdump_column            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_type                != MODULE_DEFAULT) hashconfig->salt_type               = module_ctx->module_salt_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_separator                != MODULE_DEFAULT) hashconfig->separator               = module_ctx->module_separator                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_st_hash                  != MODULE_DEFAULT) hashconfig->st_hash                 = module_ctx->module_st_hash                  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_st_pass                  != MODULE_DEFAULT) hashconfig->st_pass                 = module_ctx->module_st_pass                  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_tmp_size                 != MODULE_DEFAULT) hashconfig->tmp_size                = module_ctx->module_tmp_size                 (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_unstable_warning         != MODULE_DEFAULT) hashconfig->unstable_warning        = module_ctx->module_unstable_warning         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_warmup_disable           != MODULE_DEFAULT) hashconfig->warmup_disable          = module_ctx->module_warmup_disable           (hashconfig, user_options, user_options_extra);

  if (user_options->keyboard_layout_mapping)
  {
    if ((hashconfig->opts_type & OPTS_TYPE_KEYBOARD_MAPPING) == 0)
    {
      event_log_error (hashcat_ctx, "Parameter --keyboard-layout-mapping not valid for hash-type %u", hashconfig->hash_mode);

      return -1;
    }
  }

  if (user_options->hex_salt)
  {
    if (hashconfig->salt_type == SALT_TYPE_GENERIC)
    {
      hashconfig->opts_type |= OPTS_TYPE_ST_HEX;
    }
    else
    {
      event_log_error (hashcat_ctx, "Parameter --hex-salt not valid for hash-type %u", hashconfig->hash_mode);

      return -1;
    }
  }

  if (user_options->keep_guessing)
  {
    hashconfig->opts_type |= OPTS_TYPE_PT_NEVERCRACK;
  }

  hashconfig->has_optimized_kernel  = false;
  hashconfig->has_pure_kernel       = false;

  if (hashconfig->kern_type == (u32) -1)
  {
    // some hash modes tell hashcat about their exact hash-mode inside the parser (eg. luks and jwt)
  }
  else
  {
    // some kernels do not have an optimized kernel, simply because they do not need them
    // or because they are not yet converted, for them we should switch off optimized mode

    char source_file[256] = { 0 };

    generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, false, folder_config->shared_dir, source_file);

    hashconfig->has_pure_kernel = hc_path_read (source_file);

    generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, true, folder_config->shared_dir, source_file);

    hashconfig->has_optimized_kernel = hc_path_read (source_file);

    if (user_options->example_hashes == false)
    {
      if (user_options->optimized_kernel_enable == true)
      {
        if (hashconfig->has_optimized_kernel == false)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Optimized OpenCL kernel requested but not needed - falling back to pure OpenCL kernel", source_file);
        }
        else
        {
          hashconfig->opti_type |= OPTI_TYPE_OPTIMIZED_KERNEL;
        }
      }
      else
      {
        if (hashconfig->has_pure_kernel == false)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Pure OpenCL kernel not found, falling back to optimized OpenCL kernel", source_file);

          hashconfig->opti_type |= OPTI_TYPE_OPTIMIZED_KERNEL;
        }
        else
        {
          // nothing to do
        }
      }
    }
  }

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
  {
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16LE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16BE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD01;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD02;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD06;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD80;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADDBITS14;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADDBITS15;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_UTF16LE;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_UTF16BE;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD01;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD02;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;

    hashconfig->opti_type &= ~OPTI_TYPE_PRECOMPUTE_INIT;
    hashconfig->opti_type &= ~OPTI_TYPE_PRECOMPUTE_MERKLE;
    hashconfig->opti_type &= ~OPTI_TYPE_MEET_IN_MIDDLE;
    hashconfig->opti_type &= ~OPTI_TYPE_PREPENDED_SALT;
    hashconfig->opti_type &= ~OPTI_TYPE_APPENDED_SALT;
  }

  const bool is_salted = ((hashconfig->salt_type == SALT_TYPE_GENERIC)
                       |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED)
                       |  (hashconfig->salt_type == SALT_TYPE_VIRTUAL));

  hashconfig->is_salted = is_salted;

  // those depend on some previously defined values

  hashconfig->benchmark_esalt     = default_benchmark_esalt     (hashconfig, user_options, user_options_extra);
  hashconfig->benchmark_hook_salt = default_benchmark_hook_salt (hashconfig, user_options, user_options_extra);
  hashconfig->benchmark_mask      = default_benchmark_mask      (hashconfig, user_options, user_options_extra);
  hashconfig->benchmark_salt      = default_benchmark_salt      (hashconfig, user_options, user_options_extra);

  if (module_ctx->module_benchmark_esalt      != MODULE_DEFAULT) hashconfig->benchmark_esalt     = module_ctx->module_benchmark_esalt      (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_benchmark_hook_salt  != MODULE_DEFAULT) hashconfig->benchmark_hook_salt = module_ctx->module_benchmark_hook_salt  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_benchmark_mask       != MODULE_DEFAULT) hashconfig->benchmark_mask      = module_ctx->module_benchmark_mask       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_benchmark_salt       != MODULE_DEFAULT) hashconfig->benchmark_salt      = module_ctx->module_benchmark_salt       (hashconfig, user_options, user_options_extra);

  hashconfig->pw_max    = default_pw_max    (hashconfig, user_options, user_options_extra);
  hashconfig->pw_min    = default_pw_min    (hashconfig, user_options, user_options_extra);
  hashconfig->salt_max  = default_salt_max  (hashconfig, user_options, user_options_extra);
  hashconfig->salt_min  = default_salt_min  (hashconfig, user_options, user_options_extra);

  if (module_ctx->module_pw_max   != MODULE_DEFAULT) hashconfig->pw_max    = module_ctx->module_pw_max   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pw_min   != MODULE_DEFAULT) hashconfig->pw_min    = module_ctx->module_pw_min   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_max != MODULE_DEFAULT) hashconfig->salt_max  = module_ctx->module_salt_max (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_min != MODULE_DEFAULT) hashconfig->salt_min  = module_ctx->module_salt_min (hashconfig, user_options, user_options_extra);

  return 0;
}

void hashconfig_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  module_unload (module_ctx);

  memset (hashconfig, 0, sizeof (hashconfig_t));
}

int hashconfig_general_defaults (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  // truecrypt and veracrypt only
  if (((hashconfig->hash_mode >=  6200) && (hashconfig->hash_mode <=  6299))
   || ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode == 13799)))
  {
    hashes_t *hashes = hashcat_ctx->hashes;

    tc_t *tc = (tc_t *) hashes->esalts_buf;

    char *optional_param1 = NULL;

    if (user_options->truecrypt_keyfiles) optional_param1 = user_options->truecrypt_keyfiles;
    if (user_options->veracrypt_keyfiles) optional_param1 = user_options->veracrypt_keyfiles;

    if (optional_param1)
    {
      char *tcvc_keyfiles = optional_param1;

      char *keyfiles = hcstrdup (tcvc_keyfiles);

      if (keyfiles == NULL) return -1;

      char *saveptr = NULL;

      char *keyfile = strtok_r (keyfiles, ",", &saveptr);

      if (keyfile == NULL)
      {
        free (keyfiles);

        return -1;
      }

      do
      {
        const int rc_crc32 = cpu_crc32 (hashcat_ctx, keyfile, (u8 *) tc->keyfile_buf);

        if (rc_crc32 == -1)
        {
          free (keyfiles);

          return -1;
        }

      } while ((keyfile = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

      free (keyfiles);
    }

    // truecrypt and veracrypt boot only
    if (hashconfig->opts_type & OPTS_TYPE_KEYBOARD_MAPPING)
    {
      if (user_options->keyboard_layout_mapping)
      {
        const bool rc = initialize_keyboard_layout_mapping (hashcat_ctx, user_options->keyboard_layout_mapping, tc->keyboard_layout_mapping_buf, &tc->keyboard_layout_mapping_cnt);

        if (rc == false) return -1;
      }
    }
  }

  // veracrypt only
  if ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode == 13799))
  {
    if (user_options->veracrypt_pim)
    {
      // we can access salt directly here because in VC it's always just one salt not many

      hashes_t *hashes = hashcat_ctx->hashes;

      salt_t *salts_buf = hashes->salts_buf;

      salt_t *salt = &salts_buf[0];

      switch (hashconfig->hash_mode)
      {
        case 13711:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13712:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13713:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13721:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13722:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13723:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13731:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13732:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13733:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13741:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13742:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13743:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13751:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13752:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13753:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13761:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13762:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13763:  salt->salt_iter  = user_options->veracrypt_pim * 2048;
                     break;
        case 13771:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13772:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
        case 13773:  salt->salt_iter  = 15000 + (user_options->veracrypt_pim * 1000);
                     break;
      }

      salt->salt_iter -= 1;
    }
  }

  return 0;
}

void hashconfig_benchmark_defaults (hashcat_ctx_t *hashcat_ctx, salt_t *salt, void *esalt, void *hook_salt)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig->is_salted == true)
  {
    memcpy (salt, hashconfig->benchmark_salt, sizeof (salt_t));

    memcpy (esalt, hashconfig->benchmark_esalt, hashconfig->esalt_size);

    memcpy (hook_salt, hashconfig->benchmark_hook_salt, hashconfig->hook_salt_size);
  }
}

u32 default_hash_mode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hash_mode = user_options->hash_mode;

  return hash_mode;
}

u32 default_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 attack_exec = ATTACK_EXEC_INSIDE_KERNEL;

  return attack_exec;
}

u32 default_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 dgst_pos0 = 0;

  return dgst_pos0;
}

u32 default_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 dgst_pos1 = 1;

  return dgst_pos1;
}

u32 default_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 dgst_pos2 = 2;

  return dgst_pos2;
}

u32 default_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 dgst_pos3 = 3;

  return dgst_pos3;
}

u32 default_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 dgst_size = DGST_SIZE_4_4;

  return dgst_size;
}

u32 default_hash_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hash_type = 0;

  return hash_type;
}

const char *default_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *hash_name = "<empty default>";

  return hash_name;
}

u32 default_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hash_category = HASH_CATEGORY_UNDEFINED;

  return hash_category;
}

u32 default_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // pw_min : algo specific hard min length

  u32 pw_min = PW_MIN;

  if (optimized_kernel == true)
  {
    // unused case
  }

  return pw_min;
}

u32 default_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // pw_max : some algo suffer from support for long passwords,
  //          the user need to add -L to enable support for them

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = PW_MAX_OLD;

    if ((hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE))
    {
      pw_max /= 2;
    }

    #define PW_DICTMAX 31

    if ((user_options->rp_files_cnt > 0) || (user_options->rp_gen > 0))
    {
      if (user_options->slow_candidates == true)
      {
        pw_max = MIN (pw_max, PW_DICTMAX);
      }
      else
      {
        switch (user_options_extra->attack_kern)
        {
          case ATTACK_KERN_STRAIGHT:  pw_max = MIN (pw_max, PW_DICTMAX);
                                      break;
          case ATTACK_KERN_COMBI:     pw_max = MIN (pw_max, PW_DICTMAX);
                                      break;
        }
      }
    }
    else
    {
      if (user_options->slow_candidates == true)
      {
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          pw_max = MIN (pw_max, PW_DICTMAX);
        }
        else
        {
          // If we have a NOOP rule then we can process words from wordlists > PW_DICTMAX for slow hashes
        }
      }
      else
      {
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          switch (user_options_extra->attack_kern)
          {
            case ATTACK_KERN_STRAIGHT:  pw_max = MIN (pw_max, PW_DICTMAX);
                                        break;
            case ATTACK_KERN_COMBI:     pw_max = MIN (pw_max, PW_DICTMAX);
                                        break;
          }
        }
        else
        {
          // If we have a NOOP rule then we can process words from wordlists > PW_DICTMAX for slow hashes
        }
      }
    }
  }

  return pw_max;
}

u32 default_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // salt_min : this limit is only interessting for generic hash types that support a salt

  u32 salt_min = SALT_MIN;

  if (hashconfig->salt_type == SALT_TYPE_GENERIC)
  {
    if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
    {
      salt_min *= 2;
    }
  }

  return salt_min;
}

u32 default_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // salt_max : this limit is only interessting for generic hash types that support a salt

  u32 salt_max = SALT_MAX;

  if (optimized_kernel == true)
  {
    salt_max = SALT_MAX_OLD;

    if ((hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_ST_UTF16BE))
    {
      salt_max /= 2;
    }
  }

  if (hashconfig->salt_type == SALT_TYPE_GENERIC)
  {
    if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
    {
      salt_max *= 2;
    }
  }

  return salt_max;
}

void *default_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  void *esalt = (void *) hcmalloc (hashconfig->esalt_size);

  return esalt;
}

void *default_benchmark_hook_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  void *hook_salt = (void *) hcmalloc (hashconfig->hook_salt_size);

  return hook_salt;
}

const char *default_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?b?b?b?b?b?b?b";

  return mask;
}

salt_t *default_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_len  = 8;
  salt->salt_iter = 1;

  return salt;
}

u32 default_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 opti_type = 0;

  return opti_type;
}

u64 default_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 opts_type = 0;

  return opts_type;
}

u64 default_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 kern_type = 0;

  return kern_type;
}

u64 default_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 4;

  return tmp_size;
}

u64 default_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = 0;

  return esalt_size;
}

u32 default_kernel_accel_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_min = KERNEL_ACCEL_MIN;

  return kernel_accel_min;
}

u32 default_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_max = KERNEL_ACCEL_MAX;

  return kernel_accel_max;
}

u32 default_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = KERNEL_LOOPS_MIN;

  return kernel_loops_min;
}

u32 default_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = KERNEL_LOOPS_MAX;

  return kernel_loops_max;
}

u32 default_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_min = KERNEL_THREADS_MIN;

  return kernel_threads_min;
}

u32 default_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = KERNEL_THREADS_MAX;

  return kernel_threads_max;
}

u32 default_forced_outfile_format (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 forced_outfile_format = user_options->outfile_format;

  return forced_outfile_format;
}

u32 default_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_type = SALT_TYPE_NONE;

  return salt_type;
}

u64 default_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = 0;

  return hook_salt_size;
}

u64 default_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = 4;

  return hook_size;
}

char default_separator (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return user_options->separator;
}

const char *default_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "<empty default>";
}

const char *default_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_PASS_HASHCAT_PLAIN;
}

bool default_dictstat_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool dictstat_disable = false;

  return dictstat_disable;
}

bool default_warmup_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool warmup_disable = false;

  return warmup_disable;
}

bool default_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_disable = false;

  return outfile_check_disable;
}

bool default_outfile_check_nocomp (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_nocomp = false;

  return outfile_check_nocomp;
}

bool default_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = false;

  return hlfmt_disable;
}

bool default_potfile_keep_all_hashes (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  bool potfile_keep_all_hashes = false;

  // keep all hashes if --username was combined with --left or --show

  if (user_options->username == true)
  {
    if ((user_options->show == true) || (user_options->left == true))
    {
      potfile_keep_all_hashes = true;
    }
  }

  return potfile_keep_all_hashes;
}

u32 default_pwdump_column (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pwdump_column = PWDUMP_COLUMN_INVALID;

  return pwdump_column;
}

bool default_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool potfile_disable = false;

  return potfile_disable;
}


bool default_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool unstable_warning = false;

  return unstable_warning;
}



// migrate

void to_hccapx_t (hashcat_ctx_t *hashcat_ctx, hccapx_t *hccapx, const u32 salt_pos, const u32 digest_pos)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  const salt_t *salts_buf   = hashes->salts_buf;
  const void   *esalts_buf  = hashes->esalts_buf;

  memset (hccapx, 0, sizeof (hccapx_t));

  hccapx->signature = HCCAPX_SIGNATURE;
  hccapx->version   = HCCAPX_VERSION;

  const salt_t *salt = &salts_buf[salt_pos];

  const u32 digest_cur = salt->digests_offset + digest_pos;

  hccapx->essid_len = salt->salt_len;

  memcpy (hccapx->essid, salt->salt_buf, hccapx->essid_len);

  wpa_eapol_t *wpa_eapols = (wpa_eapol_t *) esalts_buf;
  wpa_eapol_t *wpa_eapol  = &wpa_eapols[digest_cur];

  hccapx->message_pair = wpa_eapol->message_pair;
  hccapx->keyver = wpa_eapol->keyver;

  hccapx->eapol_len = wpa_eapol->eapol_len;

  if (wpa_eapol->keyver != 1)
  {
    u32 eapol_tmp[64] = { 0 };

    for (u32 i = 0; i < 64; i++)
    {
      eapol_tmp[i] = byte_swap_32 (wpa_eapol->eapol[i]);
    }

    memcpy (hccapx->eapol, eapol_tmp, wpa_eapol->eapol_len);
  }
  else
  {
    memcpy (hccapx->eapol, wpa_eapol->eapol, wpa_eapol->eapol_len);
  }

  memcpy (hccapx->mac_ap,    wpa_eapol->orig_mac_ap,    6);
  memcpy (hccapx->mac_sta,   wpa_eapol->orig_mac_sta,   6);
  memcpy (hccapx->nonce_ap,  wpa_eapol->orig_nonce_ap,  32);
  memcpy (hccapx->nonce_sta, wpa_eapol->orig_nonce_sta, 32);

  if (wpa_eapol->keyver != 1)
  {
    u32 digest_tmp[4];

    digest_tmp[0] = byte_swap_32 (wpa_eapol->keymic[0]);
    digest_tmp[1] = byte_swap_32 (wpa_eapol->keymic[1]);
    digest_tmp[2] = byte_swap_32 (wpa_eapol->keymic[2]);
    digest_tmp[3] = byte_swap_32 (wpa_eapol->keymic[3]);

    memcpy (hccapx->keymic, digest_tmp, 16);
  }
  else
  {
    memcpy (hccapx->keymic, wpa_eapol->keymic, 16);
  }
}

int check_old_hccap (const char *hashfile)
{
  FILE *fp = fopen (hashfile, "rb");

  if (fp == NULL) return -1;

  u32 signature;

  const size_t nread = hc_fread (&signature, sizeof (u32), 1, fp);

  fclose (fp);

  if (nread != 1) return -1;

  if (signature == HCCAPX_SIGNATURE) return 0;

  return 1;
}


int luks_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig, const int keyslot_idx)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  luks_t *luks = (luks_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  struct luks_phdr hdr;

  const size_t nread = hc_fread (&hdr, sizeof (hdr), 1, fp);

  if (nread != 1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // copy digest which we're not using ;)

  u32 *mkDigest_ptr = (u32 *) hdr.mkDigest;

  digest[0] = mkDigest_ptr[0];
  digest[1] = mkDigest_ptr[1];
  digest[2] = mkDigest_ptr[2];
  digest[3] = mkDigest_ptr[3];
  digest[4] = mkDigest_ptr[4];
  digest[5] = 0;
  digest[6] = 0;
  digest[7] = 0;

  // verify the content

  char luks_magic[6] = LUKS_MAGIC;

  if (memcmp (hdr.magic, luks_magic, LUKS_MAGIC_L) != 0)
  {
    fclose (fp);

    return (PARSER_LUKS_MAGIC);
  }

  if (byte_swap_16 (hdr.version) != 1)
  {
    fclose (fp);

    return (PARSER_LUKS_VERSION);
  }

  if (strcmp (hdr.cipherName, "aes") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_AES;
  }
  else if (strcmp (hdr.cipherName, "serpent") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_SERPENT;
  }
  else if (strcmp (hdr.cipherName, "twofish") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_TWOFISH;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_CIPHER_TYPE);
  }

  if (strcmp (hdr.cipherMode, "cbc-essiv:sha256") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_ESSIV;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_CIPHER_MODE);
  }

  if (strcmp (hdr.hashSpec, "sha1") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA1;
  }
  else if (strcmp (hdr.hashSpec, "sha256") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA256;
  }
  else if (strcmp (hdr.hashSpec, "sha512") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA512;
  }
  else if (strcmp (hdr.hashSpec, "ripemd160") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_RIPEMD160;
  }
  else if (strcmp (hdr.hashSpec, "whirlpool") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_WHIRLPOOL;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_HASH_TYPE);
  }

  const u32 keyBytes = byte_swap_32 (hdr.keyBytes);

  if (keyBytes == 16)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_128;
  }
  else if (keyBytes == 32)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_256;
  }
  else if (keyBytes == 64)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_512;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_SIZE);
  }

  // find the correct kernel based on hash and cipher

  // we need to do this kind of check, otherwise an eventual matching hash from the potfile overwrites the kern_type with an eventual invalid one

  if (hashconfig->kern_type == (u32) -1)
  {
    if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_AES;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_SERPENT;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_TWOFISH;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_AES;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_SERPENT;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_TWOFISH;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_AES;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_SERPENT;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_TWOFISH;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_AES;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_SERPENT;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_TWOFISH;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_AES;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_SERPENT;
    }
    else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH;
    }
    else
    {
      fclose (fp);

      return (PARSER_LUKS_HASH_CIPHER);
    }
  }
  else
  {
         if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA1_AES)          && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA1_SERPENT)      && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA1_TWOFISH)      && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA256_AES)        && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA256_SERPENT)    && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA256_TWOFISH)    && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA512_AES)        && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA512_SERPENT)    && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_SHA512_TWOFISH)    && (luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_RIPEMD160_AES)     && (luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_RIPEMD160_SERPENT) && (luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_RIPEMD160_TWOFISH) && (luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_WHIRLPOOL_AES)     && (luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_WHIRLPOOL_SERPENT) && (luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH) && (luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
    {
      // OK
    }
    else
    {
      fclose (fp);

      return (PARSER_LUKS_HASH_CIPHER);
    }
  }

  // verify the selected keyslot informations

  const u32 active  = byte_swap_32 (hdr.keyblock[keyslot_idx].active);
  const u32 stripes = byte_swap_32 (hdr.keyblock[keyslot_idx].stripes);

  if (active  != LUKS_KEY_ENABLED)
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_DISABLED);
  }

  if (stripes != LUKS_STRIPES)
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_STRIPES);
  }

  // configure the salt (not esalt)

  u32 *passwordSalt_ptr = (u32 *) hdr.keyblock[keyslot_idx].passwordSalt;

  salt->salt_buf[0] = passwordSalt_ptr[0];
  salt->salt_buf[1] = passwordSalt_ptr[1];
  salt->salt_buf[2] = passwordSalt_ptr[2];
  salt->salt_buf[3] = passwordSalt_ptr[3];
  salt->salt_buf[4] = passwordSalt_ptr[4];
  salt->salt_buf[5] = passwordSalt_ptr[5];
  salt->salt_buf[6] = passwordSalt_ptr[6];
  salt->salt_buf[7] = passwordSalt_ptr[7];

  salt->salt_len = LUKS_SALTSIZE;

  const u32 passwordIterations = byte_swap_32 (hdr.keyblock[keyslot_idx].passwordIterations);

  salt->salt_iter = passwordIterations - 1;

  // Load AF data for this keyslot into esalt

  const u32 keyMaterialOffset = byte_swap_32 (hdr.keyblock[keyslot_idx].keyMaterialOffset);

  const int rc_seek1 = fseeko (fp, keyMaterialOffset * 512, SEEK_SET);

  if (rc_seek1 == -1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread2 = hc_fread (luks->af_src_buf, keyBytes, stripes, fp);

  if (nread2 != stripes)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // finally, copy some encrypted payload data for entropy check

  const u32 payloadOffset = byte_swap_32 (hdr.payloadOffset);

  const int rc_seek2 = fseeko (fp, payloadOffset * 512, SEEK_SET);

  if (rc_seek2 == -1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread3 = hc_fread (luks->ct_buf, sizeof (u32), 128, fp);

  if (nread3 != 128)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // that should be it, close the fp

  fclose (fp);

  return (PARSER_OK);
}

