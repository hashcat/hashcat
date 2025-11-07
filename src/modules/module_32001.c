/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// ============================================================================
// BIP39 Module Debug Control
// ============================================================================
// Set to 1 to enable verbose debug output for:
// - Hash parsing ([m32001] messages)
// - Password loading ([pw_add] messages in wordlist.c)
// - Path indices and target hashes
// 
// Set to 0 for production (clean output)
// ============================================================================
#ifndef BIP39_MODULE_DEBUG
#define BIP39_MODULE_DEBUG 0
#endif

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_inc_hash_base58.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 1;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 3;
static const u32 DGST_SIZE = DGST_SIZE_4_5;
static const u32 HASH_CATEGORY = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME = "BIP39 Passphrase Recovery (ASCII, P2SH/P2PKH/P2WPKH)";
static const u64 KERN_TYPE = 32001;
static const u32 OPTI_TYPE = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64 OPTS_TYPE = OPTS_TYPE_STOCK_MODULE | OPTS_TYPE_LOOP;
static const u32 SALT_TYPE = SALT_TYPE_EMBEDDED;
static const char *ST_PASS = "testpass";
static const char *ST_HASH = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about:33747aCmUp8PkWmWWY8epR1Cph8Tf9Aozt:m/49'/0'/0'/0/0";

#define BIP39_MAX_PATH_DEPTH 16u
#define BIP39_TARGET_IL_HEX   0u
#define BIP39_TARGET_P2SH     1u
#define BIP39_TARGET_P2PKH    2u
#define BIP39_TARGET_P2WPKH   3u
#define BIP39_PATH_KIND_FIXED   0u
#define BIP39_PATH_KIND_DYNAMIC 1u
#define BIP39_DYNAMIC_KIND_RANGE 0u
#define BIP39_DYNAMIC_KIND_LIST  1u
#define BIP39_MAX_DYNAMIC_SEGMENTS      4u
#define BIP39_MAX_DYNAMIC_VALUES        256u
#define BIP39_MAX_DYNAMIC_RANGE_SPAN  4096u
#define BIP39_MAX_PASSPHRASE_LEN      256u

typedef struct bip39_dynamic_segment
{
  u32 position;
  u32 kind;
  u32 count;
  u32 start;
  u32 end;
  u32 step;
  u32 values_offset;
} bip39_dynamic_segment_t;

static bool env_flag_is_enabled (const char *value)
{
  if (value == 0)
  {
    return false;
  }

  while ((*value == ' ') || (*value == '\t'))
  {
    value++;
  }

  const bool has_value = (*value != '\0');
  const bool equals_zero = ((*value == '0') && (value[1] == '\0'));

  if (has_value == false)
  {
    return false;
  }

  return (equals_zero == false);
}

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ATTACK_EXEC;
}

u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS0;
}

u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS1;
}

u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS2;
}

u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_POS3;
}

u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return DGST_SIZE;
}

u32 module_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return HASH_CATEGORY;
}

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return HASH_NAME;
}

u64 module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return KERN_TYPE;
}

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return OPTI_TYPE;
}

u64 module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return OPTS_TYPE;
}

u32 module_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return SALT_TYPE;
}

const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_HASH;
}

const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ST_PASS;
}

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

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39_skeleton_t);
}

typedef struct bip39_tmp
{
  u64 seed[8];
  u64 master[8];
  u32 script_hash[5];
  u32 derived_ready;
  u32 master_ready;
  u32 debug_loop_pos;
  u32 debug_loop_cnt;
  u64 debug_combo_idx;
  u64 debug_combo_total;

} bip39_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39_tmp_t);
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  const char *env = getenv ("BIP39_PROFILE");

  if (env_flag_is_enabled (env))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_PROFILE=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_PROFILE=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_debug = getenv ("BIP39_DEBUG_PRINT");

  if (env_flag_is_enabled (env_debug))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DEBUG_PRINT=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DEBUG_PRINT=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_trim = getenv ("BIP39_DISABLE_SCRIPT_HASH");

  if (env_flag_is_enabled (env_trim))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_SCRIPT_HASH=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_SCRIPT_HASH=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_sha_small = getenv ("BIP39_DISABLE_SHA256_SMALL");

  if (env_flag_is_enabled (env_sha_small))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_SHA256_SMALL=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_SHA256_SMALL=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_pubhash = getenv ("BIP39_DISABLE_PUBKEY_HASH");

  if (env_flag_is_enabled (env_pubhash))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PUBKEY_HASH=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PUBKEY_HASH=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_point_mul = getenv ("BIP39_DISABLE_POINT_MUL");

  if (env_flag_is_enabled (env_point_mul))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_POINT_MUL=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_POINT_MUL=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_key_hashes = getenv ("BIP39_DISABLE_KEY_HASHES");

  if (env_flag_is_enabled (env_key_hashes))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_KEY_HASHES=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_KEY_HASHES=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_keyhash_after_point = getenv ("BIP39_DISABLE_KEY_HASHES_AFTER_POINT");

  if (env_flag_is_enabled (env_keyhash_after_point))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_KEY_HASHES_AFTER_POINT=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_KEY_HASHES_AFTER_POINT=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_keyhash_after_pub = getenv ("BIP39_DISABLE_KEY_HASHES_AFTER_PUB");

  if (env_flag_is_enabled (env_keyhash_after_pub))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_KEY_HASHES_AFTER_PUB=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_KEY_HASHES_AFTER_PUB=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_keyhash_after_pub_sha = getenv ("BIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA");

  if (env_flag_is_enabled (env_keyhash_after_pub_sha))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_pbkdf2 = getenv ("BIP39_DISABLE_PBKDF2");

  if (env_flag_is_enabled (env_pbkdf2))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PBKDF2=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PBKDF2=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_bip32 = getenv ("BIP39_DISABLE_BIP32_MASTER");

  if (env_flag_is_enabled (env_bip32))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_BIP32_MASTER=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_BIP32_MASTER=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path = getenv ("BIP39_DISABLE_PATH_DERIVE");

  if (env_flag_is_enabled (env_path))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_DERIVE=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_DERIVE=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_init_stub = getenv ("BIP39_DISABLE_INIT_BODY");

  if (env_flag_is_enabled (env_init_stub))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_INIT_BODY=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_INIT_BODY=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_loop_stub = getenv ("BIP39_DISABLE_LOOP_BODY");

  if (env_flag_is_enabled (env_loop_stub))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_LOOP_BODY=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_LOOP_BODY=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_minimal = getenv ("BIP39_MINIMAL_KERNEL");

  if (env_flag_is_enabled (env_minimal))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_MINIMAL_KERNEL=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_MINIMAL_KERNEL=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_after_pass = getenv ("BIP39_DISABLE_INIT_AFTER_PASSPHRASE");

  if (env_flag_is_enabled (env_after_pass))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_INIT_AFTER_PASSPHRASE=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_INIT_AFTER_PASSPHRASE=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_after_pbkdf = getenv ("BIP39_DISABLE_INIT_AFTER_PBKDF2");

  if (env_flag_is_enabled (env_after_pbkdf))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_INIT_AFTER_PBKDF2=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_INIT_AFTER_PBKDF2=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_after_bip32 = getenv ("BIP39_DISABLE_INIT_AFTER_BIP32");

  if (env_flag_is_enabled (env_after_bip32))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_INIT_AFTER_BIP32=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_INIT_AFTER_BIP32=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_child = getenv ("BIP39_DISABLE_PATH_CHILDREN");

  if (env_flag_is_enabled (env_path_child))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_CHILDREN=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_CHILDREN=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_match = getenv ("BIP39_DISABLE_PATH_MATCH");

  if (env_flag_is_enabled (env_path_match))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_MATCH=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_MATCH=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_iter = getenv ("BIP39_DISABLE_PATH_ITER");

  if (env_flag_is_enabled (env_path_iter))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_ITER=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_ITER=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_block = getenv ("BIP39_DISABLE_PATH_BLOCK");

  if (env_flag_is_enabled (env_path_block))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_BLOCK=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_BLOCK=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_dynamic = getenv ("BIP39_DISABLE_DYNAMIC_SECTION");

  if (env_flag_is_enabled (env_path_dynamic))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_DYNAMIC_SECTION=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_DYNAMIC_SECTION=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  const char *env_path_static = getenv ("BIP39_DISABLE_PATH_STATIC");

  if (env_flag_is_enabled (env_path_static))
  {
    if (jit_build_options == 0)
    {
      hc_asprintf (&jit_build_options, "-DBIP39_DISABLE_PATH_STATIC=1");
    }
    else
    {
      char *tmp = NULL;

      hc_asprintf (&tmp, "%s -DBIP39_DISABLE_PATH_STATIC=1", jit_build_options);
      hcfree (jit_build_options);
      jit_build_options = tmp;
    }
  }

  return jit_build_options;
}

static bool parse_uint_substring (const char *start, const char *end, u32 *value)
{
  while ((start < end) && isspace ((unsigned char) *start))
    start++;
  while ((end > start) && isspace ((unsigned char) end[-1]))
    end--;

  if (start >= end)
    return false;

  u64 acc = 0;

  for (const char *p = start; p < end; p++)
  {
    const unsigned char ch = (unsigned char) *p;

    if ((ch < '0') || (ch > '9'))
      return false;

    acc = (acc * 10u) + (u64) (ch - '0');

    if (acc > 0x7fffffffULL)
      return false;
  }

  *value = (u32) acc;

  return true;
}

static int bech32_char_to_value (const u8 c)
{
  switch (c)
  {
  case 'q':
    return 0;
  case 'p':
    return 1;
  case 'z':
    return 2;
  case 'r':
    return 3;
  case 'y':
    return 4;
  case '9':
    return 5;
  case 'x':
    return 6;
  case '8':
    return 7;
  case 'g':
    return 8;
  case 'f':
    return 9;
  case '2':
    return 10;
  case 't':
    return 11;
  case 'v':
    return 12;
  case 'd':
    return 13;
  case 'w':
    return 14;
  case '0':
    return 15;
  case 's':
    return 16;
  case '3':
    return 17;
  case 'j':
    return 18;
  case 'n':
    return 19;
  case '5':
    return 20;
  case '4':
    return 21;
  case 'k':
    return 22;
  case 'h':
    return 23;
  case 'c':
    return 24;
  case 'e':
    return 25;
  case '6':
    return 26;
  case 'm':
    return 27;
  case 'u':
    return 28;
  case 'a':
    return 29;
  case '7':
    return 30;
  case 'l':
    return 31;
  default:
    return -1;
  }
}

static const u32 bech32_generator[5] = {
  0x3b6a57b2,
  0x26508e6d,
  0x1ea119fa,
  0x3d4233dd,
  0x2a1462b3
};

#define BECH32_CONST   1u
#define BECH32M_CONST  0x2bc830a3u

static u32 bech32_polymod (const u8 *values, const u32 len)
{
  u32 chk = 1u;

  for (u32 i = 0; i < len; i++)
  {
    const u32 top = chk >> 25;

    chk = ((chk & 0x1ffffffu) << 5) ^ values[i];

    for (u32 j = 0; j < 5; j++)
    {
      if ((top >> j) & 1u)
        chk ^= bech32_generator[j];
    }
  }

  return chk;
}

static u32 bech32_hrp_expand (const u8 *hrp, const u32 hrp_len, u8 *out)
{
  for (u32 i = 0; i < hrp_len; i++)
    out[i] = (u8) (hrp[i] >> 5);

  out[hrp_len] = 0;

  for (u32 i = 0; i < hrp_len; i++)
    out[hrp_len + 1 + i] = (u8) (hrp[i] & 31u);

  return (hrp_len * 2u) + 1u;
}

static bool bech32_convert_bits (u8 *out, u32 *out_len, const u8 *in, const u32 in_len, const u32 from_bits, const u32 to_bits)
{
  u32 acc = 0;
  u32 bits = 0;
  const u32 maxv = (1u << to_bits) - 1u;
  u32 pos = 0;

  for (u32 i = 0; i < in_len; i++)
  {
    const u32 value = in[i];

    if (value >= (1u << from_bits))
      return false;

    acc = (acc << from_bits) | value;
    bits += from_bits;

    while (bits >= to_bits)
    {
      bits -= to_bits;
      out[pos++] = (u8) ((acc >> bits) & maxv);
    }
  }

  if (bits >= from_bits)
    return false;
  if (bits > 0)
    return false;

  *out_len = pos;

  return true;
}

static bool parse_derivation_path (const char *path_str, bip39_skeleton_t *bip39)
{
  if (path_str[0] != 'm')
    return false;

  u32 depth = 0;
  u32 dynamic_count = 0;
  u32 values_offset = 0;

  if (path_str[1] == 0)
  {
    bip39->path_depth = 0;
    bip39->path_dynamic_count = 0;
    bip39->dynamic_value_total = 0;

    return true;
  }

  if (path_str[1] != '/')
    return false;

  const char *cursor = path_str + 2;

  while (*cursor)
  {
    if (depth >= BIP39_MAX_PATH_DEPTH)
      return false;

    if (*cursor == '{')
    {
      const char *closing = strchr (cursor, '}');

      if (closing == 0)
        return false;

      const char *body_start = cursor + 1;
      const char *body_end = closing;

      if (body_start == body_end)
        return false;

      const char *post = closing + 1;

      if ((*post == '\'') || (*post == 'h') || (*post == 'H'))
        return false;

      if (dynamic_count >= BIP39_MAX_DYNAMIC_SEGMENTS)
        return false;

      bip39_dynamic_segment_t *seg = &bip39->dynamic_segments[dynamic_count];

      seg->position = depth;
      seg->kind = BIP39_DYNAMIC_KIND_RANGE;
      seg->count = 0;
      seg->start = 0;
      seg->end = 0;
      seg->step = 0;
      seg->values_offset = 0;

      bool has_comma = false;
      bool has_dash = false;

      for (const char *p = body_start; p < body_end; p++)
      {
        if (*p == ',')
          has_comma = true;
        else if (*p == '-')
          has_dash = true;
      }

      if (has_comma && has_dash)
        return false;

      if (has_dash && (has_comma == false))
      {
        const char *dash = strchr (body_start, '-');

        if ((dash == 0) || (dash >= body_end))
          return false;

        u32 start_value = 0;
        u32 end_value = 0;

        if (parse_uint_substring (body_start, dash, &start_value) == false)
          return false;
        if (parse_uint_substring (dash + 1, body_end, &end_value) == false)
          return false;

        if (start_value > end_value)
          return false;

        const u32 span = (end_value - start_value) + 1u;

        if (span > BIP39_MAX_DYNAMIC_RANGE_SPAN)
          return false;

        seg->kind = BIP39_DYNAMIC_KIND_RANGE;
        seg->start = start_value;
        seg->end = end_value;
        seg->step = 1u;
        seg->count = span;
        seg->values_offset = 0;

        bip39->path_indices[depth] = start_value;
      }
      else
      {
        u32 local_count = 0;
        const char *item_start = body_start;

        seg->kind = BIP39_DYNAMIC_KIND_LIST;
        seg->values_offset = values_offset;

        while (item_start < body_end)
        {
          const char *item_end = item_start;

          while ((item_end < body_end) && (*item_end != ','))
            item_end++;

          u32 value = 0;

          if (parse_uint_substring (item_start, item_end, &value) == false)
            return false;

          if ((values_offset + local_count) >= BIP39_MAX_DYNAMIC_VALUES)
            return false;

          bip39->dynamic_values[values_offset + local_count] = value;

          local_count++;

          if (item_end == body_end)
            break;

          item_start = item_end + 1;
        }

        if (local_count == 0)
          return false;

        seg->count = local_count;

        bip39->path_indices[depth] = bip39->dynamic_values[values_offset];

        values_offset += local_count;
      }

      bip39->path_kind[depth] = BIP39_PATH_KIND_DYNAMIC;

      dynamic_count++;
      depth++;

      cursor = closing + 1;
    }
    else
    {
      const char *start = cursor;

      while ((*cursor >= '0') && (*cursor <= '9'))
        cursor++;

      if (start == cursor)
        return false;

      u32 value = 0;

      if (parse_uint_substring (start, cursor, &value) == false)
        return false;

      if ((*cursor == '\'') || (*cursor == 'h') || (*cursor == 'H'))
      {
        value |= 0x80000000u;
        cursor++;
      }

      bip39->path_indices[depth] = value;
      bip39->path_kind[depth] = BIP39_PATH_KIND_FIXED;

      depth++;
    }

    if (*cursor == 0)
    {
      break;
    }

    if (*cursor != '/')
      return false;

    cursor++;
    if (*cursor == 0)
      return false;
  }

  bip39->path_depth = depth;
  bip39->path_dynamic_count = dynamic_count;
  bip39->dynamic_value_total = values_offset;

  return true;
}

static int decode_address_script_hash (const u8 *address, const u32 address_len, bip39_skeleton_t *bip39, u32 *digest)
{
  u8 decoded[64];

  memset (decoded, 0, sizeof (decoded));

  u32 decoded_len = (u32) sizeof (decoded);

  const bool ok = b58dec (decoded, &decoded_len, address, address_len);

  if (ok == false)
    return PARSER_HASH_LENGTH;

  if (decoded_len != 25)
    return PARSER_HASH_LENGTH;

  const u32 offset = (u32) sizeof (decoded) - decoded_len;

  u32 decoded_words[16];

  memset (decoded_words, 0, sizeof (decoded_words));

  u8 *decoded_bytes = (u8 *) decoded_words;

  for (u32 i = 0; i < decoded_len; i++)
  {
    decoded_bytes[i] = decoded[offset + i];
  }

  if (b58check_25 (decoded_words) == false)
    return PARSER_HASH_ENCODING;

  const u8 version = decoded_bytes[0];

  const bool is_p2sh = (version == 0x05) || (version == 0xC4);
  const bool is_p2pkh = (version == 0x00) || (version == 0x6F);

  if ((is_p2sh == false) && (is_p2pkh == false))
    return PARSER_HASH_VALUE;

  const u8 *hash_bytes = decoded_bytes + 1;

  memset (bip39->target_hash, 0, sizeof (bip39->target_hash));

  for (u32 i = 0; i < 5; i++)
  {
    const u32 idx = i * 4;

    const u32 word = ((u32) hash_bytes[idx + 0] << 0) | ((u32) hash_bytes[idx + 1] << 8) | ((u32) hash_bytes[idx + 2] << 16) | ((u32) hash_bytes[idx + 3] << 24);

    bip39->target_hash[i] = word;

    if (i < 4)
    {
      digest[i] = word;
    }
  }

  digest[4] = bip39->target_hash[4];

  bip39->target_type = is_p2sh ? BIP39_TARGET_P2SH : BIP39_TARGET_P2PKH;

  return PARSER_OK;
}

static int decode_address_bech32 (const u8 *address, const u32 address_len, bip39_skeleton_t *bip39, u32 *digest)
{
  if (address_len < 8)
    return PARSER_HASH_LENGTH;

  bool has_lower = false;
  bool has_upper = false;

  for (u32 i = 0; i < address_len; i++)
  {
    const unsigned char ch = address[i];

    if ((ch < 33) || (ch > 126))
      return PARSER_HASH_ENCODING;
    if ((ch >= 'a') && (ch <= 'z'))
      has_lower = true;
    else if ((ch >= 'A') && (ch <= 'Z'))
      has_upper = true;
  }

  if (has_lower && has_upper)
    return PARSER_HASH_ENCODING;

  u8 lower_addr[96];

  for (u32 i = 0; i < address_len; i++)
  {
    const unsigned char ch = address[i];

    lower_addr[i] = (has_upper) ? (u8) tolower (ch) : ch;
  }

  u32 separator_index = 0xffffffffu;

  for (u32 i = 0; i < address_len; i++)
  {
    if (lower_addr[i] == '1')
    {
      separator_index = i;
      break;
    }
  }

  if ((separator_index == 0xffffffffu) || (separator_index == 0))
    return PARSER_HASH_VALUE;

  const u32 hrp_len = separator_index;
  const u32 data_len = address_len - separator_index - 1u;

  if (data_len < 6u)
    return PARSER_HASH_LENGTH;

  const u8 *hrp = lower_addr;
  const u8 *data = lower_addr + separator_index + 1u;

  u8 data_values[90];

  for (u32 i = 0; i < data_len; i++)
  {
    const int value = bech32_char_to_value (data[i]);

    if (value < 0)
      return PARSER_HASH_VALUE;
    data_values[i] = (u8) value;
  }

  u8 hrp_expand[200];
  const u32 hrp_expand_len = bech32_hrp_expand (hrp, hrp_len, hrp_expand);

  u8 polymod_input[260];

  for (u32 i = 0; i < hrp_expand_len; i++)
    polymod_input[i] = hrp_expand[i];
  for (u32 i = 0; i < data_len; i++)
    polymod_input[hrp_expand_len + i] = data_values[i];

  const u32 polymod = bech32_polymod (polymod_input, hrp_expand_len + data_len);

  u32 encoding = 0u;

  if (polymod == BECH32_CONST)
    encoding = 0u;
  else if (polymod == BECH32M_CONST)
    encoding = 1u;
  else
    return PARSER_HASH_VALUE;

  if (data_len < 7u)
    return PARSER_HASH_LENGTH;

  const u32 payload_len = data_len - 6u;

  if (payload_len < 1u)
    return PARSER_HASH_VALUE;

  const u8 witness_version = data_values[0];

  if (witness_version > 16u)
    return PARSER_HASH_VALUE;

  const u8 *prog5 = data_values + 1u;
  const u32 prog5_len = payload_len - 1u;

  u8 program[40];
  u32 program_len = 0;

  if (bech32_convert_bits (program, &program_len, prog5, prog5_len, 5u, 8u) == false)
    return PARSER_HASH_VALUE;

  if ((program_len < 2u) || (program_len > 40u))
    return PARSER_HASH_VALUE;

  if ((witness_version == 0u) && (encoding != 0u))
    return PARSER_HASH_VALUE;
  if ((witness_version > 0u) && (encoding != 1u))
    return PARSER_HASH_VALUE;

  if ((witness_version != 0u) || (program_len != 20u))
    return PARSER_HASH_VALUE;

  bip39->target_type = BIP39_TARGET_P2WPKH;

  memset (bip39->target_hash, 0, sizeof (bip39->target_hash));

  for (u32 i = 0; i < 5; i++)
  {
    const u32 idx = i * 4u;

    const u32 word = ((u32) program[idx + 0] << 0) | ((u32) program[idx + 1] << 8) | ((u32) program[idx + 2] << 16) | ((u32) program[idx + 3] << 24);

    bip39->target_hash[i] = word;

    if (i < 4)
    {
      digest[i] = word;
    }
  }

  digest[4] = bip39->target_hash[4];

  return PARSER_OK;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, void *digest_buf, salt_t *salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, const int line_len)
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
  token.len_max[0] = 1024;
  token.len_min[1] = 1;
  token.len_max[1] = 64;
  token.len_min[2] = 1;
  token.len_max[2] = 64;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
    return rc_tokenizer;

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

  if (parse_derivation_path ((const char *) bip39->path, bip39) == false)
  {
    return PARSER_HASH_VALUE;
  }

  for (u32 i = 0; i < bip39->path_depth; i++)
  {
    bip39->path_kind[i] = BIP39_PATH_KIND_FIXED;
  }

#if BIP39_MODULE_DEBUG
  fprintf (stderr, "[m32001] parsed path depth: %u\n", bip39->path_depth);
  for (u32 i = 0; i < bip39->path_depth; i++)
  {
    fprintf (stderr, "[m32001] path index[%u]: %08x\n", i, bip39->path_indices[i]);
  }
#endif

  u64 combo_total = 1;

  if (bip39->path_dynamic_count > 0)
  {
    for (u32 i = 0; i < bip39->path_dynamic_count; i++)
    {
      const u32 segment_count = bip39->dynamic_segments[i].count;

      if (segment_count == 0)
      {
        combo_total = 0;
        break;
      }

      if (combo_total > (0xffffffffffffffffULL / segment_count))
      {
        combo_total = 0xffffffffffffffffULL;
        break;
      }

      combo_total *= (u64) segment_count;
    }
  }

  if (combo_total == 0)
  {
    combo_total = 1;
  }

  bip39->path_combo_total = combo_total;

  if (bip39->path_combo_total == 0)
  {
    bip39->path_combo_total = 1;
  }

  salt->salt_iter = (bip39->path_combo_total >= 0xffffffffULL) ? 0xffffffffu : (u32) bip39->path_combo_total;
  salt->salt_iter2 = 0;
  salt->salt_len = 0;

  digest[0] = 0;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;
  digest[4] = 0;

  if (token.len[1] == 32)
  {
    if (is_valid_hex_string (address_pos, token.len[1]) == false)
      return PARSER_HASH_VALUE;

    digest[0] = byte_swap_32 (hex_to_u32 (address_pos + 0));
    digest[1] = byte_swap_32 (hex_to_u32 (address_pos + 8));
    digest[2] = byte_swap_32 (hex_to_u32 (address_pos + 16));
    digest[3] = byte_swap_32 (hex_to_u32 (address_pos + 24));
    digest[4] = 0;

    bip39->target_type = BIP39_TARGET_IL_HEX;
  }
  else
  {
    bool maybe_bech32 = false;

    if (token.len[1] >= 3)
    {
      const u8 c0 = (u8) tolower (address_pos[0]);
      const u8 c1 = (u8) tolower (address_pos[1]);

      if ((c0 == 'b') && (c1 == 'c'))
      {
        if ((u32) token.len[1] >= 3)
        {
          const u8 c2 = (u8) tolower (address_pos[2]);

          if (c2 == '1')
          {
            maybe_bech32 = true;
          }
          else if (((u32) token.len[1] >= 5) && (c2 == 'r') && ((u8) tolower (address_pos[3]) == 't') && ((u8) tolower (address_pos[4]) == '1'))
          {
            maybe_bech32 = true;
          }
        }
      }
      else if ((c0 == 't') && (c1 == 'b'))
      {
        if ((u32) token.len[1] >= 3 && (u8) tolower (address_pos[2]) == '1')
        {
          maybe_bech32 = true;
        }
      }
    }

    if (maybe_bech32)
    {
      const int rc = decode_address_bech32 (address_pos, token.len[1], bip39, digest);

      if (rc != PARSER_OK)
        return rc;
    }
    else
    {
      const int rc = decode_address_script_hash (address_pos, token.len[1], bip39, digest);

      if (rc != PARSER_OK)
        return rc;
    }
  }

#if BIP39_MODULE_DEBUG
  if (bip39->target_type == BIP39_TARGET_IL_HEX)
  {
    fprintf (stderr, "[m32001] target digest il: %08x %08x %08x %08x\n", digest[0], digest[1], digest[2], digest[3]);
  }
  else if (bip39->target_type == BIP39_TARGET_P2SH)
  {
    fprintf (stderr, "[m32001] target script hash: %08x %08x %08x %08x %08x\n", bip39->target_hash[0], bip39->target_hash[1], bip39->target_hash[2], bip39->target_hash[3], bip39->target_hash[4]);
  }
  else if (bip39->target_type == BIP39_TARGET_P2PKH)
  {
    fprintf (stderr, "[m32001] target hash160: %08x %08x %08x %08x %08x\n", bip39->target_hash[0], bip39->target_hash[1], bip39->target_hash[2], bip39->target_hash[3], bip39->target_hash[4]);
  }
  else if (bip39->target_type == BIP39_TARGET_P2WPKH)
  {
    fprintf (stderr, "[m32001] target witness prog: %08x %08x %08x %08x %08x\n", bip39->target_hash[0], bip39->target_hash[1], bip39->target_hash[2], bip39->target_hash[3], bip39->target_hash[4]);
  }
#endif

  return PARSER_OK;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  const bip39_skeleton_t *bip39 = (const bip39_skeleton_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s:%s:%s",
                                 (const char *) bip39->mnemonic_raw,
                                 (const char *) bip39->address,
                                 (const char *) bip39->path);

  return line_len;
}

int module_hash_encode_status (const hashconfig_t *hashconfig, const void *digest_buf, const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
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

  const u64 combos = bip39->path_combo_total;

  if (combos == 0)
  {
    return line_len;
  }

  const int remain = line_size - line_len;

  const int extra = snprintf (line_buf + line_len, remain, " [combos=%llu]", (unsigned long long) combos);

  if (extra >= remain)
  {
    // Truncated; ensure caller does not overrun
    return line_size - 1;
  }

  return line_len + extra;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return BIP39_MAX_PASSPHRASE_LEN;
}

const char *module_extra_tuningdb_block (const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, MAYBE_UNUSED const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  char *sanitized = hcstrdup (device_param->device_name ? device_param->device_name : "DEVICE");

  for (size_t i = 0; sanitized[i] != '\0'; i++)
  {
    const unsigned char c = (const unsigned char) sanitized[i];

    if (isalnum (c) == 0)
    {
      sanitized[i] = '_';
    }
  }

  const size_t buf_sz = 512;
  char *lines_buf = (char *) hcmalloc (buf_sz);

  size_t offset = 0;

  offset += snprintf (lines_buf + offset, buf_sz - offset, "# module_32001 tuningdb\n");

  const u32 hash_mode = hashconfig->hash_mode;

  if (device_param->is_cuda)
  {
    device_param->kernel_threads_max = MAX (device_param->kernel_threads_max, 1024);
    device_param->kernel_accel_max = MAX (device_param->kernel_accel_max, 1024);

    offset += snprintf (lines_buf + offset, buf_sz - offset, "%s * %u N A A\n", sanitized, hash_mode);
    offset += snprintf (lines_buf + offset, buf_sz - offset, "CUDA * %u N A A\n", hash_mode);
  }
  else if ((device_param->is_opencl) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
  {
    offset += snprintf (lines_buf + offset, buf_sz - offset, "# NVIDIA OpenCL uses autotune defaults (%s)\n", sanitized);
  }
  else if ((device_param->is_opencl) && ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) || (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_BEIGNET)))
  {
    bool clamp_intel = true;

    const char *env_intel_unclamp = getenv ("BIP39_ALLOW_INTEL_AUTOTUNE");

    if (env_flag_is_enabled (env_intel_unclamp))
    {
      clamp_intel = false;
    }

    if (clamp_intel)
    {
      // Intel HD 630 driver (2025-10-12 harness sweep) survives autotune only when threads stay <= 32,
      // accel <= 2, loops = 4. Clamp all Geometry knobs to the conservative configuration we run in CI.
      device_param->kernel_threads_min = MAX (device_param->kernel_threads_min, 32);
      device_param->kernel_threads_max = 32;
      device_param->kernel_accel_min = MAX (device_param->kernel_accel_min, 2);
      device_param->kernel_accel_max = 2;
      device_param->kernel_loops_min = MAX (device_param->kernel_loops_min, 4);
      device_param->kernel_loops_max = 4;

      offset += snprintf (lines_buf + offset, buf_sz - offset, "%s * %u 32 2 4\n", sanitized, hash_mode);
      offset += snprintf (lines_buf + offset, buf_sz - offset, "Intel * %u 32 2 4\n", hash_mode);
    }
    else
    {
      offset += snprintf (lines_buf + offset, buf_sz - offset, "# Intel OpenCL autotune unclamped for %s\n", sanitized);
    }
  }
  else
  {
    offset += snprintf (lines_buf + offset, buf_sz - offset, "# no dynamic tuning for %s\n", sanitized);
  }

  hcfree (sanitized);

  return lines_buf;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return KERNEL_THREADS_MAX;
}

u32 module_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return KERNEL_ACCEL_MAX;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec = module_attack_exec;
  module_ctx->module_benchmark_esalt = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt = MODULE_DEFAULT;
  module_ctx->module_bridge_name = MODULE_DEFAULT;
  module_ctx->module_bridge_type = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0 = module_dgst_pos0;
  module_ctx->module_dgst_pos1 = module_dgst_pos1;
  module_ctx->module_dgst_pos2 = module_dgst_pos2;
  module_ctx->module_dgst_pos3 = module_dgst_pos3;
  module_ctx->module_dgst_size = module_dgst_size;
  module_ctx->module_dictstat_disable = MODULE_DEFAULT;
  module_ctx->module_esalt_size = module_esalt_size;
  module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block = module_extra_tuningdb_block;
  module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
  module_ctx->module_hash_decode = module_hash_decode;
  module_ctx->module_hash_encode_status = module_hash_encode_status;
  module_ctx->module_hash_encode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_encode = module_hash_encode;
  module_ctx->module_hash_init_selftest = MODULE_DEFAULT;
  module_ctx->module_hash_mode = MODULE_DEFAULT;
  module_ctx->module_hash_category = module_hash_category;
  module_ctx->module_hash_name = module_hash_name;
  module_ctx->module_hashes_count_min = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term = MODULE_DEFAULT;
  module_ctx->module_hook12 = MODULE_DEFAULT;
  module_ctx->module_hook23 = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size = MODULE_DEFAULT;
  module_ctx->module_hook_size = MODULE_DEFAULT;
  module_ctx->module_jit_build_options = module_jit_build_options;
  module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max = module_kernel_accel_max;  // Returns KERNEL_ACCEL_MAX - no caps
  module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max = module_kernel_threads_max;  // Returns KERNEL_THREADS_MAX - no caps
  module_ctx->module_kernel_threads_min = MODULE_DEFAULT;
  module_ctx->module_kern_type = module_kern_type;
  module_ctx->module_kern_type_dynamic = MODULE_DEFAULT;
  module_ctx->module_opti_type = module_opti_type;
  module_ctx->module_opts_type = module_opts_type;
  module_ctx->module_outfile_check_disable = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check = MODULE_DEFAULT;
  module_ctx->module_potfile_disable = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column = MODULE_DEFAULT;
  module_ctx->module_pw_min = MODULE_DEFAULT;
  module_ctx->module_salt_max = MODULE_DEFAULT;
  module_ctx->module_salt_min = MODULE_DEFAULT;
  module_ctx->module_salt_type = module_salt_type;
  module_ctx->module_separator = MODULE_DEFAULT;
  module_ctx->module_st_hash = module_st_hash;
  module_ctx->module_st_pass = module_st_pass;
  module_ctx->module_tmp_size = module_tmp_size;
  module_ctx->module_unstable_warning = MODULE_DEFAULT;
  module_ctx->module_warmup_disable = MODULE_DEFAULT;
  module_ctx->module_pw_max = module_pw_max;
}
