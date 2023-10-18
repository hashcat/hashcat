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
#include "bitops.h"

#include "emu_inc_hash_base58.h"
#include "emu_inc_bip39.h"

static const char SEPARATOR = ':';
static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 1;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 3;
static const u32 DGST_SIZE = DGST_SIZE_4_32;
static const u32 HASH_CATEGORY = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME = "Bitcoin seed words and passphrase";
static const u64 KERN_TYPE = 28510;
static const u32 OPTI_TYPE = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_USES_BITS_64 | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64 OPTS_TYPE = OPTS_TYPE_COPY_TMPS;
static const u32 SALT_TYPE = SALT_TYPE_EMBEDDED;
static const char *ST_PASS = "hashcat";
static const char *ST_HASH = "P2PKH:m/44h/0h/0h/0/0:balcony catalog winner letter alley this:1B2hrNm7JGW6Wenf8oMvjWB3DPT9H9vAJ9";

typedef struct address_base58
{
  u32 digest_len;
  u32 address_len;
  u32 prefix_len;
  u8 prefix[];
} address_base58_t;

static const address_base58_t XPUB_ADDRESS = { 82, 111, 13, {0x04, 0x88, 0xb2, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF} };
static const address_base58_t P2PKH_ADDRESS = { 25, 34, 1, {0x0} };
static const address_base58_t P2SHWPKH_ADDRESS = { 25, 34, 1, {0x05} };

/******************************************************************************
 * This section provides utilities for decoding the hash value.
 * We need to parse out the address type, derivation path, mnemonic phrase,
 * as the salt.
 ******************************************************************************/

// Output the next index from the derivation_path and increment the derivation_path pointer
DECLSPEC u32 decode_derivation_path (PRIVATE_AS u8 ** derivation_path, PRIVATE_AS const char end_char)
{
  char word[9] = { 0 };
  u32 hardened = 0;

  if (derivation_path[0][0] == end_char)
    return DERIVATION_END;

  for (int i = 0; i < 9; i++)
  {
    // Parse out the digits or whether child is hardened
    if (derivation_path[0][0] == 'h' || derivation_path[0][0] == '\'')
    {
      hardened = DERIVATION_HARDENED;
    }
    else if (derivation_path[0][0] == '/')
    {
      // Ends one child of the derivation path
      *derivation_path += 1;
      return hc_strtoul (word, 0, 10) | hardened;
    }
    else if (derivation_path[0][0] == end_char)
    {
      // Ends but don't advance derivation_path pointer so we'll return DERIVATION_END next
      return hc_strtoul (word, 0, 10) | hardened;
    }
    else if (derivation_path[0][0] <= '9' && derivation_path[0][0] >= '0')
    {
      word[i] = derivation_path[0][0];
    }
    else
    {
      return DERIVATION_ERROR;
    }

    *derivation_path += 1;
  }

  // Derivation path is too long
  return DERIVATION_ERROR;
}

// Output the next word index from the mnemonic_phrase and increment the mnemonic_phrase pointer
DECLSPEC u32 decode_mnemonic_phrase (PRIVATE_AS u8 ** mnemonic_phrase, PRIVATE_AS const char end_char)
{
  char word[9] = { 0 };
  if (mnemonic_phrase[0][0] == end_char)
    return MNEMONIC_END;

  for (int i = 0; i < 9; i++)
  {
    word[i] = mnemonic_phrase[0][0];
    *mnemonic_phrase += 1;

    if (mnemonic_phrase[0][0] == end_char)
      break;
    if (mnemonic_phrase[0][0] == ' ')
    {
      *mnemonic_phrase += 1;
      break;
    }
  }

  if (strncmp (word, "?", 1) == 0)
    return MNEMONIC_GUESS;

  return bip39_from_word (word);
}

// Helper for base58 decoding into the digest, assumes prefix ends in 0xFF
static bool decode_base58 (const address_base58_t * type, const char *address, u8 * digest)
{
  u32 len = type->digest_len;
  u32 prefix_len = type->prefix_len;
  u8 decoded_address[128] = { 0 };

  if (!b58dec (decoded_address, &len, (u8 *) address, type->address_len))
    return false;
  if (!b58check (decoded_address, len))
    return false;
  if (len != type->digest_len)
    return false;

  // skip encoding the known prefix (not useful for digest entropy)
  for (u32 i = 0; i < prefix_len; i++)
  {
    if (type->prefix[i] != decoded_address[i])
      return false;
  }
  for (u32 i = 0; i < type->digest_len - prefix_len; i++)
  {
    digest[i] = decoded_address[i + prefix_len];
  }

  return true;
}

// Helper for base58 encoding into the digest
static void encode_base58 (const address_base58_t * type, u8 * address, const u8 * digest)
{
  u32 len = 0xFFFFFFFF;
  u32 prefix_len = type->prefix_len;
  u8 decoded_address[128] = { 0 };

  // build the address using the known prefix
  for (u32 i = 0; i < prefix_len; i++)
  {
    decoded_address[i] = type->prefix[i];
  }
  for (u32 i = 0; i < type->digest_len - prefix_len; i++)
  {
    decoded_address[prefix_len + i] = digest[i];
  }
  b58enc (address, &len, decoded_address, type->digest_len);

  // Sometimes encoding adds unnecessary zeros to the prefix
  u32 offset = len - type->address_len - 1;

  for (u32 i = 0; i < type->address_len; i++)
  {
    address[i] = address[i + offset];
  }
  address[type->address_len] = 0x0;
}

/******************************************************************************
 * This section provides utilities for bech32 encoding/decoding necessary for
 * newer bitcoin address types.  Could be refactored for use in other bitcoin
 * modules.
 * 
 * Adapted from https://github.com/sipa/bech32/tree/master/ref/c
 * Copyright (c) 2017, 2021 Pieter Wuille, MIT license
 ******************************************************************************/

typedef enum
{
  BECH32_ENCODING_NONE,
  BECH32_ENCODING_BECH32,
  BECH32_ENCODING_BECH32M
} bech32_encoding;

static u32 bech32_polymod_step (uint32_t pre)
{
  u8 b = pre >> 25;

  return ((pre & 0x1FFFFFF) << 5) ^ (-((b >> 0) & 1) & 0x3b6a57b2UL) ^ (-((b >> 1) & 1) & 0x26508e6dUL) ^ (-((b >> 2) & 1) & 0x1ea119faUL) ^ (-((b >> 3) & 1) & 0x3d4233ddUL) ^ (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static u32 bech32_final_constant (bech32_encoding enc)
{
  if (enc == BECH32_ENCODING_BECH32)
    return 1;
  if (enc == BECH32_ENCODING_BECH32M)
    return 0x2bc830a3;
  return 0;
}

static const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
  1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
  1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
};

int bech32_encode (char *output, const char *hrp, const uint8_t * data, size_t data_len, bech32_encoding enc)
{
  uint32_t chk = 1;
  size_t i = 0;

  while (hrp[i] != 0)
  {
    int ch = hrp[i];

    if (ch < 33 || ch > 126)
    {
      return 0;
    }

    if (ch >= 'A' && ch <= 'Z')
      return 0;
    chk = bech32_polymod_step (chk) ^ (ch >> 5);
    ++i;
  }
  if (i + 7 + data_len > 90)
    return 0;
  chk = bech32_polymod_step (chk);
  while (*hrp != 0)
  {
    chk = bech32_polymod_step (chk) ^ (*hrp & 0x1f);
    *(output++) = *(hrp++);
  }
  *(output++) = '1';
  for (i = 0; i < data_len; ++i)
  {
    if (*data >> 5)
      return 0;
    chk = bech32_polymod_step (chk) ^ (*data);
    *(output++) = charset[*(data++)];
  }
  for (i = 0; i < 6; ++i)
  {
    chk = bech32_polymod_step (chk);
  }
  chk ^= bech32_final_constant (enc);
  for (i = 0; i < 6; ++i)
  {
    *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
  }
  *output = 0;
  return 1;
}

bech32_encoding bech32_decode (char *hrp, uint8_t * data, size_t *data_len, const char *input)
{
  uint32_t chk = 1;
  size_t i;
  size_t input_len = strlen (input);
  size_t hrp_len;
  int have_lower = 0, have_upper = 0;

  if (input_len < 8 || input_len > 90)
  {
    return BECH32_ENCODING_NONE;
  }
  *data_len = 0;
  while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1')
  {
    ++(*data_len);
  }
  hrp_len = input_len - (1 + *data_len);
  if (1 + *data_len >= input_len || *data_len < 6)
  {
    return BECH32_ENCODING_NONE;
  }
  *(data_len) -= 6;
  for (i = 0; i < hrp_len; ++i)
  {
    int ch = input[i];

    if (ch < 33 || ch > 126)
    {
      return BECH32_ENCODING_NONE;
    }
    if (ch >= 'a' && ch <= 'z')
    {
      have_lower = 1;
    }
    else if (ch >= 'A' && ch <= 'Z')
    {
      have_upper = 1;
      ch = (ch - 'A') + 'a';
    }
    hrp[i] = ch;
    chk = bech32_polymod_step (chk) ^ (ch >> 5);
  }
  hrp[i] = 0;
  chk = bech32_polymod_step (chk);
  for (i = 0; i < hrp_len; ++i)
  {
    chk = bech32_polymod_step (chk) ^ (input[i] & 0x1f);
  }
  ++i;
  while (i < input_len)
  {
    int v = (input[i] & 0x80) ? -1 : charset_rev[(int) input[i]];

    if (input[i] >= 'a' && input[i] <= 'z')
      have_lower = 1;
    if (input[i] >= 'A' && input[i] <= 'Z')
      have_upper = 1;
    if (v == -1)
    {
      return BECH32_ENCODING_NONE;
    }
    chk = bech32_polymod_step (chk) ^ v;
    if (i + 6 < input_len)
    {
      data[i - (1 + hrp_len)] = v;
    }
    ++i;
  }
  if (have_lower && have_upper)
  {
    return BECH32_ENCODING_NONE;
  }
  if (chk == bech32_final_constant (BECH32_ENCODING_BECH32))
  {
    return BECH32_ENCODING_BECH32;
  }
  else if (chk == bech32_final_constant (BECH32_ENCODING_BECH32M))
  {
    return BECH32_ENCODING_BECH32M;
  }
  else
  {
    return BECH32_ENCODING_NONE;
  }
}

static int convert_bits (uint8_t * out, size_t *outlen, int outbits, const uint8_t * in, size_t inlen, int inbits, int pad)
{
  uint32_t val = 0;
  int bits = 0;
  uint32_t maxv = (((uint32_t) 1) << outbits) - 1;

  while (inlen--)
  {
    val = (val << inbits) | *(in++);
    bits += inbits;
    while (bits >= outbits)
    {
      bits -= outbits;
      out[(*outlen)++] = (val >> bits) & maxv;
    }
  }
  if (pad)
  {
    if (bits)
    {
      out[(*outlen)++] = (val << (outbits - bits)) & maxv;
    }
  }
  else if (((val << (outbits - bits)) & maxv) || bits >= inbits)
  {
    return 0;
  }
  return 1;
}

int segwit_addr_encode (char *output, const char *hrp, int witver, const uint8_t * witprog, size_t witprog_len)
{
  uint8_t data[65];
  size_t datalen = 0;
  bech32_encoding enc = BECH32_ENCODING_BECH32;

  if (witver > 16)
    return 0;
  if (witver == 0 && witprog_len != 20 && witprog_len != 32)
    return 0;
  if (witprog_len < 2 || witprog_len > 40)
    return 0;
  if (witver > 0)
    enc = BECH32_ENCODING_BECH32M;
  data[0] = witver;
  convert_bits (data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
  ++datalen;
  return bech32_encode (output, hrp, data, datalen, enc);
}

int segwit_addr_decode (int *witver, uint8_t * witdata, size_t *witdata_len, const char *hrp, const char *addr)
{
  uint8_t data[84];
  char hrp_actual[84];
  size_t data_len;
  bech32_encoding enc = bech32_decode (hrp_actual, data, &data_len, addr);

  if (enc == BECH32_ENCODING_NONE)
    return 0;
  if (data_len == 0 || data_len > 65)
    return 0;
  if (strncmp (hrp, hrp_actual, 84) != 0)
    return 0;
  if (data[0] > 16)
    return 0;
  if (data[0] == 0 && enc != BECH32_ENCODING_BECH32)
    return 0;
  if (data[0] > 0 && enc != BECH32_ENCODING_BECH32M)
    return 0;
  *witdata_len = 0;
  if (!convert_bits (witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0))
    return 0;
  if (*witdata_len < 2 || *witdata_len > 40)
    return 0;
  if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32)
    return 0;
  *witver = data[0];
  return 1;
}

/******************************************************************************
 * This section contains the typical module functions found in most modules
 * such as the encoding and decoding of the hash value to the digest.
 ******************************************************************************/

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return ATTACK_EXEC;
}

u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return DGST_POS0;
}

u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return DGST_POS1;
}

u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return DGST_POS2;
}

u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return DGST_POS3;
}

u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return DGST_SIZE;
}

u32 module_hash_category (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return HASH_CATEGORY;
}

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return HASH_NAME;
}

u64 module_kern_type (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return KERN_TYPE;
}

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return OPTI_TYPE;
}

u64 module_opts_type (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return OPTS_TYPE;
}

u32 module_salt_type (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return SALT_TYPE;
}

const char *module_st_hash (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return ST_HASH;
}

const char *module_st_pass (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return ST_PASS;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  return (const u64) sizeof (bip39_tmp_t);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t * salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t * hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u8 *digest = (u8 *) digest_buf;
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 4;
  token.sep[0] = SEPARATOR;
  token.sep[1] = SEPARATOR;
  token.sep[2] = SEPARATOR;
  token.sep[3] = SEPARATOR;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
    return (rc_tokenizer);

  const char *address_type = (char *) token.buf[0];
  const char *derivation_path = (char *) token.buf[1];
  const char *mnemonic_phrase = (char *) token.buf[2];
  const char *address = (char *) token.buf[3];

  // Store address type in salt[0] and convert into digest
  if (strncmp (address_type, "XPUB", token.len[0]) == 0)
  {
    salt->salt_buf[0] = XPUB_ADDRESS_ID;
    if (!decode_base58 (&XPUB_ADDRESS, address, digest))
      return PARSER_HASH_ENCODING;
  }
  else if (strncmp (address_type, "P2PKH", token.len[0]) == 0)
  {
    salt->salt_buf[0] = P2PKH_ADDRESS_ID;
    if (!decode_base58 (&P2PKH_ADDRESS, address, digest))
      return PARSER_HASH_ENCODING;
  }
  else if (strncmp (address_type, "P2PKH-P2WPKH", token.len[0]) == 0)
  {
    salt->salt_buf[0] = P2SHWPKH_ADDRESS_ID;
    if (!decode_base58 (&P2SHWPKH_ADDRESS, address, digest))
      return PARSER_HASH_ENCODING;
  }
  else if (strncmp (address_type, "P2PWPKH", token.len[0]) == 0)
  {
    salt->salt_buf[0] = P2WPKH_ADDRESS_ID;
    int ver;
    size_t witprog_len;

    if (!segwit_addr_decode (&ver, digest, &witprog_len, "bc", address))
      return PARSER_HASH_ENCODING;
    if (ver != 0)
      return PARSER_HASH_ENCODING;
    if (witprog_len != 20)
      return PARSER_HASH_ENCODING;
  }
  else
  {
    return PARSER_SIGNATURE_UNMATCHED;
  }

  u32 salt_index = 1;

  // Store the derivation path in the salt
  if (strncmp (derivation_path, "m/", 2) != 0)
    return PARSER_SALT_VALUE;
  derivation_path += 2;
  for (u32 derivation = 0; derivation != DERIVATION_END; salt_index++)
  {
    derivation = decode_derivation_path ((u8 **) & derivation_path, SEPARATOR);
    if (derivation == DERIVATION_ERROR)
      return PARSER_SALT_VALUE;
    salt->salt_buf[salt_index] = derivation;
  }

  // Store the mnemonic words in the salt
  for (u32 mnemonic = 0; mnemonic != MNEMONIC_END; salt_index++)
  {
    mnemonic = decode_mnemonic_phrase ((u8 **) & mnemonic_phrase, SEPARATOR);
    if (mnemonic == MNEMONIC_ERROR)
      return PARSER_SALT_ENCODING;
    salt->salt_buf[salt_index] = mnemonic;
  }

  // BIP39 requires 2048 iterations of PBKDF2-HMAC-SHA512
  salt->salt_iter = 2047;
  salt->salt_len = salt_index + 1;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t * salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t * hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u8 *digest = (const u8 *) digest_buf;
  u8 address[128];

  if (salt->salt_buf[0] == XPUB_ADDRESS_ID)
  {
    encode_base58 (&XPUB_ADDRESS, address, digest);
  }
  else if (salt->salt_buf[0] == P2PKH_ADDRESS_ID)
  {
    encode_base58 (&P2PKH_ADDRESS, address, digest);
  }
  else if (salt->salt_buf[0] == P2SHWPKH_ADDRESS_ID)
  {
    encode_base58 (&P2SHWPKH_ADDRESS, address, digest);
  }
  else if (salt->salt_buf[0] == P2WPKH_ADDRESS_ID)
  {
    segwit_addr_encode ((char *) address, "bc", 0, digest, 20);
  }

  return snprintf (line_buf, line_size, "%s", address);
}

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const hashes_t * hashes, MAYBE_UNUSED const void *tmps, const u32 * src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 * dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  u32 buf[32] = { 0 };
  msg_encoder_t encoder = encoder_init (buf);
  bip39_tmp_t *tmp = (bip39_tmp_t *) tmps;

  const u32 *salt = hashes->salts_buf[tmp->salt_index].salt_buf;
  u32 words[32] = { 0 };
  u32 pw_index = bip39_guess_words (src_buf, salt, words);

  u32 salt_index = 0;

  while (salt[salt_index] != DERIVATION_END)
  {
    salt_index++;
  }
  salt_index++;

  for (u32 i = salt_index; salt[salt_index] != MNEMONIC_END; salt_index++)
  {
    if (salt[salt_index] == MNEMONIC_GUESS)
    {
      encode_mnemonic_word (&encoder, words[salt_index - i]);
      encode_char (&encoder, ',');
    }
  }
  encode_array_le (&encoder, src_buf, src_len, pw_index);

  for (u32 i = 0; i <= encoder.len / 4; i++)
  {
    dst_buf[i] = byte_swap_32 (buf[i]);
  }

  return encoder.len;
}

void module_init (module_ctx_t * module_ctx)
{
  module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec = module_attack_exec;
  module_ctx->module_benchmark_esalt = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = module_build_plain_postprocess;
  module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0 = module_dgst_pos0;
  module_ctx->module_dgst_pos1 = module_dgst_pos1;
  module_ctx->module_dgst_pos2 = module_dgst_pos2;
  module_ctx->module_dgst_pos3 = module_dgst_pos3;
  module_ctx->module_dgst_size = module_dgst_size;
  module_ctx->module_dictstat_disable = MODULE_DEFAULT;
  module_ctx->module_esalt_size = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
  module_ctx->module_hash_decode = module_hash_decode;
  module_ctx->module_hash_encode_status = MODULE_DEFAULT;
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
  module_ctx->module_jit_build_options = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max = MODULE_DEFAULT;
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
  module_ctx->module_pw_max = MODULE_DEFAULT;
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
}
