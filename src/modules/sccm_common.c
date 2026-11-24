/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Shared by the ConfigMgr media variables modes 40177 and 40178, the way bip39_common.c is shared by
// the BIP39 modes: the line decoder. The two differ only in the algorithm id the header carries, so
// each mode passes the one it takes.
//
// The password protected media variables file of ConfigMgr PXE, boot and stand-alone media, as
// PXEThief extracts it: the first 40 bytes of the file in hex, a 24 byte header followed by the
// first ciphertext block. CryptDeriveKey turns the sha1 of the UTF-16LE password into the key. The
// file is AES-CBC with a zero IV and its plaintext starts with UTF-16LE "<?xml ve", so the first
// ciphertext block is that block encrypted under the key.
//
// PXEThief labels every line aes128, including AES-256 files. Either label is accepted, and the
// algorithm id in the header decides which of 40177 and 40178 takes the line.

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"

static const char *SIGNATURE_SCCM_AES128 = "$sccm$aes128$";
static const char *SIGNATURE_SCCM_AES256 = "$sccm$aes256$";

#define SCCM_MAGIC      0xeced0000
#define SCCM_HEADER_LEN 20

static int sccm_hash_decode (u32 *digest, const u32 alg_id_expected, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_SCCM_AES128;
  token.signatures_buf[1] = SIGNATURE_SCCM_AES256;

  token.len[0]     = 13;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 80;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *head_pos = token.buf[1];

  const u32 magic      = hex_to_u32 (&head_pos[ 0]);
  const u32 header_len = hex_to_u32 (&head_pos[ 8]);
  const u32 pt_len     = hex_to_u32 (&head_pos[16]);
  const u32 ct_len     = hex_to_u32 (&head_pos[24]);
  const u32 alg_id     = hex_to_u32 (&head_pos[32]);
  const u32 reserved   = hex_to_u32 (&head_pos[40]);

  if (magic  != SCCM_MAGIC)      return (PARSER_SIGNATURE_UNMATCHED);
  if (alg_id != alg_id_expected) return (PARSER_SIGNATURE_UNMATCHED);

  if (header_len != SCCM_HEADER_LEN) return (PARSER_HASH_VALUE);
  if (reserved   != 0)               return (PARSER_HASH_VALUE);

  // The plaintext must fill the known first block, and the ciphertext adds 1 to 16 bytes of padding.

  if (pt_len < 16)            return (PARSER_HASH_VALUE);
  if ((ct_len % 16) != 0)     return (PARSER_HASH_VALUE);
  if (ct_len <= pt_len)       return (PARSER_HASH_VALUE);
  if ((ct_len - pt_len) > 16) return (PARSER_HASH_VALUE);

  // The first ciphertext block, in the byte order the recipe's aes call produces.

  digest[0] = hex_to_u32 (&head_pos[48]);
  digest[1] = hex_to_u32 (&head_pos[56]);
  digest[2] = hex_to_u32 (&head_pos[64]);
  digest[3] = hex_to_u32 (&head_pos[72]);

  return (PARSER_OK);
}
