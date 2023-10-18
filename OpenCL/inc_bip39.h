/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BIP39_H
#define INC_BIP39_H

// Special salt codes
#define MNEMONIC_END (0x1FFFFFFF)
#define MNEMONIC_ERROR (0x2FFFFFFF)
#define MNEMONIC_GUESS (0x3FFFFFFF)
#define DERIVATION_END (0x4FFFFFFF)
#define DERIVATION_ERROR (0x5FFFFFFF)
#define DERIVATION_HARDENED (0x80000000)

// Start of BIP-39 xbit charsets
#define BIP39_BYTE_OFFSET (48)

// Address (digest) encoding types
#define XPUB_ADDRESS_ID (0)
#define P2PKH_ADDRESS_ID (1)
#define P2SHWPKH_ADDRESS_ID (2)
#define P2WPKH_ADDRESS_ID (3)

// BIP-39 variables that store the iterations of PBKDF2-SHA512
typedef struct bip39_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

  u32 salt_index;
} bip39_tmp_t;

// Represents the current state of encoding a message
typedef struct msg_encoder
{
  u32 bitwise_offset;
  u32 index;
  u32 *output;
  u32 len;
} msg_encoder_t;

DECLSPEC msg_encoder_t encoder_init (PRIVATE_AS u32 * output);
DECLSPEC void encode_char (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u8 c);
DECLSPEC void encode_array_be (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * array, PRIVATE_AS const u32 len, PRIVATE_AS const u32 start_index);
DECLSPEC void encode_array_le (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * array, PRIVATE_AS const u32 len, PRIVATE_AS const u32 start_index);
DECLSPEC u32 encode_mnemonic_word (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 word_index);
DECLSPEC void encode_mnemonic_phrase (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * words);
DECLSPEC u32 bip39_guess_words (PRIVATE_AS const u32 * password, PRIVATE_AS const u32 * salt, PRIVATE_AS u32 * wordlist);
DECLSPEC u32 bip39_from_word (PRIVATE_AS const char *word);

#endif // INC_BIP39_H
