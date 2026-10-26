/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BITCOIN_ADDRESS_H
#define INC_BITCOIN_ADDRESS_H

DECLSPEC void hash160_from_sha256_state   (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *h);
DECLSPEC void hash160_pubkey_compressed   (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y);
DECLSPEC void hash160_pubkey_uncompressed (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y);
DECLSPEC void hash160_p2sh_p2wpkh         (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *hash160);

#endif // INC_BITCOIN_ADDRESS_H
