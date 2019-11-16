/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_SECP256K1_H

#include "secp256k1.h"

bool hc_secp256k1_pubkey_parse     (secp256k1_pubkey *pubkey, u8 *buf, size_t length);
bool hc_secp256k1_pubkey_tweak_mul (secp256k1_pubkey *pubkey, u8 *buf, size_t length);

#endif // _EXT_SECP256K1_H
