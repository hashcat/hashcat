/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PUBKEY_H
#define HC_PUBKEY_H

#include <stdio.h>

// Wire format of an encrypted plain, as it appears in the outfile and the potfile:
//
//   $HCENC$1$<keyid>$<base64 ciphertext>
//
// keyid is the first 8 bytes, hex encoded, of SHA-256 over the DER SubjectPublicKeyInfo of the
// recipient's public key. It lets a reader tell at a glance which key an entry belongs to, so a
// single potfile can carry entries for more than one recipient, and it makes an encrypted entry
// impossible to confuse with a recovered password.

#define PUBKEY_MARKER         "$HCENC$1$"
#define PUBKEY_MARKER_LEN     9
#define PUBKEY_KEYID_LEN      16

// RSA-OAEP with SHA-256 for both the OAEP and the MGF1 digest costs 2 * 32 + 2 bytes of the modulus.

#define PUBKEY_OAEP_OVERHEAD  66

// Upper bound on the bound-payload header described in pubkey.c: "v1\n" plus a 64 character digest
// and newline plus a decimal timestamp and newline, rounded up.

#define PUBKEY_HEADER_MAX     96

int  pubkey_ctx_init      (hashcat_ctx_t *hashcat_ctx);
void pubkey_ctx_destroy   (hashcat_ctx_t *hashcat_ctx);

int  pubkey_encrypt_plain (hashcat_ctx_t *hashcat_ctx, const u8 *hash_buf, const int hash_len, const u8 *plain_buf, const int plain_len, u8 *out_buf, const size_t out_size, int *out_len);

#endif // HC_PUBKEY_H
