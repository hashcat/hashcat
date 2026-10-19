/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BCRYPT_PBKDF_H
#define INC_BCRYPT_PBKDF_H

// The rounds of bcrypt_pbkdf () from OpenBSD lib/libutil/bcrypt_pbkdf.c. bcrypt_hash () is one
// round over the SHA-512 of the password and of the salt, and needs the four S-boxes in local
// memory. The caller XORs the rounds together and spreads the output blocks over the key, since
// the stride follows from the length of the key it derives.

DECLSPEC void sha512_digest_to_words (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w);
DECLSPEC void bf_expand0state        (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *key);
DECLSPEC void bf_expandstate         (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *data, PRIVATE_AS const u32 *key);
DECLSPEC void bcrypt_hash            (PRIVATE_AS const u32 *sha2pass, PRIVATE_AS const u32 *sha2salt, PRIVATE_AS u32 *out, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);

#endif // INC_BCRYPT_PBKDF_H
