/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_LUKS_AF_H
#define _INC_LUKS_AF_H

DECLSPEC void AF_sha1_diffuse16 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha1_diffuse32 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha1_diffuse64 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha256_diffuse16 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha256_diffuse32 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha256_diffuse64 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha512_diffuse16 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha512_diffuse32 (PRIVATE_AS u32 *out);
DECLSPEC void AF_sha512_diffuse64 (PRIVATE_AS u32 *out);
DECLSPEC void AF_ripemd160_diffuse16 (PRIVATE_AS u32 *out);
DECLSPEC void AF_ripemd160_diffuse32 (PRIVATE_AS u32 *out);
DECLSPEC void AF_ripemd160_diffuse64 (PRIVATE_AS u32 *out);

#endif // _INC_LUKS_AF_H
