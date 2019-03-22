/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void AF_sha1_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
DECLSPEC void AF_sha256_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
DECLSPEC void AF_sha512_transform_S (const u64 *w0, const u64 *w1, const u64 *w2, const u64 *w3, u64 *digest)
DECLSPEC void AF_ripemd160_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
DECLSPEC void AF_sha1_diffuse16 (u32 *out)
DECLSPEC void AF_sha1_diffuse32 (u32 *out)
DECLSPEC void AF_sha1_diffuse64 (u32 *out)
DECLSPEC void AF_sha256_diffuse16 (u32 *out)
DECLSPEC void AF_sha256_diffuse32 (u32 *out)
DECLSPEC void AF_sha256_diffuse64 (u32 *out)
DECLSPEC void AF_sha512_diffuse16 (u32 *out)
DECLSPEC void AF_sha512_diffuse32 (u32 *out)
DECLSPEC void AF_sha512_diffuse64 (u32 *out)
DECLSPEC void AF_ripemd160_diffuse16 (u32 *out)
DECLSPEC void AF_ripemd160_diffuse32 (u32 *out)
DECLSPEC void AF_ripemd160_diffuse64 (u32 *out)
