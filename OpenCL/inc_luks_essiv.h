/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_LUKS_ESSIV_H
#define _INC_LUKS_ESSIV_H

DECLSPEC void ESSIV_sha256_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void ESSIV_sha256_init128 (u32 *key, u32 *essivhash);
DECLSPEC void ESSIV_sha256_init256 (u32 *key, u32 *essivhash);

#endif // _INC_LUKS_ESSIV_H
