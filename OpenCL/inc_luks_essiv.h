/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_LUKS_ESSIV_H
#define _INC_LUKS_ESSIV_H

DECLSPEC void ESSIV_sha256_transform_S (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest);
DECLSPEC void ESSIV_sha256_init128 (PRIVATE_AS u32 *key, PRIVATE_AS u32 *essivhash);
DECLSPEC void ESSIV_sha256_init256 (PRIVATE_AS u32 *key, PRIVATE_AS u32 *essivhash);

#endif // _INC_LUKS_ESSIV_H
