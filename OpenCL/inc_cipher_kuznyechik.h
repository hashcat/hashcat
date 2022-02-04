/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_KUZNYECHIK_H
#define _INC_CIPHER_KUZNYECHIK_H

DECLSPEC void kuznyechik_linear (PRIVATE_AS u32 *w);
DECLSPEC void kuznyechik_linear_inv (PRIVATE_AS u32 *w);
DECLSPEC void kuznyechik_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey);
DECLSPEC void kuznyechik_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void kuznyechik_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // _INC_CIPHER_KUZNYECHIK_H
