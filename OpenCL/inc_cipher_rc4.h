/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_RC4_H
#define _INC_CIPHER_RC4_H

DECLSPEC u8   GET_KEY8  (LOCAL_AS u32 *S, const int k);
DECLSPEC void SET_KEY8  (LOCAL_AS u32 *S, const int k, const u8 v);
DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const int k, const u32 v);

DECLSPEC void rc4_swap    (LOCAL_AS u32 *S, const u8 i, const u8 j);
DECLSPEC void rc4_init_16 (LOCAL_AS u32 *S, const u32 *data);
DECLSPEC u8   rc4_next_16 (LOCAL_AS u32 *S, u8 i, u8 j, CONSTANT_AS u32a *in, u32 *out);

#endif // _INC_CIPHER_RC4_H
