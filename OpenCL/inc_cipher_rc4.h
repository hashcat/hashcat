/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_RC4_H
#define _INC_CIPHER_RC4_H

DECLSPEC u8   GET_KEY8  (LOCAL_AS u32 *S, const u8 k);
DECLSPEC void SET_KEY8  (LOCAL_AS u32 *S, const u8 k, const u8 v);
DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v);

DECLSPEC void rc4_init_40        (LOCAL_AS u32 *S, const u32 *key);
DECLSPEC void rc4_init_128       (LOCAL_AS u32 *S, const u32 *key);
DECLSPEC void rc4_swap           (LOCAL_AS u32 *S, const u8 i, const u8 j);
DECLSPEC u8   rc4_next_16        (LOCAL_AS u32 *S, const u8 i, const u8 j,           const u32 *in, u32 *out);
DECLSPEC u8   rc4_next_16_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, u32 *out);

#endif // _INC_CIPHER_RC4_H
