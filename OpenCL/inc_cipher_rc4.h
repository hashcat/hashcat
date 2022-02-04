/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_RC4_H
#define _INC_CIPHER_RC4_H

DECLSPEC u8   GET_KEY8  (LOCAL_AS u32 *S, const u8 k, const u64 lid);
DECLSPEC void SET_KEY8  (LOCAL_AS u32 *S, const u8 k, const u8 v, const u64 lid);
DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, const u64 lid);

DECLSPEC void rc4_init_40        (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid);
DECLSPEC void rc4_init_128       (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid);
DECLSPEC void rc4_swap           (LOCAL_AS u32 *S, const u8 i, const u8 j, const u64 lid);
DECLSPEC u8   rc4_next_16        (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const u64 lid);
DECLSPEC u8   rc4_next_16_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, const u64 lid);

#endif // _INC_CIPHER_RC4_H
