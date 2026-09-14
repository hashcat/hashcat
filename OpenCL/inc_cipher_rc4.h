/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_CIPHER_RC4_H
#define INC_CIPHER_RC4_H

DECLSPEC u8   GET_KEY8  (LOCAL_AS u32 *S, const u8 k, const RC4_LID_TYPE lid);
DECLSPEC void SET_KEY8  (LOCAL_AS u32 *S, const u8 k, const u8 v, const RC4_LID_TYPE lid);
DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, const RC4_LID_TYPE lid);

DECLSPEC void rc4_init_40        (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid);
DECLSPEC void rc4_init_72        (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid);
DECLSPEC void rc4_init_104       (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid);
DECLSPEC void rc4_init_128       (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid);
DECLSPEC void rc4_swap           (LOCAL_AS u32 *S, const u8 i, const u8 j, const RC4_LID_TYPE lid);
DECLSPEC void rc4_dropN          (LOCAL_AS u32 *S, PRIVATE_AS u8 *i, PRIVATE_AS u8 *j, const u32 n, const RC4_LID_TYPE lid);
#ifdef RC4_ENABLE_NEXT_4
DECLSPEC u8   rc4_next_4         (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid);
#endif
DECLSPEC u8   rc4_next_16        (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid);
DECLSPEC u8   rc4_next_16_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid);

#endif // INC_CIPHER_RC4_H
