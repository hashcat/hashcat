/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_BASE58_H
#define _INC_HASH_BASE58_H

DECLSPEC bool is_valid_base58 (PRIVATE_AS const u32 *data, PRIVATE_AS const u32 offset, PRIVATE_AS const u32 len);

DECLSPEC bool b58dec    (PRIVATE_AS u8 *bin,  PRIVATE_AS u32 *binszp, PRIVATE_AS const u8 *b58, PRIVATE_AS const u32 b58sz);
DECLSPEC bool b58dec_51 (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *data);
DECLSPEC bool b58dec_52 (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *data);

DECLSPEC bool b58check    (PRIVATE_AS const u8  *bin, PRIVATE_AS const u32 binsz);
DECLSPEC bool b58check64  (PRIVATE_AS const u32 *bin, PRIVATE_AS const u32 binsz);
DECLSPEC bool b58check_25 (PRIVATE_AS const u32 *bin);
DECLSPEC bool b58check_37 (PRIVATE_AS const u32 *bin);
DECLSPEC bool b58check_38 (PRIVATE_AS const u32 *bin);

DECLSPEC bool b58enc       (PRIVATE_AS u8 *b58,  PRIVATE_AS u32 *b58sz,   PRIVATE_AS const u8 *data, PRIVATE_AS const u32 binsz);
DECLSPEC bool b58check_enc (PRIVATE_AS u8 *b58c, PRIVATE_AS u32 *b58c_sz, PRIVATE_AS const u8 ver,   PRIVATE_AS const u8 *data, PRIVATE_AS u32 datasz);

#endif // _INC_HASH_BASE58_H
