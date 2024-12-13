/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_TRUECRYPT_CRC32_H
#define INC_TRUECRYPT_CRC32_H

DECLSPEC u32 round_crc32 (u32 a, const u32 v);
DECLSPEC u32 round_crc32_4 (const u32 w, const u32 iv);

#endif // INC_TRUECRYPT_CRC32_H
