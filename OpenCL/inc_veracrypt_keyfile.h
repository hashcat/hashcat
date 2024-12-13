/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_VERACRYPT_KEYFILE_H
#define INC_VERACRYPT_KEYFILE_H

DECLSPEC u32 u8add (const u32 a, const u32 b);
DECLSPEC u32 hc_apply_keyfile_vc (PRIVATE_AS u32 *w, const int pw_len, const GLOBAL_AS vc_t *vc);

#endif // INC_VERACRYPT_KEYFILE_H
