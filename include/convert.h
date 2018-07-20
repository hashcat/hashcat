/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CONVERT_H
#define _CONVERT_H

#include <ctype.h>

bool is_hexify (const u8 *buf, const size_t len);
size_t exec_unhexify (const u8 *in_buf, const size_t in_len, u8 *out_buf, const size_t out_sz);

bool need_hexify (const u8 *buf, const size_t len, const char separator, bool always_ascii);
void exec_hexify (const u8 *buf, const size_t len, u8 *out);

bool is_valid_base64a_string  (const u8 *s, const size_t len);
bool is_valid_base64a_char    (const u8 c);
bool is_valid_base64b_string  (const u8 *s, const size_t len);
bool is_valid_base64b_char    (const u8 c);
bool is_valid_base64c_string  (const u8 *s, const size_t len);
bool is_valid_base64c_char    (const u8 c);
bool is_valid_hex_string      (const u8 *s, const size_t len);
bool is_valid_hex_char        (const u8 c);
bool is_valid_digit_string    (const u8 *s, const size_t len);
bool is_valid_digit_char      (const u8 c);

u8 hex_convert (const u8 c);

u8  hex_to_u8  (const u8 hex[2]);
u32 hex_to_u32 (const u8 hex[8]);
u64 hex_to_u64 (const u8 hex[16]);

void u8_to_hex_lower  (const u8  v, u8 hex[2]);
void u32_to_hex_lower (const u32 v, u8 hex[8]);
void u64_to_hex_lower (const u64 v, u8 hex[16]);

u8 int_to_base32    (const u8 c);
u8 base32_to_int    (const u8 c);
u8 int_to_base64    (const u8 c);
u8 base64_to_int    (const u8 c);
u8 int_to_base64url (const u8 c);
u8 base64url_to_int (const u8 c);
u8 int_to_itoa32    (const u8 c);
u8 itoa32_to_int    (const u8 c);
u8 int_to_itoa64    (const u8 c);
u8 itoa64_to_int    (const u8 c);
u8 int_to_bf64      (const u8 c);
u8 bf64_to_int      (const u8 c);
u8 int_to_lotus64   (const u8 c);
u8 lotus64_to_int   (const u8 c);

size_t base32_decode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
size_t base32_encode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
size_t base64_decode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
size_t base64_encode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);

void lowercase (u8 *buf, const size_t len);
void uppercase (u8 *buf, const size_t len);

#endif // _CONVERT_H
