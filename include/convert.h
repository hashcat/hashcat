/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_CONVERT_H
#define HC_CONVERT_H

#include <ctype.h>

HC_PLUGIN_API bool is_hexify (const u8 *buf, const size_t len);
HC_PLUGIN_API size_t exec_unhexify (const u8 *in_buf, const size_t in_len, u8 *out_buf, const size_t out_sz);

HC_PLUGIN_API bool need_hexify (const u8 *buf, const size_t len, const char separator, bool always_ascii);
HC_PLUGIN_API void exec_hexify (const u8 *buf, const size_t len, u8 *out);

HC_PLUGIN_API bool is_valid_base64a_string  (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_base64a_char    (const u8 c);
HC_PLUGIN_API bool is_valid_base64b_string  (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_base64b_char    (const u8 c);
HC_PLUGIN_API bool is_valid_base64c_string  (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_base64c_char    (const u8 c);
HC_PLUGIN_API bool is_valid_base58_string   (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_base58_char     (const u8 c);
HC_PLUGIN_API bool is_valid_bech32_string   (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_bech32_char     (const u8 c);
HC_PLUGIN_API bool is_valid_hex_string      (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_hex_char        (const u8 c);
HC_PLUGIN_API bool is_valid_digit_string    (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_digit_char      (const u8 c);
HC_PLUGIN_API bool is_valid_float_string    (const u8 *s, const size_t len);
HC_PLUGIN_API bool is_valid_float_char      (const u8 c);

HC_PLUGIN_API u8 hex_convert (const u8 c);

HC_PLUGIN_API u8  hex_to_u8  (const u8 hex[2]);
HC_PLUGIN_API u32 hex_to_u32 (const u8 hex[8]);
HC_PLUGIN_API u64 hex_to_u64 (const u8 hex[16]);

HC_PLUGIN_API void u8_to_hex  (const u8  v, u8 hex[2]);
HC_PLUGIN_API void u32_to_hex (const u32 v, u8 hex[8]);
HC_PLUGIN_API void u64_to_hex (const u64 v, u8 hex[16]);

HC_PLUGIN_API u8 int_to_base32    (const u8 c);
HC_PLUGIN_API u8 base32_to_int    (const u8 c);
HC_PLUGIN_API u8 int_to_base64    (const u8 c);
HC_PLUGIN_API u8 base64_to_int    (const u8 c);
HC_PLUGIN_API u8 int_to_ab64      (const u8 c);
HC_PLUGIN_API u8 ab64_to_int      (const u8 c);
HC_PLUGIN_API u8 int_to_base64url (const u8 c);
HC_PLUGIN_API u8 base64url_to_int (const u8 c);
HC_PLUGIN_API u8 int_to_itoa32    (const u8 c);
HC_PLUGIN_API u8 itoa32_to_int    (const u8 c);
HC_PLUGIN_API u8 int_to_itoa64    (const u8 c);
HC_PLUGIN_API u8 itoa64_to_int    (const u8 c);
HC_PLUGIN_API u8 int_to_bf64      (const u8 c);
HC_PLUGIN_API u8 bf64_to_int      (const u8 c);
HC_PLUGIN_API u8 int_to_lotus64   (const u8 c);
HC_PLUGIN_API u8 lotus64_to_int   (const u8 c);

HC_PLUGIN_API size_t base32_decode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
HC_PLUGIN_API size_t base32_encode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
HC_PLUGIN_API size_t base64_decode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);
HC_PLUGIN_API size_t base64_encode (u8 (*f) (const u8), const u8 *in_buf, const size_t in_len, u8 *out_buf);

HC_PLUGIN_API void lowercase (u8 *buf, const size_t len);
HC_PLUGIN_API void uppercase (u8 *buf, const size_t len);

HC_PLUGIN_API u8 v8a_from_v32 (const u32 v32);
HC_PLUGIN_API u8 v8b_from_v32 (const u32 v32);
HC_PLUGIN_API u8 v8c_from_v32 (const u32 v32);
HC_PLUGIN_API u8 v8d_from_v32 (const u32 v32);

HC_PLUGIN_API u16 v16a_from_v32 (const u32 v32);
HC_PLUGIN_API u16 v16b_from_v32 (const u32 v32);
HC_PLUGIN_API u32 v32_from_v16ab (const u16 v16a, const u16 v16b);

HC_PLUGIN_API u32 v32a_from_v64 (const u64 v64);
HC_PLUGIN_API u32 v32b_from_v64 (const u64 v64);
HC_PLUGIN_API u64 v64_from_v32ab (const u32 v32a, const u32 v32b);

HC_PLUGIN_API int hex_decode (const u8 *in_buf, const int in_len, u8 *out_buf);
HC_PLUGIN_API int hex_encode (const u8 *in_buf, const int in_len, u8 *out_buf);

#endif // HC_CONVERT_H
