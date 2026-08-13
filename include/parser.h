/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PARSER_H
#define HC_PARSER_H

HC_PLUGIN_API const char *strparser (const u32 parser_status);

HC_PLUGIN_API void        parser_error_reset  (void);
HC_PLUGIN_API const char *parser_error_string (const u32 parser_status);

HC_PLUGIN_API const u8 *hc_strchr_next (const u8 *input_buf, const int input_len, const u8 separator);
HC_PLUGIN_API const u8 *hc_strchr_last (const u8 *input_buf, const int input_len, const u8 separator);

HC_PLUGIN_API int input_tokenizer (const u8 *input_buf, const int input_len, hc_token_t *token);

HC_PLUGIN_API bool generic_salt_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf, int *out_len);
HC_PLUGIN_API int  generic_salt_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf);

HC_PLUGIN_API int extract_dynamicx_hash (const u8 *input_buf, const int input_len, u8 **output_buf, int *output_len);

#endif // HC_PARSER_H
