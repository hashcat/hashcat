/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_TRAINER_UTILS_H
#define HC_PCFG_TRAINER_UTILS_H

#define UTF16_NONE  0
#define UTF16_LE    1
#define UTF16_BE    2

size_t    find_base64_boundary   (const char *s, size_t len);
char     *find_email_delimiter   (char *s, size_t len, size_t *email_len, size_t *pass_len);
bool      find_hex_bounds        (const char *s, size_t len, size_t *hex_len, const char **suffix_ptr, size_t *suffix_len);
size_t    find_hex_chars_length  (const char *s, size_t len);
char     *find_hex_delimiter_ex  (char *s, size_t len, size_t *prefix_len, size_t *hex_len, size_t *suffix_len);
u32       get_domain_span        (const char *domain, u32 max_len);
bool      is_garbage_content     (const char *s, size_t len, bool decoded);
bool      is_probably_base64     (const char *s, size_t len);
bool      starts_with_bare_hex   (const char *s, size_t len);
bool      starts_with_hex        (const char *s, size_t len);
size_t    trim_padding_fast      (char *s, size_t len);
size_t    unhexify_smart         (const char *hex_in, size_t hex_len, char *out, size_t out_max, bool *was_utf16);
size_t    unhexify_bare          (const char *hex_in, size_t hex_len, char *out, size_t out_max, bool *was_utf16);

#endif // HC_PCFG_TRAINER_UTILS_H
