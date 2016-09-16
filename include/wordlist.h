/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _WORDLIST_H
#define _WORDLIST_H

#define HEX_WORDLIST 0
#define SEGMENT_SIZE 32

uint convert_from_hex (char *line_buf, const uint line_len);

void load_segment (wl_data_t *wl_data, FILE *fd);

void get_next_word_lm  (char *buf, u32 sz, u32 *len, u32 *off);
void get_next_word_uc  (char *buf, u32 sz, u32 *len, u32 *off);
void get_next_word_std (char *buf, u32 sz, u32 *len, u32 *off);

void get_next_word (wl_data_t *wl_data, FILE *fd, char **out_buf, uint *out_len);

void pw_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len);

u64 count_words (wl_data_t *wl_data, FILE *fd, const char *dictfile, dictstat_ctx_t *dictstat_ctx);

#endif // _WORDLIST_H
