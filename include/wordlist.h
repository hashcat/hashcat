/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _WORDLIST_H
#define _WORDLIST_H

#include <time.h>
#include <inttypes.h>

u32 convert_from_hex (char *line_buf, const u32 line_len, const user_options_t *user_options);

void load_segment (wl_data_t *wl_data, FILE *fd);

void get_next_word_lm  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_uc  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off);

void get_next_word (wl_data_t *wl_data, const user_options_t *user_options, const user_options_extra_t *user_options_extra, FILE *fd, char **out_buf, u32 *out_len);

void pw_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len);

u64 count_words (wl_data_t *wl_data, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, const combinator_ctx_t *combinator_ctx, FILE *fd, const char *dictfile, dictstat_ctx_t *dictstat_ctx);

void wl_data_init (wl_data_t *wl_data, const user_options_t *user_options, const hashconfig_t *hashconfig);
void wl_data_destroy (wl_data_t *wl_data);

#endif // _WORDLIST_H
