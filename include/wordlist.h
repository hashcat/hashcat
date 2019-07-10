/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _WORDLIST_H
#define _WORDLIST_H

#include <time.h>
#include <inttypes.h>

size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len);

void pw_pre_add  (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx);
void pw_base_add (hc_device_param_t *device_param, pw_pre_t *pw_pre);
void pw_add      (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len);

void get_next_word_lm  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_uc  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off);

void get_next_word   (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, char **out_buf, u32 *out_len);
int  load_segment    (hashcat_ctx_t *hashcat_ctx, HCFILE *fp);
int  count_words     (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *dictfile, u64 *result);

int  wl_data_init    (hashcat_ctx_t *hashcat_ctx);
void wl_data_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _WORDLIST_H
