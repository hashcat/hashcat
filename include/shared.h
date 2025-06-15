/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_SHARED_H
#define HC_SHARED_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <math.h>

#include "zlib.h"
#include "filehandling.h"

#if defined (_WIN)
#include <winsock2.h> // needed for select()
#else
#include <sys/select.h>
#endif

int sort_by_string_sized (const void *p1, const void *p2);
int sort_by_stringptr    (const void *p1, const void *p2);

bool overflow_check_u32_add (const u32 a, const u32 b);
bool overflow_check_u32_mul (const u32 a, const u32 b);
bool overflow_check_u64_add (const u64 a, const u64 b);
bool overflow_check_u64_mul (const u64 a, const u64 b);

bool is_power_of_2 (const u32 v);

u32 get_random_num (const u32 min, const u32 max);

u32 mydivc32 (const u32 dividend, const u32 divisor);
u64 mydivc64 (const u64 dividend, const u64 divisor);

char *filename_from_filepath (char *filepath);

int utf8_to_widechar (const char *utf8, wchar_t **wide_out);

void naive_replace (char *s, const char key_char, const char replace_char);
void naive_escape (char *s, size_t s_max, const char key_char, const char escape_char);

__attribute__ ((format (printf, 2, 3))) int hc_asprintf (char **strp, const char *fmt, ...);

void setup_environment_variables (const folder_config_t *folder_config, const user_options_t *user_options);
void setup_umask (void);
void setup_seeding (const bool rp_gen_seed_chgd, const u32 rp_gen_seed);

void  hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);
void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);

bool hc_path_is_file (const char *path);
bool hc_path_is_directory (const char *path);
bool hc_path_is_fifo (const char *path);
bool hc_path_is_empty (const char *path);
bool hc_access (const char *path, const int mode);
bool hc_path_exist (const char *path);
bool hc_path_read (const char *path);
bool hc_path_write (const char *path);
bool hc_path_create (const char *path);
bool hc_path_has_bom (const char *path);

bool hc_string_is_digit (const char *s);
int  hc_string_bom_size (const u8 *s);

void hc_string_trim_trailing (char *s);
void hc_string_trim_leading (char *s);

int hc_get_processor_count (void);

bool hc_same_files (char *file1, char *file2);

int hc_stat (const char* path, struct stat *buf);

u32 hc_strtoul  (const char *nptr, char **endptr, int base);
u64 hc_strtoull (const char *nptr, char **endptr, int base);

u32 power_of_two_ceil_32  (const u32 v);
u32 power_of_two_floor_32 (const u32 v);

u32 round_up_multiple_32 (const u32 v, const u32 m);
u64 round_up_multiple_64 (const u64 v, const u64 m);

void hc_strncat (u8 *dst, const u8 *src, const size_t n);

const u8 *hc_strchr_next (const u8 *input_buf, const int input_len, const u8 separator);
const u8 *hc_strchr_last (const u8 *input_buf, const int input_len, const u8 separator);

int count_char (const u8 *buf, const int len, const u8 c);
float get_entropy (const u8 *buf, const int len);

int select_read_timeout  (int sockfd, const int sec);
int select_write_timeout (int sockfd, const int sec);

int select_read_timeout_console (const int sec);

const char *strparser (const u32 parser_status);
const char *strhashcategory (const u32 hash_category);
const char *stroptitype (const u32 opti_type);

bool generic_salt_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf, int *out_len);
int  generic_salt_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, const u8 *in_buf, const int in_len, u8 *out_buf);

int input_tokenizer (const u8 *input_buf, const int input_len, hc_token_t *token);

int extract_dynamicx_hash (const u8 *input_buf, const int input_len, u8 **output_buf, int *output_len);

int get_current_arch();

#if defined (__APPLE__)
bool is_apple_silicon (void);
#endif

char *file_to_buffer (const char *filename);

#endif // HC_SHARED_H
