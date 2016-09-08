/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef _SHARED_H
#define _SHARED_H

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>

/**
 * OS specific includes
 */

#if defined (_POSIX)
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#endif // _POSIX

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

/**
 * unsorted
 */




#if defined (_WIN)
#define hc_sleep(x) Sleep ((x) * 1000);
#elif defined (_POSIX)
#define hc_sleep(x) sleep ((x));
#endif

#define ETC_MAX                 (60 * 60 * 24 * 365 * 10)


#define INFOSZ                  CHARSIZ

#define INDUCT_DIR              "induct"
#define OUTFILES_DIR            "outfiles"

#define LOOPBACK_FILE           "hashcat.loopback"
#define DICTSTAT_FILENAME       "hashcat.dictstat"
#define POTFILE_FILENAME        "hashcat.pot"

/**
 * functions ok for shared
 */

u32 get_random_num (const u32 min, const u32 max);

u32 mydivc32 (const u32 dividend, const u32 divisor);
u64 mydivc64 (const u64 dividend, const u64 divisor);

void naive_replace (char *s, const u8 key_char, const u8 replace_char);
void naive_escape (char *s, size_t s_max, const u8 key_char, const u8 escape_char);



/**
 * sort out
 */


int sort_by_u32          (const void *p1, const void *p2);
int sort_by_mtime        (const void *p1, const void *p2);
int sort_by_cpu_rule     (const void *p1, const void *p2);
int sort_by_kernel_rule  (const void *p1, const void *p2);
int sort_by_stringptr    (const void *p1, const void *p2);
int sort_by_dictstat     (const void *s1, const void *s2);

int sort_by_pot          (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2);
int sort_by_hash_no_salt (const void *v1, const void *v2);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_salt_buf     (const void *v1, const void *v2);
int sort_by_hash_t_salt  (const void *v1, const void *v2);
int sort_by_digest_4_2   (const void *v1, const void *v2);
int sort_by_digest_4_4   (const void *v1, const void *v2);
int sort_by_digest_4_5   (const void *v1, const void *v2);
int sort_by_digest_4_6   (const void *v1, const void *v2);
int sort_by_digest_4_8   (const void *v1, const void *v2);
int sort_by_digest_4_16  (const void *v1, const void *v2);
int sort_by_digest_4_32  (const void *v1, const void *v2);
int sort_by_digest_4_64  (const void *v1, const void *v2);
int sort_by_digest_8_8   (const void *v1, const void *v2);
int sort_by_digest_8_16  (const void *v1, const void *v2);
int sort_by_digest_8_25  (const void *v1, const void *v2);
int sort_by_digest_p0p1  (const void *v1, const void *v2);

// special version for hccap (last 2 uints should be skipped where the digest is located)
int sort_by_hash_t_salt_hccap (const void *v1, const void *v2);

void format_debug (char * debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len);
void format_plain (FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex);
void format_output (FILE *out_fp, char *out_buf, unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, unsigned char *username, const uint user_len);
void handle_show_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_show_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);



#endif // _SHARED_H
