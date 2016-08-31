#pragma once
/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */


#ifndef SHARED_H
#define SHARED_H
#include "config.h"
#include <dirent.h>

#include "common.h"
#include "inc_hash_constants.h"
#include "hc_concurrency.h"
#include "dynload.h"


 /**
 * shared stuff
 */


#include "types.h"



 /**
  * system stuff
  */

#ifdef _WIN
inline void hc_sleep(DWORD x) { Sleep(x * 1000); }
#elif defined(_POSIX)
void hc_sleep(uint32_t x);
inline void hc_sleep(uint32_t x) { sleep(x); }
#endif


/**
 * kernel types
#include "consts/display_lengths.h"
#include "consts/hash_types.h"
#include "consts/kernel_types.h"
#include "consts/signatures.h"
#include "consts/rounds_count.h"
#include "consts/salt_types.h"
#include "consts/optimizer_options.h"
#include "consts/hash_options.h"
#include "consts/digest_sizes.h"
#include "consts/parser.h"
#include "consts/devices_statuses.h"
 */
typedef enum KERN_RUN_ {
  KERN_RUN_MP = 101,
  KERN_RUN_MP_L = 102,
  KERN_RUN_MP_R = 103,

  KERN_RUN_1 = 1000,
  KERN_RUN_12 = 1500,
  KERN_RUN_2 = 2000,
  KERN_RUN_23 = 2500,
  KERN_RUN_3 = 3000
} KERN_RUN;

/*
 * functions
 */

void dump_hex(const u8 *s, const int sz);

void truecrypt_crc32(const char *filename, u8 keytab[64]);

char *get_exec_path();
char *get_install_dir(const char *progname);
char *get_profile_dir(const char *homedir);
char *get_session_dir(const char *profile_dir);
uint count_lines(FILE *fd);

void *rulefind(const void *key, void *base, int nmemb, size_t size, int(*compar) (const void *, const void *));

#include "sort_by.h"

void format_debug(char * debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len);
void format_plain(FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex);
void format_output(FILE *out_fp, char *out_buf, unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, unsigned char *username, const uint user_len);
void handle_show_request(pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int(*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request(pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int(*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_show_request_lm(pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int(*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request_lm(pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int(*sort_by_pot) (const void *, const void *), FILE *out_fp);

u32            setup_opencl_platforms_filter(char *opencl_platforms);
u32            setup_devices_filter(char *opencl_devices);
cl_device_type setup_device_types_filter(char *opencl_device_types);

u32 get_random_num(const u32 min, const u32 max);

u32 mydivc32(const u32 dividend, const u32 divisor);
u64 mydivc64(const u64 dividend, const u64 divisor);

void ascii_digest(char *out_buf, uint salt_pos, uint digest_pos);
void to_hccap_t(hccap_t *hccap, uint salt_pos, uint digest_pos);

void format_speed_display(float val, char *buf, size_t len);
void format_timer_display(struct tm *tm, char *buf, size_t len);
void lowercase(u8 *buf, int len);
void uppercase(u8 *buf, int len);
int fgetl(FILE *fp, char *line_buf);
int in_superchop(char *buf);
char **scan_directory(const char *path);
int count_dictionaries(char **dictionary_files);
char *strparser(const uint parser_status);
char *stroptitype(const uint opti_type);
char *strhashtype(const uint hash_mode);
char *strstatus(const uint threads_status);
void status();


#if F_SETLKW
void lock_file(FILE *fp);
void unlock_file(FILE *fp);
#else
void lock_file(FILE *fp);
inline void lock_file(FILE *fp) {}
void unlock_file(FILE *fp);
inline void unlock_file(FILE *fp) {}
#endif

#ifdef _WIN
void fsync(int fd);
#endif

#include "hwmon.h"

void myabort();
void myquit();

void set_cpu_affinity(char *cpu_affinity);

void usage_mini_print(const char *progname);
void usage_big_print(const char *progname);

void tuning_db_destroy(tuning_db_t *tuning_db);
tuning_db_t *tuning_db_alloc(FILE *fp);
tuning_db_t *tuning_db_init(const char *tuning_db_file);
tuning_db_entry_t *tuning_db_search(tuning_db_t *tuning_db, hc_device_param_t *device_param, int attack_mode, int hash_type);


void naive_replace(char *s, const u8 key_char, const u8 replace_char);
void naive_escape(char *s, size_t s_max, const u8 key_char, const u8 escape_char);
void load_kernel(const char *kernel_file, int num_devices, size_t *kernel_lengths, const u8 **kernel_sources);
void writeProgramBin(char *dst, u8 *binary, size_t binary_size);

u64 get_lowest_words_done();

restore_data_t *init_restore(int argc, char **argv);
void            read_restore(const char *eff_restore_file, restore_data_t *rd);
void            write_restore(const char *new_restore_file, restore_data_t *rd);
void            cycle_restore();
void            check_checkpoint();

#ifdef WIN

BOOL WINAPI sigHandler_default(DWORD sig);
BOOL WINAPI sigHandler_benchmark(DWORD sig);
void hc_signal(BOOL WINAPI(callback) (DWORD sig));

#else

void sigHandler_default(int sig);
void sigHandler_benchmark(int sig);
void hc_signal(void c(int));

#endif

bool class_num(u8 c);
bool class_lower(u8 c);
bool class_upper(u8 c);
bool class_alpha(u8 c);


int cpu_rule_to_kernel_rule(char *rule_buf, uint rule_len, kernel_rule_t *rule);
int kernel_rule_to_cpu_rule(char *rule_buf, kernel_rule_t *rule);

void *thread_device_watch(void *p);
void *thread_keypress(void *p);
void *thread_runtime(void *p);

/**
 * checksum for use on cpu
 */

#include "cpu-crc32.h"
#include "cpu-md5.h"

 /**
  * ciphers for use on cpu
  */

#include "cpu-aes.h"

#endif // SHARED_H
