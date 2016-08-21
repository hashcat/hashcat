#pragma once
#include "common.h"
#include "rp_cpu.h"

int mangle_lrest(char arr[BLOCK_SIZE], int arr_len);
int mangle_urest(char arr[BLOCK_SIZE], int arr_len);
int mangle_trest(char arr[BLOCK_SIZE], int arr_len);
int mangle_reverse(char arr[BLOCK_SIZE], int arr_len);
int mangle_double(char arr[BLOCK_SIZE], int arr_len);
int mangle_double_times(char arr[BLOCK_SIZE], int arr_len, int times);
int mangle_reflect(char arr[BLOCK_SIZE], int arr_len);
int mangle_rotate_left(char arr[BLOCK_SIZE], int arr_len);
int mangle_rotate_right(char arr[BLOCK_SIZE], int arr_len);
int mangle_append(char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_prepend(char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_delete_at(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_extract(char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_omit(char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_insert(char arr[BLOCK_SIZE], int arr_len, int upos, char c);
int mangle_overstrike(char arr[BLOCK_SIZE], int arr_len, int upos, char c);
int mangle_truncate_at(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_replace(char arr[BLOCK_SIZE], int arr_len, char oldc, char newc);
int mangle_purgechar(char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_dupeblock_prepend(char arr[BLOCK_SIZE], int arr_len, int ulen);
int mangle_dupeblock_append(char arr[BLOCK_SIZE], int arr_len, int ulen);
int mangle_dupechar_at(char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_dupechar(char arr[BLOCK_SIZE], int arr_len);
int mangle_switch_at_check(char arr[BLOCK_SIZE], int arr_len, int upos, int upos2);
int mangle_switch_at(char arr[BLOCK_SIZE], int arr_len, int upos, int upos2);
int mangle_chr_shiftl(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_shiftr(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_incr(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_decr(char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_title(char arr[BLOCK_SIZE], int arr_len);

int generate_random_rule(char rule_buf[RP_RULE_BUFSIZ], u32 rp_gen_func_min, u32 rp_gen_func_max);
int _old_apply_rule(char *rule, int rule_len, char in[BLOCK_SIZE], int in_len, char out[BLOCK_SIZE]);
