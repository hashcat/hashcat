/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */
#pragma once
#ifndef TYPES_H
#define TYPES_H
 //#include "shared.h"
#include "brute_targets.h"

#ifdef _WIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

typedef struct salt_t_
{
  uint salt_buf[16];
  uint salt_buf_pc[8];

  uint salt_len;
  uint salt_iter;
  uint salt_sign[2];

  uint keccak_mdlen;
  uint truecrypt_mdlen;

  uint digests_cnt;
  uint digests_done;

  uint digests_offset;

  uint scrypt_N;
  uint scrypt_r;
  uint scrypt_p;

} salt_t;



typedef struct user_t_
{
  char *user_name;
  uint  user_len;

} user_t;

typedef struct hashinfo_t_
{
  user_t *user;
  char   *orighash;

} hashinfo_t;

typedef struct hash_t_
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  int         cracked;
  hashinfo_t *hash_info;

} hash_t;

typedef struct hcstat_table_t_
{
  uint key;
  u64  val;

} hcstat_table_t;

typedef struct cs_t_
{
  uint cs_buf[0x100];
  uint cs_len;

} cs_t;

typedef struct hccap_t_
{
  char essid[36];

  u8   mac1[6];
  u8   mac2[6];
  u8   nonce1[32];
  u8   nonce2[32];

  u8   eapol[256];
  int  eapol_size;

  int  keyver;
  u8   keymic[16];

} hccap_t;

typedef struct psafe3_t_
{
  char signature[4];
  u32  salt_buf[8];
  u32  iterations;
  u32  hash_buf[8];

} psafe3_t;

typedef struct pot_t_
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct dictstat_t_
{
  u64    cnt;

#ifdef _POSIX
  struct stat stat;
#endif

#ifdef _WIN
  struct __stat64 stat;
#endif

} dictstat_t;

typedef struct cpu_rule_t_
{
  uint len;

  char buf[0x100];

} cpu_rule_t;

typedef struct kernel_rule_t_
{
  uint cmds[0x100];

} kernel_rule_t;

typedef struct pw_t_
{
  u32 i[16];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct bf_t_
{
  uint i;

} bf_t;

typedef struct bs_word_t_
{
  uint b[32];

} bs_word_t;

typedef struct comb_t_
{
  uint i[8];

  uint pw_len;

} comb_t;

typedef struct restore_data_t_
{
  u32  version_bin;
  char cwd[256];
  u32  pid;

  u32  dictpos;
  u32  maskpos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

typedef struct outfile_data_t_
{
  char   *file_name;
  long   seek;
  time_t ctime;

} outfile_data_t;

typedef struct wl_data_t_
{
  char *buf;
  u32  incr;
  u32  avail;
  u32  cnt;
  u32  pos;

} wl_data_t;

typedef struct bitmap_result_t_
{
  uint bitmap_shift;
  uint collisions;

} bitmap_result_t;

typedef struct cpt_t_
{
  uint   cracked;
  time_t timestamp;

} cpt_t;

/*
typedef struct plain_t_
{
  uint plain_buf[16];
  uint plain_len;

} plain_t;
*/

typedef struct plain_t_
{
  uint salt_pos;
  uint digest_pos;
  uint hash_pos;
  uint gidvid;
  uint il_pos;

} plain_t;

typedef struct wordl_t_
{
  uint word_buf[16];

} wordl_t;

typedef struct wordr_t_
{
  uint word_buf[1];

} wordr_t;

typedef struct tuning_db_alias_t_
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct tuning_db_entry_t_
{
  char *device_name;
  int   attack_mode;
  int   hash_type;
  int   workload_profile;
  int   vector_width;
  int   kernel_accel;
  int   kernel_loops;

} tuning_db_entry_t;

typedef struct tuning_db_t_
{
  tuning_db_alias_t *alias_buf;
  int                alias_cnt;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;

} tuning_db_t;

#include "hc_device_param_t.h"
#include "hc_global_data_t.h"

#endif

