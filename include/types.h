/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#ifndef _TYPES_H
#define _TYPES_H

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>


/**
 * Outfile formats
 */


typedef enum wl_mode
{
  WL_MODE_STDIN = 1,
  WL_MODE_FILE  = 2,
  WL_MODE_MASK  = 3

} wl_mode_t;

typedef enum hl_mode
{
  HL_MODE_FILE  = 4,
  HL_MODE_ARG   = 5

} hl_mode_t;

#define HLFMTS_CNT 11

typedef enum hlfmt_name
{
  HLFMT_HASHCAT  = 0,
  HLFMT_PWDUMP   = 1,
  HLFMT_PASSWD   = 2,
  HLFMT_SHADOW   = 3,
  HLFMT_DCC      = 4,
  HLFMT_DCC2     = 5,
  HLFMT_NETNTLM1 = 7,
  HLFMT_NETNTLM2 = 8,
  HLFMT_NSLDAP   = 9,
  HLFMT_NSLDAPS  = 10

} hlfmt_name_t;

typedef enum attack_mode
{
  ATTACK_MODE_STRAIGHT  = 0,
  ATTACK_MODE_COMBI     = 1,
  ATTACK_MODE_TOGGLE    = 2,
  ATTACK_MODE_BF        = 3,
  ATTACK_MODE_PERM      = 4,
  ATTACK_MODE_TABLE     = 5,
  ATTACK_MODE_HYBRID1   = 6,
  ATTACK_MODE_HYBRID2   = 7,
  ATTACK_MODE_NONE      = 100

} attack_mode_t;

typedef enum attack_kern
{
  ATTACK_KERN_STRAIGHT  = 0,
  ATTACK_KERN_COMBI     = 1,
  ATTACK_KERN_BF        = 3,
  ATTACK_KERN_NONE      = 100

} attack_kern_t;

typedef enum attack_exec
{
  ATTACK_EXEC_OUTSIDE_KERNEL = 10,
  ATTACK_EXEC_INSIDE_KERNEL  = 11

} attack_exec_t;

typedef enum combinator_mode
{
  COMBINATOR_MODE_BASE_LEFT  = 10001,
  COMBINATOR_MODE_BASE_RIGHT = 10002

} combinator_mode_t;

typedef enum kern_run
{
  KERN_RUN_1    = 1000,
  KERN_RUN_12   = 1500,
  KERN_RUN_2    = 2000,
  KERN_RUN_23   = 2500,
  KERN_RUN_3    = 3000

} kern_run_t;

typedef enum kern_run_mp
{
  KERN_RUN_MP   = 101,
  KERN_RUN_MP_L = 102,
  KERN_RUN_MP_R = 103

} kern_run_mp_t;

typedef enum outfile_fmt
{
  OUTFILE_FMT_HASH      = (1 << 0),
  OUTFILE_FMT_PLAIN     = (1 << 1),
  OUTFILE_FMT_HEXPLAIN  = (1 << 2),
  OUTFILE_FMT_CRACKPOS  = (1 << 3)

} outfile_fmt_t;

/**
 * salt types
 */

typedef enum salt_type
{
  SALT_TYPE_NONE     = 1,
  SALT_TYPE_EMBEDDED = 2,
  SALT_TYPE_INTERN   = 3,
  SALT_TYPE_EXTERN   = 4,
  SALT_TYPE_VIRTUAL  = 5

} salt_type_t;

/**
 * optimizer options
 */

typedef enum opti_type
{
  OPTI_TYPE_ZERO_BYTE         = (1 <<  1),
  OPTI_TYPE_PRECOMPUTE_INIT   = (1 <<  2),
  OPTI_TYPE_PRECOMPUTE_MERKLE = (1 <<  3),
  OPTI_TYPE_PRECOMPUTE_PERMUT = (1 <<  4),
  OPTI_TYPE_MEET_IN_MIDDLE    = (1 <<  5),
  OPTI_TYPE_EARLY_SKIP        = (1 <<  6),
  OPTI_TYPE_NOT_SALTED        = (1 <<  7),
  OPTI_TYPE_NOT_ITERATED      = (1 <<  8),
  OPTI_TYPE_PREPENDED_SALT    = (1 <<  9),
  OPTI_TYPE_APPENDED_SALT     = (1 << 10),
  OPTI_TYPE_SINGLE_HASH       = (1 << 11),
  OPTI_TYPE_SINGLE_SALT       = (1 << 12),
  OPTI_TYPE_BRUTE_FORCE       = (1 << 13),
  OPTI_TYPE_RAW_HASH          = (1 << 14),
  OPTI_TYPE_SLOW_HASH_SIMD    = (1 << 15),
  OPTI_TYPE_USES_BITS_8       = (1 << 16),
  OPTI_TYPE_USES_BITS_16      = (1 << 17),
  OPTI_TYPE_USES_BITS_32      = (1 << 18),
  OPTI_TYPE_USES_BITS_64      = (1 << 19)

} opti_type_t;

/**
 * hash options
 */

typedef enum opts_type
{
  OPTS_TYPE_PT_UNICODE        = (1 <<  0),
  OPTS_TYPE_PT_UPPER          = (1 <<  1),
  OPTS_TYPE_PT_LOWER          = (1 <<  2),
  OPTS_TYPE_PT_ADD01          = (1 <<  3),
  OPTS_TYPE_PT_ADD02          = (1 <<  4),
  OPTS_TYPE_PT_ADD80          = (1 <<  5),
  OPTS_TYPE_PT_ADDBITS14      = (1 <<  6),
  OPTS_TYPE_PT_ADDBITS15      = (1 <<  7),
  OPTS_TYPE_PT_GENERATE_LE    = (1 <<  8),
  OPTS_TYPE_PT_GENERATE_BE    = (1 <<  9),
  OPTS_TYPE_PT_NEVERCRACK     = (1 << 10), // if we want all possible results
  OPTS_TYPE_PT_BITSLICE       = (1 << 11),
  OPTS_TYPE_ST_UNICODE        = (1 << 12),
  OPTS_TYPE_ST_UPPER          = (1 << 13),
  OPTS_TYPE_ST_LOWER          = (1 << 14),
  OPTS_TYPE_ST_ADD01          = (1 << 15),
  OPTS_TYPE_ST_ADD02          = (1 << 16),
  OPTS_TYPE_ST_ADD80          = (1 << 17),
  OPTS_TYPE_ST_ADDBITS14      = (1 << 18),
  OPTS_TYPE_ST_ADDBITS15      = (1 << 19),
  OPTS_TYPE_ST_GENERATE_LE    = (1 << 20),
  OPTS_TYPE_ST_GENERATE_BE    = (1 << 21),
  OPTS_TYPE_ST_HEX            = (1 << 22),
  OPTS_TYPE_ST_BASE64         = (1 << 23),
  OPTS_TYPE_HASH_COPY         = (1 << 24),
  OPTS_TYPE_HOOK12            = (1 << 25),
  OPTS_TYPE_HOOK23            = (1 << 26)

} opts_type_t;

/**
 * digests
 */

typedef enum dgst_size
{
  DGST_SIZE_4_2  = (2  * sizeof (uint)),   // 8
  DGST_SIZE_4_4  = (4  * sizeof (uint)),   // 16
  DGST_SIZE_4_5  = (5  * sizeof (uint)),   // 20
  DGST_SIZE_4_6  = (6  * sizeof (uint)),   // 24
  DGST_SIZE_4_8  = (8  * sizeof (uint)),   // 32
  DGST_SIZE_4_16 = (16 * sizeof (uint)),   // 64 !!!
  DGST_SIZE_4_32 = (32 * sizeof (uint)),   // 128 !!!
  DGST_SIZE_4_64 = (64 * sizeof (uint)),   // 256
  DGST_SIZE_8_8  = (8  * sizeof (u64)),    // 64 !!!
  DGST_SIZE_8_16 = (16 * sizeof (u64)),    // 128 !!!
  DGST_SIZE_8_25 = (25 * sizeof (u64))     // 200

} dgst_size_t;

/**
 * status
 */



typedef struct
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

typedef struct
{
  char *user_name;
  uint  user_len;

} user_t;

typedef struct
{
  user_t *user;
  char   *orighash;

} hashinfo_t;

typedef struct
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  int         cracked;
  hashinfo_t *hash_info;

} hash_t;

typedef struct
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct
{
  u64    cnt;

  #if defined (_POSIX)
  struct stat stat;
  #endif

  #if defined (_WIN)
  struct __stat64 stat;
  #endif

} dictstat_t;

typedef struct
{
  u32 i[16];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct
{
  uint i;

} bf_t;

typedef struct
{
  uint b[32];

} bs_word_t;

typedef struct
{
  uint i[8];

  uint pw_len;

} comb_t;



typedef struct
{
  char   *file_name;
  long   seek;
  time_t ctime;

} outfile_data_t;

typedef struct
{
  char *buf;
  u32  incr;
  u32  avail;
  u32  cnt;
  u32  pos;

} wl_data_t;

#define CPT_BUF 0x20000

typedef struct
{
  uint   cracked;
  time_t timestamp;

} cpt_t;

/*
typedef struct
{
  uint plain_buf[16];
  uint plain_len;

} plain_t;
*/

typedef struct
{
  uint salt_pos;
  uint digest_pos;
  uint hash_pos;
  uint gidvid;
  uint il_pos;

} plain_t;

typedef struct
{
  uint word_buf[16];

} wordl_t;

typedef struct
{
  uint word_buf[1];

} wordr_t;

#define RULES_MAX   256
#define PW_MIN      0
#define PW_MAX      54
#define PW_MAX1     (PW_MAX + 1)
#define PW_DICTMAX  31
#define PW_DICTMAX1 (PW_DICTMAX + 1)

#endif // _TYPES_H
