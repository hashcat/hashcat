/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef TYPES_H
#define TYPES_H

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
  uint scrypt_tmto;
  uint scrypt_phy;

} salt_t;

typedef struct
{
  int   V;
  int   R;
  int   P;

  int   enc_md;

  uint  id_buf[8];
  uint  u_buf[32];
  uint  o_buf[32];

  int   id_len;
  int   o_len;
  int   u_len;

  uint  rc4key[2];
  uint  rc4data[2];

} pdf_t;

typedef struct
{
  uint pke[25];
  uint eapol[64];
  int  eapol_size;
  int  keyver;

} wpa_t;

typedef struct
{
  uint cry_master_buf[64];
  uint ckey_buf[64];
  uint public_key_buf[64];

  uint cry_master_len;
  uint ckey_len;
  uint public_key_len;

} bitcoin_wallet_t;

typedef struct
{
  uint salt_buf[30];
  uint salt_len;

  uint esalt_buf[38];
  uint esalt_len;

} sip_t;

typedef struct
{
  uint data[384];

} androidfde_t;

typedef struct
{
  uint nr_buf[16];
  uint nr_len;

  uint msg_buf[128];
  uint msg_len;

} ikepsk_t;

typedef struct
{
  uint user_len;
  uint domain_len;
  uint srvchall_len;
  uint clichall_len;

  uint userdomain_buf[64];
  uint chall_buf[256];

} netntlm_t;

typedef struct
{
  uint user[16];
  uint realm[16];
  uint salt[32];
  uint timestamp[16];
  uint checksum[4];

} krb5pa_t;

typedef struct
{
  uint salt_buf[16];
  uint data_buf[112];
  uint keyfile_buf[16];

} tc_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_md5_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_sha1_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_sha256_t;

typedef struct
{
  uint salt_buf[32];

} pbkdf2_sha512_t;

typedef struct
{
  uint8_t cipher[1040];

} agilekey_t;

typedef struct
{
  uint salt_buf[128];
  uint salt_len;

} rakp_t;

typedef struct
{
  uint data_len;
  uint data_buf[512];

} cloudkey_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];

  uint keySize;

} office2007_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2010_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2013_t;

typedef struct
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[4];
  uint rc4key[2];

} oldoffice01_t;

typedef struct
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];
  uint rc4key[2];

} oldoffice34_t;

typedef struct
{
  uint P[256];

} scrypt_tmp_t;

typedef struct
{
  uint digest[4];
  uint out[4];

} pdf14_tmp_t;

typedef struct
{
  union
  {
    uint dgst32[16];
    u64  dgst64[8];
  };

  uint  dgst_len;
  uint  W_len;

} pdf17l8_tmp_t;

typedef struct
{
  uint digest_buf[4];

} phpass_tmp_t;

typedef struct
{
  uint digest_buf[4];

} md5crypt_tmp_t;

typedef struct
{
  uint64_t l_alt_result[8];

  uint64_t l_p_bytes[2];
  uint64_t l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct
{
  uint alt_result[8];

  uint p_bytes[4];
  uint s_bytes[4];

} sha256crypt_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} wpa_tmp_t;

typedef struct
{
  uint64_t dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[4];

} dcc2_tmp_t;

typedef struct
{
  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} bcrypt_tmp_t;

typedef struct
{
  uint digest[2];

  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} pwsafe2_tmp_t;

typedef struct
{
  uint digest_buf[8];

} pwsafe3_tmp_t;

typedef struct
{
  uint digest_buf[5];

} androidpin_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} androidfde_tmp_t;

typedef struct
{
  uint ipad[16];
  uint opad[16];

  uint dgst[64];
  uint out[64];

} tc_tmp_t;

typedef struct
{
  uint64_t ipad[8];
  uint64_t opad[8];

  uint64_t dgst[32];
  uint64_t out[32];

} tc64_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} agilekey_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst1[5];
  uint out1[5];

  uint dgst2[5];
  uint out2[5];

} mywallet_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} sha1aix_tmp_t;

typedef struct
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} sha256aix_tmp_t;

typedef struct
{
  uint64_t ipad[8];
  uint64_t opad[8];

  uint64_t dgst[8];
  uint64_t out[8];

} sha512aix_tmp_t;

typedef struct
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} lastpass_tmp_t;

typedef struct
{
  uint64_t digest_buf[8];

} drupal7_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} lotus8_tmp_t;

typedef struct
{
  uint out[5];

} office2007_tmp_t;

typedef struct
{
  uint out[5];

} office2010_tmp_t;

typedef struct
{
  uint64_t out[8];

} office2013_tmp_t;

typedef struct
{
  uint digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  uint32_t ipad[4];
  uint32_t opad[4];

  uint32_t dgst[32];
  uint32_t out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  uint32_t ipad[5];
  uint32_t opad[5];

  uint32_t dgst[32];
  uint32_t out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  uint32_t ipad[8];
  uint32_t opad[8];

  uint32_t dgst[32];
  uint32_t out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  uint64_t ipad[8];
  uint64_t opad[8];

  uint64_t dgst[16];
  uint64_t out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  uint64_t out[8];

} ecryptfs_tmp_t;

typedef struct
{
  uint64_t ipad[8];
  uint64_t opad[8];

  uint64_t dgst[16];
  uint64_t out[16];

} oraclet_tmp_t;

typedef struct
{
  uint block[16];

  uint dgst[8];

  uint block_len;
  uint final_len;

} seven_zip_tmp_t;

typedef struct
{
  uint Kc[16];
  uint Kd[16];

  uint iv[2];

} bsdicrypt_tmp_t;

typedef struct
{
  uint dgst[17][5];

} rar3_tmp_t;

typedef struct
{
  uint user[16];

} cram_md5_t;

typedef struct
{
  uint iv_buf[4];
  uint iv_len;

  uint salt_buf[4];
  uint salt_len;

  uint crc;

  uint data_buf[96];
  uint data_len;

  uint unpack_size;

} seven_zip_t;

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
  uint     key;
  uint64_t val;

} hcstat_table_t;

typedef struct
{
  uint cs_buf[0x100];
  uint cs_len;

} cs_t;

typedef struct
{
  char          essid[36];

  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];

  unsigned char eapol[256];
  int           eapol_size;

  int           keyver;
  unsigned char keymic[16];

} hccap_t;

typedef struct
{
  char     signature[4];
  uint32_t salt_buf[8];
  uint32_t iterations;
  uint32_t hash_buf[8];

} psafe3_t;

typedef struct
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct
{
  uint64_t cnt;

  #ifdef _POSIX
  struct stat stat;
  #endif

  #ifdef _WIN
  struct __stat64 stat;
  #endif

} dictstat_t;

typedef struct
{
  uint len;

  char buf[0x100];

} cpu_rule_t;

typedef struct
{
  uint cmds[15];

} gpu_rule_t;

typedef struct
{
  union
  {
    uint8_t   hc4[4][ 64];
    uint32_t  hi4[4][ 16];
    uint64_t  hl4[4][  8];

    uint8_t   hc2[2][128];
    uint32_t  hi2[2][ 32];
    uint64_t  hl2[2][ 16];

    uint8_t   hc1[1][256];
    uint32_t  hi1[1][ 64];
    uint64_t  hl1[1][ 32];
  };

  uint pw_len;
  uint alignment_placeholder_1;
  uint alignment_placeholder_2;
  uint alignment_placeholder_3;

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
  pw_t pw_buf;

  uint cnt;

} pw_cache_t;

typedef struct
{
  uint32_t    version_bin;
  char        cwd[256];
  uint32_t    pid;

  uint32_t    dictpos;
  uint32_t    maskpos;

  uint64_t    words_cur;

  uint32_t    argc;
  char      **argv;

} restore_data_t;

typedef struct
{
  char     *file_name;
  long      seek;
  time_t    ctime;

} outfile_data_t;

typedef struct
{
  char     *buf;
  uint32_t  incr;
  uint32_t  avail;
  uint32_t  cnt;
  uint32_t  pos;

} wl_data_t;

typedef struct
{
  uint bitmap_shift;
  uint collisions;

} bitmap_result_t;

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

#define RULES_MAX   16
#define PW_MIN      0
#define PW_MAX      54
#define PW_MAX1     (PW_MAX + 1)
#define PW_DICTMAX  31
#define PW_DICTMAX1 (PW_DICTMAX + 1)

struct __hc_device_param
{
  uint              device_id;

  uint              gpu_processors;
  uint              gpu_threads;
  uint              gpu_accel;
  uint              gpu_vector_width;
  uint64_t          gpu_maxmem_alloc;
  uint              gpu_power;          // these both are based on their _user counterpart
  uint              gpu_blocks;         // but are modified by autotuner and used inside crack loops
  uint              gpu_power_user;
  uint              gpu_blocks_user;

  uint              size_pws;
  uint              size_tmps;
  uint              size_hooks;
  uint              size_root_css;
  uint              size_markov_css;
  uint              size_digests;
  uint              size_salts;
  uint              size_shown;
  uint              size_results;
  uint              size_plains;

  uint              vect_size;

  uint (*pw_add)    (struct __hc_device_param *, const uint8_t *, const uint);

  void (*pw_transpose) (const pw_t *, pw_t *);

  FILE             *combs_fp;
  comb_t           *combs_buf;

  void             *hooks_buf;

  pw_cache_t       *pw_caches;

  pw_t             *pws_buf;
  uint              pws_cnt;
  uint64_t          pw_cnt;

  uint64_t          words_off;
  uint64_t          words_done;

  uint             *result;

  uint              outerloop_pos;
  uint              outerloop_left;

  uint              innerloop_pos;
  uint              innerloop_left;

  uint              speed_pos;
  uint64_t          speed_cnt[SPEED_CACHE];
  float             speed_ms[SPEED_CACHE];
  hc_timer_t        speed_rec[SPEED_CACHE];

  hc_timer_t        timer_speed;

  // device specific attributes starting

  #ifdef _CUDA

  int               sm_major;
  int               sm_minor;

  CUdevice          device;

  CUfunction        function1;
  CUfunction        function12;
  CUfunction        function2;
  CUfunction        function23;
  CUfunction        function3;
  CUfunction        function_mp;
  CUfunction        function_mp_l;
  CUfunction        function_mp_r;
  CUfunction        function_amp;
  CUfunction        function_tb;
  CUfunction        function_tm;

  CUcontext         context;
  CUmodule          module;
  CUmodule          module_mp;
  CUmodule          module_amp;
  CUstream          stream;

  CUdeviceptr       d_pws_buf;
  CUdeviceptr       d_pws_amp_buf;
  CUdeviceptr       d_words_buf_l;
  CUdeviceptr       d_words_buf_r;
  CUdeviceptr       c_words_buf_r;
  CUdeviceptr       d_rules;
  CUdeviceptr       c_rules;
  CUdeviceptr       d_combs;
  CUdeviceptr       c_combs;
  CUdeviceptr       d_bfs;
  CUdeviceptr       c_bfs;
  CUdeviceptr       d_tm;
  CUdeviceptr       c_tm;
  size_t            c_bytes;
  CUdeviceptr       d_bitmap_s1_a;
  CUdeviceptr       d_bitmap_s1_b;
  CUdeviceptr       d_bitmap_s1_c;
  CUdeviceptr       d_bitmap_s1_d;
  CUdeviceptr       d_bitmap_s2_a;
  CUdeviceptr       d_bitmap_s2_b;
  CUdeviceptr       d_bitmap_s2_c;
  CUdeviceptr       d_bitmap_s2_d;
  CUdeviceptr       d_plain_bufs;
  CUdeviceptr       d_digests_buf;
  CUdeviceptr       d_digests_shown;
  CUdeviceptr       d_salt_bufs;
  CUdeviceptr       d_esalt_bufs;
  CUdeviceptr       d_bcrypt_bufs;
  CUdeviceptr       d_tmps;
  CUdeviceptr       d_hooks;
  CUdeviceptr       d_result;
  CUdeviceptr       d_scryptV_buf;
  CUdeviceptr       d_root_css_buf;
  CUdeviceptr       d_markov_css_buf;

  #elif _OCL

  char             *device_name;
  char             *device_version;
  char             *driver_version;

  cl_device_id      device;

  cl_kernel         kernel1;
  cl_kernel         kernel12;
  cl_kernel         kernel2;
  cl_kernel         kernel23;
  cl_kernel         kernel3;
  cl_kernel         kernel_mp;
  cl_kernel         kernel_mp_l;
  cl_kernel         kernel_mp_r;
  cl_kernel         kernel_amp;
  cl_kernel         kernel_tb;
  cl_kernel         kernel_tm;

  cl_context        context;

  cl_program        program;
  cl_program        program_mp;
  cl_program        program_amp;

  cl_command_queue  command_queue;

  cl_mem            d_pws_buf;
  cl_mem            d_pws_amp_buf;
  cl_mem            d_words_buf_l;
  cl_mem            d_words_buf_r;
  cl_mem            d_rules;
  cl_mem            d_rules_c;
  cl_mem            d_combs;
  cl_mem            d_combs_c;
  cl_mem            d_bfs;
  cl_mem            d_bfs_c;
  cl_mem            d_tm_c;
  cl_mem            d_bitmap_s1_a;
  cl_mem            d_bitmap_s1_b;
  cl_mem            d_bitmap_s1_c;
  cl_mem            d_bitmap_s1_d;
  cl_mem            d_bitmap_s2_a;
  cl_mem            d_bitmap_s2_b;
  cl_mem            d_bitmap_s2_c;
  cl_mem            d_bitmap_s2_d;
  cl_mem            d_plain_bufs;
  cl_mem            d_digests_buf;
  cl_mem            d_digests_shown;
  cl_mem            d_salt_bufs;
  cl_mem            d_esalt_bufs;
  cl_mem            d_bcrypt_bufs;
  cl_mem            d_tmps;
  cl_mem            d_hooks;
  cl_mem            d_result;
  cl_mem            d_scryptV_buf;
  cl_mem            d_root_css_buf;
  cl_mem            d_markov_css_buf;

  #endif

  #define PARAMCNT 32

  void             *kernel_params[PARAMCNT];
  void             *kernel_params_mp[PARAMCNT];
  void             *kernel_params_mp_r[PARAMCNT];
  void             *kernel_params_mp_l[PARAMCNT];
  void             *kernel_params_amp[PARAMCNT];
  void             *kernel_params_tb[PARAMCNT];
  void             *kernel_params_tm[PARAMCNT];

  uint32_t          kernel_params_buf32[PARAMCNT];

  uint32_t          kernel_params_mp_buf32[PARAMCNT];
  uint64_t          kernel_params_mp_buf64[PARAMCNT];

  uint32_t          kernel_params_mp_r_buf32[PARAMCNT];
  uint64_t          kernel_params_mp_r_buf64[PARAMCNT];

  uint32_t          kernel_params_mp_l_buf32[PARAMCNT];
  uint64_t          kernel_params_mp_l_buf64[PARAMCNT];

  uint32_t          kernel_params_amp_buf32[PARAMCNT];

};

typedef struct __hc_device_param hc_device_param_t;

typedef struct
{
  HM_ADAPTER adapter_index;

  #ifdef _OCL
  int od_version;
  #endif

  int fan_supported;

  // int busid; // used for CL_DEVICE_TOPOLOGY_AMD but broken for dual GPUs
  // int devid; // used for CL_DEVICE_TOPOLOGY_AMD but broken for dual GPUs

} hm_attrs_t;

typedef struct
{
  /**
   * threads
   */

  uint                devices_status;
  uint                devices_cnt;
  hc_device_param_t  *devices_param;

  uint                gpu_blocks_all;

  /**
   * attack specific
   */

  uint                wordlist_mode;
  uint                hashlist_mode;
  uint                hashlist_format;

  uint                attack_mode;
  uint                attack_kern;
  uint                attack_exec;

  uint                gpu_rules_cnt;
  gpu_rule_t         *gpu_rules_buf;

  uint                combs_mode;
  uint                combs_cnt;

  uint                bfs_cnt;

  uint                css_cnt;
  cs_t               *css_buf;

  cs_t               *root_css_buf;
  cs_t               *markov_css_buf;

  char               *rule_buf_l;
  char               *rule_buf_r;
  int                 rule_len_l;
  int                 rule_len_r;

  /**
   * hardware watchdog
   */

  HM_LIB              hm_dll;
  hm_attrs_t          hm_device[DEVICES_MAX];

  /**
   * hashes
   */

  uint                digests_cnt;
  uint                digests_done;
  uint                digests_saved;

  void               *digests_buf;
  uint               *digests_shown;
  uint               *digests_shown_tmp;

  uint                salts_cnt;
  uint                salts_done;

  salt_t             *salts_buf;
  uint               *salts_shown;

  void               *esalts_buf;

  /**
   * logging
   */

  uint    logfile_disable;
  char   *logfile;
  char   *topid;
  char   *subid;

  /**
   * crack-per-time
   */

  cpt_t  cpt_buf[CPT_BUF];
  int    cpt_pos;
  time_t cpt_start;
  uint64_t cpt_total;

  /**
   * user
   */

  char   *dictfile;
  char   *dictfile2;
  char   *mask;
  uint    maskcnt;
  uint    maskpos;
  char   *session;
  char    separator;
  char   *hashfile;
  char   *homedir;
  char   *install_dir;
  char   *profile_dir;
  char   *session_dir;
  char   *outfile;
  uint    outfile_format;
  uint    outfile_autohex;
  uint    outfile_check_timer;
  char   *eff_restore_file;
  char   *new_restore_file;
  char   *induction_directory;
  char   *outfile_check_directory;
  uint    loopback;
  char   *loopback_file;
  uint    restore;
  uint    restore_timer;
  uint    restore_disable;
  uint    status;
  uint    status_timer;
  uint    status_automat;
  uint    quiet;
  uint    force;
  uint    benchmark;
  uint    runtime;
  uint    remove;
  uint    remove_timer;
  uint    debug_mode;
  char   *debug_file;
  uint    hex_charset;
  uint    hex_salt;
  uint    hex_wordlist;
  uint    pw_min;
  uint    pw_max;
  float   gpu_blocks_div;
  uint    gpu_accel;
  uint    gpu_loops;
  uint    powertune_enable;
  uint    scrypt_tmto;
  uint    segment_size;
  char   *truecrypt_keyfiles;

  uint    hash_mode;
  uint    hash_type;
  uint    kern_type;
  uint    opts_type;
  uint    salt_type;
  uint    esalt_size;
  uint    isSalted;
  uint    dgst_size;
  uint    opti_type;
  uint    dgst_pos0;
  uint    dgst_pos1;
  uint    dgst_pos2;
  uint    dgst_pos3;

  uint    gpu_temp_disable;
  uint    gpu_temp_abort;
  uint    gpu_temp_retain;

  char  **rp_files;
  uint    rp_files_cnt;
  uint    rp_gen;
  uint    rp_gen_seed;

  FILE   *pot_fp;

  /**
   * used for restore
   */

  uint64_t skip;
  uint64_t limit;

  restore_data_t *rd;

  uint64_t checkpoint_cur_words;  // used for the "stop at next checkpoint" feature

  /**
   * status, timer
   */

  time_t     runtime_start;
  time_t     runtime_stop;

  time_t     proc_start;
  time_t     proc_stop;

  uint64_t   words_cnt;
  uint64_t   words_cur;
  uint64_t   words_base;

  uint64_t  *words_progress_done;      // progress number of words done     per salt
  uint64_t  *words_progress_rejected;  // progress number of words rejected per salt
  uint64_t  *words_progress_restored;  // progress number of words restored per salt

  hc_timer_t timer_running;         // timer on current dict
  hc_timer_t timer_paused;          // timer on current dict

  float      ms_paused;             // timer on current dict

  /**
    * hash_info and username
    */

  hashinfo_t **hash_info;
  uint         username;

  int (*sort_by_digest) (const void *, const void *);

  int (*parse_func)     (char *, uint, hash_t *);

} hc_global_data_t;

extern hc_global_data_t data;

#endif
