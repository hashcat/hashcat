/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef TYPES_H
#define TYPES_H

#ifdef _WIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

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
  uint iv[4];

} rar5_t;

typedef struct
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  uint id_buf[8];
  uint u_buf[32];
  uint o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  uint rc4key[2];
  uint rc4data[2];

} pdf_t;

typedef struct
{
  uint pke[25];
  uint eapol[64];
  int  eapol_size;
  int  keyver;
  u8   orig_mac1[6];
  u8   orig_mac2[6];
  u8   orig_nonce1[32];
  u8   orig_nonce2[32];

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
  uint account_info[512];
  uint checksum[4];
  uint edata2[2560];
  uint edata2_len;

} krb5tgs_t;

typedef struct
{
  u32 version;
  u32 algorithm;

  /* key-file handling */
  u32 keyfile_len;
  u32 keyfile[8];

  u32 final_random_seed[8];
  u32 transf_random_seed[8];
  u32 enc_iv[4];
  u32 contents_hash[8];

  /* specific to version 1 */
  u32 contents_len;
  u32 contents[75000];

  /* specific to version 2 */
  u32 expected_bytes[8];

} keepass_t;

typedef struct
{
  uint salt_buf[16];
  uint data_buf[112];
  uint keyfile_buf[16];
  uint signature;

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
  u8   cipher[1040];

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
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

typedef struct
{
  u32 type;
  u32 mode;
  u32 magic;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 compress_length;
  u32 data_len;
  u32 data_buf[2048];
  u32 auth_len;
  u32 auth_buf[4];

} zip2_t;

typedef struct
{
  uint salt_buf[32];

} win8phone_t;

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
  } d;

  uint dgst_len;
  uint W_len;

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
  u64  l_alt_result[8];

  u64  l_p_bytes[2];
  u64  l_s_bytes[2];

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
  u64  dgst[8];

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
  uint E[18];

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
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

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
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

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
  u64  digest_buf[8];

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
  u64  out[8];

} office2013_tmp_t;

typedef struct
{
  uint digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  u64  out[8];

} ecryptfs_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

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
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct
{
  u32  random[2];
  u32  hash[5];
  u32  salt[5];   // unused, but makes better valid check
  u32  iv[2];     // unused, but makes better valid check

} psafe2_hdr;

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
  uint key;
  u64  val;

} hcstat_table_t;

typedef struct
{
  uint cs_buf[0x100];
  uint cs_len;

} cs_t;

typedef struct
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

typedef struct
{
  char signature[4];
  u32  salt_buf[8];
  u32  iterations;
  u32  hash_buf[8];

} psafe3_t;

typedef struct
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct
{
  u64    cnt;

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
  uint cmds[0x100];

} kernel_rule_t;

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
  u32  version_bin;
  char cwd[256];
  u32  pid;

  u32  dictpos;
  u32  maskpos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

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

typedef struct
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct
{
  char *device_name;
  int   attack_mode;
  int   hash_type;
  int   workload_profile;
  int   vector_width;
  int   kernel_accel;
  int   kernel_loops;

} tuning_db_entry_t;

typedef struct
{
  tuning_db_alias_t *alias_buf;
  int                alias_cnt;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;

} tuning_db_t;

#define RULES_MAX   256
#define PW_MIN      0
#define PW_MAX      54
#define PW_MAX1     (PW_MAX + 1)
#define PW_DICTMAX  31
#define PW_DICTMAX1 (PW_DICTMAX + 1)
#define PARAMCNT    64

struct __hc_device_param
{
  cl_device_id      device;
  cl_device_type    device_type;

  uint    device_id;
  uint    platform_devices_id;   // for mapping with hms devices

  bool    skipped;

  uint    sm_major;
  uint    sm_minor;
  uint    kernel_exec_timeout;

  uint    device_processors;
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;

  uint    vector_width;

  uint    kernel_threads;
  uint    kernel_loops;
  uint    kernel_accel;
  uint    kernel_loops_min;
  uint    kernel_loops_max;
  uint    kernel_accel_min;
  uint    kernel_accel_max;
  uint    kernel_power;
  uint    hardware_power;

  size_t  size_pws;
  size_t  size_tmps;
  size_t  size_hooks;
  size_t  size_bfs;
  size_t  size_combs;
  size_t  size_rules;
  size_t  size_rules_c;
  size_t  size_root_css;
  size_t  size_markov_css;
  size_t  size_digests;
  size_t  size_salts;
  size_t  size_shown;
  size_t  size_results;
  size_t  size_plains;

  FILE   *combs_fp;
  comb_t *combs_buf;

  void   *hooks_buf;

  pw_t   *pws_buf;
  uint    pws_cnt;

  u64     words_off;
  u64     words_done;

  uint    outerloop_pos;
  uint    outerloop_left;

  uint    innerloop_pos;
  uint    innerloop_left;

  uint    exec_pos;
  double  exec_ms[EXEC_CACHE];

  // workaround cpu spinning

  double  exec_us_prev1[EXPECTED_ITERATIONS];
  double  exec_us_prev2[EXPECTED_ITERATIONS];
  double  exec_us_prev3[EXPECTED_ITERATIONS];

  // this is "current" speed

  uint    speed_pos;
  u64     speed_cnt[SPEED_CACHE];
  double  speed_ms[SPEED_CACHE];

  hc_timer_t timer_speed;

  // device specific attributes starting

  char   *device_name;
  char   *device_vendor;
  char   *device_name_chksum;
  char   *device_version;
  char   *driver_version;

  bool    opencl_v12;

  double  nvidia_spin_damp;

  cl_uint device_vendor_id;
  cl_uint platform_vendor_id;

  cl_kernel  kernel1;
  cl_kernel  kernel12;
  cl_kernel  kernel2;
  cl_kernel  kernel23;
  cl_kernel  kernel3;
  cl_kernel  kernel_mp;
  cl_kernel  kernel_mp_l;
  cl_kernel  kernel_mp_r;
  cl_kernel  kernel_amp;
  cl_kernel  kernel_tm;
  cl_kernel  kernel_weak;
  cl_kernel  kernel_memset;

  cl_context context;

  cl_program program;
  cl_program program_mp;
  cl_program program_amp;

  cl_command_queue command_queue;

  cl_mem  d_pws_buf;
  cl_mem  d_pws_amp_buf;
  cl_mem  d_words_buf_l;
  cl_mem  d_words_buf_r;
  cl_mem  d_rules;
  cl_mem  d_rules_c;
  cl_mem  d_combs;
  cl_mem  d_combs_c;
  cl_mem  d_bfs;
  cl_mem  d_bfs_c;
  cl_mem  d_tm_c;
  cl_mem  d_bitmap_s1_a;
  cl_mem  d_bitmap_s1_b;
  cl_mem  d_bitmap_s1_c;
  cl_mem  d_bitmap_s1_d;
  cl_mem  d_bitmap_s2_a;
  cl_mem  d_bitmap_s2_b;
  cl_mem  d_bitmap_s2_c;
  cl_mem  d_bitmap_s2_d;
  cl_mem  d_plain_bufs;
  cl_mem  d_digests_buf;
  cl_mem  d_digests_shown;
  cl_mem  d_salt_bufs;
  cl_mem  d_esalt_bufs;
  cl_mem  d_bcrypt_bufs;
  cl_mem  d_tmps;
  cl_mem  d_hooks;
  cl_mem  d_result;
  cl_mem  d_scryptV0_buf;
  cl_mem  d_scryptV1_buf;
  cl_mem  d_scryptV2_buf;
  cl_mem  d_scryptV3_buf;
  cl_mem  d_root_css_buf;
  cl_mem  d_markov_css_buf;

  void   *kernel_params[PARAMCNT];
  void   *kernel_params_mp[PARAMCNT];
  void   *kernel_params_mp_r[PARAMCNT];
  void   *kernel_params_mp_l[PARAMCNT];
  void   *kernel_params_amp[PARAMCNT];
  void   *kernel_params_tm[PARAMCNT];
  void   *kernel_params_memset[PARAMCNT];

  u32     kernel_params_buf32[PARAMCNT];

  u32     kernel_params_mp_buf32[PARAMCNT];
  u64     kernel_params_mp_buf64[PARAMCNT];

  u32     kernel_params_mp_r_buf32[PARAMCNT];
  u64     kernel_params_mp_r_buf64[PARAMCNT];

  u32     kernel_params_mp_l_buf32[PARAMCNT];
  u64     kernel_params_mp_l_buf64[PARAMCNT];

  u32     kernel_params_amp_buf32[PARAMCNT];
  u32     kernel_params_memset_buf32[PARAMCNT];
};

typedef struct __hc_device_param hc_device_param_t;

#ifdef HAVE_HWMON
typedef struct
{
  HM_ADAPTER_ADL     adl;
  HM_ADAPTER_NVML    nvml;
  HM_ADAPTER_NVAPI   nvapi;
  HM_ADAPTER_XNVCTRL xnvctrl;

  int od_version;

  int fan_get_supported;
  int fan_set_supported;

} hm_attrs_t;
#endif // HAVE_HWMON

typedef struct
{
  /**
   * threads
   */

  uint    devices_status;
  uint    devices_cnt;
  uint    devices_active;

  hc_device_param_t *devices_param;

  uint    shutdown_inner;
  uint    shutdown_outer;

  /**
   * workload specific
   */

  uint    hardware_power_all;
  uint    kernel_power_all;
  u64     kernel_power_final; // we save that so that all divisions are done from the same base

  /**
   * attack specific
   */

  uint    wordlist_mode;
  uint    hashlist_mode;
  uint    hashlist_format;

  uint    attack_mode;
  uint    attack_kern;
  uint    attack_exec;

  uint    kernel_rules_cnt;

  kernel_rule_t *kernel_rules_buf;

  uint    combs_mode;
  uint    combs_cnt;

  uint    bfs_cnt;

  uint    css_cnt;
  cs_t   *css_buf;

  cs_t   *root_css_buf;
  cs_t   *markov_css_buf;

  char   *rule_buf_l;
  char   *rule_buf_r;
  int     rule_len_l;
  int     rule_len_r;

  /**
   * opencl library stuff
   */

  void   *ocl;

  /**
   * hardware watchdog
   */

  #ifdef HAVE_HWMON
  void      *hm_adl;
  void      *hm_nvml;
  void      *hm_nvapi;
  void      *hm_xnvctrl;
  hm_attrs_t hm_device[DEVICES_MAX];
  #endif

  /**
   * hashes
   */

  uint    digests_cnt;
  uint    digests_done;
  uint    digests_saved;

  void   *digests_buf;
  uint   *digests_shown;
  uint   *digests_shown_tmp;

  uint    salts_cnt;
  uint    salts_done;

  salt_t *salts_buf;
  uint   *salts_shown;

  void   *esalts_buf;

  uint    scrypt_tmp_size;
  uint    scrypt_tmto_final;

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

  cpt_t   cpt_buf[CPT_BUF];
  int     cpt_pos;
  time_t  cpt_start;
  u64     cpt_total;

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
  char   *shared_dir;
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
  uint    machine_readable;
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
  uint    powertune_enable;
  uint    scrypt_tmto;
  uint    segment_size;
  char   *truecrypt_keyfiles;
  char   *veracrypt_keyfiles;
  uint    veracrypt_pim;
  uint    workload_profile;

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

  #ifdef HAVE_HWMON
  uint    gpu_temp_disable;
  uint    gpu_temp_abort;
  uint    gpu_temp_retain;
  #endif

  char  **rp_files;
  uint    rp_files_cnt;
  uint    rp_gen;
  uint    rp_gen_seed;

  FILE   *pot_fp;

  /**
   * used for restore
   */

  u64     skip;
  u64     limit;

  restore_data_t *rd;

  u64     checkpoint_cur_words;     // used for the "stop at next checkpoint" feature

  /**
   * status, timer
   */

  time_t  runtime_start;
  time_t  runtime_stop;

  time_t  proc_start;
  time_t  proc_stop;

  u64     words_cnt;
  u64     words_cur;
  u64     words_base;

  u64    *words_progress_done;      // progress number of words done     per salt
  u64    *words_progress_rejected;  // progress number of words rejected per salt
  u64    *words_progress_restored;  // progress number of words restored per salt

  hc_timer_t timer_running;         // timer on current dict
  hc_timer_t timer_paused;          // timer on current dict

  double  ms_paused;                // timer on current dict

  /**
    * hash_info and username
    */

  hashinfo_t **hash_info;
  uint    username;

  int (*sort_by_digest) (const void *, const void *);

  int (*parse_func)     (char *, uint, hash_t *);

} hc_global_data_t;

extern hc_global_data_t data;

#endif

