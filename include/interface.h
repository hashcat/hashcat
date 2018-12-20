/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

static const u32 MODULE_VERSION_MINIMUM = 520;

/**
 * zero hashes shutcut
 */

static const char LM_ZERO_HASH[]    = "aad3b435b51404ee";
static const char LM_MASKED_PLAIN[] = "[notfound]";

/**
 * migrate stuff
 */

typedef struct keyboard_layout_mapping
{
  u32 src_char;
  int src_len;
  u32 dst_char;
  int dst_len;

} keyboard_layout_mapping_t;

typedef struct tc
{
  u32 salt_buf[32];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

} tc_t;

typedef struct wpa_eapol
{
  u32  pke[32];
  u32  eapol[64 + 16];
  u16  eapol_len;
  u8   message_pair;
  int  message_pair_chgd;
  u8   keyver;
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   orig_nonce_ap[32];
  u8   orig_nonce_sta[32];
  u8   essid_len;
  u8   essid[32];
  u32  keymic[4];
  u32  hash[4];
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

static const u32 ROUNDS_WPA_PBKDF2         = 4096;

#define HCCAPX_VERSION   4
#define HCCAPX_SIGNATURE 0x58504348 // HCPX

// this is required to force mingw to accept the packed attribute
#pragma pack(push,1)

struct hccapx
{
  u32 signature;
  u32 version;
  u8  message_pair;
  u8  essid_len;
  u8  essid[32];
  u8  keyver;
  u8  keymic[16];
  u8  mac_ap[6];
  u8  nonce_ap[32];
  u8  mac_sta[6];
  u8  nonce_sta[32];
  u16 eapol_len;
  u8  eapol[256];

} __attribute__((packed));

typedef struct hccapx hccapx_t;

#pragma pack(pop)

void to_hccapx_t (hashcat_ctx_t *hashcat_ctx, hccapx_t *hccapx, const u32 salt_pos, const u32 digest_pos);


typedef struct seven_zip_hook
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

typedef struct seven_zip_hook_salt
{
  u32 iv_buf[4];
  u32 iv_len;

  u32 salt_buf[4];
  u32 salt_len;

  u32 crc;
  u32 crc_len;

  u8  data_type;

  u32 data_buf[81882];
  u32 data_len;

  u32 unpack_size;

  char coder_attributes[5 + 1];
  u8   coder_attributes_len;

  int aes_len; // pre-computed length of the maximal (subset of) data we need for AES-CBC

} seven_zip_hook_salt_t;

int check_old_hccap (const char *hashfile);


int luks_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig, const int keyslot_idx);

static const u32   KERN_TYPE_TOTP_HMACSHA1           = 18100;

static const u32     KERN_TYPE_LUKS_SHA1_AES           = 14611;
static const u32     KERN_TYPE_LUKS_SHA1_SERPENT       = 14612;
static const u32     KERN_TYPE_LUKS_SHA1_TWOFISH       = 14613;
static const u32     KERN_TYPE_LUKS_SHA256_AES         = 14621;
static const u32     KERN_TYPE_LUKS_SHA256_SERPENT     = 14622;
static const u32     KERN_TYPE_LUKS_SHA256_TWOFISH     = 14623;
static const u32     KERN_TYPE_LUKS_SHA512_AES         = 14631;
static const u32     KERN_TYPE_LUKS_SHA512_SERPENT     = 14632;
static const u32     KERN_TYPE_LUKS_SHA512_TWOFISH     = 14633;
static const u32     KERN_TYPE_LUKS_RIPEMD160_AES      = 14641;
static const u32     KERN_TYPE_LUKS_RIPEMD160_SERPENT  = 14642;
static const u32     KERN_TYPE_LUKS_RIPEMD160_TWOFISH  = 14643;
static const u32     KERN_TYPE_LUKS_WHIRLPOOL_AES      = 14651;
static const u32     KERN_TYPE_LUKS_WHIRLPOOL_SERPENT  = 14652;
static const u32     KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH  = 14653;

// original headers from luks.h

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20 // since SHA1
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
// Minimal number of iterations
#define LUKS_MKD_ITERATIONS_MIN  1000
#define LUKS_SLOT_ITERATIONS_MIN 1000
#define LUKS_KEY_DISABLED_OLD 0
#define LUKS_KEY_ENABLED_OLD 0xCAFE
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED  0x00AC71F3
#define LUKS_STRIPES 4000
// partition header starts with magic
#define LUKS_MAGIC {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6
/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L 40
/* Offset to keyslot area [in bytes] */
#define LUKS_ALIGN_KEYSLOTS 4096

struct luks_phdr {
  char      magic[LUKS_MAGIC_L];
  uint16_t  version;
  char      cipherName[LUKS_CIPHERNAME_L];
  char      cipherMode[LUKS_CIPHERMODE_L];
  char      hashSpec[LUKS_HASHSPEC_L];
  uint32_t  payloadOffset;
  uint32_t  keyBytes;
  char      mkDigest[LUKS_DIGESTSIZE];
  char      mkDigestSalt[LUKS_SALTSIZE];
  uint32_t  mkDigestIterations;
  char      uuid[UUID_STRING_L];
  struct {
    uint32_t active;
    /* parameters used for password processing */
    uint32_t passwordIterations;
    char     passwordSalt[LUKS_SALTSIZE];
    /* parameters used for AF store/load */
    uint32_t keyMaterialOffset;
    uint32_t stripes;
  } keyblock[LUKS_NUMKEYS];
  /* Align it to 512 sector size */
  char       _padding[432];
};

// not from original headers start with hc_

typedef enum hc_luks_hash_type
{
  HC_LUKS_HASH_TYPE_SHA1      = 1,
  HC_LUKS_HASH_TYPE_SHA256    = 2,
  HC_LUKS_HASH_TYPE_SHA512    = 3,
  HC_LUKS_HASH_TYPE_RIPEMD160 = 4,
  HC_LUKS_HASH_TYPE_WHIRLPOOL = 5,

} hc_luks_hash_type_t;

typedef enum hc_luks_key_size
{
  HC_LUKS_KEY_SIZE_128 = 128,
  HC_LUKS_KEY_SIZE_256 = 256,
  HC_LUKS_KEY_SIZE_512 = 512,

} hc_luks_key_size_t;

typedef enum hc_luks_cipher_type
{
  HC_LUKS_CIPHER_TYPE_AES     = 1,
  HC_LUKS_CIPHER_TYPE_SERPENT = 2,
  HC_LUKS_CIPHER_TYPE_TWOFISH = 3,

} hc_luks_cipher_type_t;

typedef enum hc_luks_cipher_mode
{
  HC_LUKS_CIPHER_MODE_CBC_ESSIV = 1,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN = 2,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN = 3,

} hc_luks_cipher_mode_t;

typedef struct luks
{
  int hash_type;    // hc_luks_hash_type_t
  int key_size;     // hc_luks_key_size_t
  int cipher_type;  // hc_luks_cipher_type_t
  int cipher_mode;  // hc_luks_cipher_mode_t

  u32 ct_buf[128];

  u32 af_src_buf[((HC_LUKS_KEY_SIZE_512 / 8) * LUKS_STRIPES) / 4];

} luks_t;


/**
 * output functions
 */

const char *stroptitype (const u32 opti_type);

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos);

bool initialize_keyboard_layout_mapping (hashcat_ctx_t *hashcat_ctx, const char *filename, keyboard_layout_mapping_t *keyboard_layout_mapping, int *keyboard_layout_mapping_cnt);

int         hashconfig_init                   (hashcat_ctx_t *hashcat_ctx);
void        hashconfig_destroy                (hashcat_ctx_t *hashcat_ctx);
int         hashconfig_general_defaults       (hashcat_ctx_t *hashcat_ctx);
void        hashconfig_benchmark_defaults     (hashcat_ctx_t *hashcat_ctx, salt_t *salt, void *esalt, void *hook_salt);

u32         default_attack_exec           (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
void       *default_benchmark_esalt       (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
void       *default_benchmark_hook_salt   (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
const char *default_benchmark_mask        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
salt_t     *default_benchmark_salt        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
bool        default_dictstat_disable      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_dgst_pos0             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_dgst_pos1             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_dgst_pos2             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_dgst_pos3             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_dgst_size             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_esalt_size            (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_forced_kernel_threads (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_forced_kernel_loops   (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_forced_outfile_format (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
const char *default_hash_name             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_hash_mode             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_hash_type             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
bool        default_hlfmt_disable         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_hook_salt_size        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_hook_size             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_kern_type             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_opti_type             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_opts_type             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
bool        default_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
bool        default_outfile_check_nocomp  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_pwdump_column         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_pw_min                (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_pw_max                (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_salt_min              (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_salt_max              (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         default_salt_type             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
char        default_separator             (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
const char *default_st_hash               (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
const char *default_st_pass               (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u64         default_tmp_size              (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
bool        default_warmup_disable        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);

#endif // _INTERFACE_H
