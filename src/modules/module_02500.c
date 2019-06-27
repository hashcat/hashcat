/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

#define DGST_ELEM 4

#include "emu_general.h"
#include "emu_inc_cipher_aes.h"
#include "emu_inc_hash_md5.h"
#include "m02500-pure.cl"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "WPA-EAPOL-PBKDF2";
static const u64   KERN_TYPE      = 2500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_AUX2
                                  | OPTS_TYPE_AUX3
                                  | OPTS_TYPE_BINARY_HASHFILE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL
                                  | OPTS_TYPE_COPY_TMPS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat!";
static const char *ST_HASH        = "4843505804000000000235380000000000000000000000000000000000000000000000000000000000000151aecc428f182acefbd1a9e62d369a079265784da83ba4cf88375c44c830e6e5aa5d6faf352aa496a9ee129fb8292f7435df5420b823a1cd402aed449cced04f552c5b5acfebf06ae96a09c96d9a01c443a17aa62258c4f651a68aa67b0001030077fe010900200000000000000001a4cf88375c44c830e6e5aa5d6faf352aa496a9ee129fb8292f7435df5420b8230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018dd160050f20101000050f20201000050f20201000050f20200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const u32 ROUNDS_WPA_PBKDF2 = 4096;

/*
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
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_pbkdf2_tmp_t;
*/

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

static void to_hccapx_t (const hashes_t *hashes, hccapx_t *hccapx, const u32 salt_pos, const u32 digest_pos)
{
  const salt_t *salts_buf   = hashes->salts_buf;
  const void   *esalts_buf  = hashes->esalts_buf;

  memset (hccapx, 0, sizeof (hccapx_t));

  hccapx->signature = HCCAPX_SIGNATURE;
  hccapx->version   = HCCAPX_VERSION;

  const salt_t *salt = &salts_buf[salt_pos];

  const u32 digest_cur = salt->digests_offset + digest_pos;

  hccapx->essid_len = salt->salt_len;

  memcpy (hccapx->essid, salt->salt_buf, hccapx->essid_len);

  wpa_eapol_t *wpa_eapols = (wpa_eapol_t *) esalts_buf;
  wpa_eapol_t *wpa_eapol  = &wpa_eapols[digest_cur];

  hccapx->message_pair = wpa_eapol->message_pair;
  hccapx->keyver = wpa_eapol->keyver;

  hccapx->eapol_len = wpa_eapol->eapol_len;

  if (wpa_eapol->keyver != 1)
  {
    u32 eapol_tmp[64] = { 0 };

    for (u32 i = 0; i < 64; i++)
    {
      eapol_tmp[i] = byte_swap_32 (wpa_eapol->eapol[i]);
    }

    memcpy (hccapx->eapol, eapol_tmp, wpa_eapol->eapol_len);
  }
  else
  {
    memcpy (hccapx->eapol, wpa_eapol->eapol, wpa_eapol->eapol_len);
  }

  memcpy (hccapx->mac_ap,    wpa_eapol->orig_mac_ap,    6);
  memcpy (hccapx->mac_sta,   wpa_eapol->orig_mac_sta,   6);
  memcpy (hccapx->nonce_ap,  wpa_eapol->orig_nonce_ap,  32);
  memcpy (hccapx->nonce_sta, wpa_eapol->orig_nonce_sta, 32);

  if (wpa_eapol->keyver != 1)
  {
    u32 digest_tmp[4];

    digest_tmp[0] = byte_swap_32 (wpa_eapol->keymic[0]);
    digest_tmp[1] = byte_swap_32 (wpa_eapol->keymic[1]);
    digest_tmp[2] = byte_swap_32 (wpa_eapol->keymic[2]);
    digest_tmp[3] = byte_swap_32 (wpa_eapol->keymic[3]);

    memcpy (hccapx->keymic, digest_tmp, 16);
  }
  else
  {
    memcpy (hccapx->keymic, wpa_eapol->keymic, 16);
  }
}

/*
static int check_old_hccap (const char *hashfile)
{
  FILE *fp = fopen (hashfile, "rb");

  if (fp == NULL) return -1;

  u32 signature;

  const size_t nread = hc_fread (&signature, sizeof (u32), 1, fp);

  fclose (fp);

  if (nread != 1) return -1;

  if (signature == HCCAPX_SIGNATURE) return 0;

  return 1;
}
*/

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?a";

  return mask;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (wpa_pbkdf2_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (wpa_eapol_t);

  return esalt_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 63;

  return pw_max;
}

int module_hash_decode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len, MAYBE_UNUSED void *tmps)
{
  wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) esalt_buf;

  wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (wpa_pbkdf2_tmp_t *) tmps;

  // here we have in line_hash_buf: PMK*essid:password
  // but we don't care about the password

  // PMK

  wpa_pbkdf2_tmp->out[0] = hex_to_u32 ((const u8 *) line_buf +  0);
  wpa_pbkdf2_tmp->out[1] = hex_to_u32 ((const u8 *) line_buf +  8);
  wpa_pbkdf2_tmp->out[2] = hex_to_u32 ((const u8 *) line_buf + 16);
  wpa_pbkdf2_tmp->out[3] = hex_to_u32 ((const u8 *) line_buf + 24);
  wpa_pbkdf2_tmp->out[4] = hex_to_u32 ((const u8 *) line_buf + 32);
  wpa_pbkdf2_tmp->out[5] = hex_to_u32 ((const u8 *) line_buf + 40);
  wpa_pbkdf2_tmp->out[6] = hex_to_u32 ((const u8 *) line_buf + 48);
  wpa_pbkdf2_tmp->out[7] = hex_to_u32 ((const u8 *) line_buf + 56);

  // essid

  char *sep_pos = strrchr (line_buf, ':');

  if (sep_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if ((line_buf + 64) != sep_pos) return (PARSER_HASH_LENGTH);

  char *essid_pos = sep_pos + 1;

  const int essid_len = strlen (essid_pos);

  if (essid_len & 1) return (PARSER_SALT_VALUE);

  if (essid_len > 64) return (PARSER_SALT_VALUE);

  wpa_eapol->essid_len = hex_decode ((const u8 *) essid_pos, essid_len, (u8 *) wpa_eapol->essid);

  return PARSER_OK;
}

int module_hash_encode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size, MAYBE_UNUSED const void *tmps)
{
  const wpa_eapol_t *wpa_eapol = (const wpa_eapol_t *) esalt_buf;

  const wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (const wpa_pbkdf2_tmp_t *) tmps;

  char tmp_buf[128];

  const int tmp_len = hex_encode ((const u8 *) wpa_eapol->essid, wpa_eapol->essid_len, (u8 *) tmp_buf);

  tmp_buf[tmp_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
    wpa_pbkdf2_tmp->out[0],
    wpa_pbkdf2_tmp->out[1],
    wpa_pbkdf2_tmp->out[2],
    wpa_pbkdf2_tmp->out[3],
    wpa_pbkdf2_tmp->out[4],
    wpa_pbkdf2_tmp->out[5],
    wpa_pbkdf2_tmp->out[6],
    wpa_pbkdf2_tmp->out[7],
    tmp_buf);

  return line_len;
}

int module_hash_encode_status (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s (AP:%02x:%02x:%02x:%02x:%02x:%02x STA:%02x:%02x:%02x:%02x:%02x:%02x)",
    (char *) salt->salt_buf,
    wpa_eapol->orig_mac_ap[0],
    wpa_eapol->orig_mac_ap[1],
    wpa_eapol->orig_mac_ap[2],
    wpa_eapol->orig_mac_ap[3],
    wpa_eapol->orig_mac_ap[4],
    wpa_eapol->orig_mac_ap[5],
    wpa_eapol->orig_mac_sta[0],
    wpa_eapol->orig_mac_sta[1],
    wpa_eapol->orig_mac_sta[2],
    wpa_eapol->orig_mac_sta[3],
    wpa_eapol->orig_mac_sta[4],
    wpa_eapol->orig_mac_sta[5]);

  return line_len;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  const size_t st_hash_len = strlen (hashconfig->st_hash);

  char *tmpdata = (char *) hcmalloc (st_hash_len / 2);

  for (size_t i = 0, j = 0; j < st_hash_len; i += 1, j += 2)
  {
    const u8 c = hex_to_u8 ((const u8 *) hashconfig->st_hash + j);

    tmpdata[i] = c;
  }

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, tmpdata, st_hash_len / 2);

  wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) hash->esalt;

  wpa_eapol->detected_le = 1;
  wpa_eapol->detected_be = 0;

  wpa_eapol->nonce_error_corrections = 3;

  hcfree (tmpdata);

  return parser_status;
}

int module_hash_binary_save (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos, char **buf)
{
  hccapx_t *hccapx = hcmalloc (sizeof (hccapx_t));

  to_hccapx_t (hashes, hccapx, salt_pos, digest_pos);

  *buf = (char *) hccapx;

  return sizeof (hccapx_t);
}

int module_hash_binary_parse (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, hashes_t *hashes)
{
  //  hashes->hashlist_mode = HL_MODE_FILE; ???

  hash_t *hashes_buf = hashes->hashes_buf;

  int hashes_cnt = 0;

  HCFILE fp;

  if (hc_fopen (&fp, hashes->hashfile, "rb") == false) return -1;

  char *in = (char *) hcmalloc (sizeof (hccapx_t));

  while (!hc_feof (&fp))
  {
    const size_t nread = hc_fread (in, sizeof (hccapx_t), 1, &fp);

    if (nread == 0) break;

    memset (hashes_buf[hashes_cnt].salt, 0, sizeof (salt_t));

    memset (hashes_buf[hashes_cnt].esalt, 0, sizeof (wpa_eapol_t));

    wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) hashes_buf[hashes_cnt].esalt;

    if (user_options->hccapx_message_pair_chgd == true)
    {
      wpa_eapol->message_pair_chgd = (int) user_options->hccapx_message_pair_chgd;
      wpa_eapol->message_pair      = (u8)  user_options->hccapx_message_pair;
    }

    if (wpa_eapol->message_pair & (1 << 4))
    {
      // ap-less attack detected, nc not needed

      wpa_eapol->nonce_error_corrections = 0;
    }
    else
    {
      if (wpa_eapol->message_pair & (1 << 7))
      {
        // replaycount not checked, nc needed

        wpa_eapol->nonce_error_corrections = user_options->nonce_error_corrections;
      }
      else
      {
        // replaycount checked, nc not needed, but we allow user overwrites

        if (user_options->nonce_error_corrections_chgd == true)
        {
          wpa_eapol->nonce_error_corrections = user_options->nonce_error_corrections;
        }
        else
        {
          wpa_eapol->nonce_error_corrections = 0;
        }
      }
    }

    // now some optimization related to replay counter endianess
    // hcxtools has techniques to detect them
    // since we can not guarantee to get our handshakes from hcxtools we enable both by default
    // this means that we check both even if both are not set!
    // however if one of them is set, we can assume that the endianess has been checked and the other one is not needed

    wpa_eapol->detected_le = 1;
    wpa_eapol->detected_be = 1;

    if (wpa_eapol->message_pair & (1 << 5))
    {
      wpa_eapol->detected_le = 1;
      wpa_eapol->detected_be = 0;
    }
    else if (wpa_eapol->message_pair & (1 << 6))
    {
      wpa_eapol->detected_le = 0;
      wpa_eapol->detected_be = 1;
    }

    hash_t *hash = &hashes_buf[hashes_cnt];

    const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, in, sizeof (hccapx_t));

    if (parser_status != PARSER_OK) continue;

    hashes_cnt++;
  }

  hcfree (in);

  hc_fclose (&fp);

  return hashes_cnt;
}

int module_hash_binary_count (MAYBE_UNUSED const hashes_t *hashes)
{
  struct stat st;

  if (stat (hashes->hashfile, &st) == -1) return -1;

  return st.st_size / sizeof (hccapx_t);
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

  wpa_eapol_t *wpa_eapols = (wpa_eapol_t *) hashes->esalts_buf;

  wpa_eapol_t *wpa_eapol = &wpa_eapols[digests_offset + digest_pos];

  if (wpa_eapol->keyver == 1)
  {
    return KERN_RUN_AUX1;
  }
  else if (wpa_eapol->keyver == 2)
  {
    return KERN_RUN_AUX2;
  }
  else if (wpa_eapol->keyver == 3)
  {
    return KERN_RUN_AUX3;
  }

  return 0;
}

bool module_potfile_custom_check (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hash_t *db, MAYBE_UNUSED const hash_t *entry_hash, MAYBE_UNUSED const void *entry_tmps)
{
  const wpa_eapol_t *wpa_eapol_entry = (const wpa_eapol_t *) entry_hash->esalt;
  const wpa_eapol_t *wpa_eapol_db    = (const wpa_eapol_t *) db->esalt;

  if (wpa_eapol_db->essid_len != wpa_eapol_entry->essid_len) return false;

  if (strcmp ((const char *) wpa_eapol_db->essid, (const char *) wpa_eapol_entry->essid)) return false;

  const wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (const wpa_pbkdf2_tmp_t *) entry_tmps;

  wpa_pbkdf2_tmp_t tmps;

  tmps.out[0] = byte_swap_32 (wpa_pbkdf2_tmp->out[0]);
  tmps.out[1] = byte_swap_32 (wpa_pbkdf2_tmp->out[1]);
  tmps.out[2] = byte_swap_32 (wpa_pbkdf2_tmp->out[2]);
  tmps.out[3] = byte_swap_32 (wpa_pbkdf2_tmp->out[3]);
  tmps.out[4] = byte_swap_32 (wpa_pbkdf2_tmp->out[4]);
  tmps.out[5] = byte_swap_32 (wpa_pbkdf2_tmp->out[5]);
  tmps.out[6] = byte_swap_32 (wpa_pbkdf2_tmp->out[6]);
  tmps.out[7] = byte_swap_32 (wpa_pbkdf2_tmp->out[7]);

  plain_t plains_buf;

  u32 hashes_shown = 0;

  u32 d_return_buf = 0;

  void (*m02500_aux) (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t));

  if (wpa_eapol_db->keyver == 1)
  {
    m02500_aux = m02500_aux1;
  }
  else if (wpa_eapol_db->keyver == 2)
  {
    m02500_aux = m02500_aux2;
  }
  else if (wpa_eapol_db->keyver == 3)
  {
    m02500_aux = m02500_aux3;
  }
  else
  {
    return false;
  }

  m02500_aux
  (
    NULL,               // pws
    NULL,               // rules_buf
    NULL,               // combs_buf
    NULL,               // bfs_buf
    &tmps,              // tmps
    NULL,               // hooks
    NULL,               // bitmaps_buf_s1_a
    NULL,               // bitmaps_buf_s1_b
    NULL,               // bitmaps_buf_s1_c
    NULL,               // bitmaps_buf_s1_d
    NULL,               // bitmaps_buf_s2_a
    NULL,               // bitmaps_buf_s2_b
    NULL,               // bitmaps_buf_s2_c
    NULL,               // bitmaps_buf_s2_d
    &plains_buf,        // plains_buf
    db->digest,         // digests_buf
    &hashes_shown,      // hashes_shown
    db->salt,           // salt_bufs
    db->esalt,          // esalt_bufs
    &d_return_buf,      // d_return_buf
    NULL,               // d_extra0_buf
    NULL,               // d_extra1_buf
    NULL,               // d_extra2_buf
    NULL,               // d_extra3_buf
    0,                  // bitmap_mask
    0,                  // bitmap_shift1
    0,                  // bitmap_shift2
    0,                  // salt_pos
    0,                  // loop_pos
    0,                  // loop_cnt
    0,                  // il_cnt
    1,                  // digests_cnt
    0,                  // digests_offset
    0,                  // combs_mode
    1                   // gid_max
  );

  const bool r = (d_return_buf == 0) ? false : true;

  return r;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) esalt_buf;

  // the *wpa was partially initialized beforehand, we can not simply memset it to zero

  hccapx_t in;

  memcpy (&in, line_buf, sizeof (hccapx_t));

  if (in.signature != HCCAPX_SIGNATURE) return (PARSER_HCCAPX_SIGNATURE);

  if (in.version != HCCAPX_VERSION) return (PARSER_HCCAPX_VERSION);

  if (in.eapol_len < 1 || in.eapol_len > 255) return (PARSER_HCCAPX_EAPOL_LEN);

  memcpy (wpa_eapol->keymic, in.keymic, 16);

  /*
    http://www.one-net.eu/jsw/j_sec/m_ptype.html
    The phrase "Pairwise key expansion"
    Access Point Address (referred to as Authenticator Address AA)
    Supplicant Address (referred to as Supplicant Address SA)
    Access Point Nonce (referred to as Authenticator Anonce)
    Wireless Device Nonce (referred to as Supplicant Nonce Snonce)
  */

  u32 salt_len = in.essid_len;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, in.essid, in.essid_len);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_WPA_PBKDF2 - 1;

  memcpy (wpa_eapol->essid, in.essid, in.essid_len);

  wpa_eapol->essid_len = in.essid_len;

  wpa_eapol->keyver = in.keyver;

  if ((wpa_eapol->keyver != 1) && (wpa_eapol->keyver != 2) && (wpa_eapol->keyver != 3)) return (PARSER_SALT_VALUE);

  u8 *pke_ptr = (u8 *) wpa_eapol->pke;

  memset (pke_ptr, 0, 128);

  if ((wpa_eapol->keyver == 1) || (wpa_eapol->keyver == 2))
  {
    memcpy (pke_ptr, "Pairwise key expansion", 23);

    if (memcmp (in.mac_ap, in.mac_sta, 6) < 0)
    {
      memcpy (pke_ptr + 23, in.mac_ap,  6);
      memcpy (pke_ptr + 29, in.mac_sta, 6);
    }
    else
    {
      memcpy (pke_ptr + 23, in.mac_sta, 6);
      memcpy (pke_ptr + 29, in.mac_ap,  6);
    }

    wpa_eapol->nonce_compare = memcmp (in.nonce_ap, in.nonce_sta, 32);

    if (wpa_eapol->nonce_compare < 0)
    {
      memcpy (pke_ptr + 35, in.nonce_ap,  32);
      memcpy (pke_ptr + 67, in.nonce_sta, 32);
    }
    else
    {
      memcpy (pke_ptr + 35, in.nonce_sta, 32);
      memcpy (pke_ptr + 67, in.nonce_ap,  32);
    }
  }
  else if (wpa_eapol->keyver == 3)
  {
    pke_ptr[0] = 1;
    pke_ptr[1] = 0;

    memcpy (pke_ptr + 2, "Pairwise key expansion", 22);

    if (memcmp (in.mac_ap, in.mac_sta, 6) < 0)
    {
      memcpy (pke_ptr + 24, in.mac_ap,  6);
      memcpy (pke_ptr + 30, in.mac_sta, 6);
    }
    else
    {
      memcpy (pke_ptr + 24, in.mac_sta, 6);
      memcpy (pke_ptr + 30, in.mac_ap,  6);
    }

    wpa_eapol->nonce_compare = memcmp (in.nonce_ap, in.nonce_sta, 32);

    if (wpa_eapol->nonce_compare < 0)
    {
      memcpy (pke_ptr + 36, in.nonce_ap,  32);
      memcpy (pke_ptr + 68, in.nonce_sta, 32);
    }
    else
    {
      memcpy (pke_ptr + 36, in.nonce_sta, 32);
      memcpy (pke_ptr + 68, in.nonce_ap,  32);
    }

    pke_ptr[100] = 0x80;
    pke_ptr[101] = 1;
  }

  for (int i = 0; i < 32; i++)
  {
    wpa_eapol->pke[i] = byte_swap_32 (wpa_eapol->pke[i]);
  }

  memcpy (wpa_eapol->orig_mac_ap,    in.mac_ap,    6);
  memcpy (wpa_eapol->orig_mac_sta,   in.mac_sta,   6);
  memcpy (wpa_eapol->orig_nonce_ap,  in.nonce_ap,  32);
  memcpy (wpa_eapol->orig_nonce_sta, in.nonce_sta, 32);

  u8 message_pair_orig = in.message_pair;

  in.message_pair &= 0x7f; // ignore the highest bit (it is used to indicate if the replay counters did match)

  if (wpa_eapol->message_pair_chgd == true)
  {
    if (wpa_eapol->message_pair != in.message_pair) return (PARSER_HCCAPX_MESSAGE_PAIR);
  }

  wpa_eapol->message_pair = message_pair_orig;

  wpa_eapol->eapol_len = in.eapol_len;

  u8 *eapol_ptr = (u8 *) wpa_eapol->eapol;

  memcpy (eapol_ptr, in.eapol, wpa_eapol->eapol_len);

  memset (eapol_ptr + wpa_eapol->eapol_len, 0, (256 + 64) - wpa_eapol->eapol_len);

  eapol_ptr[wpa_eapol->eapol_len] = 0x80;

  if (wpa_eapol->keyver == 1)
  {
    // nothing to do
  }
  else if (wpa_eapol->keyver == 2)
  {
    wpa_eapol->keymic[0] = byte_swap_32 (wpa_eapol->keymic[0]);
    wpa_eapol->keymic[1] = byte_swap_32 (wpa_eapol->keymic[1]);
    wpa_eapol->keymic[2] = byte_swap_32 (wpa_eapol->keymic[2]);
    wpa_eapol->keymic[3] = byte_swap_32 (wpa_eapol->keymic[3]);

    for (int i = 0; i < 64; i++)
    {
      wpa_eapol->eapol[i] = byte_swap_32 (wpa_eapol->eapol[i]);
    }
  }
  else if (wpa_eapol->keyver == 3)
  {
    // nothing to do
  }

  // Create a hash of the nonce as ESSID is not unique enough
  // Not a regular MD5 but good enough
  // We can also ignore cases where we should bzero the work buffer

  u32 hash[4];

  hash[0] = 0;
  hash[1] = 1;
  hash[2] = 2;
  hash[3] = 3;

  u32 block[16];

  memset (block, 0, sizeof (block));

  u8 *block_ptr = (u8 *) block;

  for (int i = 0; i < 16; i++) block[i] = salt->salt_buf[i];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->pke[i +  0];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->pke[i + 16];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->eapol[i +  0];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->eapol[i + 16];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->eapol[i + 32];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa_eapol->eapol[i + 48];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i <  6; i++) block_ptr[i + 0] = wpa_eapol->orig_mac_ap[i];
  for (int i = 0; i <  6; i++) block_ptr[i + 6] = wpa_eapol->orig_mac_sta[i];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 32; i++) block_ptr[i +  0] = wpa_eapol->orig_nonce_ap[i];
  for (int i = 0; i < 32; i++) block_ptr[i + 32] = wpa_eapol->orig_nonce_sta[i];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  block[0] = wpa_eapol->keymic[0];
  block[1] = wpa_eapol->keymic[1];
  block[2] = wpa_eapol->keymic[2];
  block[3] = wpa_eapol->keymic[3];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  // make all this stuff unique

  digest[0] = hash[0];
  digest[1] = hash[1];
  digest[2] = hash[2];
  digest[3] = hash[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wpa_eapol_t *wpa_eapol = (const wpa_eapol_t *) esalt_buf;

  int line_len = 0;

  if (need_hexify (wpa_eapol->essid, wpa_eapol->essid_len, ':', 0) == true)
  {
    char tmp_buf[128];

    int tmp_len = 0;

    tmp_buf[tmp_len++] = '$';
    tmp_buf[tmp_len++] = 'H';
    tmp_buf[tmp_len++] = 'E';
    tmp_buf[tmp_len++] = 'X';
    tmp_buf[tmp_len++] = '[';

    exec_hexify (wpa_eapol->essid, wpa_eapol->essid_len, (u8 *) tmp_buf + tmp_len);

    tmp_len += wpa_eapol->essid_len * 2;

    tmp_buf[tmp_len++] = ']';

    tmp_buf[tmp_len++] = 0;

    line_len = snprintf (line_buf, line_size, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
      wpa_eapol->orig_mac_ap[0],
      wpa_eapol->orig_mac_ap[1],
      wpa_eapol->orig_mac_ap[2],
      wpa_eapol->orig_mac_ap[3],
      wpa_eapol->orig_mac_ap[4],
      wpa_eapol->orig_mac_ap[5],
      wpa_eapol->orig_mac_sta[0],
      wpa_eapol->orig_mac_sta[1],
      wpa_eapol->orig_mac_sta[2],
      wpa_eapol->orig_mac_sta[3],
      wpa_eapol->orig_mac_sta[4],
      wpa_eapol->orig_mac_sta[5],
      tmp_buf);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
      wpa_eapol->orig_mac_ap[0],
      wpa_eapol->orig_mac_ap[1],
      wpa_eapol->orig_mac_ap[2],
      wpa_eapol->orig_mac_ap[3],
      wpa_eapol->orig_mac_ap[4],
      wpa_eapol->orig_mac_ap[5],
      wpa_eapol->orig_mac_sta[0],
      wpa_eapol->orig_mac_sta[1],
      wpa_eapol->orig_mac_sta[2],
      wpa_eapol->orig_mac_sta[3],
      wpa_eapol->orig_mac_sta[4],
      wpa_eapol->orig_mac_sta[5],
      wpa_eapol->essid);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = module_hash_binary_count;
  module_ctx->module_hash_binary_parse        = module_hash_binary_parse;
  module_ctx->module_hash_binary_save         = module_hash_binary_save;
  module_ctx->module_hash_decode_potfile      = module_hash_decode_potfile;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = module_hash_encode_status;
  module_ctx->module_hash_encode_potfile      = module_hash_encode_potfile;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = module_hash_init_selftest;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = module_potfile_custom_check;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
