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
#include "m16801-pure.cl"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "WPA-PMKID-PMK";
static const u64   KERN_TYPE      = 16801;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_DEEP_COMP_KERNEL
                                  | OPTS_TYPE_POTFILE_NOPASS
                                  | OPTS_TYPE_COPY_TMPS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "5b13d4babb3714ccc62c9f71864bc984efd6a55f237c7a87fc2151e1ca658a9d";
static const char *ST_HASH        = "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4";

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

static const u32 ROUNDS_WPA_PMK = 1;

/*
typedef struct wpa_pmkid
{
  u32  pmkid[4];
  u32  pmkid_data[16];
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   essid_len;
  u32  essid_buf[16];

} wpa_pmkid_t;

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;
*/

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  return mask;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (wpa_pmk_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (wpa_pmkid_t);

  return esalt_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 64;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 64;

  return pw_max;
}

int module_hash_decode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len, MAYBE_UNUSED void *tmps)
{
  wpa_pmkid_t *wpa_pmkid = (wpa_pmkid_t *) esalt_buf;

  wpa_pmk_tmp_t *wpa_pmk_tmp = (wpa_pmk_tmp_t *) tmps;

  // here we have in line_hash_buf: PMK*essid:password
  // but we don't care about the password

  // PMK

  wpa_pmk_tmp->out[0] = hex_to_u32 ((const u8 *) line_buf +  0);
  wpa_pmk_tmp->out[1] = hex_to_u32 ((const u8 *) line_buf +  8);
  wpa_pmk_tmp->out[2] = hex_to_u32 ((const u8 *) line_buf + 16);
  wpa_pmk_tmp->out[3] = hex_to_u32 ((const u8 *) line_buf + 24);
  wpa_pmk_tmp->out[4] = hex_to_u32 ((const u8 *) line_buf + 32);
  wpa_pmk_tmp->out[5] = hex_to_u32 ((const u8 *) line_buf + 40);
  wpa_pmk_tmp->out[6] = hex_to_u32 ((const u8 *) line_buf + 48);
  wpa_pmk_tmp->out[7] = hex_to_u32 ((const u8 *) line_buf + 56);

  // essid

  char *sep_pos = strrchr (line_buf, ':');

  if (sep_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if ((line_buf + 64) != sep_pos) return (PARSER_HASH_LENGTH);

  char *essid_pos = sep_pos + 1;

  const int essid_len = strlen (essid_pos);

  if (essid_len & 1) return (PARSER_SALT_VALUE);

  if (essid_len > 64) return (PARSER_SALT_VALUE);

  wpa_pmkid->essid_len = hex_decode ((const u8 *) essid_pos, essid_len, (u8 *) wpa_pmkid->essid_buf);

  return PARSER_OK;
}

int module_hash_encode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size, MAYBE_UNUSED const void *tmps)
{
  const wpa_pmkid_t *wpa_pmkid = (const wpa_pmkid_t *) esalt_buf;

  const wpa_pmk_tmp_t *wpa_pmk_tmp = (const wpa_pmk_tmp_t *) tmps;

  char tmp_buf[128];

  const int tmp_len = hex_encode ((const u8 *) wpa_pmkid->essid_buf, wpa_pmkid->essid_len, (u8 *) tmp_buf);

  tmp_buf[tmp_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
    wpa_pmk_tmp->out[0],
    wpa_pmk_tmp->out[1],
    wpa_pmk_tmp->out[2],
    wpa_pmk_tmp->out[3],
    wpa_pmk_tmp->out[4],
    wpa_pmk_tmp->out[5],
    wpa_pmk_tmp->out[6],
    wpa_pmk_tmp->out[7],
    tmp_buf);

  return line_len;
}

int module_hash_binary_save (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos, char **buf)
{
  const salt_t *salts_buf   = hashes->salts_buf;
  const void   *esalts_buf  = hashes->esalts_buf;

  const salt_t *salt = &salts_buf[salt_pos];

  const u32 digest_cur = salt->digests_offset + digest_pos;

  const wpa_pmkid_t *wpa_pmkids = (const wpa_pmkid_t *) esalts_buf;
  const wpa_pmkid_t *wpa_pmkid  = &wpa_pmkids[digest_cur];

  int len = 0;

  if (wpa_pmkid->essid_len)
  {
    char tmp_buf[128];

    const int tmp_len = hex_encode ((const u8 *) wpa_pmkid->essid_buf, wpa_pmkid->essid_len, (u8 *) tmp_buf);

    tmp_buf[tmp_len] = 0;

    len = hc_asprintf (buf, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s" EOL,
      byte_swap_32 (wpa_pmkid->pmkid[0]),
      byte_swap_32 (wpa_pmkid->pmkid[1]),
      byte_swap_32 (wpa_pmkid->pmkid[2]),
      byte_swap_32 (wpa_pmkid->pmkid[3]),
      wpa_pmkid->orig_mac_ap[0],
      wpa_pmkid->orig_mac_ap[1],
      wpa_pmkid->orig_mac_ap[2],
      wpa_pmkid->orig_mac_ap[3],
      wpa_pmkid->orig_mac_ap[4],
      wpa_pmkid->orig_mac_ap[5],
      wpa_pmkid->orig_mac_sta[0],
      wpa_pmkid->orig_mac_sta[1],
      wpa_pmkid->orig_mac_sta[2],
      wpa_pmkid->orig_mac_sta[3],
      wpa_pmkid->orig_mac_sta[4],
      wpa_pmkid->orig_mac_sta[5],
      tmp_buf);
  }
  else
  {
    len = hc_asprintf (buf, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x" EOL,
      byte_swap_32 (wpa_pmkid->pmkid[0]),
      byte_swap_32 (wpa_pmkid->pmkid[1]),
      byte_swap_32 (wpa_pmkid->pmkid[2]),
      byte_swap_32 (wpa_pmkid->pmkid[3]),
      wpa_pmkid->orig_mac_ap[0],
      wpa_pmkid->orig_mac_ap[1],
      wpa_pmkid->orig_mac_ap[2],
      wpa_pmkid->orig_mac_ap[3],
      wpa_pmkid->orig_mac_ap[4],
      wpa_pmkid->orig_mac_ap[5],
      wpa_pmkid->orig_mac_sta[0],
      wpa_pmkid->orig_mac_sta[1],
      wpa_pmkid->orig_mac_sta[2],
      wpa_pmkid->orig_mac_sta[3],
      wpa_pmkid->orig_mac_sta[4],
      wpa_pmkid->orig_mac_sta[5]);
  }

  return len;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1;
}

bool module_potfile_custom_check (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hash_t *db, MAYBE_UNUSED const hash_t *entry_hash, MAYBE_UNUSED const void *entry_tmps)
{
  const wpa_pmkid_t *wpa_pmkid_entry = (const wpa_pmkid_t *) entry_hash->esalt;
  const wpa_pmkid_t *wpa_pmkid_db    = (const wpa_pmkid_t *) db->esalt;

  if (wpa_pmkid_db->essid_len != wpa_pmkid_entry->essid_len) return false;

  if (strcmp ((const char *) wpa_pmkid_db->essid_buf, (const char *) wpa_pmkid_entry->essid_buf)) return false;

  const wpa_pmk_tmp_t *wpa_pmk_tmp = (const wpa_pmk_tmp_t *) entry_tmps;

  wpa_pmk_tmp_t tmps;

  tmps.out[0] = byte_swap_32 (wpa_pmk_tmp->out[0]);
  tmps.out[1] = byte_swap_32 (wpa_pmk_tmp->out[1]);
  tmps.out[2] = byte_swap_32 (wpa_pmk_tmp->out[2]);
  tmps.out[3] = byte_swap_32 (wpa_pmk_tmp->out[3]);
  tmps.out[4] = byte_swap_32 (wpa_pmk_tmp->out[4]);
  tmps.out[5] = byte_swap_32 (wpa_pmk_tmp->out[5]);
  tmps.out[6] = byte_swap_32 (wpa_pmk_tmp->out[6]);
  tmps.out[7] = byte_swap_32 (wpa_pmk_tmp->out[7]);

  plain_t plains_buf;

  u32 hashes_shown = 0;

  u32 d_return_buf = 0;

  void (*m16801_aux) (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));

  m16801_aux = m16801_aux1;

  m16801_aux
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

  wpa_pmkid_t *wpa_pmkid = (wpa_pmkid_t *) esalt_buf;

  // detect old/new format

  int old_sep = 0;
  int new_sep = 0;

  for (int i = 0; i < line_len; i++)
  {
    const char c = line_buf[i];

    if (c == '*') old_sep++;
    if (c == ':') new_sep++;
  }

  const u8 sep = (new_sep > old_sep) ? ':' : '*';

  // start normal parsing

  token_t token;

  // real 16801 pmkid hash-lines

  token.token_cnt  = 3;

  token.sep[0]     = sep;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = sep;
  token.len_min[1] = 12;
  token.len_max[1] = 12;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = sep;
  token.len_min[2] = 12;
  token.len_max[2] = 12;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
  {
    // we'll accept normal 16800 pmkid hash-lines, too

    token.token_cnt  = 4;

    token.sep[0]     = sep;
    token.len_min[0] = 32;
    token.len_max[0] = 32;
    token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[1]     = sep;
    token.len_min[1] = 12;
    token.len_max[1] = 12;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[2]     = sep;
    token.len_min[2] = 12;
    token.len_max[2] = 12;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[3]     = sep;
    token.len_min[3] = 0;
    token.len_max[3] = 64;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer2 = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer2 != PARSER_OK) return (rc_tokenizer);

    // essid

    const u8 *essid_buf = token.buf[3];
    const int essid_len = token.len[3];

    if (essid_len & 1) return (PARSER_SALT_VALUE);

    wpa_pmkid->essid_len = hex_decode (essid_buf, essid_len, (u8 *) wpa_pmkid->essid_buf);
  }

  // pmkid

  const u8 *pmkid_buf = token.buf[0];

  wpa_pmkid->pmkid[0] = hex_to_u32 (pmkid_buf +  0);
  wpa_pmkid->pmkid[1] = hex_to_u32 (pmkid_buf +  8);
  wpa_pmkid->pmkid[2] = hex_to_u32 (pmkid_buf + 16);
  wpa_pmkid->pmkid[3] = hex_to_u32 (pmkid_buf + 24);

  // mac_ap

  const u8 *macap_buf = token.buf[1];

  wpa_pmkid->orig_mac_ap[0] = hex_to_u8 (macap_buf +  0);
  wpa_pmkid->orig_mac_ap[1] = hex_to_u8 (macap_buf +  2);
  wpa_pmkid->orig_mac_ap[2] = hex_to_u8 (macap_buf +  4);
  wpa_pmkid->orig_mac_ap[3] = hex_to_u8 (macap_buf +  6);
  wpa_pmkid->orig_mac_ap[4] = hex_to_u8 (macap_buf +  8);
  wpa_pmkid->orig_mac_ap[5] = hex_to_u8 (macap_buf + 10);

  // mac_sta

  const u8 *macsta_buf = token.buf[2];

  wpa_pmkid->orig_mac_sta[0] = hex_to_u8 (macsta_buf +  0);
  wpa_pmkid->orig_mac_sta[1] = hex_to_u8 (macsta_buf +  2);
  wpa_pmkid->orig_mac_sta[2] = hex_to_u8 (macsta_buf +  4);
  wpa_pmkid->orig_mac_sta[3] = hex_to_u8 (macsta_buf +  6);
  wpa_pmkid->orig_mac_sta[4] = hex_to_u8 (macsta_buf +  8);
  wpa_pmkid->orig_mac_sta[5] = hex_to_u8 (macsta_buf + 10);

  // pmkid_data

  wpa_pmkid->pmkid_data[0] = 0x204b4d50; // "PMK "
  wpa_pmkid->pmkid_data[1] = 0x656d614e; // "Name"
  wpa_pmkid->pmkid_data[2] = (wpa_pmkid->orig_mac_ap[0]  <<  0)
                           | (wpa_pmkid->orig_mac_ap[1]  <<  8)
                           | (wpa_pmkid->orig_mac_ap[2]  << 16)
                           | (wpa_pmkid->orig_mac_ap[3]  << 24);
  wpa_pmkid->pmkid_data[3] = (wpa_pmkid->orig_mac_ap[4]  <<  0)
                           | (wpa_pmkid->orig_mac_ap[5]  <<  8)
                           | (wpa_pmkid->orig_mac_sta[0] << 16)
                           | (wpa_pmkid->orig_mac_sta[1] << 24);
  wpa_pmkid->pmkid_data[4] = (wpa_pmkid->orig_mac_sta[2] <<  0)
                           | (wpa_pmkid->orig_mac_sta[3] <<  8)
                           | (wpa_pmkid->orig_mac_sta[4] << 16)
                           | (wpa_pmkid->orig_mac_sta[5] << 24);

  // salt

  salt->salt_buf[0] = wpa_pmkid->pmkid_data[0];
  salt->salt_buf[1] = wpa_pmkid->pmkid_data[1];
  salt->salt_buf[2] = wpa_pmkid->pmkid_data[2];
  salt->salt_buf[3] = wpa_pmkid->pmkid_data[3];
  salt->salt_buf[4] = wpa_pmkid->pmkid_data[4];
  salt->salt_buf[5] = wpa_pmkid->pmkid_data[5];
  salt->salt_buf[6] = wpa_pmkid->pmkid_data[6];
  salt->salt_buf[7] = wpa_pmkid->pmkid_data[7];

  salt->salt_len  = 32;
  salt->salt_iter = ROUNDS_WPA_PMK - 1;

  // hash

  digest[0] = wpa_pmkid->pmkid[0];
  digest[1] = wpa_pmkid->pmkid[1];
  digest[2] = wpa_pmkid->pmkid[2];
  digest[3] = wpa_pmkid->pmkid[3];

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wpa_pmkid_t *wpa_pmkid = (const wpa_pmkid_t *) esalt_buf;

  int line_len = 0;

  if (wpa_pmkid->essid_len)
  {
    if (need_hexify ((const u8 *) wpa_pmkid->essid_buf, wpa_pmkid->essid_len, ':', 0) == true)
    {
      char tmp_buf[128];

      int tmp_len = 0;

      tmp_buf[tmp_len++] = '$';
      tmp_buf[tmp_len++] = 'H';
      tmp_buf[tmp_len++] = 'E';
      tmp_buf[tmp_len++] = 'X';
      tmp_buf[tmp_len++] = '[';

      exec_hexify ((const u8 *) wpa_pmkid->essid_buf, wpa_pmkid->essid_len, (u8 *) tmp_buf + tmp_len);

      tmp_len += wpa_pmkid->essid_len * 2;

      tmp_buf[tmp_len++] = ']';

      tmp_buf[tmp_len++] = 0;

      line_len = snprintf (line_buf, line_size, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
        wpa_pmkid->orig_mac_ap[0],
        wpa_pmkid->orig_mac_ap[1],
        wpa_pmkid->orig_mac_ap[2],
        wpa_pmkid->orig_mac_ap[3],
        wpa_pmkid->orig_mac_ap[4],
        wpa_pmkid->orig_mac_ap[5],
        wpa_pmkid->orig_mac_sta[0],
        wpa_pmkid->orig_mac_sta[1],
        wpa_pmkid->orig_mac_sta[2],
        wpa_pmkid->orig_mac_sta[3],
        wpa_pmkid->orig_mac_sta[4],
        wpa_pmkid->orig_mac_sta[5],
        tmp_buf);
    }
    else
    {
      line_len = snprintf (line_buf, line_size, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
        wpa_pmkid->orig_mac_ap[0],
        wpa_pmkid->orig_mac_ap[1],
        wpa_pmkid->orig_mac_ap[2],
        wpa_pmkid->orig_mac_ap[3],
        wpa_pmkid->orig_mac_ap[4],
        wpa_pmkid->orig_mac_ap[5],
        wpa_pmkid->orig_mac_sta[0],
        wpa_pmkid->orig_mac_sta[1],
        wpa_pmkid->orig_mac_sta[2],
        wpa_pmkid->orig_mac_sta[3],
        wpa_pmkid->orig_mac_sta[4],
        wpa_pmkid->orig_mac_sta[5],
        (const char *) wpa_pmkid->essid_buf);
    }
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x",
      wpa_pmkid->orig_mac_ap[0],
      wpa_pmkid->orig_mac_ap[1],
      wpa_pmkid->orig_mac_ap[2],
      wpa_pmkid->orig_mac_ap[3],
      wpa_pmkid->orig_mac_ap[4],
      wpa_pmkid->orig_mac_ap[5],
      wpa_pmkid->orig_mac_sta[0],
      wpa_pmkid->orig_mac_sta[1],
      wpa_pmkid->orig_mac_sta[2],
      wpa_pmkid->orig_mac_sta[3],
      wpa_pmkid->orig_mac_sta[4],
      wpa_pmkid->orig_mac_sta[5]);
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
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = module_hash_binary_save;
  module_ctx->module_hash_decode_potfile      = module_hash_decode_potfile;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = module_hash_encode_potfile;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
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
