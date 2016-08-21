#include <shared.h>
#include <parse_hash.h>
#include <converter.h>
#include <cpu/cpu-des.h>
#include <cpu/cpu-md5.h>
#include <cpu/cpu-sha1.h>
#include <cpu/cpu-sha256.h>
#include <consts/hash_options.h>
#include <consts/parser.h>
#include <decoder.h>
#include <bit_ops.h>
#include <consts/display_lengths.h>
#include <consts/signatures.h>
#include <consts/rounds_count.h>
#include <inc_hash_constants.h>
#include <logging.h>
#include <hc_global_data_t.h>
#include <hc_global.h>

/**
* parser
*/

uint parse_and_store_salt(char *out, char *in, uint salt_len)
{
  u8 tmp[256] = { 0 };

  if (salt_len + ((data.opts_type & OPTS_TYPE_ST_ADD80) !=0 ) + ((data.opts_type & OPTS_TYPE_ST_ADD01) != 0) > sizeof(tmp))
  {
    return UINT_MAX;
  }

  memcpy(tmp, in, salt_len);

  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((salt_len % 2) == 0)
    {
      u32 new_salt_len = salt_len / 2;

      for (uint i = 0, j = 0; i < new_salt_len; i += 1, j += 2)
      {
        u8 p0 = tmp[j + 0];
        u8 p1 = tmp[j + 1];

        tmp[i] = hex_convert(p1) << 0;
        tmp[i] |= hex_convert(p0) << 4;
      }

      salt_len = new_salt_len;
    }
    else
    {
      return UINT_MAX;
    }
  }
  else if (data.opts_type & OPTS_TYPE_ST_BASE64)
  {
    salt_len = base64_decode(base64_to_int, (const u8 *)in, salt_len, (u8 *)tmp);
  }

  memset(tmp + salt_len, 0, sizeof(tmp) - salt_len);

  if (data.opts_type & OPTS_TYPE_ST_UNICODE)
  {
    if (salt_len < 20)
    {
      u32 *tmp_uint = (u32 *)tmp;

      tmp_uint[9] = ((tmp_uint[4] >> 8) & 0x00FF0000) | ((tmp_uint[4] >> 16) & 0x000000FF);
      tmp_uint[8] = ((tmp_uint[4] << 8) & 0x00FF0000) | ((tmp_uint[4] >> 0) & 0x000000FF);
      tmp_uint[7] = ((tmp_uint[3] >> 8) & 0x00FF0000) | ((tmp_uint[3] >> 16) & 0x000000FF);
      tmp_uint[6] = ((tmp_uint[3] << 8) & 0x00FF0000) | ((tmp_uint[3] >> 0) & 0x000000FF);
      tmp_uint[5] = ((tmp_uint[2] >> 8) & 0x00FF0000) | ((tmp_uint[2] >> 16) & 0x000000FF);
      tmp_uint[4] = ((tmp_uint[2] << 8) & 0x00FF0000) | ((tmp_uint[2] >> 0) & 0x000000FF);
      tmp_uint[3] = ((tmp_uint[1] >> 8) & 0x00FF0000) | ((tmp_uint[1] >> 16) & 0x000000FF);
      tmp_uint[2] = ((tmp_uint[1] << 8) & 0x00FF0000) | ((tmp_uint[1] >> 0) & 0x000000FF);
      tmp_uint[1] = ((tmp_uint[0] >> 8) & 0x00FF0000) | ((tmp_uint[0] >> 16) & 0x000000FF);
      tmp_uint[0] = ((tmp_uint[0] << 8) & 0x00FF0000) | ((tmp_uint[0] >> 0) & 0x000000FF);

      salt_len = salt_len * 2;
    }
    else
    {
      return UINT_MAX;
    }
  }

  if (data.opts_type & OPTS_TYPE_ST_LOWER)
  {
    lowercase(tmp, salt_len);
  }

  if (data.opts_type & OPTS_TYPE_ST_UPPER)
  {
    uppercase(tmp, salt_len);
  }

  u32 len = salt_len;

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    tmp[len++] = 0x80;
  }

  if (data.opts_type & OPTS_TYPE_ST_ADD01)
  {
    tmp[len++] = 0x01;
  }

  if (data.opts_type & OPTS_TYPE_ST_GENERATE_LE)
  {
    u32 *tmp_uint = (uint *)tmp;

    u32 max = len / 4;

    if (len % 4) max++;

    for (u32 i = 0; i < max; i++)
    {
      tmp_uint[i] = byte_swap_32(tmp_uint[i]);
    }

    // Important: we may need to increase the length of memcpy since
    // we don't want to "loose" some swapped bytes (could happen if
    // they do not perfectly fit in the 4-byte blocks)
    // Memcpy does always copy the bytes in the BE order, but since
    // we swapped them, some important bytes could be in positions
    // we normally skip with the original len

    if (len % 4) len += 4 - (len % 4);
  }

  memcpy(out, tmp, len);

  return (salt_len);
}

int bcrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3200) || (input_len > DISPLAY_LEN_MAX_3200)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_BCRYPT1, input_buf, 4)) && (memcmp(SIGNATURE_BCRYPT2, input_buf, 4)) && (memcmp(SIGNATURE_BCRYPT3, input_buf, 4))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  memcpy((char *)salt->salt_sign, input_buf, 6);

  char *iter_pos = input_buf + 4;

  salt->salt_iter = 1u << atoi(iter_pos);

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  uint salt_len = 16;

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode(bf64_to_int, (const u8 *)salt_pos, 22, tmp_buf);

  char *salt_buf_ptr = (char *)salt->salt_buf;

  memcpy(salt_buf_ptr, tmp_buf, 16);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  char *hash_pos = salt_pos + 22;

  memset(tmp_buf, 0, sizeof(tmp_buf));

  base64_decode(bf64_to_int, (const u8 *)hash_pos, 31, tmp_buf);

  memcpy(digest, tmp_buf, 24);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);

  digest[5] &= ~0xff; // its just 23 not 24 !

  return (PARSER_OK);
}

int cisco4_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5700) || (input_len > DISPLAY_LEN_MAX_5700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode(itoa64_to_int, (const u8 *)input_buf, 43, tmp_buf);

  memcpy(digest, tmp_buf, 32);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int lm_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3000) || (input_len > DISPLAY_LEN_MAX_3000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  uint tt;

  IP(&digest[0], &digest[1], &tt);

  digest[0] = digest[0];
  digest[1] = digest[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int arubaos_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_125) || (input_len > DISPLAY_LEN_MAX_125)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[8] != '0') || (input_buf[9] != '1')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 10;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  uint salt_len = 10;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_122) || (input_len > DISPLAY_LEN_MAX_122)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 8;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx512_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1722) || (input_len > DISPLAY_LEN_MAX_1722)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 8;

  digest[0] = hex_to_u64((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u64((const u8 *)&hash_pos[16]);
  digest[2] = hex_to_u64((const u8 *)&hash_pos[32]);
  digest[3] = hex_to_u64((const u8 *)&hash_pos[48]);
  digest[4] = hex_to_u64((const u8 *)&hash_pos[64]);
  digest[5] = hex_to_u64((const u8 *)&hash_pos[80]);
  digest[6] = hex_to_u64((const u8 *)&hash_pos[96]);
  digest[7] = hex_to_u64((const u8 *)&hash_pos[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osc_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_21H) || (input_len > DISPLAY_LEN_MAX_21H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_21) || (input_len > DISPLAY_LEN_MAX_21)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int netscreen_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_22H) || (input_len > DISPLAY_LEN_MAX_22H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_22) || (input_len > DISPLAY_LEN_MAX_22)) return (PARSER_GLOBAL_LENGTH);
  }

  // unscramble

  char clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = { 0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != input_buf[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = input_buf[i];

      k++;
    }
  }

  // base64 decode

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u32 a, b, c, d, e, f;

  a = base64_to_int(clean_input_buf[0] & 0x7f);
  b = base64_to_int(clean_input_buf[1] & 0x7f);
  c = base64_to_int(clean_input_buf[2] & 0x7f);
  d = base64_to_int(clean_input_buf[3] & 0x7f);
  e = base64_to_int(clean_input_buf[4] & 0x7f);
  f = base64_to_int(clean_input_buf[5] & 0x7f);

  digest[0] = (((a << 12) | (b << 6) | (c)) << 16)
    | (((d << 12) | (e << 6) | (f)) << 0);

  a = base64_to_int(clean_input_buf[6] & 0x7f);
  b = base64_to_int(clean_input_buf[7] & 0x7f);
  c = base64_to_int(clean_input_buf[8] & 0x7f);
  d = base64_to_int(clean_input_buf[9] & 0x7f);
  e = base64_to_int(clean_input_buf[10] & 0x7f);
  f = base64_to_int(clean_input_buf[11] & 0x7f);

  digest[1] = (((a << 12) | (b << 6) | (c)) << 16)
    | (((d << 12) | (e << 6) | (f)) << 0);

  a = base64_to_int(clean_input_buf[12] & 0x7f);
  b = base64_to_int(clean_input_buf[13] & 0x7f);
  c = base64_to_int(clean_input_buf[14] & 0x7f);
  d = base64_to_int(clean_input_buf[15] & 0x7f);
  e = base64_to_int(clean_input_buf[16] & 0x7f);
  f = base64_to_int(clean_input_buf[17] & 0x7f);

  digest[2] = (((a << 12) | (b << 6) | (c)) << 16)
    | (((d << 12) | (e << 6) | (f)) << 0);

  a = base64_to_int(clean_input_buf[18] & 0x7f);
  b = base64_to_int(clean_input_buf[19] & 0x7f);
  c = base64_to_int(clean_input_buf[20] & 0x7f);
  d = base64_to_int(clean_input_buf[21] & 0x7f);
  e = base64_to_int(clean_input_buf[22] & 0x7f);
  f = base64_to_int(clean_input_buf[23] & 0x7f);

  digest[3] = (((a << 12) | (b << 6) | (c)) << 16)
    | (((d << 12) | (e << 6) | (f)) << 0);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[30] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 30 - 1;

  char *salt_buf = input_buf + 30 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32
  // 32 - 4 bytes (to fit w0lr for all attack modes) = 28

  if (salt_len > 28) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy(salt_buf_ptr + salt_len, ":Administration Tools:", 22);

  salt->salt_len += 22;

  return (PARSER_OK);
}

int smf_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_121H) || (input_len > DISPLAY_LEN_MAX_121H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_121) || (input_len > DISPLAY_LEN_MAX_121)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2100H) || (input_len > DISPLAY_LEN_MAX_2100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2100) || (input_len > DISPLAY_LEN_MAX_2100)) return (PARSER_GLOBAL_LENGTH);
  }

  if (memcmp(SIGNATURE_DCC2, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  char *iter_pos = input_buf + 6;

  salt_t *salt = hash_buf->salt;

  uint iter = atoi(iter_pos);

  if (iter < 1)
  {
    iter = ROUNDS_DCC2;
  }

  salt->salt_iter = iter - 1;

  char *salt_pos = strchr(iter_pos, '#');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *digest_pos = strchr(salt_pos, '#');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  digest_pos++;

  uint salt_len = digest_pos - salt_pos - 1;

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&digest_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&digest_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&digest_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&digest_pos[24]);

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int wpa_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  wpa_t *wpa = (wpa_t *)hash_buf->esalt;

  hccap_t in;

  memcpy(&in, input_buf, input_len);

  if (in.eapol_size < 1 || in.eapol_size > 255) return (PARSER_HCCAP_EAPOL_SIZE);

  memcpy(digest, in.keymic, 16);

  /*
  http://www.one-net.eu/jsw/j_sec/m_ptype.html
  The phrase "Pairwise key expansion"
  Access Point Address (referred to as Authenticator Address AA)
  Supplicant Address (referred to as Supplicant Address SA)
  Access Point Nonce (referred to as Authenticator Anonce)
  Wireless Device Nonce (referred to as Supplicant Nonce Snonce)
  */

  uint salt_len = strlen(in.essid);

  if (salt_len > 36)
  {
    log_info("WARNING: The ESSID length is too long, the hccap file may be invalid or corrupted");

    return (PARSER_SALT_LENGTH);
  }

  memcpy(salt->salt_buf, in.essid, salt_len);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_WPA2 - 1;

  unsigned char *pke_ptr = (unsigned char *)wpa->pke;

  memcpy(pke_ptr, "Pairwise key expansion", 23);

  if (memcmp(in.mac1, in.mac2, 6) < 0)
  {
    memcpy(pke_ptr + 23, in.mac1, 6);
    memcpy(pke_ptr + 29, in.mac2, 6);
  }
  else
  {
    memcpy(pke_ptr + 23, in.mac2, 6);
    memcpy(pke_ptr + 29, in.mac1, 6);
  }

  if (memcmp(in.nonce1, in.nonce2, 32) < 0)
  {
    memcpy(pke_ptr + 35, in.nonce1, 32);
    memcpy(pke_ptr + 67, in.nonce2, 32);
  }
  else
  {
    memcpy(pke_ptr + 35, in.nonce2, 32);
    memcpy(pke_ptr + 67, in.nonce1, 32);
  }

  for (int i = 0; i < 25; i++)
  {
    wpa->pke[i] = byte_swap_32(wpa->pke[i]);
  }

  memcpy(wpa->orig_mac1, in.mac1, 6);
  memcpy(wpa->orig_mac2, in.mac2, 6);
  memcpy(wpa->orig_nonce1, in.nonce1, 32);
  memcpy(wpa->orig_nonce2, in.nonce2, 32);

  wpa->keyver = in.keyver;

  if (wpa->keyver > 255)
  {
    log_info("ATTENTION!");
    log_info("  The WPA/WPA2 key version in your .hccap file is invalid!");
    log_info("  This could be due to a recent aircrack-ng bug.");
    log_info("  The key version was automatically reset to a reasonable value.");
    log_info("");

    wpa->keyver &= 0xff;
  }

  wpa->eapol_size = in.eapol_size;

  unsigned char *eapol_ptr = (unsigned char *)wpa->eapol;

  memcpy(eapol_ptr, in.eapol, wpa->eapol_size);

  memset(eapol_ptr + wpa->eapol_size, 0, 256 - wpa->eapol_size);

  eapol_ptr[wpa->eapol_size] = (unsigned char)0x80;

  if (wpa->keyver == 1)
  {
    // nothing to do
  }
  else
  {
    digest[0] = byte_swap_32(digest[0]);
    digest[1] = byte_swap_32(digest[1]);
    digest[2] = byte_swap_32(digest[2]);
    digest[3] = byte_swap_32(digest[3]);

    for (int i = 0; i < 64; i++)
    {
      wpa->eapol[i] = byte_swap_32(wpa->eapol[i]);
    }
  }

  uint32_t *p0 = (uint32_t *)in.essid;
  uint32_t c0 = 0;
  uint32_t c1 = 0;

  for (uint i = 0; i < sizeof(in.essid) / sizeof(uint32_t); i++) c0 ^= *p0++;
  for (uint i = 0; i < sizeof(wpa->pke) / sizeof(wpa->pke[0]); i++) c1 ^= wpa->pke[i];

  salt->salt_buf[10] = c0;
  salt->salt_buf[11] = c1;

  return (PARSER_OK);
}

int psafe2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0)
  {
    log_error("Password Safe v2 container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  psafe2_hdr buf;

  memset(&buf, 0, sizeof(psafe2_hdr));

  int n = fread(&buf, sizeof(psafe2_hdr), 1, fp);

  fclose(fp);

  if (n != 1) return (PARSER_PSAFE2_FILE_SIZE);

  salt->salt_buf[0] = buf.random[0];
  salt->salt_buf[1] = buf.random[1];

  salt->salt_len = 8;
  salt->salt_iter = 1000;

  digest[0] = byte_swap_32(buf.hash[0]);
  digest[1] = byte_swap_32(buf.hash[1]);
  digest[2] = byte_swap_32(buf.hash[2]);
  digest[3] = byte_swap_32(buf.hash[3]);
  digest[4] = byte_swap_32(buf.hash[4]);

  return (PARSER_OK);
}

int psafe3_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0)
  {
    log_error(".psafe3 not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  psafe3_t in;

  int n = fread(&in, sizeof(psafe3_t), 1, fp);

  fclose(fp);

  data.hashfile = input_buf; // we will need this in case it gets cracked

  if (memcmp(SIGNATURE_PSAFE3, in.signature, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  if (n != 1) return (PARSER_PSAFE3_FILE_SIZE);

  salt->salt_iter = in.iterations + 1;

  salt->salt_buf[0] = in.salt_buf[0];
  salt->salt_buf[1] = in.salt_buf[1];
  salt->salt_buf[2] = in.salt_buf[2];
  salt->salt_buf[3] = in.salt_buf[3];
  salt->salt_buf[4] = in.salt_buf[4];
  salt->salt_buf[5] = in.salt_buf[5];
  salt->salt_buf[6] = in.salt_buf[6];
  salt->salt_buf[7] = in.salt_buf[7];

  salt->salt_len = 32;

  digest[0] = in.hash_buf[0];
  digest[1] = in.hash_buf[1];
  digest[2] = in.hash_buf[2];
  digest[3] = in.hash_buf[3];
  digest[4] = in.hash_buf[4];
  digest[5] = in.hash_buf[5];
  digest[6] = in.hash_buf[6];
  digest[7] = in.hash_buf[7];

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int phpass_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_400) || (input_len > DISPLAY_LEN_MAX_400)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_PHPASS1, input_buf, 3)) && (memcmp(SIGNATURE_PHPASS2, input_buf, 3))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 3;

  uint salt_iter = 1u << itoa64_to_int(iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy((char *)salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  char *salt_pos = iter_pos + 1;

  uint salt_len = 8;

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char *hash_pos = salt_pos + salt_len;

  phpass_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int md5crypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (input_len < DISPLAY_LEN_MIN_500) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MD5CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp(salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len == 0) return (PARSER_SALT_ITERATION);
    if (salt_pos[0] != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi(salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if (input_len > (DISPLAY_LEN_MAX_500 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  uint hash_len = input_len - 3 - iterations_len - salt_len - 1;

  if (hash_len != 22) return (PARSER_HASH_LENGTH);

  md5crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int md5apr1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp(SIGNATURE_MD5APR1, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6;

  uint iterations_len = 0;

  if (memcmp(salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len == 0) return (PARSER_SALT_ITERATION);
    if (salt_pos[0] != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi(salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1600) || (input_len > DISPLAY_LEN_MAX_1600 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  md5crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int episerver_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_141) || (input_len > DISPLAY_LEN_MAX_141)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_EPISERVER, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 14;

  char *hash_pos = strchr(salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint salt_len = hash_pos - salt_pos - 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode(base64_to_int, (const u8 *)hash_pos, 27, tmp_buf);

  memcpy(digest, tmp_buf, 20);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int descrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1500) || (input_len > DISPLAY_LEN_MAX_1500)) return (PARSER_GLOBAL_LENGTH);

  unsigned char c12 = itoa64_to_int(input_buf[12]);

  if (c12 & 3) return (PARSER_HASH_VALUE);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // for ascii_digest
  salt->salt_sign[0] = input_buf[0];
  salt->salt_sign[1] = input_buf[1];

  salt->salt_buf[0] = itoa64_to_int(input_buf[0])
    | itoa64_to_int(input_buf[1]) << 6;

  salt->salt_len = 2;

  u8 tmp_buf[100] = { 0 };

  base64_decode(itoa64_to_int, (const u8 *)input_buf + 2, 11, tmp_buf);

  memcpy(digest, tmp_buf, 8);

  uint tt;

  IP(&digest[0], &digest[1], &tt);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int md4_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_900) || (input_len > DISPLAY_LEN_MAX_900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  return (PARSER_OK);
}

int md4s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_910H) || (input_len > DISPLAY_LEN_MAX_910H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_910) || (input_len > DISPLAY_LEN_MAX_910)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_0) || (input_len > DISPLAY_LEN_MAX_0)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int md5half_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5100) || (input_len > DISPLAY_LEN_MAX_5100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  return (PARSER_OK);
}

int md5s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_10H) || (input_len > DISPLAY_LEN_MAX_10H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_10) || (input_len > DISPLAY_LEN_MAX_10)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5pix_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2400) || (input_len > DISPLAY_LEN_MAX_2400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = itoa64_to_int(input_buf[0]) << 0
    | itoa64_to_int(input_buf[1]) << 6
    | itoa64_to_int(input_buf[2]) << 12
    | itoa64_to_int(input_buf[3]) << 18;
  digest[1] = itoa64_to_int(input_buf[4]) << 0
    | itoa64_to_int(input_buf[5]) << 6
    | itoa64_to_int(input_buf[6]) << 12
    | itoa64_to_int(input_buf[7]) << 18;
  digest[2] = itoa64_to_int(input_buf[8]) << 0
    | itoa64_to_int(input_buf[9]) << 6
    | itoa64_to_int(input_buf[10]) << 12
    | itoa64_to_int(input_buf[11]) << 18;
  digest[3] = itoa64_to_int(input_buf[12]) << 0
    | itoa64_to_int(input_buf[13]) << 6
    | itoa64_to_int(input_buf[14]) << 12
    | itoa64_to_int(input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  return (PARSER_OK);
}

int md5asa_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2410H) || (input_len > DISPLAY_LEN_MAX_2410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2410) || (input_len > DISPLAY_LEN_MAX_2410)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = itoa64_to_int(input_buf[0]) << 0
    | itoa64_to_int(input_buf[1]) << 6
    | itoa64_to_int(input_buf[2]) << 12
    | itoa64_to_int(input_buf[3]) << 18;
  digest[1] = itoa64_to_int(input_buf[4]) << 0
    | itoa64_to_int(input_buf[5]) << 6
    | itoa64_to_int(input_buf[6]) << 12
    | itoa64_to_int(input_buf[7]) << 18;
  digest[2] = itoa64_to_int(input_buf[8]) << 0
    | itoa64_to_int(input_buf[9]) << 6
    | itoa64_to_int(input_buf[10]) << 12
    | itoa64_to_int(input_buf[11]) << 18;
  digest[3] = itoa64_to_int(input_buf[12]) << 0
    | itoa64_to_int(input_buf[13]) << 6
    | itoa64_to_int(input_buf[14]) << 12
    | itoa64_to_int(input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 16 - 1;

  char *salt_buf = input_buf + 16 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

void transform_netntlmv1_key(const u8 *nthash, u8 *key)
{
  key[0] = (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}

int netntlmv1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5500) || (input_len > DISPLAY_LEN_MAX_5500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *user_pos = input_buf;

  char *unused_pos = strchr(user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  char *domain_pos = strchr(unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  char *srvchall_pos = strchr(domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  char *hash_pos = strchr(srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint srvchall_len = hash_pos - srvchall_pos;

  // if (srvchall_len != 0) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *clichall_pos = strchr(hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = clichall_pos - hash_pos;

  if (hash_len != 48) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  uint clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len != 16) return (PARSER_SALT_LENGTH);

  /**
  * store some data for later use
  */

  netntlm->user_len = user_len * 2;
  netntlm->domain_len = domain_len * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  char *userdomain_ptr = (char *)netntlm->userdomain_buf;
  char *chall_ptr = (char *)netntlm->chall_buf;

  /**
  * handle username and domainname
  */

  for (uint i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = user_pos[i];
    *userdomain_ptr++ = 0;
  }

  for (uint i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  /**
  * handle server challenge encoding
  */

  for (uint i = 0; i < srvchall_len; i += 2)
  {
    const char p0 = srvchall_pos[i + 0];
    const char p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /**
  * handle client challenge encoding
  */

  for (uint i = 0; i < clichall_len; i += 2)
  {
    const char p0 = clichall_pos[i + 0];
    const char p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /**
  * store data
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  uint salt_len = parse_and_store_salt(salt_buf_ptr, clichall_pos, clichall_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  /* special case, last 8 byte do not need to be checked since they are brute-forced next */

  uint digest_tmp[2] = { 0 };

  digest_tmp[0] = hex_to_u32((const u8 *)&hash_pos[32]);
  digest_tmp[1] = hex_to_u32((const u8 *)&hash_pos[40]);

  digest_tmp[0] = byte_swap_32(digest_tmp[0]);
  digest_tmp[1] = byte_swap_32(digest_tmp[1]);

  /* special case 2: ESS */

  if (srvchall_len == 48)
  {
    if ((netntlm->chall_buf[2] == 0) && (netntlm->chall_buf[3] == 0) && (netntlm->chall_buf[4] == 0) && (netntlm->chall_buf[5] == 0))
    {
      uint w[16] = { 0 };

      w[0] = netntlm->chall_buf[6];
      w[1] = netntlm->chall_buf[7];
      w[2] = netntlm->chall_buf[0];
      w[3] = netntlm->chall_buf[1];
      w[4] = 0x80;
      w[14] = 16 * 8;

      uint dgst[4] = { 0 };

      dgst[0] = MAGIC_A;
      dgst[1] = MAGIC_B;
      dgst[2] = MAGIC_C;
      dgst[3] = MAGIC_D;

      md5_64(w, dgst);

      salt->salt_buf[0] = dgst[0];
      salt->salt_buf[1] = dgst[1];
    }
  }

  /* precompute netntlmv1 exploit start */

  for (uint i = 0; i < 0x10000; i++)
  {
    uint key_md4[2] = { i, 0 };
    uint key_des[2] = { 0, 0 };

    transform_netntlmv1_key((u8 *)key_md4, (u8 *)key_des);

    uint Kc[16] = { 0 };
    uint Kd[16] = { 0 };

    _des_keysetup(key_des, Kc, Kd, c_skb);

    uint data3[2] = { salt->salt_buf[0], salt->salt_buf[1] };

    _des_encrypt(data3, Kc, Kd, c_SPtrans);

    if (data3[0] != digest_tmp[0]) continue;
    if (data3[1] != digest_tmp[1]) continue;

    salt->salt_buf[2] = i;

    salt->salt_len = 24;

    break;
  }

  salt->salt_buf_pc[0] = digest_tmp[0];
  salt->salt_buf_pc[1] = digest_tmp[1];

  /* precompute netntlmv1 exploit stop */

  u32 tt;

  IP(&digest[0], &digest[1], &tt);
  IP(&digest[2], &digest[3], &tt);

  digest[0] = rotr32(digest[0], 29);
  digest[1] = rotr32(digest[1], 29);
  digest[2] = rotr32(digest[2], 29);
  digest[3] = rotr32(digest[3], 29);

  IP(&salt->salt_buf[0], &salt->salt_buf[1], &tt);

  salt->salt_buf[0] = rotl32(salt->salt_buf[0], 3);
  salt->salt_buf[1] = rotl32(salt->salt_buf[1], 3);

  return (PARSER_OK);
}

int netntlmv2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5600) || (input_len > DISPLAY_LEN_MAX_5600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *user_pos = input_buf;

  char *unused_pos = strchr(user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  char *domain_pos = strchr(unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  char *srvchall_pos = strchr(domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  char *hash_pos = strchr(srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint srvchall_len = hash_pos - srvchall_pos;

  if (srvchall_len != 16) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *clichall_pos = strchr(hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = clichall_pos - hash_pos;

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  uint clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len > 1024) return (PARSER_SALT_LENGTH);

  if (clichall_len % 2) return (PARSER_SALT_VALUE);

  /**
  * store some data for later use
  */

  netntlm->user_len = user_len * 2;
  netntlm->domain_len = domain_len * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  char *userdomain_ptr = (char *)netntlm->userdomain_buf;
  char *chall_ptr = (char *)netntlm->chall_buf;

  /**
  * handle username and domainname
  */

  for (uint i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = toupper(user_pos[i]);
    *userdomain_ptr++ = 0;
  }

  for (uint i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  *userdomain_ptr++ = 0x80;

  /**
  * handle server challenge encoding
  */

  for (uint i = 0; i < srvchall_len; i += 2)
  {
    const char p0 = srvchall_pos[i + 0];
    const char p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /**
  * handle client challenge encoding
  */

  for (uint i = 0; i < clichall_len; i += 2)
  {
    const char p0 = clichall_pos[i + 0];
    const char p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  *chall_ptr++ = 0x80;

  /**
  * handle hash itself
  */

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  /**
  * reuse challange data as salt_buf, its the buffer that is most likely unique
  */

  salt->salt_buf[0] = 0;
  salt->salt_buf[1] = 0;
  salt->salt_buf[2] = 0;
  salt->salt_buf[3] = 0;
  salt->salt_buf[4] = 0;
  salt->salt_buf[5] = 0;
  salt->salt_buf[6] = 0;
  salt->salt_buf[7] = 0;

  uint *uptr;

  uptr = (uint *)netntlm->userdomain_buf;

  for (uint i = 0; i < 16; i += 16)
  {
    md5_64(uptr, salt->salt_buf);
  }

  uptr = (uint *)netntlm->chall_buf;

  for (uint i = 0; i < 256; i += 16)
  {
    md5_64(uptr, salt->salt_buf);
  }

  salt->salt_len = 16;

  return (PARSER_OK);
}

int joomla_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_11H) || (input_len > DISPLAY_LEN_MAX_11H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_11) || (input_len > DISPLAY_LEN_MAX_11)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_12H) || (input_len > DISPLAY_LEN_MAX_12H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_12) || (input_len > DISPLAY_LEN_MAX_12)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5md5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2600) || (input_len > DISPLAY_LEN_MAX_2600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /**
  * This is a virtual salt. While the algorithm is basically not salted
  * we can exploit the salt buffer to set the 0x80 and the w[14] value.
  * This way we can save a special md5md5 kernel and reuse the one from vbull.
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  uint salt_len = parse_and_store_salt(salt_buf_ptr, (char *) "", 0);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb3_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2611H) || (input_len > DISPLAY_LEN_MAX_2611H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2611) || (input_len > DISPLAY_LEN_MAX_2611)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb30_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2711H) || (input_len > DISPLAY_LEN_MAX_2711H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2711) || (input_len > DISPLAY_LEN_MAX_2711)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1100H) || (input_len > DISPLAY_LEN_MAX_1100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1100) || (input_len > DISPLAY_LEN_MAX_1100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int ipb2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2811H) || (input_len > DISPLAY_LEN_MAX_2811H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2811) || (input_len > DISPLAY_LEN_MAX_2811)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  uint salt_pc_block[16] = { 0 };

  char *salt_pc_block_ptr = (char *)salt_pc_block;

  salt_len = parse_and_store_salt(salt_pc_block_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_pc_block_ptr[salt_len] = (unsigned char)0x80;

  salt_pc_block[14] = salt_len * 8;

  uint salt_pc_digest[4] = { MAGIC_A, MAGIC_B, MAGIC_C, MAGIC_D };

  md5_64(salt_pc_block, salt_pc_digest);

  salt_pc_digest[0] = byte_swap_32(salt_pc_digest[0]);
  salt_pc_digest[1] = byte_swap_32(salt_pc_digest[1]);
  salt_pc_digest[2] = byte_swap_32(salt_pc_digest[2]);
  salt_pc_digest[3] = byte_swap_32(salt_pc_digest[3]);

  u8 *salt_buf_ptr = (u8 *)salt->salt_buf;

  memcpy(salt_buf_ptr, salt_buf, salt_len);

  u8 *salt_buf_pc_ptr = (u8 *)salt->salt_buf_pc;

  bin_to_hex_lower(salt_pc_digest[0], salt_buf_pc_ptr + 0);
  bin_to_hex_lower(salt_pc_digest[1], salt_buf_pc_ptr + 8);
  bin_to_hex_lower(salt_pc_digest[2], salt_buf_pc_ptr + 16);
  bin_to_hex_lower(salt_pc_digest[3], salt_buf_pc_ptr + 24);

  salt->salt_len = 32; // changed, was salt_len before -- was a bug? 32 should be correct

  return (PARSER_OK);
}

int sha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_100) || (input_len > DISPLAY_LEN_MAX_100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1axcrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13300) || (input_len > DISPLAY_LEN_MAX_13300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_AXCRYPT_SHA1, input_buf, 13)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  input_buf += 14;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = 0;

  return (PARSER_OK);
}

int sha1s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_110H) || (input_len > DISPLAY_LEN_MAX_110H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_110) || (input_len > DISPLAY_LEN_MAX_110)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pstoken_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13500) || (input_len > DISPLAY_LEN_MAX_13500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pstoken_t *pstoken = (pstoken_t *)hash_buf->esalt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  if (salt_len == UINT_MAX || salt_len % 2 != 0) return (PARSER_SALT_LENGTH);

  u8 *pstoken_ptr = (u8 *)pstoken->salt_buf;

  for (uint i = 0, j = 0; i < salt_len; i += 2, j += 1)
  {
    pstoken_ptr[j] = hex_to_u8((const u8 *)&salt_buf[i]);
  }

  pstoken->salt_len = salt_len / 2;

  /* some fake salt for the sorting mechanisms */

  salt->salt_buf[0] = pstoken->salt_buf[0];
  salt->salt_buf[1] = pstoken->salt_buf[1];
  salt->salt_buf[2] = pstoken->salt_buf[2];
  salt->salt_buf[3] = pstoken->salt_buf[3];
  salt->salt_buf[4] = pstoken->salt_buf[4];
  salt->salt_buf[5] = pstoken->salt_buf[5];
  salt->salt_buf[6] = pstoken->salt_buf[6];
  salt->salt_buf[7] = pstoken->salt_buf[7];

  salt->salt_len = 32;

  /* we need to check if we can precompute some of the data --
  this is possible since the scheme is badly designed */

  pstoken->pc_digest[0] = SHA1M_A;
  pstoken->pc_digest[1] = SHA1M_B;
  pstoken->pc_digest[2] = SHA1M_C;
  pstoken->pc_digest[3] = SHA1M_D;
  pstoken->pc_digest[4] = SHA1M_E;

  pstoken->pc_offset = 0;

  for (int i = 0; i < (int)pstoken->salt_len - 63; i += 64)
  {
    uint w[16];

    w[0] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 0]);
    w[1] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 1]);
    w[2] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 2]);
    w[3] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 3]);
    w[4] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 4]);
    w[5] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 5]);
    w[6] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 6]);
    w[7] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 7]);
    w[8] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 8]);
    w[9] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 9]);
    w[10] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 10]);
    w[11] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 11]);
    w[12] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 12]);
    w[13] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 13]);
    w[14] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 14]);
    w[15] = byte_swap_32(pstoken->salt_buf[pstoken->pc_offset + 15]);

    sha1_64(w, pstoken->pc_digest);

    pstoken->pc_offset += 16;
  }

  return (PARSER_OK);
}

int sha1b64_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_101) || (input_len > DISPLAY_LEN_MAX_101)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA1B64, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode(base64_to_int, (const u8 *)input_buf + 5, input_len - 5, tmp_buf);

  memcpy(digest, tmp_buf, 20);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1b64s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_111) || (input_len > DISPLAY_LEN_MAX_111)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SSHA1B64_lower, input_buf, 6) && memcmp(SIGNATURE_SSHA1B64_upper, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  int tmp_len = base64_decode(base64_to_int, (const u8 *)input_buf + 6, input_len - 6, tmp_buf);

  if (tmp_len < 20) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 20);

  int salt_len = tmp_len - 20;

  if (salt_len < 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy(salt->salt_buf, tmp_buf + 20, salt->salt_len);

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    char *ptr = (char *)salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2000_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_131) || (input_len > DISPLAY_LEN_MAX_131)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8 + 40;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2005_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_132) || (input_len > DISPLAY_LEN_MAX_132)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2012_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1731) || (input_len > DISPLAY_LEN_MAX_1731)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MSSQL2012, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8;

  digest[0] = hex_to_u64((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u64((const u8 *)&hash_pos[16]);
  digest[2] = hex_to_u64((const u8 *)&hash_pos[32]);
  digest[3] = hex_to_u64((const u8 *)&hash_pos[48]);
  digest[4] = hex_to_u64((const u8 *)&hash_pos[64]);
  digest[5] = hex_to_u64((const u8 *)&hash_pos[80]);
  digest[6] = hex_to_u64((const u8 *)&hash_pos[96]);
  digest[7] = hex_to_u64((const u8 *)&hash_pos[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int oracleh_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_3100H) || (input_len > DISPLAY_LEN_MAX_3100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_3100) || (input_len > DISPLAY_LEN_MAX_3100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 16 - 1;

  char *salt_buf = input_buf + 16 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oracles_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_112) || (input_len > DISPLAY_LEN_MAX_112)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oraclet_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12300) || (input_len > DISPLAY_LEN_MAX_12300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hash_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hash_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hash_pos[56]);
  digest[8] = hex_to_u32((const u8 *)&hash_pos[64]);
  digest[9] = hex_to_u32((const u8 *)&hash_pos[72]);
  digest[10] = hex_to_u32((const u8 *)&hash_pos[80]);
  digest[11] = hex_to_u32((const u8 *)&hash_pos[88]);
  digest[12] = hex_to_u32((const u8 *)&hash_pos[96]);
  digest[13] = hex_to_u32((const u8 *)&hash_pos[104]);
  digest[14] = hex_to_u32((const u8 *)&hash_pos[112]);
  digest[15] = hex_to_u32((const u8 *)&hash_pos[120]);

  char *salt_pos = input_buf + 128;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&salt_pos[24]);

  salt->salt_iter = ROUNDS_ORACLET - 1;
  salt->salt_len = 16;

  return (PARSER_OK);
}

int sha256_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1400) || (input_len > DISPLAY_LEN_MAX_1400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha256s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1410H) || (input_len > DISPLAY_LEN_MAX_1410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1410) || (input_len > DISPLAY_LEN_MAX_1410)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha384_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10800) || (input_len > DISPLAY_LEN_MAX_10800)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *)hash_buf->digest;

  digest[0] = hex_to_u64((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u64((const u8 *)&input_buf[16]);
  digest[2] = hex_to_u64((const u8 *)&input_buf[32]);
  digest[3] = hex_to_u64((const u8 *)&input_buf[48]);
  digest[4] = hex_to_u64((const u8 *)&input_buf[64]);
  digest[5] = hex_to_u64((const u8 *)&input_buf[80]);
  digest[6] = 0;
  digest[7] = 0;

  digest[0] -= SHA384M_A;
  digest[1] -= SHA384M_B;
  digest[2] -= SHA384M_C;
  digest[3] -= SHA384M_D;
  digest[4] -= SHA384M_E;
  digest[5] -= SHA384M_F;
  digest[6] -= 0;
  digest[7] -= 0;

  return (PARSER_OK);
}

int sha512_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1700) || (input_len > DISPLAY_LEN_MAX_1700)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *)hash_buf->digest;

  digest[0] = hex_to_u64((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u64((const u8 *)&input_buf[16]);
  digest[2] = hex_to_u64((const u8 *)&input_buf[32]);
  digest[3] = hex_to_u64((const u8 *)&input_buf[48]);
  digest[4] = hex_to_u64((const u8 *)&input_buf[64]);
  digest[5] = hex_to_u64((const u8 *)&input_buf[80]);
  digest[6] = hex_to_u64((const u8 *)&input_buf[96]);
  digest[7] = hex_to_u64((const u8 *)&input_buf[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int sha512s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1710H) || (input_len > DISPLAY_LEN_MAX_1710H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1710) || (input_len > DISPLAY_LEN_MAX_1710)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u64((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u64((const u8 *)&input_buf[16]);
  digest[2] = hex_to_u64((const u8 *)&input_buf[32]);
  digest[3] = hex_to_u64((const u8 *)&input_buf[48]);
  digest[4] = hex_to_u64((const u8 *)&input_buf[64]);
  digest[5] = hex_to_u64((const u8 *)&input_buf[80]);
  digest[6] = hex_to_u64((const u8 *)&input_buf[96]);
  digest[7] = hex_to_u64((const u8 *)&input_buf[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  if (input_buf[128] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 128 - 1;

  char *salt_buf = input_buf + 128 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha512crypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp(SIGNATURE_SHA512CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp(salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len == 0) return (PARSER_SALT_ITERATION);
    if (salt_pos[0] != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi(salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA512CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1800) || (input_len > DISPLAY_LEN_MAX_1800 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha512crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int keccak_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5000) || (input_len > DISPLAY_LEN_MAX_5000)) return (PARSER_GLOBAL_LENGTH);

  if (input_len % 16) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  uint keccak_mdlen = input_len / 2;

  for (uint i = 0; i < keccak_mdlen / 8; i++)
  {
    digest[i] = hex_to_u64((const u8 *)&input_buf[i * 16]);

    digest[i] = byte_swap_64(digest[i]);
  }

  salt->keccak_mdlen = keccak_mdlen;

  return (PARSER_OK);
}

int ikepsk_md5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5300) || (input_len > DISPLAY_LEN_MAX_5300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *)hash_buf->esalt;

  /**
  * Parse that strange long line
  */

  char *in_off[9];

  size_t in_len[9] = { 0 };

  in_off[0] = strtok(input_buf, ":");

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen(in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = strtok(NULL, ":");

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen(in_off[i]);
  }

  char *ptr = (char *)ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (char *)ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
  * Store to database
  */

  ptr = in_off[8];

  digest[0] = hex_to_u32((const u8 *)&ptr[0]);
  digest[1] = hex_to_u32((const u8 *)&ptr[8]);
  digest[2] = hex_to_u32((const u8 *)&ptr[16]);
  digest[3] = hex_to_u32((const u8 *)&ptr[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ikepsk_sha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5400) || (input_len > DISPLAY_LEN_MAX_5400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *)hash_buf->esalt;

  /**
  * Parse that strange long line
  */

  char *in_off[9];

  size_t in_len[9] = { 0 };

  in_off[0] = strtok(input_buf, ":");

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen(in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = strtok(NULL, ":");

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen(in_off[i]);
  }

  char *ptr = (char *)ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (char *)ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8((const u8 *)in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
  * Store to database
  */

  ptr = in_off[8];

  digest[0] = hex_to_u32((const u8 *)&ptr[0]);
  digest[1] = hex_to_u32((const u8 *)&ptr[8]);
  digest[2] = hex_to_u32((const u8 *)&ptr[16]);
  digest[3] = hex_to_u32((const u8 *)&ptr[24]);
  digest[4] = hex_to_u32((const u8 *)&ptr[32]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ripemd160_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6000) || (input_len > DISPLAY_LEN_MAX_6000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  return (PARSER_OK);
}

int whirlpool_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6100) || (input_len > DISPLAY_LEN_MAX_6100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);
  digest[8] = hex_to_u32((const u8 *)&input_buf[64]);
  digest[9] = hex_to_u32((const u8 *)&input_buf[72]);
  digest[10] = hex_to_u32((const u8 *)&input_buf[80]);
  digest[11] = hex_to_u32((const u8 *)&input_buf[88]);
  digest[12] = hex_to_u32((const u8 *)&input_buf[96]);
  digest[13] = hex_to_u32((const u8 *)&input_buf[104]);
  digest[14] = hex_to_u32((const u8 *)&input_buf[112]);
  digest[15] = hex_to_u32((const u8 *)&input_buf[120]);

  return (PARSER_OK);
}

int androidpin_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5800) || (input_len > DISPLAY_LEN_MAX_5800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_ANDROIDPIN - 1;

  return (PARSER_OK);
}

int truecrypt_parse_hash_1k(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("TrueCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_TC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_1K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int truecrypt_parse_hash_2k(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("TrueCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_TC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_2K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_200000(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("VeraCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_200000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_500000(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("VeraCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_500000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_327661(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("VeraCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_327661 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_655331(char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *)hash_buf->esalt;

  if (input_len == 0)
  {
    log_error("VeraCrypt container not specified");

    exit(-1);
  }

  FILE *fp = fopen(input_buf, "rb");

  if (fp == NULL)
  {
    log_error("%s: %s", input_buf, strerror(errno));

    exit(-1);
  }

  char buf[512] = { 0 };

  int n = fread(buf, 1, sizeof(buf), fp);

  fclose(fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy(tc->salt_buf, buf, 64);

  memcpy(tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_655331 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int md5aix_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6300) || (input_len > DISPLAY_LEN_MAX_6300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MD5AIX, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 8) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  salt->salt_iter = 1000;

  hash_pos++;

  md5crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int sha1aix_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6700) || (input_len > DISPLAY_LEN_MAX_6700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA1AIX, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 7;

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi(salt_iter);

  salt->salt_iter = (1u << atoi(salt_iter)) - 1;

  hash_pos++;

  sha1aix_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  return (PARSER_OK);
}

int sha256aix_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6400) || (input_len > DISPLAY_LEN_MAX_6400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA256AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 9;

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi(salt_iter);

  salt->salt_iter = (1u << atoi(salt_iter)) - 1;

  hash_pos++;

  sha256aix_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int sha512aix_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6500) || (input_len > DISPLAY_LEN_MAX_6500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA512AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 9;

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi(salt_iter);

  salt->salt_iter = (1u << atoi(salt_iter)) - 1;

  hash_pos++;

  sha512aix_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  digest[0] = byte_swap_64(digest[0]);
  digest[1] = byte_swap_64(digest[1]);
  digest[2] = byte_swap_64(digest[2]);
  digest[3] = byte_swap_64(digest[3]);
  digest[4] = byte_swap_64(digest[4]);
  digest[5] = byte_swap_64(digest[5]);
  digest[6] = byte_swap_64(digest[6]);
  digest[7] = byte_swap_64(digest[7]);

  return (PARSER_OK);
}

int agilekey_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6600) || (input_len > DISPLAY_LEN_MAX_6600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  agilekey_t *agilekey = (agilekey_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *iterations_pos = input_buf;

  char *saltbuf_pos = strchr(iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint iterations_len = saltbuf_pos - iterations_pos;

  if (iterations_len > 6) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *cipherbuf_pos = strchr(saltbuf_pos, ':');

  if (cipherbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = cipherbuf_pos - saltbuf_pos;

  if (saltbuf_len != 16) return (PARSER_SALT_LENGTH);

  uint cipherbuf_len = input_len - iterations_len - 1 - saltbuf_len - 1;

  if (cipherbuf_len != 2080) return (PARSER_HASH_LENGTH);

  cipherbuf_pos++;

  /**
  * pbkdf2 iterations
  */

  salt->salt_iter = atoi(iterations_pos) - 1;

  /**
  * handle salt encoding
  */

  char *saltbuf_ptr = (char *)salt->salt_buf;

  for (uint i = 0; i < saltbuf_len; i += 2)
  {
    const char p0 = saltbuf_pos[i + 0];
    const char p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  salt->salt_len = saltbuf_len / 2;

  /**
  * handle cipher encoding
  */

  uint *tmp = (uint *)mymalloc(32);

  char *cipherbuf_ptr = (char *)tmp;

  for (uint i = 2016; i < cipherbuf_len; i += 2)
  {
    const char p0 = cipherbuf_pos[i + 0];
    const char p1 = cipherbuf_pos[i + 1];

    *cipherbuf_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  // iv   is stored at salt_buf 4 (length 16)
  // data is stored at salt_buf 8 (length 16)

  salt->salt_buf[4] = byte_swap_32(tmp[0]);
  salt->salt_buf[5] = byte_swap_32(tmp[1]);
  salt->salt_buf[6] = byte_swap_32(tmp[2]);
  salt->salt_buf[7] = byte_swap_32(tmp[3]);

  salt->salt_buf[8] = byte_swap_32(tmp[4]);
  salt->salt_buf[9] = byte_swap_32(tmp[5]);
  salt->salt_buf[10] = byte_swap_32(tmp[6]);
  salt->salt_buf[11] = byte_swap_32(tmp[7]);

  free(tmp);

  for (uint i = 0, j = 0; i < 1040; i += 1, j += 2)
  {
    const char p0 = cipherbuf_pos[j + 0];
    const char p1 = cipherbuf_pos[j + 1];

    agilekey->cipher[i] = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /**
  * digest buf
  */

  digest[0] = 0x10101010;
  digest[1] = 0x10101010;
  digest[2] = 0x10101010;
  digest[3] = 0x10101010;

  return (PARSER_OK);
}

int lastpass_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6800) || (input_len > DISPLAY_LEN_MAX_6800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hashbuf_pos = input_buf;

  char *iterations_pos = strchr(hashbuf_pos, ':');

  if (iterations_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = iterations_pos - hashbuf_pos;

  if ((hash_len != 32) && (hash_len != 64)) return (PARSER_HASH_LENGTH);

  iterations_pos++;

  char *saltbuf_pos = strchr(iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint iterations_len = saltbuf_pos - iterations_pos;

  saltbuf_pos++;

  uint salt_len = input_len - hash_len - 1 - iterations_len - 1;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, saltbuf_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = atoi(iterations_pos) - 1;

  digest[0] = hex_to_u32((const u8 *)&hashbuf_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hashbuf_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hashbuf_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hashbuf_pos[24]);

  return (PARSER_OK);
}

int gost_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6900) || (input_len > DISPLAY_LEN_MAX_6900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int sha256crypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp(SIGNATURE_SHA256CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp(salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len == 0) return (PARSER_SALT_ITERATION);
    if (salt_pos[0] != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi(salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA256CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_7400) || (input_len > DISPLAY_LEN_MAX_7400 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha256crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int sha512osx_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  uint max_len = DISPLAY_LEN_MAX_7100 + (2 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7100) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA512OSX, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *)hash_buf->esalt;

  char *iter_pos = input_buf + 4;

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  digest[0] = hex_to_u64((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u64((const u8 *)&hash_pos[16]);
  digest[2] = hex_to_u64((const u8 *)&hash_pos[32]);
  digest[3] = hex_to_u64((const u8 *)&hash_pos[48]);
  digest[4] = hex_to_u64((const u8 *)&hash_pos[64]);
  digest[5] = hex_to_u64((const u8 *)&hash_pos[80]);
  digest[6] = hex_to_u64((const u8 *)&hash_pos[96]);
  digest[7] = hex_to_u64((const u8 *)&hash_pos[112]);

  uint salt_len = hash_pos - salt_pos - 1;

  if ((salt_len % 2) != 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len / 2;

  pbkdf2_sha512->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  pbkdf2_sha512->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);
  pbkdf2_sha512->salt_buf[2] = hex_to_u32((const u8 *)&salt_pos[16]);
  pbkdf2_sha512->salt_buf[3] = hex_to_u32((const u8 *)&salt_pos[24]);
  pbkdf2_sha512->salt_buf[4] = hex_to_u32((const u8 *)&salt_pos[32]);
  pbkdf2_sha512->salt_buf[5] = hex_to_u32((const u8 *)&salt_pos[40]);
  pbkdf2_sha512->salt_buf[6] = hex_to_u32((const u8 *)&salt_pos[48]);
  pbkdf2_sha512->salt_buf[7] = hex_to_u32((const u8 *)&salt_pos[56]);

  pbkdf2_sha512->salt_buf[0] = byte_swap_32(pbkdf2_sha512->salt_buf[0]);
  pbkdf2_sha512->salt_buf[1] = byte_swap_32(pbkdf2_sha512->salt_buf[1]);
  pbkdf2_sha512->salt_buf[2] = byte_swap_32(pbkdf2_sha512->salt_buf[2]);
  pbkdf2_sha512->salt_buf[3] = byte_swap_32(pbkdf2_sha512->salt_buf[3]);
  pbkdf2_sha512->salt_buf[4] = byte_swap_32(pbkdf2_sha512->salt_buf[4]);
  pbkdf2_sha512->salt_buf[5] = byte_swap_32(pbkdf2_sha512->salt_buf[5]);
  pbkdf2_sha512->salt_buf[6] = byte_swap_32(pbkdf2_sha512->salt_buf[6]);
  pbkdf2_sha512->salt_buf[7] = byte_swap_32(pbkdf2_sha512->salt_buf[7]);
  pbkdf2_sha512->salt_buf[8] = 0x01000000;
  pbkdf2_sha512->salt_buf[9] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_iter = atoi(iter_pos) - 1;

  return (PARSER_OK);
}

int episerver4_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1441) || (input_len > DISPLAY_LEN_MAX_1441)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_EPISERVER4, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 14;

  char *hash_pos = strchr(salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint salt_len = hash_pos - salt_pos - 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode(base64_to_int, (const u8 *)hash_pos, 43, tmp_buf);

  memcpy(digest, tmp_buf, 32);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha512grub_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  uint max_len = DISPLAY_LEN_MAX_7200 + (8 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7200) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA512GRUB, input_buf, 19)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *)hash_buf->esalt;

  char *iter_pos = input_buf + 19;

  char *salt_pos = strchr(iter_pos, '.');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '.');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  digest[0] = hex_to_u64((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u64((const u8 *)&hash_pos[16]);
  digest[2] = hex_to_u64((const u8 *)&hash_pos[32]);
  digest[3] = hex_to_u64((const u8 *)&hash_pos[48]);
  digest[4] = hex_to_u64((const u8 *)&hash_pos[64]);
  digest[5] = hex_to_u64((const u8 *)&hash_pos[80]);
  digest[6] = hex_to_u64((const u8 *)&hash_pos[96]);
  digest[7] = hex_to_u64((const u8 *)&hash_pos[112]);

  uint salt_len = hash_pos - salt_pos - 1;

  salt_len /= 2;

  char *salt_buf_ptr = (char *)pbkdf2_sha512->salt_buf;

  uint i;

  for (i = 0; i < salt_len; i++)
  {
    salt_buf_ptr[i] = hex_to_u8((const u8 *)&salt_pos[i * 2]);
  }

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_len = salt_len;

  salt->salt_iter = atoi(iter_pos) - 1;

  return (PARSER_OK);
}

int sha512b64s_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1711) || (input_len > DISPLAY_LEN_MAX_1711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SHA512B64S, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  int tmp_len = base64_decode(base64_to_int, (const u8 *)input_buf + 9, input_len - 9, tmp_buf);

  if (tmp_len < 64) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 64);

  digest[0] = byte_swap_64(digest[0]);
  digest[1] = byte_swap_64(digest[1]);
  digest[2] = byte_swap_64(digest[2]);
  digest[3] = byte_swap_64(digest[3]);
  digest[4] = byte_swap_64(digest[4]);
  digest[5] = byte_swap_64(digest[5]);
  digest[6] = byte_swap_64(digest[6]);
  digest[7] = byte_swap_64(digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  int salt_len = tmp_len - 64;

  if (salt_len < 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy(salt->salt_buf, tmp_buf + 64, salt->salt_len);

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    char *ptr = (char *)salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int hmacmd5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_50H) || (input_len > DISPLAY_LEN_MAX_50H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_50) || (input_len > DISPLAY_LEN_MAX_50)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_150H) || (input_len > DISPLAY_LEN_MAX_150H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_150) || (input_len > DISPLAY_LEN_MAX_150)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha256_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1450H) || (input_len > DISPLAY_LEN_MAX_1450H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1450) || (input_len > DISPLAY_LEN_MAX_1450)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha512_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1750H) || (input_len > DISPLAY_LEN_MAX_1750H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1750) || (input_len > DISPLAY_LEN_MAX_1750)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u64((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u64((const u8 *)&input_buf[16]);
  digest[2] = hex_to_u64((const u8 *)&input_buf[32]);
  digest[3] = hex_to_u64((const u8 *)&input_buf[48]);
  digest[4] = hex_to_u64((const u8 *)&input_buf[64]);
  digest[5] = hex_to_u64((const u8 *)&input_buf[80]);
  digest[6] = hex_to_u64((const u8 *)&input_buf[96]);
  digest[7] = hex_to_u64((const u8 *)&input_buf[112]);

  if (input_buf[128] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 128 - 1;

  char *salt_buf = input_buf + 128 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int krb5pa_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7500) || (input_len > DISPLAY_LEN_MAX_7500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_KRB5PA, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5pa_t *krb5pa = (krb5pa_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *user_pos = input_buf + 10 + 1;

  char *realm_pos = strchr(user_pos, '$');

  if (realm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = realm_pos - user_pos;

  if (user_len >= 64) return (PARSER_SALT_LENGTH);

  realm_pos++;

  char *salt_pos = strchr(realm_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint realm_len = salt_pos - realm_pos;

  if (realm_len >= 64) return (PARSER_SALT_LENGTH);

  salt_pos++;

  char *data_pos = strchr(salt_pos, '$');

  if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = data_pos - salt_pos;

  if (salt_len >= 128) return (PARSER_SALT_LENGTH);

  data_pos++;

  uint data_len = input_len - 10 - 1 - user_len - 1 - realm_len - 1 - salt_len - 1;

  if (data_len != ((36 + 16) * 2)) return (PARSER_SALT_LENGTH);

  /**
  * copy data
  */

  memcpy(krb5pa->user, user_pos, user_len);
  memcpy(krb5pa->realm, realm_pos, realm_len);
  memcpy(krb5pa->salt, salt_pos, salt_len);

  char *timestamp_ptr = (char *)krb5pa->timestamp;

  for (uint i = 0; i < (36 * 2); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *timestamp_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  char *checksum_ptr = (char *)krb5pa->checksum;

  for (uint i = (36 * 2); i < ((36 + 16) * 2); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /**
  * copy some data to generic buffers to make sorting happy
  */

  salt->salt_buf[0] = krb5pa->timestamp[0];
  salt->salt_buf[1] = krb5pa->timestamp[1];
  salt->salt_buf[2] = krb5pa->timestamp[2];
  salt->salt_buf[3] = krb5pa->timestamp[3];
  salt->salt_buf[4] = krb5pa->timestamp[4];
  salt->salt_buf[5] = krb5pa->timestamp[5];
  salt->salt_buf[6] = krb5pa->timestamp[6];
  salt->salt_buf[7] = krb5pa->timestamp[7];
  salt->salt_buf[8] = krb5pa->timestamp[8];

  salt->salt_len = 36;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = krb5pa->checksum[3];

  return (PARSER_OK);
}

int sapb_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7700) || (input_len > DISPLAY_LEN_MAX_7700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *salt_pos = input_buf;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  uint hash_len = input_len - 1 - salt_len;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  /**
  * valid some data
  */

  uint user_len = 0;

  for (uint i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
  * copy data
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  return (PARSER_OK);
}

int sapg_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7800) || (input_len > DISPLAY_LEN_MAX_7800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *salt_pos = input_buf;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  uint hash_len = input_len - 1 - salt_len;

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  /**
  * valid some data
  */

  uint user_len = 0;

  for (uint i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  // this is kinda buggy. if the username is in utf the length can be up to length 12*3
  // so far nobody complained so we stay with this because it helps in optimization
  // final string can have a max size of 32 (password) + (10 * 5) = lengthMagicArray + 12 (max salt) + 1 (the 0x80)

  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
  * copy data
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  return (PARSER_OK);
}

int drupal7_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7900) || (input_len > DISPLAY_LEN_MAX_7900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_DRUPAL7, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 3;

  uint salt_iter = 1u << itoa64_to_int(iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy((char *)salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  char *salt_pos = iter_pos + 1;

  uint salt_len = 8;

  memcpy((char *)salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char *hash_pos = salt_pos + salt_len;

  drupal7_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  // ugly hack start

  char *tmp = (char *)salt->salt_buf_pc;

  tmp[0] = hash_pos[42];

  // ugly hack end

  digest[0] = byte_swap_64(digest[0]);
  digest[1] = byte_swap_64(digest[1]);
  digest[2] = byte_swap_64(digest[2]);
  digest[3] = byte_swap_64(digest[3]);
  digest[4] = 0;
  digest[5] = 0;
  digest[6] = 0;
  digest[7] = 0;

  return (PARSER_OK);
}

int sybasease_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8000) || (input_len > DISPLAY_LEN_MAX_8000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SYBASEASE, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 16;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 16;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hash_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hash_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hash_pos[56]);

  return (PARSER_OK);
}

int mysql323_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_200) || (input_len > DISPLAY_LEN_MAX_200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rakp_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7300) || (input_len > DISPLAY_LEN_MAX_7300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rakp_t *rakp = (rakp_t *)hash_buf->esalt;

  char *saltbuf_pos = input_buf;

  char *hashbuf_pos = strchr(saltbuf_pos, ':');

  if (hashbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = hashbuf_pos - saltbuf_pos;

  if (saltbuf_len <  64) return (PARSER_SALT_LENGTH);
  if (saltbuf_len > 512) return (PARSER_SALT_LENGTH);

  if (saltbuf_len & 1) return (PARSER_SALT_LENGTH); // muss gerade sein wegen hex

  hashbuf_pos++;

  uint hashbuf_len = input_len - saltbuf_len - 1;

  if (hashbuf_len != 40) return (PARSER_HASH_LENGTH);

  char *salt_ptr = (char *)saltbuf_pos;
  char *rakp_ptr = (char *)rakp->salt_buf;

  uint i;
  uint j;

  for (i = 0, j = 0; i < saltbuf_len; i += 2, j += 1)
  {
    rakp_ptr[j] = hex_to_u8((const u8 *)&salt_ptr[i]);
  }

  rakp_ptr[j] = 0x80;

  rakp->salt_len = j;

  for (i = 0; i < 64; i++)
  {
    rakp->salt_buf[i] = byte_swap_32(rakp->salt_buf[i]);
  }

  salt->salt_buf[0] = rakp->salt_buf[0];
  salt->salt_buf[1] = rakp->salt_buf[1];
  salt->salt_buf[2] = rakp->salt_buf[2];
  salt->salt_buf[3] = rakp->salt_buf[3];
  salt->salt_buf[4] = rakp->salt_buf[4];
  salt->salt_buf[5] = rakp->salt_buf[5];
  salt->salt_buf[6] = rakp->salt_buf[6];
  salt->salt_buf[7] = rakp->salt_buf[7];

  salt->salt_len = 32; // muss min. 32 haben

  digest[0] = hex_to_u32((const u8 *)&hashbuf_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hashbuf_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hashbuf_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hashbuf_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hashbuf_pos[32]);

  return (PARSER_OK);
}

int netscaler_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8100) || (input_len > DISPLAY_LEN_MAX_8100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (memcmp(SIGNATURE_NETSCALER, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  char *salt_pos = input_buf + 1;

  memcpy(salt->salt_buf, salt_pos, 8);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);

  salt->salt_len = 8;

  char *hash_pos = salt_pos + 8;

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int chap_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_4800) || (input_len > DISPLAY_LEN_MAX_4800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *salt_buf_ptr = input_buf + 32 + 1;

  u32 *salt_buf = salt->salt_buf;

  salt_buf[0] = hex_to_u32((const u8 *)&salt_buf_ptr[0]);
  salt_buf[1] = hex_to_u32((const u8 *)&salt_buf_ptr[8]);
  salt_buf[2] = hex_to_u32((const u8 *)&salt_buf_ptr[16]);
  salt_buf[3] = hex_to_u32((const u8 *)&salt_buf_ptr[24]);

  salt_buf[0] = byte_swap_32(salt_buf[0]);
  salt_buf[1] = byte_swap_32(salt_buf[1]);
  salt_buf[2] = byte_swap_32(salt_buf[2]);
  salt_buf[3] = byte_swap_32(salt_buf[3]);

  salt->salt_len = 16 + 1;

  if (input_buf[65] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *idbyte_buf_ptr = input_buf + 32 + 1 + 32 + 1;

  salt_buf[4] = hex_to_u8((const u8 *)&idbyte_buf_ptr[0]) & 0xff;

  return (PARSER_OK);
}

int cloudkey_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8200) || (input_len > DISPLAY_LEN_MAX_8200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  cloudkey_t *cloudkey = (cloudkey_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *hashbuf_pos = input_buf;

  char *saltbuf_pos = strchr(hashbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint hashbuf_len = saltbuf_pos - hashbuf_pos;

  if (hashbuf_len != 64) return (PARSER_HASH_LENGTH);

  saltbuf_pos++;

  char *iteration_pos = strchr(saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  char *databuf_pos = strchr(iteration_pos, ':');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint iteration_len = databuf_pos - iteration_pos;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 8) return (PARSER_SALT_ITERATION);

  const uint databuf_len = input_len - hashbuf_len - 1 - saltbuf_len - 1 - iteration_len - 1;

  if (databuf_len <    1) return (PARSER_SALT_LENGTH);
  if (databuf_len > 2048) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  // digest

  digest[0] = hex_to_u32((const u8 *)&hashbuf_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hashbuf_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hashbuf_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hashbuf_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hashbuf_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hashbuf_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hashbuf_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hashbuf_pos[56]);

  // salt

  char *saltbuf_ptr = (char *)salt->salt_buf;

  for (uint i = 0; i < saltbuf_len; i += 2)
  {
    const char p0 = saltbuf_pos[i + 0];
    const char p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  salt->salt_buf[4] = 0x01000000;
  salt->salt_buf[5] = 0x80;

  salt->salt_len = saltbuf_len / 2;

  // iteration

  salt->salt_iter = atoi(iteration_pos) - 1;

  // data

  char *databuf_ptr = (char *)cloudkey->data_buf;

  for (uint i = 0; i < databuf_len; i += 2)
  {
    const char p0 = databuf_pos[i + 0];
    const char p1 = databuf_pos[i + 1];

    *databuf_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  *databuf_ptr++ = 0x80;

  for (uint i = 0; i < 512; i++)
  {
    cloudkey->data_buf[i] = byte_swap_32(cloudkey->data_buf[i]);
  }

  cloudkey->data_len = databuf_len / 2;

  return (PARSER_OK);
}

int nsec3_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8300) || (input_len > DISPLAY_LEN_MAX_8300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *hashbuf_pos = input_buf;

  char *domainbuf_pos = strchr(hashbuf_pos, ':');

  if (domainbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint hashbuf_len = domainbuf_pos - hashbuf_pos;

  if (hashbuf_len != 32) return (PARSER_HASH_LENGTH);

  domainbuf_pos++;

  if (domainbuf_pos[0] != '.') return (PARSER_SALT_VALUE);

  char *saltbuf_pos = strchr(domainbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint domainbuf_len = saltbuf_pos - domainbuf_pos;

  if (domainbuf_len >= 32) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *iteration_pos = strchr(saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len >= 28) return (PARSER_SALT_LENGTH); // 28 = 32 - 4; 4 = length

  if ((domainbuf_len + saltbuf_len) >= 48) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  const uint iteration_len = input_len - hashbuf_len - 1 - domainbuf_len - 1 - saltbuf_len - 1;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 5) return (PARSER_SALT_ITERATION);

  // ok, the plan for this algorithm is the following:
  // we have 2 salts here, the domain-name and a random salt
  // while both are used in the initial transformation,
  // only the random salt is used in the following iterations
  // so we create two buffer, one that includes domain-name (stored into salt_buf_pc[])
  // and one that includes only the real salt (stored into salt_buf[]).
  // the domain-name length is put into array position 7 of salt_buf_pc[] since there is not salt_pc_len

  u8 tmp_buf[100] = { 0 };

  base32_decode(itoa32_to_int, (const u8 *)hashbuf_pos, 32, tmp_buf);

  memcpy(digest, tmp_buf, 20);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  // domain

  char *salt_buf_pc_ptr = (char *)salt->salt_buf_pc;

  memcpy(salt_buf_pc_ptr, domainbuf_pos, domainbuf_len);

  char *len_ptr = NULL;

  for (uint i = 0; i < domainbuf_len; i++)
  {
    if (salt_buf_pc_ptr[i] == '.')
    {
      len_ptr = &salt_buf_pc_ptr[i];

      *len_ptr = 0;
    }
    else
    {
      *len_ptr += 1;
    }
  }

  salt->salt_buf_pc[7] = domainbuf_len;

  // "real" salt

  char *salt_buf_ptr = (char *)salt->salt_buf;

  const uint salt_len = parse_and_store_salt(salt_buf_ptr, saltbuf_pos, saltbuf_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  // iteration

  salt->salt_iter = atoi(iteration_pos);

  return (PARSER_OK);
}

int wbb3_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8400) || (input_len > DISPLAY_LEN_MAX_8400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int opencart_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13900) || (input_len > DISPLAY_LEN_MAX_13900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if ((salt_len != 9) || (salt_len == UINT_MAX)) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int racf_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  const u8 ascii_to_ebcdic[] =
  {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
    0x40, 0x4f, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0x4a, 0xe0, 0x5a, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x6a, 0xd0, 0xa1, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
    0x9f, 0xa0, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  };

  if ((input_len < DISPLAY_LEN_MIN_8500) || (input_len > DISPLAY_LEN_MAX_8500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_RACF, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6 + 1;

  char *digest_pos = strchr(salt_pos, '*');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  uint hash_len = input_len - 1 - salt_len - 1 - 6;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  digest_pos++;

  char *salt_buf_ptr = (char *)salt->salt_buf;
  char *salt_buf_pc_ptr = (char *)salt->salt_buf_pc;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  for (uint i = 0; i < salt_len; i++)
  {
    salt_buf_pc_ptr[i] = ascii_to_ebcdic[(int)salt_buf_ptr[i]];
  }
  for (uint i = salt_len; i < 8; i++)
  {
    salt_buf_pc_ptr[i] = 0x40;
  }

  uint tt;

  IP(&salt->salt_buf_pc[0], &salt->salt_buf_pc[1], &tt);

  salt->salt_buf_pc[0] = rotl32(salt->salt_buf_pc[0], 3u);
  salt->salt_buf_pc[1] = rotl32(salt->salt_buf_pc[1], 3u);

  digest[0] = hex_to_u32((const u8 *)&digest_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&digest_pos[8]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  IP(&digest[0], &digest[1], &tt);

  digest[0] = rotr32(digest[0], 29);
  digest[1] = rotr32(digest[1], 29);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int lotus5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8600) || (input_len > DISPLAY_LEN_MAX_8600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  return (PARSER_OK);
}

int lotus6_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8700) || (input_len > DISPLAY_LEN_MAX_8700)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'G') || (input_buf[21] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode(lotus64_to_int, (const u8 *)input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  memcpy(salt->salt_buf, tmp_buf, 5);

  salt->salt_len = 5;

  memcpy(digest, tmp_buf + 5, 9);

  // yes, only 9 byte are needed to crack, but 10 to display

  salt->salt_buf_pc[7] = input_buf[20];

  return (PARSER_OK);
}

int lotus8_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9100) || (input_len > DISPLAY_LEN_MAX_9100)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'H') || (input_buf[DISPLAY_LEN_MAX_9100 - 1] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode(lotus64_to_int, (const u8 *)input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

                    // salt

  memcpy(salt->salt_buf, tmp_buf, 16);

  salt->salt_len = 16; // Attention: in theory we have 2 salt_len, one for the -m 8700 part (len: 8), 2nd for the 9100 part (len: 16)

                       // iteration

  char tmp_iter_buf[11] = { 0 };

  memcpy(tmp_iter_buf, tmp_buf + 16, 10);

  tmp_iter_buf[10] = 0;

  salt->salt_iter = atoi(tmp_iter_buf);

  if (salt->salt_iter < 1) // well, the limit hopefully is much higher
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter--; // first round in init

                     // 2 additional bytes for display only

  salt->salt_buf_pc[0] = tmp_buf[26];
  salt->salt_buf_pc[1] = tmp_buf[27];

  // digest

  memcpy(digest, tmp_buf + 28, 8);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int hmailserver_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1421) || (input_len > DISPLAY_LEN_MAX_1421)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf_pos = input_buf;

  char *hash_buf_pos = salt_buf_pos + 6;

  digest[0] = hex_to_u32((const u8 *)&hash_buf_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_buf_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_buf_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_buf_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_buf_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hash_buf_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hash_buf_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hash_buf_pos[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  const uint salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf_pos, 6);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int phps_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2612) || (input_len > DISPLAY_LEN_MAX_2612)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  if (memcmp(SIGNATURE_PHPS, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  char *digest_buf = strchr(salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32((const u8 *)&digest_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&digest_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&digest_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&digest_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int mediawiki_b_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3711) || (input_len > DISPLAY_LEN_MAX_3711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MEDIAWIKI_B, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 3;

  char *digest_buf = strchr(salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len] = 0x2d;

  salt->salt_len = salt_len + 1;

  digest[0] = hex_to_u32((const u8 *)&digest_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&digest_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&digest_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&digest_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int peoplesoft_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_133) || (input_len > DISPLAY_LEN_MAX_133)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  base64_decode(base64_to_int, (const u8 *)input_buf, input_len, tmp_buf);

  memcpy(digest, tmp_buf, 20);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  salt->salt_buf[0] = 0x80;

  salt->salt_len = 0;

  return (PARSER_OK);
}

int skype_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_23) || (input_len > DISPLAY_LEN_MAX_23)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  /*
  * add static "salt" part
  */

  memcpy(salt_buf_ptr + salt_len, "\nskyper\n", 8);

  salt_len += 8;

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int androidfde_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8800) || (input_len > DISPLAY_LEN_MAX_8800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_ANDROIDFDE, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  androidfde_t *androidfde = (androidfde_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *saltlen_pos = input_buf + 1 + 3 + 1;

  char *saltbuf_pos = strchr(saltlen_pos, '$');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltlen_len = saltbuf_pos - saltlen_pos;

  if (saltlen_len != 2) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *keylen_pos = strchr(saltbuf_pos, '$');

  if (keylen_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = keylen_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  keylen_pos++;

  char *keybuf_pos = strchr(keylen_pos, '$');

  if (keybuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint keylen_len = keybuf_pos - keylen_pos;

  if (keylen_len != 2) return (PARSER_SALT_LENGTH);

  keybuf_pos++;

  char *databuf_pos = strchr(keybuf_pos, '$');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint keybuf_len = databuf_pos - keybuf_pos;

  if (keybuf_len != 32) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  uint data_len = input_len - 1 - 3 - 1 - saltlen_len - 1 - saltbuf_len - 1 - keylen_len - 1 - keybuf_len - 1;

  if (data_len != 3072) return (PARSER_SALT_LENGTH);

  /**
  * copy data
  */

  digest[0] = hex_to_u32((const u8 *)&keybuf_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&keybuf_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&keybuf_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&keybuf_pos[24]);

  salt->salt_buf[0] = hex_to_u32((const u8 *)&saltbuf_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&saltbuf_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&saltbuf_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&saltbuf_pos[24]);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  salt->salt_len = 16;
  salt->salt_iter = ROUNDS_ANDROIDFDE - 1;

  for (uint i = 0, j = 0; i < 3072; i += 8, j += 1)
  {
    androidfde->data[j] = hex_to_u32((const u8 *)&databuf_pos[i]);
  }

  return (PARSER_OK);
}

int scrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8900) || (input_len > DISPLAY_LEN_MAX_8900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SCRYPT, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  // first is the N salt parameter

  char *N_pos = input_buf + 6;

  if (N_pos[0] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  N_pos++;

  salt->scrypt_N = atoi(N_pos);

  // r

  char *r_pos = strchr(N_pos, ':');

  if (r_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  r_pos++;

  salt->scrypt_r = atoi(r_pos);

  // p

  char *p_pos = strchr(r_pos, ':');

  if (p_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  p_pos++;

  salt->scrypt_p = atoi(p_pos);

  // salt

  char *saltbuf_pos = strchr(p_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  saltbuf_pos++;

  char *hash_pos = strchr(saltbuf_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  // base64 decode

  int salt_len_base64 = hash_pos - saltbuf_pos;

  if (salt_len_base64 > 45) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[33] = { 0 };

  int tmp_len = base64_decode(base64_to_int, (const u8 *)saltbuf_pos, salt_len_base64, tmp_buf);

  char *salt_buf_ptr = (char *)salt->salt_buf;

  memcpy(salt_buf_ptr, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;
  salt->salt_iter = 1;

  // digest - base64 decode

  memset(tmp_buf, 0, sizeof(tmp_buf));

  tmp_len = input_len - (hash_pos - input_buf);

  if (tmp_len != 44) return (PARSER_GLOBAL_LENGTH);

  base64_decode(base64_to_int, (const u8 *)hash_pos, tmp_len, tmp_buf);

  memcpy(digest, tmp_buf, 32);

  return (PARSER_OK);
}

int juniper_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_501) || (input_len > DISPLAY_LEN_MAX_501)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char decrypted[76] = { 0 }; // iv + hash

  juniper_decrypt_hash(input_buf, decrypted);

  char *md5crypt_hash = decrypted + 12;

  if (memcmp(md5crypt_hash, "$1$danastre$", 12)) return (PARSER_SALT_VALUE);

  salt->salt_iter = ROUNDS_MD5CRYPT;

  char *salt_pos = md5crypt_hash + 3;

  char *hash_pos = strchr(salt_pos, '$'); // or simply salt_pos + 8

  salt->salt_len = hash_pos - salt_pos;    // should be 8

  memcpy((char *)salt->salt_buf, salt_pos, salt->salt_len);

  hash_pos++;

  md5crypt_decode((unsigned char *)digest, (unsigned char *)hash_pos);

  return (PARSER_OK);
}

int cisco8_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9200) || (input_len > DISPLAY_LEN_MAX_9200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_CISCO8, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *)hash_buf->esalt;

  /**
  * parse line
  */

  // first is *raw* salt

  char *salt_pos = input_buf + 3;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *salt_buf_ptr = (char *)pbkdf2_sha256->salt_buf;

  memcpy(salt_buf_ptr, salt_pos, 14);

  salt_buf_ptr[17] = 0x01;
  salt_buf_ptr[18] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];

  salt->salt_len = salt_len;
  salt->salt_iter = ROUNDS_CISCO8 - 1;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode(itoa64_to_int, (const u8 *)hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 32);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int cisco9_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9300) || (input_len > DISPLAY_LEN_MAX_9300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_CISCO9, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  // first is *raw* salt

  char *salt_pos = input_buf + 3;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;
  hash_pos++;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  memcpy(salt_buf_ptr, salt_pos, salt_len);
  salt_buf_ptr[salt_len] = 0;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode(itoa64_to_int, (const u8 *)hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 32);

  // fixed:
  salt->scrypt_N = 16384;
  salt->scrypt_r = 1;
  salt->scrypt_p = 1;
  salt->salt_iter = 1;

  return (PARSER_OK);
}

int office2007_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9400) || (input_len > DISPLAY_LEN_MAX_9400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_OFFICE2007, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2007_t *office2007 = (office2007_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 8 + 1;

  char *verifierHashSize_pos = strchr(version_pos, '*');

  if (verifierHashSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = verifierHashSize_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  verifierHashSize_pos++;

  char *keySize_pos = strchr(verifierHashSize_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 verifierHashSize_len = keySize_pos - verifierHashSize_pos;

  if (verifierHashSize_len != 2) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr(keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr(saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - verifierHashSize_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  const uint version = atoi(version_pos);

  if (version != 2007) return (PARSER_SALT_VALUE);

  const uint verifierHashSize = atoi(verifierHashSize_pos);

  if (verifierHashSize != 20) return (PARSER_SALT_VALUE);

  const uint keySize = atoi(keySize_pos);

  if ((keySize != 128) && (keySize != 256)) return (PARSER_SALT_VALUE);

  office2007->keySize = keySize;

  const uint saltSize = atoi(saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
  * salt
  */

  salt->salt_len = 16;
  salt->salt_iter = ROUNDS_OFFICE2007;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  /**
  * esalt
  */

  office2007->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  office2007->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  office2007->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  office2007->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  office2007->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  office2007->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  office2007->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  office2007->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);
  office2007->encryptedVerifierHash[4] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[32]);

  /**
  * digest
  */

  digest[0] = office2007->encryptedVerifierHash[0];
  digest[1] = office2007->encryptedVerifierHash[1];
  digest[2] = office2007->encryptedVerifierHash[2];
  digest[3] = office2007->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2010_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9500) || (input_len > DISPLAY_LEN_MAX_9500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_OFFICE2010, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2010_t *office2010 = (office2010_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 8 + 1;

  char *spinCount_pos = strchr(version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  spinCount_pos++;

  char *keySize_pos = strchr(spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  if (spinCount_len != 6) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr(keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr(saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  const uint version = atoi(version_pos);

  if (version != 2010) return (PARSER_SALT_VALUE);

  const uint spinCount = atoi(spinCount_pos);

  if (spinCount != 100000) return (PARSER_SALT_VALUE);

  const uint keySize = atoi(keySize_pos);

  if (keySize != 128) return (PARSER_SALT_VALUE);

  const uint saltSize = atoi(saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
  * salt
  */

  salt->salt_len = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  /**
  * esalt
  */

  office2010->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  office2010->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  office2010->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  office2010->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  office2010->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  office2010->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  office2010->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  office2010->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);
  office2010->encryptedVerifierHash[4] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[32]);
  office2010->encryptedVerifierHash[5] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[40]);
  office2010->encryptedVerifierHash[6] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[48]);
  office2010->encryptedVerifierHash[7] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[56]);

  /**
  * digest
  */

  digest[0] = office2010->encryptedVerifierHash[0];
  digest[1] = office2010->encryptedVerifierHash[1];
  digest[2] = office2010->encryptedVerifierHash[2];
  digest[3] = office2010->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2013_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9600) || (input_len > DISPLAY_LEN_MAX_9600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_OFFICE2013, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2013_t *office2013 = (office2013_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 8 + 1;

  char *spinCount_pos = strchr(version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  spinCount_pos++;

  char *keySize_pos = strchr(spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  if (spinCount_len != 6) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr(keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr(saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  const uint version = atoi(version_pos);

  if (version != 2013) return (PARSER_SALT_VALUE);

  const uint spinCount = atoi(spinCount_pos);

  if (spinCount != 100000) return (PARSER_SALT_VALUE);

  const uint keySize = atoi(keySize_pos);

  if (keySize != 256) return (PARSER_SALT_VALUE);

  const uint saltSize = atoi(saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
  * salt
  */

  salt->salt_len = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  /**
  * esalt
  */

  office2013->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  office2013->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  office2013->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  office2013->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  office2013->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  office2013->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  office2013->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  office2013->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);
  office2013->encryptedVerifierHash[4] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[32]);
  office2013->encryptedVerifierHash[5] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[40]);
  office2013->encryptedVerifierHash[6] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[48]);
  office2013->encryptedVerifierHash[7] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[56]);

  /**
  * digest
  */

  digest[0] = office2013->encryptedVerifierHash[0];
  digest[1] = office2013->encryptedVerifierHash[1];
  digest[2] = office2013->encryptedVerifierHash[2];
  digest[3] = office2013->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9700) || (input_len > DISPLAY_LEN_MAX_9700)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp(SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr(version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
  * esalt
  */

  oldoffice01->version = version;

  oldoffice01->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  oldoffice01->encryptedVerifier[0] = byte_swap_32(oldoffice01->encryptedVerifier[0]);
  oldoffice01->encryptedVerifier[1] = byte_swap_32(oldoffice01->encryptedVerifier[1]);
  oldoffice01->encryptedVerifier[2] = byte_swap_32(oldoffice01->encryptedVerifier[2]);
  oldoffice01->encryptedVerifier[3] = byte_swap_32(oldoffice01->encryptedVerifier[3]);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);

  oldoffice01->encryptedVerifierHash[0] = byte_swap_32(oldoffice01->encryptedVerifierHash[0]);
  oldoffice01->encryptedVerifierHash[1] = byte_swap_32(oldoffice01->encryptedVerifierHash[1]);
  oldoffice01->encryptedVerifierHash[2] = byte_swap_32(oldoffice01->encryptedVerifierHash[2]);
  oldoffice01->encryptedVerifierHash[3] = byte_swap_32(oldoffice01->encryptedVerifierHash[3]);

  /**
  * salt
  */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
  * digest
  */

  digest[0] = oldoffice01->encryptedVerifierHash[0];
  digest[1] = oldoffice01->encryptedVerifierHash[1];
  digest[2] = oldoffice01->encryptedVerifierHash[2];
  digest[3] = oldoffice01->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01cm1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  return oldoffice01_parse_hash(input_buf, input_len, hash_buf);
}

int oldoffice01cm2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9720) || (input_len > DISPLAY_LEN_MAX_9720)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp(SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr(version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  char *rc4key_pos = strchr(encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
  * esalt
  */

  oldoffice01->version = version;

  oldoffice01->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  oldoffice01->encryptedVerifier[0] = byte_swap_32(oldoffice01->encryptedVerifier[0]);
  oldoffice01->encryptedVerifier[1] = byte_swap_32(oldoffice01->encryptedVerifier[1]);
  oldoffice01->encryptedVerifier[2] = byte_swap_32(oldoffice01->encryptedVerifier[2]);
  oldoffice01->encryptedVerifier[3] = byte_swap_32(oldoffice01->encryptedVerifier[3]);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);

  oldoffice01->encryptedVerifierHash[0] = byte_swap_32(oldoffice01->encryptedVerifierHash[0]);
  oldoffice01->encryptedVerifierHash[1] = byte_swap_32(oldoffice01->encryptedVerifierHash[1]);
  oldoffice01->encryptedVerifierHash[2] = byte_swap_32(oldoffice01->encryptedVerifierHash[2]);
  oldoffice01->encryptedVerifierHash[3] = byte_swap_32(oldoffice01->encryptedVerifierHash[3]);

  oldoffice01->rc4key[1] = 0;
  oldoffice01->rc4key[0] = 0;

  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[0]) << 28;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[1]) << 24;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[2]) << 20;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[3]) << 16;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[4]) << 12;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[5]) << 8;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[6]) << 4;
  oldoffice01->rc4key[0] |= hex_convert(rc4key_pos[7]) << 0;
  oldoffice01->rc4key[1] |= hex_convert(rc4key_pos[8]) << 28;
  oldoffice01->rc4key[1] |= hex_convert(rc4key_pos[9]) << 24;

  oldoffice01->rc4key[0] = byte_swap_32(oldoffice01->rc4key[0]);
  oldoffice01->rc4key[1] = byte_swap_32(oldoffice01->rc4key[1]);

  /**
  * salt
  */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
  * digest
  */

  digest[0] = oldoffice01->rc4key[0];
  digest[1] = oldoffice01->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int oldoffice34_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9800) || (input_len > DISPLAY_LEN_MAX_9800)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_OLDOFFICE3, input_buf, 12)) && (memcmp(SIGNATURE_OLDOFFICE4, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr(version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
  * esalt
  */

  oldoffice34->version = version;

  oldoffice34->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  oldoffice34->encryptedVerifier[0] = byte_swap_32(oldoffice34->encryptedVerifier[0]);
  oldoffice34->encryptedVerifier[1] = byte_swap_32(oldoffice34->encryptedVerifier[1]);
  oldoffice34->encryptedVerifier[2] = byte_swap_32(oldoffice34->encryptedVerifier[2]);
  oldoffice34->encryptedVerifier[3] = byte_swap_32(oldoffice34->encryptedVerifier[3]);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[32]);

  oldoffice34->encryptedVerifierHash[0] = byte_swap_32(oldoffice34->encryptedVerifierHash[0]);
  oldoffice34->encryptedVerifierHash[1] = byte_swap_32(oldoffice34->encryptedVerifierHash[1]);
  oldoffice34->encryptedVerifierHash[2] = byte_swap_32(oldoffice34->encryptedVerifierHash[2]);
  oldoffice34->encryptedVerifierHash[3] = byte_swap_32(oldoffice34->encryptedVerifierHash[3]);
  oldoffice34->encryptedVerifierHash[4] = byte_swap_32(oldoffice34->encryptedVerifierHash[4]);

  /**
  * salt
  */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
  * digest
  */

  digest[0] = oldoffice34->encryptedVerifierHash[0];
  digest[1] = oldoffice34->encryptedVerifierHash[1];
  digest[2] = oldoffice34->encryptedVerifierHash[2];
  digest[3] = oldoffice34->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice34cm1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp(SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  return oldoffice34_parse_hash(input_buf, input_len, hash_buf);
}

int oldoffice34cm2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9820) || (input_len > DISPLAY_LEN_MAX_9820)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr(version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr(osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr(encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  char *rc4key_pos = strchr(encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
  * esalt
  */

  oldoffice34->version = version;

  oldoffice34->encryptedVerifier[0] = hex_to_u32((const u8 *)&encryptedVerifier_pos[0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32((const u8 *)&encryptedVerifier_pos[8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32((const u8 *)&encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32((const u8 *)&encryptedVerifier_pos[24]);

  oldoffice34->encryptedVerifier[0] = byte_swap_32(oldoffice34->encryptedVerifier[0]);
  oldoffice34->encryptedVerifier[1] = byte_swap_32(oldoffice34->encryptedVerifier[1]);
  oldoffice34->encryptedVerifier[2] = byte_swap_32(oldoffice34->encryptedVerifier[2]);
  oldoffice34->encryptedVerifier[3] = byte_swap_32(oldoffice34->encryptedVerifier[3]);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32((const u8 *)&encryptedVerifierHash_pos[32]);

  oldoffice34->encryptedVerifierHash[0] = byte_swap_32(oldoffice34->encryptedVerifierHash[0]);
  oldoffice34->encryptedVerifierHash[1] = byte_swap_32(oldoffice34->encryptedVerifierHash[1]);
  oldoffice34->encryptedVerifierHash[2] = byte_swap_32(oldoffice34->encryptedVerifierHash[2]);
  oldoffice34->encryptedVerifierHash[3] = byte_swap_32(oldoffice34->encryptedVerifierHash[3]);
  oldoffice34->encryptedVerifierHash[4] = byte_swap_32(oldoffice34->encryptedVerifierHash[4]);

  oldoffice34->rc4key[1] = 0;
  oldoffice34->rc4key[0] = 0;

  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[0]) << 28;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[1]) << 24;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[2]) << 20;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[3]) << 16;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[4]) << 12;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[5]) << 8;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[6]) << 4;
  oldoffice34->rc4key[0] |= hex_convert(rc4key_pos[7]) << 0;
  oldoffice34->rc4key[1] |= hex_convert(rc4key_pos[8]) << 28;
  oldoffice34->rc4key[1] |= hex_convert(rc4key_pos[9]) << 24;

  oldoffice34->rc4key[0] = byte_swap_32(oldoffice34->rc4key[0]);
  oldoffice34->rc4key[1] = byte_swap_32(oldoffice34->rc4key[1]);

  /**
  * salt
  */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&osalt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&osalt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
  * digest
  */

  digest[0] = oldoffice34->rc4key[0];
  digest[1] = oldoffice34->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int radmin2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9900) || (input_len > DISPLAY_LEN_MAX_9900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  return (PARSER_OK);
}

int djangosha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_124) || (input_len > DISPLAY_LEN_MAX_124)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_DJANGOSHA1, input_buf, 5)) && (memcmp(SIGNATURE_DJANGOSHA1, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *signature_pos = input_buf;

  char *salt_pos = strchr(signature_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 signature_len = salt_pos - signature_pos;

  if (signature_len != 4) return (PARSER_SIGNATURE_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - signature_len - 1 - salt_len - 1;

  if (hash_len != 40) return (PARSER_SALT_LENGTH);

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  memcpy(salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int djangopbkdf2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10000) || (input_len > DISPLAY_LEN_MAX_10000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_DJANGOPBKDF2, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *iter_pos = input_buf + 14;

  const int iter = atoi(iter_pos);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  char *salt_pos = strchr(iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint salt_len = hash_pos - salt_pos;

  hash_pos++;

  char *salt_buf_ptr = (char *)pbkdf2_sha256->salt_buf;

  memcpy(salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 44) return (PARSER_HASH_LENGTH);

  base64_decode(base64_to_int, (const u8 *)hash_pos, hash_len, tmp_buf);

  memcpy(digest, tmp_buf, 32);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int siphash_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10100) || (input_len > DISPLAY_LEN_MAX_10100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[18] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[20] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char iter_c = input_buf[17];
  char iter_d = input_buf[19];

  // atm only defaults, let's see if there's more request
  if (iter_c != '2') return (PARSER_SALT_ITERATION);
  if (iter_d != '4') return (PARSER_SALT_ITERATION);

  char *salt_buf = input_buf + 16 + 1 + 1 + 1 + 1 + 1;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_buf[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_buf[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&salt_buf[24]);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int crammd5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10200) || (input_len > DISPLAY_LEN_MAX_10200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_CRAM_MD5, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  cram_md5_t *cram_md5 = (cram_md5_t *)hash_buf->esalt;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 10;

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  hash_pos++;

  uint hash_len = input_len - 10 - salt_len - 1;

  // base64 decode salt

  if (salt_len > 133) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[100] = { 0 };

  salt_len = base64_decode(base64_to_int, (const u8 *)salt_pos, salt_len, tmp_buf);

  if (salt_len > 55) return (PARSER_SALT_LENGTH);

  tmp_buf[salt_len] = 0x80;

  memcpy(&salt->salt_buf, tmp_buf, salt_len + 1);

  salt->salt_len = salt_len;

  // base64 decode hash

  if (hash_len > 133) return (PARSER_HASH_LENGTH);

  memset(tmp_buf, 0, sizeof(tmp_buf));

  hash_len = base64_decode(base64_to_int, (const u8 *)hash_pos, hash_len, tmp_buf);

  if (hash_len < 32 + 1) return (PARSER_HASH_LENGTH);

  uint user_len = hash_len - 32;

  const u8 *tmp_hash = tmp_buf + user_len;

  user_len--; // skip the trailing space

  digest[0] = hex_to_u32(&tmp_hash[0]);
  digest[1] = hex_to_u32(&tmp_hash[8]);
  digest[2] = hex_to_u32(&tmp_hash[16]);
  digest[3] = hex_to_u32(&tmp_hash[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  // store username for host only (output hash if cracked)

  memset(cram_md5->user, 0, sizeof(cram_md5->user));
  memcpy(cram_md5->user, tmp_buf, user_len);

  return (PARSER_OK);
}

int saph_sha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10300) || (input_len > DISPLAY_LEN_MAX_10300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SAPH_SHA1, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 10;

  u32 iter = atoi(iter_pos);

  if (iter < 1)
  {
    return (PARSER_SALT_ITERATION);
  }

  iter--; // first iteration is special

  salt->salt_iter = iter;

  char *base64_pos = strchr(iter_pos, '}');

  if (base64_pos == NULL)
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }

  base64_pos++;

  // base64 decode salt

  u32 base64_len = input_len - (base64_pos - input_buf);

  u8 tmp_buf[100] = { 0 };

  u32 decoded_len = base64_decode(base64_to_int, (const u8 *)base64_pos, base64_len, tmp_buf);

  if (decoded_len < 24)
  {
    return (PARSER_SALT_LENGTH);
  }

  // copy the salt

  uint salt_len = decoded_len - 20;

  if (salt_len <  4) return (PARSER_SALT_LENGTH);
  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy(&salt->salt_buf, tmp_buf + 20, salt_len);

  salt->salt_len = salt_len;

  // set digest

  u32 *digest_ptr = (u32*)tmp_buf;

  digest[0] = byte_swap_32(digest_ptr[0]);
  digest[1] = byte_swap_32(digest_ptr[1]);
  digest[2] = byte_swap_32(digest_ptr[2]);
  digest[3] = byte_swap_32(digest_ptr[3]);
  digest[4] = byte_swap_32(digest_ptr[4]);

  return (PARSER_OK);
}

int redmine_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7600) || (input_len > DISPLAY_LEN_MAX_7600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pdf11_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10400) || (input_len > DISPLAY_LEN_MAX_10400)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_PDF, input_buf, 5)) && (memcmp(SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr(V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr(R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr(bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr(P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr(enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr(id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr(id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr(u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr(u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr(o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi(V_pos);
  const int R = atoi(R_pos);
  const int P = atoi(P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi(enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi(id_len_pos);
  const int u_len = atoi(u_len_pos);
  const int o_len = atoi(o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len != 32) return (PARSER_SALT_VALUE);
  if (o_len != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi(bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32((const u8 *)&id_buf_pos[0]);
  pdf->id_buf[1] = hex_to_u32((const u8 *)&id_buf_pos[8]);
  pdf->id_buf[2] = hex_to_u32((const u8 *)&id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32((const u8 *)&id_buf_pos[24]);
  pdf->id_len = id_len;

  pdf->u_buf[0] = hex_to_u32((const u8 *)&u_buf_pos[0]);
  pdf->u_buf[1] = hex_to_u32((const u8 *)&u_buf_pos[8]);
  pdf->u_buf[2] = hex_to_u32((const u8 *)&u_buf_pos[16]);
  pdf->u_buf[3] = hex_to_u32((const u8 *)&u_buf_pos[24]);
  pdf->u_buf[4] = hex_to_u32((const u8 *)&u_buf_pos[32]);
  pdf->u_buf[5] = hex_to_u32((const u8 *)&u_buf_pos[40]);
  pdf->u_buf[6] = hex_to_u32((const u8 *)&u_buf_pos[48]);
  pdf->u_buf[7] = hex_to_u32((const u8 *)&u_buf_pos[56]);
  pdf->u_len = u_len;

  pdf->o_buf[0] = hex_to_u32((const u8 *)&o_buf_pos[0]);
  pdf->o_buf[1] = hex_to_u32((const u8 *)&o_buf_pos[8]);
  pdf->o_buf[2] = hex_to_u32((const u8 *)&o_buf_pos[16]);
  pdf->o_buf[3] = hex_to_u32((const u8 *)&o_buf_pos[24]);
  pdf->o_buf[4] = hex_to_u32((const u8 *)&o_buf_pos[32]);
  pdf->o_buf[5] = hex_to_u32((const u8 *)&o_buf_pos[40]);
  pdf->o_buf[6] = hex_to_u32((const u8 *)&o_buf_pos[48]);
  pdf->o_buf[7] = hex_to_u32((const u8 *)&o_buf_pos[56]);
  pdf->o_len = o_len;

  pdf->id_buf[0] = byte_swap_32(pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32(pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32(pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32(pdf->id_buf[3]);

  pdf->u_buf[0] = byte_swap_32(pdf->u_buf[0]);
  pdf->u_buf[1] = byte_swap_32(pdf->u_buf[1]);
  pdf->u_buf[2] = byte_swap_32(pdf->u_buf[2]);
  pdf->u_buf[3] = byte_swap_32(pdf->u_buf[3]);
  pdf->u_buf[4] = byte_swap_32(pdf->u_buf[4]);
  pdf->u_buf[5] = byte_swap_32(pdf->u_buf[5]);
  pdf->u_buf[6] = byte_swap_32(pdf->u_buf[6]);
  pdf->u_buf[7] = byte_swap_32(pdf->u_buf[7]);

  pdf->o_buf[0] = byte_swap_32(pdf->o_buf[0]);
  pdf->o_buf[1] = byte_swap_32(pdf->o_buf[1]);
  pdf->o_buf[2] = byte_swap_32(pdf->o_buf[2]);
  pdf->o_buf[3] = byte_swap_32(pdf->o_buf[3]);
  pdf->o_buf[4] = byte_swap_32(pdf->o_buf[4]);
  pdf->o_buf[5] = byte_swap_32(pdf->o_buf[5]);
  pdf->o_buf[6] = byte_swap_32(pdf->o_buf[6]);
  pdf->o_buf[7] = byte_swap_32(pdf->o_buf[7]);

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_len = pdf->id_len;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];

  return (PARSER_OK);
}

int pdf11cm1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  return pdf11_parse_hash(input_buf, input_len, hash_buf);
}

int pdf11cm2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10420) || (input_len > DISPLAY_LEN_MAX_10420)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_PDF, input_buf, 5)) && (memcmp(SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr(V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr(R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr(bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr(P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr(enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr(id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr(id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr(u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr(u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr(o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  char *rc4key_pos = strchr(o_buf_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_buf_len = rc4key_pos - o_buf_pos;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1 - o_buf_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi(V_pos);
  const int R = atoi(R_pos);
  const int P = atoi(P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi(enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi(id_len_pos);
  const int u_len = atoi(u_len_pos);
  const int o_len = atoi(o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len != 32) return (PARSER_SALT_VALUE);
  if (o_len != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi(bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32((const u8 *)&id_buf_pos[0]);
  pdf->id_buf[1] = hex_to_u32((const u8 *)&id_buf_pos[8]);
  pdf->id_buf[2] = hex_to_u32((const u8 *)&id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32((const u8 *)&id_buf_pos[24]);
  pdf->id_len = id_len;

  pdf->u_buf[0] = hex_to_u32((const u8 *)&u_buf_pos[0]);
  pdf->u_buf[1] = hex_to_u32((const u8 *)&u_buf_pos[8]);
  pdf->u_buf[2] = hex_to_u32((const u8 *)&u_buf_pos[16]);
  pdf->u_buf[3] = hex_to_u32((const u8 *)&u_buf_pos[24]);
  pdf->u_buf[4] = hex_to_u32((const u8 *)&u_buf_pos[32]);
  pdf->u_buf[5] = hex_to_u32((const u8 *)&u_buf_pos[40]);
  pdf->u_buf[6] = hex_to_u32((const u8 *)&u_buf_pos[48]);
  pdf->u_buf[7] = hex_to_u32((const u8 *)&u_buf_pos[56]);
  pdf->u_len = u_len;

  pdf->o_buf[0] = hex_to_u32((const u8 *)&o_buf_pos[0]);
  pdf->o_buf[1] = hex_to_u32((const u8 *)&o_buf_pos[8]);
  pdf->o_buf[2] = hex_to_u32((const u8 *)&o_buf_pos[16]);
  pdf->o_buf[3] = hex_to_u32((const u8 *)&o_buf_pos[24]);
  pdf->o_buf[4] = hex_to_u32((const u8 *)&o_buf_pos[32]);
  pdf->o_buf[5] = hex_to_u32((const u8 *)&o_buf_pos[40]);
  pdf->o_buf[6] = hex_to_u32((const u8 *)&o_buf_pos[48]);
  pdf->o_buf[7] = hex_to_u32((const u8 *)&o_buf_pos[56]);
  pdf->o_len = o_len;

  pdf->id_buf[0] = byte_swap_32(pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32(pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32(pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32(pdf->id_buf[3]);

  pdf->u_buf[0] = byte_swap_32(pdf->u_buf[0]);
  pdf->u_buf[1] = byte_swap_32(pdf->u_buf[1]);
  pdf->u_buf[2] = byte_swap_32(pdf->u_buf[2]);
  pdf->u_buf[3] = byte_swap_32(pdf->u_buf[3]);
  pdf->u_buf[4] = byte_swap_32(pdf->u_buf[4]);
  pdf->u_buf[5] = byte_swap_32(pdf->u_buf[5]);
  pdf->u_buf[6] = byte_swap_32(pdf->u_buf[6]);
  pdf->u_buf[7] = byte_swap_32(pdf->u_buf[7]);

  pdf->o_buf[0] = byte_swap_32(pdf->o_buf[0]);
  pdf->o_buf[1] = byte_swap_32(pdf->o_buf[1]);
  pdf->o_buf[2] = byte_swap_32(pdf->o_buf[2]);
  pdf->o_buf[3] = byte_swap_32(pdf->o_buf[3]);
  pdf->o_buf[4] = byte_swap_32(pdf->o_buf[4]);
  pdf->o_buf[5] = byte_swap_32(pdf->o_buf[5]);
  pdf->o_buf[6] = byte_swap_32(pdf->o_buf[6]);
  pdf->o_buf[7] = byte_swap_32(pdf->o_buf[7]);

  pdf->rc4key[1] = 0;
  pdf->rc4key[0] = 0;

  pdf->rc4key[0] |= hex_convert(rc4key_pos[0]) << 28;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[1]) << 24;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[2]) << 20;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[3]) << 16;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[4]) << 12;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[5]) << 8;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[6]) << 4;
  pdf->rc4key[0] |= hex_convert(rc4key_pos[7]) << 0;
  pdf->rc4key[1] |= hex_convert(rc4key_pos[8]) << 28;
  pdf->rc4key[1] |= hex_convert(rc4key_pos[9]) << 24;

  pdf->rc4key[0] = byte_swap_32(pdf->rc4key[0]);
  pdf->rc4key[1] = byte_swap_32(pdf->rc4key[1]);

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len = pdf->id_len + 16;

  digest[0] = pdf->rc4key[0];
  digest[1] = pdf->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf14_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10500) || (input_len > DISPLAY_LEN_MAX_10500)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_PDF, input_buf, 5)) && (memcmp(SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr(V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr(R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr(bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr(P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr(enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr(id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr(id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if ((id_buf_len != 32) && (id_buf_len != 64)) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr(u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr(u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr(o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi(V_pos);
  const int R = atoi(R_pos);
  const int P = atoi(P_pos);

  int vr_ok = 0;

  if ((V == 2) && (R == 3)) vr_ok = 1;
  if ((V == 4) && (R == 4)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int id_len = atoi(id_len_pos);
  const int u_len = atoi(u_len_pos);
  const int o_len = atoi(o_len_pos);

  if ((id_len != 16) && (id_len != 32)) return (PARSER_SALT_VALUE);

  if (u_len != 32) return (PARSER_SALT_VALUE);
  if (o_len != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi(bits_pos);

  if (bits != 128) return (PARSER_SALT_VALUE);

  int enc_md = 1;

  if (R >= 4)
  {
    enc_md = atoi(enc_md_pos);
  }

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32((const u8 *)&id_buf_pos[0]);
  pdf->id_buf[1] = hex_to_u32((const u8 *)&id_buf_pos[8]);
  pdf->id_buf[2] = hex_to_u32((const u8 *)&id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32((const u8 *)&id_buf_pos[24]);

  if (id_len == 32)
  {
    pdf->id_buf[4] = hex_to_u32((const u8 *)&id_buf_pos[32]);
    pdf->id_buf[5] = hex_to_u32((const u8 *)&id_buf_pos[40]);
    pdf->id_buf[6] = hex_to_u32((const u8 *)&id_buf_pos[48]);
    pdf->id_buf[7] = hex_to_u32((const u8 *)&id_buf_pos[56]);
  }

  pdf->id_len = id_len;

  pdf->u_buf[0] = hex_to_u32((const u8 *)&u_buf_pos[0]);
  pdf->u_buf[1] = hex_to_u32((const u8 *)&u_buf_pos[8]);
  pdf->u_buf[2] = hex_to_u32((const u8 *)&u_buf_pos[16]);
  pdf->u_buf[3] = hex_to_u32((const u8 *)&u_buf_pos[24]);
  pdf->u_buf[4] = hex_to_u32((const u8 *)&u_buf_pos[32]);
  pdf->u_buf[5] = hex_to_u32((const u8 *)&u_buf_pos[40]);
  pdf->u_buf[6] = hex_to_u32((const u8 *)&u_buf_pos[48]);
  pdf->u_buf[7] = hex_to_u32((const u8 *)&u_buf_pos[56]);
  pdf->u_len = u_len;

  pdf->o_buf[0] = hex_to_u32((const u8 *)&o_buf_pos[0]);
  pdf->o_buf[1] = hex_to_u32((const u8 *)&o_buf_pos[8]);
  pdf->o_buf[2] = hex_to_u32((const u8 *)&o_buf_pos[16]);
  pdf->o_buf[3] = hex_to_u32((const u8 *)&o_buf_pos[24]);
  pdf->o_buf[4] = hex_to_u32((const u8 *)&o_buf_pos[32]);
  pdf->o_buf[5] = hex_to_u32((const u8 *)&o_buf_pos[40]);
  pdf->o_buf[6] = hex_to_u32((const u8 *)&o_buf_pos[48]);
  pdf->o_buf[7] = hex_to_u32((const u8 *)&o_buf_pos[56]);
  pdf->o_len = o_len;

  pdf->id_buf[0] = byte_swap_32(pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32(pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32(pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32(pdf->id_buf[3]);

  if (id_len == 32)
  {
    pdf->id_buf[4] = byte_swap_32(pdf->id_buf[4]);
    pdf->id_buf[5] = byte_swap_32(pdf->id_buf[5]);
    pdf->id_buf[6] = byte_swap_32(pdf->id_buf[6]);
    pdf->id_buf[7] = byte_swap_32(pdf->id_buf[7]);
  }

  pdf->u_buf[0] = byte_swap_32(pdf->u_buf[0]);
  pdf->u_buf[1] = byte_swap_32(pdf->u_buf[1]);
  pdf->u_buf[2] = byte_swap_32(pdf->u_buf[2]);
  pdf->u_buf[3] = byte_swap_32(pdf->u_buf[3]);
  pdf->u_buf[4] = byte_swap_32(pdf->u_buf[4]);
  pdf->u_buf[5] = byte_swap_32(pdf->u_buf[5]);
  pdf->u_buf[6] = byte_swap_32(pdf->u_buf[6]);
  pdf->u_buf[7] = byte_swap_32(pdf->u_buf[7]);

  pdf->o_buf[0] = byte_swap_32(pdf->o_buf[0]);
  pdf->o_buf[1] = byte_swap_32(pdf->o_buf[1]);
  pdf->o_buf[2] = byte_swap_32(pdf->o_buf[2]);
  pdf->o_buf[3] = byte_swap_32(pdf->o_buf[3]);
  pdf->o_buf[4] = byte_swap_32(pdf->o_buf[4]);
  pdf->o_buf[5] = byte_swap_32(pdf->o_buf[5]);
  pdf->o_buf[6] = byte_swap_32(pdf->o_buf[6]);
  pdf->o_buf[7] = byte_swap_32(pdf->o_buf[7]);

  // precompute rc4 data for later use

  uint padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  // md5

  uint salt_pc_block[32] = { 0 };

  char *salt_pc_ptr = (char *)salt_pc_block;

  memcpy(salt_pc_ptr, padding, 32);
  memcpy(salt_pc_ptr + 32, pdf->id_buf, pdf->id_len);

  uint salt_pc_digest[4] = { 0 };

  md5_complete_no_limit(salt_pc_digest, salt_pc_block, 32 + pdf->id_len);

  pdf->rc4data[0] = salt_pc_digest[0];
  pdf->rc4data[1] = salt_pc_digest[1];

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len = pdf->id_len + 16;

  salt->salt_iter = ROUNDS_PDF14;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf17l3_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  int ret = pdf17l8_parse_hash(input_buf, input_len, hash_buf);

  if (ret != PARSER_OK)
  {
    return ret;
  }

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  salt->salt_buf[2] = 0x80;

  return (PARSER_OK);
}

int pdf17l8_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10600) || (input_len > DISPLAY_LEN_MAX_10600)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp(SIGNATURE_PDF, input_buf, 5)) && (memcmp(SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr(V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr(R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr(bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr(P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr(enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr(id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr(id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  u_len_pos++;

  char *u_buf_pos = strchr(u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr(u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  o_len_pos++;

  char *o_buf_pos = strchr(o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  char *last = strchr(o_buf_pos, '*');

  if (last == NULL) last = input_buf + input_len;

  u32 o_buf_len = last - o_buf_pos;

  // validate data

  const int V = atoi(V_pos);
  const int R = atoi(R_pos);

  int vr_ok = 0;

  if ((V == 5) && (R == 5)) vr_ok = 1;
  if ((V == 5) && (R == 6)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int bits = atoi(bits_pos);

  if (bits != 256) return (PARSER_SALT_VALUE);

  int enc_md = atoi(enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const uint id_len = atoi(id_len_pos);
  const uint u_len = atoi(u_len_pos);
  const uint o_len = atoi(o_len_pos);

  if (V_len      > 6) return (PARSER_SALT_LENGTH);
  if (R_len      > 6) return (PARSER_SALT_LENGTH);
  if (P_len      > 6) return (PARSER_SALT_LENGTH);
  if (id_len_len > 6) return (PARSER_SALT_LENGTH);
  if (u_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (o_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (bits_len   > 6) return (PARSER_SALT_LENGTH);
  if (enc_md_len > 6) return (PARSER_SALT_LENGTH);

  if ((id_len * 2) != id_buf_len) return (PARSER_SALT_VALUE);
  if ((u_len * 2) != u_buf_len)  return (PARSER_SALT_VALUE);
  if ((o_len * 2) != o_buf_len)  return (PARSER_SALT_VALUE);

  // copy data to esalt

  if (u_len < 40) return (PARSER_SALT_VALUE);

  for (int i = 0, j = 0; i < 8 + 2; i += 1, j += 8)
  {
    pdf->u_buf[i] = hex_to_u32((const u8 *)&u_buf_pos[j]);
  }

  salt->salt_buf[0] = pdf->u_buf[8];
  salt->salt_buf[1] = pdf->u_buf[9];

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);

  salt->salt_len = 8;
  salt->salt_iter = ROUNDS_PDF17L8;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];
  digest[4] = pdf->u_buf[4];
  digest[5] = pdf->u_buf[5];
  digest[6] = pdf->u_buf[6];
  digest[7] = pdf->u_buf[7];

  return (PARSER_OK);
}

int pbkdf2_sha256_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10900) || (input_len > DISPLAY_LEN_MAX_10900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_PBKDF2_SHA256, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *)hash_buf->esalt;

  /**
  * parse line
  */

  // iterations

  char *iter_pos = input_buf + 7;

  u32 iter = atoi(iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr(iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *)pbkdf2_sha256->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode(base64_to_int, (const u8 *)hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 16);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int prestashop_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11000) || (input_len > DISPLAY_LEN_MAX_11000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_auth_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11100) || (input_len > DISPLAY_LEN_MAX_11100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_POSTGRESQL_AUTH, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *user_pos = input_buf + 10;

  char *salt_pos = strchr(user_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, '*');

  hash_pos++;

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  uint user_len = salt_pos - user_pos - 1;

  uint salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 8) return (PARSER_SALT_LENGTH);

  /*
  * store digest
  */

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /*
  * store salt
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  // first 4 bytes are the "challenge"

  salt_buf_ptr[0] = hex_to_u8((const u8 *)&salt_pos[0]);
  salt_buf_ptr[1] = hex_to_u8((const u8 *)&salt_pos[2]);
  salt_buf_ptr[2] = hex_to_u8((const u8 *)&salt_pos[4]);
  salt_buf_ptr[3] = hex_to_u8((const u8 *)&salt_pos[6]);

  // append the user name

  user_len = parse_and_store_salt(salt_buf_ptr + 4, user_pos, user_len);

  salt->salt_len = 4 + user_len;

  return (PARSER_OK);
}

int mysql_auth_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11200) || (input_len > DISPLAY_LEN_MAX_11200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MYSQL_AUTH, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 9;

  char *hash_pos = strchr(salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  uint salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 40) return (PARSER_SALT_LENGTH);

  /*
  * store digest
  */

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);

  /*
  * store salt
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int bitcoin_wallet_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11300) || (input_len > DISPLAY_LEN_MAX_11300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_BITCOIN_WALLET, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  bitcoin_wallet_t *bitcoin_wallet = (bitcoin_wallet_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *cry_master_len_pos = input_buf + 9;

  char *cry_master_buf_pos = strchr(cry_master_len_pos, '$');

  if (cry_master_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_len_len = cry_master_buf_pos - cry_master_len_pos;

  cry_master_buf_pos++;

  char *cry_salt_len_pos = strchr(cry_master_buf_pos, '$');

  if (cry_salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_buf_len = cry_salt_len_pos - cry_master_buf_pos;

  cry_salt_len_pos++;

  char *cry_salt_buf_pos = strchr(cry_salt_len_pos, '$');

  if (cry_salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_len_len = cry_salt_buf_pos - cry_salt_len_pos;

  cry_salt_buf_pos++;

  char *cry_rounds_pos = strchr(cry_salt_buf_pos, '$');

  if (cry_rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_buf_len = cry_rounds_pos - cry_salt_buf_pos;

  cry_rounds_pos++;

  char *ckey_len_pos = strchr(cry_rounds_pos, '$');

  if (ckey_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_rounds_len = ckey_len_pos - cry_rounds_pos;

  ckey_len_pos++;

  char *ckey_buf_pos = strchr(ckey_len_pos, '$');

  if (ckey_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_len_len = ckey_buf_pos - ckey_len_pos;

  ckey_buf_pos++;

  char *public_key_len_pos = strchr(ckey_buf_pos, '$');

  if (public_key_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_buf_len = public_key_len_pos - ckey_buf_pos;

  public_key_len_pos++;

  char *public_key_buf_pos = strchr(public_key_len_pos, '$');

  if (public_key_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 public_key_len_len = public_key_buf_pos - public_key_len_pos;

  public_key_buf_pos++;

  u32 public_key_buf_len = input_len - 1 - 7 - 1 - cry_master_len_len - 1 - cry_master_buf_len - 1 - cry_salt_len_len - 1 - cry_salt_buf_len - 1 - cry_rounds_len - 1 - ckey_len_len - 1 - ckey_buf_len - 1 - public_key_len_len - 1;

  const uint cry_master_len = atoi(cry_master_len_pos);
  const uint cry_salt_len = atoi(cry_salt_len_pos);
  const uint ckey_len = atoi(ckey_len_pos);
  const uint public_key_len = atoi(public_key_len_pos);

  if (cry_master_buf_len != cry_master_len) return (PARSER_SALT_VALUE);
  if (cry_salt_buf_len != cry_salt_len)   return (PARSER_SALT_VALUE);
  if (ckey_buf_len != ckey_len)       return (PARSER_SALT_VALUE);
  if (public_key_buf_len != public_key_len) return (PARSER_SALT_VALUE);

  for (uint i = 0, j = 0; j < cry_master_len; i += 1, j += 8)
  {
    bitcoin_wallet->cry_master_buf[i] = hex_to_u32((const u8 *)&cry_master_buf_pos[j]);

    bitcoin_wallet->cry_master_buf[i] = byte_swap_32(bitcoin_wallet->cry_master_buf[i]);
  }

  for (uint i = 0, j = 0; j < ckey_len; i += 1, j += 8)
  {
    bitcoin_wallet->ckey_buf[i] = hex_to_u32((const u8 *)&ckey_buf_pos[j]);

    bitcoin_wallet->ckey_buf[i] = byte_swap_32(bitcoin_wallet->ckey_buf[i]);
  }

  for (uint i = 0, j = 0; j < public_key_len; i += 1, j += 8)
  {
    bitcoin_wallet->public_key_buf[i] = hex_to_u32((const u8 *)&public_key_buf_pos[j]);

    bitcoin_wallet->public_key_buf[i] = byte_swap_32(bitcoin_wallet->public_key_buf[i]);
  }

  bitcoin_wallet->cry_master_len = cry_master_len / 2;
  bitcoin_wallet->ckey_len = ckey_len / 2;
  bitcoin_wallet->public_key_len = public_key_len / 2;

  /*
  * store digest (should be unique enought, hopefully)
  */

  digest[0] = bitcoin_wallet->cry_master_buf[0];
  digest[1] = bitcoin_wallet->cry_master_buf[1];
  digest[2] = bitcoin_wallet->cry_master_buf[2];
  digest[3] = bitcoin_wallet->cry_master_buf[3];

  /*
  * store salt
  */

  if (cry_rounds_len >= 7) return (PARSER_SALT_VALUE);

  const uint cry_rounds = atoi(cry_rounds_pos);

  salt->salt_iter = cry_rounds - 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  const uint salt_len = parse_and_store_salt(salt_buf_ptr, cry_salt_buf_pos, cry_salt_buf_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sip_auth_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11400) || (input_len > DISPLAY_LEN_MAX_11400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SIP_AUTH, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  sip_t *sip = (sip_t *)hash_buf->esalt;

  // work with a temporary copy of input_buf (s.t. we can manipulate it directly)

  char *temp_input_buf = (char *)mymalloc(input_len + 1);

  memcpy(temp_input_buf, input_buf, input_len);

  // URI_server:

  char *URI_server_pos = temp_input_buf + 6;

  char *URI_client_pos = strchr(URI_server_pos, '*');

  if (URI_client_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_client_pos[0] = 0;
  URI_client_pos++;

  uint URI_server_len = strlen(URI_server_pos);

  if (URI_server_len > 512)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_client:

  char *user_pos = strchr(URI_client_pos, '*');

  if (user_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  user_pos[0] = 0;
  user_pos++;

  uint URI_client_len = strlen(URI_client_pos);

  if (URI_client_len > 512)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // user:

  char *realm_pos = strchr(user_pos, '*');

  if (realm_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  realm_pos[0] = 0;
  realm_pos++;

  uint user_len = strlen(user_pos);

  if (user_len > 116)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // realm:

  char *method_pos = strchr(realm_pos, '*');

  if (method_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  method_pos[0] = 0;
  method_pos++;

  uint realm_len = strlen(realm_pos);

  if (realm_len > 116)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // method:

  char *URI_prefix_pos = strchr(method_pos, '*');

  if (URI_prefix_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_prefix_pos[0] = 0;
  URI_prefix_pos++;

  uint method_len = strlen(method_pos);

  if (method_len > 246)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_prefix:

  char *URI_resource_pos = strchr(URI_prefix_pos, '*');

  if (URI_resource_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_resource_pos[0] = 0;
  URI_resource_pos++;

  uint URI_prefix_len = strlen(URI_prefix_pos);

  if (URI_prefix_len > 245)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_resource:

  char *URI_suffix_pos = strchr(URI_resource_pos, '*');

  if (URI_suffix_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_suffix_pos[0] = 0;
  URI_suffix_pos++;

  uint URI_resource_len = strlen(URI_resource_pos);

  if (URI_resource_len < 1 || URI_resource_len > 246)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_suffix:

  char *nonce_pos = strchr(URI_suffix_pos, '*');

  if (nonce_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_pos[0] = 0;
  nonce_pos++;

  uint URI_suffix_len = strlen(URI_suffix_pos);

  if (URI_suffix_len > 245)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce:

  char *nonce_client_pos = strchr(nonce_pos, '*');

  if (nonce_client_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_client_pos[0] = 0;
  nonce_client_pos++;

  uint nonce_len = strlen(nonce_pos);

  if (nonce_len < 1 || nonce_len > 50)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce_client:

  char *nonce_count_pos = strchr(nonce_client_pos, '*');

  if (nonce_count_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_count_pos[0] = 0;
  nonce_count_pos++;

  uint nonce_client_len = strlen(nonce_client_pos);

  if (nonce_client_len > 50)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce_count:

  char *qop_pos = strchr(nonce_count_pos, '*');

  if (qop_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  qop_pos[0] = 0;
  qop_pos++;

  uint nonce_count_len = strlen(nonce_count_pos);

  if (nonce_count_len > 50)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // qop:

  char *directive_pos = strchr(qop_pos, '*');

  if (directive_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  directive_pos[0] = 0;
  directive_pos++;

  uint qop_len = strlen(qop_pos);

  if (qop_len > 50)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // directive

  char *digest_pos = strchr(directive_pos, '*');

  if (digest_pos == NULL)
  {
    myfree(temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  digest_pos[0] = 0;
  digest_pos++;

  uint directive_len = strlen(directive_pos);

  if (directive_len != 3)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  if (memcmp(directive_pos, "MD5", 3))
  {
    log_info("ERROR: Only the MD5 directive is currently supported\n");

    myfree(temp_input_buf);

    return (PARSER_SIP_AUTH_DIRECTIVE);
  }

  /*
  * first (pre-)compute: HA2 = md5 ($method . ":" . $uri)
  */

  uint md5_len = 0;

  uint md5_max_len = 4 * 64;

  uint md5_remaining_len = md5_max_len;

  uint tmp_md5_buf[64] = { 0 };

  char *tmp_md5_ptr = (char *)tmp_md5_buf;

  snprintf(tmp_md5_ptr, md5_remaining_len, "%s:", method_pos);

  md5_len += method_len + 1;
  tmp_md5_ptr += method_len + 1;

  if (URI_prefix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf(tmp_md5_ptr, md5_remaining_len + 1, "%s:", URI_prefix_pos);

    md5_len += URI_prefix_len + 1;
    tmp_md5_ptr += URI_prefix_len + 1;
  }

  md5_remaining_len = md5_max_len - md5_len;

  snprintf(tmp_md5_ptr, md5_remaining_len + 1, "%s", URI_resource_pos);

  md5_len += URI_resource_len;
  tmp_md5_ptr += URI_resource_len;

  if (URI_suffix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf(tmp_md5_ptr, md5_remaining_len + 1, ":%s", URI_suffix_pos);

    md5_len += 1 + URI_suffix_len;
  }

  uint tmp_digest[4] = { 0 };

  md5_complete_no_limit(tmp_digest, tmp_md5_buf, md5_len);

  tmp_digest[0] = byte_swap_32(tmp_digest[0]);
  tmp_digest[1] = byte_swap_32(tmp_digest[1]);
  tmp_digest[2] = byte_swap_32(tmp_digest[2]);
  tmp_digest[3] = byte_swap_32(tmp_digest[3]);

  /*
  * esalt
  */

  char *esalt_buf_ptr = (char *)sip->esalt_buf;

  uint esalt_len = 0;

  uint max_esalt_len = sizeof(sip->esalt_buf); // 151 = (64 + 64 + 55) - 32, where 32 is the hexadecimal MD5 HA1 hash

                                               // there are 2 possibilities for the esalt:

  if ((strcmp(qop_pos, "auth") == 0) || (strcmp(qop_pos, "auth-int") == 0))
  {
    esalt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

    if (esalt_len > max_esalt_len)
    {
      myfree(temp_input_buf);

      return (PARSER_SALT_LENGTH);
    }

    snprintf(esalt_buf_ptr, max_esalt_len, ":%s:%s:%s:%s:%08x%08x%08x%08x",
      nonce_pos,
      nonce_count_pos,
      nonce_client_pos,
      qop_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }
  else
  {
    esalt_len = 1 + nonce_len + 1 + 32;

    if (esalt_len > max_esalt_len)
    {
      myfree(temp_input_buf);

      return (PARSER_SALT_LENGTH);
    }

    snprintf(esalt_buf_ptr, max_esalt_len, ":%s:%08x%08x%08x%08x",
      nonce_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }

  // add 0x80 to esalt

  esalt_buf_ptr[esalt_len] = 0x80;

  sip->esalt_len = esalt_len;

  /*
  * actual salt
  */

  char *sip_salt_ptr = (char *)sip->salt_buf;

  uint salt_len = user_len + 1 + realm_len + 1;

  uint max_salt_len = 119;

  if (salt_len > max_salt_len)
  {
    myfree(temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  snprintf(sip_salt_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  sip->salt_len = salt_len;

  /*
  * fake salt (for sorting)
  */

  char *salt_buf_ptr = (char *)salt->salt_buf;

  max_salt_len = 55;

  uint fake_salt_len = salt_len;

  if (fake_salt_len > max_salt_len)
  {
    fake_salt_len = max_salt_len;
  }

  snprintf(salt_buf_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  salt->salt_len = fake_salt_len;

  /*
  * digest
  */

  digest[0] = hex_to_u32((const u8 *)&digest_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&digest_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&digest_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&digest_pos[24]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  myfree(temp_input_buf);

  return (PARSER_OK);
}

int crc32_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11500) || (input_len > DISPLAY_LEN_MAX_11500)) return (PARSER_GLOBAL_LENGTH);

  if (input_buf[8] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // digest

  char *digest_pos = input_buf;

  digest[0] = hex_to_u32((const u8 *)&digest_pos[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  // salt

  char *salt_buf = input_buf + 8 + 1;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int seven_zip_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11600) || (input_len > DISPLAY_LEN_MAX_11600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_SEVEN_ZIP, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  seven_zip_t *seven_zip = (seven_zip_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *p_buf_pos = input_buf + 4;

  char *NumCyclesPower_pos = strchr(p_buf_pos, '$');

  if (NumCyclesPower_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 p_buf_len = NumCyclesPower_pos - p_buf_pos;

  NumCyclesPower_pos++;

  char *salt_len_pos = strchr(NumCyclesPower_pos, '$');

  if (salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 NumCyclesPower_len = salt_len_pos - NumCyclesPower_pos;

  salt_len_pos++;

  char *salt_buf_pos = strchr(salt_len_pos, '$');

  if (salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len_len = salt_buf_pos - salt_len_pos;

  salt_buf_pos++;

  char *iv_len_pos = strchr(salt_buf_pos, '$');

  if (iv_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_buf_len = iv_len_pos - salt_buf_pos;

  iv_len_pos++;

  char *iv_buf_pos = strchr(iv_len_pos, '$');

  if (iv_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_len_len = iv_buf_pos - iv_len_pos;

  iv_buf_pos++;

  char *crc_buf_pos = strchr(iv_buf_pos, '$');

  if (crc_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_buf_len = crc_buf_pos - iv_buf_pos;

  crc_buf_pos++;

  char *data_len_pos = strchr(crc_buf_pos, '$');

  if (data_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 crc_buf_len = data_len_pos - crc_buf_pos;

  data_len_pos++;

  char *unpack_size_pos = strchr(data_len_pos, '$');

  if (unpack_size_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = unpack_size_pos - data_len_pos;

  unpack_size_pos++;

  char *data_buf_pos = strchr(unpack_size_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 unpack_size_len = data_buf_pos - unpack_size_pos;

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 2 - 1 - p_buf_len - 1 - NumCyclesPower_len - 1 - salt_len_len - 1 - salt_buf_len - 1 - iv_len_len - 1 - iv_buf_len - 1 - crc_buf_len - 1 - data_len_len - 1 - unpack_size_len - 1;

  const uint iter = atoi(NumCyclesPower_pos);
  const uint crc = atoi(crc_buf_pos);
  const uint p_buf = atoi(p_buf_pos);
  const uint salt_len = atoi(salt_len_pos);
  const uint iv_len = atoi(iv_len_pos);
  const uint unpack_size = atoi(unpack_size_pos);
  const uint data_len = atoi(data_len_pos);

  /**
  * verify some data
  */

  if (p_buf != 0) return (PARSER_SALT_VALUE);
  if (salt_len != 0) return (PARSER_SALT_VALUE);

  if ((data_len * 2) != data_buf_len) return (PARSER_SALT_VALUE);

  if (data_len > 384) return (PARSER_SALT_VALUE);

  if (unpack_size > data_len) return (PARSER_SALT_VALUE);

  /**
  * store data
  */

  seven_zip->iv_buf[0] = hex_to_u32((const u8 *)&iv_buf_pos[0]);
  seven_zip->iv_buf[1] = hex_to_u32((const u8 *)&iv_buf_pos[8]);
  seven_zip->iv_buf[2] = hex_to_u32((const u8 *)&iv_buf_pos[16]);
  seven_zip->iv_buf[3] = hex_to_u32((const u8 *)&iv_buf_pos[24]);

  seven_zip->iv_len = iv_len;

  memcpy(seven_zip->salt_buf, salt_buf_pos, salt_buf_len); // we just need that for later ascii_digest()

  seven_zip->salt_len = 0;

  seven_zip->crc = crc;

  for (uint i = 0, j = 0; j < data_buf_len; i += 1, j += 8)
  {
    seven_zip->data_buf[i] = hex_to_u32((const u8 *)&data_buf_pos[j]);

    seven_zip->data_buf[i] = byte_swap_32(seven_zip->data_buf[i]);
  }

  seven_zip->data_len = data_len;

  seven_zip->unpack_size = unpack_size;

  // real salt

  salt->salt_buf[0] = seven_zip->data_buf[0];
  salt->salt_buf[1] = seven_zip->data_buf[1];
  salt->salt_buf[2] = seven_zip->data_buf[2];
  salt->salt_buf[3] = seven_zip->data_buf[3];

  salt->salt_len = 16;

  salt->salt_sign[0] = iter;

  salt->salt_iter = 1u << iter;

  /**
  * digest
  */

  digest[0] = crc;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int gost2012sbog_256_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11700) || (input_len > DISPLAY_LEN_MAX_11700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);

  return (PARSER_OK);
}

int gost2012sbog_512_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11800) || (input_len > DISPLAY_LEN_MAX_11800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);
  digest[8] = hex_to_u32((const u8 *)&input_buf[64]);
  digest[9] = hex_to_u32((const u8 *)&input_buf[72]);
  digest[10] = hex_to_u32((const u8 *)&input_buf[80]);
  digest[11] = hex_to_u32((const u8 *)&input_buf[88]);
  digest[12] = hex_to_u32((const u8 *)&input_buf[96]);
  digest[13] = hex_to_u32((const u8 *)&input_buf[104]);
  digest[14] = hex_to_u32((const u8 *)&input_buf[112]);
  digest[15] = hex_to_u32((const u8 *)&input_buf[120]);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);
  digest[4] = byte_swap_32(digest[4]);
  digest[5] = byte_swap_32(digest[5]);
  digest[6] = byte_swap_32(digest[6]);
  digest[7] = byte_swap_32(digest[7]);
  digest[8] = byte_swap_32(digest[8]);
  digest[9] = byte_swap_32(digest[9]);
  digest[10] = byte_swap_32(digest[10]);
  digest[11] = byte_swap_32(digest[11]);
  digest[12] = byte_swap_32(digest[12]);
  digest[13] = byte_swap_32(digest[13]);
  digest[14] = byte_swap_32(digest[14]);
  digest[15] = byte_swap_32(digest[15]);

  return (PARSER_OK);
}

int pbkdf2_md5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11900) || (input_len > DISPLAY_LEN_MAX_11900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_PBKDF2_MD5, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_md5_t *pbkdf2_md5 = (pbkdf2_md5_t *)hash_buf->esalt;

  /**
  * parse line
  */

  // iterations

  char *iter_pos = input_buf + 4;

  u32 iter = atoi(iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr(iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *)pbkdf2_md5->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode(base64_to_int, (const u8 *)hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 16);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_md5->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_md5->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_md5->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_md5->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha1_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12000) || (input_len > DISPLAY_LEN_MAX_12000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_PBKDF2_SHA1, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha1_t *pbkdf2_sha1 = (pbkdf2_sha1_t *)hash_buf->esalt;

  /**
  * parse line
  */

  // iterations

  char *iter_pos = input_buf + 5;

  u32 iter = atoi(iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr(iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *)pbkdf2_sha1->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode(base64_to_int, (const u8 *)hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 16);

  digest[0] = byte_swap_32(digest[0]);
  digest[1] = byte_swap_32(digest[1]);
  digest[2] = byte_swap_32(digest[2]);
  digest[3] = byte_swap_32(digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha1->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha1->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha1->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha1->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha512_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12100) || (input_len > DISPLAY_LEN_MAX_12100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_PBKDF2_SHA512, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *)hash_buf->esalt;

  /**
  * parse line
  */

  // iterations

  char *iter_pos = input_buf + 7;

  u32 iter = atoi(iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr(iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr(salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *)pbkdf2_sha512->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode(base64_to_int, (const u8 *)hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy(digest, tmp_buf, 64);

  digest[0] = byte_swap_64(digest[0]);
  digest[1] = byte_swap_64(digest[1]);
  digest[2] = byte_swap_64(digest[2]);
  digest[3] = byte_swap_64(digest[3]);
  digest[4] = byte_swap_64(digest[4]);
  digest[5] = byte_swap_64(digest[5]);
  digest[6] = byte_swap_64(digest[6]);
  digest[7] = byte_swap_64(digest[7]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int ecryptfs_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12200) || (input_len > DISPLAY_LEN_MAX_12200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_ECRYPTFS, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  uint *digest = (uint *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *salt_pos = input_buf + 10 + 2 + 2; // skip over "0$" and "1$"

  char *hash_pos = strchr(salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 10 - 2 - 2 - salt_len - 1;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  // decode hash

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = 0;
  digest[3] = 0;
  digest[4] = 0;
  digest[5] = 0;
  digest[6] = 0;
  digest[7] = 0;
  digest[8] = 0;
  digest[9] = 0;
  digest[10] = 0;
  digest[11] = 0;
  digest[12] = 0;
  digest[13] = 0;
  digest[14] = 0;
  digest[15] = 0;

  // decode salt

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);

  salt->salt_iter = ROUNDS_ECRYPTFS;
  salt->salt_len = 8;

  return (PARSER_OK);
}

int bsdicrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12400) || (input_len > DISPLAY_LEN_MAX_12400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_BSDICRYPT, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  unsigned char c19 = itoa64_to_int(input_buf[19]);

  if (c19 & 3) return (PARSER_HASH_VALUE);

  salt_t *salt = hash_buf->salt;

  u32 *digest = (u32 *)hash_buf->digest;

  // iteration count

  salt->salt_iter = itoa64_to_int(input_buf[1])
    | itoa64_to_int(input_buf[2]) << 6
    | itoa64_to_int(input_buf[3]) << 12
    | itoa64_to_int(input_buf[4]) << 18;

  // set salt

  salt->salt_buf[0] = itoa64_to_int(input_buf[5])
    | itoa64_to_int(input_buf[6]) << 6
    | itoa64_to_int(input_buf[7]) << 12
    | itoa64_to_int(input_buf[8]) << 18;

  salt->salt_len = 4;

  u8 tmp_buf[100] = { 0 };

  base64_decode(itoa64_to_int, (const u8 *)input_buf + 9, 11, tmp_buf);

  memcpy(digest, tmp_buf, 8);

  uint tt;

  IP(&digest[0], &digest[1], &tt);

  digest[0] = rotr32(digest[0], 31);
  digest[1] = rotr32(digest[1], 31);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar3hp_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12500) || (input_len > DISPLAY_LEN_MAX_12500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_RAR3, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *type_pos = input_buf + 6 + 1;

  char *salt_pos = strchr(type_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 type_len = salt_pos - type_pos;

  if (type_len != 1) return (PARSER_SALT_LENGTH);

  salt_pos++;

  char *crypted_pos = strchr(salt_pos, '*');

  if (crypted_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = crypted_pos - salt_pos;

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  crypted_pos++;

  u32 crypted_len = input_len - 6 - 1 - type_len - 1 - salt_len - 1;

  if (crypted_len != 32) return (PARSER_SALT_LENGTH);

  /**
  * copy data
  */

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);

  salt->salt_buf[2] = hex_to_u32((const u8 *)&crypted_pos[0]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&crypted_pos[8]);
  salt->salt_buf[4] = hex_to_u32((const u8 *)&crypted_pos[16]);
  salt->salt_buf[5] = hex_to_u32((const u8 *)&crypted_pos[24]);

  salt->salt_len = 24;
  salt->salt_iter = ROUNDS_RAR3;

  // there's no hash for rar3. the data which is in crypted_pos is some encrypted data and
  // if it matches the value \xc4\x3d\x7b\x00\x40\x07\x00 after decrypt we know that we successfully cracked it.

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar5_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13000) || (input_len > DISPLAY_LEN_MAX_13000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_RAR5, input_buf, 1 + 4 + 1)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rar5_t *rar5 = (rar5_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *param0_pos = input_buf + 1 + 4 + 1;

  char *param1_pos = strchr(param0_pos, '$');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  char *param2_pos = strchr(param1_pos, '$');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  char *param3_pos = strchr(param2_pos, '$');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  char *param4_pos = strchr(param3_pos, '$');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  char *param5_pos = strchr(param4_pos, '$');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  u32 param5_len = input_len - 1 - 4 - 1 - param0_len - 1 - param1_len - 1 - param2_len - 1 - param3_len - 1 - param4_len - 1;

  char *salt_buf = param1_pos;
  char *iv = param3_pos;
  char *pswcheck = param5_pos;

  const uint salt_len = atoi(param0_pos);
  const uint iterations = atoi(param2_pos);
  const uint pswcheck_len = atoi(param4_pos);

  /**
  * verify some data
  */

  if (param1_len != 32) return (PARSER_SALT_VALUE);
  if (param3_len != 32) return (PARSER_SALT_VALUE);
  if (param5_len != 16) return (PARSER_SALT_VALUE);

  if (salt_len != 16) return (PARSER_SALT_VALUE);
  if (iterations == 0) return (PARSER_SALT_VALUE);
  if (pswcheck_len != 8) return (PARSER_SALT_VALUE);

  /**
  * store data
  */

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_buf[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_buf[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&salt_buf[24]);

  rar5->iv[0] = hex_to_u32((const u8 *)&iv[0]);
  rar5->iv[1] = hex_to_u32((const u8 *)&iv[8]);
  rar5->iv[2] = hex_to_u32((const u8 *)&iv[16]);
  rar5->iv[3] = hex_to_u32((const u8 *)&iv[24]);

  salt->salt_len = 16;

  salt->salt_sign[0] = iterations;

  salt->salt_iter = ((1u << iterations) + 32) - 1;

  /**
  * digest buf
  */

  digest[0] = hex_to_u32((const u8 *)&pswcheck[0]);
  digest[1] = hex_to_u32((const u8 *)&pswcheck[8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int krb5tgs_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13100) || (input_len > DISPLAY_LEN_MAX_13100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_KRB5TGS, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5tgs_t *krb5tgs = (krb5tgs_t *)hash_buf->esalt;

  /**
  * parse line
  */

  /* Skip '$' */
  char *account_pos = input_buf + 11 + 1;

  char *data_pos;

  uint data_len;

  if (account_pos[0] == '*')
  {
    account_pos++;

    data_pos = strchr(account_pos, '*');

    /* Skip '*' */
    data_pos++;

    if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    uint account_len = data_pos - account_pos + 1;

    if (account_len >= 512) return (PARSER_SALT_LENGTH);

    /* Skip '$' */
    data_pos++;

    data_len = input_len - 11 - 1 - account_len - 2;

    memcpy(krb5tgs->account_info, account_pos - 1, account_len);
  }
  else
  {
    /* assume $krb5tgs$23$checksum$edata2 */
    data_pos = account_pos;

    memcpy(krb5tgs->account_info, "**", 3);

    data_len = input_len - 11 - 1 - 1;
  }

  if (data_len < ((16 + 32) * 2)) return (PARSER_SALT_LENGTH);

  char *checksum_ptr = (char *)krb5tgs->checksum;

  for (uint i = 0; i < 16 * 2; i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  char *edata_ptr = (char *)krb5tgs->edata2;

  krb5tgs->edata2_len = (data_len - 32) / 2;

  /* skip '$' */
  for (uint i = 16 * 2 + 1; i < (krb5tgs->edata2_len * 2) + (16 * 2 + 1); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];
    *edata_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;
  }

  /* this is needed for hmac_md5 */
  *edata_ptr++ = 0x80;

  salt->salt_buf[0] = krb5tgs->checksum[0];
  salt->salt_buf[1] = krb5tgs->checksum[1];
  salt->salt_buf[2] = krb5tgs->checksum[2];
  salt->salt_buf[3] = krb5tgs->checksum[3];

  salt->salt_len = 32;

  digest[0] = krb5tgs->checksum[0];
  digest[1] = krb5tgs->checksum[1];
  digest[2] = krb5tgs->checksum[2];
  digest[3] = krb5tgs->checksum[3];

  return (PARSER_OK);
}

int axcrypt_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13200) || (input_len > DISPLAY_LEN_MAX_13200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_AXCRYPT, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  /* Skip '*' */
  char *wrapping_rounds_pos = input_buf + 11 + 1;

  char *salt_pos;

  char *wrapped_key_pos;

  char *data_pos;

  salt->salt_iter = atoi(wrapping_rounds_pos);

  salt_pos = strchr(wrapping_rounds_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint wrapping_rounds_len = salt_pos - wrapping_rounds_pos;

  /* Skip '*' */
  salt_pos++;

  data_pos = salt_pos;

  wrapped_key_pos = strchr(salt_pos, '*');

  if (wrapped_key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = wrapped_key_pos - salt_pos;

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  /* Skip '*' */
  wrapped_key_pos++;

  uint wrapped_key_len = input_len - 11 - 1 - wrapping_rounds_len - 1 - salt_len - 1;

  if (wrapped_key_len != 48) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = hex_to_u32((const u8 *)&data_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&data_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&data_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&data_pos[24]);

  data_pos += 33;

  salt->salt_buf[4] = hex_to_u32((const u8 *)&data_pos[0]);
  salt->salt_buf[5] = hex_to_u32((const u8 *)&data_pos[8]);
  salt->salt_buf[6] = hex_to_u32((const u8 *)&data_pos[16]);
  salt->salt_buf[7] = hex_to_u32((const u8 *)&data_pos[24]);
  salt->salt_buf[8] = hex_to_u32((const u8 *)&data_pos[32]);
  salt->salt_buf[9] = hex_to_u32((const u8 *)&data_pos[40]);

  salt->salt_len = 40;

  digest[0] = salt->salt_buf[0];
  digest[1] = salt->salt_buf[1];
  digest[2] = salt->salt_buf[2];
  digest[3] = salt->salt_buf[3];

  return (PARSER_OK);
}

int keepass_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13400) || (input_len > DISPLAY_LEN_MAX_13400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_KEEPASS, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  keepass_t *keepass = (keepass_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *version_pos;

  char *rounds_pos;

  char *algorithm_pos;

  char *final_random_seed_pos;
  u32   final_random_seed_len;

  char *transf_random_seed_pos;
  u32   transf_random_seed_len;

  char *enc_iv_pos;
  u32   enc_iv_len;

  /* default is no keyfile provided */
  char *keyfile_len_pos;
  u32   keyfile_len = 0;
  u32   is_keyfile_present = 0;
  char *keyfile_inline_pos;
  char *keyfile_pos;

  /* specific to version 1 */
  char *contents_len_pos;
  u32   contents_len;
  char *contents_pos;

  /* specific to version 2 */
  char *expected_bytes_pos;
  u32   expected_bytes_len;

  char *contents_hash_pos;
  u32   contents_hash_len;

  version_pos = input_buf + 8 + 1 + 1;

  keepass->version = atoi(version_pos);

  rounds_pos = strchr(version_pos, '*');

  if (rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  rounds_pos++;

  salt->salt_iter = (atoi(rounds_pos));

  algorithm_pos = strchr(rounds_pos, '*');

  if (algorithm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  algorithm_pos++;

  keepass->algorithm = atoi(algorithm_pos);

  final_random_seed_pos = strchr(algorithm_pos, '*');

  if (final_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_pos++;

  keepass->final_random_seed[0] = hex_to_u32((const u8 *)&final_random_seed_pos[0]);
  keepass->final_random_seed[1] = hex_to_u32((const u8 *)&final_random_seed_pos[8]);
  keepass->final_random_seed[2] = hex_to_u32((const u8 *)&final_random_seed_pos[16]);
  keepass->final_random_seed[3] = hex_to_u32((const u8 *)&final_random_seed_pos[24]);

  if (keepass->version == 2)
  {
    keepass->final_random_seed[4] = hex_to_u32((const u8 *)&final_random_seed_pos[32]);
    keepass->final_random_seed[5] = hex_to_u32((const u8 *)&final_random_seed_pos[40]);
    keepass->final_random_seed[6] = hex_to_u32((const u8 *)&final_random_seed_pos[48]);
    keepass->final_random_seed[7] = hex_to_u32((const u8 *)&final_random_seed_pos[56]);
  }

  transf_random_seed_pos = strchr(final_random_seed_pos, '*');

  if (transf_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_len = transf_random_seed_pos - final_random_seed_pos;

  if (keepass->version == 1 && final_random_seed_len != 32) return (PARSER_SALT_LENGTH);
  if (keepass->version == 2 && final_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  transf_random_seed_pos++;

  keepass->transf_random_seed[0] = hex_to_u32((const u8 *)&transf_random_seed_pos[0]);
  keepass->transf_random_seed[1] = hex_to_u32((const u8 *)&transf_random_seed_pos[8]);
  keepass->transf_random_seed[2] = hex_to_u32((const u8 *)&transf_random_seed_pos[16]);
  keepass->transf_random_seed[3] = hex_to_u32((const u8 *)&transf_random_seed_pos[24]);
  keepass->transf_random_seed[4] = hex_to_u32((const u8 *)&transf_random_seed_pos[32]);
  keepass->transf_random_seed[5] = hex_to_u32((const u8 *)&transf_random_seed_pos[40]);
  keepass->transf_random_seed[6] = hex_to_u32((const u8 *)&transf_random_seed_pos[48]);
  keepass->transf_random_seed[7] = hex_to_u32((const u8 *)&transf_random_seed_pos[56]);

  enc_iv_pos = strchr(transf_random_seed_pos, '*');

  if (enc_iv_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  transf_random_seed_len = enc_iv_pos - transf_random_seed_pos;

  if (transf_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  enc_iv_pos++;

  keepass->enc_iv[0] = hex_to_u32((const u8 *)&enc_iv_pos[0]);
  keepass->enc_iv[1] = hex_to_u32((const u8 *)&enc_iv_pos[8]);
  keepass->enc_iv[2] = hex_to_u32((const u8 *)&enc_iv_pos[16]);
  keepass->enc_iv[3] = hex_to_u32((const u8 *)&enc_iv_pos[24]);

  if (keepass->version == 1)
  {
    contents_hash_pos = strchr(enc_iv_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = contents_hash_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    keepass->contents_hash[0] = hex_to_u32((const u8 *)&contents_hash_pos[0]);
    keepass->contents_hash[1] = hex_to_u32((const u8 *)&contents_hash_pos[8]);
    keepass->contents_hash[2] = hex_to_u32((const u8 *)&contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32((const u8 *)&contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32((const u8 *)&contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32((const u8 *)&contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32((const u8 *)&contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32((const u8 *)&contents_hash_pos[56]);

    /* get length of contents following */
    char *inline_flag_pos = strchr(contents_hash_pos, '*');

    if (inline_flag_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_hash_len = inline_flag_pos - contents_hash_pos;

    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);

    inline_flag_pos++;

    u32 inline_flag = atoi(inline_flag_pos);

    if (inline_flag != 1) return (PARSER_SALT_LENGTH);

    contents_len_pos = strchr(inline_flag_pos, '*');

    if (contents_len_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_len_pos++;

    contents_len = atoi(contents_len_pos);

    if (contents_len > 50000) return (PARSER_SALT_LENGTH);

    contents_pos = strchr(contents_len_pos, '*');

    if (contents_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_pos++;

    u32 i;

    keepass->contents_len = contents_len;

    contents_len = contents_len / 4;

    keyfile_inline_pos = strchr(contents_pos, '*');

    u32 real_contents_len;

    if (keyfile_inline_pos == NULL)
      real_contents_len = input_len - (contents_pos - input_buf);
    else
    {
      real_contents_len = keyfile_inline_pos - contents_pos;
      keyfile_inline_pos++;
      is_keyfile_present = 1;
    }

    if (real_contents_len != keepass->contents_len * 2) return (PARSER_SALT_LENGTH);

    for (i = 0; i < contents_len; i++)
      keepass->contents[i] = hex_to_u32((const u8 *)&contents_pos[i * 8]);
  }
  else if (keepass->version == 2)
  {
    expected_bytes_pos = strchr(enc_iv_pos, '*');

    if (expected_bytes_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = expected_bytes_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    expected_bytes_pos++;

    keepass->expected_bytes[0] = hex_to_u32((const u8 *)&expected_bytes_pos[0]);
    keepass->expected_bytes[1] = hex_to_u32((const u8 *)&expected_bytes_pos[8]);
    keepass->expected_bytes[2] = hex_to_u32((const u8 *)&expected_bytes_pos[16]);
    keepass->expected_bytes[3] = hex_to_u32((const u8 *)&expected_bytes_pos[24]);
    keepass->expected_bytes[4] = hex_to_u32((const u8 *)&expected_bytes_pos[32]);
    keepass->expected_bytes[5] = hex_to_u32((const u8 *)&expected_bytes_pos[40]);
    keepass->expected_bytes[6] = hex_to_u32((const u8 *)&expected_bytes_pos[48]);
    keepass->expected_bytes[7] = hex_to_u32((const u8 *)&expected_bytes_pos[56]);

    contents_hash_pos = strchr(expected_bytes_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    expected_bytes_len = contents_hash_pos - expected_bytes_pos;

    if (expected_bytes_len != 64) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    keepass->contents_hash[0] = hex_to_u32((const u8 *)&contents_hash_pos[0]);
    keepass->contents_hash[1] = hex_to_u32((const u8 *)&contents_hash_pos[8]);
    keepass->contents_hash[2] = hex_to_u32((const u8 *)&contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32((const u8 *)&contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32((const u8 *)&contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32((const u8 *)&contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32((const u8 *)&contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32((const u8 *)&contents_hash_pos[56]);

    keyfile_inline_pos = strchr(contents_hash_pos, '*');

    if (keyfile_inline_pos == NULL)
      contents_hash_len = input_len - (int)(contents_hash_pos - input_buf);
    else
    {
      contents_hash_len = keyfile_inline_pos - contents_hash_pos;
      keyfile_inline_pos++;
      is_keyfile_present = 1;
    }
    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);
  }

  if (is_keyfile_present != 0)
  {
    keyfile_len_pos = strchr(keyfile_inline_pos, '*');

    keyfile_len_pos++;

    keyfile_len = atoi(keyfile_len_pos);

    keepass->keyfile_len = keyfile_len;

    if (keyfile_len != 64) return (PARSER_SALT_LENGTH);

    keyfile_pos = strchr(keyfile_len_pos, '*');

    if (keyfile_pos == NULL) return (PARSER_SALT_LENGTH);

    keyfile_pos++;

    u32 real_keyfile_len = input_len - (keyfile_pos - input_buf);

    if (real_keyfile_len != 64) return (PARSER_SALT_LENGTH);

    keepass->keyfile[0] = hex_to_u32((const u8 *)&keyfile_pos[0]);
    keepass->keyfile[1] = hex_to_u32((const u8 *)&keyfile_pos[8]);
    keepass->keyfile[2] = hex_to_u32((const u8 *)&keyfile_pos[16]);
    keepass->keyfile[3] = hex_to_u32((const u8 *)&keyfile_pos[24]);
    keepass->keyfile[4] = hex_to_u32((const u8 *)&keyfile_pos[32]);
    keepass->keyfile[5] = hex_to_u32((const u8 *)&keyfile_pos[40]);
    keepass->keyfile[6] = hex_to_u32((const u8 *)&keyfile_pos[48]);
    keepass->keyfile[7] = hex_to_u32((const u8 *)&keyfile_pos[56]);
  }

  digest[0] = keepass->enc_iv[0];
  digest[1] = keepass->enc_iv[1];
  digest[2] = keepass->enc_iv[2];
  digest[3] = keepass->enc_iv[3];

  salt->salt_buf[0] = keepass->transf_random_seed[0];
  salt->salt_buf[1] = keepass->transf_random_seed[1];
  salt->salt_buf[2] = keepass->transf_random_seed[2];
  salt->salt_buf[3] = keepass->transf_random_seed[3];
  salt->salt_buf[4] = keepass->transf_random_seed[4];
  salt->salt_buf[5] = keepass->transf_random_seed[5];
  salt->salt_buf[6] = keepass->transf_random_seed[6];
  salt->salt_buf[7] = keepass->transf_random_seed[7];

  return (PARSER_OK);
}

int cf10_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12600) || (input_len > DISPLAY_LEN_MAX_12600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *)salt->salt_buf;

  salt_len = parse_and_store_salt(salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  /**
  * we can precompute the first sha256 transform
  */

  uint w[16] = { 0 };

  w[0] = byte_swap_32(salt->salt_buf[0]);
  w[1] = byte_swap_32(salt->salt_buf[1]);
  w[2] = byte_swap_32(salt->salt_buf[2]);
  w[3] = byte_swap_32(salt->salt_buf[3]);
  w[4] = byte_swap_32(salt->salt_buf[4]);
  w[5] = byte_swap_32(salt->salt_buf[5]);
  w[6] = byte_swap_32(salt->salt_buf[6]);
  w[7] = byte_swap_32(salt->salt_buf[7]);
  w[8] = byte_swap_32(salt->salt_buf[8]);
  w[9] = byte_swap_32(salt->salt_buf[9]);
  w[10] = byte_swap_32(salt->salt_buf[10]);
  w[11] = byte_swap_32(salt->salt_buf[11]);
  w[12] = byte_swap_32(salt->salt_buf[12]);
  w[13] = byte_swap_32(salt->salt_buf[13]);
  w[14] = byte_swap_32(salt->salt_buf[14]);
  w[15] = byte_swap_32(salt->salt_buf[15]);

  uint pc256[8] = { SHA256M_A, SHA256M_B, SHA256M_C, SHA256M_D, SHA256M_E, SHA256M_F, SHA256M_G, SHA256M_H };

  sha256_64(w, pc256);

  salt->salt_buf_pc[0] = pc256[0];
  salt->salt_buf_pc[1] = pc256[1];
  salt->salt_buf_pc[2] = pc256[2];
  salt->salt_buf_pc[3] = pc256[3];
  salt->salt_buf_pc[4] = pc256[4];
  salt->salt_buf_pc[5] = pc256[5];
  salt->salt_buf_pc[6] = pc256[6];
  salt->salt_buf_pc[7] = pc256[7];

  digest[0] -= pc256[0];
  digest[1] -= pc256[1];
  digest[2] -= pc256[2];
  digest[3] -= pc256[3];
  digest[4] -= pc256[4];
  digest[5] -= pc256[5];
  digest[6] -= pc256[6];
  digest[7] -= pc256[7];

  return (PARSER_OK);
}

int mywallet_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12700) || (input_len > DISPLAY_LEN_MAX_12700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MYWALLET, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *data_len_pos = input_buf + 1 + 10 + 1;

  char *data_buf_pos = strchr(data_len_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = data_buf_pos - data_len_pos;

  if (data_len_len < 1) return (PARSER_SALT_LENGTH);
  if (data_len_len > 5) return (PARSER_SALT_LENGTH);

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 10 - 1 - data_len_len - 1;

  if (data_buf_len < 64) return (PARSER_HASH_LENGTH);

  if (data_buf_len % 16) return (PARSER_HASH_LENGTH);

  u32 data_len = atoi(data_len_pos);

  if ((data_len * 2) != data_buf_len) return (PARSER_HASH_LENGTH);

  /**
  * salt
  */

  char *salt_pos = data_buf_pos;

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&salt_pos[24]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32((const u8 *)&salt_pos[32]);
  salt->salt_buf[5] = hex_to_u32((const u8 *)&salt_pos[40]);
  salt->salt_buf[6] = hex_to_u32((const u8 *)&salt_pos[48]);
  salt->salt_buf[7] = hex_to_u32((const u8 *)&salt_pos[56]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  salt->salt_iter = 10 - 1;

  /**
  * digest buf
  */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int ms_drsr_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12800) || (input_len > DISPLAY_LEN_MAX_12800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_MS_DRSR, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *salt_pos = input_buf + 11 + 1;

  char *iter_pos = strchr(salt_pos, ',');

  if (iter_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = iter_pos - salt_pos;

  if (salt_len != 20) return (PARSER_SALT_LENGTH);

  iter_pos++;

  char *hash_pos = strchr(iter_pos, ',');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_len = hash_pos - iter_pos;

  if (iter_len > 5) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 11 - 1 - salt_len - 1 - iter_len - 1;

  if (hash_len != 64) return (PARSER_HASH_LENGTH);

  /**
  * salt
  */

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt_pos[16]) & 0xffff0000;
  salt->salt_buf[3] = 0x00018000;

  salt->salt_buf[0] = byte_swap_32(salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32(salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32(salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32(salt->salt_buf[3]);

  salt->salt_len = salt_len / 2;

  salt->salt_iter = atoi(iter_pos) - 1;

  /**
  * digest buf
  */

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hash_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hash_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hash_pos[56]);

  return (PARSER_OK);
}

int androidfde_samsung_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12900) || (input_len > DISPLAY_LEN_MAX_12900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
  * parse line
  */

  char *hash_pos = input_buf + 64;
  char *salt1_pos = input_buf + 128;
  char *salt2_pos = input_buf;

  /**
  * salt
  */

  salt->salt_buf[0] = hex_to_u32((const u8 *)&salt1_pos[0]);
  salt->salt_buf[1] = hex_to_u32((const u8 *)&salt1_pos[8]);
  salt->salt_buf[2] = hex_to_u32((const u8 *)&salt1_pos[16]);
  salt->salt_buf[3] = hex_to_u32((const u8 *)&salt1_pos[24]);

  salt->salt_buf[4] = hex_to_u32((const u8 *)&salt2_pos[0]);
  salt->salt_buf[5] = hex_to_u32((const u8 *)&salt2_pos[8]);
  salt->salt_buf[6] = hex_to_u32((const u8 *)&salt2_pos[16]);
  salt->salt_buf[7] = hex_to_u32((const u8 *)&salt2_pos[24]);

  salt->salt_buf[8] = hex_to_u32((const u8 *)&salt2_pos[32]);
  salt->salt_buf[9] = hex_to_u32((const u8 *)&salt2_pos[40]);
  salt->salt_buf[10] = hex_to_u32((const u8 *)&salt2_pos[48]);
  salt->salt_buf[11] = hex_to_u32((const u8 *)&salt2_pos[56]);

  salt->salt_len = 48;

  salt->salt_iter = ROUNDS_ANDROIDFDE_SAMSUNG - 1;

  /**
  * digest buf
  */

  digest[0] = hex_to_u32((const u8 *)&hash_pos[0]);
  digest[1] = hex_to_u32((const u8 *)&hash_pos[8]);
  digest[2] = hex_to_u32((const u8 *)&hash_pos[16]);
  digest[3] = hex_to_u32((const u8 *)&hash_pos[24]);
  digest[4] = hex_to_u32((const u8 *)&hash_pos[32]);
  digest[5] = hex_to_u32((const u8 *)&hash_pos[40]);
  digest[6] = hex_to_u32((const u8 *)&hash_pos[48]);
  digest[7] = hex_to_u32((const u8 *)&hash_pos[56]);

  return (PARSER_OK);
}

int zip2_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13600) || (input_len > DISPLAY_LEN_MAX_13600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp(SIGNATURE_ZIP2_START, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);
  if (memcmp(SIGNATURE_ZIP2_STOP, input_buf + input_len - 7, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  zip2_t *zip2 = (zip2_t *)hash_buf->esalt;

  /**
  * parse line
  */

  char *param0_pos = input_buf + 6 + 1;

  char *param1_pos = strchr(param0_pos, '*');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  char *param2_pos = strchr(param1_pos, '*');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  char *param3_pos = strchr(param2_pos, '*');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  char *param4_pos = strchr(param3_pos, '*');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  char *param5_pos = strchr(param4_pos, '*');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  char *param6_pos = strchr(param5_pos, '*');

  if (param6_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param5_len = param6_pos - param5_pos;

  param6_pos++;

  char *param7_pos = strchr(param6_pos, '*');

  if (param7_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param6_len = param7_pos - param6_pos;

  param7_pos++;

  char *param8_pos = strchr(param7_pos, '*');

  if (param8_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param7_len = param8_pos - param7_pos;

  param8_pos++;

  const uint type = atoi(param0_pos);
  const uint mode = atoi(param1_pos);
  const uint magic = atoi(param2_pos);

  char *salt_buf = param3_pos;

  uint verify_bytes; sscanf(param4_pos, "%4x*", &verify_bytes);

  const uint compress_length = atoi(param5_pos);

  char *data_buf = param6_pos;
  char *auth = param7_pos;

  /**
  * verify some data
  */

  if (param0_len != 1) return (PARSER_SALT_VALUE);

  if (param1_len != 1) return (PARSER_SALT_VALUE);

  if (param2_len != 1) return (PARSER_SALT_VALUE);

  if ((param3_len != 16) && (param3_len != 24) && (param3_len != 32)) return (PARSER_SALT_VALUE);

  if (param4_len >= 5) return (PARSER_SALT_VALUE);

  if (param5_len >= 5) return (PARSER_SALT_VALUE);

  if (param6_len >= 8192) return (PARSER_SALT_VALUE);

  if (param6_len & 1) return (PARSER_SALT_VALUE);

  if (param7_len != 20) return (PARSER_SALT_VALUE);

  if (type != 0) return (PARSER_SALT_VALUE);

  if ((mode != 1) && (mode != 2) && (mode != 3)) return (PARSER_SALT_VALUE);

  if (magic != 0) return (PARSER_SALT_VALUE);

  if (verify_bytes >= 0x10000) return (PARSER_SALT_VALUE);

  /**
  * store data
  */

  zip2->type = type;
  zip2->mode = mode;
  zip2->magic = magic;

  if (mode == 1)
  {
    zip2->salt_buf[0] = hex_to_u32((const u8 *)&salt_buf[0]);
    zip2->salt_buf[1] = hex_to_u32((const u8 *)&salt_buf[8]);
    zip2->salt_buf[2] = 0;
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 8;
  }
  else if (mode == 2)
  {
    zip2->salt_buf[0] = hex_to_u32((const u8 *)&salt_buf[0]);
    zip2->salt_buf[1] = hex_to_u32((const u8 *)&salt_buf[8]);
    zip2->salt_buf[2] = hex_to_u32((const u8 *)&salt_buf[16]);
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 12;
  }
  else if (mode == 3)
  {
    zip2->salt_buf[0] = hex_to_u32((const u8 *)&salt_buf[0]);
    zip2->salt_buf[1] = hex_to_u32((const u8 *)&salt_buf[8]);
    zip2->salt_buf[2] = hex_to_u32((const u8 *)&salt_buf[16]);
    zip2->salt_buf[3] = hex_to_u32((const u8 *)&salt_buf[24]);

    zip2->salt_len = 16;
  }

  zip2->salt_buf[0] = byte_swap_32(zip2->salt_buf[0]);
  zip2->salt_buf[1] = byte_swap_32(zip2->salt_buf[1]);
  zip2->salt_buf[2] = byte_swap_32(zip2->salt_buf[2]);
  zip2->salt_buf[3] = byte_swap_32(zip2->salt_buf[3]);

  zip2->verify_bytes = verify_bytes;

  zip2->compress_length = compress_length;

  char *data_buf_ptr = (char *)zip2->data_buf;

  for (uint i = 0; i < param6_len; i += 2)
  {
    const char p0 = data_buf[i + 0];
    const char p1 = data_buf[i + 1];

    *data_buf_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;

    zip2->data_len++;
  }

  *data_buf_ptr = 0x80;

  char *auth_ptr = (char *)zip2->auth_buf;

  for (uint i = 0; i < param7_len; i += 2)
  {
    const char p0 = auth[i + 0];
    const char p1 = auth[i + 1];

    *auth_ptr++ = hex_convert(p1) << 0
      | hex_convert(p0) << 4;

    zip2->auth_len++;
  }

  /**
  * salt buf (fake)
  */

  salt->salt_buf[0] = zip2->salt_buf[0];
  salt->salt_buf[1] = zip2->salt_buf[1];
  salt->salt_buf[2] = zip2->salt_buf[2];
  salt->salt_buf[3] = zip2->salt_buf[3];
  salt->salt_buf[4] = zip2->data_buf[0];
  salt->salt_buf[5] = zip2->data_buf[1];
  salt->salt_buf[6] = zip2->data_buf[2];
  salt->salt_buf[7] = zip2->data_buf[3];

  salt->salt_len = 32;

  salt->salt_iter = ROUNDS_ZIP2 - 1;

  /**
  * digest buf (fake)
  */

  digest[0] = zip2->auth_buf[0];
  digest[1] = zip2->auth_buf[1];
  digest[2] = zip2->auth_buf[2];
  digest[3] = zip2->auth_buf[3];

  return (PARSER_OK);
}

int win8phone_parse_hash(char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13800) || (input_len > DISPLAY_LEN_MAX_13800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *)hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  win8phone_t *esalt = (win8phone_t *) hash_buf->esalt;

  digest[0] = hex_to_u32((const u8 *)&input_buf[0]);
  digest[1] = hex_to_u32((const u8 *)&input_buf[8]);
  digest[2] = hex_to_u32((const u8 *)&input_buf[16]);
  digest[3] = hex_to_u32((const u8 *)&input_buf[24]);
  digest[4] = hex_to_u32((const u8 *)&input_buf[32]);
  digest[5] = hex_to_u32((const u8 *)&input_buf[40]);
  digest[6] = hex_to_u32((const u8 *)&input_buf[48]);
  digest[7] = hex_to_u32((const u8 *)&input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *salt_buf_ptr = input_buf + 64 + 1;

  u32 *salt_buf = esalt->salt_buf;

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    salt_buf[i] = hex_to_u32((const u8 *)&salt_buf_ptr[j]);
  }

  salt->salt_buf[0] = salt_buf[0];
  salt->salt_buf[1] = salt_buf[1];
  salt->salt_buf[2] = salt_buf[2];
  salt->salt_buf[3] = salt_buf[3];
  salt->salt_buf[4] = salt_buf[4];
  salt->salt_buf[5] = salt_buf[5];
  salt->salt_buf[6] = salt_buf[6];
  salt->salt_buf[7] = salt_buf[7];

  salt->salt_len = 64;

  return (PARSER_OK);
}
