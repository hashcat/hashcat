#include <shared.h>
#include <bit_ops.h>
#include <hc_global_data_t.h>
#include <hc_global.h>
#include <converter.h>
#include <decoder.h>
#include <consts/digest_sizes.h>
#include <consts/hash_types.h>
#include <consts/hash_options.h>
#include <consts/salt_types.h>
#include <consts/signatures.h>
#include <cpu/cpu-des.h>
#include <consts/rounds_count.h>
#include <consts/optimizer_options.h>
#include <inc_hash_constants.h>

void ascii_digest(char *out_buf, uint salt_pos, uint digest_pos)
{
  uint hash_type = data.hash_type;
  uint hash_mode = data.hash_mode;
  uint salt_type = data.salt_type;
  uint opts_type = data.opts_type;
  uint opti_type = data.opti_type;
  uint dgst_size = data.dgst_size;

  char *hashfile = data.hashfile;

  uint len = 4096;

  u8 datax[256] = { 0 };

  u64 *digest_buf64 = (u64 *)datax;
  u32 *digest_buf = (u32 *)datax;

  char *digests_buf_ptr = (char *)data.digests_buf;

  memcpy(digest_buf, digests_buf_ptr + (data.salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

  if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
  {
    uint tt;

    switch (hash_type)
    {
    case HASH_TYPE_DESCRYPT:
      FP(&digest_buf[1], &digest_buf[0], &tt);
      break;

    case HASH_TYPE_DESRACF:
      digest_buf[0] = rotl32(digest_buf[0], 29);
      digest_buf[1] = rotl32(digest_buf[1], 29);

      FP(&digest_buf[1], &digest_buf[0], &tt);
      break;

    case HASH_TYPE_LM:
      FP(&digest_buf[1], &digest_buf[0], &tt);
      break;

    case HASH_TYPE_NETNTLM:
      digest_buf[0] = rotl32(digest_buf[0], 29);
      digest_buf[1] = rotl32(digest_buf[1], 29);
      digest_buf[2] = rotl32(digest_buf[2], 29);
      digest_buf[3] = rotl32(digest_buf[3], 29);

      FP(&digest_buf[1], &digest_buf[0], &tt);
      FP(&digest_buf[3], &digest_buf[2], &tt);
      break;

    case HASH_TYPE_BSDICRYPT:
      digest_buf[0] = rotl32(digest_buf[0], 31);
      digest_buf[1] = rotl32(digest_buf[1], 31);

      FP(&digest_buf[1], &digest_buf[0], &tt);
      break;
    }
  }

  if (opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    switch (hash_type)
    {
    case HASH_TYPE_MD4:
      digest_buf[0] += MD4M_A;
      digest_buf[1] += MD4M_B;
      digest_buf[2] += MD4M_C;
      digest_buf[3] += MD4M_D;
      break;

    case HASH_TYPE_MD5:
      digest_buf[0] += MD5M_A;
      digest_buf[1] += MD5M_B;
      digest_buf[2] += MD5M_C;
      digest_buf[3] += MD5M_D;
      break;

    case HASH_TYPE_SHA1:
      digest_buf[0] += SHA1M_A;
      digest_buf[1] += SHA1M_B;
      digest_buf[2] += SHA1M_C;
      digest_buf[3] += SHA1M_D;
      digest_buf[4] += SHA1M_E;
      break;

    case HASH_TYPE_SHA256:
      digest_buf[0] += SHA256M_A;
      digest_buf[1] += SHA256M_B;
      digest_buf[2] += SHA256M_C;
      digest_buf[3] += SHA256M_D;
      digest_buf[4] += SHA256M_E;
      digest_buf[5] += SHA256M_F;
      digest_buf[6] += SHA256M_G;
      digest_buf[7] += SHA256M_H;
      break;

    case HASH_TYPE_SHA384:
      digest_buf64[0] += SHA384M_A;
      digest_buf64[1] += SHA384M_B;
      digest_buf64[2] += SHA384M_C;
      digest_buf64[3] += SHA384M_D;
      digest_buf64[4] += SHA384M_E;
      digest_buf64[5] += SHA384M_F;
      digest_buf64[6] += 0;
      digest_buf64[7] += 0;
      break;

    case HASH_TYPE_SHA512:
      digest_buf64[0] += SHA512M_A;
      digest_buf64[1] += SHA512M_B;
      digest_buf64[2] += SHA512M_C;
      digest_buf64[3] += SHA512M_D;
      digest_buf64[4] += SHA512M_E;
      digest_buf64[5] += SHA512M_F;
      digest_buf64[6] += SHA512M_G;
      digest_buf64[7] += SHA512M_H;
      break;
    }
  }

  if (opts_type & OPTS_TYPE_PT_GENERATE_LE)
  {
    if (dgst_size == DGST_SIZE_4_2)
    {
      for (int i = 0; i < 2; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_4)
    {
      for (int i = 0; i < 4; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_5)
    {
      for (int i = 0; i < 5; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_6)
    {
      for (int i = 0; i < 6; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_8)
    {
      for (int i = 0; i < 8; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if ((dgst_size == DGST_SIZE_4_16) || (dgst_size == DGST_SIZE_8_8)) // same size, same result :)
    {
      if (hash_type == HASH_TYPE_WHIRLPOOL)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
      }
      else if (hash_type == HASH_TYPE_SHA384)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64(digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_SHA512)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64(digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_GOST)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
      }
    }
    else if (dgst_size == DGST_SIZE_4_64)
    {
      for (int i = 0; i < 64; i++) digest_buf[i] = byte_swap_32(digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_8_25)
    {
      for (int i = 0; i < 25; i++) digest_buf64[i] = byte_swap_64(digest_buf64[i]);
    }
  }

  uint isSalted = ((data.salt_type == SALT_TYPE_INTERN)
    | (data.salt_type == SALT_TYPE_EXTERN)
    | (data.salt_type == SALT_TYPE_EMBEDDED));

  salt_t salt;

  if (isSalted)
  {
    memset(&salt, 0, sizeof(salt_t));

    memcpy(&salt, &data.salts_buf[salt_pos], sizeof(salt_t));

    char *ptr = (char *)salt.salt_buf;

    uint len = salt.salt_len;

    if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
    {
      uint tt;

      switch (hash_type)
      {
      case HASH_TYPE_NETNTLM:

        salt.salt_buf[0] = rotr32(salt.salt_buf[0], 3);
        salt.salt_buf[1] = rotr32(salt.salt_buf[1], 3);

        FP(salt.salt_buf[1], salt.salt_buf[0], tt);

        break;
      }
    }

    if (opts_type & OPTS_TYPE_ST_UNICODE)
    {
      for (uint i = 0, j = 0; i < len; i += 1, j += 2)
      {
        ptr[i] = ptr[j];
      }

      len = len / 2;
    }

    if (opts_type & OPTS_TYPE_ST_GENERATE_LE)
    {
      uint max = salt.salt_len / 4;

      if (len % 4) max++;

      for (uint i = 0; i < max; i++)
      {
        salt.salt_buf[i] = byte_swap_32(salt.salt_buf[i]);
      }
    }

    if (opts_type & OPTS_TYPE_ST_HEX)
    {
      char tmp[64] = { 0 };

      for (uint i = 0, j = 0; i < len; i += 1, j += 2)
      {
        sprintf(tmp + j, "%02x", (unsigned char)ptr[i]);
      }

      len = len * 2;

      memcpy(ptr, tmp, len);
    }

    uint memset_size = ((48 - (int)len) > 0) ? (48 - len) : 0;

    memset(ptr + len, 0, memset_size);

    salt.salt_len = len;
  }

  //
  // some modes require special encoding
  //

  uint out_buf_plain[256] = { 0 };
  uint out_buf_salt[256] = { 0 };

  char tmp_buf[1024] = { 0 };

  char *ptr_plain = (char *)out_buf_plain;
  char *ptr_salt = (char *)out_buf_salt;

  if (hash_mode == 22)
  {
    char username[30] = { 0 };

    memcpy(username, salt.salt_buf, salt.salt_len - 22);

    char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };

    u16 *ptr = (u16 *)digest_buf;

    tmp_buf[0] = sig[0];
    tmp_buf[1] = int_to_base64(((ptr[1]) >> 12) & 0x3f);
    tmp_buf[2] = int_to_base64(((ptr[1]) >> 6) & 0x3f);
    tmp_buf[3] = int_to_base64(((ptr[1]) >> 0) & 0x3f);
    tmp_buf[4] = int_to_base64(((ptr[0]) >> 12) & 0x3f);
    tmp_buf[5] = int_to_base64(((ptr[0]) >> 6) & 0x3f);
    tmp_buf[6] = sig[1];
    tmp_buf[7] = int_to_base64(((ptr[0]) >> 0) & 0x3f);
    tmp_buf[8] = int_to_base64(((ptr[3]) >> 12) & 0x3f);
    tmp_buf[9] = int_to_base64(((ptr[3]) >> 6) & 0x3f);
    tmp_buf[10] = int_to_base64(((ptr[3]) >> 0) & 0x3f);
    tmp_buf[11] = int_to_base64(((ptr[2]) >> 12) & 0x3f);
    tmp_buf[12] = sig[2];
    tmp_buf[13] = int_to_base64(((ptr[2]) >> 6) & 0x3f);
    tmp_buf[14] = int_to_base64(((ptr[2]) >> 0) & 0x3f);
    tmp_buf[15] = int_to_base64(((ptr[5]) >> 12) & 0x3f);
    tmp_buf[16] = int_to_base64(((ptr[5]) >> 6) & 0x3f);
    tmp_buf[17] = sig[3];
    tmp_buf[18] = int_to_base64(((ptr[5]) >> 0) & 0x3f);
    tmp_buf[19] = int_to_base64(((ptr[4]) >> 12) & 0x3f);
    tmp_buf[20] = int_to_base64(((ptr[4]) >> 6) & 0x3f);
    tmp_buf[21] = int_to_base64(((ptr[4]) >> 0) & 0x3f);
    tmp_buf[22] = int_to_base64(((ptr[7]) >> 12) & 0x3f);
    tmp_buf[23] = sig[4];
    tmp_buf[24] = int_to_base64(((ptr[7]) >> 6) & 0x3f);
    tmp_buf[25] = int_to_base64(((ptr[7]) >> 0) & 0x3f);
    tmp_buf[26] = int_to_base64(((ptr[6]) >> 12) & 0x3f);
    tmp_buf[27] = int_to_base64(((ptr[6]) >> 6) & 0x3f);
    tmp_buf[28] = int_to_base64(((ptr[6]) >> 0) & 0x3f);
    tmp_buf[29] = sig[5];

    snprintf(out_buf, len - 1, "%s:%s",
      tmp_buf,
      username);
  }
  else if (hash_mode == 23)
  {
    // do not show the skyper part in output

    char *salt_buf_ptr = (char *)salt.salt_buf;

    salt_buf_ptr[salt.salt_len - 8] = 0;

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      salt_buf_ptr);
  }
  else if (hash_mode == 101)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    memcpy(tmp_buf, digest_buf, 20);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 20, (u8 *)ptr_plain);

    snprintf(out_buf, len - 1, "{SHA}%s", ptr_plain);
  }
  else if (hash_mode == 111)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    memcpy(tmp_buf, digest_buf, 20);
    memcpy(tmp_buf + 20, salt.salt_buf, salt.salt_len);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 20 + salt.salt_len, (u8 *)ptr_plain);

    snprintf(out_buf, len - 1, "{SSHA}%s", ptr_plain);
  }
  else if ((hash_mode == 122) || (hash_mode == 125))
  {
    snprintf(out_buf, len - 1, "%s%08x%08x%08x%08x%08x",
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 124)
  {
    snprintf(out_buf, len - 1, "sha1$%s$%08x%08x%08x%08x%08x",
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 131)
  {
    snprintf(out_buf, len - 1, "0x0100%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (char *)salt.salt_buf,
      0, 0, 0, 0, 0,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 132)
  {
    snprintf(out_buf, len - 1, "0x0100%s%08x%08x%08x%08x%08x",
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 133)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    memcpy(tmp_buf, digest_buf, 20);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 20, (u8 *)ptr_plain);

    snprintf(out_buf, len - 1, "%s", ptr_plain);
  }
  else if (hash_mode == 141)
  {
    memcpy(tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, salt.salt_len, (u8 *)ptr_salt);

    memset(tmp_buf, 0, sizeof(tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    memcpy(tmp_buf, digest_buf, 20);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 20, (u8 *)ptr_plain);

    ptr_plain[27] = 0;

    snprintf(out_buf, len - 1, "%s%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 400)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);

    phpass_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    snprintf(out_buf, len - 1, "%s%s%s", (char *)salt.salt_sign, (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 500)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);

    md5crypt_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf(out_buf, len - 1, "$1$%s$%s", (char *)salt.salt_buf, (char *)ptr_plain);
    }
    else
    {
      snprintf(out_buf, len - 1, "$1$rounds=%i$%s$%s", salt.salt_iter, (char *)salt.salt_buf, (char *)ptr_plain);
    }
  }
  else if (hash_mode == 501)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 1421)
  {
    u8 *salt_ptr = (u8 *)salt.salt_buf;

    snprintf(out_buf, len - 1, "%c%c%c%c%c%c%08x%08x%08x%08x%08x%08x%08x%08x",
      salt_ptr[0],
      salt_ptr[1],
      salt_ptr[2],
      salt_ptr[3],
      salt_ptr[4],
      salt_ptr[5],
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 1441)
  {
    memcpy(tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, salt.salt_len, (u8 *)ptr_salt);

    memset(tmp_buf, 0, sizeof(tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);

    memcpy(tmp_buf, digest_buf, 32);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 32, (u8 *)ptr_plain);

    ptr_plain[43] = 0;

    snprintf(out_buf, len - 1, "%s%s*%s", SIGNATURE_EPISERVER4, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1500)
  {
    out_buf[0] = salt.salt_sign[0] & 0xff;
    out_buf[1] = salt.salt_sign[1] & 0xff;
    //original method, but changed because of this ticket: https://hashcat.net/trac/ticket/269
    //out_buf[0] = int_to_itoa64 ((salt.salt_buf[0] >> 0) & 0x3f);
    //out_buf[1] = int_to_itoa64 ((salt.salt_buf[0] >> 6) & 0x3f);

    memset(tmp_buf, 0, sizeof(tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);

    memcpy(tmp_buf, digest_buf, 8);

    base64_encode(int_to_itoa64, (const u8 *)tmp_buf, 8, (u8 *)ptr_plain);

    snprintf(out_buf + 2, len - 1 - 2, "%s", ptr_plain);

    out_buf[13] = 0;
  }
  else if (hash_mode == 1600)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);

    md5crypt_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf(out_buf, len - 1, "$apr1$%s$%s", (char *)salt.salt_buf, (char *)ptr_plain);
    }
    else
    {
      snprintf(out_buf, len - 1, "$apr1$rounds=%i$%s$%s", salt.salt_iter, (char *)salt.salt_buf, (char *)ptr_plain);
    }
  }
  else if (hash_mode == 1711)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf64[0] = byte_swap_64(digest_buf64[0]);
    digest_buf64[1] = byte_swap_64(digest_buf64[1]);
    digest_buf64[2] = byte_swap_64(digest_buf64[2]);
    digest_buf64[3] = byte_swap_64(digest_buf64[3]);
    digest_buf64[4] = byte_swap_64(digest_buf64[4]);
    digest_buf64[5] = byte_swap_64(digest_buf64[5]);
    digest_buf64[6] = byte_swap_64(digest_buf64[6]);
    digest_buf64[7] = byte_swap_64(digest_buf64[7]);

    memcpy(tmp_buf, digest_buf, 64);
    memcpy(tmp_buf + 64, salt.salt_buf, salt.salt_len);

    base64_encode(int_to_base64, (const u8 *)tmp_buf, 64 + salt.salt_len, (u8 *)ptr_plain);

    snprintf(out_buf, len - 1, "%s%s", SIGNATURE_SHA512B64S, ptr_plain);
  }
  else if (hash_mode == 1722)
  {
    uint *ptr = digest_buf;

    snprintf(out_buf, len - 1, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *)salt.salt_buf,
      ptr[1], ptr[0],
      ptr[3], ptr[2],
      ptr[5], ptr[4],
      ptr[7], ptr[6],
      ptr[9], ptr[8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 1731)
  {
    uint *ptr = digest_buf;

    snprintf(out_buf, len - 1, "0x0200%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *)salt.salt_buf,
      ptr[1], ptr[0],
      ptr[3], ptr[2],
      ptr[5], ptr[4],
      ptr[7], ptr[6],
      ptr[9], ptr[8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 1800)
  {
    // temp workaround

    digest_buf64[0] = byte_swap_64(digest_buf64[0]);
    digest_buf64[1] = byte_swap_64(digest_buf64[1]);
    digest_buf64[2] = byte_swap_64(digest_buf64[2]);
    digest_buf64[3] = byte_swap_64(digest_buf64[3]);
    digest_buf64[4] = byte_swap_64(digest_buf64[4]);
    digest_buf64[5] = byte_swap_64(digest_buf64[5]);
    digest_buf64[6] = byte_swap_64(digest_buf64[6]);
    digest_buf64[7] = byte_swap_64(digest_buf64[7]);

    sha512crypt_encode((unsigned char *)digest_buf64, (unsigned char *)ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA512CRYPT)
    {
      snprintf(out_buf, len - 1, "$6$%s$%s", (char *)salt.salt_buf, (char *)ptr_plain);
    }
    else
    {
      snprintf(out_buf, len - 1, "$6$rounds=%i$%s$%s", salt.salt_iter, (char *)salt.salt_buf, (char *)ptr_plain);
    }
  }
  else if (hash_mode == 2100)
  {
    uint pos = 0;

    snprintf(out_buf + pos, len - 1, "%s%i#",
      SIGNATURE_DCC2,
      salt.salt_iter + 1);

    uint signature_len = strlen(out_buf);

    pos += signature_len;
    len -= signature_len;

    char *salt_ptr = (char *)salt.salt_buf;

    for (uint i = 0; i < salt.salt_len; i++, pos++, len--) snprintf(out_buf + pos, len - 1, "%c", salt_ptr[i]);

    snprintf(out_buf + pos, len - 1, "#%08x%08x%08x%08x",
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]));
  }
  else if ((hash_mode == 2400) || (hash_mode == 2410))
  {
    memcpy(tmp_buf, digest_buf, 16);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);

    out_buf[0] = int_to_itoa64((digest_buf[0] >> 0) & 0x3f);
    out_buf[1] = int_to_itoa64((digest_buf[0] >> 6) & 0x3f);
    out_buf[2] = int_to_itoa64((digest_buf[0] >> 12) & 0x3f);
    out_buf[3] = int_to_itoa64((digest_buf[0] >> 18) & 0x3f);

    out_buf[4] = int_to_itoa64((digest_buf[1] >> 0) & 0x3f);
    out_buf[5] = int_to_itoa64((digest_buf[1] >> 6) & 0x3f);
    out_buf[6] = int_to_itoa64((digest_buf[1] >> 12) & 0x3f);
    out_buf[7] = int_to_itoa64((digest_buf[1] >> 18) & 0x3f);

    out_buf[8] = int_to_itoa64((digest_buf[2] >> 0) & 0x3f);
    out_buf[9] = int_to_itoa64((digest_buf[2] >> 6) & 0x3f);
    out_buf[10] = int_to_itoa64((digest_buf[2] >> 12) & 0x3f);
    out_buf[11] = int_to_itoa64((digest_buf[2] >> 18) & 0x3f);

    out_buf[12] = int_to_itoa64((digest_buf[3] >> 0) & 0x3f);
    out_buf[13] = int_to_itoa64((digest_buf[3] >> 6) & 0x3f);
    out_buf[14] = int_to_itoa64((digest_buf[3] >> 12) & 0x3f);
    out_buf[15] = int_to_itoa64((digest_buf[3] >> 18) & 0x3f);

    out_buf[16] = 0;
  }
  else if (hash_mode == 2500)
  {
    wpa_t *wpas = (wpa_t *)data.esalts_buf;

    wpa_t *wpa = &wpas[salt_pos];

    snprintf(out_buf, len - 1, "%s:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x",
      (char *)salt.salt_buf,
      wpa->orig_mac1[0],
      wpa->orig_mac1[1],
      wpa->orig_mac1[2],
      wpa->orig_mac1[3],
      wpa->orig_mac1[4],
      wpa->orig_mac1[5],
      wpa->orig_mac2[0],
      wpa->orig_mac2[1],
      wpa->orig_mac2[2],
      wpa->orig_mac2[3],
      wpa->orig_mac2[4],
      wpa->orig_mac2[5]);
  }
  else if (hash_mode == 4400)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x",
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]));
  }
  else if (hash_mode == 4700)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x",
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]),
      byte_swap_32(digest_buf[4]));
  }
  else if (hash_mode == 4800)
  {
    u8 chap_id_byte = (u8)salt.salt_buf[4];

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x:%08x%08x%08x%08x:%02x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]),
      chap_id_byte);
  }
  else if (hash_mode == 4900)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x",
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]),
      byte_swap_32(digest_buf[4]));
  }
  else if (hash_mode == 5100)
  {
    snprintf(out_buf, len - 1, "%08x%08x",
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 5200)
  {
    snprintf(out_buf, len - 1, "%s", hashfile);
  }
  else if (hash_mode == 5300)
  {
    ikepsk_t *ikepsks = (ikepsk_t *)data.esalts_buf;

    ikepsk_t *ikepsk = &ikepsks[salt_pos];

    int buf_len = len - 1;

    // msg_buf

    uint ikepsk_msg_len = ikepsk->msg_len / 4;

    for (uint i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", byte_swap_32(ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    uint ikepsk_nr_len = ikepsk->nr_len / 4;

    for (uint i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", byte_swap_32(ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (uint i = 0; i < 4; i++)
    {
      if (i == 0)
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5400)
  {
    ikepsk_t *ikepsks = (ikepsk_t *)data.esalts_buf;

    ikepsk_t *ikepsk = &ikepsks[salt_pos];

    int buf_len = len - 1;

    // msg_buf

    uint ikepsk_msg_len = ikepsk->msg_len / 4;

    for (uint i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", byte_swap_32(ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    uint ikepsk_nr_len = ikepsk->nr_len / 4;

    for (uint i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", byte_swap_32(ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (uint i = 0; i < 5; i++)
    {
      if (i == 0)
      {
        snprintf(out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf(out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5500)
  {
    netntlm_t *netntlms = (netntlm_t *)data.esalts_buf;

    netntlm_t *netntlm = &netntlms[salt_pos];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (uint i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *)netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (uint i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *)netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (uint i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *)netntlm->chall_buf;

      sprintf(srvchall_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *)netntlm->chall_buf;

      sprintf(clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf(out_buf, len - 1, "%s::%s:%s:%08x%08x%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32(salt.salt_buf_pc[0]),
      byte_swap_32(salt.salt_buf_pc[1]),
      clichall_buf);
  }
  else if (hash_mode == 5600)
  {
    netntlm_t *netntlms = (netntlm_t *)data.esalts_buf;

    netntlm_t *netntlm = &netntlms[salt_pos];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (uint i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *)netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (uint i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *)netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (uint i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *)netntlm->chall_buf;

      sprintf(srvchall_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *)netntlm->chall_buf;

      sprintf(clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf(out_buf, len - 1, "%s::%s:%s:%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      clichall_buf);
  }
  else if (hash_mode == 5700)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);

    memcpy(tmp_buf, digest_buf, 32);

    base64_encode(int_to_itoa64, (const u8 *)tmp_buf, 32, (u8 *)ptr_plain);

    ptr_plain[43] = 0;

    snprintf(out_buf, len - 1, "%s", ptr_plain);
  }
  else if (hash_mode == 5800)
  {
    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if ((hash_mode >= 6200) && (hash_mode <= 6299))
  {
    snprintf(out_buf, len - 1, "%s", hashfile);
  }
  else if (hash_mode == 6300)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);

    md5crypt_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    snprintf(out_buf, len - 1, "{smd5}%s$%s", (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 6400)
  {
    sha256aix_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    snprintf(out_buf, len - 1, "{ssha256}%02d$%s$%s", salt.salt_sign[0], (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 6500)
  {
    sha512aix_encode((unsigned char *)digest_buf64, (unsigned char *)ptr_plain);

    snprintf(out_buf, len - 1, "{ssha512}%02d$%s$%s", salt.salt_sign[0], (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 6600)
  {
    agilekey_t *agilekeys = (agilekey_t *)data.esalts_buf;

    agilekey_t *agilekey = &agilekeys[salt_pos];

    salt.salt_buf[0] = byte_swap_32(salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32(salt.salt_buf[1]);

    uint buf_len = len - 1;

    uint off = snprintf(out_buf, buf_len, "%d:%08x%08x:", salt.salt_iter + 1, salt.salt_buf[0], salt.salt_buf[1]);
    buf_len -= 22;

    for (uint i = 0, j = off; i < 1040; i++, j += 2)
    {
      snprintf(out_buf + j, buf_len, "%02x", agilekey->cipher[i]);

      buf_len -= 2;
    }
  }
  else if (hash_mode == 6700)
  {
    sha1aix_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    snprintf(out_buf, len - 1, "{ssha1}%02d$%s$%s", salt.salt_sign[0], (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 6800)
  {
    snprintf(out_buf, len - 1, "%s", (char *)salt.salt_buf);
  }
  else if (hash_mode == 7100)
  {
    uint *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *)data.esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512 = &pbkdf2_sha512s[salt_pos];

    uint esalt[8] = { 0 };

    esalt[0] = byte_swap_32(pbkdf2_sha512->salt_buf[0]);
    esalt[1] = byte_swap_32(pbkdf2_sha512->salt_buf[1]);
    esalt[2] = byte_swap_32(pbkdf2_sha512->salt_buf[2]);
    esalt[3] = byte_swap_32(pbkdf2_sha512->salt_buf[3]);
    esalt[4] = byte_swap_32(pbkdf2_sha512->salt_buf[4]);
    esalt[5] = byte_swap_32(pbkdf2_sha512->salt_buf[5]);
    esalt[6] = byte_swap_32(pbkdf2_sha512->salt_buf[6]);
    esalt[7] = byte_swap_32(pbkdf2_sha512->salt_buf[7]);

    snprintf(out_buf, len - 1, "%s%i$%08x%08x%08x%08x%08x%08x%08x%08x$%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_SHA512OSX,
      salt.salt_iter + 1,
      esalt[0], esalt[1],
      esalt[2], esalt[3],
      esalt[4], esalt[5],
      esalt[6], esalt[7],
      ptr[1], ptr[0],
      ptr[3], ptr[2],
      ptr[5], ptr[4],
      ptr[7], ptr[6],
      ptr[9], ptr[8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 7200)
  {
    uint *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *)data.esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512 = &pbkdf2_sha512s[salt_pos];

    uint len_used = 0;

    snprintf(out_buf + len_used, len - len_used - 1, "%s%i.", SIGNATURE_SHA512GRUB, salt.salt_iter + 1);

    len_used = strlen(out_buf);

    unsigned char *salt_buf_ptr = (unsigned char *)pbkdf2_sha512->salt_buf;

    for (uint i = 0; i < salt.salt_len; i++, len_used += 2)
    {
      snprintf(out_buf + len_used, len - len_used - 1, "%02x", salt_buf_ptr[i]);
    }

    snprintf(out_buf + len_used, len - len_used - 1, ".%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      ptr[1], ptr[0],
      ptr[3], ptr[2],
      ptr[5], ptr[4],
      ptr[7], ptr[6],
      ptr[9], ptr[8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 7300)
  {
    rakp_t *rakps = (rakp_t *)data.esalts_buf;

    rakp_t *rakp = &rakps[salt_pos];

    for (uint i = 0, j = 0; (i * 4) < rakp->salt_len; i += 1, j += 8)
    {
      sprintf(out_buf + j, "%08x", rakp->salt_buf[i]);
    }

    snprintf(out_buf + rakp->salt_len * 2, len - 1, ":%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7400)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);

    sha256crypt_encode((unsigned char *)digest_buf, (unsigned char *)ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA256CRYPT)
    {
      snprintf(out_buf, len - 1, "$5$%s$%s", (char *)salt.salt_buf, (char *)ptr_plain);
    }
    else
    {
      snprintf(out_buf, len - 1, "$5$rounds=%i$%s$%s", salt.salt_iter, (char *)salt.salt_buf, (char *)ptr_plain);
    }
  }
  else if (hash_mode == 7500)
  {
    krb5pa_t *krb5pas = (krb5pa_t *)data.esalts_buf;

    krb5pa_t *krb5pa = &krb5pas[salt_pos];

    u8 *ptr_timestamp = (u8 *)krb5pa->timestamp;
    u8 *ptr_checksum = (u8 *)krb5pa->checksum;

    char data[128] = { 0 };

    char *ptr_data = data;

    for (uint i = 0; i < 36; i++, ptr_data += 2)
    {
      sprintf(ptr_data, "%02x", ptr_timestamp[i]);
    }

    for (uint i = 0; i < 16; i++, ptr_data += 2)
    {
      sprintf(ptr_data, "%02x", ptr_checksum[i]);
    }

    *ptr_data = 0;

    snprintf(out_buf, len - 1, "%s$%s$%s$%s$%s",
      SIGNATURE_KRB5PA,
      (char *)krb5pa->user,
      (char *)krb5pa->realm,
      (char *)krb5pa->salt,
      data);
  }
  else if (hash_mode == 7700)
  {
    snprintf(out_buf, len - 1, "%s$%08X%08X",
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 7800)
  {
    snprintf(out_buf, len - 1, "%s$%08X%08X%08X%08X%08X",
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7900)
  {
    drupal7_encode((unsigned char *)digest_buf64, (unsigned char *)ptr_plain);

    // ugly hack start

    char *tmp = (char *)salt.salt_buf_pc;

    ptr_plain[42] = tmp[0];

    // ugly hack end

    ptr_plain[43] = 0;

    snprintf(out_buf, len - 1, "%s%s%s", (char *)salt.salt_sign, (char *)salt.salt_buf, (char *)ptr_plain);
  }
  else if (hash_mode == 8000)
  {
    snprintf(out_buf, len - 1, "0xc007%s%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 8100)
  {
    salt.salt_buf[0] = byte_swap_32(salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32(salt.salt_buf[1]);

    snprintf(out_buf, len - 1, "1%s%08x%08x%08x%08x%08x",
      (unsigned char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 8200)
  {
    cloudkey_t *cloudkeys = (cloudkey_t *)data.esalts_buf;

    cloudkey_t *cloudkey = &cloudkeys[salt_pos];

    char data_buf[4096] = { 0 };

    for (int i = 0, j = 0; i < 512; i += 1, j += 8)
    {
      sprintf(data_buf + j, "%08x", cloudkey->data_buf[i]);
    }

    data_buf[cloudkey->data_len * 2] = 0;

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);

    salt.salt_buf[0] = byte_swap_32(salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32(salt.salt_buf[1]);
    salt.salt_buf[2] = byte_swap_32(salt.salt_buf[2]);
    salt.salt_buf[3] = byte_swap_32(salt.salt_buf[3]);

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x:%08x%08x%08x%08x:%u:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_iter + 1,
      data_buf);
  }
  else if (hash_mode == 8300)
  {
    char digest_buf_c[34] = { 0 };

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);

    base32_encode(int_to_itoa32, (const u8 *)digest_buf, 20, (u8 *)digest_buf_c);

    digest_buf_c[32] = 0;

    // domain

    const uint salt_pc_len = salt.salt_buf_pc[7]; // what a hack

    char domain_buf_c[33] = { 0 };

    memcpy(domain_buf_c, (char *)salt.salt_buf_pc, salt_pc_len);

    for (uint i = 0; i < salt_pc_len; i++)
    {
      const char next = domain_buf_c[i];

      domain_buf_c[i] = '.';

      i += next;
    }

    domain_buf_c[salt_pc_len] = 0;

    // final

    snprintf(out_buf, len - 1, "%s:%s:%s:%u", digest_buf_c, domain_buf_c, (char *)salt.salt_buf, salt.salt_iter);
  }
  else if (hash_mode == 8500)
  {
    snprintf(out_buf, len - 1, "%s*%s*%08X%08X", SIGNATURE_RACF, (char *)salt.salt_buf, digest_buf[0], digest_buf[1]);
  }
  else if (hash_mode == 2612)
  {
    snprintf(out_buf, len - 1, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_PHPS,
      (char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 3711)
  {
    char *salt_ptr = (char *)salt.salt_buf;

    salt_ptr[salt.salt_len - 1] = 0;

    snprintf(out_buf, len - 1, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_MEDIAWIKI_B,
      salt_ptr,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 8800)
  {
    androidfde_t *androidfdes = (androidfde_t *)data.esalts_buf;

    androidfde_t *androidfde = &androidfdes[salt_pos];

    char tmp[3073] = { 0 };

    for (uint i = 0, j = 0; i < 384; i += 1, j += 8)
    {
      sprintf(tmp + j, "%08x", androidfde->data[i]);
    }

    tmp[3072] = 0;

    snprintf(out_buf, len - 1, "%s16$%08x%08x%08x%08x$16$%08x%08x%08x%08x$%s",
      SIGNATURE_ANDROIDFDE,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]),
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]),
      tmp);
  }
  else if (hash_mode == 8900)
  {
    uint N = salt.scrypt_N;
    uint r = salt.scrypt_r;
    uint p = salt.scrypt_p;

    char base64_salt[32] = { 0 };

    base64_encode(int_to_base64, (const u8 *)salt.salt_buf, salt.salt_len, (u8 *)base64_salt);

    memset(tmp_buf, 0, 46);

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode(int_to_base64, (const u8 *)digest_buf, 32, (u8 *)tmp_buf);

    snprintf(out_buf, len - 1, "%s:%i:%i:%i:%s:%s",
      SIGNATURE_SCRYPT,
      N,
      r,
      p,
      base64_salt,
      tmp_buf);
  }
  else if (hash_mode == 9000)
  {
    snprintf(out_buf, len - 1, "%s", hashfile);
  }
  else if (hash_mode == 9200)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *)data.esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256 = &pbkdf2_sha256s[salt_pos];

    unsigned char *salt_buf_ptr = (unsigned char *)pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode(int_to_itoa64, (const u8 *)digest_buf, 32, (u8 *)tmp_buf);
    tmp_buf[43] = 0; // cut it here

                     // output

    snprintf(out_buf, len - 1, "%s%s$%s", SIGNATURE_CISCO8, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9300)
  {
    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode(int_to_itoa64, (const u8 *)digest_buf, 32, (u8 *)tmp_buf);
    tmp_buf[43] = 0; // cut it here

    unsigned char *salt_buf_ptr = (unsigned char *)salt.salt_buf;

    snprintf(out_buf, len - 1, "%s%s$%s", SIGNATURE_CISCO9, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9400)
  {
    office2007_t *office2007s = (office2007_t *)data.esalts_buf;

    office2007_t *office2007 = &office2007s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2007,
      2007,
      20,
      office2007->keySize,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2007->encryptedVerifier[0],
      office2007->encryptedVerifier[1],
      office2007->encryptedVerifier[2],
      office2007->encryptedVerifier[3],
      office2007->encryptedVerifierHash[0],
      office2007->encryptedVerifierHash[1],
      office2007->encryptedVerifierHash[2],
      office2007->encryptedVerifierHash[3],
      office2007->encryptedVerifierHash[4]);
  }
  else if (hash_mode == 9500)
  {
    office2010_t *office2010s = (office2010_t *)data.esalts_buf;

    office2010_t *office2010 = &office2010s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x", SIGNATURE_OFFICE2010, 2010, 100000, 128, 16,

      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2010->encryptedVerifier[0],
      office2010->encryptedVerifier[1],
      office2010->encryptedVerifier[2],
      office2010->encryptedVerifier[3],
      office2010->encryptedVerifierHash[0],
      office2010->encryptedVerifierHash[1],
      office2010->encryptedVerifierHash[2],
      office2010->encryptedVerifierHash[3],
      office2010->encryptedVerifierHash[4],
      office2010->encryptedVerifierHash[5],
      office2010->encryptedVerifierHash[6],
      office2010->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9600)
  {
    office2013_t *office2013s = (office2013_t *)data.esalts_buf;

    office2013_t *office2013 = &office2013s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x", SIGNATURE_OFFICE2013, 2013, 100000, 256, 16,

      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2013->encryptedVerifier[0],
      office2013->encryptedVerifier[1],
      office2013->encryptedVerifier[2],
      office2013->encryptedVerifier[3],
      office2013->encryptedVerifierHash[0],
      office2013->encryptedVerifierHash[1],
      office2013->encryptedVerifierHash[2],
      office2013->encryptedVerifierHash[3],
      office2013->encryptedVerifierHash[4],
      office2013->encryptedVerifierHash[5],
      office2013->encryptedVerifierHash[6],
      office2013->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9700)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *)data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]),
      byte_swap_32(oldoffice01->encryptedVerifier[0]),
      byte_swap_32(oldoffice01->encryptedVerifier[1]),
      byte_swap_32(oldoffice01->encryptedVerifier[2]),
      byte_swap_32(oldoffice01->encryptedVerifier[3]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9710)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *)data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]),
      byte_swap_32(oldoffice01->encryptedVerifier[0]),
      byte_swap_32(oldoffice01->encryptedVerifier[1]),
      byte_swap_32(oldoffice01->encryptedVerifier[2]),
      byte_swap_32(oldoffice01->encryptedVerifier[3]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9720)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *)data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    u8 *rc4key = (u8 *)oldoffice01->rc4key;

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]),
      byte_swap_32(oldoffice01->encryptedVerifier[0]),
      byte_swap_32(oldoffice01->encryptedVerifier[1]),
      byte_swap_32(oldoffice01->encryptedVerifier[2]),
      byte_swap_32(oldoffice01->encryptedVerifier[3]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice01->encryptedVerifierHash[3]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 9800)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *)data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32(oldoffice34->encryptedVerifier[0]),
      byte_swap_32(oldoffice34->encryptedVerifier[1]),
      byte_swap_32(oldoffice34->encryptedVerifier[2]),
      byte_swap_32(oldoffice34->encryptedVerifier[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9810)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *)data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32(oldoffice34->encryptedVerifier[0]),
      byte_swap_32(oldoffice34->encryptedVerifier[1]),
      byte_swap_32(oldoffice34->encryptedVerifier[2]),
      byte_swap_32(oldoffice34->encryptedVerifier[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9820)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *)data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    u8 *rc4key = (u8 *)oldoffice34->rc4key;

    snprintf(out_buf, len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32(oldoffice34->encryptedVerifier[0]),
      byte_swap_32(oldoffice34->encryptedVerifier[1]),
      byte_swap_32(oldoffice34->encryptedVerifier[2]),
      byte_swap_32(oldoffice34->encryptedVerifier[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32(oldoffice34->encryptedVerifierHash[4]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 10000)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *)data.esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256 = &pbkdf2_sha256s[salt_pos];

    unsigned char *salt_buf_ptr = (unsigned char *)pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);
    digest_buf[2] = byte_swap_32(digest_buf[2]);
    digest_buf[3] = byte_swap_32(digest_buf[3]);
    digest_buf[4] = byte_swap_32(digest_buf[4]);
    digest_buf[5] = byte_swap_32(digest_buf[5]);
    digest_buf[6] = byte_swap_32(digest_buf[6]);
    digest_buf[7] = byte_swap_32(digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode(int_to_base64, (const u8 *)digest_buf, 32, (u8 *)tmp_buf);

    // output

    snprintf(out_buf, len - 1, "%s%i$%s$%s", SIGNATURE_DJANGOPBKDF2, salt.salt_iter + 1, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 10100)
  {
    snprintf(out_buf, len - 1, "%08x%08x:%u:%u:%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      2,
      4,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      byte_swap_32(salt.salt_buf[2]),
      byte_swap_32(salt.salt_buf[3]));
  }
  else if (hash_mode == 10200)
  {
    cram_md5_t *cram_md5s = (cram_md5_t *)data.esalts_buf;

    cram_md5_t *cram_md5 = &cram_md5s[salt_pos];

    // challenge

    char challenge[100] = { 0 };

    base64_encode(int_to_base64, (const u8 *)salt.salt_buf, salt.salt_len, (u8 *)challenge);

    // response

    char tmp_buf[100] = { 0 };

    uint tmp_len = snprintf(tmp_buf, 100, "%s %08x%08x%08x%08x",
      (char *)cram_md5->user,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);

    char response[100] = { 0 };

    base64_encode(int_to_base64, (const u8 *)tmp_buf, tmp_len, (u8 *)response);

    snprintf(out_buf, len - 1, "%s%s$%s", SIGNATURE_CRAM_MD5, challenge, response);
  }
  else if (hash_mode == 10300)
  {
    char tmp_buf[100] = { 0 };

    memcpy(tmp_buf + 0, digest_buf, 20);
    memcpy(tmp_buf + 20, salt.salt_buf, salt.salt_len);

    uint tmp_len = 20 + salt.salt_len;

    // base64 encode it

    char base64_encoded[100] = { 0 };

    base64_encode(int_to_base64, (const u8 *)tmp_buf, tmp_len, (u8 *)base64_encoded);

    snprintf(out_buf, len - 1, "%s%i}%s", SIGNATURE_SAPH_SHA1, salt.salt_iter + 1, base64_encoded);
  }
  else if (hash_mode == 10400)
  {
    pdf_t *pdfs = (pdf_t *)data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    snprintf(out_buf, len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32(pdf->id_buf[0]),
      byte_swap_32(pdf->id_buf[1]),
      byte_swap_32(pdf->id_buf[2]),
      byte_swap_32(pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32(pdf->u_buf[0]),
      byte_swap_32(pdf->u_buf[1]),
      byte_swap_32(pdf->u_buf[2]),
      byte_swap_32(pdf->u_buf[3]),
      byte_swap_32(pdf->u_buf[4]),
      byte_swap_32(pdf->u_buf[5]),
      byte_swap_32(pdf->u_buf[6]),
      byte_swap_32(pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32(pdf->o_buf[0]),
      byte_swap_32(pdf->o_buf[1]),
      byte_swap_32(pdf->o_buf[2]),
      byte_swap_32(pdf->o_buf[3]),
      byte_swap_32(pdf->o_buf[4]),
      byte_swap_32(pdf->o_buf[5]),
      byte_swap_32(pdf->o_buf[6]),
      byte_swap_32(pdf->o_buf[7])
      );
  }
  else if (hash_mode == 10410)
  {
    pdf_t *pdfs = (pdf_t *)data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    snprintf(out_buf, len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32(pdf->id_buf[0]),
      byte_swap_32(pdf->id_buf[1]),
      byte_swap_32(pdf->id_buf[2]),
      byte_swap_32(pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32(pdf->u_buf[0]),
      byte_swap_32(pdf->u_buf[1]),
      byte_swap_32(pdf->u_buf[2]),
      byte_swap_32(pdf->u_buf[3]),
      byte_swap_32(pdf->u_buf[4]),
      byte_swap_32(pdf->u_buf[5]),
      byte_swap_32(pdf->u_buf[6]),
      byte_swap_32(pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32(pdf->o_buf[0]),
      byte_swap_32(pdf->o_buf[1]),
      byte_swap_32(pdf->o_buf[2]),
      byte_swap_32(pdf->o_buf[3]),
      byte_swap_32(pdf->o_buf[4]),
      byte_swap_32(pdf->o_buf[5]),
      byte_swap_32(pdf->o_buf[6]),
      byte_swap_32(pdf->o_buf[7])
      );
  }
  else if (hash_mode == 10420)
  {
    pdf_t *pdfs = (pdf_t *)data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    u8 *rc4key = (u8 *)pdf->rc4key;

    snprintf(out_buf, len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32(pdf->id_buf[0]),
      byte_swap_32(pdf->id_buf[1]),
      byte_swap_32(pdf->id_buf[2]),
      byte_swap_32(pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32(pdf->u_buf[0]),
      byte_swap_32(pdf->u_buf[1]),
      byte_swap_32(pdf->u_buf[2]),
      byte_swap_32(pdf->u_buf[3]),
      byte_swap_32(pdf->u_buf[4]),
      byte_swap_32(pdf->u_buf[5]),
      byte_swap_32(pdf->u_buf[6]),
      byte_swap_32(pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32(pdf->o_buf[0]),
      byte_swap_32(pdf->o_buf[1]),
      byte_swap_32(pdf->o_buf[2]),
      byte_swap_32(pdf->o_buf[3]),
      byte_swap_32(pdf->o_buf[4]),
      byte_swap_32(pdf->o_buf[5]),
      byte_swap_32(pdf->o_buf[6]),
      byte_swap_32(pdf->o_buf[7]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]
      );
  }
  else if (hash_mode == 10500)
  {
    pdf_t *pdfs = (pdf_t *)data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    if (pdf->id_len == 32)
    {
      snprintf(out_buf, len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32(pdf->id_buf[0]),
        byte_swap_32(pdf->id_buf[1]),
        byte_swap_32(pdf->id_buf[2]),
        byte_swap_32(pdf->id_buf[3]),
        byte_swap_32(pdf->id_buf[4]),
        byte_swap_32(pdf->id_buf[5]),
        byte_swap_32(pdf->id_buf[6]),
        byte_swap_32(pdf->id_buf[7]),
        pdf->u_len,
        byte_swap_32(pdf->u_buf[0]),
        byte_swap_32(pdf->u_buf[1]),
        byte_swap_32(pdf->u_buf[2]),
        byte_swap_32(pdf->u_buf[3]),
        byte_swap_32(pdf->u_buf[4]),
        byte_swap_32(pdf->u_buf[5]),
        byte_swap_32(pdf->u_buf[6]),
        byte_swap_32(pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32(pdf->o_buf[0]),
        byte_swap_32(pdf->o_buf[1]),
        byte_swap_32(pdf->o_buf[2]),
        byte_swap_32(pdf->o_buf[3]),
        byte_swap_32(pdf->o_buf[4]),
        byte_swap_32(pdf->o_buf[5]),
        byte_swap_32(pdf->o_buf[6]),
        byte_swap_32(pdf->o_buf[7])
        );
    }
    else
    {
      snprintf(out_buf, len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32(pdf->id_buf[0]),
        byte_swap_32(pdf->id_buf[1]),
        byte_swap_32(pdf->id_buf[2]),
        byte_swap_32(pdf->id_buf[3]),
        pdf->u_len,
        byte_swap_32(pdf->u_buf[0]),
        byte_swap_32(pdf->u_buf[1]),
        byte_swap_32(pdf->u_buf[2]),
        byte_swap_32(pdf->u_buf[3]),
        byte_swap_32(pdf->u_buf[4]),
        byte_swap_32(pdf->u_buf[5]),
        byte_swap_32(pdf->u_buf[6]),
        byte_swap_32(pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32(pdf->o_buf[0]),
        byte_swap_32(pdf->o_buf[1]),
        byte_swap_32(pdf->o_buf[2]),
        byte_swap_32(pdf->o_buf[3]),
        byte_swap_32(pdf->o_buf[4]),
        byte_swap_32(pdf->o_buf[5]),
        byte_swap_32(pdf->o_buf[6]),
        byte_swap_32(pdf->o_buf[7])
        );
    }
  }
  else if (hash_mode == 10600)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 10700)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 10900)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 11100)
  {
    u32 salt_challenge = salt.salt_buf[0];

    salt_challenge = byte_swap_32(salt_challenge);

    unsigned char *user_name = (unsigned char *)(salt.salt_buf + 1);

    snprintf(out_buf, len - 1, "%s%s*%08x*%08x%08x%08x%08x",
      SIGNATURE_POSTGRESQL_AUTH,
      user_name,
      salt_challenge,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 11200)
  {
    snprintf(out_buf, len - 1, "%s%s*%08x%08x%08x%08x%08x",
      SIGNATURE_MYSQL_AUTH,
      (unsigned char *)salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 11300)
  {
    bitcoin_wallet_t *bitcoin_wallets = (bitcoin_wallet_t *)data.esalts_buf;

    bitcoin_wallet_t *bitcoin_wallet = &bitcoin_wallets[salt_pos];

    const uint cry_master_len = bitcoin_wallet->cry_master_len;
    const uint ckey_len = bitcoin_wallet->ckey_len;
    const uint public_key_len = bitcoin_wallet->public_key_len;

    char *cry_master_buf = (char *)mymalloc((cry_master_len * 2) + 1);
    char *ckey_buf = (char *)mymalloc((ckey_len * 2) + 1);
    char *public_key_buf = (char *)mymalloc((public_key_len * 2) + 1);

    for (uint i = 0, j = 0; i < cry_master_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)bitcoin_wallet->cry_master_buf;

      sprintf(cry_master_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < ckey_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)bitcoin_wallet->ckey_buf;

      sprintf(ckey_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < public_key_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)bitcoin_wallet->public_key_buf;

      sprintf(public_key_buf + j, "%02x", ptr[i]);
    }

    snprintf(out_buf, len - 1, "%s%d$%s$%d$%s$%d$%d$%s$%d$%s",
      SIGNATURE_BITCOIN_WALLET,
      cry_master_len * 2,
      cry_master_buf,
      salt.salt_len,
      (unsigned char *)salt.salt_buf,
      salt.salt_iter + 1,
      ckey_len * 2,
      ckey_buf,
      public_key_len * 2,
      public_key_buf
      );

    free(cry_master_buf);
    free(ckey_buf);
    free(public_key_buf);
  }
  else if (hash_mode == 11400)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 11600)
  {
    seven_zip_t *seven_zips = (seven_zip_t *)data.esalts_buf;

    seven_zip_t *seven_zip = &seven_zips[salt_pos];

    const uint data_len = seven_zip->data_len;

    char *data_buf = (char *)mymalloc((data_len * 2) + 1);

    for (uint i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)seven_zip->data_buf;

      sprintf(data_buf + j, "%02x", ptr[i]);
    }

    snprintf(out_buf, len - 1, "%s%u$%u$%u$%s$%u$%08x%08x%08x%08x$%u$%u$%u$%s",
      SIGNATURE_SEVEN_ZIP,
      0,
      salt.salt_sign[0],
      0,
      (char *)seven_zip->salt_buf,
      seven_zip->iv_len,
      seven_zip->iv_buf[0],
      seven_zip->iv_buf[1],
      seven_zip->iv_buf[2],
      seven_zip->iv_buf[3],
      seven_zip->crc,
      seven_zip->data_len,
      seven_zip->unpack_size,
      data_buf);

    free(data_buf);
  }
  else if (hash_mode == 11700)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 11800)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      digest_buf[8],
      digest_buf[9],
      digest_buf[10],
      digest_buf[11],
      digest_buf[12],
      digest_buf[13],
      digest_buf[14],
      digest_buf[15]);
  }
  else if (hash_mode == 11900)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12000)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12100)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12200)
  {
    uint *ptr_digest = digest_buf;
    uint *ptr_salt = salt.salt_buf;

    snprintf(out_buf, len - 1, "%s0$1$%08x%08x$%08x%08x",
      SIGNATURE_ECRYPTFS,
      ptr_salt[0],
      ptr_salt[1],
      ptr_digest[0],
      ptr_digest[1]);
  }
  else if (hash_mode == 12300)
  {
    uint *ptr_digest = digest_buf;
    uint *ptr_salt = salt.salt_buf;

    snprintf(out_buf, len - 1, "%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
      ptr_digest[0], ptr_digest[1],
      ptr_digest[2], ptr_digest[3],
      ptr_digest[4], ptr_digest[5],
      ptr_digest[6], ptr_digest[7],
      ptr_digest[8], ptr_digest[9],
      ptr_digest[10], ptr_digest[11],
      ptr_digest[12], ptr_digest[13],
      ptr_digest[14], ptr_digest[15],
      ptr_salt[0],
      ptr_salt[1],
      ptr_salt[2],
      ptr_salt[3]);
  }
  else if (hash_mode == 12400)
  {
    // encode iteration count

    char salt_iter[5] = { 0 };

    salt_iter[0] = int_to_itoa64((salt.salt_iter) & 0x3f);
    salt_iter[1] = int_to_itoa64((salt.salt_iter >> 6) & 0x3f);
    salt_iter[2] = int_to_itoa64((salt.salt_iter >> 12) & 0x3f);
    salt_iter[3] = int_to_itoa64((salt.salt_iter >> 18) & 0x3f);
    salt_iter[4] = 0;

    // encode salt

    ptr_salt[0] = int_to_itoa64((salt.salt_buf[0]) & 0x3f);
    ptr_salt[1] = int_to_itoa64((salt.salt_buf[0] >> 6) & 0x3f);
    ptr_salt[2] = int_to_itoa64((salt.salt_buf[0] >> 12) & 0x3f);
    ptr_salt[3] = int_to_itoa64((salt.salt_buf[0] >> 18) & 0x3f);
    ptr_salt[4] = 0;

    // encode digest

    memset(tmp_buf, 0, sizeof(tmp_buf));

    digest_buf[0] = byte_swap_32(digest_buf[0]);
    digest_buf[1] = byte_swap_32(digest_buf[1]);

    memcpy(tmp_buf, digest_buf, 8);

    base64_encode(int_to_itoa64, (const u8 *)tmp_buf, 8, (u8 *)ptr_plain);

    ptr_plain[11] = 0;

    // fill the resulting buffer

    snprintf(out_buf, len - 1, "_%s%s%s", salt_iter, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 12500)
  {
    snprintf(out_buf, len - 1, "%s*0*%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_RAR3,
      byte_swap_32(salt.salt_buf[0]),
      byte_swap_32(salt.salt_buf[1]),
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5]);
  }
  else if (hash_mode == 12600)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0] + salt.salt_buf_pc[0],
      digest_buf[1] + salt.salt_buf_pc[1],
      digest_buf[2] + salt.salt_buf_pc[2],
      digest_buf[3] + salt.salt_buf_pc[3],
      digest_buf[4] + salt.salt_buf_pc[4],
      digest_buf[5] + salt.salt_buf_pc[5],
      digest_buf[6] + salt.salt_buf_pc[6],
      digest_buf[7] + salt.salt_buf_pc[7]);
  }
  else if (hash_mode == 12700)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf = hashinfo_ptr[digest_idx]->orighash;

    snprintf(out_buf, len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12800)
  {
    const u8 *ptr = (const u8 *)salt.salt_buf;

    snprintf(out_buf, len - 1, "%s,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%d,%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_MS_DRSR,
      ptr[0],
      ptr[1],
      ptr[2],
      ptr[3],
      ptr[4],
      ptr[5],
      ptr[6],
      ptr[7],
      ptr[8],
      ptr[9],
      salt.salt_iter + 1,
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]),
      byte_swap_32(digest_buf[4]),
      byte_swap_32(digest_buf[5]),
      byte_swap_32(digest_buf[6]),
      byte_swap_32(digest_buf[7])
      );
  }
  else if (hash_mode == 12900)
  {
    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      salt.salt_buf[4],
      salt.salt_buf[5],
      salt.salt_buf[6],
      salt.salt_buf[7],
      salt.salt_buf[8],
      salt.salt_buf[9],
      salt.salt_buf[10],
      salt.salt_buf[11],
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1]),
      byte_swap_32(digest_buf[2]),
      byte_swap_32(digest_buf[3]),
      byte_swap_32(digest_buf[4]),
      byte_swap_32(digest_buf[5]),
      byte_swap_32(digest_buf[6]),
      byte_swap_32(digest_buf[7]),
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3]
      );
  }
  else if (hash_mode == 13000)
  {
    rar5_t *rar5s = (rar5_t *)data.esalts_buf;

    rar5_t *rar5 = &rar5s[salt_pos];

    snprintf(out_buf, len - 1, "$rar5$16$%08x%08x%08x%08x$%u$%08x%08x%08x%08x$8$%08x%08x",
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_sign[0],
      rar5->iv[0],
      rar5->iv[1],
      rar5->iv[2],
      rar5->iv[3],
      byte_swap_32(digest_buf[0]),
      byte_swap_32(digest_buf[1])
      );
  }
  else if (hash_mode == 13100)
  {
    krb5tgs_t *krb5tgss = (krb5tgs_t *)data.esalts_buf;

    krb5tgs_t *krb5tgs = &krb5tgss[salt_pos];

    u8 *ptr_checksum = (u8 *)krb5tgs->checksum;
    u8 *ptr_edata2 = (u8 *)krb5tgs->edata2;

    char data[2560 * 4 * 2] = { 0 };

    char *ptr_data = data;

    for (uint i = 0; i < 16; i++, ptr_data += 2)
      sprintf(ptr_data, "%02x", ptr_checksum[i]);

    /* skip '$' */
    ptr_data++;

    for (uint i = 0; i < krb5tgs->edata2_len; i++, ptr_data += 2)
      sprintf(ptr_data, "%02x", ptr_edata2[i]);

    snprintf(out_buf, len - 1, "%s$%s$%s$%s",
      SIGNATURE_KRB5TGS,
      (char *)krb5tgs->account_info,
      data,
      data + 33);
  }
  else if (hash_mode == 13200)
  {
    snprintf(out_buf, len - 1, "%s*%d*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT,
      salt.salt_iter,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5],
      salt.salt_buf[6],
      salt.salt_buf[7],
      salt.salt_buf[8],
      salt.salt_buf[9]);
  }
  else if (hash_mode == 13300)
  {
    snprintf(out_buf, len - 1, "%s$%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT_SHA1,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 13400)
  {
    keepass_t *keepasss = (keepass_t *)data.esalts_buf;

    keepass_t *keepass = &keepasss[salt_pos];

    u32 version = (u32)keepass->version;
    u32 rounds = salt.salt_iter;
    u32 algorithm = (u32)keepass->algorithm;
    u32 keyfile_len = (u32)keepass->keyfile_len;

    u32 *ptr_final_random_seed = (u32 *)keepass->final_random_seed;
    u32 *ptr_transf_random_seed = (u32 *)keepass->transf_random_seed;
    u32 *ptr_enc_iv = (u32 *)keepass->enc_iv;
    u32 *ptr_contents_hash = (u32 *)keepass->contents_hash;
    u32 *ptr_keyfile = (u32 *)keepass->keyfile;

    /* specific to version 1 */
    u32 contents_len;
    u32 *ptr_contents;

    /* specific to version 2 */
    u32 expected_bytes_len;
    u32 *ptr_expected_bytes;

    u32 final_random_seed_len;
    u32 transf_random_seed_len;
    u32 enc_iv_len;
    u32 contents_hash_len;

    transf_random_seed_len = 8;
    enc_iv_len = 4;
    contents_hash_len = 8;
    final_random_seed_len = 8;

    if (version == 1)
      final_random_seed_len = 4;

    snprintf(out_buf, len - 1, "%s*%d*%d*%d",
      SIGNATURE_KEEPASS,
      version,
      rounds,
      algorithm);

    char *ptr_data = out_buf;

    ptr_data += strlen(out_buf);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < final_random_seed_len; i++, ptr_data += 8)
      sprintf(ptr_data, "%08x", ptr_final_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < transf_random_seed_len; i++, ptr_data += 8)
      sprintf(ptr_data, "%08x", ptr_transf_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < enc_iv_len; i++, ptr_data += 8)
      sprintf(ptr_data, "%08x", ptr_enc_iv[i]);

    *ptr_data = '*';
    ptr_data++;

    if (version == 1)
    {
      contents_len = (u32)keepass->contents_len;
      ptr_contents = (u32 *)keepass->contents;

      for (uint i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf(ptr_data, "%08x", ptr_contents_hash[i]);

      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      char ptr_contents_len[10] = { 0 };

      sprintf((char*)ptr_contents_len, "%d", contents_len);

      sprintf(ptr_data, "%d", contents_len);

      ptr_data += strlen(ptr_contents_len);

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < contents_len / 4; i++, ptr_data += 8)
        sprintf(ptr_data, "%08x", ptr_contents[i]);
    }
    else if (version == 2)
    {
      expected_bytes_len = 8;
      ptr_expected_bytes = (u32 *)keepass->expected_bytes;

      for (uint i = 0; i < expected_bytes_len; i++, ptr_data += 8)
        sprintf(ptr_data, "%08x", ptr_expected_bytes[i]);

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf(ptr_data, "%08x", ptr_contents_hash[i]);
    }
    if (keyfile_len)
    {
      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      sprintf(ptr_data, "%d", keyfile_len);

      ptr_data += 2;

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < 8; i++, ptr_data += 8)
        sprintf(ptr_data, "%08x", ptr_keyfile[i]);
    }
  }
  else if (hash_mode == 13500)
  {
    pstoken_t *pstokens = (pstoken_t *)data.esalts_buf;

    pstoken_t *pstoken = &pstokens[salt_pos];

    const u32 salt_len = (pstoken->salt_len > 512) ? 512 : pstoken->salt_len;

    char pstoken_tmp[1024 + 1] = { 0 };

    for (uint i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)pstoken->salt_buf;

      sprintf(pstoken_tmp + j, "%02x", ptr[i]);
    }

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      pstoken_tmp);
  }
  else if (hash_mode == 13600)
  {
    zip2_t *zip2s = (zip2_t *)data.esalts_buf;

    zip2_t *zip2 = &zip2s[salt_pos];

    const u32 salt_len = zip2->salt_len;

    char salt_tmp[32 + 1] = { 0 };

    for (uint i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)zip2->salt_buf;

      sprintf(salt_tmp + j, "%02x", ptr[i]);
    }

    const u32 data_len = zip2->data_len;

    char data_tmp[8192 + 1] = { 0 };

    for (uint i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)zip2->data_buf;

      sprintf(data_tmp + j, "%02x", ptr[i]);
    }

    const u32 auth_len = zip2->auth_len;

    char auth_tmp[20 + 1] = { 0 };

    for (uint i = 0, j = 0; i < auth_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *)zip2->auth_buf;

      sprintf(auth_tmp + j, "%02x", ptr[i]);
    }

    snprintf(out_buf, 255, "%s*%u*%u*%u*%s*%x*%u*%s*%s*%s",
      SIGNATURE_ZIP2_START,
      zip2->type,
      zip2->mode,
      zip2->magic,
      salt_tmp,
      zip2->verify_bytes,
      zip2->compress_length,
      data_tmp,
      auth_tmp,
      SIGNATURE_ZIP2_STOP);
  }
  else if ((hash_mode >= 13700) && (hash_mode <= 13799))
  {
    snprintf(out_buf, len - 1, "%s", hashfile);
  }
  else if (hash_mode == 13800)
  {
    win8phone_t *esalts = (win8phone_t *)data.esalts_buf;

    win8phone_t *esalt = &esalts[salt_pos];

    char buf[256 + 1] = { 0 };

    for (int i = 0, j = 0; i < 32; i += 1, j += 8)
    {
      sprintf(buf + j, "%08x", esalt->salt_buf[i]);
    }

    snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      buf);
  }
  else
  {
    if (hash_type == HASH_TYPE_MD4)
    {
      snprintf(out_buf, 255, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_MD5)
    {
      snprintf(out_buf, len - 1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_SHA1)
    {
      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_SHA256)
    {
      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_SHA384)
    {
      uint *ptr = digest_buf;

      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[1], ptr[0],
        ptr[3], ptr[2],
        ptr[5], ptr[4],
        ptr[7], ptr[6],
        ptr[9], ptr[8],
        ptr[11], ptr[10]);
    }
    else if (hash_type == HASH_TYPE_SHA512)
    {
      uint *ptr = digest_buf;

      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[1], ptr[0],
        ptr[3], ptr[2],
        ptr[5], ptr[4],
        ptr[7], ptr[6],
        ptr[9], ptr[8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
    }
    else if (hash_type == HASH_TYPE_LM)
    {
      snprintf(out_buf, len - 1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_ORACLEH)
    {
      snprintf(out_buf, len - 1, "%08X%08X",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_BCRYPT)
    {
      base64_encode(int_to_bf64, (const u8 *)salt.salt_buf, 16, (u8 *)tmp_buf + 0);
      base64_encode(int_to_bf64, (const u8 *)digest_buf, 23, (u8 *)tmp_buf + 22);

      tmp_buf[22 + 31] = 0; // base64_encode wants to pad

      snprintf(out_buf, len - 1, "%s$%s", (char *)salt.salt_sign, tmp_buf);
    }
    else if (hash_type == HASH_TYPE_KECCAK)
    {
      uint *ptr = digest_buf;

      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[1], ptr[0],
        ptr[3], ptr[2],
        ptr[5], ptr[4],
        ptr[7], ptr[6],
        ptr[9], ptr[8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14],
        ptr[17], ptr[16],
        ptr[19], ptr[18],
        ptr[21], ptr[20],
        ptr[23], ptr[22],
        ptr[25], ptr[24],
        ptr[27], ptr[26],
        ptr[29], ptr[28],
        ptr[31], ptr[30],
        ptr[33], ptr[32],
        ptr[35], ptr[34],
        ptr[37], ptr[36],
        ptr[39], ptr[38],
        ptr[41], ptr[30],
        ptr[43], ptr[42],
        ptr[45], ptr[44],
        ptr[47], ptr[46],
        ptr[49], ptr[48]
        );

      out_buf[salt.keccak_mdlen * 2] = 0;
    }
    else if (hash_type == HASH_TYPE_RIPEMD160)
    {
      snprintf(out_buf, 255, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_WHIRLPOOL)
    {
      digest_buf[0] = digest_buf[0];
      digest_buf[1] = digest_buf[1];
      digest_buf[2] = digest_buf[2];
      digest_buf[3] = digest_buf[3];
      digest_buf[4] = digest_buf[4];
      digest_buf[5] = digest_buf[5];
      digest_buf[6] = digest_buf[6];
      digest_buf[7] = digest_buf[7];
      digest_buf[8] = digest_buf[8];
      digest_buf[9] = digest_buf[9];
      digest_buf[10] = digest_buf[10];
      digest_buf[11] = digest_buf[11];
      digest_buf[12] = digest_buf[12];
      digest_buf[13] = digest_buf[13];
      digest_buf[14] = digest_buf[14];
      digest_buf[15] = digest_buf[15];

      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7],
        digest_buf[8],
        digest_buf[9],
        digest_buf[10],
        digest_buf[11],
        digest_buf[12],
        digest_buf[13],
        digest_buf[14],
        digest_buf[15]);
    }
    else if (hash_type == HASH_TYPE_GOST)
    {
      snprintf(out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_MYSQL)
    {
      snprintf(out_buf, len - 1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_LOTUS5)
    {
      snprintf(out_buf, len - 1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_LOTUS6)
    {
      digest_buf[0] = byte_swap_32(digest_buf[0]);
      digest_buf[1] = byte_swap_32(digest_buf[1]);
      digest_buf[2] = byte_swap_32(digest_buf[2]);
      digest_buf[3] = byte_swap_32(digest_buf[3]);

      char buf[16] = { 0 };

      memcpy(buf + 0, salt.salt_buf, 5);
      memcpy(buf + 5, digest_buf, 9);

      buf[3] -= -4;

      base64_encode(int_to_lotus64, (const u8 *)buf, 14, (u8 *)tmp_buf);

      tmp_buf[18] = salt.salt_buf_pc[7];
      tmp_buf[19] = 0;

      snprintf(out_buf, len - 1, "(G%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_LOTUS8)
    {
      char buf[52] = { 0 };

      // salt

      memcpy(buf + 0, salt.salt_buf, 16);

      buf[3] -= -4;

      // iteration

      snprintf(buf + 16, 11, "%010i", salt.salt_iter + 1);

      // chars

      buf[26] = salt.salt_buf_pc[0];
      buf[27] = salt.salt_buf_pc[1];

      // digest

      memcpy(buf + 28, digest_buf, 8);

      base64_encode(int_to_lotus64, (const u8 *)buf, 36, (u8 *)tmp_buf);

      tmp_buf[49] = 0;

      snprintf(out_buf, len - 1, "(H%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_CRC32)
    {
      snprintf(out_buf, len - 1, "%08x", byte_swap_32(digest_buf[0]));
    }
  }

  if (salt_type == SALT_TYPE_INTERN)
  {
    size_t pos = strlen(out_buf);

    out_buf[pos] = data.separator;

    char *ptr = (char *)salt.salt_buf;

    memcpy(out_buf + pos + 1, ptr, salt.salt_len);

    out_buf[pos + 1 + salt.salt_len] = 0;
  }
}
