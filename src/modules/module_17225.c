/*

PKZIP Kernels for Hashcat (c) 2018, European Union

PKZIP Kernels for Hashcat has been developed by the Joint Research Centre of the European Commission.
It is released as open source software under the MIT License.

PKZIP Kernels for Hashcat makes use of two primary external components, which continue to be subject
to the terms and conditions stipulated in the respective licences they have been released under. These
external components include, but are not necessarily limited to, the following:

-----

1. Hashcat: MIT License

Copyright (c) 2015-2018 Jens Steube

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

2. Miniz: MIT License

Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

The European Union disclaims all liability related to or arising out of the use made by third parties of
any external components and dependencies which may be included with PKZIP Kernels for Hashcat.

-----

The MIT License

Copyright (c) 2018, EUROPEAN UNION

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Author:              Sein Coray
Related publication: https://scitepress.org/PublicationsDetail.aspx?ID=KLPzPqStp5g=

*/

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "PKZIP (Mixed Multi-File)";
static const u64   KERN_TYPE      = 17225;
static const u32   OPTI_TYPE      = 0;
static const u64   OPTS_TYPE      = 0;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$pkzip2$3*1*1*0*0*24*3e2c*3ef8*0619e9d17ff3f994065b99b1fa8aef41c056edf9fa4540919c109742dcb32f797fc90ce0*1*0*8*24*431a*3f26*18e2461c0dbad89bd9cc763067a020c89b5e16195b1ac5fa7fb13bd246d000b6833a2988*2*0*23*17*1e3c1a16*2e4*2f*0*23*1e3c*3f2d*54ea4dbc711026561485bbd191bf300ae24fa0997f3779b688cdad323985f8d3bb8b0c*$/pkzip2$";

#define MAX_DATA (320 * 1024)

// this is required to force mingw to accept the packed attribute
#pragma pack(push,1)

struct pkzip_hash
{
  u8  data_type_enum;
  u8  magic_type_enum;
  u32 compressed_length;
  u32 uncompressed_length;
  u32 crc32;
  u32 offset;
  u32 additional_offset;
  u8  compression_type;
  u32 data_length;
  u16 checksum_from_crc;
  u16 checksum_from_timestamp;
  u32 data[MAX_DATA / 4]; // a quarter because of the u32 type

} __attribute__((packed));

typedef struct pkzip_hash pkzip_hash_t;

struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;

  pkzip_hash_t hashes[8];

} __attribute__((packed));

typedef struct pkzip pkzip_t;

#pragma pack(pop)

static const char *SIGNATURE_PKZIP_V1 = "$pkzip$";
static const char *SIGNATURE_PKZIP_V2 = "$pkzip2$";

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

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pkzip_t);

  return esalt_size;
}

void hex_to_binary (const char *source, int len, char* out)
{
  for (int i = 0, j = 0; j < len; i += 1, j += 2)
  {
    out[i] = hex_to_u8 ((const u8 *) &source[j]);
  }
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  pkzip_t *pkzip = (pkzip_t *) esalt_buf;

  u32 *digest = (u32 *) digest_buf;

  char input[line_len + 1];
  input[line_len] = '\0';
  memcpy (&input, line_buf, line_len);

  char *saveptr = NULL;

  char *p = strtok_r (input, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  if (strncmp (p, SIGNATURE_PKZIP_V1, 7) != 0 && strncmp (p, SIGNATURE_PKZIP_V2, 8) != 0) return PARSER_SIGNATURE_UNMATCHED;

  pkzip->version = 1;

  if (strlen (p) == 9) pkzip->version = 2;

  char sub[2];
  sub[0] = p[strlen (p) - 1];
  sub[1] = '\0';
  pkzip->hash_count = atoi (sub);

  // check here that the hash_count is valid for the attack type
  if (pkzip->hash_count > 8) return PARSER_HASH_VALUE;

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->checksum_size = atoi (p);
  if (pkzip->checksum_size != 1 && pkzip->checksum_size != 2) return PARSER_HASH_LENGTH;

  for (int i = 0; i < pkzip->hash_count; i++)
  {
    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hashes[i].data_type_enum = atoi (p);
    if (pkzip->hashes[i].data_type_enum > 3) return PARSER_HASH_LENGTH;

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hashes[i].magic_type_enum = atoi (p);

    if (pkzip->hashes[i].data_type_enum > 1)
    {
      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      pkzip->hashes[i].compressed_length = strtoul (p, NULL, 16);

      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      pkzip->hashes[i].uncompressed_length = strtoul (p, NULL, 16);
      if (pkzip->hashes[i].compressed_length > MAX_DATA)
      {
        return PARSER_TOKEN_LENGTH;
      }

      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      u32 crc32 = 0;
      sscanf (p, "%x", &crc32);
      pkzip->hashes[i].crc32 = crc32;

      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      pkzip->hashes[i].offset = strtoul (p, NULL, 16);

      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      pkzip->hashes[i].additional_offset = strtoul (p, NULL, 16);
    }

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hashes[i].compression_type = atoi (p);
    if (pkzip->hashes[i].compression_type != 8 && pkzip->hashes[i].compression_type != 0) return PARSER_HASH_VALUE;

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hashes[i].data_length = strtoul (p, NULL, 16);

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    u16 checksum_from_crc = 0;
    sscanf (p, "%hx", &checksum_from_crc);
    pkzip->hashes[i].checksum_from_crc = checksum_from_crc;

    if (pkzip->version == 2)
    {
      p = strtok_r (NULL, "*", &saveptr);
      if (p == NULL) return PARSER_HASH_LENGTH;
      u16 checksum_from_timestamp = 0;
      sscanf (p, "%hx", &checksum_from_timestamp);
      pkzip->hashes[i].checksum_from_timestamp = checksum_from_timestamp;
    }
    else
    {
      pkzip->hashes[i].checksum_from_timestamp = pkzip->hashes[i].checksum_from_crc;
    }

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;

    hex_to_binary (p, strlen (p), (char *) &(pkzip->hashes[i].data));

    // fake salt
    salt->salt_buf[i] = pkzip->hashes[i].data[0];

    if (i == 0) digest[i] = pkzip->hashes[i].checksum_from_crc;
  }

  salt->salt_len = pkzip->hash_count << 2;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const pkzip_t *pkzip = (const pkzip_t *) esalt_buf;

  int out_len = 0;

  if (pkzip->version == 1)
  {
    sprintf (line_buf, "%s", SIGNATURE_PKZIP_V1);
    out_len += 7;
  }
  else
  {
    sprintf (line_buf, "%s", SIGNATURE_PKZIP_V2);
    out_len += 8;
  }
  out_len += sprintf (line_buf + out_len, "%i*%i*", pkzip->hash_count, pkzip->checksum_size);

  for (int cnt = 0; cnt < pkzip->hash_count; cnt++)
  {
    if (cnt > 0)
    {
      out_len += sprintf (line_buf + out_len, "*");
    }
    out_len += sprintf (line_buf + out_len, "%i*%i*", pkzip->hashes[cnt].data_type_enum, pkzip->hashes[cnt].magic_type_enum);
    if (pkzip->hashes[cnt].data_type_enum > 1)
    {
      out_len += sprintf (line_buf + out_len, "%x*%x*%x*%x*%x*", pkzip->hashes[cnt].compressed_length, pkzip->hashes[cnt].uncompressed_length, pkzip->hashes[cnt].crc32, pkzip->hashes[cnt].offset, pkzip->hashes[cnt].additional_offset);
    }

    out_len += sprintf (line_buf + out_len, "%i*%x*%04x*", pkzip->hashes[cnt].compression_type, pkzip->hashes[cnt].data_length, pkzip->hashes[cnt].checksum_from_crc);
    if (pkzip->version == 2)
    {
      out_len += sprintf (line_buf + out_len, "%04x*", pkzip->hashes[cnt].checksum_from_timestamp);
    }

    for (u32 i = 0; i < pkzip->hashes[cnt].data_length / 4; i++)
    {
      out_len += sprintf (line_buf + out_len, "%08x", byte_swap_32 (pkzip->hashes[cnt].data[i]));
    }
    for (u32 i = 0; i < pkzip->hashes[cnt].data_length % 4; i++)
    {
      out_len += sprintf (line_buf + out_len, "%02x", (pkzip->hashes[cnt].data[pkzip->hashes[cnt].data_length / 4] >> i*8) & 0xff);
    }
  }

  if (pkzip->version == 1)
  {
    out_len += sprintf (line_buf + out_len, "*$/pkzip$");
  }
  else
  {
    out_len += sprintf (line_buf + out_len, "*$/pkzip2$");
  }

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
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
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
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
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
