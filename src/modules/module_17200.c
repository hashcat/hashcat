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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "PKZIP (Compressed)";
static const u64   KERN_TYPE      = 17200;
static const u32   OPTI_TYPE      = 0;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$";

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

  pkzip_hash_t hash;

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

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // problem with this kernel is the huge amount of register pressure on u8 tmp[TMPSIZ];
  // some runtimes cant handle it by swapping it to global memory
  // it leads to CL_KERNEL_WORK_GROUP_SIZE to return 0 and later we will divide with 0
  // workaround would be to rewrite kernel to use global memory

  if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
  {
    return true;
  }

  // AppleM1, OpenCL, MTLCompilerService never-end
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    return true;
  }

  return false;
}

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
  if (pkzip->hash_count != 1) return PARSER_HASH_VALUE;

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->checksum_size = atoi (p);
  if (pkzip->checksum_size != 1 && pkzip->checksum_size != 2) return PARSER_HASH_LENGTH;

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->hash.data_type_enum = atoi (p);
  if (pkzip->hash.data_type_enum > 3) return PARSER_HASH_LENGTH;

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->hash.magic_type_enum = atoi (p);

  if (pkzip->hash.data_type_enum > 1)
  {
    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hash.compressed_length = strtoul (p, NULL, 16);

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hash.uncompressed_length = strtoul (p, NULL, 16);
    if (pkzip->hash.compressed_length > MAX_DATA)
    {
      return PARSER_TOKEN_LENGTH;
    }

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    u32 crc32 = 0;
    sscanf (p, "%x", &crc32);
    pkzip->hash.crc32 = crc32;

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hash.offset = strtoul (p, NULL, 16);

    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    pkzip->hash.additional_offset = strtoul (p, NULL, 16);
  }

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->hash.compression_type = atoi (p);
  if (pkzip->hash.compression_type != 8) return PARSER_PKZIP_CT_UNMATCHED;

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  pkzip->hash.data_length = strtoul (p, NULL, 16);

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;
  u16 checksum_from_crc = 0;
  sscanf (p, "%hx", &checksum_from_crc);
  pkzip->hash.checksum_from_crc = checksum_from_crc;

  if (pkzip->version == 2)
  {
    p = strtok_r (NULL, "*", &saveptr);
    if (p == NULL) return PARSER_HASH_LENGTH;
    u16 checksum_from_timestamp = 0;
    sscanf (p, "%hx", &checksum_from_timestamp);
    pkzip->hash.checksum_from_timestamp = checksum_from_timestamp;
  }
  else
  {
    pkzip->hash.checksum_from_timestamp = pkzip->hash.checksum_from_crc;
  }

  p = strtok_r (NULL, "*", &saveptr);
  if (p == NULL) return PARSER_HASH_LENGTH;

  hex_to_binary (p, strlen (p), (char *) &(pkzip->hash.data));

  // fake salt
  salt->salt_buf[0] = pkzip->hash.data[0];
  salt->salt_buf[1] = pkzip->hash.data[1];
  salt->salt_buf[2] = pkzip->hash.data[2];
  salt->salt_buf[3] = pkzip->hash.data[3];

  salt->salt_len = 16;

  digest[0] = pkzip->hash.crc32;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

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

  out_len += sprintf (line_buf + out_len, "%i*%i*", pkzip->hash.data_type_enum, pkzip->hash.magic_type_enum);
  if (pkzip->hash.data_type_enum > 1)
  {
    out_len += sprintf (line_buf + out_len, "%x*%x*%x*%x*%x*", pkzip->hash.compressed_length, pkzip->hash.uncompressed_length, pkzip->hash.crc32, pkzip->hash.offset, pkzip->hash.additional_offset);
  }

  out_len += sprintf (line_buf + out_len, "%i*%x*%04x*", pkzip->hash.compression_type, pkzip->hash.data_length, pkzip->hash.checksum_from_crc);
  if (pkzip->version == 2)
  {
    out_len += sprintf (line_buf + out_len, "%04x*", pkzip->hash.checksum_from_timestamp);
  }

  for (u32 i = 0; i < pkzip->hash.data_length / 4; i++)
  {
    out_len += sprintf (line_buf + out_len, "%08x", byte_swap_32 (pkzip->hash.data[i]));
  }
  for (u32 i = 0; i < pkzip->hash.data_length % 4; i++)
  {
    out_len += sprintf (line_buf + out_len, "%02x", (pkzip->hash.data[pkzip->hash.data_length / 4] >> i*8) & 0xff);
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
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
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
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
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
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
