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

Author: Sein Coray

*/

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_rp.h"
#include "inc_rp.cl"

#define CRC32(x,c) (((x)>>8)^l_crc32tab[((x)^(c))&0xff])
#define MSB(x)     ((x)>>24)
#define CONST      0x08088405
#define POLYNOMIAL 0xEDB88320

#define MAX_COMPRESSED_LENGTH   2048

typedef struct pkzip_hash
{
  u8  data_type_enum;
  u8  magic_type_enum;
  u32 compressed_length;
  u32 uncompressed_length;
  u32 crc32;
  u8  offset;
  u8  additional_offset;
  u8  compression_type;
  u32 data_length;
  u16 checksum_from_crc;
  u16 checksum_from_timestamp;
  u8  data[MAX_COMPRESSED_LENGTH];
} pkzip_hash_t;

typedef struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;
  pkzip_hash_t hashes[8];
} pkzip_t;

__kernel void m17230_sxx (KERN_ATTR_VECTOR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  __local u32 l_crc32tab[0x100];

  u32 remainder;
  u32 b = 0;
  u8 set = 0;
  for (u32 b = 0; b < 256; b++)
  {
    remainder = b;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    l_crc32tab[b] = remainder;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x key0, key1, key2;
  u32x key0init, key1init, key2init;
  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0 = w0l | w0r;
    w[0] = w0;

    key0init = 0x12345678;
    key1init = 0x23456789;
    key2init = 0x34567890;

    for (u8 i = 0; i < pw_len; i++)
    {
      key0init = CRC32( key0init, (w[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1init = (key1init + (key0init & 0xff)) * CONST + 1;
      key2init = CRC32( key2init, MSB(key1init) );
    }

    u8 plain;
    u8 key3;
    u16 temp;

    for (u8 idx = 0; idx < esalt_bufs[digests_offset].hash_count; idx++)
    {
      key0 = key0init;
      key1 = key1init;
      key2 = key2init;

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[0] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[1] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[2] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[3] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[4] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[5] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[6] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[7] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[8] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[9] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[10] ^ key3;

      if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_timestamp & 0xff))
      {
        idx = 0xfe;
        continue;
      }

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[11] ^ key3;

      if (plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_timestamp >> 8))
      {
        idx = 0xfe;
        continue;
      }

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[12] ^ key3;

      if ((plain & 6) == 0 || (plain & 6) == 6)
      {
        idx = 0xfe;
        continue;
      }

      if (idx + 1 == esalt_bufs[digests_offset].hash_count){                                                                                                                                                            \
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}

__kernel void m17230_mxx (KERN_ATTR_VECTOR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  __local u32 l_crc32tab[0x100];

  u32 remainder;
  u32 b = 0;
  u8 set = 0;
  for (u32 b = 0; b < 256; b++)
  {
    remainder = b;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    l_crc32tab[b] = remainder;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x key0, key1, key2;
  u32x key0init, key1init, key2init;
  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0 = w0l | w0r;
    w[0] = w0;

    key0init = 0x12345678;
    key1init = 0x23456789;
    key2init = 0x34567890;

    for (u8 i = 0; i < pw_len; i++)
    {
      key0init = CRC32( key0init, (w[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1init = (key1init + (key0init & 0xff)) * CONST + 1;
      key2init = CRC32( key2init, MSB(key1init) );
    }

    u8 plain;
    u8 key3;
    u16 temp;

    for (u8 idx = 0; idx < esalt_bufs[digests_offset].hash_count; idx++)
    {
      key0 = key0init;
      key1 = key1init;
      key2 = key2init;

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[0] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[1] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[2] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[3] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[4] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[5] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[6] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[7] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[8] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[9] ^ key3;
      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[10] ^ key3;

      if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_timestamp & 0xff))
      {
        idx = 0xfe;
        continue;
      }

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[11] ^ key3;

      if (plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hashes[idx].checksum_from_timestamp >> 8))
      {
        idx = 0xfe;
        continue;
      }

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hashes[idx].data[12] ^ key3;

      if ((plain & 6) == 0 || (plain & 6) == 6)
      {
        idx = 0xfe;
        continue;
      }

      if (idx + 1 == esalt_bufs[digests_offset].hash_count){                                                                                                                                                            \
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}