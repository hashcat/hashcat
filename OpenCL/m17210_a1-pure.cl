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

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.cl"
#include "inc_simd.cl"

#define CRC32(x,c) (((x)>>8)^l_crc32tab[((x)^(c))&0xff])
#define MSB(x)     ((x)>>24)
#define CONST      0x08088405
#define POLYNOMIAL 0xEDB88320

#define MAX_UNCOMPRESSED_LENGTH 4096

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
  u8  data[MAX_UNCOMPRESSED_LENGTH];
} pkzip_hash_t;

typedef struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;
  pkzip_hash_t hash;
} pkzip_t;

__kernel void m17210_sxx (KERN_ATTR_ESALT (pkzip_t))
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
   * loop
   */

  u32x key0, key1, key2;
  u32x key0init, key1init, key2init;

  key0init = 0x12345678;
  key1init = 0x23456789;
  key2init = 0x34567890;

  for (u8 i = 0; i < pws[gid].pw_len; i++)
  {
    key0init = CRC32( key0init, (pws[gid].i[i >> 2] >> ((i & 3) << 3)) & 0xff );
    key1init = (key1init + (key0init & 0xff)) * CONST + 1;
    key2init = CRC32( key2init, MSB(key1init) );
  }

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    key0 = key0init;
    key1 = key1init;
    key2 = key2init;

    for (u8 i = 0; i < combs_buf[il_pos].pw_len; i++)
    {
      key0 = CRC32( key0, (combs_buf[il_pos].i[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );
    }

    u8  plain;
    u8  key3;
    u16 temp;

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[0] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[1] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[2] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[3] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[4] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[5] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[6] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[7] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[8] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[9] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[10] ^ key3;

    if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hash.checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp & 0xff))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp^1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[11] ^ key3;

    if (plain != (esalt_bufs[digests_offset].hash.checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp >> 8))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[12] ^ key3;

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    u32x crc = 0xffffffff;
    crc = CRC32(crc, plain);

    for (unsigned int i = 13; i < esalt_bufs[digests_offset].hash.data_length; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      crc = CRC32(crc, plain);
    }
    crc = ~crc;

    if (crc == esalt_bufs[digests_offset].hash.crc32)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

__kernel void m17210_mxx (KERN_ATTR_ESALT (pkzip_t))
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
   * loop
   */

  u32x key0, key1, key2;
  u32x key0init, key1init, key2init;

  key0init = 0x12345678;
  key1init = 0x23456789;
  key2init = 0x34567890;

  for (u8 i = 0; i < pws[gid].pw_len; i++)
  {
    key0init = CRC32( key0init, (pws[gid].i[i >> 2] >> ((i & 3) << 3)) & 0xff );
    key1init = (key1init + (key0init & 0xff)) * CONST + 1;
    key2init = CRC32( key2init, MSB(key1init) );
  }

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    key0 = key0init;
    key1 = key1init;
    key2 = key2init;

    for (u8 i = 0; i < combs_buf[il_pos].pw_len; i++)
    {
      key0 = CRC32( key0, (combs_buf[il_pos].i[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );
    }

    u8  plain;
    u8  key3;
    u16 temp;

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[0] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[1] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[2] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[3] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[4] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[5] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[6] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[7] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[8] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[9] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[10] ^ key3;

    if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hash.checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp & 0xff))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp^1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[11] ^ key3;

    if (plain != (esalt_bufs[digests_offset].hash.checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp >> 8))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[12] ^ key3;

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    u32x crc = 0xffffffff;
    crc = CRC32(crc, plain);

    for (unsigned int i = 13; i < esalt_bufs[digests_offset].hash.data_length; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      crc = CRC32(crc, plain);
    }
    crc = ~crc;

    if (crc == esalt_bufs[digests_offset].hash.crc32)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
