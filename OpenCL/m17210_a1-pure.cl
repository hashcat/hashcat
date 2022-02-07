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

#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)

#define MAX_LOCAL 512 // too much leaves no room for compiler optimizations, simply benchmark to find a good trade-off - make it as big as possible
#define TMPSIZ    32

#define CRC32(x,c,t) (((x) >> 8) ^ (t)[((x) ^ (c)) & 0xff])
#define MSB(x)       ((x) >> 24)
#define CONST        0x08088405

#define MAX_DATA (320 * 1024)

#define update_key012(k0,k1,k2,c,t)           \
{                                             \
  (k0) = CRC32 ((k0), c, (t));                \
  (k1) = ((k1) + ((k0) & 0xff)) * CONST + 1;  \
  (k2) = CRC32 ((k2), MSB (k1), (t));         \
}

#define update_key3(k2,k3)                  \
{                                           \
  const u32 temp = ((k2) & 0xffff) | 3;     \
                                            \
  (k3) = ((temp * (temp ^ 1)) >> 8) & 0xff; \
}

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

CONSTANT_VK u32a crc32tab[256] =
{
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

KERNEL_FQ void m17210_sxx (KERN_ATTR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  LOCAL_VK u32 l_data[MAX_LOCAL];

  for (u64 i = lid; i < MAX_LOCAL; i += lsz)
  {
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * prefetch from global memory
   */

  const u32 checksum_size           = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 checksum_from_crc       = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_crc;
  const u32 checksum_from_timestamp = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_timestamp;
  const u32 crc32_final             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.crc32;
  const u32 data_length             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data_length;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0 = key0init;
    u32x key1 = key1init;
    u32x key2 = key2init;

    for (u32 i = 0, j = 0; i < combs_buf[il_pos].pw_len; i += 4, j += 1)
    {
      if (combs_buf[il_pos].pw_len >= (i + 1)) update_key012 (key0, key1, key2, unpack_v8a_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 2)) update_key012 (key0, key1, key2, unpack_v8b_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 3)) update_key012 (key0, key1, key2, unpack_v8c_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 4)) update_key012 (key0, key1, key2, unpack_v8d_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
    }

    u32 plain;
    u32 key3;
    u32 next;

    next = l_data[0];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    next = l_data[1];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    next = l_data[2];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    if ((checksum_size == 2) && ((checksum_from_crc & 0xff) != plain) && ((checksum_from_timestamp & 0xff) != plain)) continue;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    if ((plain != (checksum_from_crc >> 8)) && (plain != (checksum_from_timestamp >> 8))) continue;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    u32x crc = 0xffffffff;

    for (u32 i = 12, j = 3; i < data_length && j < MAX_LOCAL; i += 4, j += 1)
    {
      next = l_data[j];

      if (data_length >= (i + 1))
      {
        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 2))
      {
        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 3))
      {
        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 4))
      {
        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }
    }

    // global memory from here

    for (u32 j = MAX_LOCAL, i = MAX_LOCAL * 4; i < data_length; j++, i += 4)
    {
      next = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[j];

      if (data_length >= (i + 1))
      {
        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 2))
      {
        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 3))
      {
        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 4))
      {
        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }
    }

    const u32 r0 = ~crc;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m17210_mxx (KERN_ATTR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  LOCAL_VK u32 l_data[MAX_LOCAL];

  for (u64 i = lid; i < MAX_LOCAL; i += lsz)
  {
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 checksum_size           = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 checksum_from_crc       = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_crc;
  const u32 checksum_from_timestamp = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_timestamp;
  const u32 crc32_final             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.crc32;
  const u32 data_length             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data_length;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0 = key0init;
    u32x key1 = key1init;
    u32x key2 = key2init;

    for (u32 i = 0, j = 0; i < combs_buf[il_pos].pw_len; i += 4, j += 1)
    {
      if (combs_buf[il_pos].pw_len >= (i + 1)) update_key012 (key0, key1, key2, unpack_v8a_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 2)) update_key012 (key0, key1, key2, unpack_v8b_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 3)) update_key012 (key0, key1, key2, unpack_v8c_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
      if (combs_buf[il_pos].pw_len >= (i + 4)) update_key012 (key0, key1, key2, unpack_v8d_from_v32_S (combs_buf[il_pos].i[j]), l_crc32tab);
    }

    u32 plain;
    u32 key3;
    u32 next;

    next = l_data[0];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    next = l_data[1];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    next = l_data[2];

    update_key3 (key2, key3);
    plain = unpack_v8a_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8b_from_v32_S (next) ^ key3;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8c_from_v32_S (next) ^ key3;
    if ((checksum_size == 2) && ((checksum_from_crc & 0xff) != plain) && ((checksum_from_timestamp & 0xff) != plain)) continue;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);
    plain = unpack_v8d_from_v32_S (next) ^ key3;
    if ((plain != (checksum_from_crc >> 8)) && (plain != (checksum_from_timestamp >> 8))) continue;
    update_key012 (key0, key1, key2, plain, l_crc32tab);

    u32x crc = 0xffffffff;

    for (u32 i = 12, j = 3; i < data_length && j < MAX_LOCAL; i += 4, j += 1)
    {
      next = l_data[j];

      if (data_length >= (i + 1))
      {
        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 2))
      {
        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 3))
      {
        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 4))
      {
        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }
    }

    // global memory from here

    for (u32 j = MAX_LOCAL, i = MAX_LOCAL * 4; i < data_length; j++, i += 4)
    {
      next = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[j];

      if (data_length >= (i + 1))
      {
        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 2))
      {
        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 3))
      {
        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }

      if (data_length >= (i + 4))
      {
        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        crc = CRC32 (crc, plain, l_crc32tab);
      }
    }

    const u32 r0 = ~crc;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

#undef MAX_LOCAL
#undef TMPSIZ
#undef CRC32
#undef MSB
#undef CONST
#undef MAX_DATA
#undef update_key012
#undef update_key3
