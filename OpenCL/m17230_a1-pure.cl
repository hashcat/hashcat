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
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)

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

// One buffer of the candidate through the key schedule. -a 12 assembles a candidate from five
// pieces, so this runs once per piece rather than once for the base word and once for the amplifier.

#define update_key012_buf(k0,k1,k2,buf,len,t)                                             \
{                                                                                         \
  const u32 blen = (len);                                                                 \
                                                                                          \
  for (u32 bi = 0, bj = 0; bi < blen; bi += 4, bj += 1)                                   \
  {                                                                                       \
    if (blen >= (bi + 1)) update_key012 (k0, k1, k2, unpack_v8a_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 2)) update_key012 (k0, k1, k2, unpack_v8b_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 3)) update_key012 (k0, k1, k2, unpack_v8c_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 4)) update_key012 (k0, k1, k2, unpack_v8d_from_v32_S ((buf)[bj]), t); \
  }                                                                                       \
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

  pkzip_hash_t hashes[8];

} __attribute__((packed));

typedef struct pkzip pkzip_t;

#pragma pack(pop)

KERNEL_FQ KERNEL_FA void m17230_sxx (KERN_ATTR_ESALT (pkzip_t))
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
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 checksum_size = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 hash_count    = esalt_bufs[DIGESTS_OFFSET_HOST].hash_count;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32x key0empty = key0init;
  const u32x key1empty = key1init;
  const u32x key2empty = key2init;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0init2 = key0init;
    u32x key1init2 = key1init;
    u32x key2init2 = key2init;

    if (COMBS_IS_MIDDLE)
    {
      // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
      // base word produced on its own is no longer the state this continues from

      key0init2 = key0empty;
      key1init2 = key1empty;
      key2init2 = key2empty;

      update_key012_buf (key0init2, key1init2, key2init2, COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, pws[gid].i,            pws[gid].pw_len,            l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, l_crc32tab);
    }

    update_key012_buf (key0init2, key1init2, key2init2, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, l_crc32tab);

    u32 plain;
    u32 key3;
    u32 next;

    for (u32 idx = 0; idx < hash_count; idx++)
    {
      u32x key0 = key0init2;
      u32x key1 = key1init2;
      u32x key2 = key2init2;

      if (idx == 0) next = l_data[0];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[0];

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

      if (idx == 0) next = l_data[1];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[1];

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

      if (idx == 0) next = l_data[2];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[2];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      if ((checksum_size == 2) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc & 0xff) != plain) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp & 0xff) != plain)) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      if ((plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc >> 8)) && (plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp >> 8))) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[3];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[3];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && ((plain & 6) == 0 || (plain & 6) == 6)) break;

      if (idx + 1 == esalt_bufs[DIGESTS_OFFSET_HOST].hash_count)
      {
        /**
         * digest
         */

        const u32 search[4] =
        {
          esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].checksum_from_crc,
          0,
          0,
          0
        };

        const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].checksum_from_crc;
        const u32 r1 = 0;
        const u32 r2 = 0;
        const u32 r3 = 0;

        COMPARE_S_SIMD (r0, r1, r2, r3);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m17230_mxx (KERN_ATTR_ESALT (pkzip_t))
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
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 checksum_size = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 hash_count    = esalt_bufs[DIGESTS_OFFSET_HOST].hash_count;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32x key0empty = key0init;
  const u32x key1empty = key1init;
  const u32x key2empty = key2init;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0init2 = key0init;
    u32x key1init2 = key1init;
    u32x key2init2 = key2init;

    if (COMBS_IS_MIDDLE)
    {
      // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
      // base word produced on its own is no longer the state this continues from

      key0init2 = key0empty;
      key1init2 = key1empty;
      key2init2 = key2empty;

      update_key012_buf (key0init2, key1init2, key2init2, COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, pws[gid].i,            pws[gid].pw_len,            l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, l_crc32tab);
    }

    update_key012_buf (key0init2, key1init2, key2init2, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, l_crc32tab);

    u32 plain;
    u32 key3;
    u32 next;

    for (u32 idx = 0; idx < hash_count; idx++)
    {
      u32x key0 = key0init2;
      u32x key1 = key1init2;
      u32x key2 = key2init2;

      if (idx == 0) next = l_data[0];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[0];

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

      if (idx == 0) next = l_data[1];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[1];

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

      if (idx == 0) next = l_data[2];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[2];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      if ((checksum_size == 2) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc & 0xff) != plain) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp & 0xff) != plain)) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      if ((plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc >> 8)) && (plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp >> 8))) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[3];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[3];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && ((plain & 6) == 0 || (plain & 6) == 6)) break;

      if (idx + 1 == esalt_bufs[DIGESTS_OFFSET_HOST].hash_count)
      {
        const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].checksum_from_crc;
        const u32 r1 = 0;
        const u32 r2 = 0;
        const u32 r3 = 0;

        COMPARE_M_SIMD (r0, r1, r2, r3);
      }
    }
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
