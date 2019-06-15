/*

PKZIP Kernels for Hashcat (c) 2018, European Union

PKZIP Kernels for Hashcat has been developed by the Joint Research Centre of the European Commission.
It is released as open source software under the MIT License.

PKZIP Kernels for Hashcat makes use of a primary external components, which continue to be subject
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

  /* for fixed length 3
  for (u32 pos = pw_len - 1; pos >= 3; pos--)
  {
    const u32 t = hc_bfe_S (pws[gid].i[pos / 4], (pos & 3) * 8, 8);

    inv_update_key012 (prep0, prep1, prep2, t, l_icrc32tab);
  }

  inv_update_key012 (prep0, prep1, prep2, 0, l_icrc32tab);

  prep2 = INVCRC32 (prep2, MSB (prep1), l_icrc32tab);
  prep1 = (prep1 - 1) * INVCONST;

    key0 = key0 ^ w0c;

    key1 = key1 - (key0 & 0xff);
    key0 = INVCRC32 (key0, w0b, l_icrc32tab);

    inv_update_key012 (key0, key1, key2, w0a, l_icrc32tab);
  */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

#define MSB(x)          ((x) >> 24)
#define CRC32(x,c,t)    (((x) >> 8) ^ (t)[((x) ^ (c)) & 0xff])
#define CONST           0x08088405
#define INVCRC32(x,c,t) (((x) << 8) ^ (t)[(x) >> 24] ^ ((c) & 0xff))
#define INVCONST        0xd94fa8cd
#define KEY0INIT        0x12345678
#define KEY1INIT        0x23456789
#define KEY2INIT        0x34567890

#define inv_update_key012(k0,k1,k2,c,t)         \
  (k2) = INVCRC32 ((k2), MSB (k1), (t));        \
  (k1) = ((k1) - 1) * INVCONST - ((k0) & 0xff); \
  (k0) = INVCRC32 ((k0), (c), (t));

#define update_key012(k0,k1,k2,c,t)           \
{                                             \
  (k0) = CRC32 ((k0), c, (t));                \
  (k1) = ((k1) + ((k0) & 0xff)) * CONST + 1;  \
  (k2) = CRC32 ((k2), MSB (k1), (t));         \
}

CONSTANT_VK u32a icrc32tab[256] =
{
  0x00000000, 0xdb710641, 0x6d930ac3, 0xb6e20c82,
  0xdb261586, 0x005713c7, 0xb6b51f45, 0x6dc41904,
  0x6d3d2d4d, 0xb64c2b0c, 0x00ae278e, 0xdbdf21cf,
  0xb61b38cb, 0x6d6a3e8a, 0xdb883208, 0x00f93449,
  0xda7a5a9a, 0x010b5cdb, 0xb7e95059, 0x6c985618,
  0x015c4f1c, 0xda2d495d, 0x6ccf45df, 0xb7be439e,
  0xb74777d7, 0x6c367196, 0xdad47d14, 0x01a57b55,
  0x6c616251, 0xb7106410, 0x01f26892, 0xda836ed3,
  0x6f85b375, 0xb4f4b534, 0x0216b9b6, 0xd967bff7,
  0xb4a3a6f3, 0x6fd2a0b2, 0xd930ac30, 0x0241aa71,
  0x02b89e38, 0xd9c99879, 0x6f2b94fb, 0xb45a92ba,
  0xd99e8bbe, 0x02ef8dff, 0xb40d817d, 0x6f7c873c,
  0xb5ffe9ef, 0x6e8eefae, 0xd86ce32c, 0x031de56d,
  0x6ed9fc69, 0xb5a8fa28, 0x034af6aa, 0xd83bf0eb,
  0xd8c2c4a2, 0x03b3c2e3, 0xb551ce61, 0x6e20c820,
  0x03e4d124, 0xd895d765, 0x6e77dbe7, 0xb506dda6,
  0xdf0b66ea, 0x047a60ab, 0xb2986c29, 0x69e96a68,
  0x042d736c, 0xdf5c752d, 0x69be79af, 0xb2cf7fee,
  0xb2364ba7, 0x69474de6, 0xdfa54164, 0x04d44725,
  0x69105e21, 0xb2615860, 0x048354e2, 0xdff252a3,
  0x05713c70, 0xde003a31, 0x68e236b3, 0xb39330f2,
  0xde5729f6, 0x05262fb7, 0xb3c42335, 0x68b52574,
  0x684c113d, 0xb33d177c, 0x05df1bfe, 0xdeae1dbf,
  0xb36a04bb, 0x681b02fa, 0xdef90e78, 0x05880839,
  0xb08ed59f, 0x6bffd3de, 0xdd1ddf5c, 0x066cd91d,
  0x6ba8c019, 0xb0d9c658, 0x063bcada, 0xdd4acc9b,
  0xddb3f8d2, 0x06c2fe93, 0xb020f211, 0x6b51f450,
  0x0695ed54, 0xdde4eb15, 0x6b06e797, 0xb077e1d6,
  0x6af48f05, 0xb1858944, 0x076785c6, 0xdc168387,
  0xb1d29a83, 0x6aa39cc2, 0xdc419040, 0x07309601,
  0x07c9a248, 0xdcb8a409, 0x6a5aa88b, 0xb12baeca,
  0xdcefb7ce, 0x079eb18f, 0xb17cbd0d, 0x6a0dbb4c,
  0x6567cb95, 0xbe16cdd4, 0x08f4c156, 0xd385c717,
  0xbe41de13, 0x6530d852, 0xd3d2d4d0, 0x08a3d291,
  0x085ae6d8, 0xd32be099, 0x65c9ec1b, 0xbeb8ea5a,
  0xd37cf35e, 0x080df51f, 0xbeeff99d, 0x659effdc,
  0xbf1d910f, 0x646c974e, 0xd28e9bcc, 0x09ff9d8d,
  0x643b8489, 0xbf4a82c8, 0x09a88e4a, 0xd2d9880b,
  0xd220bc42, 0x0951ba03, 0xbfb3b681, 0x64c2b0c0,
  0x0906a9c4, 0xd277af85, 0x6495a307, 0xbfe4a546,
  0x0ae278e0, 0xd1937ea1, 0x67717223, 0xbc007462,
  0xd1c46d66, 0x0ab56b27, 0xbc5767a5, 0x672661e4,
  0x67df55ad, 0xbcae53ec, 0x0a4c5f6e, 0xd13d592f,
  0xbcf9402b, 0x6788466a, 0xd16a4ae8, 0x0a1b4ca9,
  0xd098227a, 0x0be9243b, 0xbd0b28b9, 0x667a2ef8,
  0x0bbe37fc, 0xd0cf31bd, 0x662d3d3f, 0xbd5c3b7e,
  0xbda50f37, 0x66d40976, 0xd03605f4, 0x0b4703b5,
  0x66831ab1, 0xbdf21cf0, 0x0b101072, 0xd0611633,
  0xba6cad7f, 0x611dab3e, 0xd7ffa7bc, 0x0c8ea1fd,
  0x614ab8f9, 0xba3bbeb8, 0x0cd9b23a, 0xd7a8b47b,
  0xd7518032, 0x0c208673, 0xbac28af1, 0x61b38cb0,
  0x0c7795b4, 0xd70693f5, 0x61e49f77, 0xba959936,
  0x6016f7e5, 0xbb67f1a4, 0x0d85fd26, 0xd6f4fb67,
  0xbb30e263, 0x6041e422, 0xd6a3e8a0, 0x0dd2eee1,
  0x0d2bdaa8, 0xd65adce9, 0x60b8d06b, 0xbbc9d62a,
  0xd60dcf2e, 0x0d7cc96f, 0xbb9ec5ed, 0x60efc3ac,
  0xd5e91e0a, 0x0e98184b, 0xb87a14c9, 0x630b1288,
  0x0ecf0b8c, 0xd5be0dcd, 0x635c014f, 0xb82d070e,
  0xb8d43347, 0x63a53506, 0xd5473984, 0x0e363fc5,
  0x63f226c1, 0xb8832080, 0x0e612c02, 0xd5102a43,
  0x0f934490, 0xd4e242d1, 0x62004e53, 0xb9714812,
  0xd4b55116, 0x0fc45757, 0xb9265bd5, 0x62575d94,
  0x62ae69dd, 0xb9df6f9c, 0x0f3d631e, 0xd44c655f,
  0xb9887c5b, 0x62f97a1a, 0xd41b7698, 0x0f6a70d9,
};

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

KERNEL_FQ void m20500_sxx (KERN_ATTR_VECTOR ())
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

  LOCAL_VK u32 l_icrc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_icrc32tab[i] = icrc32tab[i];
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    KEY0INIT, // static initial values
    KEY1INIT, // should remain unchanged
    KEY2INIT,
    0
  };

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  /**
   * reverse
   */

  u32 prep0 = digests_buf[digests_offset].digest_buf[0];
  u32 prep1 = digests_buf[digests_offset].digest_buf[1];
  u32 prep2 = digests_buf[digests_offset].digest_buf[2];

  for (u32 pos = pw_len - 1; pos >= 4; pos--)
  {
    const u32 t = hc_bfe_S (pws[gid].i[pos / 4], (pos & 3) * 8, 8);

    inv_update_key012 (prep0, prep1, prep2, t, l_icrc32tab);
  }

  if (pw_len >= 4)
  {
    inv_update_key012 (prep0, prep1, prep2, 0, l_icrc32tab);

    prep2 = INVCRC32 (prep2, MSB (prep1), l_icrc32tab);
    prep1 = (prep1 - 1) * INVCONST;
  }

  /**
   * loop
   */

  u32 w0l = pws[gid].i[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x key0 = prep0;
    u32x key1 = prep1;
    u32x key2 = prep2;

    const u32x w0a = unpack_v8a_from_v32_S (w0);
    const u32x w0b = unpack_v8b_from_v32_S (w0);
    const u32x w0c = unpack_v8c_from_v32_S (w0);
    const u32x w0d = unpack_v8d_from_v32_S (w0);

    if (pw_len >= 4) key0 = key0 ^ w0d;

    if (pw_len >= 3)
    {
      key1 = key1 - (key0 & 0xff);
      key0 = INVCRC32 (key0, w0c, l_icrc32tab);
    }

    if (pw_len >= 2)
    {
      inv_update_key012 (key0, key1, key2, w0b, l_icrc32tab);
    }

    if (pw_len >= 1)
    {
      inv_update_key012 (key0, key1, key2, w0a, l_icrc32tab);
    }

    const u32x r0 = key0;
    const u32x r1 = key1;
    const u32x r2 = key2;
    const u32x r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m20500_mxx (KERN_ATTR_VECTOR ())
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

  u32 w0l =  w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x key0 = KEY0INIT;
    u32x key1 = KEY1INIT;
    u32x key2 = KEY2INIT;

    if (pw_len >=  1) update_key012 (key0, key1, key2, unpack_v8a_from_v32_S (w0), l_crc32tab);
    if (pw_len >=  2) update_key012 (key0, key1, key2, unpack_v8b_from_v32_S (w0), l_crc32tab);
    if (pw_len >=  3) update_key012 (key0, key1, key2, unpack_v8c_from_v32_S (w0), l_crc32tab);
    if (pw_len >=  4) update_key012 (key0, key1, key2, unpack_v8d_from_v32_S (w0), l_crc32tab);

    for (u32 i = 4, j = 1; i < pw_len; i += 4, j += 1)
    {
      if (pw_len >= (i + 1)) update_key012 (key0, key1, key2, unpack_v8a_from_v32_S (w[j]), l_crc32tab);
      if (pw_len >= (i + 2)) update_key012 (key0, key1, key2, unpack_v8b_from_v32_S (w[j]), l_crc32tab);
      if (pw_len >= (i + 3)) update_key012 (key0, key1, key2, unpack_v8c_from_v32_S (w[j]), l_crc32tab);
      if (pw_len >= (i + 4)) update_key012 (key0, key1, key2, unpack_v8d_from_v32_S (w[j]), l_crc32tab);
    }

    const u32x r0 = key0;
    const u32x r1 = key1;
    const u32x r2 = key2;
    const u32x r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

#undef inv_update_key012
#undef INVCONST
#undef INVCRC32
#undef MSB
#undef KEY0INIT
#undef KEY1INIT
#undef KEY2INIT
