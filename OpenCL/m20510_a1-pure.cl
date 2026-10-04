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

#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)

typedef struct pkzip_extra
{
  u32 buf[2];
  u32 len;

} pkzip_extra_t;

#define MSB(x)          ((x) >> 24)
#define CRC32(x,c,t)    (((x) >> 8) ^ (t)[((x) ^ (c)) & 0xff])
#define INVCRC32(x,c,t) (((x) << 8) ^ (t)[(x) >> 24] ^ ((c) & 0xff))
#define INVCONST        0xd94fa8cd
#define KEY0INIT        0x12345678
#define KEY1INIT        0x23456789
#define KEY2INIT        0x34567890

#define inv_update_key012(k0,k1,k2,c,t)         \
  (k2) = INVCRC32 ((k2), MSB (k1), (t));        \
  (k1) = ((k1) - 1) * INVCONST - ((k0) & 0xff); \
  (k0) = INVCRC32 ((k0), (c), (t));

// One buffer of the candidate back through the key schedule. -a 12 assembles a candidate from five
// pieces, so this runs once per piece rather than once for the amplifier and once for the base word.

#define inv_update_key012_buf(k0,k1,k2,buf,len,t)                 \
{                                                                 \
  for (int bpos = (int) (len) - 1; bpos >= 0; bpos--)             \
  {                                                               \
    const u32 bt = hc_bfe_S ((buf)[bpos / 4], (bpos & 3) * 8, 8); \
                                                                  \
    inv_update_key012 (k0, k1, k2, bt, t);                        \
  }                                                               \
}

CONSTANT_VK u32a lsbk0[256] =
{
  0x00, 0x56, 0xac, 0x21, 0x77, 0xcd, 0x42, 0x98,
  0xee, 0x0d, 0x63, 0xb9, 0x2e, 0x84, 0xda, 0x4f,
  0xa5, 0xfb, 0x1a, 0x70, 0xc6, 0x3b, 0x91, 0xe7,
  0x06, 0x5c, 0xb2, 0x27, 0x7d, 0xd3, 0x48, 0x9e,
  0xf4, 0x13, 0x69, 0xbf, 0x34, 0x8a, 0xe0, 0x55,
  0xab, 0x20, 0x76, 0xcc, 0x41, 0x97, 0xed, 0x0c,
  0x62, 0xb8, 0x2d, 0x83, 0xd9, 0x4e, 0xa4, 0xfa,
  0x19, 0x6f, 0xc5, 0x3a, 0x90, 0xe6, 0x05, 0x5b,
  0xb1, 0x26, 0x7c, 0xd2, 0x47, 0x9d, 0xf3, 0x12,
  0x68, 0xbe, 0x33, 0x89, 0xdf, 0x54, 0xaa, 0x1f,
  0x75, 0xcb, 0x40, 0x96, 0xec, 0x0b, 0x61, 0xb7,
  0x2c, 0x82, 0xd8, 0x4d, 0xa3, 0xf9, 0x18, 0x6e,
  0xc4, 0x39, 0x8f, 0xe5, 0x04, 0x5a, 0xb0, 0x25,
  0x7b, 0xd1, 0x46, 0x9c, 0xf2, 0x11, 0x67, 0xbd,
  0x32, 0x88, 0xde, 0x53, 0xa9, 0xff, 0x1e, 0x74,
  0xca, 0x3f, 0x95, 0xeb, 0x0a, 0x60, 0xb6, 0x2b,
  0x81, 0xd7, 0x4c, 0xa2, 0xf8, 0x17, 0x6d, 0xc3,
  0x38, 0x8e, 0xe4, 0x03, 0x59, 0xaf, 0x24, 0x7a,
  0xd0, 0x45, 0x9b, 0xf1, 0x10, 0x66, 0xbc, 0x31,
  0x87, 0xdd, 0x52, 0xa8, 0xfe, 0x1d, 0x73, 0xc9,
  0x3e, 0x94, 0xea, 0x09, 0x5f, 0xb5, 0x2a, 0x80,
  0xd6, 0x4b, 0xa1, 0xf7, 0x16, 0x6c, 0xc2, 0x37,
  0x8d, 0xe3, 0x02, 0x58, 0xae, 0x23, 0x79, 0xcf,
  0x44, 0x9a, 0xf0, 0x0f, 0x65, 0xbb, 0x30, 0x86,
  0xdc, 0x51, 0xa7, 0xfd, 0x1c, 0x72, 0xc8, 0x3d,
  0x93, 0xe9, 0x08, 0x5e, 0xb4, 0x29, 0x7f, 0xd5,
  0x4a, 0xa0, 0xf6, 0x15, 0x6b, 0xc1, 0x36, 0x8c,
  0xe2, 0x01, 0x57, 0xad, 0x22, 0x78, 0xce, 0x43,
  0x99, 0xef, 0x0e, 0x64, 0xba, 0x2f, 0x85, 0xdb,
  0x50, 0xa6, 0xfc, 0x1b, 0x71, 0xc7, 0x3c, 0x92,
  0xe8, 0x07, 0x5d, 0xb3, 0x28, 0x7e, 0xd4, 0x49,
  0x9f, 0xf5, 0x14, 0x6a, 0xc0, 0x35, 0x8b, 0xe1
};

CONSTANT_VK int lsbk0_count0[256] =
{
    0,   2,   3,   3,   4,   6,   6,   7,
    8,   9,  11,  12,  12,  13,  15,  15,
   16,  17,  18,  20,  21,  21,  22,  24,
   25,  26,  27,  27,  29,  30,  30,  31,
   33,  34,  35,  36,  36,  38,  39,  39,
   40,  41,  42,  43,  44,  44,  46,  47,
   48,  49,  50,  50,  52,  53,  53,  54,
   56,  57,  58,  59,  59,  61,  62,  63,
   64,  65,  66,  67,  68,  68,  70,  71,
   72,  73,  74,  75,  76,  77,  77,  79,
   79,  80,  81,  82,  83,  84,  85,  86,
   88,  88,  89,  90,  91,  92,  93,  94,
   95,  97,  97,  98,  99, 100, 101, 103,
  103, 104, 105, 106, 107, 108, 109, 110,
  112, 112, 113, 114, 115, 116, 117, 118,
  119, 121, 121, 122, 123, 124, 126, 127,
  127, 128, 130, 130, 131, 132, 133, 135,
  136, 136, 137, 139, 140, 141, 142, 142,
  144, 145, 145, 146, 148, 149, 150, 151,
  151, 152, 154, 154, 155, 156, 157, 159,
  160, 160, 161, 163, 164, 165, 166, 166,
  168, 169, 169, 170, 172, 173, 174, 175,
  175, 177, 178, 179, 180, 181, 182, 183,
  184, 184, 186, 187, 188, 189, 190, 191,
  192, 193, 193, 195, 196, 197, 198, 199,
  200, 201, 202, 203, 204, 205, 206, 207,
  208, 208, 210, 211, 212, 213, 214, 215,
  216, 217, 218, 220, 220, 221, 222, 223,
  224, 225, 226, 227, 229, 229, 230, 231,
  232, 233, 234, 235, 236, 238, 238, 239,
  240, 241, 243, 244, 244, 245, 247, 247,
  248, 249, 250, 252, 253, 253, 254, 255
};

CONSTANT_VK int lsbk0_count1[256] =
{
    2,   3,   3,   4,   6,   6,   7,   8,
    9,  11,  12,  12,  13,  15,  15,  16,
   17,  18,  20,  21,  21,  22,  24,  25,
   26,  27,  27,  29,  30,  30,  31,  33,
   34,  35,  36,  36,  38,  39,  39,  40,
   41,  42,  43,  44,  44,  46,  47,  48,
   49,  50,  50,  52,  53,  53,  54,  56,
   57,  58,  59,  59,  61,  62,  63,  64,
   65,  66,  67,  68,  68,  70,  71,  72,
   73,  74,  75,  76,  77,  77,  79,  79,
   80,  81,  82,  83,  84,  85,  86,  88,
   88,  89,  90,  91,  92,  93,  94,  95,
   97,  97,  98,  99, 100, 101, 103, 103,
  104, 105, 106, 107, 108, 109, 110, 112,
  112, 113, 114, 115, 116, 117, 118, 119,
  121, 121, 122, 123, 124, 126, 127, 127,
  128, 130, 130, 131, 132, 133, 135, 136,
  136, 137, 139, 140, 141, 142, 142, 144,
  145, 145, 146, 148, 149, 150, 151, 151,
  152, 154, 154, 155, 156, 157, 159, 160,
  160, 161, 163, 164, 165, 166, 166, 168,
  169, 169, 170, 172, 173, 174, 175, 175,
  177, 178, 179, 180, 181, 182, 183, 184,
  184, 186, 187, 188, 189, 190, 191, 192,
  193, 193, 195, 196, 197, 198, 199, 200,
  201, 202, 203, 204, 205, 206, 207, 208,
  208, 210, 211, 212, 213, 214, 215, 216,
  217, 218, 220, 220, 221, 222, 223, 224,
  225, 226, 227, 229, 229, 230, 231, 232,
  233, 234, 235, 236, 238, 238, 239, 240,
  241, 243, 244, 244, 245, 247, 247, 248,
  249, 250, 252, 253, 253, 254, 255, 256
};

DECLSPEC int derivelast6bytes (const u32x k0, const u32x k1, const u32x k2, PRIVATE_AS u32 *password, LOCAL_AS u32 *l_crc32tab, LOCAL_AS u32 *l_icrc32tab, LOCAL_AS u32 *l_lsbk0, LOCAL_AS int *l_lsbk0_count0, LOCAL_AS int *l_lsbk0_count1)
{
  // step 1
  const u32 k2_1 = INVCRC32 (k2,   (k1   >> 24), l_icrc32tab);
  const u32 k1_1 = (k1 - 1) * INVCONST - (k0 & 0xff);
  const u32 k2_2 = INVCRC32 (k2_1, (k1_1 >> 24), l_icrc32tab);

  // step 2
  u32 k2_3 = INVCRC32 (k2_2, 0, l_icrc32tab);
  u32 k2_4 = INVCRC32 (k2_3, 0, l_icrc32tab);
  u32 k2_5 = INVCRC32 (k2_4, 0, l_icrc32tab);

  // step 3
  const u32 k1_5 = ((u32)((0x90)        ^ l_icrc32tab[(k2_5 >> 24)])) << 24;
            k2_5 = CRC32 (KEY2INIT, (k1_5 >> 24), l_crc32tab);
  const u32 k1_4 = ((u32)((k2_5 & 0xFF) ^ l_icrc32tab[(k2_4 >> 24)])) << 24;
            k2_4 = CRC32 (k2_5    , (k1_4 >> 24), l_crc32tab);
  const u32 k1_3 = ((u32)((k2_4 & 0xFF) ^ l_icrc32tab[(k2_3 >> 24)])) << 24;
            k2_3 = CRC32 (k2_4    , (k1_3 >> 24), l_crc32tab);
  const u32 k1_2 = ((u32)((k2_3 & 0xFF) ^ l_icrc32tab[(k2_2 >> 24)])) << 24;

  // step 5.2

  #define IDX(x) ((x) & 0xff)

  const u32 rhs_step1_0 = (k1_1 - 1) * INVCONST;

  u32 diff0 = ((rhs_step1_0 - 1) * INVCONST - (k1_3 & 0xff000000)) >> 24;

  for (int c0 = 0; c0 < 2; c0++, diff0--)
  {
    for (int i0 = l_lsbk0_count0[IDX (diff0)]; i0 < l_lsbk0_count1[IDX (diff0)]; i0++)
    {
      if (((rhs_step1_0 - l_lsbk0[i0]) >> 24) != (k1_2 >> 24)) continue;

      const u32 rhs_step1_1 = (rhs_step1_0 - l_lsbk0[i0] - 1) * INVCONST;

      u32 diff1 = ((rhs_step1_1 - 1) * INVCONST - (k1_4 & 0xff000000)) >> 24;

      for (int c1 = 0; c1 < 2; c1++, diff1--)
      {
        for (int i1 = l_lsbk0_count0[IDX (diff1)]; i1 < l_lsbk0_count1[IDX (diff1)]; i1++)
        {
          if (((rhs_step1_1 - l_lsbk0[i1]) >> 24) != (k1_3 >> 24)) continue;

          const u32 rhs_step1_2 = (rhs_step1_1 - l_lsbk0[i1] - 1) * INVCONST;

          u32 diff2 = ((rhs_step1_2 - 1) * INVCONST - (k1_5 & 0xff000000)) >> 24;

          for (int c2 = 0; c2 < 2; c2++, diff2--)
          {
            for (int i2 = l_lsbk0_count0[IDX (diff2)]; i2 < l_lsbk0_count1[IDX (diff2)]; i2++)
            {
              if (((rhs_step1_2 - l_lsbk0[i2]) >> 24) != (k1_4 >> 24)) continue;

              const u32 rhs_step1_3 = (rhs_step1_2 - l_lsbk0[i2] - 1) * INVCONST;

              u32 diff3 = ((rhs_step1_3 - 1) * INVCONST - (0x23000000)) >> 24;

              for (int c3 = 0; c3 < 2; c3++, diff3--)
              {
                for (int i3 = l_lsbk0_count0[IDX (diff3)]; i3 < l_lsbk0_count1[IDX (diff3)]; i3++)
                {
                  if (((rhs_step1_3 - l_lsbk0[i3]) >> 24) != (k1_5 >> 24)) continue;

                  const u32 rhs_step1_4 = (rhs_step1_3 - l_lsbk0[i3] - 1) * INVCONST;

                  u32 diff4 = ((rhs_step1_4 - 1) * INVCONST - (0x05000000)) >> 24;

                  for (int c4 = 0; c4 < 2; c4++, diff4--)
                  {
                    for (int i4 = l_lsbk0_count0[IDX (diff4)]; i4 < l_lsbk0_count1[IDX (diff4)]; i4++)
                    {
                      if ((rhs_step1_4 - l_lsbk0[i4]) != KEY1INIT) continue;

                      u32 kk;

                      u32 t5 = ((l_lsbk0[i0]) ^ l_icrc32tab[k0 >> 24]) & 0xff;

                      kk = INVCRC32 (k0, t5, l_icrc32tab);

                      u32 t4 = ((l_lsbk0[i1]) ^ l_icrc32tab[kk >> 24]) & 0xff;

                      kk = INVCRC32 (kk, t4, l_icrc32tab);

                      u32 t3 = ((l_lsbk0[i2]) ^ l_icrc32tab[kk >> 24]) & 0xff;

                      kk = INVCRC32 (kk, t3, l_icrc32tab);

                      u32 t2 = ((l_lsbk0[i3]) ^ l_icrc32tab[kk >> 24]) & 0xff;

                      kk = INVCRC32 (kk, t2, l_icrc32tab);

                      u32 t1 = ((l_lsbk0[i4]) ^ l_icrc32tab[kk >> 24]) & 0xff;

                      kk = INVCRC32 (kk, t1, l_icrc32tab);

                      u32 t0 = ((KEY0INIT)    ^ l_icrc32tab[kk >> 24]) & 0xff;

                      if (INVCRC32 (kk, t0, l_icrc32tab) == KEY0INIT)
                      {
                        // found

                        password[0] = t0 <<  0
                                    | t1 <<  8
                                    | t2 << 16
                                    | t3 << 24;

                        password[1] = t4 <<  0
                                    | t5 <<  8;

                        return 1;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  #undef IDX0
  #undef IDX1

  // not found

  return 0;
}

KERNEL_FQ KERNEL_FA void m20510_sxx (KERN_ATTR_BASIC ())
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

  for (int i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  LOCAL_VK u32 l_icrc32tab[256];

  for (int i = lid; i < 256; i += lsz)
  {
    l_icrc32tab[i] = icrc32tab[i];
  }

  LOCAL_VK u32 l_lsbk0[256];

  for (int i = lid; i < 256; i += lsz)
  {
    l_lsbk0[i] = lsbk0[i];
  }

  LOCAL_VK int l_lsbk0_count0[256];
  LOCAL_VK int l_lsbk0_count1[256];

  for (int i = lid; i < 256; i += lsz)
  {
    l_lsbk0_count0[i] = lsbk0_count0[i];
    l_lsbk0_count1[i] = lsbk0_count1[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

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
   * reverse
   */

  u32 prep0 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0]);
  u32 prep1 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1]);
  u32 prep2 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2]);

  /**
   * loop
   */

  u32 pws_pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pws_pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x key0 = prep0;
    u32x key1 = prep1;
    u32x key2 = prep2;

    if (COMBS_IS_MIDDLE)
    {
      // five pieces in a fixed order: mask, base word, mask, second word, mask. This walks the
      // candidate backwards, so the pieces go in the other way round.

      inv_update_key012_buf (key0, key1, key2, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, l_icrc32tab);
      inv_update_key012_buf (key0, key1, key2, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, l_icrc32tab);
      inv_update_key012_buf (key0, key1, key2, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, l_icrc32tab);
      inv_update_key012_buf (key0, key1, key2, w,                     pws_pw_len,                 l_icrc32tab);
      inv_update_key012_buf (key0, key1, key2, COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, l_icrc32tab);
    }
    else
    {
      inv_update_key012_buf (key0, key1, key2, combs_buf[il_pos].i, combs_buf[il_pos].pw_len, l_icrc32tab);
      inv_update_key012_buf (key0, key1, key2, w,                   pws_pw_len,               l_icrc32tab);
    }

    u32 password[2];

    if (derivelast6bytes (key0, key1, key2, password, l_crc32tab, l_icrc32tab, l_lsbk0, l_lsbk0_count0, l_lsbk0_count1) == 1)
    {
      GLOBAL_AS pkzip_extra_t *pkzip_extra = (GLOBAL_AS pkzip_extra_t *) tmps;

      pkzip_extra[gid].buf[0] = password[0];
      pkzip_extra[gid].buf[1] = password[1];

      pkzip_extra[gid].len = 6;

      const u32x r0 = KEY0INIT;
      const u32x r1 = KEY1INIT;
      const u32x r2 = KEY2INIT;
      const u32x r3 = 0;

      COMPARE_S_SIMD (r0, r1, r2, r3);
    }
  }
}

KERNEL_FQ KERNEL_FA void m20510_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * NOT AVAILABLE
   */
}

#undef MSB
#undef CRC32
#undef INVCRC32
#undef INVCONST
#undef KEY0INIT
#undef KEY1INIT
#undef KEY2INIT
#undef inv_update_key012
