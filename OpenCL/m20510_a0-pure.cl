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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)

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

KERNEL_FQ void m20510_sxx (KERN_ATTR_RULES ())
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
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * reverse
   */

  u32 prep0 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0]);
  u32 prep1 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1]);
  u32 prep2 = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    pw_t t = PASTE_PW;

    t.pw_len = apply_rules (rules_buf[il_pos].cmds, t.i, t.pw_len);

    u32x key0 = prep0;
    u32x key1 = prep1;
    u32x key2 = prep2;

    for (int pos = t.pw_len - 1; pos >= 0; pos--)
    {
      const u32 tt = hc_bfe_S (t.i[pos / 4], (pos & 3) * 8, 8);

      inv_update_key012 (key0, key1, key2, tt, l_icrc32tab);
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

KERNEL_FQ void m20510_mxx (KERN_ATTR_RULES ())
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
