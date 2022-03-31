/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define ROUNDS 0x40000

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

typedef struct rar3
{
  u32 data[81920];

  u32 pack_size;
  u32 unpack_size;

} rar3_t;

typedef struct rar3_tmp
{
  u32 dgst[5];

  u32 w[66]; // 256 byte pass + 8 byte salt

  u32 iv[4];

} rar3_tmp_t;

CONSTANT_VK u32a crc32tab[0x100] =
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

DECLSPEC u32 round_crc32 (const u32 a, const u32 v, LOCAL_AS u32 *l_crc32tab)
{
  const u32 k = (a ^ v) & 0xff;

  const u32 s = a >> 8;

  return l_crc32tab[k] ^ s;
}

DECLSPEC u32 round_crc32_16 (const u32 crc32, PRIVATE_AS const u32 *buf, const u32 len, LOCAL_AS u32 *l_crc32tab)
{
  const int crc_len = MIN (len, 16);

  u32 c = crc32;

  for (int i = 0; i < crc_len; i++)
  {
    const u32 idx = i / 4;
    const u32 mod = i % 4;
    const u32 sht = (3 - mod) * 8;

    const u32 b = buf[idx] >> sht; // b & 0xff (but already done in round_crc32 ())

    c = round_crc32 (c, b, l_crc32tab);
  }

  return c;
}

DECLSPEC void memcat8c_be (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 len, const u32 append, PRIVATE_AS u32 *digest)
{
  const u32 func_len = len & 63;

  //const u32 mod = func_len & 3;
  const u32 div = func_len / 4;

  u32 tmp0;
  u32 tmp1;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  tmp0 = hc_bytealign_be (0, append, func_len);
  tmp1 = hc_bytealign_be (append, 0, func_len);
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((func_len & 3) * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> ((func_len & 3) * 8));
  #endif

  tmp0 = hc_byte_perm (append, 0, selector);
  tmp1 = hc_byte_perm (0, append, selector);
  #endif

  u32 carry = 0;

  switch (div)
  {
    case  0:  w0[0] |= tmp0; w0[1]  = tmp1; break;
    case  1:  w0[1] |= tmp0; w0[2]  = tmp1; break;
    case  2:  w0[2] |= tmp0; w0[3]  = tmp1; break;
    case  3:  w0[3] |= tmp0; w1[0]  = tmp1; break;
    case  4:  w1[0] |= tmp0; w1[1]  = tmp1; break;
    case  5:  w1[1] |= tmp0; w1[2]  = tmp1; break;
    case  6:  w1[2] |= tmp0; w1[3]  = tmp1; break;
    case  7:  w1[3] |= tmp0; w2[0]  = tmp1; break;
    case  8:  w2[0] |= tmp0; w2[1]  = tmp1; break;
    case  9:  w2[1] |= tmp0; w2[2]  = tmp1; break;
    case 10:  w2[2] |= tmp0; w2[3]  = tmp1; break;
    case 11:  w2[3] |= tmp0; w3[0]  = tmp1; break;
    case 12:  w3[0] |= tmp0; w3[1]  = tmp1; break;
    case 13:  w3[1] |= tmp0; w3[2]  = tmp1; break;
    case 14:  w3[2] |= tmp0; w3[3]  = tmp1; break;
    default:  w3[3] |= tmp0; carry  = tmp1; break; // this is a bit weird but helps to workaround AMD JiT compiler segfault if set to case 15:
  }

  const u32 new_len = func_len + 3;

  if (new_len >= 64)
  {
    sha1_transform (w0, w1, w2, w3, digest);

    w0[0] = carry;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
}

// only change in this function compared to OpenCL/inc_hash_sha1.cl is that it returns
// the expanded 64 byte buffer w0_t..wf_t in t[]:

DECLSPEC void sha1_transform_rar29 (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest, PRIVATE_AS u32 *t)
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];

  #ifdef IS_CPU

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wf_t);

  t[ 0] = w0_t;
  t[ 1] = w1_t;
  t[ 2] = w2_t;
  t[ 3] = w3_t;
  t[ 4] = w4_t;
  t[ 5] = w5_t;
  t[ 6] = w6_t;
  t[ 7] = w7_t;
  t[ 8] = w8_t;
  t[ 9] = w9_t;
  t[10] = wa_t;
  t[11] = wb_t;
  t[12] = wc_t;
  t[13] = wd_t;
  t[14] = we_t;
  t[15] = wf_t;

  #undef K

  #else

  u32 w00_t = w0[0];
  u32 w01_t = w0[1];
  u32 w02_t = w0[2];
  u32 w03_t = w0[3];
  u32 w04_t = w1[0];
  u32 w05_t = w1[1];
  u32 w06_t = w1[2];
  u32 w07_t = w1[3];
  u32 w08_t = w2[0];
  u32 w09_t = w2[1];
  u32 w0a_t = w2[2];
  u32 w0b_t = w2[3];
  u32 w0c_t = w3[0];
  u32 w0d_t = w3[1];
  u32 w0e_t = w3[2];
  u32 w0f_t = w3[3];
  u32 w10_t;
  u32 w11_t;
  u32 w12_t;
  u32 w13_t;
  u32 w14_t;
  u32 w15_t;
  u32 w16_t;
  u32 w17_t;
  u32 w18_t;
  u32 w19_t;
  u32 w1a_t;
  u32 w1b_t;
  u32 w1c_t;
  u32 w1d_t;
  u32 w1e_t;
  u32 w1f_t;
  u32 w20_t;
  u32 w21_t;
  u32 w22_t;
  u32 w23_t;
  u32 w24_t;
  u32 w25_t;
  u32 w26_t;
  u32 w27_t;
  u32 w28_t;
  u32 w29_t;
  u32 w2a_t;
  u32 w2b_t;
  u32 w2c_t;
  u32 w2d_t;
  u32 w2e_t;
  u32 w2f_t;
  u32 w30_t;
  u32 w31_t;
  u32 w32_t;
  u32 w33_t;
  u32 w34_t;
  u32 w35_t;
  u32 w36_t;
  u32 w37_t;
  u32 w38_t;
  u32 w39_t;
  u32 w3a_t;
  u32 w3b_t;
  u32 w3c_t;
  u32 w3d_t;
  u32 w3e_t;
  u32 w3f_t;
  u32 w40_t;
  u32 w41_t;
  u32 w42_t;
  u32 w43_t;
  u32 w44_t;
  u32 w45_t;
  u32 w46_t;
  u32 w47_t;
  u32 w48_t;
  u32 w49_t;
  u32 w4a_t;
  u32 w4b_t;
  u32 w4c_t;
  u32 w4d_t;
  u32 w4e_t;
  u32 w4f_t;

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w00_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w01_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w02_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w03_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w04_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w05_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w06_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w07_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w08_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w09_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0a_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0b_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w0c_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w0d_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w0e_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0f_t);
  w10_t = hc_rotl32_S ((w0d_t ^ w08_t ^ w02_t ^ w00_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w10_t);
  w11_t = hc_rotl32_S ((w0e_t ^ w09_t ^ w03_t ^ w01_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w11_t);
  w12_t = hc_rotl32_S ((w0f_t ^ w0a_t ^ w04_t ^ w02_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w12_t);
  w13_t = hc_rotl32_S ((w10_t ^ w0b_t ^ w05_t ^ w03_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w13_t);

  #undef K
  #define K SHA1C01

  w14_t = hc_rotl32_S ((w11_t ^ w0c_t ^ w06_t ^ w04_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w14_t);
  w15_t = hc_rotl32_S ((w12_t ^ w0d_t ^ w07_t ^ w05_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w15_t);
  w16_t = hc_rotl32_S ((w13_t ^ w0e_t ^ w08_t ^ w06_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w16_t);
  w17_t = hc_rotl32_S ((w14_t ^ w0f_t ^ w09_t ^ w07_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w17_t);
  w18_t = hc_rotl32_S ((w15_t ^ w10_t ^ w0a_t ^ w08_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w18_t);
  w19_t = hc_rotl32_S ((w16_t ^ w11_t ^ w0b_t ^ w09_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w19_t);
  w1a_t = hc_rotl32_S ((w17_t ^ w12_t ^ w0c_t ^ w0a_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1a_t);
  w1b_t = hc_rotl32_S ((w18_t ^ w13_t ^ w0d_t ^ w0b_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w1b_t);
  w1c_t = hc_rotl32_S ((w19_t ^ w14_t ^ w0e_t ^ w0c_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1c_t);
  w1d_t = hc_rotl32_S ((w1a_t ^ w15_t ^ w0f_t ^ w0d_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w1d_t);
  w1e_t = hc_rotl32_S ((w1b_t ^ w16_t ^ w10_t ^ w0e_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1e_t);
  w1f_t = hc_rotl32_S ((w1c_t ^ w17_t ^ w11_t ^ w0f_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1f_t);
  w20_t = hc_rotl32_S ((w1a_t ^ w10_t ^ w04_t ^ w00_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w20_t);
  w21_t = hc_rotl32_S ((w1b_t ^ w11_t ^ w05_t ^ w01_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w21_t);
  w22_t = hc_rotl32_S ((w1c_t ^ w12_t ^ w06_t ^ w02_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w22_t);
  w23_t = hc_rotl32_S ((w1d_t ^ w13_t ^ w07_t ^ w03_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w23_t);
  w24_t = hc_rotl32_S ((w1e_t ^ w14_t ^ w08_t ^ w04_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w24_t);
  w25_t = hc_rotl32_S ((w1f_t ^ w15_t ^ w09_t ^ w05_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w25_t);
  w26_t = hc_rotl32_S ((w20_t ^ w16_t ^ w0a_t ^ w06_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w26_t);
  w27_t = hc_rotl32_S ((w21_t ^ w17_t ^ w0b_t ^ w07_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w27_t);

  #undef K
  #define K SHA1C02

  w28_t = hc_rotl32_S ((w22_t ^ w18_t ^ w0c_t ^ w08_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w28_t);
  w29_t = hc_rotl32_S ((w23_t ^ w19_t ^ w0d_t ^ w09_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w29_t);
  w2a_t = hc_rotl32_S ((w24_t ^ w1a_t ^ w0e_t ^ w0a_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2a_t);
  w2b_t = hc_rotl32_S ((w25_t ^ w1b_t ^ w0f_t ^ w0b_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w2b_t);
  w2c_t = hc_rotl32_S ((w26_t ^ w1c_t ^ w10_t ^ w0c_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w2c_t);
  w2d_t = hc_rotl32_S ((w27_t ^ w1d_t ^ w11_t ^ w0d_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2d_t);
  w2e_t = hc_rotl32_S ((w28_t ^ w1e_t ^ w12_t ^ w0e_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w2e_t);
  w2f_t = hc_rotl32_S ((w29_t ^ w1f_t ^ w13_t ^ w0f_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2f_t);
  w30_t = hc_rotl32_S ((w2a_t ^ w20_t ^ w14_t ^ w10_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w30_t);
  w31_t = hc_rotl32_S ((w2b_t ^ w21_t ^ w15_t ^ w11_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w31_t);
  w32_t = hc_rotl32_S ((w2c_t ^ w22_t ^ w16_t ^ w12_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w32_t);
  w33_t = hc_rotl32_S ((w2d_t ^ w23_t ^ w17_t ^ w13_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w33_t);
  w34_t = hc_rotl32_S ((w2e_t ^ w24_t ^ w18_t ^ w14_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w34_t);
  w35_t = hc_rotl32_S ((w2f_t ^ w25_t ^ w19_t ^ w15_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w35_t);
  w36_t = hc_rotl32_S ((w30_t ^ w26_t ^ w1a_t ^ w16_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w36_t);
  w37_t = hc_rotl32_S ((w31_t ^ w27_t ^ w1b_t ^ w17_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w37_t);
  w38_t = hc_rotl32_S ((w32_t ^ w28_t ^ w1c_t ^ w18_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w38_t);
  w39_t = hc_rotl32_S ((w33_t ^ w29_t ^ w1d_t ^ w19_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w39_t);
  w3a_t = hc_rotl32_S ((w34_t ^ w2a_t ^ w1e_t ^ w1a_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w3a_t);
  w3b_t = hc_rotl32_S ((w35_t ^ w2b_t ^ w1f_t ^ w1b_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w3b_t);

  #undef K
  #define K SHA1C03

  w3c_t = hc_rotl32_S ((w36_t ^ w2c_t ^ w20_t ^ w1c_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3c_t);
  w3d_t = hc_rotl32_S ((w37_t ^ w2d_t ^ w21_t ^ w1d_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w3d_t);
  w3e_t = hc_rotl32_S ((w38_t ^ w2e_t ^ w22_t ^ w1e_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3e_t);
  w3f_t = hc_rotl32_S ((w39_t ^ w2f_t ^ w23_t ^ w1f_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w3f_t);
  w40_t = hc_rotl32_S ((w34_t ^ w20_t ^ w08_t ^ w00_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w40_t);
  w41_t = hc_rotl32_S ((w35_t ^ w21_t ^ w09_t ^ w01_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w41_t);
  w42_t = hc_rotl32_S ((w36_t ^ w22_t ^ w0a_t ^ w02_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w42_t);
  w43_t = hc_rotl32_S ((w37_t ^ w23_t ^ w0b_t ^ w03_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w43_t);
  w44_t = hc_rotl32_S ((w38_t ^ w24_t ^ w0c_t ^ w04_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w44_t);
  w45_t = hc_rotl32_S ((w39_t ^ w25_t ^ w0d_t ^ w05_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w45_t);
  w46_t = hc_rotl32_S ((w3a_t ^ w26_t ^ w0e_t ^ w06_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w46_t);
  w47_t = hc_rotl32_S ((w3b_t ^ w27_t ^ w0f_t ^ w07_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w47_t);
  w48_t = hc_rotl32_S ((w3c_t ^ w28_t ^ w10_t ^ w08_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w48_t);
  w49_t = hc_rotl32_S ((w3d_t ^ w29_t ^ w11_t ^ w09_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w49_t);
  w4a_t = hc_rotl32_S ((w3e_t ^ w2a_t ^ w12_t ^ w0a_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4a_t);
  w4b_t = hc_rotl32_S ((w3f_t ^ w2b_t ^ w13_t ^ w0b_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4b_t);
  w4c_t = hc_rotl32_S ((w40_t ^ w2c_t ^ w14_t ^ w0c_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4c_t);
  w4d_t = hc_rotl32_S ((w41_t ^ w2d_t ^ w15_t ^ w0d_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w4d_t);
  w4e_t = hc_rotl32_S ((w42_t ^ w2e_t ^ w16_t ^ w0e_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4e_t);
  w4f_t = hc_rotl32_S ((w43_t ^ w2f_t ^ w17_t ^ w0f_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4f_t);

  t[ 0] = w40_t;
  t[ 1] = w41_t;
  t[ 2] = w42_t;
  t[ 3] = w43_t;
  t[ 4] = w44_t;
  t[ 5] = w45_t;
  t[ 6] = w46_t;
  t[ 7] = w47_t;
  t[ 8] = w48_t;
  t[ 9] = w49_t;
  t[10] = w4a_t;
  t[11] = w4b_t;
  t[12] = w4c_t;
  t[13] = w4d_t;
  t[14] = w4e_t;
  t[15] = w4f_t;

  #undef K
  #endif

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
}

// only change in this function compared to OpenCL/inc_hash_sha1.cl is that
// it calls our modified sha1_transform_rar29 () function

DECLSPEC void sha1_update_64_rar29 (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int bytes, PRIVATE_AS u32 *t)
{
  if (bytes == 0) return;

  const int pos = ctx->len & 63;

  int len = 64;

  if (bytes < 64)
  {
    len = bytes;
  }

  ctx->len += len;

  if (pos == 0)
  {
    ctx->w0[0] = w0[0];
    ctx->w0[1] = w0[1];
    ctx->w0[2] = w0[2];
    ctx->w0[3] = w0[3];
    ctx->w1[0] = w1[0];
    ctx->w1[1] = w1[1];
    ctx->w1[2] = w1[2];
    ctx->w1[3] = w1[3];
    ctx->w2[0] = w2[0];
    ctx->w2[1] = w2[1];
    ctx->w2[2] = w2[2];
    ctx->w2[3] = w2[3];
    ctx->w3[0] = w3[0];
    ctx->w3[1] = w3[1];
    ctx->w3[2] = w3[2];
    ctx->w3[3] = w3[3];

    if (len == 64)
    {
      sha1_transform_rar29 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, t);

      ctx->w0[0] = 0;
      ctx->w0[1] = 0;
      ctx->w0[2] = 0;
      ctx->w0[3] = 0;
      ctx->w1[0] = 0;
      ctx->w1[1] = 0;
      ctx->w1[2] = 0;
      ctx->w1[3] = 0;
      ctx->w2[0] = 0;
      ctx->w2[1] = 0;
      ctx->w2[2] = 0;
      ctx->w2[3] = 0;
      ctx->w3[0] = 0;
      ctx->w3[1] = 0;
      ctx->w3[2] = 0;
      ctx->w3[3] = 0;
    }
  }
  else
  {
    if ((pos + len) < 64)
    {
      switch_buffer_by_offset_be_S (w0, w1, w2, w3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];
    }
    else
    {
      u32 c0[4] = { 0 };
      u32 c1[4] = { 0 };
      u32 c2[4] = { 0 };
      u32 c3[4] = { 0 };

      switch_buffer_by_offset_carry_be_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];

      sha1_transform_rar29 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, t);

      ctx->w0[0] = c0[0];
      ctx->w0[1] = c0[1];
      ctx->w0[2] = c0[2];
      ctx->w0[3] = c0[3];
      ctx->w1[0] = c1[0];
      ctx->w1[1] = c1[1];
      ctx->w1[2] = c1[2];
      ctx->w1[3] = c1[3];
      ctx->w2[0] = c2[0];
      ctx->w2[1] = c2[1];
      ctx->w2[2] = c2[2];
      ctx->w2[3] = c2[3];
      ctx->w3[0] = c3[0];
      ctx->w3[1] = c3[1];
      ctx->w3[2] = c3[2];
      ctx->w3[3] = c3[3];
    }
  }
}

// main change in this function compared to OpenCL/inc_hash_sha1.cl is that
// we call sha1_update_64_rar29 () and sometimes replace w[]

DECLSPEC void sha1_update_rar29 (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len == 0) return;

  const int pos = ctx->len & 63;

  int pos1 = 0;
  int pos4 = 0;

  if (len > 64) // or: if (pos1 < (len - 64))
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);

    pos1 += 64;
    pos4 += 16;
  }

  for (int diff = 64 - pos; pos1 < len; pos1 += 64, pos4 += 16, diff += 64)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    // only major change in this function compared to OpenCL/inc_hash_sha1.cl:

    u32 t[17] = { 0 };

    sha1_update_64_rar29 (ctx, w0, w1, w2, w3, len - pos1, t);


    if ((diff + 63) >= len) break;

    // replaces 64 bytes (with offset diff) of the underlying data w[] with t[]:

    // for (int i = 0; i < 16; i++) t[i] = hc_swap32_S (t[i]);

    t[ 0] = hc_swap32_S (t[ 0]); // unroll seems to be faster
    t[ 1] = hc_swap32_S (t[ 1]);
    t[ 2] = hc_swap32_S (t[ 2]);
    t[ 3] = hc_swap32_S (t[ 3]);
    t[ 4] = hc_swap32_S (t[ 4]);
    t[ 5] = hc_swap32_S (t[ 5]);
    t[ 6] = hc_swap32_S (t[ 6]);
    t[ 7] = hc_swap32_S (t[ 7]);
    t[ 8] = hc_swap32_S (t[ 8]);
    t[ 9] = hc_swap32_S (t[ 9]);
    t[10] = hc_swap32_S (t[10]);
    t[11] = hc_swap32_S (t[11]);
    t[12] = hc_swap32_S (t[12]);
    t[13] = hc_swap32_S (t[13]);
    t[14] = hc_swap32_S (t[14]);
    t[15] = hc_swap32_S (t[15]);

    const u32 n_idx = diff / 4;
    const u32 n_off = diff % 4;

    if (n_off)
    {
      const u32 off_mul = n_off * 8;
      const u32 off_sub = 32 - off_mul;

      t[16] =                      (t[15] << off_sub);
      t[15] = (t[15] >> off_mul) | (t[14] << off_sub);
      t[14] = (t[14] >> off_mul) | (t[13] << off_sub);
      t[13] = (t[13] >> off_mul) | (t[12] << off_sub);
      t[12] = (t[12] >> off_mul) | (t[11] << off_sub);
      t[11] = (t[11] >> off_mul) | (t[10] << off_sub);
      t[10] = (t[10] >> off_mul) | (t[ 9] << off_sub);
      t[ 9] = (t[ 9] >> off_mul) | (t[ 8] << off_sub);
      t[ 8] = (t[ 8] >> off_mul) | (t[ 7] << off_sub);
      t[ 7] = (t[ 7] >> off_mul) | (t[ 6] << off_sub);
      t[ 6] = (t[ 6] >> off_mul) | (t[ 5] << off_sub);
      t[ 5] = (t[ 5] >> off_mul) | (t[ 4] << off_sub);
      t[ 4] = (t[ 4] >> off_mul) | (t[ 3] << off_sub);
      t[ 3] = (t[ 3] >> off_mul) | (t[ 2] << off_sub);
      t[ 2] = (t[ 2] >> off_mul) | (t[ 1] << off_sub);
      t[ 1] = (t[ 1] >> off_mul) | (t[ 0] << off_sub);
      t[ 0] = (t[ 0] >> off_mul);
    }

    w[n_idx] &= 0xffffff00 << ((3 - n_off) * 8);

    w[n_idx] |= t[0];

    w[n_idx +  1] = t[ 1];
    w[n_idx +  2] = t[ 2];
    w[n_idx +  3] = t[ 3];
    w[n_idx +  4] = t[ 4];
    w[n_idx +  5] = t[ 5];
    w[n_idx +  6] = t[ 6];
    w[n_idx +  7] = t[ 7];
    w[n_idx +  8] = t[ 8];
    w[n_idx +  9] = t[ 9];
    w[n_idx + 10] = t[10];
    w[n_idx + 11] = t[11];
    w[n_idx + 12] = t[12];
    w[n_idx + 13] = t[13];
    w[n_idx + 14] = t[14];
    w[n_idx + 15] = t[15];

    // the final set is only meaningful: if (n_off)

    w[n_idx + 16] &= 0xffffffff >> (n_off * 8);

    w[n_idx + 16] |= t[16];
  }
}

KERNEL_FQ void m23700_init (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].dgst[0] = SHA1M_A;
  tmps[gid].dgst[1] = SHA1M_B;
  tmps[gid].dgst[2] = SHA1M_C;
  tmps[gid].dgst[3] = SHA1M_D;
  tmps[gid].dgst[4] = SHA1M_E;

  // store pass and salt in tmps:

  const int pw_len = pws[gid].pw_len;

  if (pw_len == -1) return; // gpu_utf8_to_utf16() can result in -1

  u32 w[80] = { 0 };

  for (int i = 0, j = 0; i < pw_len; i += 4, j += 1)
  {
    w[j] = hc_swap32_S (pws[gid].i[j]);
  }

  // append salt:

  const u32 salt_idx = pw_len / 4;
  const u32 salt_off = pw_len & 3;

  u32 salt_buf[3];

  salt_buf[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]); // swap needed due to -O kernel
  salt_buf[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);
  salt_buf[2] = 0;

  // switch buffer by offset (can only be 0 or 2 because of utf16):

  if (salt_off == 2) // or just: if (salt_off)
  {
    salt_buf[2] =                       (salt_buf[1] << 16);
    salt_buf[1] = (salt_buf[1] >> 16) | (salt_buf[0] << 16);
    salt_buf[0] = (salt_buf[0] >> 16);
  }

  w[salt_idx + 0] |= salt_buf[0];
  w[salt_idx + 1]  = salt_buf[1];
  w[salt_idx + 2]  = salt_buf[2];

  // store initial w[] (pass and salt) in tmps:

  for (u32 i = 0; i < 66; i++) // unroll ?
  {
    tmps[gid].w[i] = w[i];
  }

  // iv:

  tmps[gid].iv[0] = 0;
  tmps[gid].iv[1] = 0;
  tmps[gid].iv[2] = 0;
  tmps[gid].iv[3] = 0;
}

KERNEL_FQ void m23700_loop (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const int pw_len = pws[gid].pw_len;

  if (pw_len == -1) return; // gpu_utf8_to_utf16() can result in -1

  const u32 salt_len = 8;

  const u32 pw_salt_len = pw_len + salt_len;

  const u32 p3 = pw_salt_len + 3;

  u32 w[80] = { 0 };

  for (u32 i = 0; i < 66; i++)
  {
    w[i] = tmps[gid].w[i];
  }

  // update IV:

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);

  sha1_ctx_t ctx_iv;

  sha1_init (&ctx_iv);

  ctx_iv.h[0] = tmps[gid].dgst[0];
  ctx_iv.h[1] = tmps[gid].dgst[1];
  ctx_iv.h[2] = tmps[gid].dgst[2];
  ctx_iv.h[3] = tmps[gid].dgst[3];
  ctx_iv.h[4] = tmps[gid].dgst[4];

  ctx_iv.len = LOOP_POS * p3;

  sha1_update_rar29 (&ctx_iv, w, pw_salt_len);

  memcat8c_be (ctx_iv.w0, ctx_iv.w1, ctx_iv.w2, ctx_iv.w3, ctx_iv.len, hc_swap32_S (LOOP_POS), ctx_iv.h);

  ctx_iv.len += 3;


  // copy the context from ctx_iv to ctx:

  sha1_ctx_t ctx;

  ctx.h[0] = ctx_iv.h[0];
  ctx.h[1] = ctx_iv.h[1];
  ctx.h[2] = ctx_iv.h[2];
  ctx.h[3] = ctx_iv.h[3];
  ctx.h[4] = ctx_iv.h[4];

  ctx.w0[0] = ctx_iv.w0[0];
  ctx.w0[1] = ctx_iv.w0[1];
  ctx.w0[2] = ctx_iv.w0[2];
  ctx.w0[3] = ctx_iv.w0[3];

  ctx.w1[0] = ctx_iv.w1[0];
  ctx.w1[1] = ctx_iv.w1[1];
  ctx.w1[2] = ctx_iv.w1[2];
  ctx.w1[3] = ctx_iv.w1[3];

  ctx.w2[0] = ctx_iv.w2[0];
  ctx.w2[1] = ctx_iv.w2[1];
  ctx.w2[2] = ctx_iv.w2[2];
  ctx.w2[3] = ctx_iv.w2[3];

  ctx.w3[0] = ctx_iv.w3[0];
  ctx.w3[1] = ctx_iv.w3[1];
  ctx.w3[2] = ctx_iv.w3[2];
  ctx.w3[3] = ctx_iv.w3[3];

  ctx.len = p3; // or ctx_iv.len ?

  // final () for the IV byte:

  sha1_final (&ctx_iv);

  const u32 iv_idx = init_pos / 4;
  const u32 iv_off = init_pos % 4;

  tmps[gid].iv[iv_idx] |= (ctx_iv.h[4] & 0xff) << (iv_off * 8);

  // main loop:

  for (u32 i = 0, j = (LOOP_POS + 1); i < 16383; i++, j++)
  {
    sha1_update_rar29 (&ctx, w, pw_salt_len);

    memcat8c_be (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.len, hc_swap32_S (j), ctx.h);

    ctx.len += 3;
  }

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];

  // only needed if pw_len > 28:

  for (u32 i = 0; i < 66; i++) // unroll ?
  {
    tmps[gid].w[i] = w[i];
  }
}

KERNEL_FQ void m23700_comp (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  LOCAL_VK u32 l_crc32tab[256];

  for (int i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const int pw_len = pws[gid].pw_len;

  if (pw_len == -1) return; // gpu_utf8_to_utf16() can result in -1

  const u32 salt_len = 8;

  const u32 pw_salt_len = pw_len + salt_len;

  const u32 p3 = pw_salt_len + 3;

  u32 h[5];

  h[0] = tmps[gid].dgst[0];
  h[1] = tmps[gid].dgst[1];
  h[2] = tmps[gid].dgst[2];
  h[3] = tmps[gid].dgst[3];
  h[4] = tmps[gid].dgst[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 0x80000000;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (ROUNDS * p3) * 8;

  sha1_transform (w0, w1, w2, w3, h);

  u32 ukey[4];

  ukey[0] = hc_swap32_S (h[0]);
  ukey[1] = hc_swap32_S (h[1]);
  ukey[2] = hc_swap32_S (h[2]);
  ukey[3] = hc_swap32_S (h[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  const u32 pack_size   = esalt_bufs[DIGESTS_OFFSET_HOST].pack_size;
  const u32 unpack_size = esalt_bufs[DIGESTS_OFFSET_HOST].unpack_size;

  if (pack_size > unpack_size) // could be aligned
  {
    if (pack_size >= 32) // otherwise IV...
    {
      const u32 pack_size_elements = pack_size / 4;

      u32 last_block_encrypted[4];

      last_block_encrypted[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 0];
      last_block_encrypted[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 1];
      last_block_encrypted[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 2];
      last_block_encrypted[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 3];

      u32 last_block_decrypted[4];

      AES128_decrypt (ks, last_block_encrypted, last_block_decrypted, s_td0, s_td1, s_td2, s_td3, s_td4);

      u32 last_block_iv[4];

      last_block_iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 8 + 0];
      last_block_iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 8 + 1];
      last_block_iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 8 + 2];
      last_block_iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 8 + 3];

      last_block_decrypted[0] ^= last_block_iv[0];
      last_block_decrypted[1] ^= last_block_iv[1];
      last_block_decrypted[2] ^= last_block_iv[2];
      last_block_decrypted[3] ^= last_block_iv[3];

      if ((last_block_decrypted[3] & 0xff) != 0) return;
    }
  }

  u32 iv[4];

  iv[0] = tmps[gid].iv[0];
  iv[1] = tmps[gid].iv[1];
  iv[2] = tmps[gid].iv[2];
  iv[3] = tmps[gid].iv[3];

  iv[0] = hc_swap32_S (iv[0]);
  iv[1] = hc_swap32_S (iv[1]);
  iv[2] = hc_swap32_S (iv[2]);
  iv[3] = hc_swap32_S (iv[3]);

  u32 data_left = unpack_size;

  u32 crc32 = ~0;

  for (u32 i = 0, j = 0; i < pack_size / 16; i += 1, j += 4)
  {
    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[j + 0];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[j + 1];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[j + 2];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[j + 3];

    u32 out[4];

    AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    crc32 = round_crc32_16 (crc32, out, data_left, l_crc32tab);

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    data_left -= 16;
  }

  const u32 r0 = crc32;
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
