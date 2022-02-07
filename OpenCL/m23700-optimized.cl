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

#define PUTCHAR(a,p,c) ((PRIVATE_AS u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)   ((PRIVATE_AS u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((PRIVATE_AS u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((PRIVATE_AS u8 *)(a))[(p) ^ 3]

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

typedef struct rar3
{
  u32 data[81920];

  u32 pack_size;
  u32 unpack_size;

} rar3_t;

typedef struct rar3_tmp
{
  u32 dgst[17][5];

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

KERNEL_FQ void m23700_init (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].dgst[0][0] = SHA1M_A;
  tmps[gid].dgst[0][1] = SHA1M_B;
  tmps[gid].dgst[0][2] = SHA1M_C;
  tmps[gid].dgst[0][3] = SHA1M_D;
  tmps[gid].dgst[0][4] = SHA1M_E;
}

/*
KERNEL_FQ void m23700_loop (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf[10];

  pw_buf[0] = pws[gid].i[0];
  pw_buf[1] = pws[gid].i[1];
  pw_buf[2] = pws[gid].i[2];
  pw_buf[3] = pws[gid].i[3];
  pw_buf[4] = pws[gid].i[4];
  pw_buf[5] = pws[gid].i[5];
  pw_buf[6] = pws[gid].i[6];
  pw_buf[7] = pws[gid].i[7];
  pw_buf[8] = pws[gid].i[8];
  pw_buf[9] = pws[gid].i[9];

  const u32 pw_len = MIN (pws[gid].pw_len, 40);

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 salt_len = 8;

  // this is large enough to hold all possible w[] arrays for 64 iterations

  u32 cb[16] = { 0 };

  u32 p = 0;

  for (u32 j = 0; j < pw_len; j++, p += 1)
  {
    PUTCHAR_BE (cb, p, GETCHAR (pw_buf, j));
  }

  for (u32 j = 0; j < salt_len; j++, p += 1)
  {
    PUTCHAR_BE (cb, p, GETCHAR (salt_buf, j));
  }

  const u32 p2 = pw_len + salt_len;
  const u32 p3 = pw_len + salt_len + 3;

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[init_pos][0];
  dgst[1] = tmps[gid].dgst[init_pos][1];
  dgst[2] = tmps[gid].dgst[init_pos][2];
  dgst[3] = tmps[gid].dgst[init_pos][3];
  dgst[4] = tmps[gid].dgst[init_pos][4];

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };
  u32 w4[4] = { 0 };
  u32 w5[4] = { 0 };
  u32 w6[4] = { 0 };
  u32 w7[4] = { 0 };

  u32 iter = LOOP_POS;

  for (u32 i = 0; i < 256; i++)
  {
    u32 k1 = 0;
    u32 k2 = p2;

    for (u32 j = 0; j < p3; j++)
    {
      w0[0] = w4[0];
      w0[1] = w4[1];
      w0[2] = w4[2];
      w0[3] = w4[3];
      w1[0] = w5[0];
      w1[1] = w5[1];
      w1[2] = w5[2];
      w1[3] = w5[3];
      w2[0] = w6[0];
      w2[1] = w6[1];
      w2[2] = w6[2];
      w2[3] = w6[3];
      w3[0] = w7[0];
      w3[1] = w7[1];
      w3[2] = w7[2];
      w3[3] = w7[3];
      w4[0] = 0;
      w4[1] = 0;
      w4[2] = 0;
      w4[3] = 0;
      w5[0] = 0;
      w5[1] = 0;
      w5[2] = 0;
      w5[3] = 0;
      w6[0] = 0;
      w6[1] = 0;
      w6[2] = 0;
      w6[3] = 0;
      w7[0] = 0;
      w7[1] = 0;
      w7[2] = 0;
      w7[3] = 0;

      const u32 t1 = k1;

      while (k1 < 64)
      {
        u32 x0[4];
        u32 x1[4];
        u32 x2[4];
        u32 x3[4];
        u32 x4[4];
        u32 x5[4];
        u32 x6[4];
        u32 x7[4];

        x0[0] = cb[ 0];
        x0[1] = cb[ 1];
        x0[2] = cb[ 2];
        x0[3] = cb[ 3];
        x1[0] = cb[ 4];
        x1[1] = cb[ 5];
        x1[2] = cb[ 6];
        x1[3] = cb[ 7];
        x2[0] = cb[ 8];
        x2[1] = cb[ 9];
        x2[2] = cb[10];
        x2[3] = cb[11];
        x3[0] = cb[12];
        x3[1] = cb[13];
        x3[2] = cb[14];
        x3[3] = cb[15];
        x4[0] = 0;
        x4[1] = 0;
        x4[2] = 0;
        x4[3] = 0;
        x5[0] = 0;
        x5[1] = 0;
        x5[2] = 0;
        x5[3] = 0;
        x6[0] = 0;
        x6[1] = 0;
        x6[2] = 0;
        x6[3] = 0;
        x7[0] = 0;
        x7[1] = 0;
        x7[2] = 0;
        x7[3] = 0;

        switch_buffer_by_offset_carry_be (x0, x1, x2, x3, x4, x5, x6, x7, k1);

        w0[0] |= x0[0];
        w0[1] |= x0[1];
        w0[2] |= x0[2];
        w0[3] |= x0[3];
        w1[0] |= x1[0];
        w1[1] |= x1[1];
        w1[2] |= x1[2];
        w1[3] |= x1[3];
        w2[0] |= x2[0];
        w2[1] |= x2[1];
        w2[2] |= x2[2];
        w2[3] |= x2[3];
        w3[0] |= x3[0];
        w3[1] |= x3[1];
        w3[2] |= x3[2];
        w3[3] |= x3[3];
        w4[0] |= x4[0];
        w4[1] |= x4[1];
        w4[2] |= x4[2];
        w4[3] |= x4[3];
        w5[0] |= x5[0];
        w5[1] |= x5[1];
        w5[2] |= x5[2];
        w5[3] |= x5[3];
        w6[0] |= x6[0];
        w6[1] |= x6[1];
        w6[2] |= x6[2];
        w6[3] |= x6[3];
        w7[0] |= x7[0];
        w7[1] |= x7[1];
        w7[2] |= x7[2];
        w7[3] |= x7[3];

        k1 += p3;
      }

      while (k2 < k1)
      {
        const u32 iter_s = hc_swap32_S (iter);

        u32 tmp0 = 0;
        u32 tmp1 = 0;

        switch (k2 & 3)
        {
          case 0: tmp0 = iter_s >>  0;
                  tmp1 = 0;
                  break;
          case 1: tmp0 = iter_s >>  8;
                  tmp1 = 0;
                  break;
          case 2: tmp0 = iter_s >> 16;
                  tmp1 = iter_s << 16;
                  break;
          case 3: tmp0 = iter_s >> 24;
                  tmp1 = iter_s <<  8;
                  break;
        }

        switch (k2 / 4)
        {
          case  0: w0[0] |= tmp0;
                   w0[1] |= tmp1;
                   break;
          case  1: w0[1] |= tmp0;
                   w0[2] |= tmp1;
                   break;
          case  2: w0[2] |= tmp0;
                   w0[3] |= tmp1;
                   break;
          case  3: w0[3] |= tmp0;
                   w1[0] |= tmp1;
                   break;
          case  4: w1[0] |= tmp0;
                   w1[1] |= tmp1;
                   break;
          case  5: w1[1] |= tmp0;
                   w1[2] |= tmp1;
                   break;
          case  6: w1[2] |= tmp0;
                   w1[3] |= tmp1;
                   break;
          case  7: w1[3] |= tmp0;
                   w2[0] |= tmp1;
                   break;
          case  8: w2[0] |= tmp0;
                   w2[1] |= tmp1;
                   break;
          case  9: w2[1] |= tmp0;
                   w2[2] |= tmp1;
                   break;
          case 10: w2[2] |= tmp0;
                   w2[3] |= tmp1;
                   break;
          case 11: w2[3] |= tmp0;
                   w3[0] |= tmp1;
                   break;
          case 12: w3[0] |= tmp0;
                   w3[1] |= tmp1;
                   break;
          case 13: w3[1] |= tmp0;
                   w3[2] |= tmp1;
                   break;
          case 14: w3[2] |= tmp0;
                   w3[3] |= tmp1;
                   break;
          case 15: w3[3] |= tmp0;
                   w4[0] |= tmp1;
                   break;
          case 16: w4[0] |= tmp0;
                   w4[1] |= tmp1;
                   break;
          case 17: w4[1] |= tmp0;
                   w4[2] |= tmp1;
                   break;
          case 18: w4[2] |= tmp0;
                   w4[3] |= tmp1;
                   break;
          case 19: w4[3] |= tmp0;
                   w5[0] |= tmp1;
                   break;
          case 20: w5[0] |= tmp0;
                   w5[1] |= tmp1;
                   break;
          case 21: w5[1] |= tmp0;
                   w5[2] |= tmp1;
                   break;
          case 22: w5[2] |= tmp0;
                   w5[3] |= tmp1;
                   break;
          case 23: w5[3] |= tmp0;
                   w6[0] |= tmp1;
                   break;
          case 24: w6[0] |= tmp0;
                   w6[1] |= tmp1;
                   break;
          case 25: w6[1] |= tmp0;
                   w6[2] |= tmp1;
                   break;
          case 26: w6[2] |= tmp0;
                   w6[3] |= tmp1;
                   break;
          case 27: w6[3] |= tmp0;
                   w7[0] |= tmp1;
                   break;
          case 28: w7[0] |= tmp0;
                   w7[1] |= tmp1;
                   break;
          case 29: w7[1] |= tmp0;
                   w7[2] |= tmp1;
                   break;
          case 30: w7[2] |= tmp0;
                   w7[3] |= tmp1;
                   break;
          case 31: w7[3] |= tmp0;

                   break;
        }

        iter++;

        k2 += p3;
      }

      sha1_transform (w0, w1, w2, w3, dgst);

      k1 &= 63;
      k2 &= 63;
    }
  }

  tmps[gid].dgst[init_pos + 1][0] = dgst[0];
  tmps[gid].dgst[init_pos + 1][1] = dgst[1];
  tmps[gid].dgst[init_pos + 1][2] = dgst[2];
  tmps[gid].dgst[init_pos + 1][3] = dgst[3];
  tmps[gid].dgst[init_pos + 1][4] = dgst[4];
}
*/

KERNEL_FQ void m23700_loop (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, rar3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf[10];

  pw_buf[0] = pws[gid].i[0];
  pw_buf[1] = pws[gid].i[1];
  pw_buf[2] = pws[gid].i[2];
  pw_buf[3] = pws[gid].i[3];
  pw_buf[4] = pws[gid].i[4];
  pw_buf[5] = pws[gid].i[5];
  pw_buf[6] = pws[gid].i[6];
  pw_buf[7] = pws[gid].i[7];
  pw_buf[8] = pws[gid].i[8];
  pw_buf[9] = pws[gid].i[9];

  const u32 pw_len = MIN (pws[gid].pw_len, 40);

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 salt_len = 8;

  // this is large enough to hold all possible w[] arrays for 64 iterations

  #define LARGEBLOCK_ELEMS ((40 + 8 + 3) * 16)

  u32 largeblock[LARGEBLOCK_ELEMS];

  for (u32 i = 0; i < LARGEBLOCK_ELEMS; i++) largeblock[i] = 0;

  for (u32 i = 0, p = 0; i < 64; i++)
  {
    for (u32 j = 0; j < pw_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (salt_buf, j));
    }

    PUTCHAR_BE (largeblock, p + 2, (LOOP_POS >> 16) & 0xff);

    p += 3;
  }

  const u32 p2 = pw_len + salt_len;

  const u32 p3 = pw_len + salt_len + 3;

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[init_pos][0];
  dgst[1] = tmps[gid].dgst[init_pos][1];
  dgst[2] = tmps[gid].dgst[init_pos][2];
  dgst[3] = tmps[gid].dgst[init_pos][3];
  dgst[4] = tmps[gid].dgst[init_pos][4];

  u32 iter = LOOP_POS;

  for (u32 i = 0; i < 256; i++)
  {
    u32 tmp = 0;

    u32 k = p2;

    for (u32 j = 0; j < p3; j++)
    {
      const u32 j16 = j * 16;

      u32 w[16 + 1];

      w[ 0] = largeblock[j16 +  0] | tmp;
      w[ 1] = largeblock[j16 +  1];
      w[ 2] = largeblock[j16 +  2];
      w[ 3] = largeblock[j16 +  3];
      w[ 4] = largeblock[j16 +  4];
      w[ 5] = largeblock[j16 +  5];
      w[ 6] = largeblock[j16 +  6];
      w[ 7] = largeblock[j16 +  7];
      w[ 8] = largeblock[j16 +  8];
      w[ 9] = largeblock[j16 +  9];
      w[10] = largeblock[j16 + 10];
      w[11] = largeblock[j16 + 11];
      w[12] = largeblock[j16 + 12];
      w[13] = largeblock[j16 + 13];
      w[14] = largeblock[j16 + 14];
      w[15] = largeblock[j16 + 15];
      w[16] = 0;

      while (k < 64)
      {
        const u32 iter_s = hc_swap32_S (iter);

        u32 mask0 = 0;
        u32 mask1 = 0;

        u32 tmp0 = 0;
        u32 tmp1 = 0;

        const int kd = k / 4;
        const int km = k & 3;

             if (km == 0) { tmp0 = iter_s >>  0; tmp1 = 0;            mask0 = 0x0000ffff; mask1 = 0xffffffff; }
        else if (km == 1) { tmp0 = iter_s >>  8; tmp1 = 0;            mask0 = 0xff0000ff; mask1 = 0xffffffff; }
        else if (km == 2) { tmp0 = iter_s >> 16; tmp1 = 0;            mask0 = 0xffff0000; mask1 = 0xffffffff; }
        else if (km == 3) { tmp0 = iter_s >> 24; tmp1 = iter_s <<  8; mask0 = 0xffffff00; mask1 = 0x00ffffff; }

        switch (kd)
        {
          case  0: w[ 0] = (w[ 0] & mask0) | tmp0;
                   w[ 1] = (w[ 1] & mask1) | tmp1;
                   break;
          case  1: w[ 1] = (w[ 1] & mask0) | tmp0;
                   w[ 2] = (w[ 2] & mask1) | tmp1;
                   break;
          case  2: w[ 2] = (w[ 2] & mask0) | tmp0;
                   w[ 3] = (w[ 3] & mask1) | tmp1;
                   break;
          case  3: w[ 3] = (w[ 3] & mask0) | tmp0;
                   w[ 4] = (w[ 4] & mask1) | tmp1;
                   break;
          case  4: w[ 4] = (w[ 4] & mask0) | tmp0;
                   w[ 5] = (w[ 5] & mask1) | tmp1;
                   break;
          case  5: w[ 5] = (w[ 5] & mask0) | tmp0;
                   w[ 6] = (w[ 6] & mask1) | tmp1;
                   break;
          case  6: w[ 6] = (w[ 6] & mask0) | tmp0;
                   w[ 7] = (w[ 7] & mask1) | tmp1;
                   break;
          case  7: w[ 7] = (w[ 7] & mask0) | tmp0;
                   w[ 8] = (w[ 8] & mask1) | tmp1;
                   break;
          case  8: w[ 8] = (w[ 8] & mask0) | tmp0;
                   w[ 9] = (w[ 9] & mask1) | tmp1;
                   break;
          case  9: w[ 9] = (w[ 9] & mask0) | tmp0;
                   w[10] = (w[10] & mask1) | tmp1;
                   break;
          case 10: w[10] = (w[10] & mask0) | tmp0;
                   w[11] = (w[11] & mask1) | tmp1;
                   break;
          case 11: w[11] = (w[11] & mask0) | tmp0;
                   w[12] = (w[12] & mask1) | tmp1;
                   break;
          case 12: w[12] = (w[12] & mask0) | tmp0;
                   w[13] = (w[13] & mask1) | tmp1;
                   break;
          case 13: w[13] = (w[13] & mask0) | tmp0;
                   w[14] = (w[14] & mask1) | tmp1;
                   break;
          case 14: w[14] = (w[14] & mask0) | tmp0;
                   w[15] = (w[15] & mask1) | tmp1;
                   break;
          case 15: w[15] = (w[15] & mask0) | tmp0;
                   w[16] =                   tmp1;
                   break;
        }

        iter++;

        k += p3;
      }

      sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);

      k &= 63;

      tmp = w[16];
    }
  }

  tmps[gid].dgst[init_pos + 1][0] = dgst[0];
  tmps[gid].dgst[init_pos + 1][1] = dgst[1];
  tmps[gid].dgst[init_pos + 1][2] = dgst[2];
  tmps[gid].dgst[init_pos + 1][3] = dgst[3];
  tmps[gid].dgst[init_pos + 1][4] = dgst[4];
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

  const u32 pw_len = MIN (pws[gid].pw_len, 40);

  const u32 salt_len = 8;

  const u32 p3 = pw_len + salt_len + 3;

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
  w3[3] = (p3 * ROUNDS) * 8;

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[16][0];
  dgst[1] = tmps[gid].dgst[16][1];
  dgst[2] = tmps[gid].dgst[16][2];
  dgst[3] = tmps[gid].dgst[16][3];
  dgst[4] = tmps[gid].dgst[16][4];

  sha1_transform (w0, w1, w2, w3, dgst);

  u32 ukey[4];

  ukey[0] = hc_swap32_S (dgst[0]);
  ukey[1] = hc_swap32_S (dgst[1]);
  ukey[2] = hc_swap32_S (dgst[2]);
  ukey[3] = hc_swap32_S (dgst[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4];

  iv[0] = 0;
  iv[1] = 0;
  iv[2] = 0;
  iv[3] = 0;

  for (int i = 0; i < 16; i++)
  {
    u32 pw_buf[10];

    pw_buf[0] = pws[gid].i[0];
    pw_buf[1] = pws[gid].i[1];
    pw_buf[2] = pws[gid].i[2];
    pw_buf[3] = pws[gid].i[3];
    pw_buf[4] = pws[gid].i[4];
    pw_buf[5] = pws[gid].i[5];
    pw_buf[6] = pws[gid].i[6];
    pw_buf[7] = pws[gid].i[7];
    pw_buf[8] = pws[gid].i[8];
    pw_buf[9] = pws[gid].i[9];

    //const u32 pw_len = pws[gid].pw_len;

    u32 salt_buf[2];

    salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

    //const u32 salt_len = 8;

    //const u32 p3 = pw_len + salt_len + 3;

    u32 w[16];

    w[ 0] = 0;
    w[ 1] = 0;
    w[ 2] = 0;
    w[ 3] = 0;
    w[ 4] = 0;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u32 p = 0;

    for (u32 j = 0; j < pw_len; j++, p += 1)
    {
      PUTCHAR_BE (w, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (w, p, GETCHAR (salt_buf, j));
    }

    const u32 iter_pos = i * (ROUNDS / 16);

    PUTCHAR_BE (w, p + 0, (iter_pos >>  0) & 0xff);
    PUTCHAR_BE (w, p + 1, (iter_pos >>  8) & 0xff);
    PUTCHAR_BE (w, p + 2, (iter_pos >> 16) & 0xff);

    PUTCHAR_BE (w, p3, 0x80);

    w[15] = ((iter_pos + 1) * p3) * 8;

    u32 dgst[5];

    dgst[0] = tmps[gid].dgst[i][0];
    dgst[1] = tmps[gid].dgst[i][1];
    dgst[2] = tmps[gid].dgst[i][2];
    dgst[3] = tmps[gid].dgst[i][3];
    dgst[4] = tmps[gid].dgst[i][4];

    sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);

    PUTCHAR (iv, i, dgst[4] & 0xff);
  }

  iv[0] = hc_swap32_S (iv[0]);
  iv[1] = hc_swap32_S (iv[1]);
  iv[2] = hc_swap32_S (iv[2]);
  iv[3] = hc_swap32_S (iv[3]);

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
