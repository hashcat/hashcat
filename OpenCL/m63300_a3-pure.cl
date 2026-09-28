/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct racf_ph
{
  u32 hash_blocks[26];
  u32 num_blocks;
  u32 pw_len;

} racf_ph_t;

CONSTANT_VK u32a c_ascii_to_ebcdic[256] =
{
  0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
  0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
  0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
  0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xba, 0xe0, 0xbb, 0xb0, 0x6d,
  0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
  0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
  0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xff,
  0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5, 0xbd, 0xb4, 0x9a, 0x8a, 0x5f, 0xca, 0xaf, 0xbc,
  0x90, 0x8f, 0xea, 0xfa, 0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
  0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,
  0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf, 0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xad, 0xae, 0x59,
  0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
  0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb, 0xdc, 0x8d, 0x8e, 0xdf,
};

DECLSPEC u32 ascii_to_ebcdic_u32 (const u32 w, CONSTANT_AS u32a *table)
{
  return (table[(w >>  0) & 0xff] <<  0)
       | (table[(w >>  8) & 0xff] <<  8)
       | (table[(w >> 16) & 0xff] << 16)
       | (table[(w >> 24) & 0xff] << 24);
}

KERNEL_FQ KERNEL_FA void m63300_mxx (KERN_ATTR_VECTOR_ESALT (racf_ph_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 num_blocks = esalt_bufs[DIGESTS_OFFSET_HOST].num_blocks;
  const u32 ph_pw_len  = esalt_bufs[DIGESTS_OFFSET_HOST].pw_len;

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    if (pw_len != ph_pw_len) continue;

    const u32 pw_u32_cnt = (pw_len + 3) / 4;

    u32 pw_ebc[26];

    for (u32 i = 0; i < num_blocks * 2; i++) pw_ebc[i] = 0x40404040;

    for (u32 i = 0; i < pw_u32_cnt; i++)
    {
      pw_ebc[i] = ascii_to_ebcdic_u32 (w[i], c_ascii_to_ebcdic);
    }

    const u32 rem = pw_len & 3;

    if (rem > 0)
    {
      const u32 mask = (1u << (rem * 8)) - 1;
      pw_ebc[pw_u32_cnt - 1] = (pw_ebc[pw_u32_cnt - 1] & mask) | (0x40404040 & ~mask);
    }

    u32 prev[2] = { 0, 0 };
    u32 matched = 1;

    for (u32 block = 0; block < num_blocks; block++)
    {
      u32 k0 = ((pw_ebc[block * 2 + 0] ^ prev[0] ^ 0x55555555) & 0x7f7f7f7f) << 1;
      u32 k1 = ((pw_ebc[block * 2 + 1] ^ prev[1] ^ 0x55555555) & 0x7f7f7f7f) << 1;

      u32 Kc[16];
      u32 Kd[16];

      _des_crypt_keysetup (k0, k1, Kc, Kd, s_skb);

      u32 data[2];

      data[0] = salt_buf[0];
      data[1] = salt_buf[1];

      u32 out[2];

      _des_crypt_encrypt (out, data, Kc, Kd, s_SPtrans);

      const u32 exp0 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[block * 2 + 0];
      const u32 exp1 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[block * 2 + 1];

      if (block < (num_blocks - 1))
      {
        if ((out[0] != exp0) || (out[1] != exp1)) { matched = 0; break; }
      }
      else
      {
        const u32 remainder = ph_pw_len - (block * 8);

        if (remainder >= 8)
        {
          if ((out[0] != exp0) || (out[1] != exp1)) matched = 0;
        }
        else if (remainder >= 4)
        {
          if (out[0] != exp0) matched = 0;
          const u32 rmask = (1u << ((remainder - 4) * 8)) - 1;
          if ((out[1] & rmask) != (exp1 & rmask)) matched = 0;
        }
        else
        {
          const u32 rmask = (1u << (remainder * 8)) - 1;
          if ((out[0] & rmask) != (exp0 & rmask)) matched = 0;
        }
      }

      prev[0] = out[0];
      prev[1] = out[1];
    }

    if (matched == 1)
    {
      const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[0];
      const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[1];
      const u32 r2 = 0;
      const u32 r3 = 0;

      COMPARE_M_SIMD (r0, r1, r2, r3);
    }
  }
}

KERNEL_FQ KERNEL_FA void m63300_sxx (KERN_ATTR_VECTOR_ESALT (racf_ph_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  const u32 num_blocks = esalt_bufs[DIGESTS_OFFSET_HOST].num_blocks;
  const u32 ph_pw_len  = esalt_bufs[DIGESTS_OFFSET_HOST].pw_len;

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    if (pw_len != ph_pw_len) continue;

    const u32 pw_u32_cnt = (pw_len + 3) / 4;

    u32 pw_ebc[26];

    for (u32 i = 0; i < num_blocks * 2; i++) pw_ebc[i] = 0x40404040;

    for (u32 i = 0; i < pw_u32_cnt; i++)
    {
      pw_ebc[i] = ascii_to_ebcdic_u32 (w[i], c_ascii_to_ebcdic);
    }

    const u32 rem = pw_len & 3;

    if (rem > 0)
    {
      const u32 mask = (1u << (rem * 8)) - 1;
      pw_ebc[pw_u32_cnt - 1] = (pw_ebc[pw_u32_cnt - 1] & mask) | (0x40404040 & ~mask);
    }

    u32 prev[2] = { 0, 0 };
    u32 matched = 1;

    for (u32 block = 0; block < num_blocks; block++)
    {
      u32 k0 = ((pw_ebc[block * 2 + 0] ^ prev[0] ^ 0x55555555) & 0x7f7f7f7f) << 1;
      u32 k1 = ((pw_ebc[block * 2 + 1] ^ prev[1] ^ 0x55555555) & 0x7f7f7f7f) << 1;

      u32 Kc[16];
      u32 Kd[16];

      _des_crypt_keysetup (k0, k1, Kc, Kd, s_skb);

      u32 data[2];

      data[0] = salt_buf[0];
      data[1] = salt_buf[1];

      u32 out[2];

      _des_crypt_encrypt (out, data, Kc, Kd, s_SPtrans);

      const u32 exp0 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[block * 2 + 0];
      const u32 exp1 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[block * 2 + 1];

      if (block < (num_blocks - 1))
      {
        if ((out[0] != exp0) || (out[1] != exp1)) { matched = 0; break; }
      }
      else
      {
        const u32 remainder = ph_pw_len - (block * 8);

        if (remainder >= 8)
        {
          if ((out[0] != exp0) || (out[1] != exp1)) matched = 0;
        }
        else if (remainder >= 4)
        {
          if (out[0] != exp0) matched = 0;
          const u32 rmask = (1u << ((remainder - 4) * 8)) - 1;
          if ((out[1] & rmask) != (exp1 & rmask)) matched = 0;
        }
        else
        {
          const u32 rmask = (1u << (remainder * 8)) - 1;
          if ((out[0] & rmask) != (exp0 & rmask)) matched = 0;
        }
      }

      prev[0] = out[0];
      prev[1] = out[1];
    }

    if (matched == 1)
    {
      const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[0];
      const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].hash_blocks[1];
      const u32 r2 = 0;
      const u32 r3 = 0;

      COMPARE_S_SIMD (r0, r1, r2, r3);
    }
  }
}
