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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

CONSTANT_VK u32a c_ascii_to_ebcdic_pc[256] =
{
  // little hack, can't crack 0-bytes in password, but who cares
  //    0xab, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x2a, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x8a, 0x89, 0x8f, 0x8c, 0xd3, 0xd0, 0xce, 0xe6, 0x9b, 0x98, 0xd5, 0xe5, 0x92, 0x91, 0x97, 0x94,
  0x2a, 0x34, 0x54, 0x5d, 0x1c, 0x73, 0x0b, 0x51, 0x31, 0x10, 0x13, 0x37, 0x7c, 0x6b, 0x3d, 0x68,
  0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40, 0x46, 0x45, 0x5b, 0x58, 0x5e, 0x16, 0x32, 0x57, 0x76, 0x75,
  0x52, 0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07,
  0x04, 0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x3e, 0x6b, 0x1f, 0x15, 0x70,
  0x58, 0xa8, 0xae, 0xad, 0xa2, 0xa1, 0xa7, 0xa4, 0xba, 0xb9, 0x89, 0x8f, 0x8c, 0x83, 0x80, 0x86,
  0x85, 0x9b, 0x98, 0xef, 0xec, 0xe3, 0xe0, 0xe6, 0xe5, 0xfb, 0xf8, 0x2a, 0x7f, 0x0b, 0xe9, 0xa4,
  0xea, 0xe9, 0xef, 0xec, 0xe3, 0x80, 0xa7, 0x85, 0xfb, 0xf8, 0xfe, 0xfd, 0xf2, 0xb9, 0xbf, 0x9d,
  0xcb, 0xc8, 0x9e, 0xcd, 0xc2, 0xc1, 0xc7, 0xba, 0xda, 0xd9, 0xdf, 0xdc, 0xa2, 0x83, 0xd6, 0x68,
  0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07, 0x04,
  0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40,
  0x46, 0x45, 0x5b, 0xab, 0xbf, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5, 0x8a, 0x9e, 0x9d, 0x92, 0x91, 0x97,
  0x94, 0xea, 0xfe, 0xfd, 0xf2, 0xf1, 0xf7, 0xf4, 0xcb, 0xc8, 0xce, 0xcd, 0xc2, 0xc1, 0xc7, 0xc4,
  0xda, 0xd9, 0xdf, 0xdc, 0xd3, 0xd0, 0xd6, 0xd5, 0x3e, 0x3d, 0x32, 0x31, 0x37, 0x34, 0x1f, 0x1c,
  0x13, 0x10, 0x16, 0x15, 0x7f, 0x7c, 0x73, 0x70, 0x76, 0x75, 0x5e, 0x5d, 0x52, 0x51, 0x57, 0x54,
};

#if   VECT_SIZE == 1
#define BOX1(i,S) (S)[(i)]
#elif VECT_SIZE == 2
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

DECLSPEC void transform_racf_key (const u32 w0, const u32x w1, PRIVATE_AS u32x *key)
{
  key[0] = BOX1 (((w0 >>  0) & 0xff), c_ascii_to_ebcdic_pc) <<  0
         | BOX1 (((w0 >>  8) & 0xff), c_ascii_to_ebcdic_pc) <<  8
         | BOX1 (((w0 >> 16) & 0xff), c_ascii_to_ebcdic_pc) << 16
         | BOX1 (((w0 >> 24) & 0xff), c_ascii_to_ebcdic_pc) << 24;

  key[1] = BOX1 (((w1 >>  0) & 0xff), c_ascii_to_ebcdic_pc) <<  0
         | BOX1 (((w1 >>  8) & 0xff), c_ascii_to_ebcdic_pc) <<  8
         | BOX1 (((w1 >> 16) & 0xff), c_ascii_to_ebcdic_pc) << 16
         | BOX1 (((w1 >> 24) & 0xff), c_ascii_to_ebcdic_pc) << 24;
}

KERNEL_FQ KERNEL_FA void m08500_mxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

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

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * salt
   */

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * main
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    /**
     * RACF
     */

    u32 key[2];

    transform_racf_key (tmp.i[0], tmp.i[1], key);

    const u32 c = key[0];
    const u32 d = key[1];

    u32 Kc[16];
    u32 Kd[16];

    _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

    u32 data[2];

    data[0] = salt_buf0[0];
    data[1] = salt_buf0[1];

    u32 iv[2];

    _des_crypt_encrypt_racf (iv, data, Kc, Kd, s_SPtrans);

    u32 iv2[2] = { 0, 0 };

    if (tmp.pw_len > 8)
    {
      const u32 c9  = (tmp.i[2] >>  0) & 0xff;
      const u32 c10 = (tmp.pw_len > 9) ? ((tmp.i[2] >> 8) & 0xff) : 0x20;

      const u32 w0_b2 = c9 | (c10 << 8) | (0x20 << 16) | (0x20 << 24);
      const u32 w1_b2 = 0x20202020;

      u32 key2[2];

      transform_racf_key (w0_b2, w1_b2, key2);

      u32 Kc2[16];
      u32 Kd2[16];

      _des_crypt_keysetup (key2[0], key2[1], Kc2, Kd2, s_skb);

      _des_crypt_encrypt_racf (iv2, data, Kc2, Kd2, s_SPtrans);
    }

    COMPARE_M_SIMD (iv[0], iv[1], iv2[0], iv2[1]);
  }
}

KERNEL_FQ KERNEL_FA void m08500_sxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

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

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * salt
   */

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * main
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    /**
     * RACF
     */

    u32 key[2];

    transform_racf_key (tmp.i[0], tmp.i[1], key);

    const u32 c = key[0];
    const u32 d = key[1];

    u32 Kc[16];
    u32 Kd[16];

    _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

    u32 data[2];

    data[0] = salt_buf0[0];
    data[1] = salt_buf0[1];

    u32 iv[2];

    _des_crypt_encrypt_racf (iv, data, Kc, Kd, s_SPtrans);

    u32 iv2[2] = { 0, 0 };

    if (tmp.pw_len > 8)
    {
      const u32 c9  = (tmp.i[2] >>  0) & 0xff;
      const u32 c10 = (tmp.pw_len > 9) ? ((tmp.i[2] >> 8) & 0xff) : 0x20;

      const u32 w0_b2 = c9 | (c10 << 8) | (0x20 << 16) | (0x20 << 24);
      const u32 w1_b2 = 0x20202020;

      u32 key2[2];

      transform_racf_key (w0_b2, w1_b2, key2);

      u32 Kc2[16];
      u32 Kd2[16];

      _des_crypt_keysetup (key2[0], key2[1], Kc2, Kd2, s_skb);

      _des_crypt_encrypt_racf (iv2, data, Kc2, Kd2, s_SPtrans);
    }

    COMPARE_S_SIMD (iv[0], iv[1], iv2[0], iv2[1]);
  }
}
