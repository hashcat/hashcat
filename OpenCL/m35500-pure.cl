/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

CONSTANT_VK u32 bin2base64[0x40] =
{
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
  0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
  0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f,
};

#if   VECT_SIZE == 1
#define int_to_base64(c) make_u32x (s_bin2base64[(c)])
#elif VECT_SIZE == 2
#define int_to_base64(c) make_u32x (s_bin2base64[(c).s0], s_bin2base64[(c).s1])
#elif VECT_SIZE == 4
#define int_to_base64(c) make_u32x (s_bin2base64[(c).s0], s_bin2base64[(c).s1], s_bin2base64[(c).s2], s_bin2base64[(c).s3])
#elif VECT_SIZE == 8
#define int_to_base64(c) make_u32x (s_bin2base64[(c).s0], s_bin2base64[(c).s1], s_bin2base64[(c).s2], s_bin2base64[(c).s3], s_bin2base64[(c).s4], s_bin2base64[(c).s5], s_bin2base64[(c).s6], s_bin2base64[(c).s7])
#elif VECT_SIZE == 16
#define int_to_base64(c) make_u32x (s_bin2base64[(c).s0], s_bin2base64[(c).s1], s_bin2base64[(c).s2], s_bin2base64[(c).s3], s_bin2base64[(c).s4], s_bin2base64[(c).s5], s_bin2base64[(c).s6], s_bin2base64[(c).s7], s_bin2base64[(c).s8], s_bin2base64[(c).s9], s_bin2base64[(c).sa], s_bin2base64[(c).sb], s_bin2base64[(c).sc], s_bin2base64[(c).sd], s_bin2base64[(c).se], s_bin2base64[(c).sf])
#endif

typedef struct bcrypt_tmp
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

KERNEL_FQ KERNEL_FA void m35500_init (KERN_ATTR_TMPS (bcrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  CONSTANT_AS u32a *s_bin2base64 = bin2base64;

  if (gid >= GID_CNT) return;

  // "wp-sha384" key
  const u32 key[32] = { 0x732D7077, 0x38336168, 0x00000034, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  sha384_hmac_ctx_t ctx0;

  sha384_hmac_init_swap (&ctx0, key, 9);

  sha384_hmac_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  sha384_hmac_final (&ctx0);

  #define tmp_u8_00 ((ctx0.opad.h[0] >> 58) & 0x3f)
  #define tmp_u8_01 ((ctx0.opad.h[0] >> 52) & 0x3f)
  #define tmp_u8_02 ((ctx0.opad.h[0] >> 46) & 0x3f)
  #define tmp_u8_03 ((ctx0.opad.h[0] >> 40) & 0x3f)
  #define tmp_u8_04 ((ctx0.opad.h[0] >> 34) & 0x3f)
  #define tmp_u8_05 ((ctx0.opad.h[0] >> 28) & 0x3f)
  #define tmp_u8_06 ((ctx0.opad.h[0] >> 22) & 0x3f)
  #define tmp_u8_07 ((ctx0.opad.h[0] >> 16) & 0x3f)
  #define tmp_u8_08 ((ctx0.opad.h[0] >> 10) & 0x3f)
  #define tmp_u8_09 ((ctx0.opad.h[0] >>  4) & 0x3f)
  #define tmp_u8_10 ((ctx0.opad.h[0] <<  2) & 0x3c) | ((ctx0.opad.h[1] >> 62) & 0x03)

  #define tmp_u8_11 ((ctx0.opad.h[1] >> 56) & 0x3f)
  #define tmp_u8_12 ((ctx0.opad.h[1] >> 50) & 0x3f)
  #define tmp_u8_13 ((ctx0.opad.h[1] >> 44) & 0x3f)
  #define tmp_u8_14 ((ctx0.opad.h[1] >> 38) & 0x3f)
  #define tmp_u8_15 ((ctx0.opad.h[1] >> 32) & 0x3f)
  #define tmp_u8_16 ((ctx0.opad.h[1] >> 26) & 0x3f)
  #define tmp_u8_17 ((ctx0.opad.h[1] >> 20) & 0x3f)
  #define tmp_u8_18 ((ctx0.opad.h[1] >> 14) & 0x3f)
  #define tmp_u8_19 ((ctx0.opad.h[1] >>  8) & 0x3f)
  #define tmp_u8_20 ((ctx0.opad.h[1] >>  2) & 0x3f)
  #define tmp_u8_21 ((ctx0.opad.h[1] <<  4) & 0x30) | ((ctx0.opad.h[2] >> 60) & 0x0f)

  #define tmp_u8_22 ((ctx0.opad.h[2] >> 54) & 0x3f)
  #define tmp_u8_23 ((ctx0.opad.h[2] >> 48) & 0x3f)
  #define tmp_u8_24 ((ctx0.opad.h[2] >> 42) & 0x3f)
  #define tmp_u8_25 ((ctx0.opad.h[2] >> 36) & 0x3f)
  #define tmp_u8_26 ((ctx0.opad.h[2] >> 30) & 0x3f)
  #define tmp_u8_27 ((ctx0.opad.h[2] >> 24) & 0x3f)
  #define tmp_u8_28 ((ctx0.opad.h[2] >> 18) & 0x3f)
  #define tmp_u8_29 ((ctx0.opad.h[2] >> 12) & 0x3f)
  #define tmp_u8_30 ((ctx0.opad.h[2] >>  6) & 0x3f)
  #define tmp_u8_31 ((ctx0.opad.h[2] >>  0) & 0x3f)

  #define tmp_u8_32 ((ctx0.opad.h[3] >> 58) & 0x3f)
  #define tmp_u8_33 ((ctx0.opad.h[3] >> 52) & 0x3f)
  #define tmp_u8_34 ((ctx0.opad.h[3] >> 46) & 0x3f)
  #define tmp_u8_35 ((ctx0.opad.h[3] >> 40) & 0x3f)
  #define tmp_u8_36 ((ctx0.opad.h[3] >> 34) & 0x3f)
  #define tmp_u8_37 ((ctx0.opad.h[3] >> 28) & 0x3f)
  #define tmp_u8_38 ((ctx0.opad.h[3] >> 22) & 0x3f)
  #define tmp_u8_39 ((ctx0.opad.h[3] >> 16) & 0x3f)
  #define tmp_u8_40 ((ctx0.opad.h[3] >> 10) & 0x3f)
  #define tmp_u8_41 ((ctx0.opad.h[3] >>  4) & 0x3f)
  #define tmp_u8_42 ((ctx0.opad.h[3] <<  2) & 0x3c) | ((ctx0.opad.h[4] >> 62) & 0x03)

  #define tmp_u8_43 ((ctx0.opad.h[4] >> 56) & 0x3f)
  #define tmp_u8_44 ((ctx0.opad.h[4] >> 50) & 0x3f)
  #define tmp_u8_45 ((ctx0.opad.h[4] >> 44) & 0x3f)
  #define tmp_u8_46 ((ctx0.opad.h[4] >> 38) & 0x3f)
  #define tmp_u8_47 ((ctx0.opad.h[4] >> 32) & 0x3f)
  #define tmp_u8_48 ((ctx0.opad.h[4] >> 26) & 0x3f)
  #define tmp_u8_49 ((ctx0.opad.h[4] >> 20) & 0x3f)
  #define tmp_u8_50 ((ctx0.opad.h[4] >> 14) & 0x3f)
  #define tmp_u8_51 ((ctx0.opad.h[4] >>  8) & 0x3f)
  #define tmp_u8_52 ((ctx0.opad.h[4] >>  2) & 0x3f)
  #define tmp_u8_53 ((ctx0.opad.h[4] <<  4) & 0x30) | ((ctx0.opad.h[5] >> 60) & 0x0f)

  #define tmp_u8_54 ((ctx0.opad.h[5] >> 54) & 0x3f)
  #define tmp_u8_55 ((ctx0.opad.h[5] >> 48) & 0x3f)
  #define tmp_u8_56 ((ctx0.opad.h[5] >> 42) & 0x3f)
  #define tmp_u8_57 ((ctx0.opad.h[5] >> 36) & 0x3f)
  #define tmp_u8_58 ((ctx0.opad.h[5] >> 30) & 0x3f)
  #define tmp_u8_59 ((ctx0.opad.h[5] >> 24) & 0x3f)
  #define tmp_u8_60 ((ctx0.opad.h[5] >> 18) & 0x3f)
  #define tmp_u8_61 ((ctx0.opad.h[5] >> 12) & 0x3f)
  #define tmp_u8_62 ((ctx0.opad.h[5] >>  6) & 0x3f)
  #define tmp_u8_63 ((ctx0.opad.h[5] >>  0) & 0x3f)

  u32 w[18] = { 0 };

  w[ 0] = int_to_base64 (tmp_u8_00) <<  0
        | int_to_base64 (tmp_u8_01) <<  8
        | int_to_base64 (tmp_u8_02) << 16
        | int_to_base64 (tmp_u8_03) << 24;
  w[ 1] = int_to_base64 (tmp_u8_04) <<  0
        | int_to_base64 (tmp_u8_05) <<  8
        | int_to_base64 (tmp_u8_06) << 16
        | int_to_base64 (tmp_u8_07) << 24;
  w[ 2] = int_to_base64 (tmp_u8_08) <<  0
        | int_to_base64 (tmp_u8_09) <<  8
        | int_to_base64 (tmp_u8_10) << 16
        | int_to_base64 (tmp_u8_11) << 24;
  w[ 3] = int_to_base64 (tmp_u8_12) <<  0
        | int_to_base64 (tmp_u8_13) <<  8
        | int_to_base64 (tmp_u8_14) << 16
        | int_to_base64 (tmp_u8_15) << 24;
  w[ 4] = int_to_base64 (tmp_u8_16) <<  0
        | int_to_base64 (tmp_u8_17) <<  8
        | int_to_base64 (tmp_u8_18) << 16
        | int_to_base64 (tmp_u8_19) << 24;
  w[ 5] = int_to_base64 (tmp_u8_20) <<  0
        | int_to_base64 (tmp_u8_21) <<  8
        | int_to_base64 (tmp_u8_22) << 16
        | int_to_base64 (tmp_u8_23) << 24;
  w[ 6] = int_to_base64 (tmp_u8_24) <<  0
        | int_to_base64 (tmp_u8_25) <<  8
        | int_to_base64 (tmp_u8_26) << 16
        | int_to_base64 (tmp_u8_27) << 24;
  w[ 7] = int_to_base64 (tmp_u8_28) <<  0
        | int_to_base64 (tmp_u8_29) <<  8
        | int_to_base64 (tmp_u8_30) << 16
        | int_to_base64 (tmp_u8_31) << 24;
  w[ 8] = int_to_base64 (tmp_u8_32) <<  0
        | int_to_base64 (tmp_u8_33) <<  8
        | int_to_base64 (tmp_u8_34) << 16
        | int_to_base64 (tmp_u8_35) << 24;
  w[ 9] = int_to_base64 (tmp_u8_36) <<  0
        | int_to_base64 (tmp_u8_37) <<  8
        | int_to_base64 (tmp_u8_38) << 16
        | int_to_base64 (tmp_u8_39) << 24;
  w[10] = int_to_base64 (tmp_u8_40) <<  0
        | int_to_base64 (tmp_u8_41) <<  8
        | int_to_base64 (tmp_u8_42) << 16
        | int_to_base64 (tmp_u8_43) << 24;
  w[11] = int_to_base64 (tmp_u8_44) <<  0
        | int_to_base64 (tmp_u8_45) <<  8
        | int_to_base64 (tmp_u8_46) << 16
        | int_to_base64 (tmp_u8_47) << 24;
  w[12] = int_to_base64 (tmp_u8_48) <<  0
        | int_to_base64 (tmp_u8_49) <<  8
        | int_to_base64 (tmp_u8_50) << 16
        | int_to_base64 (tmp_u8_51) << 24;
  w[13] = int_to_base64 (tmp_u8_52) <<  0
        | int_to_base64 (tmp_u8_53) <<  8
        | int_to_base64 (tmp_u8_54) << 16
        | int_to_base64 (tmp_u8_55) << 24;
  w[14] = int_to_base64 (tmp_u8_56) <<  0
        | int_to_base64 (tmp_u8_57) <<  8
        | int_to_base64 (tmp_u8_58) << 16
        | int_to_base64 (tmp_u8_59) << 24;
  w[15] = int_to_base64 (tmp_u8_60) <<  0
        | int_to_base64 (tmp_u8_61) <<  8
        | int_to_base64 (tmp_u8_62) << 16
        | int_to_base64 (tmp_u8_63) << 24;

  u32 E[18] = { 0 };

  expand_key (E, w, 64);

  E[ 0] = hc_swap32_S (E[ 0]);
  E[ 1] = hc_swap32_S (E[ 1]);
  E[ 2] = hc_swap32_S (E[ 2]);
  E[ 3] = hc_swap32_S (E[ 3]);
  E[ 4] = hc_swap32_S (E[ 4]);
  E[ 5] = hc_swap32_S (E[ 5]);
  E[ 6] = hc_swap32_S (E[ 6]);
  E[ 7] = hc_swap32_S (E[ 7]);
  E[ 8] = hc_swap32_S (E[ 8]);
  E[ 9] = hc_swap32_S (E[ 9]);
  E[10] = hc_swap32_S (E[10]);
  E[11] = hc_swap32_S (E[11]);
  E[12] = hc_swap32_S (E[12]);
  E[13] = hc_swap32_S (E[13]);
  E[14] = hc_swap32_S (E[14]);
  E[15] = hc_swap32_S (E[15]);
  E[16] = hc_swap32_S (E[16]);
  E[17] = hc_swap32_S (E[17]);

  for (u32 i = 0; i < 18; i++)
  {
    tmps[gid].E[i] = E[i];
  }

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  u32 P[18];

  blowfish_set_key_salt (E, 18, salt_buf, P, S0, S1, S2, S3);

  // store

  for (u32 i = 0; i < 18; i++)
  {
    tmps[gid].P[i] = P[i];
  }

  for (u32 i = 0; i < 256; i++)
  {
    tmps[gid].S0[i] = GET_KEY32 (S0, i);
    tmps[gid].S1[i] = GET_KEY32 (S1, i);
    tmps[gid].S2[i] = GET_KEY32 (S2, i);
    tmps[gid].S3[i] = GET_KEY32 (S3, i);
  }
}

KERNEL_FQ KERNEL_FA void m35500_loop (KERN_ATTR_TMPS (bcrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  // load

  u32 E[18];

  for (u32 i = 0; i < 18; i++)
  {
    E[i] = tmps[gid].E[i];
  }

  u32 P[18];

  for (u32 i = 0; i < 18; i++)
  {
    P[i] = tmps[gid].P[i];
  }

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  for (u32 i = 0; i < 256; i++)
  {
    SET_KEY32 (S0, i, tmps[gid].S0[i]);
    SET_KEY32 (S1, i, tmps[gid].S1[i]);
    SET_KEY32 (S2, i, tmps[gid].S2[i]);
    SET_KEY32 (S3, i, tmps[gid].S3[i]);
  }

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  /**
   * main loop
   */

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (u32 i = 0; i < 18; i++)
    {
      P[i] ^= E[i];
    }

    blowfish_encrypt (P, S0, S1, S2, S3);

    P[ 0] ^= salt_buf[0];
    P[ 1] ^= salt_buf[1];
    P[ 2] ^= salt_buf[2];
    P[ 3] ^= salt_buf[3];
    P[ 4] ^= salt_buf[0];
    P[ 5] ^= salt_buf[1];
    P[ 6] ^= salt_buf[2];
    P[ 7] ^= salt_buf[3];
    P[ 8] ^= salt_buf[0];
    P[ 9] ^= salt_buf[1];
    P[10] ^= salt_buf[2];
    P[11] ^= salt_buf[3];
    P[12] ^= salt_buf[0];
    P[13] ^= salt_buf[1];
    P[14] ^= salt_buf[2];
    P[15] ^= salt_buf[3];
    P[16] ^= salt_buf[0];
    P[17] ^= salt_buf[1];

    blowfish_encrypt (P, S0, S1, S2, S3);
  }

  // store

  for (u32 i = 0; i < 18; i++)
  {
    tmps[gid].P[i] = P[i];
  }

  for (u32 i = 0; i < 256; i++)
  {
    tmps[gid].S0[i] = GET_KEY32 (S0, i);
    tmps[gid].S1[i] = GET_KEY32 (S1, i);
    tmps[gid].S2[i] = GET_KEY32 (S2, i);
    tmps[gid].S3[i] = GET_KEY32 (S3, i);
  }
}

KERNEL_FQ KERNEL_FA void m35500_comp (KERN_ATTR_TMPS (bcrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  // load

  u32 P[18];

  for (u32 i = 0; i < 18; i++)
  {
    P[i] = tmps[gid].P[i];
  }

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  for (u32 i = 0; i < 256; i++)
  {
    SET_KEY32 (S0, i, tmps[gid].S0[i]);
    SET_KEY32 (S1, i, tmps[gid].S1[i]);
    SET_KEY32 (S2, i, tmps[gid].S2[i]);
    SET_KEY32 (S3, i, tmps[gid].S3[i]);
  }

  /**
   * main
   */

  u32 L0;
  u32 R0;

  L0 = BCRYPTM_0;
  R0 = BCRYPTM_1;

  for (u32 i = 0; i < 64; i++)
  {
    BF_ENCRYPT (L0, R0);
  }

  const u32 r0 = L0;
  const u32 r1 = R0;

  L0 = BCRYPTM_2;
  R0 = BCRYPTM_3;

  for (u32 i = 0; i < 64; i++)
  {
    BF_ENCRYPT (L0, R0);
  }

  const u32 r2 = L0;
  const u32 r3 = R0;

  /*
  e = L0;
  f = R0;

  f &= ~0xff; // its just 23 not 24 !
  */

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
