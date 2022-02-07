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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

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

KERNEL_FQ void m28300_mxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_bin2base64[0x40];

  for (u32 i = lid; i < 0x40; i += lsz)
  {
    s_bin2base64[i] = bin2base64[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_bin2base64 = bin2base64;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha1_final (&ctx);

    u32 h[5];

    h[0] = ctx.h[0];
    h[1] = ctx.h[1];
    h[2] = ctx.h[2];
    h[3] = ctx.h[3];
    h[4] = ctx.h[4];

    #define tmp_u8_00 ((h[0] >> 26) & 0x3f)
    #define tmp_u8_01 ((h[0] >> 20) & 0x3f)
    #define tmp_u8_02 ((h[0] >> 14) & 0x3f)
    #define tmp_u8_03 ((h[0] >>  8) & 0x3f)
    #define tmp_u8_04 ((h[0] >>  2) & 0x3f)
    #define tmp_u8_05 ((h[0] <<  4) & 0x3c) | ((h[1] >> 28) & 0x0f)
    #define tmp_u8_06 ((h[1] >> 22) & 0x3f)
    #define tmp_u8_07 ((h[1] >> 16) & 0x3f)
    #define tmp_u8_08 ((h[1] >> 10) & 0x3f)
    #define tmp_u8_09 ((h[1] >>  4) & 0x3f)
    #define tmp_u8_10 ((h[1] <<  2) & 0x3c) | ((h[2] >> 30) & 0x03)
    #define tmp_u8_11 ((h[2] >> 24) & 0x3f)
    #define tmp_u8_12 ((h[2] >> 18) & 0x3f)
    #define tmp_u8_13 ((h[2] >> 12) & 0x3f)
    #define tmp_u8_14 ((h[2] >>  6) & 0x3f)
    #define tmp_u8_15 ((h[2] >>  0) & 0x3f)
    #define tmp_u8_16 ((h[3] >> 26) & 0x3f)
    #define tmp_u8_17 ((h[3] >> 20) & 0x3f)
    #define tmp_u8_18 ((h[3] >> 14) & 0x3f)
    #define tmp_u8_19 ((h[3] >>  8) & 0x3f)
    #define tmp_u8_20 ((h[3] >>  2) & 0x3f)
    #define tmp_u8_21 ((h[3] <<  4) & 0x3c) | ((h[4] >> 28) & 0x0f)
    #define tmp_u8_22 ((h[4] >> 22) & 0x3f)
    #define tmp_u8_23 ((h[4] >> 16) & 0x3f)
    #define tmp_u8_24 ((h[4] >> 10) & 0x3f)
    #define tmp_u8_25 ((h[4] >>  4) & 0x3f)
    #define tmp_u8_26 ((h[4] <<  2) & 0x3c)

    sha1_init (&ctx);

    ctx.w0[0] = int_to_base64 (tmp_u8_00) << 24
              | int_to_base64 (tmp_u8_01) << 16
              | int_to_base64 (tmp_u8_02) <<  8
              | int_to_base64 (tmp_u8_03) <<  0;
    ctx.w0[1] = int_to_base64 (tmp_u8_04) << 24
              | int_to_base64 (tmp_u8_05) << 16
              | int_to_base64 (tmp_u8_06) <<  8
              | int_to_base64 (tmp_u8_07) <<  0;
    ctx.w0[2] = int_to_base64 (tmp_u8_08) << 24
              | int_to_base64 (tmp_u8_09) << 16
              | int_to_base64 (tmp_u8_10) <<  8
              | int_to_base64 (tmp_u8_11) <<  0;
    ctx.w0[3] = int_to_base64 (tmp_u8_12) << 24
              | int_to_base64 (tmp_u8_13) << 16
              | int_to_base64 (tmp_u8_14) <<  8
              | int_to_base64 (tmp_u8_15) <<  0;
    ctx.w1[0] = int_to_base64 (tmp_u8_16) << 24
              | int_to_base64 (tmp_u8_17) << 16
              | int_to_base64 (tmp_u8_18) <<  8
              | int_to_base64 (tmp_u8_19) <<  0;
    ctx.w1[1] = int_to_base64 (tmp_u8_20) << 24
              | int_to_base64 (tmp_u8_21) << 16
              | int_to_base64 (tmp_u8_22) <<  8
              | int_to_base64 (tmp_u8_23) <<  0;
    ctx.w1[2] = int_to_base64 (tmp_u8_24) << 24
              | int_to_base64 (tmp_u8_25) << 16
              | int_to_base64 (tmp_u8_26) <<  8
              |                       '=' <<  0;

    ctx.len = 28;

    sha1_update (&ctx, s, 152);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28300_sxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_bin2base64[0x40];

  for (u32 i = lid; i < 0x40; i += lsz)
  {
    s_bin2base64[i] = bin2base64[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_bin2base64 = bin2base64;

  #endif

  if (gid >= GID_CNT) return;

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
   * base
   */

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha1_final (&ctx);

    u32 h[5];

    h[0] = ctx.h[0];
    h[1] = ctx.h[1];
    h[2] = ctx.h[2];
    h[3] = ctx.h[3];
    h[4] = ctx.h[4];

    #define tmp_u8_00 ((h[0] >> 26) & 0x3f)
    #define tmp_u8_01 ((h[0] >> 20) & 0x3f)
    #define tmp_u8_02 ((h[0] >> 14) & 0x3f)
    #define tmp_u8_03 ((h[0] >>  8) & 0x3f)
    #define tmp_u8_04 ((h[0] >>  2) & 0x3f)
    #define tmp_u8_05 ((h[0] <<  4) & 0x3c) | ((h[1] >> 28) & 0x0f)
    #define tmp_u8_06 ((h[1] >> 22) & 0x3f)
    #define tmp_u8_07 ((h[1] >> 16) & 0x3f)
    #define tmp_u8_08 ((h[1] >> 10) & 0x3f)
    #define tmp_u8_09 ((h[1] >>  4) & 0x3f)
    #define tmp_u8_10 ((h[1] <<  2) & 0x3c) | ((h[2] >> 30) & 0x03)
    #define tmp_u8_11 ((h[2] >> 24) & 0x3f)
    #define tmp_u8_12 ((h[2] >> 18) & 0x3f)
    #define tmp_u8_13 ((h[2] >> 12) & 0x3f)
    #define tmp_u8_14 ((h[2] >>  6) & 0x3f)
    #define tmp_u8_15 ((h[2] >>  0) & 0x3f)
    #define tmp_u8_16 ((h[3] >> 26) & 0x3f)
    #define tmp_u8_17 ((h[3] >> 20) & 0x3f)
    #define tmp_u8_18 ((h[3] >> 14) & 0x3f)
    #define tmp_u8_19 ((h[3] >>  8) & 0x3f)
    #define tmp_u8_20 ((h[3] >>  2) & 0x3f)
    #define tmp_u8_21 ((h[3] <<  4) & 0x3c) | ((h[4] >> 28) & 0x0f)
    #define tmp_u8_22 ((h[4] >> 22) & 0x3f)
    #define tmp_u8_23 ((h[4] >> 16) & 0x3f)
    #define tmp_u8_24 ((h[4] >> 10) & 0x3f)
    #define tmp_u8_25 ((h[4] >>  4) & 0x3f)
    #define tmp_u8_26 ((h[4] <<  2) & 0x3c)

    sha1_init (&ctx);

    ctx.w0[0] = int_to_base64 (tmp_u8_00) << 24
              | int_to_base64 (tmp_u8_01) << 16
              | int_to_base64 (tmp_u8_02) <<  8
              | int_to_base64 (tmp_u8_03) <<  0;
    ctx.w0[1] = int_to_base64 (tmp_u8_04) << 24
              | int_to_base64 (tmp_u8_05) << 16
              | int_to_base64 (tmp_u8_06) <<  8
              | int_to_base64 (tmp_u8_07) <<  0;
    ctx.w0[2] = int_to_base64 (tmp_u8_08) << 24
              | int_to_base64 (tmp_u8_09) << 16
              | int_to_base64 (tmp_u8_10) <<  8
              | int_to_base64 (tmp_u8_11) <<  0;
    ctx.w0[3] = int_to_base64 (tmp_u8_12) << 24
              | int_to_base64 (tmp_u8_13) << 16
              | int_to_base64 (tmp_u8_14) <<  8
              | int_to_base64 (tmp_u8_15) <<  0;
    ctx.w1[0] = int_to_base64 (tmp_u8_16) << 24
              | int_to_base64 (tmp_u8_17) << 16
              | int_to_base64 (tmp_u8_18) <<  8
              | int_to_base64 (tmp_u8_19) <<  0;
    ctx.w1[1] = int_to_base64 (tmp_u8_20) << 24
              | int_to_base64 (tmp_u8_21) << 16
              | int_to_base64 (tmp_u8_22) <<  8
              | int_to_base64 (tmp_u8_23) <<  0;
    ctx.w1[2] = int_to_base64 (tmp_u8_24) << 24
              | int_to_base64 (tmp_u8_25) << 16
              | int_to_base64 (tmp_u8_26) <<  8
              |                       '=' <<  0;

    ctx.len = 28;

    sha1_update (&ctx, s, 152);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
