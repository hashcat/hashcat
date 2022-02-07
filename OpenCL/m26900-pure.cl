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
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SNMPV3_SALT_MAX             1500
#define SNMPV3_ENGINEID_MAX         34
#define SNMPV3_MSG_AUTH_PARAMS_MAX  32
#define SNMPV3_ROUNDS               1048576
#define SNMPV3_MAX_PW_LENGTH        128

#define SNMPV3_TMP_ELEMS            8192 // 8192 = (256 (max pw length) * SNMPV3_MAX_PW_LENGTH) / sizeof (u32)
#define SNMPV3_HASH_ELEMS           8

#define SNMPV3_MAX_SALT_ELEMS       512 // 512 * 4 = 2048 > 1500, also has to be multiple of SNMPV3_MAX_PW_LENGTH
#define SNMPV3_MAX_ENGINE_ELEMS     32  // 32 * 4 = 128 > 34, also has to be multiple of SNMPV3_MAX_PW_LENGTH
#define SNMPV3_MAX_PNUM_ELEMS       4   // 4 * 4 = 16 > 9

#define SNMPV3_MAX_PW_LENGTH_OPT    32
#define SNMPV3_TMP_ELEMS_OPT        ((SNMPV3_MAX_PW_LENGTH_OPT * SNMPV3_MAX_PW_LENGTH) / 4)
                                    // (32 * 128) / 4 = 1024
                                    // for pw length > 32 we use global memory reads

typedef struct hmac_sha384_tmp
{
  u32 tmp[SNMPV3_TMP_ELEMS];
  u64 h[SNMPV3_HASH_ELEMS];

} hmac_sha384_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_MAX_SALT_ELEMS];
  u32 salt_len;

  u32 engineID_buf[SNMPV3_MAX_ENGINE_ELEMS];
  u32 engineID_len;

  u32 packet_number[SNMPV3_MAX_PNUM_ELEMS];

} snmpv3_t;

KERNEL_FQ void m26900_init (KERN_ATTR_TMPS_ESALT (hmac_sha384_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[128] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  PRIVATE_AS u8 *src_ptr = (PRIVATE_AS u8 *) w;

  // password 128 times, also swapped

  u32 dst_buf[32];

  PRIVATE_AS u8 *dst_ptr = (PRIVATE_AS u8 *) dst_buf;

  int tmp_idx = 0;

  for (int i = 0; i < 128; i++)
  {
    for (u32 j = 0; j < pw_len; j++)
    {
      const int dst_idx = tmp_idx & 127;

      dst_ptr[dst_idx] = src_ptr[j];

      // write to global memory every time 64 byte are written into cache

      if (dst_idx == 127)
      {
        const int tmp_idx4 = (tmp_idx - 127) / 4;

        tmps[gid].tmp[tmp_idx4 +  0] = hc_swap32_S (dst_buf[ 0]);
        tmps[gid].tmp[tmp_idx4 +  1] = hc_swap32_S (dst_buf[ 1]);
        tmps[gid].tmp[tmp_idx4 +  2] = hc_swap32_S (dst_buf[ 2]);
        tmps[gid].tmp[tmp_idx4 +  3] = hc_swap32_S (dst_buf[ 3]);
        tmps[gid].tmp[tmp_idx4 +  4] = hc_swap32_S (dst_buf[ 4]);
        tmps[gid].tmp[tmp_idx4 +  5] = hc_swap32_S (dst_buf[ 5]);
        tmps[gid].tmp[tmp_idx4 +  6] = hc_swap32_S (dst_buf[ 6]);
        tmps[gid].tmp[tmp_idx4 +  7] = hc_swap32_S (dst_buf[ 7]);
        tmps[gid].tmp[tmp_idx4 +  8] = hc_swap32_S (dst_buf[ 8]);
        tmps[gid].tmp[tmp_idx4 +  9] = hc_swap32_S (dst_buf[ 9]);
        tmps[gid].tmp[tmp_idx4 + 10] = hc_swap32_S (dst_buf[10]);
        tmps[gid].tmp[tmp_idx4 + 11] = hc_swap32_S (dst_buf[11]);
        tmps[gid].tmp[tmp_idx4 + 12] = hc_swap32_S (dst_buf[12]);
        tmps[gid].tmp[tmp_idx4 + 13] = hc_swap32_S (dst_buf[13]);
        tmps[gid].tmp[tmp_idx4 + 14] = hc_swap32_S (dst_buf[14]);
        tmps[gid].tmp[tmp_idx4 + 15] = hc_swap32_S (dst_buf[15]);
        tmps[gid].tmp[tmp_idx4 + 16] = hc_swap32_S (dst_buf[16]);
        tmps[gid].tmp[tmp_idx4 + 17] = hc_swap32_S (dst_buf[17]);
        tmps[gid].tmp[tmp_idx4 + 18] = hc_swap32_S (dst_buf[18]);
        tmps[gid].tmp[tmp_idx4 + 19] = hc_swap32_S (dst_buf[19]);
        tmps[gid].tmp[tmp_idx4 + 20] = hc_swap32_S (dst_buf[20]);
        tmps[gid].tmp[tmp_idx4 + 21] = hc_swap32_S (dst_buf[21]);
        tmps[gid].tmp[tmp_idx4 + 22] = hc_swap32_S (dst_buf[22]);
        tmps[gid].tmp[tmp_idx4 + 23] = hc_swap32_S (dst_buf[23]);
        tmps[gid].tmp[tmp_idx4 + 24] = hc_swap32_S (dst_buf[24]);
        tmps[gid].tmp[tmp_idx4 + 25] = hc_swap32_S (dst_buf[25]);
        tmps[gid].tmp[tmp_idx4 + 26] = hc_swap32_S (dst_buf[26]);
        tmps[gid].tmp[tmp_idx4 + 27] = hc_swap32_S (dst_buf[27]);
        tmps[gid].tmp[tmp_idx4 + 28] = hc_swap32_S (dst_buf[28]);
        tmps[gid].tmp[tmp_idx4 + 29] = hc_swap32_S (dst_buf[29]);
        tmps[gid].tmp[tmp_idx4 + 30] = hc_swap32_S (dst_buf[30]);
        tmps[gid].tmp[tmp_idx4 + 31] = hc_swap32_S (dst_buf[31]);
      }

      tmp_idx++;
    }
  }

  // hash

  tmps[gid].h[0] = SHA384M_A;
  tmps[gid].h[1] = SHA384M_B;
  tmps[gid].h[2] = SHA384M_C;
  tmps[gid].h[3] = SHA384M_D;
  tmps[gid].h[4] = SHA384M_E;
  tmps[gid].h[5] = SHA384M_F;
  tmps[gid].h[6] = SHA384M_G;
  tmps[gid].h[7] = SHA384M_H;
}

KERNEL_FQ void m26900_loop (KERN_ATTR_TMPS_ESALT (hmac_sha384_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u64 h[8];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];
  h[5] = tmps[gid].h[5];
  h[6] = tmps[gid].h[6];
  h[7] = tmps[gid].h[7];

  const u32 pw_len = pws[gid].pw_len;

  const int pw_len128 = pw_len * 128;

  if (pw_len <= SNMPV3_MAX_PW_LENGTH_OPT)
  {
    u32 tmp[SNMPV3_TMP_ELEMS_OPT];

    for (int i = 0; i < pw_len128 / 4; i++)
    {
      tmp[i] = tmps[gid].tmp[i];
    }

    for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i += 128, j += 128)
    {
      const int idx = (j % pw_len128) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];
      u32 w4[4];
      u32 w5[4];
      u32 w6[4];
      u32 w7[4];

      w0[0] = tmp[idx +  0];
      w0[1] = tmp[idx +  1];
      w0[2] = tmp[idx +  2];
      w0[3] = tmp[idx +  3];
      w1[0] = tmp[idx +  4];
      w1[1] = tmp[idx +  5];
      w1[2] = tmp[idx +  6];
      w1[3] = tmp[idx +  7];
      w2[0] = tmp[idx +  8];
      w2[1] = tmp[idx +  9];
      w2[2] = tmp[idx + 10];
      w2[3] = tmp[idx + 11];
      w3[0] = tmp[idx + 12];
      w3[1] = tmp[idx + 13];
      w3[2] = tmp[idx + 14];
      w3[3] = tmp[idx + 15];
      w4[0] = tmp[idx + 16];
      w4[1] = tmp[idx + 17];
      w4[2] = tmp[idx + 18];
      w4[3] = tmp[idx + 19];
      w5[0] = tmp[idx + 20];
      w5[1] = tmp[idx + 21];
      w5[2] = tmp[idx + 22];
      w5[3] = tmp[idx + 23];
      w6[0] = tmp[idx + 24];
      w6[1] = tmp[idx + 25];
      w6[2] = tmp[idx + 26];
      w6[3] = tmp[idx + 27];
      w7[0] = tmp[idx + 28];
      w7[1] = tmp[idx + 29];
      w7[2] = tmp[idx + 30];
      w7[3] = tmp[idx + 31];

      sha384_transform (w0, w1, w2, w3, w4, w5, w6, w7, h);
    }
  }
  else
  {
    for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i += 128, j += 128)
    {
      const int idx = (j % pw_len128) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];
      u32 w4[4];
      u32 w5[4];
      u32 w6[4];
      u32 w7[4];

      w0[0] = tmps[gid].tmp[idx +  0];
      w0[1] = tmps[gid].tmp[idx +  1];
      w0[2] = tmps[gid].tmp[idx +  2];
      w0[3] = tmps[gid].tmp[idx +  3];
      w1[0] = tmps[gid].tmp[idx +  4];
      w1[1] = tmps[gid].tmp[idx +  5];
      w1[2] = tmps[gid].tmp[idx +  6];
      w1[3] = tmps[gid].tmp[idx +  7];
      w2[0] = tmps[gid].tmp[idx +  8];
      w2[1] = tmps[gid].tmp[idx +  9];
      w2[2] = tmps[gid].tmp[idx + 10];
      w2[3] = tmps[gid].tmp[idx + 11];
      w3[0] = tmps[gid].tmp[idx + 12];
      w3[1] = tmps[gid].tmp[idx + 13];
      w3[2] = tmps[gid].tmp[idx + 14];
      w3[3] = tmps[gid].tmp[idx + 15];
      w4[0] = tmps[gid].tmp[idx + 16];
      w4[1] = tmps[gid].tmp[idx + 17];
      w4[2] = tmps[gid].tmp[idx + 18];
      w4[3] = tmps[gid].tmp[idx + 19];
      w5[0] = tmps[gid].tmp[idx + 20];
      w5[1] = tmps[gid].tmp[idx + 21];
      w5[2] = tmps[gid].tmp[idx + 22];
      w5[3] = tmps[gid].tmp[idx + 23];
      w6[0] = tmps[gid].tmp[idx + 24];
      w6[1] = tmps[gid].tmp[idx + 25];
      w6[2] = tmps[gid].tmp[idx + 26];
      w6[3] = tmps[gid].tmp[idx + 27];
      w7[0] = tmps[gid].tmp[idx + 28];
      w7[1] = tmps[gid].tmp[idx + 29];
      w7[2] = tmps[gid].tmp[idx + 30];
      w7[3] = tmps[gid].tmp[idx + 31];

      sha384_transform (w0, w1, w2, w3, w4, w5, w6, w7, h);
    }
  }

  tmps[gid].h[0] = h[0];
  tmps[gid].h[1] = h[1];
  tmps[gid].h[2] = h[2];
  tmps[gid].h[3] = h[3];
  tmps[gid].h[4] = h[4];
  tmps[gid].h[5] = h[5];
  tmps[gid].h[6] = h[6];
  tmps[gid].h[7] = h[7];
}

KERNEL_FQ void m26900_comp (KERN_ATTR_TMPS_ESALT (hmac_sha384_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

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
  w3[3] = 0;
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
  w7[3] = 1048576 * 8;

  u64 h[8];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];
  h[5] = tmps[gid].h[5];
  h[6] = tmps[gid].h[6];
  h[7] = tmps[gid].h[7];

  sha384_transform (w0, w1, w2, w3, w4, w5, w6, w7, h);

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  u32 w[32];

  w[ 0] = h32_from_64_S (h[0]);
  w[ 1] = l32_from_64_S (h[0]);
  w[ 2] = h32_from_64_S (h[1]);
  w[ 3] = l32_from_64_S (h[1]);
  w[ 4] = h32_from_64_S (h[2]);
  w[ 5] = l32_from_64_S (h[2]);
  w[ 6] = h32_from_64_S (h[3]);
  w[ 7] = l32_from_64_S (h[3]);
  w[ 8] = h32_from_64_S (h[4]);
  w[ 9] = l32_from_64_S (h[4]);
  w[10] = h32_from_64_S (h[5]);
  w[11] = l32_from_64_S (h[5]);
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;
  w[16] = 0;
  w[17] = 0;
  w[18] = 0;
  w[19] = 0;
  w[20] = 0;
  w[21] = 0;
  w[22] = 0;
  w[23] = 0;
  w[24] = 0;
  w[25] = 0;
  w[26] = 0;
  w[27] = 0;
  w[28] = 0;
  w[29] = 0;
  w[30] = 0;
  w[31] = 0;

  sha384_update (&ctx, w, 48);

  sha384_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_buf, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_len);

  w[ 0] = h32_from_64_S (h[0]);
  w[ 1] = l32_from_64_S (h[0]);
  w[ 2] = h32_from_64_S (h[1]);
  w[ 3] = l32_from_64_S (h[1]);
  w[ 4] = h32_from_64_S (h[2]);
  w[ 5] = l32_from_64_S (h[2]);
  w[ 6] = h32_from_64_S (h[3]);
  w[ 7] = l32_from_64_S (h[3]);
  w[ 8] = h32_from_64_S (h[4]);
  w[ 9] = l32_from_64_S (h[4]);
  w[10] = h32_from_64_S (h[5]);
  w[11] = l32_from_64_S (h[5]);
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;
  w[16] = 0;
  w[17] = 0;
  w[18] = 0;
  w[19] = 0;
  w[20] = 0;
  w[21] = 0;
  w[22] = 0;
  w[23] = 0;
  w[24] = 0;
  w[25] = 0;
  w[26] = 0;
  w[27] = 0;
  w[28] = 0;
  w[29] = 0;
  w[30] = 0;
  w[31] = 0;

  sha384_update (&ctx, w, 48);

  sha384_final (&ctx);

  w[ 0] = h32_from_64_S (ctx.h[0]);
  w[ 1] = l32_from_64_S (ctx.h[0]);
  w[ 2] = h32_from_64_S (ctx.h[1]);
  w[ 3] = l32_from_64_S (ctx.h[1]);
  w[ 4] = h32_from_64_S (ctx.h[2]);
  w[ 5] = l32_from_64_S (ctx.h[2]);
  w[ 6] = h32_from_64_S (ctx.h[3]);
  w[ 7] = l32_from_64_S (ctx.h[3]);
  w[ 8] = h32_from_64_S (ctx.h[4]);
  w[ 9] = l32_from_64_S (ctx.h[4]);
  w[10] = h32_from_64_S (ctx.h[5]);
  w[11] = l32_from_64_S (ctx.h[5]);
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;
  w[16] = 0;
  w[17] = 0;
  w[18] = 0;
  w[19] = 0;
  w[20] = 0;
  w[21] = 0;
  w[22] = 0;
  w[23] = 0;
  w[24] = 0;
  w[25] = 0;
  w[26] = 0;
  w[27] = 0;
  w[28] = 0;
  w[29] = 0;
  w[30] = 0;
  w[31] = 0;

  sha384_hmac_ctx_t hmac_ctx;

  sha384_hmac_init (&hmac_ctx, w, 48);

  sha384_hmac_update_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  sha384_hmac_final (&hmac_ctx);

  const u32 r0 = l32_from_64 (hmac_ctx.opad.h[1]);
  const u32 r1 = h32_from_64 (hmac_ctx.opad.h[1]);
  const u32 r2 = l32_from_64 (hmac_ctx.opad.h[0]);
  const u32 r3 = h32_from_64 (hmac_ctx.opad.h[0]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
