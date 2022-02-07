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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SNMPV3_SALT_MAX             1500
#define SNMPV3_ENGINEID_MAX         34
#define SNMPV3_MSG_AUTH_PARAMS_LEN  12
#define SNMPV3_ROUNDS               1048576
#define SNMPV3_MAX_PW_LENGTH        64

#define SNMPV3_TMP_ELEMS            4096 // 4096 = (256 (max pw length) * 64) / sizeof (u32)
#define SNMPV3_HASH_ELEMS           8    // 8 = aligned 5

#define SNMPV3_MAX_SALT_ELEMS       512 // 512 * 4 = 2048 > 1500, also has to be multiple of 64
#define SNMPV3_MAX_ENGINE_ELEMS     16  // 16 * 4 = 64 > 32, also has to be multiple of 64
#define SNMPV3_MAX_PNUM_ELEMS       4   // 4 * 4 = 16 > 9

#define SNMPV3_MAX_PW_LENGTH_OPT    64
#define SNMPV3_TMP_ELEMS_OPT        ((SNMPV3_MAX_PW_LENGTH_OPT * SNMPV3_MAX_PW_LENGTH) / 4)
                                    // (64 * 64) / 4 = 1024
                                    // for pw length > 64 we use global memory reads

typedef struct hmac_sha1_tmp
{
  u32 tmp[SNMPV3_TMP_ELEMS];
  u32 h[SNMPV3_HASH_ELEMS];

} hmac_sha1_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_MAX_SALT_ELEMS];
  u32 salt_len;

  u32 engineID_buf[SNMPV3_MAX_ENGINE_ELEMS];
  u32 engineID_len;

  u32 packet_number[SNMPV3_MAX_PNUM_ELEMS];

} snmpv3_t;

KERNEL_FQ void m25200_init (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
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

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  PRIVATE_AS u8 *src_ptr = (PRIVATE_AS u8 *) w;

  // password 64 times, also swapped

  u32 dst_buf[16];

  PRIVATE_AS u8 *dst_ptr = (PRIVATE_AS u8 *) dst_buf;

  int tmp_idx = 0;

  for (int i = 0; i < 64; i++)
  {
    for (int j = 0; j < pw_len; j++)
    {
      const int dst_idx = tmp_idx & 63;

      dst_ptr[dst_idx] = src_ptr[j];

      // write to global memory every time 64 byte are written into cache

      if (dst_idx == 63)
      {
        const int tmp_idx4 = (tmp_idx - 63) / 4;

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
      }

      tmp_idx++;
    }
  }

  // hash

  tmps[gid].h[0] = SHA1M_A;
  tmps[gid].h[1] = SHA1M_B;
  tmps[gid].h[2] = SHA1M_C;
  tmps[gid].h[3] = SHA1M_D;
  tmps[gid].h[4] = SHA1M_E;
}

KERNEL_FQ void m25200_loop (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 h[5];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];

  const u32 pw_len = pws[gid].pw_len;

  const int pw_len64 = pw_len * 64;

  if (pw_len <= SNMPV3_MAX_PW_LENGTH_OPT)
  {
    u32 tmp[SNMPV3_TMP_ELEMS_OPT];

    for (int i = 0; i < pw_len64 / 4; i++)
    {
      tmp[i] = tmps[gid].tmp[i];
    }

    for (int i = 0, j = LOOP_POS; i < LOOP_CNT; i += 64, j += 64)
    {
      const int idx = (j % pw_len64) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

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

      sha1_transform (w0, w1, w2, w3, h);
    }
  }
  else
  {
    for (int i = 0, j = LOOP_POS; i < LOOP_CNT; i += 64, j += 64)
    {
      const int idx = (j % pw_len64) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

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

      sha1_transform (w0, w1, w2, w3, h);
    }
  }

  tmps[gid].h[0] = h[0];
  tmps[gid].h[1] = h[1];
  tmps[gid].h[2] = h[2];
  tmps[gid].h[3] = h[3];
  tmps[gid].h[4] = h[4];
}

KERNEL_FQ void m25200_comp (KERN_ATTR_TMPS_ESALT (hmac_sha1_tmp_t, snmpv3_t))
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
  w3[3] = 1048576 * 8;

  u32 h[5];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];

  sha1_transform (w0, w1, w2, w3, h);

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  u32 w[16];

  w[ 0] = h[0];
  w[ 1] = h[1];
  w[ 2] = h[2];
  w[ 3] = h[3];
  w[ 4] = h[4];
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

  sha1_update (&ctx, w, 20);

  sha1_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_buf, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_len);

  w[ 0] = h[0];
  w[ 1] = h[1];
  w[ 2] = h[2];
  w[ 3] = h[3];
  w[ 4] = h[4];
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

  sha1_update (&ctx, w, 20);

  sha1_final (&ctx);

  w[ 0] = ctx.h[0];
  w[ 1] = ctx.h[1];
  w[ 2] = ctx.h[2];
  w[ 3] = ctx.h[3];
  w[ 4] = ctx.h[4];
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

  sha1_hmac_ctx_t hmac_ctx;

  sha1_hmac_init (&hmac_ctx, w, 20);

  sha1_hmac_update_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  sha1_hmac_final (&hmac_ctx);

  const u32 r0 = hmac_ctx.opad.h[DGST_R0];
  const u32 r1 = hmac_ctx.opad.h[DGST_R1];
  const u32 r2 = hmac_ctx.opad.h[DGST_R2];
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

