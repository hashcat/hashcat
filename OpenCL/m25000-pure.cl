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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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
#define SNMPV3_HASH_ELEMS_MD5       4
#define SNMPV3_HASH_ELEMS_SHA1      8 // 8 = aligned 5

#define SNMPV3_MAX_SALT_ELEMS       512 // 512 * 4 = 2048 > 1500, also has to be multiple of 64
#define SNMPV3_MAX_ENGINE_ELEMS     16  // 16 * 4 = 64 > 32, also has to be multiple of 64
#define SNMPV3_MAX_PNUM_ELEMS       4   // 4 * 4 = 16 > 9

#define SNMPV3_MAX_PW_LENGTH_OPT    64
#define SNMPV3_TMP_ELEMS_OPT        ((SNMPV3_MAX_PW_LENGTH_OPT * SNMPV3_MAX_PW_LENGTH) / 4)
                                    // (64 * 64) / 4 = 1024
                                    // for pw length > 64 we use global memory reads

typedef struct hmac_md5_tmp
{
  u32 tmp_md5[SNMPV3_TMP_ELEMS];
  u32 tmp_sha1[SNMPV3_TMP_ELEMS];

  u32 h_md5[SNMPV3_HASH_ELEMS_MD5];
  u32 h_sha1[SNMPV3_HASH_ELEMS_SHA1];

} hmac_md5_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_MAX_SALT_ELEMS];
  u32 salt_len;

  u32 engineID_buf[SNMPV3_MAX_ENGINE_ELEMS];
  u32 engineID_len;

  u32 packet_number[SNMPV3_MAX_PNUM_ELEMS];

} snmpv3_t;

KERNEL_FQ void m25000_init (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
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

        // md5

        tmps[gid].tmp_md5[tmp_idx4 +  0] = dst_buf[ 0];
        tmps[gid].tmp_md5[tmp_idx4 +  1] = dst_buf[ 1];
        tmps[gid].tmp_md5[tmp_idx4 +  2] = dst_buf[ 2];
        tmps[gid].tmp_md5[tmp_idx4 +  3] = dst_buf[ 3];
        tmps[gid].tmp_md5[tmp_idx4 +  4] = dst_buf[ 4];
        tmps[gid].tmp_md5[tmp_idx4 +  5] = dst_buf[ 5];
        tmps[gid].tmp_md5[tmp_idx4 +  6] = dst_buf[ 6];
        tmps[gid].tmp_md5[tmp_idx4 +  7] = dst_buf[ 7];
        tmps[gid].tmp_md5[tmp_idx4 +  8] = dst_buf[ 8];
        tmps[gid].tmp_md5[tmp_idx4 +  9] = dst_buf[ 9];
        tmps[gid].tmp_md5[tmp_idx4 + 10] = dst_buf[10];
        tmps[gid].tmp_md5[tmp_idx4 + 11] = dst_buf[11];
        tmps[gid].tmp_md5[tmp_idx4 + 12] = dst_buf[12];
        tmps[gid].tmp_md5[tmp_idx4 + 13] = dst_buf[13];
        tmps[gid].tmp_md5[tmp_idx4 + 14] = dst_buf[14];
        tmps[gid].tmp_md5[tmp_idx4 + 15] = dst_buf[15];

        // sha1

        tmps[gid].tmp_sha1[tmp_idx4 +  0] = hc_swap32_S (dst_buf[ 0]);
        tmps[gid].tmp_sha1[tmp_idx4 +  1] = hc_swap32_S (dst_buf[ 1]);
        tmps[gid].tmp_sha1[tmp_idx4 +  2] = hc_swap32_S (dst_buf[ 2]);
        tmps[gid].tmp_sha1[tmp_idx4 +  3] = hc_swap32_S (dst_buf[ 3]);
        tmps[gid].tmp_sha1[tmp_idx4 +  4] = hc_swap32_S (dst_buf[ 4]);
        tmps[gid].tmp_sha1[tmp_idx4 +  5] = hc_swap32_S (dst_buf[ 5]);
        tmps[gid].tmp_sha1[tmp_idx4 +  6] = hc_swap32_S (dst_buf[ 6]);
        tmps[gid].tmp_sha1[tmp_idx4 +  7] = hc_swap32_S (dst_buf[ 7]);
        tmps[gid].tmp_sha1[tmp_idx4 +  8] = hc_swap32_S (dst_buf[ 8]);
        tmps[gid].tmp_sha1[tmp_idx4 +  9] = hc_swap32_S (dst_buf[ 9]);
        tmps[gid].tmp_sha1[tmp_idx4 + 10] = hc_swap32_S (dst_buf[10]);
        tmps[gid].tmp_sha1[tmp_idx4 + 11] = hc_swap32_S (dst_buf[11]);
        tmps[gid].tmp_sha1[tmp_idx4 + 12] = hc_swap32_S (dst_buf[12]);
        tmps[gid].tmp_sha1[tmp_idx4 + 13] = hc_swap32_S (dst_buf[13]);
        tmps[gid].tmp_sha1[tmp_idx4 + 14] = hc_swap32_S (dst_buf[14]);
        tmps[gid].tmp_sha1[tmp_idx4 + 15] = hc_swap32_S (dst_buf[15]);
     }

      tmp_idx++;
    }
  }

  // hash md5

  tmps[gid].h_md5[0] = MD5M_A;
  tmps[gid].h_md5[1] = MD5M_B;
  tmps[gid].h_md5[2] = MD5M_C;
  tmps[gid].h_md5[3] = MD5M_D;

  // hash sha1

  tmps[gid].h_sha1[0] = SHA1M_A;
  tmps[gid].h_sha1[1] = SHA1M_B;
  tmps[gid].h_sha1[2] = SHA1M_C;
  tmps[gid].h_sha1[3] = SHA1M_D;
  tmps[gid].h_sha1[4] = SHA1M_E;
}

KERNEL_FQ void m25000_loop (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 h_md5[4];

  h_md5[0] = tmps[gid].h_md5[0];
  h_md5[1] = tmps[gid].h_md5[1];
  h_md5[2] = tmps[gid].h_md5[2];
  h_md5[3] = tmps[gid].h_md5[3];

  u32 h_sha1[5];

  h_sha1[0] = tmps[gid].h_sha1[0];
  h_sha1[1] = tmps[gid].h_sha1[1];
  h_sha1[2] = tmps[gid].h_sha1[2];
  h_sha1[3] = tmps[gid].h_sha1[3];
  h_sha1[4] = tmps[gid].h_sha1[4];

  const u32 pw_len = pws[gid].pw_len;

  const int pw_len64 = pw_len * 64;

  if (pw_len <= SNMPV3_MAX_PW_LENGTH_OPT)
  {
    u32 tmp_shared[SNMPV3_TMP_ELEMS_OPT];

    // md5

    for (int i = 0; i < pw_len64 / 4; i++)
    {
      tmp_shared[i] = tmps[gid].tmp_md5[i];
    }

    for (int i = 0, j = LOOP_POS; i < LOOP_CNT; i += 64, j += 64)
    {
      const int idx = (j % pw_len64) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = tmp_shared[idx +  0];
      w0[1] = tmp_shared[idx +  1];
      w0[2] = tmp_shared[idx +  2];
      w0[3] = tmp_shared[idx +  3];
      w1[0] = tmp_shared[idx +  4];
      w1[1] = tmp_shared[idx +  5];
      w1[2] = tmp_shared[idx +  6];
      w1[3] = tmp_shared[idx +  7];
      w2[0] = tmp_shared[idx +  8];
      w2[1] = tmp_shared[idx +  9];
      w2[2] = tmp_shared[idx + 10];
      w2[3] = tmp_shared[idx + 11];
      w3[0] = tmp_shared[idx + 12];
      w3[1] = tmp_shared[idx + 13];
      w3[2] = tmp_shared[idx + 14];
      w3[3] = tmp_shared[idx + 15];

      md5_transform (w0, w1, w2, w3, h_md5);
    }

    // sha1

    for (int i = 0; i < pw_len64 / 4; i++)
    {
      tmp_shared[i] = tmps[gid].tmp_sha1[i];
    }

    for (int i = 0, j = LOOP_POS; i < LOOP_CNT; i += 64, j += 64)
    {
      const int idx = (j % pw_len64) / 4; // the optimization trick is to be able to do this

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = tmp_shared[idx +  0];
      w0[1] = tmp_shared[idx +  1];
      w0[2] = tmp_shared[idx +  2];
      w0[3] = tmp_shared[idx +  3];
      w1[0] = tmp_shared[idx +  4];
      w1[1] = tmp_shared[idx +  5];
      w1[2] = tmp_shared[idx +  6];
      w1[3] = tmp_shared[idx +  7];
      w2[0] = tmp_shared[idx +  8];
      w2[1] = tmp_shared[idx +  9];
      w2[2] = tmp_shared[idx + 10];
      w2[3] = tmp_shared[idx + 11];
      w3[0] = tmp_shared[idx + 12];
      w3[1] = tmp_shared[idx + 13];
      w3[2] = tmp_shared[idx + 14];
      w3[3] = tmp_shared[idx + 15];

      sha1_transform (w0, w1, w2, w3, h_sha1);
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

      // md5

      w0[0] = tmps[gid].tmp_md5[idx +  0];
      w0[1] = tmps[gid].tmp_md5[idx +  1];
      w0[2] = tmps[gid].tmp_md5[idx +  2];
      w0[3] = tmps[gid].tmp_md5[idx +  3];
      w1[0] = tmps[gid].tmp_md5[idx +  4];
      w1[1] = tmps[gid].tmp_md5[idx +  5];
      w1[2] = tmps[gid].tmp_md5[idx +  6];
      w1[3] = tmps[gid].tmp_md5[idx +  7];
      w2[0] = tmps[gid].tmp_md5[idx +  8];
      w2[1] = tmps[gid].tmp_md5[idx +  9];
      w2[2] = tmps[gid].tmp_md5[idx + 10];
      w2[3] = tmps[gid].tmp_md5[idx + 11];
      w3[0] = tmps[gid].tmp_md5[idx + 12];
      w3[1] = tmps[gid].tmp_md5[idx + 13];
      w3[2] = tmps[gid].tmp_md5[idx + 14];
      w3[3] = tmps[gid].tmp_md5[idx + 15];

      md5_transform (w0, w1, w2, w3, h_md5);

      // sha1

      w0[0] = tmps[gid].tmp_sha1[idx +  0];
      w0[1] = tmps[gid].tmp_sha1[idx +  1];
      w0[2] = tmps[gid].tmp_sha1[idx +  2];
      w0[3] = tmps[gid].tmp_sha1[idx +  3];
      w1[0] = tmps[gid].tmp_sha1[idx +  4];
      w1[1] = tmps[gid].tmp_sha1[idx +  5];
      w1[2] = tmps[gid].tmp_sha1[idx +  6];
      w1[3] = tmps[gid].tmp_sha1[idx +  7];
      w2[0] = tmps[gid].tmp_sha1[idx +  8];
      w2[1] = tmps[gid].tmp_sha1[idx +  9];
      w2[2] = tmps[gid].tmp_sha1[idx + 10];
      w2[3] = tmps[gid].tmp_sha1[idx + 11];
      w3[0] = tmps[gid].tmp_sha1[idx + 12];
      w3[1] = tmps[gid].tmp_sha1[idx + 13];
      w3[2] = tmps[gid].tmp_sha1[idx + 14];
      w3[3] = tmps[gid].tmp_sha1[idx + 15];

      sha1_transform (w0, w1, w2, w3, h_sha1);
    }
  }

  tmps[gid].h_md5[0] = h_md5[0];
  tmps[gid].h_md5[1] = h_md5[1];
  tmps[gid].h_md5[2] = h_md5[2];
  tmps[gid].h_md5[3] = h_md5[3];

  tmps[gid].h_sha1[0] = h_sha1[0];
  tmps[gid].h_sha1[1] = h_sha1[1];
  tmps[gid].h_sha1[2] = h_sha1[2];
  tmps[gid].h_sha1[3] = h_sha1[3];
  tmps[gid].h_sha1[4] = h_sha1[4];
}

KERNEL_FQ void m25000_comp (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
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

  // md5

  w0[0] = 0x00000080;
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
  w3[2] = 1048576 * 8;
  w3[3] = 0;

  u32 h_md5[4];

  h_md5[0] = tmps[gid].h_md5[0];
  h_md5[1] = tmps[gid].h_md5[1];
  h_md5[2] = tmps[gid].h_md5[2];
  h_md5[3] = tmps[gid].h_md5[3];

  md5_transform (w0, w1, w2, w3, h_md5);

  // sha1

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

  u32 h_sha1[5];

  h_sha1[0] = tmps[gid].h_sha1[0];
  h_sha1[1] = tmps[gid].h_sha1[1];
  h_sha1[2] = tmps[gid].h_sha1[2];
  h_sha1[3] = tmps[gid].h_sha1[3];
  h_sha1[4] = tmps[gid].h_sha1[4];

  sha1_transform (w0, w1, w2, w3, h_sha1);

  md5_ctx_t md5_ctx;
  sha1_ctx_t sha1_ctx;

  md5_init (&md5_ctx);
  sha1_init (&sha1_ctx);

  u32 w[16];

  // md5

  w[ 0] = h_md5[0];
  w[ 1] = h_md5[1];
  w[ 2] = h_md5[2];
  w[ 3] = h_md5[3];
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

  md5_update (&md5_ctx, w, 16);

  // sha1

  w[ 0] = h_sha1[0];
  w[ 1] = h_sha1[1];
  w[ 2] = h_sha1[2];
  w[ 3] = h_sha1[3];
  w[ 4] = h_sha1[4];
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

  sha1_update (&sha1_ctx, w, 20);

  // engineID

  md5_update_global (&md5_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_buf, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_len);

  sha1_update_global_swap (&sha1_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_buf, esalt_bufs[DIGESTS_OFFSET_HOST].engineID_len);

  // md5

  w[ 0] = h_md5[0];
  w[ 1] = h_md5[1];
  w[ 2] = h_md5[2];
  w[ 3] = h_md5[3];
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

  md5_update (&md5_ctx, w, 16);

  // sha1

  w[ 0] = h_sha1[0];
  w[ 1] = h_sha1[1];
  w[ 2] = h_sha1[2];
  w[ 3] = h_sha1[3];
  w[ 4] = h_sha1[4];
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

  sha1_update (&sha1_ctx, w, 20);

  md5_final (&md5_ctx);
  sha1_final (&sha1_ctx);

  // md5

  w[ 0] = md5_ctx.h[0];
  w[ 1] = md5_ctx.h[1];
  w[ 2] = md5_ctx.h[2];
  w[ 3] = md5_ctx.h[3];
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

  md5_hmac_ctx_t md5_hmac_ctx;

  md5_hmac_init (&md5_hmac_ctx, w, 16);

  md5_hmac_update_global (&md5_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  md5_hmac_final (&md5_hmac_ctx);

  {
    const u32 r0 = hc_swap32_S (md5_hmac_ctx.opad.h[DGST_R0]);
    const u32 r1 = hc_swap32_S (md5_hmac_ctx.opad.h[DGST_R1]);
    const u32 r2 = hc_swap32_S (md5_hmac_ctx.opad.h[DGST_R2]);
    const u32 r3 = 0;

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }

  // sha1

  w[ 0] = sha1_ctx.h[0];
  w[ 1] = sha1_ctx.h[1];
  w[ 2] = sha1_ctx.h[2];
  w[ 3] = sha1_ctx.h[3];
  w[ 4] = sha1_ctx.h[4];
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

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init (&sha1_hmac_ctx, w, 20);

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  sha1_hmac_final (&sha1_hmac_ctx);

  {
    const u32 r0 = sha1_hmac_ctx.opad.h[DGST_R0];
    const u32 r1 = sha1_hmac_ctx.opad.h[DGST_R1];
    const u32 r2 = sha1_hmac_ctx.opad.h[DGST_R2];
    const u32 r3 = 0;

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
