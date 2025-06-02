/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SCRYPT_R_MAX 16
#define SCRYPT_P_MAX 16

#define SCRYPT_TMP_SIZE (128ULL * SCRYPT_R_MAX * SCRYPT_P_MAX)
#define SCRYPT_TMP_SIZE4 (SCRYPT_TMP_SIZE / 4)

typedef struct
{
  u32 P[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

KERNEL_FQ void m70100_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

	u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
	u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

	u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0, k = 1; i < x_bytes; i += 32, j += 8, k += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = k;
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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    u32 digest[8];

    digest[0] = sha256_hmac_ctx2.opad.h[0];
    digest[1] = sha256_hmac_ctx2.opad.h[1];
    digest[2] = sha256_hmac_ctx2.opad.h[2];
    digest[3] = sha256_hmac_ctx2.opad.h[3];
    digest[4] = sha256_hmac_ctx2.opad.h[4];
    digest[5] = sha256_hmac_ctx2.opad.h[5];
    digest[6] = sha256_hmac_ctx2.opad.h[6];
    digest[7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].P[j + 0] = hc_swap32_S (digest[0]);
    tmps[gid].P[j + 1] = hc_swap32_S (digest[1]);
    tmps[gid].P[j + 2] = hc_swap32_S (digest[2]);
    tmps[gid].P[j + 3] = hc_swap32_S (digest[3]);
    tmps[gid].P[j + 4] = hc_swap32_S (digest[4]);
    tmps[gid].P[j + 5] = hc_swap32_S (digest[5]);
    tmps[gid].P[j + 6] = hc_swap32_S (digest[6]);
    tmps[gid].P[j + 7] = hc_swap32_S (digest[7]);
  }
}

KERNEL_FQ void m70100_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
}

KERNEL_FQ void m70100_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  /**
   * 2nd pbkdf2, creates B
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

	u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
	u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

	u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0; i < x_bytes; i += 64, j += 16)
  {
    w0[0] = hc_swap32_S (tmps[gid].P[j +  0]);
    w0[1] = hc_swap32_S (tmps[gid].P[j +  1]);
    w0[2] = hc_swap32_S (tmps[gid].P[j +  2]);
    w0[3] = hc_swap32_S (tmps[gid].P[j +  3]);
    w1[0] = hc_swap32_S (tmps[gid].P[j +  4]);
    w1[1] = hc_swap32_S (tmps[gid].P[j +  5]);
    w1[2] = hc_swap32_S (tmps[gid].P[j +  6]);
    w1[3] = hc_swap32_S (tmps[gid].P[j +  7]);
    w2[0] = hc_swap32_S (tmps[gid].P[j +  8]);
    w2[1] = hc_swap32_S (tmps[gid].P[j +  9]);
    w2[2] = hc_swap32_S (tmps[gid].P[j + 10]);
    w2[3] = hc_swap32_S (tmps[gid].P[j + 11]);
    w3[0] = hc_swap32_S (tmps[gid].P[j + 12]);
    w3[1] = hc_swap32_S (tmps[gid].P[j + 13]);
    w3[2] = hc_swap32_S (tmps[gid].P[j + 14]);
    w3[3] = hc_swap32_S (tmps[gid].P[j + 15]);

    sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 1;
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

  sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&ctx);

  const u32 r0 = hc_swap32_S (ctx.opad.h[DGST_R0]);
  const u32 r1 = hc_swap32_S (ctx.opad.h[DGST_R1]);
  const u32 r2 = hc_swap32_S (ctx.opad.h[DGST_R2]);
  const u32 r3 = hc_swap32_S (ctx.opad.h[DGST_R3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
