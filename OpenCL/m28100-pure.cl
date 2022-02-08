/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct winhello
{
  // we need a lot of padding here because sha512_update expects them to be multiple of 128

  u32 mk_buf[16];
  u32 mk_buf_pc[8];
  u32 hmac_buf[32];
  u32 blob_buf[256];
  u32 magicv_buf[32];

  int mk_len;
  int hmac_len;
  int blob_len;
  int magicv_len;

} winhello_t;

typedef struct winhello_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} winhello_tmp_t;

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m28100_init (KERN_ATTR_TMPS_ESALT (winhello_tmp_t, winhello_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const int pw_len = pws[gid].pw_len & 127;

  u32 w[128] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  PRIVATE_AS u8 *w_ptr = (PRIVATE_AS u8 *) w;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = pw_len - 1; i >= 0; i--)
  {
    const u8 c = w_ptr[i];

    const u8 c0 = (c >> 0) & 15;
    const u8 c1 = (c >> 4) & 15;

    w_ptr[(i * 4) + 0] = (c1 < 10) ? '0' + c1 : 'A' - 10 + c1;
    w_ptr[(i * 4) + 1] = 0;
    w_ptr[(i * 4) + 2] = (c0 < 10) ? '0' + c0 : 'A' - 10 + c0;
    w_ptr[(i * 4) + 3] = 0;
  }

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, w, pw_len * 4);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    tmps[gid].dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
    tmps[gid].out[i + 5] = tmps[gid].dgst[i + 5];
    tmps[gid].out[i + 6] = tmps[gid].dgst[i + 6];
    tmps[gid].out[i + 7] = tmps[gid].dgst[i + 7];
  }
}

KERNEL_FQ void m28100_loop (KERN_ATTR_TMPS_ESALT (winhello_tmp_t, winhello_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ void m28100_comp (KERN_ATTR_TMPS_ESALT (winhello_tmp_t, winhello_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  u32 w[32];

  w[0] = hc_swap32_S (tmps[gid].out[0]);
  w[1] = hc_swap32_S (tmps[gid].out[1]);
  w[2] = hc_swap32_S (tmps[gid].out[2]);
  w[3] = hc_swap32_S (tmps[gid].out[3]);
  w[4] = hc_swap32_S (tmps[gid].out[4]);
  w[5] = hc_swap32_S (tmps[gid].out[5]);
  w[6] = hc_swap32_S (tmps[gid].out[6]);
  w[7] = hc_swap32_S (tmps[gid].out[7]);

  PRIVATE_AS u8 *w_ptr = (PRIVATE_AS u8 *) w;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 31; i >= 0; i--)
  {
    const u8 c = w_ptr[i];

    const u8 c0 = (c >> 0) & 15;
    const u8 c1 = (c >> 4) & 15;

    w_ptr[(i * 4) + 0] = (c1 < 10) ? '0' + c1 : 'A' - 10 + c1;
    w_ptr[(i * 4) + 1] = 0;
    w_ptr[(i * 4) + 2] = (c0 < 10) ? '0' + c0 : 'A' - 10 + c0;
    w_ptr[(i * 4) + 3] = 0;
  }

  sha512_ctx_t ctx1;

  sha512_init (&ctx1);

  sha512_update_swap (&ctx1, w, 128);

  sha512_final (&ctx1);

  u32 stage4_sha512[32] = { 0 };

  stage4_sha512[ 0] = h32_from_64_S (ctx1.h[0]);
  stage4_sha512[ 1] = l32_from_64_S (ctx1.h[0]);
  stage4_sha512[ 2] = h32_from_64_S (ctx1.h[1]);
  stage4_sha512[ 3] = l32_from_64_S (ctx1.h[1]);
  stage4_sha512[ 4] = h32_from_64_S (ctx1.h[2]);
  stage4_sha512[ 5] = l32_from_64_S (ctx1.h[2]);
  stage4_sha512[ 6] = h32_from_64_S (ctx1.h[3]);
  stage4_sha512[ 7] = l32_from_64_S (ctx1.h[3]);
  stage4_sha512[ 8] = h32_from_64_S (ctx1.h[4]);
  stage4_sha512[ 9] = l32_from_64_S (ctx1.h[4]);
  stage4_sha512[10] = h32_from_64_S (ctx1.h[5]);
  stage4_sha512[11] = l32_from_64_S (ctx1.h[5]);
  stage4_sha512[12] = h32_from_64_S (ctx1.h[6]);
  stage4_sha512[13] = l32_from_64_S (ctx1.h[6]);
  stage4_sha512[14] = h32_from_64_S (ctx1.h[7]);
  stage4_sha512[15] = l32_from_64_S (ctx1.h[7]);

  // stage4_sha512 ready in ctx.h[]

  u32 sub_digest_seed[32];

  for (int i = 0; i < 32; i++) sub_digest_seed[i] = 0x36363636;

  sub_digest_seed[0] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[0];
  sub_digest_seed[1] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[1];
  sub_digest_seed[2] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[2];
  sub_digest_seed[3] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[3];
  sub_digest_seed[4] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[4];

  // sub_digest

  sha512_ctx_t ctx2;

  sha512_init (&ctx2);

  sha512_update        (&ctx2, sub_digest_seed, 128);
  sha512_update_global (&ctx2, esalt_bufs[DIGESTS_OFFSET_HOST].hmac_buf,
                               esalt_bufs[DIGESTS_OFFSET_HOST].hmac_len);
  sha512_update_global (&ctx2, esalt_bufs[DIGESTS_OFFSET_HOST].magicv_buf,
                               esalt_bufs[DIGESTS_OFFSET_HOST].magicv_len);
  sha512_update        (&ctx2, stage4_sha512, 64);
  sha512_update_global (&ctx2, esalt_bufs[DIGESTS_OFFSET_HOST].blob_buf,
                               esalt_bufs[DIGESTS_OFFSET_HOST].blob_len);

  sha512_final (&ctx2);

  u32 sub_digest[32] = { 0 };

  sub_digest[ 0] = h32_from_64_S (ctx2.h[0]);
  sub_digest[ 1] = l32_from_64_S (ctx2.h[0]);
  sub_digest[ 2] = h32_from_64_S (ctx2.h[1]);
  sub_digest[ 3] = l32_from_64_S (ctx2.h[1]);
  sub_digest[ 4] = h32_from_64_S (ctx2.h[2]);
  sub_digest[ 5] = l32_from_64_S (ctx2.h[2]);
  sub_digest[ 6] = h32_from_64_S (ctx2.h[3]);
  sub_digest[ 7] = l32_from_64_S (ctx2.h[3]);
  sub_digest[ 8] = h32_from_64_S (ctx2.h[4]);
  sub_digest[ 9] = l32_from_64_S (ctx2.h[4]);
  sub_digest[10] = h32_from_64_S (ctx2.h[5]);
  sub_digest[11] = l32_from_64_S (ctx2.h[5]);
  sub_digest[12] = h32_from_64_S (ctx2.h[6]);
  sub_digest[13] = l32_from_64_S (ctx2.h[6]);
  sub_digest[14] = h32_from_64_S (ctx2.h[7]);
  sub_digest[15] = l32_from_64_S (ctx2.h[7]);

  // main_digest_seed

  u32 main_digest_seed[32];

  for (int i = 0; i < 32; i++) main_digest_seed[i] = 0x5c5c5c5c;

  main_digest_seed[0] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[0];
  main_digest_seed[1] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[1];
  main_digest_seed[2] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[2];
  main_digest_seed[3] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[3];
  main_digest_seed[4] ^= esalt_bufs[DIGESTS_OFFSET_HOST].mk_buf_pc[4];

  // main_digest

  sha512_ctx_t ctx3;

  sha512_init (&ctx3);

  sha512_update (&ctx3, main_digest_seed, 128);
  sha512_update (&ctx3, sub_digest, 64);

  sha512_final (&ctx3);

  const u32 r0 = l32_from_64_S (ctx3.h[0]);
  const u32 r1 = h32_from_64_S (ctx3.h[0]);
  const u32 r2 = l32_from_64_S (ctx3.h[1]);
  const u32 r3 = h32_from_64_S (ctx3.h[1]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
