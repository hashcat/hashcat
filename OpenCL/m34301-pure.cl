
/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

/*
Pseudocode:
1. sha256(sha256(password=masterkey)||keyfile||userkey) = aes_key
2. aes(aes_key, iterations) = aes_out
3. sha256(aes_out) = shaed_aes_out
4. sha512(masterseed||shaed_aes_out||0x01) = final
5. sha512(0xFFFFFFFFFFFFFFFF||final) = out
6. hmac_sha256(init=out, data=header) = header_hmac
7. compare header_hmac to hash
*/

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct keepass4_tmp
{
  u32 tmp_digest[8];

} keepass4_tmp_t;

typedef struct keepass4
{
  u32 masterseed[8];

  u32 header_len;
  u32 header[1024];

  u32 keyfile_len;
  u32 keyfile[8];

  u32 userkey_len;
  u32 userkey[16];

} keepass4_t;


KERNEL_FQ KERNEL_FA void m34301_init (KERN_ATTR_TMPS_ESALT (keepass4_tmp_t, keepass4_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS const keepass4_t *keepass4 = &esalt_bufs[DIGESTS_OFFSET_HOST];

  sha256_ctx_t ctx0;
  sha256_init (&ctx0);
  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
  sha256_final (&ctx0);

  // the composite key: the password digest, then 32 bytes for a key file and 64 bytes for a
  // Windows user account when the database uses those key providers

  u32 w[32] = { 0 };

  w[0] = ctx0.h[0];
  w[1] = ctx0.h[1];
  w[2] = ctx0.h[2];
  w[3] = ctx0.h[3];
  w[4] = ctx0.h[4];
  w[5] = ctx0.h[5];
  w[6] = ctx0.h[6];
  w[7] = ctx0.h[7];

  u32 w_len = 32;

  if (keepass4->keyfile_len)
  {
    for (u32 i = 0; i < 8; i++) w[8 + i] = keepass4->keyfile[i];

    w_len += 32;
  }

  if (keepass4->userkey_len)
  {
    const u32 idx = w_len / 4;

    for (u32 i = 0; i < 16; i++) w[idx + i] = keepass4->userkey[i];

    w_len += 64;
  }

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, w, w_len);

  sha256_final (&ctx);

  tmps[gid].tmp_digest[0] = ctx.h[0];
  tmps[gid].tmp_digest[1] = ctx.h[1];
  tmps[gid].tmp_digest[2] = ctx.h[2];
  tmps[gid].tmp_digest[3] = ctx.h[3];
  tmps[gid].tmp_digest[4] = ctx.h[4];
  tmps[gid].tmp_digest[5] = ctx.h[5];
  tmps[gid].tmp_digest[6] = ctx.h[6];
  tmps[gid].tmp_digest[7] = ctx.h[7];

}

KERNEL_FQ KERNEL_FA void m34301_loop (KERN_ATTR_TMPS_ESALT (keepass4_tmp_t, keepass4_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /* Construct AES key */

  u32 ukey[8];
  ukey[0] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0]);
  ukey[1] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1]);
  ukey[2] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2]);
  ukey[3] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3]);
  ukey[4] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[4]);
  ukey[5] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[5]);
  ukey[6] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[6]);
  ukey[7] = hc_swap32_S(salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[7]);

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 data0[4];
  u32 data1[4];

  data0[0] = tmps[gid].tmp_digest[0];
  data0[1] = tmps[gid].tmp_digest[1];
  data0[2] = tmps[gid].tmp_digest[2];
  data0[3] = tmps[gid].tmp_digest[3];
  data1[0] = tmps[gid].tmp_digest[4];
  data1[1] = tmps[gid].tmp_digest[5];
  data1[2] = tmps[gid].tmp_digest[6];
  data1[3] = tmps[gid].tmp_digest[7];

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    AES256_encrypt (ks, data0, data0, s_te0, s_te1, s_te2, s_te3, s_te4);
    AES256_encrypt (ks, data1, data1, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  tmps[gid].tmp_digest[0] = data0[0];
  tmps[gid].tmp_digest[1] = data0[1];
  tmps[gid].tmp_digest[2] = data0[2];
  tmps[gid].tmp_digest[3] = data0[3];
  tmps[gid].tmp_digest[4] = data1[0];
  tmps[gid].tmp_digest[5] = data1[1];
  tmps[gid].tmp_digest[6] = data1[2];
  tmps[gid].tmp_digest[7] = data1[3];
}

KERNEL_FQ KERNEL_FA void m34301_comp (KERN_ATTR_TMPS_ESALT (keepass4_tmp_t, keepass4_t))
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

  SYNC_THREADS ();

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

  if (gid >= GID_CNT) return;

  u32 tmp_buf[16];
  tmp_buf[0] =   tmps[gid].tmp_digest[0];
  tmp_buf[1] =   tmps[gid].tmp_digest[1];
  tmp_buf[2] =   tmps[gid].tmp_digest[2];
  tmp_buf[3] =   tmps[gid].tmp_digest[3];
  tmp_buf[4] =   tmps[gid].tmp_digest[4];
  tmp_buf[5] =   tmps[gid].tmp_digest[5];
  tmp_buf[6] =   tmps[gid].tmp_digest[6];
  tmp_buf[7] =   tmps[gid].tmp_digest[7];
  tmp_buf[8] =   0;
  tmp_buf[9] =   0;
  tmp_buf[10] =  0;
  tmp_buf[11] =  0;
  tmp_buf[12] =  0;
  tmp_buf[13] =  0;
  tmp_buf[14] =  0;
  tmp_buf[15] =  0;

  sha256_ctx_t ctx0;
  sha256_init (&ctx0);
  sha256_update (&ctx0, tmp_buf, 32);
  sha256_final (&ctx0);

  GLOBAL_AS const keepass4_t *keepass4 = &esalt_bufs[DIGESTS_OFFSET_HOST];

  sha512_ctx_t ctx;
  sha512_init (&ctx);

  ctx.w0[0] = hc_swap32_S (keepass4->masterseed[0]);
  ctx.w0[1] = hc_swap32_S (keepass4->masterseed[1]);
  ctx.w0[2] = hc_swap32_S (keepass4->masterseed[2]);
  ctx.w0[3] = hc_swap32_S (keepass4->masterseed[3]);
  ctx.w1[0] = hc_swap32_S (keepass4->masterseed[4]);
  ctx.w1[1] = hc_swap32_S (keepass4->masterseed[5]);
  ctx.w1[2] = hc_swap32_S (keepass4->masterseed[6]);
  ctx.w1[3] = hc_swap32_S (keepass4->masterseed[7]);
  ctx.w2[0] = ctx0.h[0];
  ctx.w2[1] = ctx0.h[1];
  ctx.w2[2] = ctx0.h[2];
  ctx.w2[3] = ctx0.h[3];
  ctx.w3[0] = ctx0.h[4];
  ctx.w3[1] = ctx0.h[5];
  ctx.w3[2] = ctx0.h[6];
  ctx.w3[3] = ctx0.h[7];
  ctx.w4[0] = 0x01000000;

  ctx.len = 32 + 32 + 1;

  sha512_final (&ctx);

  sha512_ctx_t ctx2;
  sha512_init (&ctx2);

  ctx2.w0[0] = 0xffffffff;
  ctx2.w0[1] = 0xffffffff;
  ctx2.w0[2] = h32_from_64_S (ctx.h[0]);
  ctx2.w0[3] = l32_from_64_S (ctx.h[0]);
  ctx2.w1[0] = h32_from_64_S (ctx.h[1]);
  ctx2.w1[1] = l32_from_64_S (ctx.h[1]);
  ctx2.w1[2] = h32_from_64_S (ctx.h[2]);
  ctx2.w1[3] = l32_from_64_S (ctx.h[2]);
  ctx2.w2[0] = h32_from_64_S (ctx.h[3]);
  ctx2.w2[1] = l32_from_64_S (ctx.h[3]);
  ctx2.w2[2] = h32_from_64_S (ctx.h[4]);
  ctx2.w2[3] = l32_from_64_S (ctx.h[4]);
  ctx2.w3[0] = h32_from_64_S (ctx.h[5]);
  ctx2.w3[1] = l32_from_64_S (ctx.h[5]);
  ctx2.w3[2] = h32_from_64_S (ctx.h[6]);
  ctx2.w3[3] = l32_from_64_S (ctx.h[6]);
  ctx2.w4[0] = h32_from_64_S (ctx.h[7]);
  ctx2.w4[1] = l32_from_64_S (ctx.h[7]);

  ctx2.len = 8 + 64;

  sha512_final (&ctx2);

  u32 outu32[16];

  outu32[ 0] = h32_from_64_S (ctx2.h[0]);
  outu32[ 1] = l32_from_64_S (ctx2.h[0]);
  outu32[ 2] = h32_from_64_S (ctx2.h[1]);
  outu32[ 3] = l32_from_64_S (ctx2.h[1]);
  outu32[ 4] = h32_from_64_S (ctx2.h[2]);
  outu32[ 5] = l32_from_64_S (ctx2.h[2]);
  outu32[ 6] = h32_from_64_S (ctx2.h[3]);
  outu32[ 7] = l32_from_64_S (ctx2.h[3]);
  outu32[ 8] = h32_from_64_S (ctx2.h[4]);
  outu32[ 9] = l32_from_64_S (ctx2.h[4]);
  outu32[10] = h32_from_64_S (ctx2.h[5]);
  outu32[11] = l32_from_64_S (ctx2.h[5]);
  outu32[12] = h32_from_64_S (ctx2.h[6]);
  outu32[13] = l32_from_64_S (ctx2.h[6]);
  outu32[14] = h32_from_64_S (ctx2.h[7]);
  outu32[15] = l32_from_64_S (ctx2.h[7]);

  sha256_hmac_ctx_t ctx3;
  sha256_hmac_init (&ctx3, outu32, 64);
  sha256_hmac_update_global_swap (&ctx3, keepass4->header, keepass4->header_len);
  sha256_hmac_final (&ctx3);

  const u32 r0 = hc_swap32_S (ctx3.opad.h[0]);
  const u32 r1 = hc_swap32_S (ctx3.opad.h[1]);
  const u32 r2 = hc_swap32_S (ctx3.opad.h[2]);
  const u32 r3 = hc_swap32_S (ctx3.opad.h[3]);

  #define il_pos 0

  #include COMPARE_M
}
