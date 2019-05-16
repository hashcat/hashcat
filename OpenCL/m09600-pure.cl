/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct office2013_tmp
{
  u64  out[8];

} office2013_tmp_t;

typedef struct office2013
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2013_t;

KERNEL_FQ void m09600_init (KERN_ATTR_TMPS_ESALT (office2013_tmp_t, office2013_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha512_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_final (&ctx);

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
  tmps[gid].out[5] = ctx.h[5];
  tmps[gid].out[6] = ctx.h[6];
  tmps[gid].out[7] = ctx.h[7];
}

KERNEL_FQ void m09600_loop (KERN_ATTR_TMPS_ESALT (office2013_tmp_t, office2013_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x t0 = pack64v (tmps, out, gid, 0);
  u64x t1 = pack64v (tmps, out, gid, 1);
  u64x t2 = pack64v (tmps, out, gid, 2);
  u64x t3 = pack64v (tmps, out, gid, 3);
  u64x t4 = pack64v (tmps, out, gid, 4);
  u64x t5 = pack64v (tmps, out, gid, 5);
  u64x t6 = pack64v (tmps, out, gid, 6);
  u64x t7 = pack64v (tmps, out, gid, 7);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  w0[0] = 0;
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
  w4[1] = 0x80000000;
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
  w7[3] = (4 + 64) * 8;

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    w0[0] = hc_swap32 (j);
    w0[1] = h32_from_64 (t0);
    w0[2] = l32_from_64 (t0);
    w0[3] = h32_from_64 (t1);
    w1[0] = l32_from_64 (t1);
    w1[1] = h32_from_64 (t2);
    w1[2] = l32_from_64 (t2);
    w1[3] = h32_from_64 (t3);
    w2[0] = l32_from_64 (t3);
    w2[1] = h32_from_64 (t4);
    w2[2] = l32_from_64 (t4);
    w2[3] = h32_from_64 (t5);
    w3[0] = l32_from_64 (t5);
    w3[1] = h32_from_64 (t6);
    w3[2] = l32_from_64 (t6);
    w3[3] = h32_from_64 (t7);
    w4[0] = l32_from_64 (t7);

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
    t6 = digest[6];
    t7 = digest[7];
  }

  unpack64v (tmps, out, gid, 0, t0);
  unpack64v (tmps, out, gid, 1, t1);
  unpack64v (tmps, out, gid, 2, t2);
  unpack64v (tmps, out, gid, 3, t3);
  unpack64v (tmps, out, gid, 4, t4);
  unpack64v (tmps, out, gid, 5, t5);
  unpack64v (tmps, out, gid, 6, t6);
  unpack64v (tmps, out, gid, 7, t7);
}

KERNEL_FQ void m09600_comp (KERN_ATTR_TMPS_ESALT (office2013_tmp_t, office2013_t))
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

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[8];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];
  tmp[6] = tmps[gid].out[6];
  tmp[7] = tmps[gid].out[7];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = h32_from_64_S (tmp[6]);
  w3[1] = l32_from_64_S (tmp[6]);
  w3[2] = h32_from_64_S (tmp[7]);
  w3[3] = l32_from_64_S (tmp[7]);
  w4[0] = encryptedVerifierHashInputBlockKey[0];
  w4[1] = encryptedVerifierHashInputBlockKey[1];
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
  w7[3] = 0;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 + 8);

  sha512_final (&ctx);

  u64 digest0[4];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];
  digest0[3] = ctx.h[3];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = h32_from_64_S (tmp[6]);
  w3[1] = l32_from_64_S (tmp[6]);
  w3[2] = h32_from_64_S (tmp[7]);
  w3[3] = l32_from_64_S (tmp[7]);
  w4[0] = encryptedVerifierHashValueBlockKey[0];
  w4[1] = encryptedVerifierHashValueBlockKey[1];
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
  w7[3] = 0;

  sha512_init (&ctx);

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 + 8);

  sha512_final (&ctx);

  u64 digest1[4];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];
  digest1[3] = ctx.h[3];

  // now we got the AES key, decrypt the verifier

  u32 ukey[8];

  ukey[0] = h32_from_64_S (digest0[0]);
  ukey[1] = l32_from_64_S (digest0[0]);
  ukey[2] = h32_from_64_S (digest0[1]);
  ukey[3] = l32_from_64_S (digest0[1]);
  ukey[4] = h32_from_64_S (digest0[2]);
  ukey[5] = l32_from_64_S (digest0[2]);
  ukey[6] = h32_from_64_S (digest0[3]);
  ukey[7] = l32_from_64_S (digest0[3]);

  u32 ks[60];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  const u32 digest_cur = digests_offset + loop_pos;

  u32 data[4];

  data[0] = esalt_bufs[digest_cur].encryptedVerifier[0];
  data[1] = esalt_bufs[digest_cur].encryptedVerifier[1];
  data[2] = esalt_bufs[digest_cur].encryptedVerifier[2];
  data[3] = esalt_bufs[digest_cur].encryptedVerifier[3];

  u32 out[4];

  AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= salt_bufs[salt_pos].salt_buf[0];
  out[1] ^= salt_bufs[salt_pos].salt_buf[1];
  out[2] ^= salt_bufs[salt_pos].salt_buf[2];
  out[3] ^= salt_bufs[salt_pos].salt_buf[3];

  //  do a sha512 of the result

  w0[0] = out[0];
  w0[1] = out[1];
  w0[2] = out[2];
  w0[3] = out[3];
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
  w7[3] = 0;

  sha512_init (&ctx);

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha512_final (&ctx);

  u64 digest[4];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];

  // encrypt with 2nd key

  ukey[0] = h32_from_64_S (digest1[0]);
  ukey[1] = l32_from_64_S (digest1[0]);
  ukey[2] = h32_from_64_S (digest1[1]);
  ukey[3] = l32_from_64_S (digest1[1]);
  ukey[4] = h32_from_64_S (digest1[2]);
  ukey[5] = l32_from_64_S (digest1[2]);
  ukey[6] = h32_from_64_S (digest1[3]);
  ukey[7] = l32_from_64_S (digest1[3]);

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  data[0] = h32_from_64_S (digest[0]) ^ salt_bufs[salt_pos].salt_buf[0];
  data[1] = l32_from_64_S (digest[0]) ^ salt_bufs[salt_pos].salt_buf[1];
  data[2] = h32_from_64_S (digest[1]) ^ salt_bufs[salt_pos].salt_buf[2];
  data[3] = l32_from_64_S (digest[1]) ^ salt_bufs[salt_pos].salt_buf[3];

  AES256_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
