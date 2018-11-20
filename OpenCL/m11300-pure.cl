/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"

DECLSPEC void hmac_sha512_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, u64x *ipad, u64x *opad, u64x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
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
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

__kernel void m11300_init (KERN_ATTR_TMPS_ESALT (bitcoin_wallet_tmp_t, bitcoin_wallet_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha512_update_global_swap (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha512_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
  tmps[gid].dgst[5] = ctx.h[5];
  tmps[gid].dgst[6] = ctx.h[6];
  tmps[gid].dgst[7] = ctx.h[7];
}

__kernel void m11300_loop (KERN_ATTR_TMPS_ESALT (bitcoin_wallet_tmp_t, bitcoin_wallet_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x t0 = pack64v (tmps, dgst, gid, 0);
  u64x t1 = pack64v (tmps, dgst, gid, 1);
  u64x t2 = pack64v (tmps, dgst, gid, 2);
  u64x t3 = pack64v (tmps, dgst, gid, 3);
  u64x t4 = pack64v (tmps, dgst, gid, 4);
  u64x t5 = pack64v (tmps, dgst, gid, 5);
  u64x t6 = pack64v (tmps, dgst, gid, 6);
  u64x t7 = pack64v (tmps, dgst, gid, 7);

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
  w4[0] = 0x80000000;
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
  w7[3] = 64 * 8;

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    w0[0] = h32_from_64 (t0);
    w0[1] = l32_from_64 (t0);
    w0[2] = h32_from_64 (t1);
    w0[3] = l32_from_64 (t1);
    w1[0] = h32_from_64 (t2);
    w1[1] = l32_from_64 (t2);
    w1[2] = h32_from_64 (t3);
    w1[3] = l32_from_64 (t3);
    w2[0] = h32_from_64 (t4);
    w2[1] = l32_from_64 (t4);
    w2[2] = h32_from_64 (t5);
    w2[3] = l32_from_64 (t5);
    w3[0] = h32_from_64 (t6);
    w3[1] = l32_from_64 (t6);
    w3[2] = h32_from_64 (t7);
    w3[3] = l32_from_64 (t7);

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

  unpack64v (tmps, dgst, gid, 0, t0);
  unpack64v (tmps, dgst, gid, 1, t1);
  unpack64v (tmps, dgst, gid, 2, t2);
  unpack64v (tmps, dgst, gid, 3, t3);
  unpack64v (tmps, dgst, gid, 4, t4);
  unpack64v (tmps, dgst, gid, 5, t5);
  unpack64v (tmps, dgst, gid, 6, t6);
  unpack64v (tmps, dgst, gid, 7, t7);
}

__kernel void m11300_comp (KERN_ATTR_TMPS_ESALT (bitcoin_wallet_tmp_t, bitcoin_wallet_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /**
   * real code
   */

  u64 dgst[8];

  dgst[0] = tmps[gid].dgst[0];
  dgst[1] = tmps[gid].dgst[1];
  dgst[2] = tmps[gid].dgst[2];
  dgst[3] = tmps[gid].dgst[3];
  dgst[4] = tmps[gid].dgst[4];
  dgst[5] = tmps[gid].dgst[5];
  dgst[6] = tmps[gid].dgst[6];
  dgst[7] = tmps[gid].dgst[7];

  u32 key[8];

  key[0] = h32_from_64_S (dgst[0]);
  key[1] = l32_from_64_S (dgst[0]);
  key[2] = h32_from_64_S (dgst[1]);
  key[3] = l32_from_64_S (dgst[1]);
  key[4] = h32_from_64_S (dgst[2]);
  key[5] = l32_from_64_S (dgst[2]);
  key[6] = h32_from_64_S (dgst[3]);
  key[7] = l32_from_64_S (dgst[3]);

  u32 iv[4];

  iv[0] = h32_from_64_S (dgst[4]);
  iv[1] = l32_from_64_S (dgst[4]);
  iv[2] = h32_from_64_S (dgst[5]);
  iv[3] = l32_from_64_S (dgst[5]);

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 out[4];

  for (u32 i = 0; i < esalt_bufs[digests_offset].cry_master_len; i += 16)
  {
    u32 data[4];

    data[0] = swap32_S (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 0]);
    data[1] = swap32_S (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 1]);
    data[2] = swap32_S (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 2]);
    data[3] = swap32_S (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 3]);

    AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];
  }

  if ((out[0] == 0x10101010)
   && (out[1] == 0x10101010)
   && (out[2] == 0x10101010)
   && (out[3] == 0x10101010))
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0);
    }
  }
}
