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
#include "inc_hash_sha1.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__kernel void m09400_init (KERN_ATTR_TMPS_ESALT (office2007_tmp_t, office2007_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha1_final (&ctx);

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
}

__kernel void m09400_loop (KERN_ATTR_TMPS_ESALT (office2007_tmp_t, office2007_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x t0 = packv (tmps, out, gid, 0);
  u32x t1 = packv (tmps, out, gid, 1);
  u32x t2 = packv (tmps, out, gid, 2);
  u32x t3 = packv (tmps, out, gid, 3);
  u32x t4 = packv (tmps, out, gid, 4);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = 0;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (4 + 20) * 8;

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    w0[0] = swap32 (j);
    w0[1] = t0;
    w0[2] = t1;
    w0[3] = t2;
    w1[0] = t3;
    w1[1] = t4;

    u32x digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
  }

  unpackv (tmps, out, gid, 0, t0);
  unpackv (tmps, out, gid, 1, t1);
  unpackv (tmps, out, gid, 2, t2);
  unpackv (tmps, out, gid, 3, t3);
  unpackv (tmps, out, gid, 4, t4);
}

__kernel void m09400_comp (KERN_ATTR_TMPS_ESALT (office2007_tmp_t, office2007_t))
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
   * base
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = tmps[gid].out[0];
  w0[1] = tmps[gid].out[1];
  w0[2] = tmps[gid].out[2];
  w0[3] = tmps[gid].out[3];
  w1[0] = tmps[gid].out[4];
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

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 4);

  sha1_final (&ctx);

  u32 digest_common[5];

  digest_common[0] = ctx.h[0];
  digest_common[1] = ctx.h[1];
  digest_common[2] = ctx.h[2];
  digest_common[3] = ctx.h[3];
  digest_common[4] = ctx.h[4];

  w0[0] = 0x36363636 ^ digest_common[0];
  w0[1] = 0x36363636 ^ digest_common[1];
  w0[2] = 0x36363636 ^ digest_common[2];
  w0[3] = 0x36363636 ^ digest_common[3];
  w1[0] = 0x36363636 ^ digest_common[4];
  w1[1] = 0x36363636;
  w1[2] = 0x36363636;
  w1[3] = 0x36363636;
  w2[0] = 0x36363636;
  w2[1] = 0x36363636;
  w2[2] = 0x36363636;
  w2[3] = 0x36363636;
  w3[0] = 0x36363636;
  w3[1] = 0x36363636;
  w3[2] = 0x36363636;
  w3[3] = 0x36363636;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_final (&ctx);

  u32 digest_saved[5];

  digest_saved[0] = ctx.h[0];
  digest_saved[1] = ctx.h[1];
  digest_saved[2] = ctx.h[2];
  digest_saved[3] = ctx.h[3];
  digest_saved[4] = ctx.h[4];

  // now we got the AES key, decrypt the verifier

  u32 ukey[8];

  ukey[0] = digest_saved[0];
  ukey[1] = digest_saved[1];
  ukey[2] = digest_saved[2];
  ukey[3] = digest_saved[3];

  u32 ks[60];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 verifier[4];

  verifier[0] = esalt_bufs[digests_offset].encryptedVerifier[0];
  verifier[1] = esalt_bufs[digests_offset].encryptedVerifier[1];
  verifier[2] = esalt_bufs[digests_offset].encryptedVerifier[2];
  verifier[3] = esalt_bufs[digests_offset].encryptedVerifier[3];

  u32 data[4];

  data[0] = verifier[0];
  data[1] = verifier[1];
  data[2] = verifier[2];
  data[3] = verifier[3];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  // do a sha1 of the result

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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // encrypt it again for verify

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4);

  data[0] = ctx.h[0];
  data[1] = ctx.h[1];
  data[2] = ctx.h[2];
  data[3] = ctx.h[3];

  AES128_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  {
    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #define il_pos 0

    #include COMPARE_M
  }

  /*
   * AES-256 test
   */

  // try same procedure but with AES-256

  w0[0] = 0x5c5c5c5c ^ digest_common[0];
  w0[1] = 0x5c5c5c5c ^ digest_common[1];
  w0[2] = 0x5c5c5c5c ^ digest_common[2];
  w0[3] = 0x5c5c5c5c ^ digest_common[3];
  w1[0] = 0x5c5c5c5c ^ digest_common[4];
  w1[1] = 0x5c5c5c5c;
  w1[2] = 0x5c5c5c5c;
  w1[3] = 0x5c5c5c5c;
  w2[0] = 0x5c5c5c5c;
  w2[1] = 0x5c5c5c5c;
  w2[2] = 0x5c5c5c5c;
  w2[3] = 0x5c5c5c5c;
  w3[0] = 0x5c5c5c5c;
  w3[1] = 0x5c5c5c5c;
  w3[2] = 0x5c5c5c5c;
  w3[3] = 0x5c5c5c5c;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_final (&ctx);

  // now we got the AES key, decrypt the verifier

  ukey[0] = digest_saved[0];
  ukey[1] = digest_saved[1];
  ukey[2] = digest_saved[2];
  ukey[3] = digest_saved[3];
  ukey[4] = digest_saved[4];
  ukey[5] = ctx.h[0];
  ukey[6] = ctx.h[1];
  ukey[7] = ctx.h[2];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  data[0] = verifier[0];
  data[1] = verifier[1];
  data[2] = verifier[2];
  data[3] = verifier[3];

  AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  // do a sha1 of the result

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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // encrypt it again for verify

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4);

  data[0] = ctx.h[0];
  data[1] = ctx.h[1];
  data[2] = ctx.h[2];
  data[3] = ctx.h[3];

  AES256_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  {
    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #define il_pos 0

    #include COMPARE_M
  }
}
