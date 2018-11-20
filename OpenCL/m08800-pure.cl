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
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"

DECLSPEC void hmac_sha1_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

__kernel void m08800_init (KERN_ATTR_TMPS_ESALT (androidfde_tmp_t, androidfde_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len & 255);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

__kernel void m08800_loop (KERN_ATTR_TMPS_ESALT (androidfde_tmp_t, androidfde_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  for (u32 i = 0; i < 8; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < loop_cnt; j++)
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
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

__kernel void m08800_comp (KERN_ATTR_TMPS_ESALT (androidfde_tmp_t, androidfde_t))
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
   * aes
   */

  u32 ukey[4];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 data[4];

  data[0] = digests_buf[digests_offset].digest_buf[0];
  data[1] = digests_buf[digests_offset].digest_buf[1];
  data[2] = digests_buf[digests_offset].digest_buf[2];
  data[3] = digests_buf[digests_offset].digest_buf[3];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 iv[4];

  iv[0] = tmps[gid].out[4];
  iv[1] = tmps[gid].out[5];
  iv[2] = tmps[gid].out[6];
  iv[3] = tmps[gid].out[7];

  const u32 a = out[0] ^ iv[0];
  const u32 b = out[1] ^ iv[1];
  const u32 c = out[2] ^ iv[2];
  const u32 d = out[3] ^ iv[3];

  // check for FAT

  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
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

    sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

    sha256_final (&ctx);

    u32 essivhash[8];

    essivhash[0] = ctx.h[0];
    essivhash[1] = ctx.h[1];
    essivhash[2] = ctx.h[2];
    essivhash[3] = ctx.h[3];
    essivhash[4] = ctx.h[4];
    essivhash[5] = ctx.h[5];
    essivhash[6] = ctx.h[6];
    essivhash[7] = ctx.h[7];

    // 2. generate essiv based on startsector -- each 512 byte is one sector

    AES256_set_encrypt_key (ks, essivhash, s_te0, s_te1, s_te2, s_te3, s_te4);

    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    u32 essiv[4];

    AES256_encrypt (ks, data, essiv, s_te0, s_te1, s_te2, s_te3, s_te4);

    // 3. decrypt real data, xor essiv afterwards

    data[0] = esalt_bufs[digests_offset].data[0];
    data[1] = esalt_bufs[digests_offset].data[1];
    data[2] = esalt_bufs[digests_offset].data[2];
    data[3] = esalt_bufs[digests_offset].data[3];

    iv[0] = essiv[0];
    iv[1] = essiv[1];
    iv[2] = essiv[2];
    iv[3] = essiv[3];

    ukey[0] = a;
    ukey[1] = b;
    ukey[2] = c;
    ukey[3] = d;

    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

    AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 r0 = out[0] ^ iv[0];
    u32 r1 = out[1] ^ iv[1];
    u32 r2 = out[2] ^ iv[2];
    u32 r3 = out[3] ^ iv[3];

    // rotate 3 byte (in fat!)

    r0 = r1 << 8 | r0 >> 24;
    r1 = r2 << 8 | r1 >> 24;

    // MSDOS5.0
    if ((r0 == 0x4f44534d) && (r1 == 0x302e3553))
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0);
      }
    }
  }

  // check for extfs

  {
    // 3. decrypt real data

    ukey[0] = a;
    ukey[1] = b;
    ukey[2] = c;
    ukey[3] = d;

    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 r[16];

    // not needed because of cbc mode -- implementation flaw !!. first 16 byte are not interessting

    r[0] = 0;
    r[1] = 0;
    r[2] = 0;
    r[3] = 0;

    for (u32 i = 4; i < 16; i += 4)
    {
      data[0] = esalt_bufs[digests_offset].data[256 + i + 0];
      data[1] = esalt_bufs[digests_offset].data[256 + i + 1];
      data[2] = esalt_bufs[digests_offset].data[256 + i + 2];
      data[3] = esalt_bufs[digests_offset].data[256 + i + 3];

      iv[0] = esalt_bufs[digests_offset].data[256 + i + 0 - 4];
      iv[1] = esalt_bufs[digests_offset].data[256 + i + 1 - 4];
      iv[2] = esalt_bufs[digests_offset].data[256 + i + 2 - 4];
      iv[3] = esalt_bufs[digests_offset].data[256 + i + 3 - 4];

      AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      r[i + 0] = out[0] ^ iv[0];
      r[i + 1] = out[1] ^ iv[1];
      r[i + 2] = out[2] ^ iv[2];
      r[i + 3] = out[3] ^ iv[3];
    }

    // we need just a few swapped, because we do not access the others
    r[ 5] = swap32_S (r[ 5]);
    r[ 6] = swap32_S (r[ 6]);
    r[14] = swap32_S (r[14]);

    // superblock not on id 0 or 1
    // assumes max block size is 32MiB
    // has EXT2_SUPER_MAGIC

    if ((r[5] < 2) && (r[6] < 16) && ((r[14] & 0xffff) == 0xEF53))
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0);
      }
    }
  }
}
