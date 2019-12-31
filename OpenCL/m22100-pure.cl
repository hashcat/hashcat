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
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

typedef struct bitlocker
{
  u32 type;
  u32 iv[4];
  u32 data[15];

} bitlocker_t;

typedef struct bitlocker_tmp
{
  u32 last_hash[8];
  u32 init_hash[8];
  u32 salt[4];

} bitlocker_tmp_t;

KERNEL_FQ void m22100_init (KERN_ATTR_TMPS_ESALT (bitlocker_tmp_t, bitlocker_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;


  // sha256 of utf16le converted password:

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_utf16le_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  sha256_final (&ctx0);

  u32 w[16] = { 0 }; // 64 bytes blocks/aligned, we need 32 bytes

  w[0] = ctx0.h[0];
  w[1] = ctx0.h[1];
  w[2] = ctx0.h[2];
  w[3] = ctx0.h[3];
  w[4] = ctx0.h[4];
  w[5] = ctx0.h[5];
  w[6] = ctx0.h[6];
  w[7] = ctx0.h[7];


  // sha256 of sha256:

  sha256_ctx_t ctx1;

  sha256_init   (&ctx1);
  sha256_update (&ctx1, w, 32);
  sha256_final  (&ctx1);


  // set tmps:

  tmps[gid].init_hash[0] = ctx1.h[0];
  tmps[gid].init_hash[1] = ctx1.h[1];
  tmps[gid].init_hash[2] = ctx1.h[2];
  tmps[gid].init_hash[3] = ctx1.h[3];
  tmps[gid].init_hash[4] = ctx1.h[4];
  tmps[gid].init_hash[5] = ctx1.h[5];
  tmps[gid].init_hash[6] = ctx1.h[6];
  tmps[gid].init_hash[7] = ctx1.h[7];

  tmps[gid].last_hash[0] = 0;
  tmps[gid].last_hash[1] = 0;
  tmps[gid].last_hash[2] = 0;
  tmps[gid].last_hash[3] = 0;
  tmps[gid].last_hash[4] = 0;
  tmps[gid].last_hash[5] = 0;
  tmps[gid].last_hash[6] = 0;
  tmps[gid].last_hash[7] = 0;

  tmps[gid].salt[0] = salt_bufs[salt_pos].salt_buf[0];
  tmps[gid].salt[1] = salt_bufs[salt_pos].salt_buf[1];
  tmps[gid].salt[2] = salt_bufs[salt_pos].salt_buf[2];
  tmps[gid].salt[3] = salt_bufs[salt_pos].salt_buf[3];
}

KERNEL_FQ void m22100_loop (KERN_ATTR_TMPS_ESALT (bitlocker_tmp_t, bitlocker_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  // init

  u32x w[32] = { 0 }; // 64 bytes blocks/aligned, 88 bytes needed (22 u32 = 22 * 4)

  w[ 0] = packv (tmps, last_hash, gid, 0);
  w[ 1] = packv (tmps, last_hash, gid, 1);
  w[ 2] = packv (tmps, last_hash, gid, 2);
  w[ 3] = packv (tmps, last_hash, gid, 3);
  w[ 4] = packv (tmps, last_hash, gid, 4);
  w[ 5] = packv (tmps, last_hash, gid, 5);
  w[ 6] = packv (tmps, last_hash, gid, 6);
  w[ 7] = packv (tmps, last_hash, gid, 7);

  w[ 8] = packv (tmps, init_hash, gid, 0);
  w[ 9] = packv (tmps, init_hash, gid, 1);
  w[10] = packv (tmps, init_hash, gid, 2);
  w[11] = packv (tmps, init_hash, gid, 3);
  w[12] = packv (tmps, init_hash, gid, 4);
  w[13] = packv (tmps, init_hash, gid, 5);
  w[14] = packv (tmps, init_hash, gid, 6);
  w[15] = packv (tmps, init_hash, gid, 7);

  w[16] = packv (tmps, salt, gid, 0);
  w[17] = packv (tmps, salt, gid, 1);
  w[18] = packv (tmps, salt, gid, 2);
  w[19] = packv (tmps, salt, gid, 3);

  // main loop

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    w[20] = hc_swap32 (j);

    sha256_ctx_vector_t ctx;

    sha256_init_vector   (&ctx);
    sha256_update_vector (&ctx, w, 88);
    sha256_final_vector  (&ctx);

    w[0] = ctx.h[0];
    w[1] = ctx.h[1];
    w[2] = ctx.h[2];
    w[3] = ctx.h[3];
    w[4] = ctx.h[4];
    w[5] = ctx.h[5];
    w[6] = ctx.h[6];
    w[7] = ctx.h[7];
  }

  unpackv (tmps, last_hash, gid, 0, w[0]);
  unpackv (tmps, last_hash, gid, 1, w[1]);
  unpackv (tmps, last_hash, gid, 2, w[2]);
  unpackv (tmps, last_hash, gid, 3, w[3]);
  unpackv (tmps, last_hash, gid, 4, w[4]);
  unpackv (tmps, last_hash, gid, 5, w[5]);
  unpackv (tmps, last_hash, gid, 6, w[6]);
  unpackv (tmps, last_hash, gid, 7, w[7]);
}

KERNEL_FQ void m22100_comp (KERN_ATTR_TMPS_ESALT (bitlocker_tmp_t, bitlocker_t))
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


  /*
   * AES decrypt the data_buf
   */

  // init AES

  u32 ukey[8];

  ukey[0] = tmps[gid].last_hash[0];
  ukey[1] = tmps[gid].last_hash[1];
  ukey[2] = tmps[gid].last_hash[2];
  ukey[3] = tmps[gid].last_hash[3];
  ukey[4] = tmps[gid].last_hash[4];
  ukey[5] = tmps[gid].last_hash[5];
  ukey[6] = tmps[gid].last_hash[6];
  ukey[7] = tmps[gid].last_hash[7];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);


  // decrypt:

  u32 iv[4];

  iv[0] = esalt_bufs[digests_offset].iv[0];
  iv[1] = esalt_bufs[digests_offset].iv[1];
  iv[2] = esalt_bufs[digests_offset].iv[2];
  iv[3] = esalt_bufs[digests_offset].iv[3];


  // in total we've 60 bytes: we need out0 (16 bytes) to out3 (16 bytes) for MAC verification

  // 1

  u32 out1[4];

  AES256_encrypt (ks, iv, out1, s_te0, s_te1, s_te2, s_te3, s_te4);


  // some early reject:

  out1[0] ^= esalt_bufs[digests_offset].data[4]; // skip MAC for now (first 16 bytes)

  if ((out1[0] & 0xffff0000) != 0x2c000000) return; // data_size must be 0x2c00


  out1[1] ^= esalt_bufs[digests_offset].data[5];

  if ((out1[1] & 0xffff0000) != 0x01000000) return; // version must be 0x0100


  out1[2] ^= esalt_bufs[digests_offset].data[6];

  if ((out1[2] & 0x00ff0000) != 0x00200000) return; // v2 must be 0x20


  if ((out1[2] >> 24) > 0x05) return; // v1 must be <= 5



  // if no MAC verification should be performed, we are already done:

  u32 type = esalt_bufs[digests_offset].type;

  if (type == 0)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0, 0, 0);
    }

    return;
  }

  out1[3] ^= esalt_bufs[digests_offset].data[7];


  /*
   * Decrypt the whole data buffer for MAC verification (type == 1):
   */

  // 0

  iv[3] = iv[3] & 0xff000000; // xx000000

  u32 out0[4];

  AES256_encrypt (ks, iv, out0, s_te0, s_te1, s_te2, s_te3, s_te4);

  out0[0] ^= esalt_bufs[digests_offset].data[0];
  out0[1] ^= esalt_bufs[digests_offset].data[1];
  out0[2] ^= esalt_bufs[digests_offset].data[2];
  out0[3] ^= esalt_bufs[digests_offset].data[3];

  // 2

  // add 2 because we already did block 1 for the early reject

  iv[3] += 2; // xx000002

  u32 out2[4];

  AES256_encrypt (ks, iv, out2, s_te0, s_te1, s_te2, s_te3, s_te4);

  out2[0] ^= esalt_bufs[digests_offset].data[ 8];
  out2[1] ^= esalt_bufs[digests_offset].data[ 9];
  out2[2] ^= esalt_bufs[digests_offset].data[10];
  out2[3] ^= esalt_bufs[digests_offset].data[11];

  // 3

  iv[3] += 1; // xx000003

  u32 out3[4]; // actually only 3 needed

  AES256_encrypt (ks, iv, out3, s_te0, s_te1, s_te2, s_te3, s_te4);

  out3[0] ^= esalt_bufs[digests_offset].data[12];
  out3[1] ^= esalt_bufs[digests_offset].data[13];
  out3[2] ^= esalt_bufs[digests_offset].data[14];


  // compute MAC:

  // out1

  iv[0] = (iv[0] & 0x00ffffff) | 0x3a000000;
  iv[3] = (iv[3] & 0xff000000) | 0x0000002c;

  u32 mac[4];

  AES256_encrypt (ks, iv, mac, s_te0, s_te1, s_te2, s_te3, s_te4);

  iv[0] = mac[0] ^ out1[0];
  iv[1] = mac[1] ^ out1[1];
  iv[2] = mac[2] ^ out1[2];
  iv[3] = mac[3] ^ out1[3];

  // out2

  AES256_encrypt (ks, iv, mac, s_te0, s_te1, s_te2, s_te3, s_te4);

  iv[0] = mac[0] ^ out2[0];
  iv[1] = mac[1] ^ out2[1];
  iv[2] = mac[2] ^ out2[2];
  iv[3] = mac[3] ^ out2[3];

  // out3

  AES256_encrypt (ks, iv, mac, s_te0, s_te1, s_te2, s_te3, s_te4);

  iv[0] = mac[0] ^ out3[0];
  iv[1] = mac[1] ^ out3[1];
  iv[2] = mac[2] ^ out3[2];
  iv[3] = mac[3];

  // final

  AES256_encrypt (ks, iv, mac, s_te0, s_te1, s_te2, s_te3, s_te4);

  if (mac[0] != out0[0]) return;
  if (mac[1] != out0[1]) return;
  if (mac[2] != out0[2]) return;
  if (mac[3] != out0[3]) return;


  // if we end up here, we are sure to have found the correct password:

  if (atomic_inc (&hashes_shown[digests_offset]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0, 0, 0);
  }
}
