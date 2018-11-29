/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_streebog512.cl"

#include "inc_cipher_aes.cl"
#include "inc_cipher_twofish.cl"
#include "inc_cipher_serpent.cl"
#include "inc_cipher_camellia.cl"
#include "inc_cipher_kuznyechik.cl"

#include "inc_truecrypt_keyfile.cl"
#include "inc_truecrypt_crc32.cl"
#include "inc_truecrypt_xts.cl"
#include "inc_veracrypt_xts.cl"

DECLSPEC void hmac_streebog512_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u64x *ipad_hash, u64x *opad_hash, u64x *ipad_raw, u64x *opad_raw, u64x *digest, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  const u64x nullbuf[8] = { 0 };
  u64x counterbuf[8]    = { 0 };
  u64x padding[8]       = { 0 };
  u64x message[8];

  padding[7] = 0x0100000000000000;

  //inner HMAC: ipad + message

  //first transform: precalculated ipad hash
  counterbuf[7] = 0x0002000000000000;

  //second transform: message = previous HMAC digest
  message[7] = hl32_to_64 (w3[2], w3[3]);
  message[6] = hl32_to_64 (w3[0], w3[1]);
  message[5] = hl32_to_64 (w2[2], w2[3]);
  message[4] = hl32_to_64 (w2[0], w2[1]);
  message[3] = hl32_to_64 (w1[2], w1[3]);
  message[2] = hl32_to_64 (w1[0], w1[1]);
  message[1] = hl32_to_64 (w0[2], w0[3]);
  message[0] = hl32_to_64 (w0[0], w0[1]);

  digest[0] = ipad_hash[0];
  digest[1] = ipad_hash[1];
  digest[2] = ipad_hash[2];
  digest[3] = ipad_hash[3];
  digest[4] = ipad_hash[4];
  digest[5] = ipad_hash[5];
  digest[6] = ipad_hash[6];
  digest[7] = ipad_hash[7];

  streebog512_g_vector (digest, counterbuf, message, s_sbob_sl64);

  counterbuf[7] = 0x0004000000000000;

  //final: padding byte
  streebog512_g_vector (digest, counterbuf, padding, s_sbob_sl64);

  streebog512_add_vector (message, ipad_raw);
  streebog512_add_vector (message, padding);

  streebog512_g_vector (digest, nullbuf, counterbuf, s_sbob_sl64);

  streebog512_g_vector (digest, nullbuf, message, s_sbob_sl64);

  //outer HMAC: opad + digest

  //first transform: precalculated opad hash
  counterbuf[7] = 0x0002000000000000;

  //second transform: message = inner HMAC digest
  message[0] = digest[0];
  message[1] = digest[1];
  message[2] = digest[2];
  message[3] = digest[3];
  message[4] = digest[4];
  message[5] = digest[5];
  message[6] = digest[6];
  message[7] = digest[7];

  digest[0] = opad_hash[0];
  digest[1] = opad_hash[1];
  digest[2] = opad_hash[2];
  digest[3] = opad_hash[3];
  digest[4] = opad_hash[4];
  digest[5] = opad_hash[5];
  digest[6] = opad_hash[6];
  digest[7] = opad_hash[7];

  streebog512_g_vector (digest, counterbuf, message, s_sbob_sl64);

  counterbuf[7] = 0x0004000000000000;

  streebog512_g_vector (digest, counterbuf, padding, s_sbob_sl64);

  streebog512_add_vector (message, opad_raw);
  streebog512_add_vector (message, padding);

  streebog512_g_vector (digest, nullbuf, counterbuf, s_sbob_sl64);

  streebog512_g_vector (digest, nullbuf, message, s_sbob_sl64);
}

__kernel void m13771_init (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, tc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  const int keyboard_layout_mapping_cnt = esalt_bufs[digests_offset].keyboard_layout_mapping_cnt;

  __local keyboard_layout_mapping_t s_keyboard_layout_mapping_buf[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_keyboard_layout_mapping_buf[i] = esalt_bufs[digests_offset].keyboard_layout_mapping_buf[i];
  }

  #ifdef REAL_SHM

  __local u64a s_sbob_sl64[8][256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob_sl64[0][i];
    s_sbob_sl64[1][i] = sbob_sl64[1][i];
    s_sbob_sl64[2][i] = sbob_sl64[2][i];
    s_sbob_sl64[3][i] = sbob_sl64[3][i];
    s_sbob_sl64[4][i] = sbob_sl64[4][i];
    s_sbob_sl64[5][i] = sbob_sl64[5][i];
    s_sbob_sl64[6][i] = sbob_sl64[6][i];
    s_sbob_sl64[7][i] = sbob_sl64[7][i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u64a (*s_sbob_sl64)[256] = sbob_sl64;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];
  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];
  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  execute_keyboard_layout_mapping (w0, w1, w2, w3, pw_len, s_keyboard_layout_mapping_buf, keyboard_layout_mapping_cnt);

  w0[0] = u8add (w0[0], esalt_bufs[digests_offset].keyfile_buf[ 0]);
  w0[1] = u8add (w0[1], esalt_bufs[digests_offset].keyfile_buf[ 1]);
  w0[2] = u8add (w0[2], esalt_bufs[digests_offset].keyfile_buf[ 2]);
  w0[3] = u8add (w0[3], esalt_bufs[digests_offset].keyfile_buf[ 3]);
  w1[0] = u8add (w1[0], esalt_bufs[digests_offset].keyfile_buf[ 4]);
  w1[1] = u8add (w1[1], esalt_bufs[digests_offset].keyfile_buf[ 5]);
  w1[2] = u8add (w1[2], esalt_bufs[digests_offset].keyfile_buf[ 6]);
  w1[3] = u8add (w1[3], esalt_bufs[digests_offset].keyfile_buf[ 7]);
  w2[0] = u8add (w2[0], esalt_bufs[digests_offset].keyfile_buf[ 8]);
  w2[1] = u8add (w2[1], esalt_bufs[digests_offset].keyfile_buf[ 9]);
  w2[2] = u8add (w2[2], esalt_bufs[digests_offset].keyfile_buf[10]);
  w2[3] = u8add (w2[3], esalt_bufs[digests_offset].keyfile_buf[11]);
  w3[0] = u8add (w3[0], esalt_bufs[digests_offset].keyfile_buf[12]);
  w3[1] = u8add (w3[1], esalt_bufs[digests_offset].keyfile_buf[13]);
  w3[2] = u8add (w3[2], esalt_bufs[digests_offset].keyfile_buf[14]);
  w3[3] = u8add (w3[3], esalt_bufs[digests_offset].keyfile_buf[15]);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  streebog512_hmac_ctx_t streebog512_hmac_ctx;

  streebog512_hmac_init_64 (&streebog512_hmac_ctx, w0, w1, w2, w3, s_sbob_sl64);

  tmps[gid].ipad_hash[0] = streebog512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad_hash[1] = streebog512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad_hash[2] = streebog512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad_hash[3] = streebog512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad_hash[4] = streebog512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad_hash[5] = streebog512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad_hash[6] = streebog512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad_hash[7] = streebog512_hmac_ctx.ipad.h[7];

  tmps[gid].opad_hash[0] = streebog512_hmac_ctx.opad.h[0];
  tmps[gid].opad_hash[1] = streebog512_hmac_ctx.opad.h[1];
  tmps[gid].opad_hash[2] = streebog512_hmac_ctx.opad.h[2];
  tmps[gid].opad_hash[3] = streebog512_hmac_ctx.opad.h[3];
  tmps[gid].opad_hash[4] = streebog512_hmac_ctx.opad.h[4];
  tmps[gid].opad_hash[5] = streebog512_hmac_ctx.opad.h[5];
  tmps[gid].opad_hash[6] = streebog512_hmac_ctx.opad.h[6];
  tmps[gid].opad_hash[7] = streebog512_hmac_ctx.opad.h[7];

  tmps[gid].ipad_raw[0] = streebog512_hmac_ctx.ipad.s[0];
  tmps[gid].ipad_raw[1] = streebog512_hmac_ctx.ipad.s[1];
  tmps[gid].ipad_raw[2] = streebog512_hmac_ctx.ipad.s[2];
  tmps[gid].ipad_raw[3] = streebog512_hmac_ctx.ipad.s[3];
  tmps[gid].ipad_raw[4] = streebog512_hmac_ctx.ipad.s[4];
  tmps[gid].ipad_raw[5] = streebog512_hmac_ctx.ipad.s[5];
  tmps[gid].ipad_raw[6] = streebog512_hmac_ctx.ipad.s[6];
  tmps[gid].ipad_raw[7] = streebog512_hmac_ctx.ipad.s[7];

  tmps[gid].opad_raw[0] = streebog512_hmac_ctx.opad.s[0];
  tmps[gid].opad_raw[1] = streebog512_hmac_ctx.opad.s[1];
  tmps[gid].opad_raw[2] = streebog512_hmac_ctx.opad.s[2];
  tmps[gid].opad_raw[3] = streebog512_hmac_ctx.opad.s[3];
  tmps[gid].opad_raw[4] = streebog512_hmac_ctx.opad.s[4];
  tmps[gid].opad_raw[5] = streebog512_hmac_ctx.opad.s[5];
  tmps[gid].opad_raw[6] = streebog512_hmac_ctx.opad.s[6];
  tmps[gid].opad_raw[7] = streebog512_hmac_ctx.opad.s[7];

  streebog512_hmac_update_global_swap (&streebog512_hmac_ctx, esalt_bufs[digests_offset].salt_buf, 64);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    streebog512_hmac_ctx_t streebog512_hmac_ctx2 = streebog512_hmac_ctx;

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

    streebog512_hmac_update_64 (&streebog512_hmac_ctx2, w0, w1, w2, w3, 4);

    streebog512_hmac_final (&streebog512_hmac_ctx2);

    tmps[gid].dgst[i + 0] = streebog512_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = streebog512_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = streebog512_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = streebog512_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = streebog512_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = streebog512_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = streebog512_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = streebog512_hmac_ctx2.opad.h[7];

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

__kernel void m13771_loop (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, tc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  __local u64a s_sbob_sl64[8][256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob_sl64[0][i];
    s_sbob_sl64[1][i] = sbob_sl64[1][i];
    s_sbob_sl64[2][i] = sbob_sl64[2][i];
    s_sbob_sl64[3][i] = sbob_sl64[3][i];
    s_sbob_sl64[4][i] = sbob_sl64[4][i];
    s_sbob_sl64[5][i] = sbob_sl64[5][i];
    s_sbob_sl64[6][i] = sbob_sl64[6][i];
    s_sbob_sl64[7][i] = sbob_sl64[7][i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u64a (*s_sbob_sl64)[256] = sbob_sl64;

  #endif

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x ipad_hash[8];
  u64x opad_hash[8];

  ipad_hash[0] = pack64v (tmps, ipad_hash, gid, 0);
  ipad_hash[1] = pack64v (tmps, ipad_hash, gid, 1);
  ipad_hash[2] = pack64v (tmps, ipad_hash, gid, 2);
  ipad_hash[3] = pack64v (tmps, ipad_hash, gid, 3);
  ipad_hash[4] = pack64v (tmps, ipad_hash, gid, 4);
  ipad_hash[5] = pack64v (tmps, ipad_hash, gid, 5);
  ipad_hash[6] = pack64v (tmps, ipad_hash, gid, 6);
  ipad_hash[7] = pack64v (tmps, ipad_hash, gid, 7);

  opad_hash[0] = pack64v (tmps, opad_hash, gid, 0);
  opad_hash[1] = pack64v (tmps, opad_hash, gid, 1);
  opad_hash[2] = pack64v (tmps, opad_hash, gid, 2);
  opad_hash[3] = pack64v (tmps, opad_hash, gid, 3);
  opad_hash[4] = pack64v (tmps, opad_hash, gid, 4);
  opad_hash[5] = pack64v (tmps, opad_hash, gid, 5);
  opad_hash[6] = pack64v (tmps, opad_hash, gid, 6);
  opad_hash[7] = pack64v (tmps, opad_hash, gid, 7);

  u64x ipad_raw[8];
  u64x opad_raw[8];

  ipad_raw[0] = pack64v (tmps, ipad_raw, gid, 0);
  ipad_raw[1] = pack64v (tmps, ipad_raw, gid, 1);
  ipad_raw[2] = pack64v (tmps, ipad_raw, gid, 2);
  ipad_raw[3] = pack64v (tmps, ipad_raw, gid, 3);
  ipad_raw[4] = pack64v (tmps, ipad_raw, gid, 4);
  ipad_raw[5] = pack64v (tmps, ipad_raw, gid, 5);
  ipad_raw[6] = pack64v (tmps, ipad_raw, gid, 6);
  ipad_raw[7] = pack64v (tmps, ipad_raw, gid, 7);

  opad_raw[0] = pack64v (tmps, opad_raw, gid, 0);
  opad_raw[1] = pack64v (tmps, opad_raw, gid, 1);
  opad_raw[2] = pack64v (tmps, opad_raw, gid, 2);
  opad_raw[3] = pack64v (tmps, opad_raw, gid, 3);
  opad_raw[4] = pack64v (tmps, opad_raw, gid, 4);
  opad_raw[5] = pack64v (tmps, opad_raw, gid, 5);
  opad_raw[6] = pack64v (tmps, opad_raw, gid, 6);
  opad_raw[7] = pack64v (tmps, opad_raw, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst, gid, i + 7);

    out[0] = pack64v (tmps, out, gid, i + 0);
    out[1] = pack64v (tmps, out, gid, i + 1);
    out[2] = pack64v (tmps, out, gid, i + 2);
    out[3] = pack64v (tmps, out, gid, i + 3);
    out[4] = pack64v (tmps, out, gid, i + 4);
    out[5] = pack64v (tmps, out, gid, i + 5);
    out[6] = pack64v (tmps, out, gid, i + 6);
    out[7] = pack64v (tmps, out, gid, i + 7);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = h32_from_64 (dgst[0]);
      w0[1] = l32_from_64 (dgst[0]);
      w0[2] = h32_from_64 (dgst[1]);
      w0[3] = l32_from_64 (dgst[1]);
      w1[0] = h32_from_64 (dgst[2]);
      w1[1] = l32_from_64 (dgst[2]);
      w1[2] = h32_from_64 (dgst[3]);
      w1[3] = l32_from_64 (dgst[3]);
      w2[0] = h32_from_64 (dgst[4]);
      w2[1] = l32_from_64 (dgst[4]);
      w2[2] = h32_from_64 (dgst[5]);
      w2[3] = l32_from_64 (dgst[5]);
      w3[0] = h32_from_64 (dgst[6]);
      w3[1] = l32_from_64 (dgst[6]);
      w3[2] = h32_from_64 (dgst[7]);
      w3[3] = l32_from_64 (dgst[7]);

      hmac_streebog512_run_V (w0, w1, w2, w3, ipad_hash, opad_hash, ipad_raw, opad_raw, dgst, s_sbob_sl64);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpack64v (tmps, dgst, gid, i + 0, dgst[0]);
    unpack64v (tmps, dgst, gid, i + 1, dgst[1]);
    unpack64v (tmps, dgst, gid, i + 2, dgst[2]);
    unpack64v (tmps, dgst, gid, i + 3, dgst[3]);
    unpack64v (tmps, dgst, gid, i + 4, dgst[4]);
    unpack64v (tmps, dgst, gid, i + 5, dgst[5]);
    unpack64v (tmps, dgst, gid, i + 6, dgst[6]);
    unpack64v (tmps, dgst, gid, i + 7, dgst[7]);

    unpack64v (tmps, out, gid, i + 0, out[0]);
    unpack64v (tmps, out, gid, i + 1, out[1]);
    unpack64v (tmps, out, gid, i + 2, out[2]);
    unpack64v (tmps, out, gid, i + 3, out[3]);
    unpack64v (tmps, out, gid, i + 4, out[4]);
    unpack64v (tmps, out, gid, i + 5, out[5]);
    unpack64v (tmps, out, gid, i + 6, out[6]);
    unpack64v (tmps, out, gid, i + 7, out[7]);
  }
}

__kernel void m13771_comp (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, tc_t))
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

  u32 ukey1[8];
  u32 ukey2[8];

  ukey1[0] = swap32_S (h32_from_64_S (tmps[gid].out[7]));
  ukey1[1] = swap32_S (l32_from_64_S (tmps[gid].out[7]));
  ukey1[2] = swap32_S (h32_from_64_S (tmps[gid].out[6]));
  ukey1[3] = swap32_S (l32_from_64_S (tmps[gid].out[6]));
  ukey1[4] = swap32_S (h32_from_64_S (tmps[gid].out[5]));
  ukey1[5] = swap32_S (l32_from_64_S (tmps[gid].out[5]));
  ukey1[6] = swap32_S (h32_from_64_S (tmps[gid].out[4]));
  ukey1[7] = swap32_S (l32_from_64_S (tmps[gid].out[4]));

  ukey2[0] = swap32_S (h32_from_64_S (tmps[gid].out[3]));
  ukey2[1] = swap32_S (l32_from_64_S (tmps[gid].out[3]));
  ukey2[2] = swap32_S (h32_from_64_S (tmps[gid].out[2]));
  ukey2[3] = swap32_S (l32_from_64_S (tmps[gid].out[2]));
  ukey2[4] = swap32_S (h32_from_64_S (tmps[gid].out[1]));
  ukey2[5] = swap32_S (l32_from_64_S (tmps[gid].out[1]));
  ukey2[6] = swap32_S (h32_from_64_S (tmps[gid].out[0]));
  ukey2[7] = swap32_S (l32_from_64_S (tmps[gid].out[0]));

  if (verify_header_aes (esalt_bufs, ukey1, ukey2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }

  if (verify_header_serpent (esalt_bufs, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }

  if (verify_header_twofish (esalt_bufs, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }

  if (verify_header_camellia (esalt_bufs, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }

  if (verify_header_kuznyechik (esalt_bufs, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }
}
