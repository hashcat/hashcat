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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

DECLSPEC int is_valid_bitcoinj_8 (const u8 v)
{
  // .abcdefghijklmnopqrstuvwxyz

  if (v > (u8) 'z') return 0;
  if (v < (u8) '.') return 0;

  if ((v > (u8) '.') && (v < (u8) 'a')) return 0;

  return 1;
}

KERNEL_FQ void m22500_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

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

  /**
   * salt
   */

  u32 s[64] = { 0 };

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  u32 data[8];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  data[2] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  data[3] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  data[4] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  data[5] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  data[6] = salt_bufs[SALT_POS_HOST].salt_buf[8];
  data[7] = salt_bufs[SALT_POS_HOST].salt_buf[9];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    /**
     * key1 = md5 ($pass . $salt):
     */

    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    u32 ukey[8];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    /**
     * key2 = md5 ($key1 . $pass . $salt):
     */

    u32 w[16] = { 0 }; // we need 64-bit alignment for md5_update ()

    w[0] = ctx.h[0];
    w[1] = ctx.h[1];
    w[2] = ctx.h[2];
    w[3] = ctx.h[3];

    md5_init   (&ctx);
    md5_update (&ctx, w, 16);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];
    ukey[6] = ctx.h[2];
    ukey[7] = ctx.h[3];

    /**
     * iv = md5 ($key2 . $pass . $salt):
     */

    w[0] = ctx.h[0];
    w[1] = ctx.h[1];
    w[2] = ctx.h[2];
    w[3] = ctx.h[3];

    md5_init   (&ctx);
    md5_update (&ctx, w, 16);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    u32 iv[4];

    iv[0] = ctx.h[0];
    iv[1] = ctx.h[1];
    iv[2] = ctx.h[2];
    iv[3] = ctx.h[3];

    /**
     * AES-256-CBC:
     */

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 encrypted[4];

    encrypted[0] = data[0];
    encrypted[1] = data[1];
    encrypted[2] = data[2];
    encrypted[3] = data[3];

    u32 out[4];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];

    // first char of decrypted wallet data must be K, L, Q, 5, # or \n

    const u32 first_byte = out[0] & 0xff;

    if ((first_byte != 0x4b) && // K
        (first_byte != 0x4c) && // L
        (first_byte != 0x51) && // Q
        (first_byte != 0x35) && // 5
        (first_byte != 0x23) && // #
        (first_byte != 0x0a))   // \n
    {
      continue;
    }

    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if ((first_byte == 0x4b) || // K => MultiBit Classic Wallet
        (first_byte == 0x4c) || // L
        (first_byte == 0x51) || // Q
        (first_byte == 0x35))   // 5
    {
      // base58 check:

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;
    }
    else if (first_byte == 0x0a) // \n => bitcoinj
    {
      if ((out[0] & 0x0000ff00)  > 0x00007f00) continue; // second_byte

      // check for "org." substring:

      if ((out[0] & 0xffff0000) != 0x726f0000) continue; // "ro" (byte swapped)
      if ((out[1] & 0x0000ffff) != 0x00002e67) continue; // ".g"

      if (is_valid_bitcoinj_8 (out[1] >> 16) == 0) continue; // byte  6 (counting from 0)
      if (is_valid_bitcoinj_8 (out[1] >> 24) == 0) continue; // byte  7

      if (is_valid_bitcoinj_8 (out[2] >>  0) == 0) continue; // byte  8
      if (is_valid_bitcoinj_8 (out[2] >>  8) == 0) continue; // byte  9
      if (is_valid_bitcoinj_8 (out[2] >> 16) == 0) continue; // byte 10
      if (is_valid_bitcoinj_8 (out[2] >> 24) == 0) continue; // byte 11

      if (is_valid_bitcoinj_8 (out[3] >>  0) == 0) continue; // byte 12
      if (is_valid_bitcoinj_8 (out[3] >>  8) == 0) continue; // byte 13
    }
    else // if (first_byte == 0x23) // # => KnCGroup Bitcoin Wallet
    {
      // Full string would be:
      // "# KEEP YOUR PRIVATE KEYS SAFE! Anyone who can read this can spend your Bitcoins."

      // check for "# KEEP YOUR PRIV" substring:

      if (out[0] != 0x454b2023) continue; // "EK #" (byte swapped)
      if (out[1] != 0x59205045) continue; // "Y PE"
      if (out[2] != 0x2052554f) continue; // " RUO"
      if (out[3] != 0x56495250) continue; // "VIRP"

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // check for "ATE KEYS SAFE! A" substring:

      if (out[0] != 0x20455441) continue; // " ETA" (byte swapped)
      if (out[1] != 0x5359454b) continue; // "SYEK"
      if (out[2] != 0x46415320) continue; // "FAS "
      if (out[3] != 0x41202145) continue; // "A !E"
    }

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ void m22500_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

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

  /**
   * salt
   */

  u32 s[64] = { 0 };

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  u32 data[8];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  data[2] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  data[3] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  data[4] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  data[5] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  data[6] = salt_bufs[SALT_POS_HOST].salt_buf[8];
  data[7] = salt_bufs[SALT_POS_HOST].salt_buf[9];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    /**
     * key1 = md5 ($pass . $salt):
     */

    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    u32 ukey[8];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    /**
     * key2 = md5 ($key1 . $pass . $salt):
     */

    u32 w[16] = { 0 }; // we need 64-bit alignment for md5_update ()

    w[0] = ctx.h[0];
    w[1] = ctx.h[1];
    w[2] = ctx.h[2];
    w[3] = ctx.h[3];

    md5_init   (&ctx);
    md5_update (&ctx, w, 16);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];
    ukey[6] = ctx.h[2];
    ukey[7] = ctx.h[3];

    /**
     * iv = md5 ($key2 . $pass . $salt):
     */

    w[0] = ctx.h[0];
    w[1] = ctx.h[1];
    w[2] = ctx.h[2];
    w[3] = ctx.h[3];

    md5_init   (&ctx);
    md5_update (&ctx, w, 16);

    md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, 8);
    md5_final  (&ctx);

    u32 iv[4];

    iv[0] = ctx.h[0];
    iv[1] = ctx.h[1];
    iv[2] = ctx.h[2];
    iv[3] = ctx.h[3];

    /**
     * AES-256-CBC:
     */

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 encrypted[4];

    encrypted[0] = data[0];
    encrypted[1] = data[1];
    encrypted[2] = data[2];
    encrypted[3] = data[3];

    u32 out[4];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];

    // first char of decrypted wallet data must be K, L, Q, 5, # or \n

    const u32 first_byte = out[0] & 0xff;

    if ((first_byte != 0x4b) && // K
        (first_byte != 0x4c) && // L
        (first_byte != 0x51) && // Q
        (first_byte != 0x35) && // 5
        (first_byte != 0x23) && // #
        (first_byte != 0x0a))   // \n
    {
      continue;
    }

    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if ((first_byte == 0x4b) || // K => MultiBit Classic Wallet
        (first_byte == 0x4c) || // L
        (first_byte == 0x51) || // Q
        (first_byte == 0x35))   // 5
    {
      // base58 check:

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;
    }
    else if (first_byte == 0x0a) // \n => bitcoinj
    {
      if ((out[0] & 0x0000ff00)  > 0x00007f00) continue; // second_byte

      // check for "org." substring:

      if ((out[0] & 0xffff0000) != 0x726f0000) continue; // "ro" (byte swapped)
      if ((out[1] & 0x0000ffff) != 0x00002e67) continue; // ".g"

      if (is_valid_bitcoinj_8 (out[1] >> 16) == 0) continue; // byte  6 (counting from 0)
      if (is_valid_bitcoinj_8 (out[1] >> 24) == 0) continue; // byte  7

      if (is_valid_bitcoinj_8 (out[2] >>  0) == 0) continue; // byte  8
      if (is_valid_bitcoinj_8 (out[2] >>  8) == 0) continue; // byte  9
      if (is_valid_bitcoinj_8 (out[2] >> 16) == 0) continue; // byte 10
      if (is_valid_bitcoinj_8 (out[2] >> 24) == 0) continue; // byte 11

      if (is_valid_bitcoinj_8 (out[3] >>  0) == 0) continue; // byte 12
      if (is_valid_bitcoinj_8 (out[3] >>  8) == 0) continue; // byte 13
    }
    else // if (first_byte == 0x23) // # => KnCGroup Bitcoin Wallet
    {
      // Full string would be:
      // "# KEEP YOUR PRIVATE KEYS SAFE! Anyone who can read this can spend your Bitcoins."

      // check for "# KEEP YOUR PRIV" substring:

      if (out[0] != 0x454b2023) continue; // "EK #" (byte swapped)
      if (out[1] != 0x59205045) continue; // "Y PE"
      if (out[2] != 0x2052554f) continue; // " RUO"
      if (out[3] != 0x56495250) continue; // "VIRP"

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // check for "ATE KEYS SAFE! A" substring:

      if (out[0] != 0x20455441) continue; // " ETA" (byte swapped)
      if (out[1] != 0x5359454b) continue; // "SYEK"
      if (out[2] != 0x46415320) continue; // "FAS "
      if (out[3] != 0x41202145) continue; // "A !E"
    }

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}
