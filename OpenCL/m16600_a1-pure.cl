/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

typedef struct electrum_wallet
{
  u32 salt_type;
  u32 iv[4];
  u32 encrypted[4];

} electrum_wallet_t;

KERNEL_FQ void m16600_mxx (KERN_ATTR_ESALT (electrum_wallet_t))
{
  /**
   * base
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

  if (gid >= gid_max) return;

  /**
   * base
   */

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx);

    u32 a = ctx.h[0];
    u32 b = ctx.h[1];
    u32 c = ctx.h[2];
    u32 d = ctx.h[3];
    u32 e = ctx.h[4];
    u32 f = ctx.h[5];
    u32 g = ctx.h[6];
    u32 h = ctx.h[7];

    sha256_init (&ctx);

    ctx.w0[0] = a;
    ctx.w0[1] = b;
    ctx.w0[2] = c;
    ctx.w0[3] = d;
    ctx.w1[0] = e;
    ctx.w1[1] = f;
    ctx.w1[2] = g;
    ctx.w1[3] = h;

    ctx.len = 32;

    sha256_final (&ctx);

    a = ctx.h[0];
    b = ctx.h[1];
    c = ctx.h[2];
    d = ctx.h[3];
    e = ctx.h[4];
    f = ctx.h[5];
    g = ctx.h[6];
    h = ctx.h[7];

    u32 ukey[8];

    ukey[0] = hc_swap32_S (a);
    ukey[1] = hc_swap32_S (b);
    ukey[2] = hc_swap32_S (c);
    ukey[3] = hc_swap32_S (d);
    ukey[4] = hc_swap32_S (e);
    ukey[5] = hc_swap32_S (f);
    ukey[6] = hc_swap32_S (g);
    ukey[7] = hc_swap32_S (h);

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 encrypted[4];

    encrypted[0] = esalt_bufs[digests_offset].encrypted[0];
    encrypted[1] = esalt_bufs[digests_offset].encrypted[1];
    encrypted[2] = esalt_bufs[digests_offset].encrypted[2];
    encrypted[3] = esalt_bufs[digests_offset].encrypted[3];

    u32 out[4];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 iv[4];

    iv[0] = esalt_bufs[digests_offset].iv[0];
    iv[1] = esalt_bufs[digests_offset].iv[1];
    iv[2] = esalt_bufs[digests_offset].iv[2];
    iv[3] = esalt_bufs[digests_offset].iv[3];

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if (esalt_bufs[digests_offset].salt_type == 1)
    {
      if (is_valid_hex_32 (out[0]) == 0) continue;
      if (is_valid_hex_32 (out[1]) == 0) continue;
      if (is_valid_hex_32 (out[2]) == 0) continue;
      if (is_valid_hex_32 (out[3]) == 0) continue;

      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }

    if (esalt_bufs[digests_offset].salt_type == 2)
    {
      if ((u8) (out[0] >> 0) != 'x') continue;
      if ((u8) (out[0] >> 8) != 'p') continue;
      if ((u8) (out[0] >> 16) != 'r') continue;
      if ((u8) (out[0] >> 24) != 'v') continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;

      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }

    if (esalt_bufs[digests_offset].salt_type == 3)
    {
      // check PKCS7 padding (either 13 times 0x0d or 12 times 0x0c at the end, we only check 12 bytes, it's enough):

      if ((out[1] == 0x0c0c0c0c) && (out[2] == 0x0c0c0c0c) && (out[3] == 0x0c0c0c0c))
      {
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }

      if ((out[1] == 0x0d0d0d0d) && (out[2] == 0x0d0d0d0d) && (out[3] == 0x0d0d0d0d))
      {
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ void m16600_sxx (KERN_ATTR_ESALT (electrum_wallet_t))
{
  /**
   * base
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

  if (gid >= gid_max) return;

  /**
   * base
   */

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx);

    u32 a = ctx.h[0];
    u32 b = ctx.h[1];
    u32 c = ctx.h[2];
    u32 d = ctx.h[3];
    u32 e = ctx.h[4];
    u32 f = ctx.h[5];
    u32 g = ctx.h[6];
    u32 h = ctx.h[7];

    sha256_init (&ctx);

    ctx.w0[0] = a;
    ctx.w0[1] = b;
    ctx.w0[2] = c;
    ctx.w0[3] = d;
    ctx.w1[0] = e;
    ctx.w1[1] = f;
    ctx.w1[2] = g;
    ctx.w1[3] = h;

    ctx.len = 32;

    sha256_final (&ctx);

    a = ctx.h[0];
    b = ctx.h[1];
    c = ctx.h[2];
    d = ctx.h[3];
    e = ctx.h[4];
    f = ctx.h[5];
    g = ctx.h[6];
    h = ctx.h[7];

    u32 ukey[8];

    ukey[0] = hc_swap32_S (a);
    ukey[1] = hc_swap32_S (b);
    ukey[2] = hc_swap32_S (c);
    ukey[3] = hc_swap32_S (d);
    ukey[4] = hc_swap32_S (e);
    ukey[5] = hc_swap32_S (f);
    ukey[6] = hc_swap32_S (g);
    ukey[7] = hc_swap32_S (h);

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 encrypted[4];

    encrypted[0] = esalt_bufs[digests_offset].encrypted[0];
    encrypted[1] = esalt_bufs[digests_offset].encrypted[1];
    encrypted[2] = esalt_bufs[digests_offset].encrypted[2];
    encrypted[3] = esalt_bufs[digests_offset].encrypted[3];

    u32 out[4];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 iv[4];

    iv[0] = esalt_bufs[digests_offset].iv[0];
    iv[1] = esalt_bufs[digests_offset].iv[1];
    iv[2] = esalt_bufs[digests_offset].iv[2];
    iv[3] = esalt_bufs[digests_offset].iv[3];

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if (esalt_bufs[digests_offset].salt_type == 1)
    {
      if (is_valid_hex_32 (out[0]) == 0) continue;
      if (is_valid_hex_32 (out[1]) == 0) continue;
      if (is_valid_hex_32 (out[2]) == 0) continue;
      if (is_valid_hex_32 (out[3]) == 0) continue;

      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }

    if (esalt_bufs[digests_offset].salt_type == 2)
    {
      if ((u8) (out[0] >> 0) != 'x') continue;
      if ((u8) (out[0] >> 8) != 'p') continue;
      if ((u8) (out[0] >> 16) != 'r') continue;
      if ((u8) (out[0] >> 24) != 'v') continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;

      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }

    if (esalt_bufs[digests_offset].salt_type == 3)
    {
      // check PKCS7 padding (either 13 times 0x0d or 12 times 0x0c at the end, we only check 12 bytes, it's enough):

      if ((out[1] == 0x0c0c0c0c) && (out[2] == 0x0c0c0c0c) && (out[3] == 0x0c0c0c0c))
      {
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }

      if ((out[1] == 0x0d0d0d0d) && (out[2] == 0x0d0d0d0d) && (out[3] == 0x0d0d0d0d))
      {
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}
