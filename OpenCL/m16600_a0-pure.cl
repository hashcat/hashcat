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
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"

__kernel void m16600_mxx (KERN_ATTR_RULES_ESALT (electrum_wallet_t))
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

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

    ukey[0] = swap32_S (a);
    ukey[1] = swap32_S (b);
    ukey[2] = swap32_S (c);
    ukey[3] = swap32_S (d);
    ukey[4] = swap32_S (e);
    ukey[5] = swap32_S (f);
    ukey[6] = swap32_S (g);
    ukey[7] = swap32_S (h);

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

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
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
      }
    }
  }
}

__kernel void m16600_sxx (KERN_ATTR_RULES_ESALT (electrum_wallet_t))
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

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

    ukey[0] = swap32_S (a);
    ukey[1] = swap32_S (b);
    ukey[2] = swap32_S (c);
    ukey[3] = swap32_S (d);
    ukey[4] = swap32_S (e);
    ukey[5] = swap32_S (f);
    ukey[6] = swap32_S (g);
    ukey[7] = swap32_S (h);

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

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
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
      }
    }
  }
}
