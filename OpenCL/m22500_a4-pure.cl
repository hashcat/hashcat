/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
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

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_td0[256];             \
  LOCAL_VK u32 s_td1[256];             \
  LOCAL_VK u32 s_td2[256];             \
  LOCAL_VK u32 s_td3[256];             \
  LOCAL_VK u32 s_td4[256];             \
  LOCAL_VK u32 s_te0[256];             \
  LOCAL_VK u32 s_te1[256];             \
  LOCAL_VK u32 s_te2[256];             \
  LOCAL_VK u32 s_te3[256];             \
  LOCAL_VK u32 s_inv0[256];            \
  LOCAL_VK u32 s_inv1[256];            \
  LOCAL_VK u32 s_inv2[256];            \
  LOCAL_VK u32 s_inv3[256];            \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_td0[i] = td0[i];                 \
    s_td1[i] = td1[i];                 \
    s_td2[i] = td2[i];                 \
    s_td3[i] = td3[i];                 \
    s_td4[i] = td4[i];                 \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_inv0[i] = td_inv0[i];            \
    s_inv1[i] = td_inv1[i];            \
    s_inv2[i] = td_inv2[i];            \
    s_inv3[i] = td_inv3[i];            \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_td0 = s_td0;            \
  (hc)->s_td1 = s_td1;            \
  (hc)->s_td2 = s_td2;            \
  (hc)->s_td3 = s_td3;            \
  (hc)->s_td4 = s_td4;            \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_inv0 = s_inv0;          \
  (hc)->s_inv1 = s_inv1;          \
  (hc)->s_inv2 = s_inv2;          \
  (hc)->s_inv3 = s_inv3;
#endif

typedef struct pcfg_hash_ctx
{
  u32 s[64];

  u32 data[8];

  u32 search[4];

  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0;
  LOCAL_AS u32 *s_td1;
  LOCAL_AS u32 *s_td2;
  LOCAL_AS u32 *s_td3;
  LOCAL_AS u32 *s_td4;
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_inv0;
  LOCAL_AS u32 *s_inv1;
  LOCAL_AS u32 *s_inv2;
  LOCAL_AS u32 *s_inv3;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  hc->s[0] = salt_bufs[salt_pos].salt_buf[0];
  hc->s[1] = salt_bufs[salt_pos].salt_buf[1];

  hc->data[0] = salt_bufs[salt_pos].salt_buf[2];
  hc->data[1] = salt_bufs[salt_pos].salt_buf[3];
  hc->data[2] = salt_bufs[salt_pos].salt_buf[4];
  hc->data[3] = salt_bufs[salt_pos].salt_buf[5];
  hc->data[4] = salt_bufs[salt_pos].salt_buf[6];
  hc->data[5] = salt_bufs[salt_pos].salt_buf[7];
  hc->data[6] = salt_bufs[salt_pos].salt_buf[8];
  hc->data[7] = salt_bufs[salt_pos].salt_buf[9];

  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_td0 = hc->s_td0;
  LOCAL_AS u32 *s_td1 = hc->s_td1;
  LOCAL_AS u32 *s_td2 = hc->s_td2;
  LOCAL_AS u32 *s_td3 = hc->s_td3;
  LOCAL_AS u32 *s_td4 = hc->s_td4;
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_inv0 = hc->s_inv0;
  LOCAL_AS u32 *s_inv1 = hc->s_inv1;
  LOCAL_AS u32 *s_inv2 = hc->s_inv2;
  LOCAL_AS u32 *s_inv3 = hc->s_inv3;
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
  CONSTANT_AS u32a *s_inv0 = td_inv0;
  CONSTANT_AS u32a *s_inv1 = td_inv1;
  CONSTANT_AS u32a *s_inv2 = td_inv2;
  CONSTANT_AS u32a *s_inv3 = td_inv3;
  #endif

  md5_ctx_t ctx;

  md5_init   (&ctx);
  md5_update (&ctx, w, len);
  md5_update (&ctx, hc->s, 8);
  md5_final  (&ctx);

  u32 ukey[8];

  ukey[0] = ctx.h[0];
  ukey[1] = ctx.h[1];
  ukey[2] = ctx.h[2];
  ukey[3] = ctx.h[3];

  u32 t[16] = { 0 };

  t[0] = ctx.h[0];
  t[1] = ctx.h[1];
  t[2] = ctx.h[2];
  t[3] = ctx.h[3];

  md5_init   (&ctx);
  md5_update (&ctx, t, 16);
  md5_update (&ctx, w, len);
  md5_update (&ctx, hc->s, 8);
  md5_final  (&ctx);

  ukey[4] = ctx.h[0];
  ukey[5] = ctx.h[1];
  ukey[6] = ctx.h[2];
  ukey[7] = ctx.h[3];

  t[0] = ctx.h[0];
  t[1] = ctx.h[1];
  t[2] = ctx.h[2];
  t[3] = ctx.h[3];

  md5_init   (&ctx);
  md5_update (&ctx, t, 16);
  md5_update (&ctx, w, len);
  md5_update (&ctx, hc->s, 8);
  md5_final  (&ctx);

  u32 iv[4];

  iv[0] = ctx.h[0];
  iv[1] = ctx.h[1];
  iv[2] = ctx.h[2];
  iv[3] = ctx.h[3];

  u32 ks[60];

  aes256_set_decrypt_key_inv (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_inv0, s_inv1, s_inv2, s_inv3);

  u32 encrypted[4];

  encrypted[0] = hc->data[0];
  encrypted[1] = hc->data[1];
  encrypted[2] = hc->data[2];
  encrypted[3] = hc->data[3];

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
      (first_byte != 0x0a)) // \n
  {
    return false;
  }

  out[1] ^= iv[1];
  out[2] ^= iv[2];
  out[3] ^= iv[3];

  if ((first_byte == 0x4b) || // K => MultiBit Classic Wallet
      (first_byte == 0x4c) || // L
      (first_byte == 0x51) || // Q
      (first_byte == 0x35)) // 5
  {
    // base58 check:

    if (is_valid_base58_32 (out[0]) == 0) return false;
    if (is_valid_base58_32 (out[1]) == 0) return false;
    if (is_valid_base58_32 (out[2]) == 0) return false;
    if (is_valid_base58_32 (out[3]) == 0) return false;

    iv[0] = encrypted[0];
    iv[1] = encrypted[1];
    iv[2] = encrypted[2];
    iv[3] = encrypted[3];

    encrypted[0] = hc->data[4];
    encrypted[1] = hc->data[5];
    encrypted[2] = hc->data[6];
    encrypted[3] = hc->data[7];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if (is_valid_base58_32 (out[0]) == 0) return false;
    if (is_valid_base58_32 (out[1]) == 0) return false;
    if (is_valid_base58_32 (out[2]) == 0) return false;
    if (is_valid_base58_32 (out[3]) == 0) return false;
  }
  else if (first_byte == 0x0a) // \n => bitcoinj
  {
    if ((out[0] & 0x0000ff00)  > 0x00007f00) return false; // second_byte

    // check for "org." substring:

    if ((out[0] & 0xffff0000) != 0x726f0000) return false; // "ro" (byte swapped)
    if ((out[1] & 0x0000ffff) != 0x00002e67) return false; // ".g"

    if (is_valid_bitcoinj_8 (out[1] >> 16) == 0) return false; // byte  6 (counting from 0)
    if (is_valid_bitcoinj_8 (out[1] >> 24) == 0) return false; // byte  7

    if (is_valid_bitcoinj_8 (out[2] >>  0) == 0) return false; // byte  8
    if (is_valid_bitcoinj_8 (out[2] >>  8) == 0) return false; // byte  9
    if (is_valid_bitcoinj_8 (out[2] >> 16) == 0) return false; // byte 10
    if (is_valid_bitcoinj_8 (out[2] >> 24) == 0) return false; // byte 11

    if (is_valid_bitcoinj_8 (out[3] >>  0) == 0) return false; // byte 12
    if (is_valid_bitcoinj_8 (out[3] >>  8) == 0) return false; // byte 13
  }
  else // if (first_byte == 0x23) // # => KnCGroup Bitcoin Wallet
  {
    // Full string would be:
    // "# KEEP YOUR PRIVATE KEYS SAFE! Anyone who can read this can spend your Bitcoins."
    // check for "# KEEP YOUR PRIV" substring:

    if (out[0] != 0x454b2023) return false; // "EK #" (byte swapped)
    if (out[1] != 0x59205045) return false; // "Y PE"
    if (out[2] != 0x2052554f) return false; // " RUO"
    if (out[3] != 0x56495250) return false; // "VIRP"

    iv[0] = encrypted[0];
    iv[1] = encrypted[1];
    iv[2] = encrypted[2];
    iv[3] = encrypted[3];

    encrypted[0] = hc->data[4];
    encrypted[1] = hc->data[5];
    encrypted[2] = hc->data[6];
    encrypted[3] = hc->data[7];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    // check for "ATE KEYS SAFE! A" substring:

    if (out[0] != 0x20455441) return false; // " ETA" (byte swapped)
    if (out[1] != 0x5359454b) return false; // "SYEK"
    if (out[2] != 0x46415320) return false; // "FAS "
    if (out[3] != 0x41202145) return false; // "A !E"
  }

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m22500_mxx
#define PCFG_KERNEL_SXX m22500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
