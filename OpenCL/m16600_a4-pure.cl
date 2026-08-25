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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct electrum_wallet
{
  u32 iv[4];
  u32 encrypted[4];
  u32 salt_type;

} electrum_wallet_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (electrum_wallet_t)

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
  u32 search[4];

  u32 iv[4];
  u32 encrypted[4];

  u32 salt_type;

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

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const electrum_wallet_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->salt_type = esalt_bufs[digest_pos].salt_type;

  hc->encrypted[0] = esalt_bufs[digest_pos].encrypted[0];
  hc->encrypted[1] = esalt_bufs[digest_pos].encrypted[1];
  hc->encrypted[2] = esalt_bufs[digest_pos].encrypted[2];
  hc->encrypted[3] = esalt_bufs[digest_pos].encrypted[3];

  hc->iv[0] = esalt_bufs[digest_pos].iv[0];
  hc->iv[1] = esalt_bufs[digest_pos].iv[1];
  hc->iv[2] = esalt_bufs[digest_pos].iv[2];
  hc->iv[3] = esalt_bufs[digest_pos].iv[3];
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

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_swap (&ctx, w, len);

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

  u32 ks[60];

  aes256_set_decrypt_key_inv (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_inv0, s_inv1, s_inv2, s_inv3);

  u32 out[4];

  aes256_decrypt (ks, hc->encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= hc->iv[0];
  out[1] ^= hc->iv[1];
  out[2] ^= hc->iv[2];
  out[3] ^= hc->iv[3];

  if (hc->salt_type < 1) return false;
  if (hc->salt_type > 3) return false;

  if (hc->salt_type == 1)
  {
    if (is_valid_hex_32 (out[0]) == 0) return false;
    if (is_valid_hex_32 (out[1]) == 0) return false;
    if (is_valid_hex_32 (out[2]) == 0) return false;
    if (is_valid_hex_32 (out[3]) == 0) return false;
  }

  if (hc->salt_type == 2)
  {
    u8 version = (u8) (out[0] >> 0);

    // https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
    // Does not include testnet addresses
    if (version != 'x' &&
        version != 'y' &&
        version != 'Y' &&
        version != 'z' &&
        version != 'Z' ) return false;
    if ((u8) (out[0] >> 8) != 'p') return false;
    if ((u8) (out[0] >> 16) != 'r') return false;
    if ((u8) (out[0] >> 24) != 'v') return false;
    if (is_valid_base58_32 (out[1]) == 0) return false;
    if (is_valid_base58_32 (out[2]) == 0) return false;
    if (is_valid_base58_32 (out[3]) == 0) return false;
  }

  if (hc->salt_type == 3)
  {
    // check PKCS7 padding (either 13 times 0x0d or 12 times 0x0c at the end, we only check 12 bytes, it's enough):

    const bool pad_0c = (out[1] == 0x0c0c0c0c) && (out[2] == 0x0c0c0c0c) && (out[3] == 0x0c0c0c0c);
    const bool pad_0d = (out[1] == 0x0d0d0d0d) && (out[2] == 0x0d0d0d0d) && (out[3] == 0x0d0d0d0d);

    if ((pad_0c == false) && (pad_0d == false)) return false;
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

#define PCFG_KERNEL_MXX m16600_mxx
#define PCFG_KERNEL_SXX m16600_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
