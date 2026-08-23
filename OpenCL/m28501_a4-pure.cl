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
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

typedef struct pcfg_hash_ctx
{
  secp256k1_t preG;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  set_precomputed_basepoint_g (&hc->preG);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 52) return false;

  const u32 b = hc_swap32_S (w[0]);

  if ((b < 0x4b774469) ||
      (b > 0x4c356f4c)) return false;

  const bool status_base58 = is_valid_base58 (w, 0, 52);

  if (status_base58 != true) return false;

  u32 tmp[16] = { 0 };

  const bool status_dec = b58dec_52 (tmp, w);

  if (status_dec != true) return false;

  if ((tmp[0] & 0xff000000) != 0x80000000) return false;

  if ((tmp[8] & 0x00ff0000) != 0x00010000) return false;

  const bool status_check = b58check_38 (tmp);

  if (status_check != true) return false;

  u32 prv_key[9];

  prv_key[0] = (tmp[7] << 8) | (tmp[8] >> 24);
  prv_key[1] = (tmp[6] << 8) | (tmp[7] >> 24);
  prv_key[2] = (tmp[5] << 8) | (tmp[6] >> 24);
  prv_key[3] = (tmp[4] << 8) | (tmp[5] >> 24);
  prv_key[4] = (tmp[3] << 8) | (tmp[4] >> 24);
  prv_key[5] = (tmp[2] << 8) | (tmp[3] >> 24);
  prv_key[6] = (tmp[1] << 8) | (tmp[2] >> 24);
  prv_key[7] = (tmp[0] << 8) | (tmp[1] >> 24);

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, prv_key, &hc->preG);

  u32 pub_key[16] = { 0 };

  const u32 type = 0x02 | (y[0] & 1);

  pub_key[8] =               (x[0] << 24);
  pub_key[7] = (x[0] >> 8) | (x[1] << 24);
  pub_key[6] = (x[1] >> 8) | (x[2] << 24);
  pub_key[5] = (x[2] >> 8) | (x[3] << 24);
  pub_key[4] = (x[3] >> 8) | (x[4] << 24);
  pub_key[3] = (x[4] >> 8) | (x[5] << 24);
  pub_key[2] = (x[5] >> 8) | (x[6] << 24);
  pub_key[1] = (x[6] >> 8) | (x[7] << 24);
  pub_key[0] = (x[7] >> 8) | (type << 24);

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, pub_key, 33);
  sha256_final  (&ctx);

  for (u32 i = 0; i < 8; i++) tmp[i] = ctx.h[i];

  for (u32 i = 8; i < 16; i++) tmp[i] = 0;

  ripemd160_ctx_t rctx;

  ripemd160_init        (&rctx);
  ripemd160_update_swap (&rctx, tmp, 32);
  ripemd160_final       (&rctx);

  dgst[0] = rctx.h[0];
  dgst[1] = rctx.h[1];
  dgst[2] = rctx.h[2];
  dgst[3] = rctx.h[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64];

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool ok = pcfg_hash (hc, t, len, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m28501_mxx
#define PCFG_KERNEL_SXX m28501_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
