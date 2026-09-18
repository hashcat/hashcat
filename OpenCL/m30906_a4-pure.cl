/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

DECLSPEC u32 hex_convert_u32 (PRIVATE_AS const u32 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u32 hex_u32_to_u32 (PRIVATE_AS const u32 hex0, PRIVATE_AS const u32 hex1)
{
  u32 v = 0;

  v |= hex_convert_u32 ((hex0 >>  0) & 0xff) << 28;
  v |= hex_convert_u32 ((hex0 >>  8) & 0xff) << 24;
  v |= hex_convert_u32 ((hex0 >> 16) & 0xff) << 20;
  v |= hex_convert_u32 ((hex0 >> 24) & 0xff) << 16;

  v |= hex_convert_u32 ((hex1 >>  0) & 0xff) << 12;
  v |= hex_convert_u32 ((hex1 >>  8) & 0xff) <<  8;
  v |= hex_convert_u32 ((hex1 >> 16) & 0xff) <<  4;
  v |= hex_convert_u32 ((hex1 >> 24) & 0xff) <<  0;

  return (v);
}

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
  if (len != 64) return false;

  u32 e = 0;

  for (u32 i = 0; i < 16; i++)
  {
    if (is_valid_hex_32 (w[i]) != 0) continue;

    e = 1;

    break;
  }

  if (e == 1) return false;

  u32 tmp[16] = { 0 };

  for (u32 i = 0, j = 0; i < 8; i += 1, j += 2)
  {
    tmp[i] = hex_u32_to_u32 (w[j + 0], w[j + 1]);
  }

  u32 prv_key[9] = { 0 };

  prv_key[0] = tmp[7];
  prv_key[1] = tmp[6];
  prv_key[2] = tmp[5];
  prv_key[3] = tmp[4];
  prv_key[4] = tmp[3];
  prv_key[5] = tmp[2];
  prv_key[6] = tmp[1];
  prv_key[7] = tmp[0];

  u32 x[8] = { 0 };
  u32 y[8] = { 0 };

  point_mul_xy (x, y, prv_key, &hc->preG);

  u32 pub_key[32] = { 0 };

  pub_key[16] =               (y[0] << 24);
  pub_key[15] = (y[0] >> 8) | (y[1] << 24);
  pub_key[14] = (y[1] >> 8) | (y[2] << 24);
  pub_key[13] = (y[2] >> 8) | (y[3] << 24);
  pub_key[12] = (y[3] >> 8) | (y[4] << 24);
  pub_key[11] = (y[4] >> 8) | (y[5] << 24);
  pub_key[10] = (y[5] >> 8) | (y[6] << 24);
  pub_key[ 9] = (y[6] >> 8) | (y[7] << 24);
  pub_key[ 8] = (y[7] >> 8) | (x[0] << 24);
  pub_key[ 7] = (x[0] >> 8) | (x[1] << 24);
  pub_key[ 6] = (x[1] >> 8) | (x[2] << 24);
  pub_key[ 5] = (x[2] >> 8) | (x[3] << 24);
  pub_key[ 4] = (x[3] >> 8) | (x[4] << 24);
  pub_key[ 3] = (x[4] >> 8) | (x[5] << 24);
  pub_key[ 2] = (x[5] >> 8) | (x[6] << 24);
  pub_key[ 1] = (x[6] >> 8) | (x[7] << 24);
  pub_key[ 0] = (x[7] >> 8) | (0x04000000);

  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, pub_key, 65);
  sha256_final  (&ctx);

  for (u32 i = 0; i < 8; i++) tmp[i] = ctx.h[i];

  for (u32 i = 8; i < 16; i++) tmp[i] = 0;

  ripemd160_ctx_t rctx;

  ripemd160_init        (&rctx);
  ripemd160_update_swap (&rctx, tmp, 32);
  ripemd160_final       (&rctx);

  tmp[0] = (rctx.h[0] << 16) | (         0x1400);
  tmp[1] = (rctx.h[1] << 16) | (rctx.h[0] >> 16);
  tmp[2] = (rctx.h[2] << 16) | (rctx.h[1] >> 16);
  tmp[3] = (rctx.h[3] << 16) | (rctx.h[2] >> 16);
  tmp[4] = (rctx.h[4] << 16) | (rctx.h[3] >> 16);
  tmp[5] =                     (rctx.h[4] >> 16);

  for (u32 i = 6; i < 16; i++) tmp[i] = 0;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, tmp, 22);
  sha256_final       (&ctx);

  for (u32 i = 0; i <  8; i++) tmp[i] = ctx.h[i];

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

#define PCFG_KERNEL_MXX m30906_mxx
#define PCFG_KERNEL_SXX m30906_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
