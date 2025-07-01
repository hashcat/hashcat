/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
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

KERNEL_FQ KERNEL_FA void m30906_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;


  /**
   * base
   */

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);

  COPY_PW (pws[gid]);


  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t p = PASTE_PW;

    p.pw_len = apply_rules (rules_buf[il_pos].cmds, p.i, p.pw_len);

    if (p.pw_len != 64) continue;

    for (u32 i = 0; i < 16; i++)
    {
      if (is_valid_hex_32 (p.i[i]) == 0) continue;
    }


    // convert password from hex to binary

    u32 tmp[16] = { 0 };

    for (u32 i = 0, j = 0; i < 8; i += 1, j += 2)
    {
      tmp[i] = hex_u32_to_u32 (p.i[j + 0], p.i[j + 1]);
    }

    u32 prv_key[9];

    prv_key[0] = tmp[7];
    prv_key[1] = tmp[6];
    prv_key[2] = tmp[5];
    prv_key[3] = tmp[4];
    prv_key[4] = tmp[3];
    prv_key[5] = tmp[2];
    prv_key[6] = tmp[1];
    prv_key[7] = tmp[0];


    // convert: pub_key = G * prv_key

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, prv_key, &preG);


    // to public key:

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


    // calculate HASH160 for pub key

    sha256_ctx_t ctx;

    sha256_init   (&ctx);
    sha256_update (&ctx, pub_key, 65); // length of public key: 65
    sha256_final  (&ctx);

    for (u32 i = 0; i < 8; i++) tmp[i] = ctx.h[i];

    // tmp[ 8] = 0; tmp[ 9] = 0; tmp[10] = 0; tmp[11] = 0;
    // tmp[12] = 0; tmp[13] = 0; tmp[14] = 0; tmp[15] = 0;

    for (u32 i = 8; i < 16; i++) tmp[i] = 0;


    // now let's do RIPEMD-160 on the sha256sum

    ripemd160_ctx_t rctx;

    ripemd160_init        (&rctx);
    ripemd160_update_swap (&rctx, tmp, 32);
    ripemd160_final       (&rctx);


    /*
     * 2nd RIPEMD160 (SHA256 ()):
     */

    tmp[0] = (rctx.h[0] << 16) | (         0x1400); // (swapped) OP_0 operation (0x00),
    tmp[1] = (rctx.h[1] << 16) | (rctx.h[0] >> 16); // 0x14 == 20, this indicates the
    tmp[2] = (rctx.h[2] << 16) | (rctx.h[1] >> 16); // data len
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

    const u32 r0 = rctx.h[0];
    const u32 r1 = rctx.h[1];
    const u32 r2 = rctx.h[2];
    const u32 r3 = rctx.h[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m30906_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;


  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };


  /**
   * base
   */

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);

  COPY_PW (pws[gid]);


  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t p = PASTE_PW;

    p.pw_len = apply_rules (rules_buf[il_pos].cmds, p.i, p.pw_len);

    if (p.pw_len != 64) continue;

    for (u32 i = 0; i < 16; i++)
    {
      if (is_valid_hex_32 (p.i[i]) == 0) continue;
    }


    // convert password from hex to binary

    u32 tmp[16] = { 0 };

    for (u32 i = 0, j = 0; i < 8; i += 1, j += 2)
    {
      tmp[i] = hex_u32_to_u32 (p.i[j + 0], p.i[j + 1]);
    }

    u32 prv_key[9];

    prv_key[0] = tmp[7];
    prv_key[1] = tmp[6];
    prv_key[2] = tmp[5];
    prv_key[3] = tmp[4];
    prv_key[4] = tmp[3];
    prv_key[5] = tmp[2];
    prv_key[6] = tmp[1];
    prv_key[7] = tmp[0];


    // convert: pub_key = G * prv_key

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, prv_key, &preG);


    // to public key:

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


    // calculate HASH160 for pub key

    sha256_ctx_t ctx;

    sha256_init   (&ctx);
    sha256_update (&ctx, pub_key, 65); // length of public key: 65
    sha256_final  (&ctx);

    for (u32 i = 0; i < 8; i++) tmp[i] = ctx.h[i];

    // tmp[ 8] = 0; tmp[ 9] = 0; tmp[10] = 0; tmp[11] = 0;
    // tmp[12] = 0; tmp[13] = 0; tmp[14] = 0; tmp[15] = 0;

    for (u32 i = 8; i < 16; i++) tmp[i] = 0;


    // now let's do RIPEMD-160 on the sha256sum

    ripemd160_ctx_t rctx;

    ripemd160_init        (&rctx);
    ripemd160_update_swap (&rctx, tmp, 32);
    ripemd160_final       (&rctx);


    /*
     * 2nd RIPEMD160 (SHA256 ()):
     */

    tmp[0] = (rctx.h[0] << 16) | (         0x1400); // (swapped) OP_0 operation (0x00),
    tmp[1] = (rctx.h[1] << 16) | (rctx.h[0] >> 16); // 0x14 == 20, this indicates the
    tmp[2] = (rctx.h[2] << 16) | (rctx.h[1] >> 16); // data len
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

    const u32 r0 = rctx.h[0];
    const u32 r1 = rctx.h[1];
    const u32 r2 = rctx.h[2];
    const u32 r3 = rctx.h[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
