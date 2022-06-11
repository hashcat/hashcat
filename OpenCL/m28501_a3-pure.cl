/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

// #define SECP256K1_TMPS_TYPE CONSTANT_AS
#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

// or use set_precomputed_basepoint_g () instead:
// (set SECP256K1_TMPS_TYPE to CONSTANT_AS above:)

// CONSTANT_AS const secp256k1_t preG =
// {
//   {
//     SECP256K1_G_PRE_COMPUTED_00, SECP256K1_G_PRE_COMPUTED_01, SECP256K1_G_PRE_COMPUTED_02,
//     SECP256K1_G_PRE_COMPUTED_03, SECP256K1_G_PRE_COMPUTED_04, SECP256K1_G_PRE_COMPUTED_05,
//     SECP256K1_G_PRE_COMPUTED_06, SECP256K1_G_PRE_COMPUTED_07, SECP256K1_G_PRE_COMPUTED_08,
//     SECP256K1_G_PRE_COMPUTED_09, SECP256K1_G_PRE_COMPUTED_10, SECP256K1_G_PRE_COMPUTED_11,
//     SECP256K1_G_PRE_COMPUTED_12, SECP256K1_G_PRE_COMPUTED_13, SECP256K1_G_PRE_COMPUTED_14,
//     SECP256K1_G_PRE_COMPUTED_15, SECP256K1_G_PRE_COMPUTED_16, SECP256K1_G_PRE_COMPUTED_17,
//     SECP256K1_G_PRE_COMPUTED_18, SECP256K1_G_PRE_COMPUTED_19, SECP256K1_G_PRE_COMPUTED_20,
//     SECP256K1_G_PRE_COMPUTED_21, SECP256K1_G_PRE_COMPUTED_22, SECP256K1_G_PRE_COMPUTED_23,
//     SECP256K1_G_PRE_COMPUTED_24, SECP256K1_G_PRE_COMPUTED_25, SECP256K1_G_PRE_COMPUTED_26,
//     SECP256K1_G_PRE_COMPUTED_27, SECP256K1_G_PRE_COMPUTED_28, SECP256K1_G_PRE_COMPUTED_29,
//     SECP256K1_G_PRE_COMPUTED_30, SECP256K1_G_PRE_COMPUTED_31, SECP256K1_G_PRE_COMPUTED_32,
//     SECP256K1_G_PRE_COMPUTED_33, SECP256K1_G_PRE_COMPUTED_34, SECP256K1_G_PRE_COMPUTED_35,
//     SECP256K1_G_PRE_COMPUTED_36, SECP256K1_G_PRE_COMPUTED_37, SECP256K1_G_PRE_COMPUTED_38,
//     SECP256K1_G_PRE_COMPUTED_39, SECP256K1_G_PRE_COMPUTED_40, SECP256K1_G_PRE_COMPUTED_41,
//     SECP256K1_G_PRE_COMPUTED_42, SECP256K1_G_PRE_COMPUTED_43, SECP256K1_G_PRE_COMPUTED_44,
//     SECP256K1_G_PRE_COMPUTED_45, SECP256K1_G_PRE_COMPUTED_46, SECP256K1_G_PRE_COMPUTED_47,
//     SECP256K1_G_PRE_COMPUTED_48, SECP256K1_G_PRE_COMPUTED_49, SECP256K1_G_PRE_COMPUTED_50,
//     SECP256K1_G_PRE_COMPUTED_51, SECP256K1_G_PRE_COMPUTED_52, SECP256K1_G_PRE_COMPUTED_53,
//     SECP256K1_G_PRE_COMPUTED_54, SECP256K1_G_PRE_COMPUTED_55, SECP256K1_G_PRE_COMPUTED_56,
//     SECP256K1_G_PRE_COMPUTED_57, SECP256K1_G_PRE_COMPUTED_58, SECP256K1_G_PRE_COMPUTED_59,
//     SECP256K1_G_PRE_COMPUTED_60, SECP256K1_G_PRE_COMPUTED_61, SECP256K1_G_PRE_COMPUTED_62,
//     SECP256K1_G_PRE_COMPUTED_63, SECP256K1_G_PRE_COMPUTED_64, SECP256K1_G_PRE_COMPUTED_65,
//     SECP256K1_G_PRE_COMPUTED_66, SECP256K1_G_PRE_COMPUTED_67, SECP256K1_G_PRE_COMPUTED_68,
//     SECP256K1_G_PRE_COMPUTED_69, SECP256K1_G_PRE_COMPUTED_70, SECP256K1_G_PRE_COMPUTED_71,
//     SECP256K1_G_PRE_COMPUTED_72, SECP256K1_G_PRE_COMPUTED_73, SECP256K1_G_PRE_COMPUTED_74,
//     SECP256K1_G_PRE_COMPUTED_75, SECP256K1_G_PRE_COMPUTED_76, SECP256K1_G_PRE_COMPUTED_77,
//     SECP256K1_G_PRE_COMPUTED_78, SECP256K1_G_PRE_COMPUTED_79, SECP256K1_G_PRE_COMPUTED_80,
//     SECP256K1_G_PRE_COMPUTED_81, SECP256K1_G_PRE_COMPUTED_82, SECP256K1_G_PRE_COMPUTED_83,
//     SECP256K1_G_PRE_COMPUTED_84, SECP256K1_G_PRE_COMPUTED_85, SECP256K1_G_PRE_COMPUTED_86,
//     SECP256K1_G_PRE_COMPUTED_87, SECP256K1_G_PRE_COMPUTED_88, SECP256K1_G_PRE_COMPUTED_89,
//     SECP256K1_G_PRE_COMPUTED_90, SECP256K1_G_PRE_COMPUTED_91, SECP256K1_G_PRE_COMPUTED_92,
//     SECP256K1_G_PRE_COMPUTED_93, SECP256K1_G_PRE_COMPUTED_94, SECP256K1_G_PRE_COMPUTED_95,
//   }
// };

KERNEL_FQ void m28501_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;


  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len != 52) return;


  // copy password to w

  u32 w[13]; // 52 bytes needed

  for (u32 i = 0; i < 13; i++) // pw_len / 4
  {
    w[i] = pws[gid].i[i];
  }

  const bool status_base58 = is_valid_base58 (w, 4, 52);

  if (status_base58 != true) return;

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);


  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0 = w0l | w0r;

    w[0] = w0;

    const u32 b = hc_swap32_S (w[0]);

    if ((b < 0x4b774469) ||         // 'KwDi'
        (b > 0x4c356f4c)) continue; // 'L5oL'

    const bool status_base58 = is_valid_base58 (w, 0, 4);

    if (status_base58 != true) continue;


    // convert password from b58 to binary

    u32 tmp[16] = { 0 };

    const bool status_dec = b58dec_52 (tmp, w);

    if (status_dec != true) continue;


    // check for bitcoin main network identifier:

    if ((tmp[0] & 0xff000000) != 0x80000000) continue;


    // check that compression is enabled:

    if ((tmp[8] & 0x00ff0000) != 0x00010000) continue; // 33th byte


    // verify sha256 (sha256 (tmp[0..38 - 4]))
    // real work is done in b58check where sha256 is run twice

    const bool status_check = b58check_38 (tmp); // length is 34 (+ 4 checksum bytes)

    if (status_check != true) continue;


    u32 prv_key[9]; // why is re-using the "tmp" variable here slower ?

    prv_key[0] = (tmp[7] << 8) | (tmp[8] >> 24);
    prv_key[1] = (tmp[6] << 8) | (tmp[7] >> 24);
    prv_key[2] = (tmp[5] << 8) | (tmp[6] >> 24);
    prv_key[3] = (tmp[4] << 8) | (tmp[5] >> 24);
    prv_key[4] = (tmp[3] << 8) | (tmp[4] >> 24);
    prv_key[5] = (tmp[2] << 8) | (tmp[3] >> 24);
    prv_key[6] = (tmp[1] << 8) | (tmp[2] >> 24);
    prv_key[7] = (tmp[0] << 8) | (tmp[1] >> 24);


    // convert: pub_key = G * prv_key

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, prv_key, &preG);


    // to public key:

    u32 pub_key[16] = { 0 }; // why is re-using the "tmp" variable here slower ?

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


    // calculate HASH160 for pub key

    sha256_ctx_t ctx;

    sha256_init   (&ctx);
    sha256_update (&ctx, pub_key, 33); // length of public key: 33
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

    const u32 r0 = rctx.h[0];
    const u32 r1 = rctx.h[1];
    const u32 r2 = rctx.h[2];
    const u32 r3 = rctx.h[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28501_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len != 52) return;


  // copy password to w

  u32 w[13]; // 52 bytes needed

  for (u32 i = 0; i < 13; i++) // pw_len / 4
  {
    w[i] = pws[gid].i[i];
  }

  const bool status_base58 = is_valid_base58 (w, 4, 52);

  if (status_base58 != true) return;

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);


  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0 = w0l | w0r;

    w[0] = w0;

    const u32 b = hc_swap32_S (w[0]);

    if ((b < 0x4b774469) ||         // 'KwDi'
        (b > 0x4c356f4c)) continue; // 'L5oL'

    const bool status_base58 = is_valid_base58 (w, 0, 4);

    if (status_base58 != true) continue;


    // convert password from b58 to binary

    u32 tmp[16] = { 0 };

    const bool status_dec = b58dec_52 (tmp, w);

    if (status_dec != true) continue;


    // check for bitcoin main network identifier:

    if ((tmp[0] & 0xff000000) != 0x80000000) continue;


    // check that compression is enabled:

    if ((tmp[8] & 0x00ff0000) != 0x00010000) continue; // 33th byte


    // verify sha256 (sha256 (tmp[0..38 - 4]))
    // real work is done in b58check where sha256 is run twice

    const bool status_check = b58check_38 (tmp); // length is 34 (+ 4 checksum bytes)

    if (status_check != true) continue;


    u32 prv_key[9]; // why is re-using the "tmp" variable here slower ?

    prv_key[0] = (tmp[7] << 8) | (tmp[8] >> 24);
    prv_key[1] = (tmp[6] << 8) | (tmp[7] >> 24);
    prv_key[2] = (tmp[5] << 8) | (tmp[6] >> 24);
    prv_key[3] = (tmp[4] << 8) | (tmp[5] >> 24);
    prv_key[4] = (tmp[3] << 8) | (tmp[4] >> 24);
    prv_key[5] = (tmp[2] << 8) | (tmp[3] >> 24);
    prv_key[6] = (tmp[1] << 8) | (tmp[2] >> 24);
    prv_key[7] = (tmp[0] << 8) | (tmp[1] >> 24);


    // convert: pub_key = G * prv_key

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, prv_key, &preG);


    // to public key:

    u32 pub_key[16] = { 0 }; // why is re-using the "tmp" variable here slower ?

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


    // calculate HASH160 for pub key

    sha256_ctx_t ctx;

    sha256_init   (&ctx);
    sha256_update (&ctx, pub_key, 33); // length of public key: 33
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

    const u32 r0 = rctx.h[0];
    const u32 r1 = rctx.h[1];
    const u32 r2 = rctx.h[2];
    const u32 r3 = rctx.h[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
