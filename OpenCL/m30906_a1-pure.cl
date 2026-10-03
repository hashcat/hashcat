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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
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

KERNEL_FQ KERNEL_FA void m30906_mxx (KERN_ATTR_BASIC ())
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

  // copy password to w

  u32 w[16] = { 0 };

  for (u32 idx = 0; idx < 16; idx++)
  {
    w[idx] = pws[gid].i[idx];
  }

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_len_S (combs_buf, il_pos, COMBS_MODE);

    if ((pw_len + comb_len) != 64) continue;

    u32 c[64] = { 0 };

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    u32 e = 0;

    for (u32 i = 0; i < 16; i++)
    {
      if (is_valid_hex_32 (c[i]) != 0) continue;

      e = 1;

      break;
    }

    if (e == 1) continue; // not a valid hex

    // convert password from hex to binary

    u32 tmp[16] = { 0 };

    for (u32 i = 0, j = 0; i < 8; i += 1, j += 2)
    {
      tmp[i] = hex_u32_to_u32 (c[j + 0], c[j + 1]);
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

    // convert: pub_key = G * prv_key

    u32 x[8] = { 0 };
    u32 y[8] = { 0 };

    point_mul_xy (x, y, prv_key, &preG);

    // to the address hash, by way of the P2SH redeem script wrapping the P2WPKH

    u32 h160[5];
    u32 script_h160[5];

    hash160_pubkey_uncompressed (h160, x, y);
    hash160_p2sh_p2wpkh (script_h160, h160);

    const u32 r0 = script_h160[0];
    const u32 r1 = script_h160[1];
    const u32 r2 = script_h160[2];
    const u32 r3 = script_h160[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m30906_sxx (KERN_ATTR_BASIC ())
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

  // copy password to w

  u32 w[16] = { 0 };

  for (u32 idx = 0; idx < 16; idx++)
  {
    w[idx] = pws[gid].i[idx];
  }

  secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

  set_precomputed_basepoint_g (&preG);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_len_S (combs_buf, il_pos, COMBS_MODE);

    if ((pw_len + comb_len) != 64) continue;

    u32 c[64] = { 0 };

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    u32 e = 0;

    for (u32 i = 0; i < 16; i++)
    {
      if (is_valid_hex_32 (c[i]) != 0) continue;

      e = 1;

      break;
    }

    if (e == 1) continue; // not a valid hex

    // convert password from hex to binary

    u32 tmp[16] = { 0 };

    for (u32 i = 0, j = 0; i < 8; i += 1, j += 2)
    {
      tmp[i] = hex_u32_to_u32 (c[j + 0], c[j + 1]);
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

    // convert: pub_key = G * prv_key

    u32 x[8] = { 0 };
    u32 y[8] = { 0 };

    point_mul_xy (x, y, prv_key, &preG);

    // to the address hash, by way of the P2SH redeem script wrapping the P2WPKH

    u32 h160[5];
    u32 script_h160[5];

    hash160_pubkey_uncompressed (h160, x, y);
    hash160_p2sh_p2wpkh (script_h160, h160);

    const u32 r0 = script_h160[0];
    const u32 r1 = script_h160[1];
    const u32 r2 = script_h160[2];
    const u32 r3 = script_h160[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
