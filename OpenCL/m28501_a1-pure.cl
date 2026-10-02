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
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

KERNEL_FQ KERNEL_FA void m28501_mxx (KERN_ATTR_BASIC ())
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

  u32 w[13] = { 0 }; // 52 bytes needed

  // for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  for (u32 idx = 0; idx < 13; idx++)
  {
    w[idx] = pws[gid].i[idx];
  }

  // The candidate starts with the base word in every attack mode but -a 12, which may put a piece of
  // mask in front of it. The same test on the assembled candidate is inside the loop below.

  if ((pw_len > 3) && (COMBS_IS_MIDDLE == 0))
  {
    const u32 b = hc_swap32_S (w[0]);

    if ((b < 0x4b774469) ||       // 'KwDi'
        (b > 0x4c356f4c)) return; // 'L5oL'
  }

  const bool status_base58 = is_valid_base58 (w, 0, pw_len);

  if (status_base58 != true) return;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_len_S (combs_buf, il_pos, COMBS_MODE);

    if ((pw_len + comb_len) != 52) continue;

    u32 c[64] = { 0 };

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    const u32 b = hc_swap32_S (c[0]);

    if ((b < 0x4b774469) ||         // 'KwDi'
        (b > 0x4c356f4c)) continue; // 'L5oL'

    // -a 12 does not put the base word at the front, so the check that ran outside this loop no
    // longer covers a prefix and the whole candidate has to be checked here.

    const u32 base58_off = (COMBS_IS_MIDDLE) ? 0 : pw_len;

    const bool status_base58 = is_valid_base58 (c, base58_off, 52);

    if (status_base58 != true) continue;


    // convert password from b58 to binary

    u32 tmp[16] = { 0 };

    const bool status_dec = b58dec_52 (tmp, c);

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

    secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

    set_precomputed_basepoint_g (&preG);

    point_mul_xy (x, y, prv_key, &preG);

    // to the address hash

    u32 h160[5];

    hash160_pubkey_compressed (h160, x, y);

    const u32 r0 = h160[0];
    const u32 r1 = h160[1];
    const u32 r2 = h160[2];
    const u32 r3 = h160[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m28501_sxx (KERN_ATTR_BASIC ())
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

  u32 w[13] = { 0 }; // 52 bytes needed

  // for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  for (u32 idx = 0; idx < 13; idx++)
  {
    w[idx] = pws[gid].i[idx];
  }

  // The candidate starts with the base word in every attack mode but -a 12, which may put a piece of
  // mask in front of it. The same test on the assembled candidate is inside the loop below.

  if ((pw_len > 3) && (COMBS_IS_MIDDLE == 0))
  {
    const u32 b = hc_swap32_S (w[0]);

    if ((b < 0x4b774469) ||       // 'KwDi'
        (b > 0x4c356f4c)) return; // 'L5oL'
  }

  const bool status_base58 = is_valid_base58 (w, 0, pw_len);

  if (status_base58 != true) return;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_len_S (combs_buf, il_pos, COMBS_MODE);

    if ((pw_len + comb_len) != 52) continue;

    u32 c[64] = { 0 };

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    const u32 b = hc_swap32_S (c[0]);

    if ((b < 0x4b774469) ||         // 'KwDi'
        (b > 0x4c356f4c)) continue; // 'L5oL'

    // -a 12 does not put the base word at the front, so the check that ran outside this loop no
    // longer covers a prefix and the whole candidate has to be checked here.

    const u32 base58_off = (COMBS_IS_MIDDLE) ? 0 : pw_len;

    const bool status_base58 = is_valid_base58 (c, base58_off, 52);

    if (status_base58 != true) continue;


    // convert password from b58 to binary

    u32 tmp[16] = { 0 };

    const bool status_dec = b58dec_52 (tmp, c);

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

    secp256k1_t preG; // need to change SECP256K1_TMPS_TYPE above to: PRIVATE_AS

    set_precomputed_basepoint_g (&preG);

    point_mul_xy (x, y, prv_key, &preG);

    // to the address hash

    u32 h160[5];

    hash160_pubkey_compressed (h160, x, y);

    const u32 r0 = h160[0];
    const u32 r1 = h160[1];
    const u32 r2 = h160[2];
    const u32 r3 = h160[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
