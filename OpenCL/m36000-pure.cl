/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE
#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

DECLSPEC u8 bip39_pw_get_byte (GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 idx)
{
  const u32 word = pws_local[gid_local].i[idx >> 2];
  const u32 shift = (idx & 3u) << 3;

  return (u8) (word >> shift);
}

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define BIP39_MAX_PATH_DEPTH 16u
#define BIP39_TARGET_IL_HEX  0u
#define BIP39_TARGET_P2SH    1u
#define BIP39_TARGET_P2PKH   2u
#define BIP39_TARGET_P2WPKH  3u
#define BIP39_PATH_KIND_FIXED   0u
#define BIP39_PATH_KIND_DYNAMIC 1u
#define BIP39_DYNAMIC_KIND_RANGE 0u
#define BIP39_DYNAMIC_KIND_LIST  1u
#define BIP39_MAX_DYNAMIC_SEGMENTS      4u
#define BIP39_MAX_DYNAMIC_VALUES        256u
#define BIP39_MAX_DYNAMIC_RANGE_SPAN  4096u

typedef struct bip39_dynamic_segment
{
  u32 position;
  u32 kind;
  u32 count;
  u32 start;
  u32 end;
  u32 step;
  u32 values_offset;
} bip39_dynamic_segment_t;

typedef struct bip39_skeleton
{
  u32 mnemonic_len;
  u32 address_len;
  u32 path_len;
  u32 path_depth;
  u32 target_type;
  u32 reserved;

  u32 path_indices[BIP39_MAX_PATH_DEPTH];
  u32 path_kind[BIP39_MAX_PATH_DEPTH];
  u32 path_dynamic_count;
  u32 dynamic_value_total;
  u64 path_combo_total;
  bip39_dynamic_segment_t dynamic_segments[BIP39_MAX_DYNAMIC_SEGMENTS];
  u32 dynamic_values[BIP39_MAX_DYNAMIC_VALUES];
  u32 target_hash[5];

  u8 mnemonic[1024];
  u8 address[64];
  u8 path[64];
  u32 mnemonic_raw_len;
  u8 mnemonic_raw[1024];

} bip39_skeleton_t;

#define BIP39_MAX_HITS 16u

typedef struct bip39_tmp
{
  u64 master[8];

  u32 prefix_key[8];
  u32 prefix_chain[8];

  // The combination indices whose address matched a digest. Only the first BIP39_MAX_HITS are
  // kept, but hit_cnt counts every one of them, so a candidate reaching more addresses than that
  // sends the comp kernel around the whole range again rather than losing a match. That costs one
  // work item the whole range, so the slot count is set well past what a hash file holds.
  u32 hit[BIP39_MAX_HITS];
  u32 hit_cnt;

  u32 valid;

} bip39_tmp_t;

#define BIP39_SALT_PREFIX_LEN        8u
#define BIP39_MAX_PASSPHRASE_LEN   256u
#define BIP39_PBKDF2_ROUNDS       2048u
#define BIP39_SALT_WORDS         ((BIP39_SALT_PREFIX_LEN + BIP39_MAX_PASSPHRASE_LEN + 4u + 3u) / 4u)

// Packs a byte buffer into the big-endian words the shared sha512 code reads. dst_words has to be
// at least ceil (len / 4) for the length later handed to the update, since a shared updater reads
// one word per four bytes of the length it is given.

DECLSPEC void bip39_bytes_to_words_be (PRIVATE_AS const u8 *src, const u32 len, PRIVATE_AS u32 *dst, const u32 dst_words)
{
  for (u32 i = 0; i < dst_words; i++)
  {
    dst[i] = 0;
  }

  for (u32 i = 0; i < len; i++)
  {
    const u32 word_idx = i / 4;
    const u32 shift = (3 - (i % 4)) * 8;

    dst[word_idx] |= ((u32) src[i]) << shift;
  }
}

DECLSPEC void bip39_u64_to_words_be (PRIVATE_AS const u64 *src, const u32 cnt, PRIVATE_AS u32 *dst)
{
  for (u32 i = 0; i < cnt; i++)
  {
    dst[(i * 2) + 0] = h32_from_64_S (src[i]);
    dst[(i * 2) + 1] = l32_from_64_S (src[i]);
  }
}

DECLSPEC void bip39_u64_to_bytes_be (PRIVATE_AS const u64 *src, PRIVATE_AS u8 *dst)
{
  for (u32 i = 0; i < 8; i++)
  {
    const u64 word = src[i];

    dst[(i * 8) + 0] = (u8) (word >> 56);
    dst[(i * 8) + 1] = (u8) (word >> 48);
    dst[(i * 8) + 2] = (u8) (word >> 40);
    dst[(i * 8) + 3] = (u8) (word >> 32);
    dst[(i * 8) + 4] = (u8) (word >> 24);
    dst[(i * 8) + 5] = (u8) (word >> 16);
    dst[(i * 8) + 6] = (u8) (word >> 8);
    dst[(i * 8) + 7] = (u8) (word >> 0);
  }
}

// PBKDF2-HMAC-SHA512 over the mnemonic as the password and "mnemonic" followed by the passphrase
// as the salt, 2048 rounds and a single output block, which is the BIP39 seed. The ipad and opad
// states depend only on the mnemonic, so they are computed once and every round starts from a copy.

DECLSPEC void bip39_pbkdf2_seed (GLOBAL_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, PRIVATE_AS const u8 *passphrase_bytes, const u32 passphrase_len, PRIVATE_AS u64 *seed)
{
  sha512_hmac_ctx_t ctx_base;

  sha512_hmac_init_global_swap (&ctx_base, (GLOBAL_AS const u32 *) mnemonic_bytes, mnemonic_len);

  const u8 prefix[BIP39_SALT_PREFIX_LEN] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };

  PRIVATE_AS u8 salt_bytes[BIP39_SALT_PREFIX_LEN + BIP39_MAX_PASSPHRASE_LEN + 4];

  for (u32 i = 0; i < BIP39_SALT_PREFIX_LEN; i++)
  {
    salt_bytes[i] = prefix[i];
  }

  for (u32 i = 0; i < passphrase_len; i++)
  {
    salt_bytes[BIP39_SALT_PREFIX_LEN + i] = passphrase_bytes[i];
  }

  const u32 salt_len = BIP39_SALT_PREFIX_LEN + passphrase_len;

  salt_bytes[salt_len + 0] = 0;
  salt_bytes[salt_len + 1] = 0;
  salt_bytes[salt_len + 2] = 0;
  salt_bytes[salt_len + 3] = 1;

  PRIVATE_AS u32 salt_words[BIP39_SALT_WORDS];

  bip39_bytes_to_words_be (salt_bytes, salt_len + 4, salt_words, BIP39_SALT_WORDS);

  sha512_hmac_ctx_t ctx = ctx_base;

  sha512_hmac_update (&ctx, salt_words, salt_len + 4);
  sha512_hmac_final (&ctx);

  PRIVATE_AS u64 carry[8];

  for (u32 i = 0; i < 8; i++)
  {
    carry[i] = ctx.opad.h[i];
    seed[i]  = ctx.opad.h[i];
  }

  for (u32 round = 1; round < BIP39_PBKDF2_ROUNDS; round++)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    PRIVATE_AS u32 carry_words[16];

    bip39_u64_to_words_be (carry, 8, carry_words);

    for (u32 i = 0; i < 4; i++)
    {
      w0[i] = carry_words[0 + i];
      w1[i] = carry_words[4 + i];
      w2[i] = carry_words[8 + i];
      w3[i] = carry_words[12 + i];

      w4[i] = 0;
      w5[i] = 0;
      w6[i] = 0;
      w7[i] = 0;
    }

    sha512_hmac_ctx_t ctx_round = ctx_base;

    sha512_hmac_update_128 (&ctx_round, w0, w1, w2, w3, w4, w5, w6, w7, 64);
    sha512_hmac_final (&ctx_round);

    for (u32 i = 0; i < 8; i++)
    {
      carry[i] = ctx_round.opad.h[i];
      seed[i] ^= ctx_round.opad.h[i];
    }
  }
}

// The BIP32 master key and chain code are HMAC-SHA512 of the seed under the fixed key
// "Bitcoin seed".

DECLSPEC void bip39_derive_bip32_master (PRIVATE_AS const u64 *seed, PRIVATE_AS u64 *master)
{
  const u8 key_bytes[12] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };

  PRIVATE_AS u32 key_words[3];

  bip39_bytes_to_words_be (key_bytes, 12, key_words, 3);

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init (&ctx, key_words, 12);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  PRIVATE_AS u32 seed_words[16];

  bip39_u64_to_words_be (seed, 8, seed_words);

  for (u32 i = 0; i < 4; i++)
  {
    w0[i] = seed_words[0 + i];
    w1[i] = seed_words[4 + i];
    w2[i] = seed_words[8 + i];
    w3[i] = seed_words[12 + i];

    w4[i] = 0;
    w5[i] = 0;
    w6[i] = 0;
    w7[i] = 0;
  }

  sha512_hmac_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);
  sha512_hmac_final (&ctx);

  for (u32 i = 0; i < 8; i++)
  {
    master[i] = ctx.opad.h[i];
  }
}

DECLSPEC void bip39_words_le_to_bytes_be32 (PRIVATE_AS const u32 *src, PRIVATE_AS u8 *dst)
{
  for (u32 i = 0; i < 8; i++)
  {
    const u32 word = src[7 - i];

    dst[(i * 4) + 0] = (u8) (word >> 24);
    dst[(i * 4) + 1] = (u8) (word >> 16);
    dst[(i * 4) + 2] = (u8) (word >> 8);
    dst[(i * 4) + 3] = (u8) (word >> 0);
  }
}

DECLSPEC void bip39_bytes_be32_to_words_le (PRIVATE_AS const u8 *src, PRIVATE_AS u32 *dst)
{
  for (u32 i = 0; i < 8; i++)
  {
    const u32 offset = 28u - (i * 4u);

    dst[i] = ((u32) src[offset + 0] << 24) | ((u32) src[offset + 1] << 16) | ((u32) src[offset + 2] << 8) | ((u32) src[offset + 3] << 0);
  }
}

DECLSPEC u32 bip39_il_ge_curve_n (PRIVATE_AS const u8 *il_bytes)
{
  const u32 curve_n_be[8] = {
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xfffffffe,
    0xbaaedce6,
    0xaf48a03b,
    0xbfd25e8c,
    0xd0364141
  };

  u32 il_be[8];

  for (u32 i = 0; i < 8; i++)
  {
    const u32 offset = i * 4;

    il_be[i] = ((u32) il_bytes[offset + 0] << 24) | ((u32) il_bytes[offset + 1] << 16) | ((u32) il_bytes[offset + 2] << 8) | ((u32) il_bytes[offset + 3] << 0);
  }

  for (u32 i = 0; i < 8; i++)
  {
    if (il_be[i] > curve_n_be[i]) return 1;
    if (il_be[i] < curve_n_be[i]) return 0;
  }

  return 1;
}

DECLSPEC void bip39_add_mod_n (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
{
  const u32 curve_n[8] = {
    SECP256K1_N0,
    SECP256K1_N1,
    SECP256K1_N2,
    SECP256K1_N3,
    SECP256K1_N4,
    SECP256K1_N5,
    SECP256K1_N6,
    SECP256K1_N7
  };

  u64 carry = 0;

  for (u32 i = 0; i < 8; i++)
  {
    const u64 sum = (u64) a[i] + (u64) b[i] + carry;

    r[i] = (u32) sum;
    carry = sum >> 32;
  }

  u32 reduce = (carry != 0);

  if (reduce == 0)
  {
    // A sum equal to the order has to reduce as well, so the flag starts set and only a limb that
    // is strictly smaller clears it. Starting from clear left r == n unreduced.

    reduce = 1;

    for (int i = 7; i >= 0; i--)
    {
      if (r[i] > curve_n[i]) break;

      if (r[i] < curve_n[i])
      {
        reduce = 0;

        break;
      }
    }
  }

  if (reduce == 1)
  {
    u64 borrow = 0;

    for (u32 i = 0; i < 8; i++)
    {
      const u64 diff = (u64) r[i] - (u64) curve_n[i] - borrow;

      r[i] = (u32) diff;
      borrow = (diff >> 63) & 1u;
    }
  }
}

DECLSPEC u32 bip39_scalar_is_zero (PRIVATE_AS const u32 *v)
{
  u32 acc = 0;

  for (u32 i = 0; i < 8; i++) acc |= v[i];

  return (acc == 0);
}

DECLSPEC void bip39_bip32_public_child_data (PRIVATE_AS u8 *data_bytes, PRIVATE_AS u32 *key_le, PRIVATE_AS secp256k1_t *preG)
{
  u32 x[8];
  u32 y[8];

  for (u32 i = 0; i < 8; i++)
  {
    x[i] = 0;
    y[i] = 0;
  }

  point_mul_xy (x, y, key_le, preG);

  data_bytes[0] = (y[0] & 1u) ? 0x03 : 0x02;

  bip39_words_le_to_bytes_be32 (x, data_bytes + 1);
}

DECLSPEC u32 bip39_bip32_child (const u32 index, PRIVATE_AS u32 *key_le, PRIVATE_AS u8 *key_bytes, PRIVATE_AS u8 *chain_bytes, PRIVATE_AS secp256k1_t *preG)
{
  PRIVATE_AS u8 data_bytes[37];

  if ((index & 0x80000000) != 0)
  {
    data_bytes[0] = 0;

    for (u32 i = 0; i < 32; i++) data_bytes[1 + i] = key_bytes[i];
  }
  else
  {
    bip39_bip32_public_child_data (data_bytes, key_le, preG);
  }

  data_bytes[33] = (u8) (index >> 24);
  data_bytes[34] = (u8) (index >> 16);
  data_bytes[35] = (u8) (index >> 8);
  data_bytes[36] = (u8) (index >> 0);

  PRIVATE_AS u8 hmac_bytes[64];

  PRIVATE_AS u32 chain_words[8];
  PRIVATE_AS u32 data_words[10];

  bip39_bytes_to_words_be (chain_bytes, 32u, chain_words, 8);
  bip39_bytes_to_words_be (data_bytes, 37u, data_words, 10);

  sha512_hmac_ctx_t hmac_ctx;

  sha512_hmac_init (&hmac_ctx, chain_words, 32);

  sha512_hmac_update (&hmac_ctx, data_words, 37);
  sha512_hmac_final (&hmac_ctx);

  bip39_u64_to_bytes_be (hmac_ctx.opad.h, hmac_bytes);

  PRIVATE_AS const u8 *il_bytes = hmac_bytes;
  PRIVATE_AS const u8 *ir_bytes = hmac_bytes + 32;

  if (bip39_il_ge_curve_n (il_bytes) == 1) return 0;

  PRIVATE_AS u32 il_le[8];

  bip39_bytes_be32_to_words_le (il_bytes, il_le);

  PRIVATE_AS u32 child_le[8];

  bip39_add_mod_n (child_le, key_le, il_le);

  if (bip39_scalar_is_zero (child_le) == 1) return 0;

  for (u32 i = 0; i < 8; i++) key_le[i] = child_le[i];

  bip39_words_le_to_bytes_be32 (key_le, key_bytes);

  for (u32 i = 0; i < 32; i++) chain_bytes[i] = ir_bytes[i];

  return 1;
}

// One combination of the dynamic path segments, derived from the prefix the init kernel left in
// tmps. Returns 0 when a child index lands outside the curve order, which BIP32 asks us to skip.

DECLSPEC u32 bip39_derive_combination (const u32 combo_idx, GLOBAL_AS const bip39_skeleton_t *skeleton, PRIVATE_AS const u32 *prefix_key, PRIVATE_AS const u32 *prefix_chain, PRIVATE_AS secp256k1_t *preG, PRIVATE_AS u32 *out_hash)
{
  const u32 path_depth  = skeleton->path_depth;
  const u32 dynamic_cnt = skeleton->path_dynamic_count;

  PRIVATE_AS u32 path_values[BIP39_MAX_PATH_DEPTH];

  for (u32 i = 0; i < path_depth; i++)
  {
    path_values[i] = skeleton->path_indices[i];
  }

  // Segment 0 is the least significant digit of the combination index. The host counts the
  // combinations in the same order when it works out how many there are.

  u32 rem = combo_idx;

  u32 prefix_len = path_depth;

  for (u32 d = 0; d < dynamic_cnt; d++)
  {
    const bip39_dynamic_segment_t segment = skeleton->dynamic_segments[d];

    const u32 digit = rem % segment.count;

    rem /= segment.count;

    const u32 value = (segment.kind == BIP39_DYNAMIC_KIND_RANGE) ? (segment.start + (digit * segment.step)) : skeleton->dynamic_values[segment.values_offset + digit];

    path_values[segment.position] = value;

    if (segment.position < prefix_len) prefix_len = segment.position;
  }

  PRIVATE_AS u32 key_le[8];

  for (u32 i = 0; i < 8; i++)
  {
    key_le[i] = prefix_key[i];
  }

  PRIVATE_AS u8 key_bytes[32];
  PRIVATE_AS u8 chain_bytes[32];

  bip39_words_le_to_bytes_be32 (key_le, key_bytes);
  bip39_words_le_to_bytes_be32 (prefix_chain, chain_bytes);

  for (u32 i = prefix_len; i < path_depth; i++)
  {
    if (bip39_bip32_child (path_values[i], key_le, key_bytes, chain_bytes, preG) == 0) return 0;
  }

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, key_le, preG);

  u32 h160[5];

  hash160_pubkey_compressed (h160, x, y);

  if (skeleton->target_type == BIP39_TARGET_P2SH)
  {
    hash160_p2sh_p2wpkh (out_hash, h160);

    return 1;
  }

  for (u32 i = 0; i < 5; i++)
  {
    out_hash[i] = h160[i];
  }

  return 1;
}

KERNEL_FQ KERNEL_FA void m36000_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].hit_cnt = 0;
  tmps[gid].valid   = 0;

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].master[i] = 0;
  }

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len > BIP39_MAX_PASSPHRASE_LEN) return;

  PRIVATE_AS u8 passphrase_buf[BIP39_MAX_PASSPHRASE_LEN];

  for (u32 i = 0; i < pw_len; i++)
  {
    passphrase_buf[i] = bip39_pw_get_byte (pws, gid, i);
  }

  PRIVATE_AS u64 seed[8];

  for (u32 i = 0; i < 8; i++)
  {
    seed[i] = 0;
  }

  bip39_pbkdf2_seed ((GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic, esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len, passphrase_buf, pw_len, seed);

  PRIVATE_AS u64 master[8];

  for (u32 i = 0; i < 8; i++)
  {
    master[i] = 0;
  }

  bip39_derive_bip32_master (seed, master);

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].master[i] = master[i];
  }

  const u32 target_type = esalt_bufs[DIGESTS_OFFSET_HOST].target_type;

  if (target_type == BIP39_TARGET_IL_HEX)
  {
    tmps[gid].valid = 1;

    return;
  }

  // Everything above the first dynamic path element is the same for every combination, so it is
  // derived once here and the loop kernel carries on from it.

  PRIVATE_AS u8 master_bytes[64];

  bip39_u64_to_bytes_be (master, master_bytes);

  PRIVATE_AS u8 key_bytes[32];
  PRIVATE_AS u8 chain_bytes[32];

  for (u32 i = 0; i < 32; i++)
  {
    key_bytes[i]   = master_bytes[i];
    chain_bytes[i] = master_bytes[32 + i];
  }

  PRIVATE_AS u32 key_le[8];

  bip39_bytes_be32_to_words_le (key_bytes, key_le);

  const u32 path_depth  = esalt_bufs[DIGESTS_OFFSET_HOST].path_depth;
  const u32 dynamic_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].path_dynamic_count;

  u32 prefix_len = path_depth;

  for (u32 d = 0; d < dynamic_cnt; d++)
  {
    const u32 position = esalt_bufs[DIGESTS_OFFSET_HOST].dynamic_segments[d].position;

    if (position < prefix_len) prefix_len = position;
  }

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  for (u32 i = 0; i < prefix_len; i++)
  {
    const u32 index = esalt_bufs[DIGESTS_OFFSET_HOST].path_indices[i];

    if (bip39_bip32_child (index, key_le, key_bytes, chain_bytes, &preG) == 0) return;
  }

  PRIVATE_AS u32 chain_le[8];

  bip39_bytes_be32_to_words_le (chain_bytes, chain_le);

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].prefix_key[i]   = key_le[i];
    tmps[gid].prefix_chain[i] = chain_le[i];
  }

  tmps[gid].valid = 1;
}

KERNEL_FQ KERNEL_FA void m36000_loop (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (tmps[gid].valid == 0) return;

  if (esalt_bufs[DIGESTS_OFFSET_HOST].target_type == BIP39_TARGET_IL_HEX) return;

  PRIVATE_AS u32 prefix_key[8];
  PRIVATE_AS u32 prefix_chain[8];

  for (u32 i = 0; i < 8; i++)
  {
    prefix_key[i]   = tmps[gid].prefix_key[i];
    prefix_chain[i] = tmps[gid].prefix_chain[i];
  }

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  // Same count the host put in salt_iter, read through the esalt because the self-test sets the
  // digest offset deliberately and leaves the salt position alone.

  const u32 combo_cnt = (u32) esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    const u32 combo_idx = LOOP_POS + j;

    // Autotune launches this kernel with the loop count it wants to time rather than the window
    // the keyspace actually has left, so the index can run past the end here.

    if (combo_idx >= combo_cnt) break;

    PRIVATE_AS u32 candidate[5];

    if (bip39_derive_combination (combo_idx, &esalt_bufs[DIGESTS_OFFSET_HOST], prefix_key, prefix_chain, &preG, candidate) == 0) continue;

    if (check (candidate,
               bitmaps_buf_s1_a,
               bitmaps_buf_s1_b,
               bitmaps_buf_s1_c,
               bitmaps_buf_s1_d,
               bitmaps_buf_s2_a,
               bitmaps_buf_s2_b,
               bitmaps_buf_s2_c,
               bitmaps_buf_s2_d,
               BITMAP_MASK) == 0) continue;

    if (find_hash (candidate, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]) == 0xffffffff) continue;

    // Record the index and leave the exact comparison to the comp kernel. Marking a hash from a
    // kernel that autotune runs would report a crack against a launch geometry that is still
    // being chosen.

    const u32 n = tmps[gid].hit_cnt;

    if (n < BIP39_MAX_HITS) tmps[gid].hit[n] = combo_idx;

    tmps[gid].hit_cnt = n + 1;
  }
}

KERNEL_FQ KERNEL_FA void m36000_comp (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (tmps[gid].valid == 0) return;

  #define il_pos 0

// The shared compare reads four digest words, and an address is five. The fifth is compared here
// and the run of equal hashes either side of the match is walked, so several targets that share a
// salt all get marked.

#define BIP39_COMPARE_M5(r0, r1, r2, r3, r4)                                                                  \
{                                                                                                             \
  u32 digest_tp[5];                                                                                           \
                                                                                                              \
  digest_tp[0] = (r0);                                                                                        \
  digest_tp[1] = (r1);                                                                                        \
  digest_tp[2] = (r2);                                                                                        \
  digest_tp[3] = (r3);                                                                                        \
  digest_tp[4] = (r4);                                                                                        \
                                                                                                              \
  if (check (digest_tp,                                                                                       \
             bitmaps_buf_s1_a,                                                                                \
             bitmaps_buf_s1_b,                                                                                \
             bitmaps_buf_s1_c,                                                                                \
             bitmaps_buf_s1_d,                                                                                \
             bitmaps_buf_s2_a,                                                                                \
             bitmaps_buf_s2_b,                                                                                \
             bitmaps_buf_s2_c,                                                                                \
             bitmaps_buf_s2_d,                                                                                \
             BITMAP_MASK))                                                                                    \
  {                                                                                                           \
    int digest_pos = find_hash (digest_tp, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);                    \
                                                                                                              \
    if (digest_pos != -1)                                                                                     \
    {                                                                                                         \
      while ((digest_pos > 0) && (hash_comp (digest_tp, digests_buf[DIGESTS_OFFSET_HOST + digest_pos - 1].digest_buf) == 0)) \
      {                                                                                                       \
        digest_pos--;                                                                                          \
      }                                                                                                       \
                                                                                                              \
      for (u32 scan_pos = (u32) digest_pos; scan_pos < DIGESTS_CNT; scan_pos++)                               \
      {                                                                                                       \
        const u32 final_hash_pos = DIGESTS_OFFSET_HOST + scan_pos;                                            \
                                                                                                              \
        if (hash_comp (digest_tp, digests_buf[final_hash_pos].digest_buf) != 0)                               \
        {                                                                                                     \
          break;                                                                                              \
        }                                                                                                     \
                                                                                                              \
        if (digests_buf[final_hash_pos].digest_buf[4] != digest_tp[4])                                        \
        {                                                                                                     \
          continue;                                                                                           \
        }                                                                                                     \
                                                                                                              \
        if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                               \
        {                                                                                                     \
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, scan_pos, final_hash_pos, gid, il_pos, 0, 0); \
        }                                                                                                     \
      }                                                                                                       \
    }                                                                                                         \
  }                                                                                                           \
}

  const u32 target_type = esalt_bufs[DIGESTS_OFFSET_HOST].target_type;

  if (target_type == BIP39_TARGET_IL_HEX)
  {
    const u32 r0 = h32_from_64_S (tmps[gid].master[0]);
    const u32 r1 = l32_from_64_S (tmps[gid].master[0]);
    const u32 r2 = h32_from_64_S (tmps[gid].master[1]);
    const u32 r3 = l32_from_64_S (tmps[gid].master[1]);
    const u32 r4 = 0;

    if (DIGESTS_CNT == 1)
    {
#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
    }
    else
    {
      BIP39_COMPARE_M5 (r0, r1, r2, r3, r4);
    }

    return;
  }

  const u32 hit_cnt = tmps[gid].hit_cnt;

  if (hit_cnt == 0) return;

  PRIVATE_AS u32 prefix_key[8];
  PRIVATE_AS u32 prefix_chain[8];

  for (u32 i = 0; i < 8; i++)
  {
    prefix_key[i]   = tmps[gid].prefix_key[i];
    prefix_chain[i] = tmps[gid].prefix_chain[i];
  }

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  // More recorded hits than there are slots for means a slot was dropped, so every combination is
  // re-derived here instead of only the ones that fit.

  const u32 walk_all = (hit_cnt > BIP39_MAX_HITS) ? 1 : 0;

  const u32 replay_cnt = (walk_all == 1) ? (u32) esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total : hit_cnt;

  for (u32 j = 0; j < replay_cnt; j++)
  {
    const u32 combo_idx = (walk_all == 1) ? j : tmps[gid].hit[j];

    PRIVATE_AS u32 candidate[5];

    if (bip39_derive_combination (combo_idx, &esalt_bufs[DIGESTS_OFFSET_HOST], prefix_key, prefix_chain, &preG, candidate) == 0) continue;

    BIP39_COMPARE_M5 (candidate[0], candidate[1], candidate[2], candidate[3], candidate[4]);
  }

#undef BIP39_COMPARE_M5
}
