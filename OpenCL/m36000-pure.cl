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
#include M2S(INCLUDE_PATH/inc_bip39.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

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

typedef struct bip39_tmp
{
  u64 master[8];

  u32 prefix_key[8];
  u32 prefix_chain[8];

  // The compressed public key of prefix_key, as its x coordinate and its 0x02 or 0x03 tag. The init
  // kernel sets it only when the first dynamic path level is non-hardened, and a tag of 0 means unset.

  u32 prefix_pub_x[8];
  u32 prefix_pub_tag;

  // The combination indices whose address matched a digest. Only the first BIP39_MAX_HITS are
  // kept, but hit_cnt counts every one of them, so a candidate reaching more addresses than that
  // sends the comp kernel around the whole range again rather than losing a match. That costs one
  // work item the whole range, so the slot count is set well past what a hash file holds.
  u32 hit[BIP39_MAX_HITS];
  u32 hit_cnt;

  u32 valid;

} bip39_tmp_t;

#define BIP39_MAX_PASSPHRASE_LEN   256u
#define BIP39_SALT_WORDS         ((BIP39_SALT_PREFIX_LEN + BIP39_MAX_PASSPHRASE_LEN + 4u + 3u) / 4u)

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

KERNEL_FQ KERNEL_FA void m36000_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].hit_cnt        = 0;
  tmps[gid].valid          = 0;
  tmps[gid].prefix_pub_tag = 0;

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

  // A non-hardened first dynamic level hashes the public key of prefix_key for every combination.
  // It is the same point each time, so it is computed once here rather than once per combination.

  u32 pub_x[8];

  for (u32 i = 0; i < 8; i++) pub_x[i] = 0;

  u32 pub_tag = 0;

  if ((prefix_len < path_depth) && ((esalt_bufs[DIGESTS_OFFSET_HOST].path_indices[prefix_len] & 0x80000000) == 0))
  {
    u32 pub_y[8];

    point_mul_xy (pub_x, pub_y, key_le, &preG);

    pub_tag = (pub_y[0] & 1u) ? 0x03 : 0x02;
  }

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].prefix_key[i]   = key_le[i];
    tmps[gid].prefix_chain[i] = chain_le[i];
    tmps[gid].prefix_pub_x[i] = pub_x[i];
  }

  tmps[gid].prefix_pub_tag = pub_tag;

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
  PRIVATE_AS u32 prefix_pub_x[8];

  for (u32 i = 0; i < 8; i++)
  {
    prefix_key[i]   = tmps[gid].prefix_key[i];
    prefix_chain[i] = tmps[gid].prefix_chain[i];
    prefix_pub_x[i] = tmps[gid].prefix_pub_x[i];
  }

  const u32 prefix_pub_tag = tmps[gid].prefix_pub_tag;

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  // Same count the host put in salt_iter, read through the esalt because the self-test sets the
  // digest offset deliberately and leaves the salt position alone.

  const u32 combo_cnt = (u32) esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;

  GLOBAL_AS const bip39_skeleton_t *sk = &esalt_bufs[DIGESTS_OFFSET_HOST];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    const u32 combo_idx = LOOP_POS + j;

    // Autotune launches this kernel with the loop count it wants to time rather than the window
    // the keyspace actually has left, so the index can run past the end here.

    if (combo_idx >= combo_cnt) break;

    PRIVATE_AS u32 candidate[5];

    if (bip39_derive_combination (combo_idx, sk->path_depth, sk->path_dynamic_count, sk->target_type, sk->path_indices, sk->dynamic_segments, sk->dynamic_values, prefix_key, prefix_chain, prefix_pub_x, prefix_pub_tag, &preG, candidate) == 0) continue;

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
  PRIVATE_AS u32 prefix_pub_x[8];

  for (u32 i = 0; i < 8; i++)
  {
    prefix_key[i]   = tmps[gid].prefix_key[i];
    prefix_chain[i] = tmps[gid].prefix_chain[i];
    prefix_pub_x[i] = tmps[gid].prefix_pub_x[i];
  }

  const u32 prefix_pub_tag = tmps[gid].prefix_pub_tag;

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  // More recorded hits than there are slots for means a slot was dropped, so every combination is
  // re-derived here instead of only the ones that fit.

  const u32 walk_all = (hit_cnt > BIP39_MAX_HITS) ? 1 : 0;

  const u32 replay_cnt = (walk_all == 1) ? (u32) esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total : hit_cnt;

  GLOBAL_AS const bip39_skeleton_t *sk = &esalt_bufs[DIGESTS_OFFSET_HOST];

  for (u32 j = 0; j < replay_cnt; j++)
  {
    const u32 combo_idx = (walk_all == 1) ? j : tmps[gid].hit[j];

    PRIVATE_AS u32 candidate[5];

    if (bip39_derive_combination (combo_idx, sk->path_depth, sk->path_dynamic_count, sk->target_type, sk->path_indices, sk->dynamic_segments, sk->dynamic_values, prefix_key, prefix_chain, prefix_pub_x, prefix_pub_tag, &preG, candidate) == 0) continue;

    BIP39_COMPARE_M5 (candidate[0], candidate[1], candidate[2], candidate[3], candidate[4]);
  }
}
