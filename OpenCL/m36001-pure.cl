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
#include M2S(INCLUDE_PATH/inc_bip39_english.cl)
#endif

DECLSPEC u8 bip39s_pw_get_byte (GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 idx)
{
  const u32 word = pws_local[gid_local].i[idx >> 2];
  const u32 shift = (idx & 3u) << 3;

  return (u8) (word >> shift);
}

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define BIP39S_MAX_PATH_DEPTH 16u
#define BIP39S_TARGET_IL_HEX  0u
#define BIP39S_TARGET_P2SH    1u
#define BIP39S_TARGET_P2PKH   2u
#define BIP39S_TARGET_P2WPKH  3u
#define BIP39S_PATH_KIND_FIXED   0u
#define BIP39S_PATH_KIND_DYNAMIC 1u
#define BIP39S_DYNAMIC_KIND_RANGE 0u
#define BIP39S_DYNAMIC_KIND_LIST  1u
#define BIP39S_MAX_DYNAMIC_SEGMENTS      4u
#define BIP39S_MAX_DYNAMIC_VALUES        256u
#define BIP39S_MAX_DYNAMIC_RANGE_SPAN  4096u
#define BIP39S_MAX_WORDS                 24u
#define BIP39S_PLACEHOLDER        0xffffffffu
#define BIP39S_MAX_CANDIDATE_LEN         17u

typedef struct bip39s_dynamic_segment
{
  u32 position;
  u32 kind;
  u32 count;
  u32 start;
  u32 end;
  u32 step;
  u32 values_offset;
} bip39s_dynamic_segment_t;

typedef struct bip39s_skeleton
{
  u32 skeleton_len;
  u32 address_len;
  u32 path_len;
  u32 path_depth;
  u32 target_type;
  u32 word_cnt;
  u32 ph_cnt;
  u32 variant_slots;

  u32 path_indices[BIP39S_MAX_PATH_DEPTH];
  u32 path_kind[BIP39S_MAX_PATH_DEPTH];
  u32 path_dynamic_count;
  u32 dynamic_value_total;
  u64 path_combo_total;
  bip39s_dynamic_segment_t dynamic_segments[BIP39S_MAX_DYNAMIC_SEGMENTS];
  u32 dynamic_values[BIP39S_MAX_DYNAMIC_VALUES];
  u32 target_hash[5];
  u32 word_idx[BIP39S_MAX_WORDS];

  u8 skeleton[512];
  u8 address[64];
  u8 path[64];

} bip39s_skeleton_t;

#define BIP39S_MAX_HITS 16u

typedef struct bip39s_tmp
{
  u64 master[2][8];

  u32 prefix_key[2][8];
  u32 prefix_chain[2][8];

  // The compressed public key of prefix_key, as its x coordinate and its 0x02 or 0x03 tag. The init
  // kernel sets it only when the first dynamic path level is non-hardened, and a tag of 0 means unset.

  u32 prefix_pub_x[2][8];
  u32 prefix_pub_tag[2];

  // A candidate carries one or two unknown words. Two concatenated words can split into valid word
  // pairs in more than one way ("canalarm" is "can alarm" and "canal arm"), and each split is a
  // different mnemonic, so every split that passes the checksum gets its own derivation prefix and
  // the loop kernel walks variant_slots times the path combinations.

  u32 variant_ok[2];

  // The combination indices whose address matched a digest. Only the first BIP39S_MAX_HITS are
  // kept, but hit_cnt counts every one of them, so a candidate reaching more addresses than that
  // sends the comp kernel around the whole range again rather than losing a match. That costs one
  // work item the whole range, so the slot count is set well past what a hash file holds.
  u32 hit[BIP39S_MAX_HITS];
  u32 hit_cnt;

  u32 valid;

} bip39s_tmp_t;

#define BIP39S_SALT_PREFIX_LEN   8u
#define BIP39S_PBKDF2_ROUNDS  2048u

// Packs a byte buffer into the big-endian words the shared sha512 code reads. dst_words has to be
// at least ceil (len / 4) for the length later handed to the update, since a shared updater reads
// one word per four bytes of the length it is given.

DECLSPEC void bip39s_bytes_to_words_be (PRIVATE_AS const u8 *src, const u32 len, PRIVATE_AS u32 *dst, const u32 dst_words)
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

DECLSPEC void bip39s_u64_to_words_be (PRIVATE_AS const u64 *src, const u32 cnt, PRIVATE_AS u32 *dst)
{
  for (u32 i = 0; i < cnt; i++)
  {
    dst[(i * 2) + 0] = h32_from_64_S (src[i]);
    dst[(i * 2) + 1] = l32_from_64_S (src[i]);
  }
}

DECLSPEC void bip39s_u64_to_bytes_be (PRIVATE_AS const u64 *src, PRIVATE_AS u8 *dst)
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

// Looks up one candidate word in the BIP39 list. Returns the word index, or -1 when the word is
// not on the list. The four letter prefix is unique per word, so a prefix hit plus a length match
// is an exact answer for any word on the list.

DECLSPEC int bip39s_word_lookup (const u32 prefix4, const u32 word_len)
{
  u32 lo = 0;
  u32 hi = 2048;

  while (lo < hi)
  {
    const u32 mid = (lo + hi) / 2;

    if (bip39_english_prefix4[mid] < prefix4)
    {
      lo = mid + 1;
    }
    else
    {
      hi = mid;
    }
  }

  if (lo >= 2048) return -1;

  if (bip39_english_prefix4[lo] != prefix4) return -1;

  const u32 len_packed = bip39_english_word_len[lo >> 2];

  const u32 listed_len = (len_packed >> ((lo & 3u) * 8u)) & 0xffu;

  if (listed_len != word_len) return -1;

  return (int) lo;
}

// The first four letters of the candidate word starting at byte offset off, packed big-endian and
// zero padded, matching how bip39_english_prefix4 is built.

DECLSPEC u32 bip39s_candidate_prefix4 (GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 off, const u32 word_len)
{
  u32 prefix4 = 0;

  for (u32 i = 0; i < 4; i++)
  {
    prefix4 <<= 8;

    if (i < word_len)
    {
      prefix4 |= bip39s_pw_get_byte (pws_local, gid_local, off + i);
    }
  }

  return prefix4;
}

// The BIP39 checksum: the word indices form the entropy followed by the first word_cnt / 3 bits
// of SHA-256 over the entropy. Runs before PBKDF2 and rejects 15 of 16 single-word candidates.

DECLSPEC u32 bip39s_checksum_ok (PRIVATE_AS const u32 *word_idx, const u32 word_cnt)
{
  const u32 cs_bits = word_cnt / 3;

  // The entropy is the bit stream without its checksum tail: 128 bits for 12 words up to 256 for
  // 24. Writing past it overflows ent and feeds the checksum bits into the hash.

  const u32 ent_len = (word_cnt * 11 - cs_bits) / 8;

  u32 acc = 0;
  u32 nbits = 0;

  PRIVATE_AS u8 ent[32];

  u32 nout = 0;

  for (u32 i = 0; i < word_cnt; i++)
  {
    acc = (acc << 11) | word_idx[i];
    nbits += 11;

    while ((nbits >= 8) && (nout < ent_len))
    {
      nbits -= 8;

      ent[nout] = (u8) (acc >> nbits);

      nout++;
    }
  }

  const u32 cs_got = acc & ((1u << cs_bits) - 1u);

  PRIVATE_AS u32 ent_words[8];

  bip39s_bytes_to_words_be (ent, nout, ent_words, 8);

  sha256_ctx_t ctx;

  sha256_init (&ctx);
  sha256_update (&ctx, ent_words, nout);
  sha256_final (&ctx);

  const u32 cs_want = (ctx.h[0] >> 24) >> (8 - cs_bits);

  return (cs_got == cs_want) ? 1 : 0;
}

// Rebuilds the full mnemonic from the skeleton: known words are copied from the skeleton text and
// every placeholder is replaced by the matching candidate word span.

DECLSPEC u32 bip39s_build_mnemonic (GLOBAL_AS const bip39s_skeleton_t *sk, GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 w1_len, const u32 w2_off, const u32 w2_len, PRIVATE_AS u8 *out)
{
  const u32 skeleton_len = sk->skeleton_len;

  u32 pos = 0;
  u32 ph = 0;

  for (u32 i = 0; i < skeleton_len; i++)
  {
    const u8 c = sk->skeleton[i];

    if ((c == '?') || (c == '*'))
    {
      const u32 word_off = (ph == 0) ? 0 : w2_off;
      const u32 word_len = (ph == 0) ? w1_len : w2_len;

      for (u32 j = 0; j < word_len; j++)
      {
        out[pos] = bip39s_pw_get_byte (pws_local, gid_local, word_off + j);

        pos++;
      }

      ph++;
    }
    else
    {
      out[pos] = c;

      pos++;
    }
  }

  return pos;
}

// PBKDF2-HMAC-SHA512 over the mnemonic as the password and "mnemonic" as the salt, 2048 rounds and
// a single output block, which is the BIP39 seed. The ipad and opad states depend only on the
// mnemonic, so they are computed once and every round starts from a copy.

DECLSPEC void bip39s_pbkdf2_seed (PRIVATE_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, PRIVATE_AS u64 *seed)
{
  PRIVATE_AS u32 key_words[56];

  bip39s_bytes_to_words_be (mnemonic_bytes, mnemonic_len, key_words, 56);

  sha512_hmac_ctx_t ctx_base;

  sha512_hmac_init (&ctx_base, key_words, mnemonic_len);

  // salt is "mnemonic" followed by the block index 1

  const u8 prefix[BIP39S_SALT_PREFIX_LEN] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };

  PRIVATE_AS u8 salt_bytes[BIP39S_SALT_PREFIX_LEN + 4];

  for (u32 i = 0; i < BIP39S_SALT_PREFIX_LEN; i++)
  {
    salt_bytes[i] = prefix[i];
  }

  salt_bytes[BIP39S_SALT_PREFIX_LEN + 0] = 0;
  salt_bytes[BIP39S_SALT_PREFIX_LEN + 1] = 0;
  salt_bytes[BIP39S_SALT_PREFIX_LEN + 2] = 0;
  salt_bytes[BIP39S_SALT_PREFIX_LEN + 3] = 1;

  PRIVATE_AS u32 salt_words[4];

  bip39s_bytes_to_words_be (salt_bytes, BIP39S_SALT_PREFIX_LEN + 4, salt_words, 4);

  sha512_hmac_ctx_t ctx = ctx_base;

  sha512_hmac_update (&ctx, salt_words, BIP39S_SALT_PREFIX_LEN + 4);
  sha512_hmac_final (&ctx);

  PRIVATE_AS u64 carry[8];

  for (u32 i = 0; i < 8; i++)
  {
    carry[i] = ctx.opad.h[i];
    seed[i]  = ctx.opad.h[i];
  }

  for (u32 round = 1; round < BIP39S_PBKDF2_ROUNDS; round++)
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

    bip39s_u64_to_words_be (carry, 8, carry_words);

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

DECLSPEC void bip39s_derive_bip32_master (PRIVATE_AS const u64 *seed, PRIVATE_AS u64 *master)
{
  const u8 key_bytes[12] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };

  PRIVATE_AS u32 key_words[3];

  bip39s_bytes_to_words_be (key_bytes, 12, key_words, 3);

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

  bip39s_u64_to_words_be (seed, 8, seed_words);

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

DECLSPEC void bip39s_words_le_to_bytes_be32 (PRIVATE_AS const u32 *src, PRIVATE_AS u8 *dst)
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

DECLSPEC void bip39s_bytes_be32_to_words_le (PRIVATE_AS const u8 *src, PRIVATE_AS u32 *dst)
{
  for (u32 i = 0; i < 8; i++)
  {
    const u32 offset = 28u - (i * 4u);

    dst[i] = ((u32) src[offset + 0] << 24) | ((u32) src[offset + 1] << 16) | ((u32) src[offset + 2] << 8) | ((u32) src[offset + 3] << 0);
  }
}

DECLSPEC u32 bip39s_il_ge_curve_n (PRIVATE_AS const u8 *il_bytes)
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

DECLSPEC void bip39s_add_mod_n (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b)
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

DECLSPEC u32 bip39s_scalar_is_zero (PRIVATE_AS const u32 *v)
{
  u32 acc = 0;

  for (u32 i = 0; i < 8; i++) acc |= v[i];

  return (acc == 0);
}

DECLSPEC void bip39s_bip32_public_child_data (PRIVATE_AS u8 *data_bytes, PRIVATE_AS u32 *key_le, PRIVATE_AS secp256k1_t *preG)
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

  bip39s_words_le_to_bytes_be32 (x, data_bytes + 1);
}

// The HMAC half of a BIP32 child derivation. data_bytes holds the 33 bytes of parent data, 00 and the
// key for a hardened index or the compressed public key otherwise, and has room for the index.

DECLSPEC u32 bip39s_bip32_child_from_data (const u32 index, PRIVATE_AS u8 *data_bytes, PRIVATE_AS u32 *key_le, PRIVATE_AS u8 *key_bytes, PRIVATE_AS u8 *chain_bytes)
{
  data_bytes[33] = (u8) (index >> 24);
  data_bytes[34] = (u8) (index >> 16);
  data_bytes[35] = (u8) (index >> 8);
  data_bytes[36] = (u8) (index >> 0);

  PRIVATE_AS u8 hmac_bytes[64];

  PRIVATE_AS u32 chain_words[8];
  PRIVATE_AS u32 data_words[10];

  bip39s_bytes_to_words_be (chain_bytes, 32u, chain_words, 8);
  bip39s_bytes_to_words_be (data_bytes, 37u, data_words, 10);

  sha512_hmac_ctx_t hmac_ctx;

  sha512_hmac_init (&hmac_ctx, chain_words, 32);

  sha512_hmac_update (&hmac_ctx, data_words, 37);
  sha512_hmac_final (&hmac_ctx);

  bip39s_u64_to_bytes_be (hmac_ctx.opad.h, hmac_bytes);

  PRIVATE_AS const u8 *il_bytes = hmac_bytes;
  PRIVATE_AS const u8 *ir_bytes = hmac_bytes + 32;

  if (bip39s_il_ge_curve_n (il_bytes) == 1) return 0;

  PRIVATE_AS u32 il_le[8];

  bip39s_bytes_be32_to_words_le (il_bytes, il_le);

  PRIVATE_AS u32 child_le[8];

  bip39s_add_mod_n (child_le, key_le, il_le);

  if (bip39s_scalar_is_zero (child_le) == 1) return 0;

  for (u32 i = 0; i < 8; i++) key_le[i] = child_le[i];

  bip39s_words_le_to_bytes_be32 (key_le, key_bytes);

  for (u32 i = 0; i < 32; i++) chain_bytes[i] = ir_bytes[i];

  return 1;
}

DECLSPEC u32 bip39s_bip32_child (const u32 index, PRIVATE_AS u32 *key_le, PRIVATE_AS u8 *key_bytes, PRIVATE_AS u8 *chain_bytes, PRIVATE_AS secp256k1_t *preG)
{
  PRIVATE_AS u8 data_bytes[37];

  if ((index & 0x80000000) != 0)
  {
    data_bytes[0] = 0;

    for (u32 i = 0; i < 32; i++) data_bytes[1 + i] = key_bytes[i];
  }
  else
  {
    bip39s_bip32_public_child_data (data_bytes, key_le, preG);
  }

  const u32 derived = bip39s_bip32_child_from_data (index, data_bytes, key_le, key_bytes, chain_bytes);

  return derived;
}

// One combination of the dynamic path segments, derived from the prefix the init kernel left in
// tmps. Returns 0 when a child index lands outside the curve order, which BIP32 asks us to skip.

DECLSPEC u32 bip39s_derive_combination (const u32 combo_idx, GLOBAL_AS const bip39s_skeleton_t *skeleton, PRIVATE_AS const u32 *prefix_key, PRIVATE_AS const u32 *prefix_chain, PRIVATE_AS const u32 *prefix_pub_x, const u32 prefix_pub_tag, PRIVATE_AS secp256k1_t *preG, PRIVATE_AS u32 *out_hash)
{
  const u32 path_depth  = skeleton->path_depth;
  const u32 dynamic_cnt = skeleton->path_dynamic_count;

  PRIVATE_AS u32 path_values[BIP39S_MAX_PATH_DEPTH];

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
    const bip39s_dynamic_segment_t segment = skeleton->dynamic_segments[d];

    const u32 digit = rem % segment.count;

    rem /= segment.count;

    const u32 value = (segment.kind == BIP39S_DYNAMIC_KIND_RANGE) ? (segment.start + (digit * segment.step)) : skeleton->dynamic_values[segment.values_offset + digit];

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

  bip39s_words_le_to_bytes_be32 (key_le, key_bytes);
  bip39s_words_le_to_bytes_be32 (prefix_chain, chain_bytes);

  for (u32 i = prefix_len; i < path_depth; i++)
  {
    const u32 index = path_values[i];

    // Every combination shares the parent of the first level after the prefix, so a non-hardened
    // index there reuses the public key the init kernel computed. The init kernel looks only at the
    // segment's first value, so each index is tested again here rather than trusting the parser to
    // keep a segment all hardened or all not.

    if ((i == prefix_len) && (prefix_pub_tag != 0) && ((index & 0x80000000) == 0))
    {
      PRIVATE_AS u8 data_bytes[37];

      data_bytes[0] = (u8) prefix_pub_tag;

      bip39s_words_le_to_bytes_be32 (prefix_pub_x, data_bytes + 1);

      if (bip39s_bip32_child_from_data (index, data_bytes, key_le, key_bytes, chain_bytes) == 0) return 0;

      continue;
    }

    if (bip39s_bip32_child (index, key_le, key_bytes, chain_bytes, preG) == 0) return 0;
  }

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, key_le, preG);

  u32 h160[5];

  hash160_pubkey_compressed (h160, x, y);

  if (skeleton->target_type == BIP39S_TARGET_P2SH)
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

// Resolves one candidate into its word splits. A single placeholder takes the whole candidate as
// the word. Two placeholders take either a space separated pair or a concatenation of two words,
// and a concatenation is split at every position where both halves are listed words, up to the two
// splits the tmps buffer holds.

DECLSPEC u32 bip39s_resolve_candidate (GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 pw_len, const u32 ph_cnt, PRIVATE_AS u32 *w1_len, PRIVATE_AS u32 *w2_off, PRIVATE_AS u32 *w2_len, PRIVATE_AS u32 *w1_idx, PRIVATE_AS u32 *w2_idx)
{
  if (ph_cnt == 1)
  {
    const u32 prefix4 = bip39s_candidate_prefix4 (pws_local, gid_local, 0, pw_len);

    const int idx = bip39s_word_lookup (prefix4, pw_len);

    if (idx < 0) return 0;

    w1_len[0] = pw_len;
    w2_off[0] = 0;
    w2_len[0] = 0;
    w1_idx[0] = (u32) idx;
    w2_idx[0] = 0;

    return 1;
  }

  u32 split_cnt = 0;

  u32 space_off = 0xffffffffu;

  for (u32 i = 0; i < pw_len; i++)
  {
    if (bip39s_pw_get_byte (pws_local, gid_local, i) == ' ')
    {
      space_off = i;

      break;
    }
  }

  if (space_off != 0xffffffffu)
  {
    const u32 left_len  = space_off;
    const u32 right_off = space_off + 1;
    const u32 right_len = pw_len - right_off;

    const int idx1 = bip39s_word_lookup (bip39s_candidate_prefix4 (pws_local, gid_local, 0,         left_len),  left_len);
    const int idx2 = bip39s_word_lookup (bip39s_candidate_prefix4 (pws_local, gid_local, right_off, right_len), right_len);

    if ((idx1 < 0) || (idx2 < 0)) return 0;

    w1_len[0] = left_len;
    w2_off[0] = right_off;
    w2_len[0] = right_len;
    w1_idx[0] = (u32) idx1;
    w2_idx[0] = (u32) idx2;

    return 1;
  }

  for (u32 s = 3; (s + 3 <= pw_len) && (split_cnt < 2); s++)
  {
    const int idx1 = bip39s_word_lookup (bip39s_candidate_prefix4 (pws_local, gid_local, 0, s), s);
    const int idx2 = bip39s_word_lookup (bip39s_candidate_prefix4 (pws_local, gid_local, s, pw_len - s), pw_len - s);

    if ((idx1 < 0) || (idx2 < 0)) continue;

    w1_len[split_cnt] = s;
    w2_off[split_cnt] = s;
    w2_len[split_cnt] = pw_len - s;
    w1_idx[split_cnt] = (u32) idx1;
    w2_idx[split_cnt] = (u32) idx2;

    split_cnt++;
  }

  return split_cnt;
}

KERNEL_FQ KERNEL_FA void m36001_init (KERN_ATTR_TMPS_ESALT (bip39s_tmp_t, bip39s_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].hit_cnt      = 0;
  tmps[gid].valid        = 0;
  tmps[gid].variant_ok[0] = 0;
  tmps[gid].variant_ok[1] = 0;

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len > BIP39S_MAX_CANDIDATE_LEN) return;

  GLOBAL_AS const bip39s_skeleton_t *sk = &esalt_bufs[DIGESTS_OFFSET_HOST];

  const u32 ph_cnt   = sk->ph_cnt;
  const u32 word_cnt = sk->word_cnt;

  PRIVATE_AS u32 w1_len[2];
  PRIVATE_AS u32 w2_off[2];
  PRIVATE_AS u32 w2_len[2];
  PRIVATE_AS u32 w1_idx[2];
  PRIVATE_AS u32 w2_idx[2];

  const u32 split_cnt = bip39s_resolve_candidate (pws, gid, pw_len, ph_cnt, w1_len, w2_off, w2_len, w1_idx, w2_idx);

  if (split_cnt == 0) return;

  const u32 target_type = sk->target_type;

  const u32 path_depth  = sk->path_depth;
  const u32 dynamic_cnt = sk->path_dynamic_count;

  u32 prefix_len = path_depth;

  for (u32 d = 0; d < dynamic_cnt; d++)
  {
    const u32 position = sk->dynamic_segments[d].position;

    if (position < prefix_len) prefix_len = position;
  }

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  for (u32 v = 0; v < split_cnt; v++)
  {
    // The word indices of the full mnemonic, with the candidate words in the placeholder slots.

    PRIVATE_AS u32 word_idx[BIP39S_MAX_WORDS];

    u32 ph = 0;

    for (u32 i = 0; i < word_cnt; i++)
    {
      if (sk->word_idx[i] == BIP39S_PLACEHOLDER)
      {
        word_idx[i] = (ph == 0) ? w1_idx[v] : w2_idx[v];

        ph++;
      }
      else
      {
        word_idx[i] = sk->word_idx[i];
      }
    }

    if (bip39s_checksum_ok (word_idx, word_cnt) == 0) continue;

    PRIVATE_AS u8 mnemonic_bytes[216];

    const u32 mnemonic_len = bip39s_build_mnemonic (sk, pws, gid, w1_len[v], w2_off[v], w2_len[v], mnemonic_bytes);

    PRIVATE_AS u64 seed[8];

    for (u32 i = 0; i < 8; i++)
    {
      seed[i] = 0;
    }

    bip39s_pbkdf2_seed (mnemonic_bytes, mnemonic_len, seed);

    PRIVATE_AS u64 master[8];

    for (u32 i = 0; i < 8; i++)
    {
      master[i] = 0;
    }

    bip39s_derive_bip32_master (seed, master);

    for (u32 i = 0; i < 8; i++)
    {
      tmps[gid].master[v][i] = master[i];
    }

    if (target_type == BIP39S_TARGET_IL_HEX)
    {
      tmps[gid].variant_ok[v] = 1;

      continue;
    }

    // Everything above the first dynamic path element is the same for every combination, so it is
    // derived once here and the loop kernel carries on from it.

    PRIVATE_AS u8 master_bytes[64];

    bip39s_u64_to_bytes_be (master, master_bytes);

    PRIVATE_AS u8 key_bytes[32];
    PRIVATE_AS u8 chain_bytes[32];

    for (u32 i = 0; i < 32; i++)
    {
      key_bytes[i]   = master_bytes[i];
      chain_bytes[i] = master_bytes[32 + i];
    }

    PRIVATE_AS u32 key_le[8];

    bip39s_bytes_be32_to_words_le (key_bytes, key_le);

    u32 derived = 1;

    for (u32 i = 0; i < prefix_len; i++)
    {
      const u32 index = sk->path_indices[i];

      if (bip39s_bip32_child (index, key_le, key_bytes, chain_bytes, &preG) == 0)
      {
        derived = 0;

        break;
      }
    }

    if (derived == 0) continue;

    PRIVATE_AS u32 chain_le[8];

    bip39s_bytes_be32_to_words_le (chain_bytes, chain_le);

    // A non-hardened first dynamic level hashes the public key of prefix_key for every combination.
    // It is the same point each time, so it is computed once here rather than once per combination.

    u32 pub_x[8];

    for (u32 i = 0; i < 8; i++) pub_x[i] = 0;

    u32 pub_tag = 0;

    if ((prefix_len < path_depth) && ((sk->path_indices[prefix_len] & 0x80000000) == 0))
    {
      u32 pub_y[8];

      point_mul_xy (pub_x, pub_y, key_le, &preG);

      pub_tag = (pub_y[0] & 1u) ? 0x03 : 0x02;
    }

    for (u32 i = 0; i < 8; i++)
    {
      tmps[gid].prefix_key[v][i]   = key_le[i];
      tmps[gid].prefix_chain[v][i] = chain_le[i];
      tmps[gid].prefix_pub_x[v][i] = pub_x[i];
    }

    tmps[gid].prefix_pub_tag[v] = pub_tag;

    tmps[gid].variant_ok[v] = 1;
  }

  tmps[gid].valid = (tmps[gid].variant_ok[0] | tmps[gid].variant_ok[1]);
}

KERNEL_FQ KERNEL_FA void m36001_loop (KERN_ATTR_TMPS_ESALT (bip39s_tmp_t, bip39s_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (tmps[gid].valid == 0) return;

  GLOBAL_AS const bip39s_skeleton_t *sk = &esalt_bufs[DIGESTS_OFFSET_HOST];

  if (sk->target_type == BIP39S_TARGET_IL_HEX) return;

  const u32 path_combos = (u32) sk->path_combo_total;

  // The host counts each candidate once per variant slot per path combination, which is what
  // salt_iter holds.

  const u32 combo_cnt = path_combos * sk->variant_slots;

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    const u32 combo_idx = LOOP_POS + j;

    // Autotune launches this kernel with the loop count it wants to time rather than the window
    // the keyspace actually has left, so the index can run past the end here.

    if (combo_idx >= combo_cnt) break;

    const u32 variant = combo_idx / path_combos;
    const u32 pcombo  = combo_idx - (variant * path_combos);

    if (variant > 1) continue;

    if (tmps[gid].variant_ok[variant] == 0) continue;

    PRIVATE_AS u32 prefix_key[8];
    PRIVATE_AS u32 prefix_chain[8];
    PRIVATE_AS u32 prefix_pub_x[8];

    for (u32 i = 0; i < 8; i++)
    {
      prefix_key[i]   = tmps[gid].prefix_key[variant][i];
      prefix_chain[i] = tmps[gid].prefix_chain[variant][i];
      prefix_pub_x[i] = tmps[gid].prefix_pub_x[variant][i];
    }

    const u32 prefix_pub_tag = tmps[gid].prefix_pub_tag[variant];

    PRIVATE_AS u32 candidate[5];

    if (bip39s_derive_combination (pcombo, sk, prefix_key, prefix_chain, prefix_pub_x, prefix_pub_tag, &preG, candidate) == 0) continue;

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

    if (n < BIP39S_MAX_HITS) tmps[gid].hit[n] = combo_idx;

    tmps[gid].hit_cnt = n + 1;
  }
}

KERNEL_FQ KERNEL_FA void m36001_comp (KERN_ATTR_TMPS_ESALT (bip39s_tmp_t, bip39s_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (tmps[gid].valid == 0) return;

  #define il_pos 0

// The shared compare reads four digest words, and an address is five. The fifth is compared here
// and the run of equal hashes either side of the match is walked, so several targets that share a
// salt all get marked.

#define BIP39S_COMPARE_M5(r0, r1, r2, r3, r4)                                                                 \
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

  GLOBAL_AS const bip39s_skeleton_t *sk = &esalt_bufs[DIGESTS_OFFSET_HOST];

  const u32 target_type = sk->target_type;

  if (target_type == BIP39S_TARGET_IL_HEX)
  {
    for (u32 v = 0; v < 2; v++)
    {
      if (tmps[gid].variant_ok[v] == 0) continue;

      const u32 r0 = h32_from_64_S (tmps[gid].master[v][0]);
      const u32 r1 = l32_from_64_S (tmps[gid].master[v][0]);
      const u32 r2 = h32_from_64_S (tmps[gid].master[v][1]);
      const u32 r3 = l32_from_64_S (tmps[gid].master[v][1]);
      const u32 r4 = 0;

      BIP39S_COMPARE_M5 (r0, r1, r2, r3, r4);
    }

    return;
  }

  const u32 hit_cnt = tmps[gid].hit_cnt;

  if (hit_cnt == 0) return;

  const u32 path_combos = (u32) sk->path_combo_total;

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  // More recorded hits than there are slots for means a slot was dropped, so every combination is
  // re-derived here instead of only the ones that fit.

  const u32 walk_all = (hit_cnt > BIP39S_MAX_HITS) ? 1 : 0;

  const u32 replay_cnt = (walk_all == 1) ? (path_combos * sk->variant_slots) : hit_cnt;

  for (u32 j = 0; j < replay_cnt; j++)
  {
    const u32 combo_idx = (walk_all == 1) ? j : tmps[gid].hit[j];

    const u32 variant = combo_idx / path_combos;
    const u32 pcombo  = combo_idx - (variant * path_combos);

    if (variant > 1) continue;

    if (tmps[gid].variant_ok[variant] == 0) continue;

    PRIVATE_AS u32 prefix_key[8];
    PRIVATE_AS u32 prefix_chain[8];
    PRIVATE_AS u32 prefix_pub_x[8];

    for (u32 i = 0; i < 8; i++)
    {
      prefix_key[i]   = tmps[gid].prefix_key[variant][i];
      prefix_chain[i] = tmps[gid].prefix_chain[variant][i];
      prefix_pub_x[i] = tmps[gid].prefix_pub_x[variant][i];
    }

    const u32 prefix_pub_tag = tmps[gid].prefix_pub_tag[variant];

    PRIVATE_AS u32 candidate[5];

    if (bip39s_derive_combination (pcombo, sk, prefix_key, prefix_chain, prefix_pub_x, prefix_pub_tag, &preG, candidate) == 0) continue;

    BIP39S_COMPARE_M5 (candidate[0], candidate[1], candidate[2], candidate[3], candidate[4]);
  }

#undef BIP39S_COMPARE_M5
}
