/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef IS_NV
#undef HAS_PRMT
#define HAS_PRMT 0
#define NO_FUNNELSHIFT
#else
#define NEW_SIMD_CODE
#endif
#define SECP256K1_TMPS_TYPE PRIVATE_AS
#ifndef BIP39_DEBUG_PRINT
#define BIP39_DEBUG_PRINT 0
#endif

#ifndef BIP39_DEBUG_GID
#define BIP39_DEBUG_GID 0xffffffffu
#endif

#ifndef BIP39_PROFILE
#define BIP39_PROFILE 0
#endif

#define BIP39_USE_CUSTOM_SHA512 1

#ifndef BIP39_DISABLE_SCRIPT_HASH
#define BIP39_DISABLE_SCRIPT_HASH 0
#endif

#ifndef BIP39_DISABLE_SHA256_SMALL
#define BIP39_DISABLE_SHA256_SMALL 0
#endif

#ifndef BIP39_DISABLE_PUBKEY_HASH
#define BIP39_DISABLE_PUBKEY_HASH 0
#endif

#ifndef BIP39_DISABLE_POINT_MUL
#define BIP39_DISABLE_POINT_MUL 0
#endif

#ifndef BIP39_DISABLE_KEY_HASHES_AFTER_POINT
#define BIP39_DISABLE_KEY_HASHES_AFTER_POINT 0
#endif

#ifndef BIP39_DISABLE_KEY_HASHES_AFTER_PUB
#define BIP39_DISABLE_KEY_HASHES_AFTER_PUB 0
#endif

#ifndef BIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA
#define BIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA 0
#endif

#ifndef BIP39_DISABLE_KEY_HASHES
#define BIP39_DISABLE_KEY_HASHES 0
#endif

#ifndef BIP39_DISABLE_PBKDF2
#define BIP39_DISABLE_PBKDF2 0
#endif

#ifndef BIP39_DISABLE_BIP32_MASTER
#define BIP39_DISABLE_BIP32_MASTER 0
#endif

#ifndef BIP39_DISABLE_PATH_DERIVE
#define BIP39_DISABLE_PATH_DERIVE 0
#endif

#ifndef BIP39_DISABLE_PATH_BLOCK
#define BIP39_DISABLE_PATH_BLOCK 0
#endif

#ifndef BIP39_DISABLE_PATH_CHILDREN
#define BIP39_DISABLE_PATH_CHILDREN 0
#endif

#ifndef BIP39_DISABLE_PATH_MATCH
#define BIP39_DISABLE_PATH_MATCH 0
#endif

#ifndef BIP39_DISABLE_INIT_BODY
#define BIP39_DISABLE_INIT_BODY 0
#endif

#ifndef BIP39_DISABLE_INIT_AFTER_PASSPHRASE
#define BIP39_DISABLE_INIT_AFTER_PASSPHRASE 0
#endif

#ifndef BIP39_DISABLE_INIT_AFTER_PBKDF2
#define BIP39_DISABLE_INIT_AFTER_PBKDF2 0
#endif

#ifndef BIP39_DISABLE_INIT_AFTER_BIP32
#define BIP39_DISABLE_INIT_AFTER_BIP32 0
#endif

#ifndef BIP39_DISABLE_LOOP_BODY
#define BIP39_DISABLE_LOOP_BODY 0
#endif

#ifndef BIP39_DISABLE_AFTER_PASSPHRASE
#define BIP39_DISABLE_AFTER_PASSPHRASE 0
#endif

#ifndef BIP39_DISABLE_AFTER_PBKDF2
#define BIP39_DISABLE_AFTER_PBKDF2 0
#endif

#ifndef BIP39_DISABLE_AFTER_BIP32
#define BIP39_DISABLE_AFTER_BIP32 0
#endif

#ifndef BIP39_DISABLE_PATH_WALK
#define BIP39_DISABLE_PATH_WALK 0
#endif

#ifndef BIP39_MINIMAL_KERNEL
#define BIP39_MINIMAL_KERNEL 0
#endif

#ifndef M2S_HELPER
#define M2S_HELPER(x) #x
#define M2S(x) M2S_HELPER(x)
#endif

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

#if BIP39_MINIMAL_KERNEL

#define BIP39_MAX_PATH_DEPTH 16u

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
  bip39_dynamic_segment_t dynamic_segments[4];
  u32 dynamic_values[256];
  u32 target_hash[5];

  u8 mnemonic[1024];
  u8 address[64];
  u8 path[64];
  u32 mnemonic_raw_len;
  u8 mnemonic_raw[1024];

} bip39_skeleton_t;

typedef struct bip39_tmp
{
  u64 seed[8];
  u64 master[8];
  u32 script_hash[5];
  u32 derived_ready;
  u32 master_ready;
  u32 debug_loop_pos;
  u32 debug_loop_cnt;
  u64 debug_combo_idx;
  u64 debug_combo_total;
} bip39_tmp_t;

typedef struct bip39_hook
{
  u32 debug_loop_pos;
  u32 debug_loop_cnt;
  u64 debug_combo_idx;
  u64 debug_combo_total;
  u32 reserved;
  u32 reserved_extra0;
  u32 reserved_extra1;
  u32 reserved_extra2;
} bip39_hook_t;

KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;

  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].master_ready = 0;
  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_idx = 0;
  tmps[gid].debug_combo_total = 0;
}

KERNEL_FQ void m32001_loop (KERN_ATTR_TMPS_HOOKS_ESALT (bip39_tmp_t, bip39_hook_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  hooks[gid].debug_loop_pos  = LOOP_POS;
  hooks[gid].debug_loop_cnt  = LOOP_CNT;
  hooks[gid].debug_combo_idx = 0;
  hooks[gid].debug_combo_total = 0;
  hooks[gid].reserved        = 0u;
  hooks[gid].reserved_extra0 = 0u;
  hooks[gid].reserved_extra1 = 0u;
  hooks[gid].reserved_extra2 = 0u;
}

KERNEL_FQ KERNEL_FA void m32001_hook23 (KERN_ATTR_TMPS_HOOKS (bip39_tmp_t, bip39_hook_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  hooks[gid].debug_loop_pos  = tmps[gid].debug_loop_pos;
  hooks[gid].debug_loop_cnt  = tmps[gid].debug_loop_cnt;
  hooks[gid].debug_combo_idx = tmps[gid].debug_combo_idx;
  hooks[gid].debug_combo_total = tmps[gid].debug_combo_total;
  hooks[gid].reserved        = 0u;
  hooks[gid].reserved_extra0 = 0u;
  hooks[gid].reserved_extra1 = 0u;
  hooks[gid].reserved_extra2 = 0u;
}

KERNEL_FQ void m32001_comp (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;
}

KERNEL_FQ void m32001_mxx (KERN_ATTR_ESALT (bip39_skeleton_t))
{
}

KERNEL_FQ void m32001_sxx (KERN_ATTR_ESALT (bip39_skeleton_t))
{
}

KERNEL_FQ void bip39_test_u1 (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS u64 *out_digest)
{
  if (mnemonic_len > 0)
    out_digest[0] = 0;
}

KERNEL_FQ void bip39_test_master (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS u64 *out_seed, GLOBAL_AS u64 *out_master)
{
  if (mnemonic_len > 0)
  {
    out_seed[0] = 0;
    out_master[0] = 0;
  }
}

KERNEL_FQ void bip39_test_script_hash (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS const u32 *path_indices, const u32 path_depth, GLOBAL_AS u32 *out_key_le, GLOBAL_AS u32 *out_hash, GLOBAL_AS u32 *out_status, GLOBAL_AS u32 *out_parent, GLOBAL_AS u32 *out_il)
{
  if (path_depth > 0)
    out_status[0] = 0;
}

KERNEL_FQ void bip39_test_hmac (GLOBAL_AS const u32 *key_words, const u32 key_len, GLOBAL_AS const u32 *data_words, const u32 data_len, GLOBAL_AS u64 *out_digest)
{
  if (key_len > 0)
    out_digest[0] = 0;
}

#else

DECLSPEC u8 bip39_pw_get_byte (GLOBAL_AS const pw_t *pws_local, const u64 gid_local, const u32 idx)
{
  const u32 word = pws_local[gid_local].i[idx >> 2];
  const u32 shift = (idx & 3u) << 3;

  return (u8) (word >> shift);
}

#if BIP39_USE_CUSTOM_SHA512

typedef struct bip39_sha512_ctx
{
  u64 h[8];
  u64 total_len;
  u32 buffer_len;
  u8 buffer[128];
} bip39_sha512_ctx_t;

DECLSPEC u64 bip39_rotr64 (const u64 x, const u32 n)
{
  return (x >> n) | (x << (64u - n));
}

CONSTANT_VK u64 bip39_sha512_k[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

CONSTANT_VK u8 bip39_salt_prefix_bytes[8] = {
  'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c'
};

DECLSPEC void bip39_sha512_process_block (PRIVATE_AS u64 *h, PRIVATE_AS const u8 *block)
{
  u64 wbuf[16];

  for (int i = 0; i < 16; i++)
  {
    const int idx = i * 8;

    wbuf[i] = ((u64) block[idx + 0] << 56) | ((u64) block[idx + 1] << 48) | ((u64) block[idx + 2] << 40) | ((u64) block[idx + 3] << 32) | ((u64) block[idx + 4] << 24) | ((u64) block[idx + 5] << 16) | ((u64) block[idx + 6] << 8) | ((u64) block[idx + 7] << 0);
  }

  u64 a = h[0];
  u64 b = h[1];
  u64 c = h[2];
  u64 d = h[3];
  u64 e = h[4];
  u64 f = h[5];
  u64 g = h[6];
  u64 hval = h[7];

  for (int i = 0; i < 80; i++)
  {
    if (i >= 16)
    {
      const int j = i & 15;
      const int j1 = (j + 1) & 15;
      const int j9 = (j + 9) & 15;
      const int j14 = (j + 14) & 15;

      const u64 s0 = bip39_rotr64 (wbuf[j1], 1) ^ bip39_rotr64 (wbuf[j1], 8) ^ (wbuf[j1] >> 7);
      const u64 s1 = bip39_rotr64 (wbuf[j14], 19) ^ bip39_rotr64 (wbuf[j14], 61) ^ (wbuf[j14] >> 6);

      wbuf[j] += s0 + wbuf[j9] + s1;
    }

    const u64 w_t = wbuf[i & 15];

    const u64 S1 = bip39_rotr64 (e, 14) ^ bip39_rotr64 (e, 18) ^ bip39_rotr64 (e, 41);
    const u64 ch = (e & f) ^ ((~e) & g);
    const u64 temp1 = hval + S1 + ch + bip39_sha512_k[i] + w_t;
    const u64 S0 = bip39_rotr64 (a, 28) ^ bip39_rotr64 (a, 34) ^ bip39_rotr64 (a, 39);
    const u64 maj = (a & b) ^ (a & c) ^ (b & c);
    const u64 temp2 = S0 + maj;

    hval = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hval;
}

DECLSPEC void bip39_sha512_init (PRIVATE_AS bip39_sha512_ctx_t *ctx)
{
  ctx->h[0] = 0x6a09e667f3bcc908ULL;
  ctx->h[1] = 0xbb67ae8584caa73bULL;
  ctx->h[2] = 0x3c6ef372fe94f82bULL;
  ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->h[4] = 0x510e527fade682d1ULL;
  ctx->h[5] = 0x9b05688c2b3e6c1fULL;
  ctx->h[6] = 0x1f83d9abfb41bd6bULL;
  ctx->h[7] = 0x5be0cd19137e2179ULL;
  ctx->total_len = 0;
  ctx->buffer_len = 0;
}

DECLSPEC void bip39_sha512_update (PRIVATE_AS bip39_sha512_ctx_t *ctx, PRIVATE_AS const u8 *data, const u32 len)
{
  u32 consumed = 0;

  ctx->total_len += (u64) len;

  if (ctx->buffer_len > 0)
  {
    const u32 need = 128u - ctx->buffer_len;
    const u32 take = (len < need) ? len : need;

    for (u32 i = 0; i < take; i++)
    {
      ctx->buffer[ctx->buffer_len + i] = data[i];
    }

    ctx->buffer_len += take;
    consumed += take;

    if (ctx->buffer_len == 128u)
    {
      bip39_sha512_process_block (ctx->h, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }

  while ((len - consumed) >= 128u)
  {
    bip39_sha512_process_block (ctx->h, data + consumed);
    consumed += 128u;
  }

  const u32 remaining = len - consumed;

  for (u32 i = 0; i < remaining; i++)
  {
    ctx->buffer[ctx->buffer_len + i] = data[consumed + i];
  }

  ctx->buffer_len += remaining;
}

DECLSPEC void bip39_sha512_final (PRIVATE_AS bip39_sha512_ctx_t *ctx, PRIVATE_AS u8 *out)
{
  u32 buf_len = ctx->buffer_len;

  ctx->buffer[buf_len++] = 0x80;

  if (buf_len > 112u)
  {
    for (u32 i = buf_len; i < 128u; i++)
      ctx->buffer[i] = 0;

    bip39_sha512_process_block (ctx->h, ctx->buffer);

    buf_len = 0;
  }

  for (u32 i = buf_len; i < 112u; i++)
    ctx->buffer[i] = 0;

  const u64 bit_len = ctx->total_len << 3;
  const u64 bit_len_hi = ctx->total_len >> 61;

  ctx->buffer[112] = (u8) (bit_len_hi >> 56);
  ctx->buffer[113] = (u8) (bit_len_hi >> 48);
  ctx->buffer[114] = (u8) (bit_len_hi >> 40);
  ctx->buffer[115] = (u8) (bit_len_hi >> 32);
  ctx->buffer[116] = (u8) (bit_len_hi >> 24);
  ctx->buffer[117] = (u8) (bit_len_hi >> 16);
  ctx->buffer[118] = (u8) (bit_len_hi >> 8);
  ctx->buffer[119] = (u8) (bit_len_hi >> 0);

  ctx->buffer[120] = (u8) (bit_len >> 56);
  ctx->buffer[121] = (u8) (bit_len >> 48);
  ctx->buffer[122] = (u8) (bit_len >> 40);
  ctx->buffer[123] = (u8) (bit_len >> 32);
  ctx->buffer[124] = (u8) (bit_len >> 24);
  ctx->buffer[125] = (u8) (bit_len >> 16);
  ctx->buffer[126] = (u8) (bit_len >> 8);
  ctx->buffer[127] = (u8) (bit_len >> 0);

  bip39_sha512_process_block (ctx->h, ctx->buffer);

  ctx->buffer_len = 0;

  for (u32 i = 0; i < 8; i++)
  {
    const u64 word = ctx->h[i];

    out[(i * 8) + 0] = (u8) (word >> 56);
    out[(i * 8) + 1] = (u8) (word >> 48);
    out[(i * 8) + 2] = (u8) (word >> 40);
    out[(i * 8) + 3] = (u8) (word >> 32);
    out[(i * 8) + 4] = (u8) (word >> 24);
    out[(i * 8) + 5] = (u8) (word >> 16);
    out[(i * 8) + 6] = (u8) (word >> 8);
    out[(i * 8) + 7] = (u8) (word >> 0);
  }
}

DECLSPEC void bip39_hmac_sha512_prehash_states (PRIVATE_AS const u8 *key_buf_128, PRIVATE_AS u64 inner_state[8], PRIVATE_AS u64 outer_state[8])
{
  const u64 sha512_init_state[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
  };

  PRIVATE_AS u8 ipad_block[128];
  PRIVATE_AS u8 opad_block[128];

  for (u32 i = 0; i < 128; i++)
  {
    ipad_block[i] = key_buf_128[i] ^ 0x36;
    opad_block[i] = key_buf_128[i] ^ 0x5c;
  }

  for (u32 i = 0; i < 8; i++)
  {
    inner_state[i] = sha512_init_state[i];
    outer_state[i] = sha512_init_state[i];
  }

  bip39_sha512_process_block (inner_state, ipad_block);
  bip39_sha512_process_block (outer_state, opad_block);
}

DECLSPEC void bip39_hmac_sha512_from_prehashed (PRIVATE_AS const u64 inner_state_init[8], PRIVATE_AS const u64 outer_state_init[8], PRIVATE_AS const u8 *msg, const u32 msg_len, PRIVATE_AS u8 *out)
{
  bip39_sha512_ctx_t inner_ctx;
  bip39_sha512_ctx_t outer_ctx;

  for (u32 i = 0; i < 8; i++)
  {
    inner_ctx.h[i] = inner_state_init[i];
    outer_ctx.h[i] = outer_state_init[i];
  }

  inner_ctx.total_len = 128;
  inner_ctx.buffer_len = 0;
  outer_ctx.total_len = 128;
  outer_ctx.buffer_len = 0;

  bip39_sha512_update (&inner_ctx, msg, msg_len);
  bip39_sha512_final (&inner_ctx, out);

  bip39_sha512_update (&outer_ctx, out, 64u);
  bip39_sha512_final (&outer_ctx, out);
}

DECLSPEC void bip39_hmac_sha512 (PRIVATE_AS const u8 *key, const u32 key_len, PRIVATE_AS const u8 *msg, const u32 msg_len, PRIVATE_AS u8 *out)
{
  PRIVATE_AS u8 key_buf[128];

  if (key_len > 128u)
  {
    bip39_sha512_ctx_t key_ctx;

    bip39_sha512_init (&key_ctx);

    u32 processed = 0;

    while ((key_len - processed) >= 128u)
    {
      for (u32 i = 0; i < 128; i++)
        key_buf[i] = key[processed + i];
      bip39_sha512_update (&key_ctx, key_buf, 128u);
      processed += 128u;
    }

    const u32 rem = key_len - processed;

    if (rem > 0)
    {
      for (u32 i = 0; i < rem; i++)
        key_buf[i] = key[processed + i];
      bip39_sha512_update (&key_ctx, key_buf, rem);
    }

    bip39_sha512_final (&key_ctx, key_buf);

    for (u32 i = 64; i < 128; i++)
      key_buf[i] = 0;
  }
  else
  {
    for (u32 i = 0; i < key_len; i++)
      key_buf[i] = key[i];
    for (u32 i = key_len; i < 128u; i++)
      key_buf[i] = 0;
  }

  for (u32 i = 0; i < 128; i++)
    key_buf[i] ^= 0x36;

  bip39_sha512_ctx_t inner_ctx;

  bip39_sha512_init (&inner_ctx);
  bip39_sha512_update (&inner_ctx, key_buf, 128u);
  bip39_sha512_update (&inner_ctx, msg, msg_len);
  bip39_sha512_final (&inner_ctx, out);

  for (u32 i = 0; i < 128; i++)
    key_buf[i] ^= 0x6a;         // transform ipad xor into opad xor

  bip39_sha512_ctx_t outer_ctx;

  bip39_sha512_init (&outer_ctx);
  bip39_sha512_update (&outer_ctx, key_buf, 128u);
  bip39_sha512_update (&outer_ctx, out, 64u);
  bip39_sha512_final (&outer_ctx, out);
}

#endif // BIP39_USE_CUSTOM_SHA512

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

typedef struct bip39_tmp
{
  u64 seed[8];
  u64 master[8];
  u32 script_hash[5];
  u32 derived_ready;
  u32 master_ready;
  u32 debug_loop_pos;
  u32 debug_loop_cnt;
  u64 debug_combo_idx;
  u64 debug_combo_total;
} bip39_tmp_t;

typedef struct bip39_hook
{
  u32 debug_loop_pos;
  u32 debug_loop_cnt;
  u32 debug_combo_idx;
  u32 reserved;
  u32 debug_combo_total;
  u32 reserved_extra0;
  u32 reserved_extra1;
  u32 reserved_extra2;
} bip39_hook_t;

#define BIP39_SALT_PREFIX_LEN        8u
#define BIP39_MAX_PASSPHRASE_LEN   256u
#define BIP39_SALT_WORDS         ((BIP39_SALT_PREFIX_LEN + BIP39_MAX_PASSPHRASE_LEN + 4u + 3u) / 4u)

#ifndef BIP39_TEST_ONLY
#define BIP39_TEST_ONLY 0
#endif

#ifdef BIP39_TEST_KERNEL
#define BIP39_TEST_ONLY 1
#endif

#if BIP39_USE_CUSTOM_SHA512

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

DECLSPEC void bip39_bytes_to_u64_be (PRIVATE_AS const u8 *src, PRIVATE_AS u64 *dst)
{
  for (u32 i = 0; i < 8; i++)
  {
    dst[i] = ((u64) src[(i * 8) + 0] << 56) | ((u64) src[(i * 8) + 1] << 48) | ((u64) src[(i * 8) + 2] << 40) | ((u64) src[(i * 8) + 3] << 32) | ((u64) src[(i * 8) + 4] << 24) | ((u64) src[(i * 8) + 5] << 16) | ((u64) src[(i * 8) + 6] << 8) | ((u64) src[(i * 8) + 7] << 0);
  }
}

DECLSPEC void bip39_hmac_sha512_from_global (GLOBAL_AS const u8 *key, const u32 key_len, PRIVATE_AS const u8 *msg, const u32 msg_len, PRIVATE_AS u8 *out)
{
  PRIVATE_AS u8 key_buf[128];

  if (key_len > 128u)
  {
    bip39_sha512_ctx_t key_ctx;

    bip39_sha512_init (&key_ctx);

    u32 offset = 0;

    while ((key_len - offset) >= 128u)
    {
      for (u32 i = 0; i < 128; i++)
        key_buf[i] = key[offset + i];
      bip39_sha512_update (&key_ctx, key_buf, 128u);
      offset += 128u;
    }

    const u32 rem = key_len - offset;

    if (rem > 0)
    {
      for (u32 i = 0; i < rem; i++)
        key_buf[i] = key[offset + i];
      bip39_sha512_update (&key_ctx, key_buf, rem);
    }

    bip39_sha512_final (&key_ctx, key_buf);
    for (u32 i = 64; i < 128; i++)
      key_buf[i] = 0;
  }
  else
  {
    for (u32 i = 0; i < key_len; i++)
      key_buf[i] = key[i];
    for (u32 i = key_len; i < 128u; i++)
      key_buf[i] = 0;
  }

  bip39_hmac_sha512 (key_buf, 128u, msg, msg_len, out);
}

DECLSPEC void bip39_hmac_sha512_pbkdf2_block (GLOBAL_AS const u8 *key, const u32 key_len, PRIVATE_AS const u8 *passphrase, const u32 passphrase_len, const u32 counter, PRIVATE_AS u8 *out)
{
  PRIVATE_AS u8 key_buf[128];

  if (key_len > 128u)
  {
    bip39_sha512_ctx_t key_ctx;

    bip39_sha512_init (&key_ctx);

    u32 offset = 0;

    while ((key_len - offset) >= 128u)
    {
      for (u32 i = 0; i < 128; i++)
        key_buf[i] = key[offset + i];

      bip39_sha512_update (&key_ctx, key_buf, 128u);

      offset += 128u;
    }

    const u32 rem = key_len - offset;

    if (rem > 0)
    {
      for (u32 i = 0; i < rem; i++)
        key_buf[i] = key[offset + i];
      bip39_sha512_update (&key_ctx, key_buf, rem);
    }

    bip39_sha512_final (&key_ctx, key_buf);
    for (u32 i = 64; i < 128; i++)
      key_buf[i] = 0;
  }
  else
  {
    for (u32 i = 0; i < key_len; i++)
      key_buf[i] = key[i];
    for (u32 i = key_len; i < 128u; i++)
      key_buf[i] = 0;
  }

  for (u32 i = 0; i < 128; i++)
    key_buf[i] ^= 0x36;

  bip39_sha512_ctx_t inner_ctx;

  bip39_sha512_init (&inner_ctx);
  bip39_sha512_update (&inner_ctx, key_buf, 128u);

  const u8 salt_prefix_local[8] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };
  bip39_sha512_update (&inner_ctx, salt_prefix_local, 8u);
  bip39_sha512_update (&inner_ctx, passphrase, passphrase_len);

  u8 counter_bytes[4];

  counter_bytes[0] = (u8) (counter >> 24);
  counter_bytes[1] = (u8) (counter >> 16);
  counter_bytes[2] = (u8) (counter >> 8);
  counter_bytes[3] = (u8) (counter >> 0);

  bip39_sha512_update (&inner_ctx, counter_bytes, 4u);

  bip39_sha512_final (&inner_ctx, out);

  for (u32 i = 0; i < 128; i++)
    key_buf[i] ^= 0x6a;

  bip39_sha512_ctx_t outer_ctx;

  bip39_sha512_init (&outer_ctx);
  bip39_sha512_update (&outer_ctx, key_buf, 128u);
  bip39_sha512_update (&outer_ctx, out, 64u);
  bip39_sha512_final (&outer_ctx, out);
}

DECLSPEC void bip39_pbkdf2_seed_from_passphrase_custom (GLOBAL_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, PRIVATE_AS const u8 *passphrase_bytes, const u32 passphrase_len, PRIVATE_AS u64 seed[8])
{
  if (passphrase_len > BIP39_MAX_PASSPHRASE_LEN)
  {
    return;
  }

  PRIVATE_AS u8 key_buf[128];

  if (mnemonic_len > 128u)
  {
    bip39_sha512_ctx_t key_ctx;

    bip39_sha512_init (&key_ctx);

    u32 offset = 0;

    while ((mnemonic_len - offset) >= 128u)
    {
      for (u32 i = 0; i < 128; i++)
        key_buf[i] = mnemonic_bytes[offset + i];
      bip39_sha512_update (&key_ctx, key_buf, 128u);
      offset += 128u;
    }

    const u32 rem = mnemonic_len - offset;

    if (rem > 0)
    {
      for (u32 i = 0; i < rem; i++)
        key_buf[i] = mnemonic_bytes[offset + i];
      bip39_sha512_update (&key_ctx, key_buf, rem);
    }

    bip39_sha512_final (&key_ctx, key_buf);
    for (u32 i = 64; i < 128; i++)
      key_buf[i] = 0;
  }
  else
  {
    for (u32 i = 0; i < mnemonic_len; i++)
      key_buf[i] = mnemonic_bytes[i];
    for (u32 i = mnemonic_len; i < 128u; i++)
      key_buf[i] = 0;
  }

  PRIVATE_AS u64 inner_state[8];
  PRIVATE_AS u64 outer_state[8];

  bip39_hmac_sha512_prehash_states (key_buf, inner_state, outer_state);

  PRIVATE_AS u8 salt_buf[BIP39_MAX_PASSPHRASE_LEN + 12];
  const u8 salt_prefix_local[8] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };

  for (u32 i = 0; i < 8; i++)
    salt_buf[i] = salt_prefix_local[i];
  for (u32 i = 0; i < passphrase_len; i++)
    salt_buf[8 + i] = passphrase_bytes[i];

  salt_buf[8 + passphrase_len + 0] = 0;
  salt_buf[8 + passphrase_len + 1] = 0;
  salt_buf[8 + passphrase_len + 2] = 0;
  salt_buf[8 + passphrase_len + 3] = 1;

  const u32 salt_len = 8 + passphrase_len + 4;

  PRIVATE_AS u8 digest_bytes[64];
  PRIVATE_AS u64 u_prev[8];
  PRIVATE_AS u64 u_xor[8];

  bip39_hmac_sha512_from_prehashed (inner_state, outer_state, salt_buf, salt_len, digest_bytes);
  bip39_bytes_to_u64_be (digest_bytes, u_prev);

  for (u32 i = 0; i < 8; i++)
  {
    u_xor[i] = u_prev[i];
  }

  for (u32 iter = 1; iter < 2048; iter++)
  {
    bip39_u64_to_bytes_be (u_prev, digest_bytes);
    bip39_hmac_sha512_from_prehashed (inner_state, outer_state, digest_bytes, 64u, digest_bytes);
    bip39_bytes_to_u64_be (digest_bytes, u_prev);

    for (u32 i = 0; i < 8; i++)
    {
      u_xor[i] ^= u_prev[i];
    }
  }

  for (u32 i = 0; i < 8; i++)
    seed[i] = u_xor[i];
}

DECLSPEC void bip39_pbkdf2_u1 (GLOBAL_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, PRIVATE_AS const u8 *passphrase_bytes, const u32 passphrase_len, PRIVATE_AS u64 seed[8])
{
  if (passphrase_len > BIP39_MAX_PASSPHRASE_LEN)
  {
    return;
  }

  const u32 pass_len_use = passphrase_len;

  bip39_pbkdf2_seed_from_passphrase_custom (mnemonic_bytes, mnemonic_len, passphrase_bytes, pass_len_use, seed);
}

#else

DECLSPEC void bip39_pbkdf2_u1 (GLOBAL_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, PRIVATE_AS const u8 *passphrase_bytes, const u32 passphrase_len, PRIVATE_AS u64 seed[8])
{
  if (passphrase_len > BIP39_MAX_PASSPHRASE_LEN)
  {
    return;
  }

  const u32 pass_len_use = passphrase_len;

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_global_swap (&ctx, (GLOBAL_AS const u32 *) mnemonic_bytes, mnemonic_len);

  const sha512_hmac_ctx_t ctx_base = ctx;

  const u32 salt_len = BIP39_SALT_PREFIX_LEN + pass_len_use;
  const u32 total_len = salt_len + 4u;

  PRIVATE_AS u32 salt_words[BIP39_SALT_WORDS];

  for (u32 i = 0; i < BIP39_SALT_WORDS; i++)
  {
    salt_words[i] = 0;
  }

  const u8 prefix[BIP39_SALT_PREFIX_LEN] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };

  for (u32 i = 0; i < salt_len; i++)
  {
    const u8 src = (i < BIP39_SALT_PREFIX_LEN) ? prefix[i] : passphrase_bytes[i - BIP39_SALT_PREFIX_LEN];

    const u32 word_idx = i >> 2;
    const u32 shift = (i & 3u) << 3;

    salt_words[word_idx] |= ((u32) src) << shift;
  }

  const u8 counter_bytes[4] = { 0, 0, 0, 1 };

  for (u32 i = 0; i < 4; i++)
  {
    const u32 pos = salt_len + i;
    const u32 word_idx = pos >> 2;
    const u32 shift = (pos & 3u) << 3;

    salt_words[word_idx] |= ((u32) counter_bytes[i]) << shift;
  }

  sha512_hmac_ctx_t ctx_iter = ctx_base;

  sha512_hmac_update_swap (&ctx_iter, salt_words, total_len);
  sha512_hmac_final (&ctx_iter);

  PRIVATE_AS u64 u_prev[8];
  PRIVATE_AS u64 u_xor[8];

  for (u32 i = 0; i < 8; i++)
  {
    const u64 word = ctx_iter.opad.h[i];

    u_prev[i] = word;
    u_xor[i] = word;
  }

  for (u32 iter = 1; iter < 2048; iter++)
  {
    ctx_iter = ctx_base;

    sha512_ctx_t *ipad = &ctx_iter.ipad;

    ipad->w0[0] = h32_from_64_S (u_prev[0]);
    ipad->w0[1] = l32_from_64_S (u_prev[0]);
    ipad->w0[2] = h32_from_64_S (u_prev[1]);
    ipad->w0[3] = l32_from_64_S (u_prev[1]);

    ipad->w1[0] = h32_from_64_S (u_prev[2]);
    ipad->w1[1] = l32_from_64_S (u_prev[2]);
    ipad->w1[2] = h32_from_64_S (u_prev[3]);
    ipad->w1[3] = l32_from_64_S (u_prev[3]);

    ipad->w2[0] = h32_from_64_S (u_prev[4]);
    ipad->w2[1] = l32_from_64_S (u_prev[4]);
    ipad->w2[2] = h32_from_64_S (u_prev[5]);
    ipad->w2[3] = l32_from_64_S (u_prev[5]);

    ipad->w3[0] = h32_from_64_S (u_prev[6]);
    ipad->w3[1] = l32_from_64_S (u_prev[6]);
    ipad->w3[2] = h32_from_64_S (u_prev[7]);
    ipad->w3[3] = l32_from_64_S (u_prev[7]);

    sha512_hmac_update_128 (&ctx_iter, ipad->w0, ipad->w1, ipad->w2, ipad->w3, ipad->w4, ipad->w5, ipad->w6, ipad->w7, 64);

    for (u32 i = 0; i < 4; i++)
    {
      ipad->w4[i] = 0;
      ipad->w5[i] = 0;
      ipad->w6[i] = 0;
      ipad->w7[i] = 0;
    }
    sha512_hmac_final (&ctx_iter);

    for (u32 i = 0; i < 8; i++)
    {
      const u64 word = ctx_iter.opad.h[i];

      u_prev[i] = word;
      u_xor[i] ^= word;
    }

  }

  for (u32 i = 0; i < 8; i++)
    seed[i] = u_xor[i];
}

#endif

DECLSPEC void bip39_pbkdf2_u1_from_global (GLOBAL_AS const u8 *mnemonic_bytes, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase_bytes, const u32 passphrase_len, PRIVATE_AS u64 seed[8])
{
  if (passphrase_len > BIP39_MAX_PASSPHRASE_LEN)
  {
    return;
  }

  const u32 pass_len_raw = passphrase_len;

  // ASCII-only: use raw UTF-8 bytes directly (no NFKD normalization)
  PRIVATE_AS u8 passphrase_buf[BIP39_MAX_PASSPHRASE_LEN];

  for (u32 i = 0; i < pass_len_raw; i++)
  {
    passphrase_buf[i] = passphrase_bytes[i];
  }

  bip39_pbkdf2_seed_from_passphrase_custom (mnemonic_bytes, mnemonic_len, passphrase_buf, pass_len_raw, seed);
}

#if BIP39_USE_CUSTOM_SHA512

DECLSPEC void bip39_derive_bip32_master (PRIVATE_AS const u64 seed[8], PRIVATE_AS u64 master[8])
{
  PRIVATE_AS u8 seed_bytes[64];

  bip39_u64_to_bytes_be (seed, seed_bytes);

  const u8 key_bytes[12] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };

  PRIVATE_AS u8 digest[64];

  bip39_hmac_sha512 (key_bytes, 12u, seed_bytes, 64u, digest);
  bip39_bytes_to_u64_be (digest, master);
}

#else

DECLSPEC void bip39_derive_bip32_master (PRIVATE_AS const u64 seed[8], PRIVATE_AS u64 master[8])
{
  PRIVATE_AS u32 key_words[32];

  for (u32 i = 0; i < 32; i++)
    key_words[i] = 0;

  const u8 key_bytes[12] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };

  for (u32 i = 0; i < 12; i++)
  {
    const u32 word_idx = i >> 2;
    const u32 shift = (i & 3u) << 3;

    key_words[word_idx] |= ((u32) key_bytes[i]) << shift;
  }

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_swap (&ctx, key_words, 12);

  PRIVATE_AS u32 w0[4];
  PRIVATE_AS u32 w1[4];
  PRIVATE_AS u32 w2[4];
  PRIVATE_AS u32 w3[4];
  PRIVATE_AS u32 w4[4];
  PRIVATE_AS u32 w5[4];
  PRIVATE_AS u32 w6[4];
  PRIVATE_AS u32 w7[4];

  for (u32 i = 0; i < 4; i++)
  {
    w0[i] = 0;
    w1[i] = 0;
    w2[i] = 0;
    w3[i] = 0;
    w4[i] = 0;
    w5[i] = 0;
    w6[i] = 0;
    w7[i] = 0;
  }

  w0[0] = h32_from_64_S (seed[0]);
  w0[1] = l32_from_64_S (seed[0]);
  w0[2] = h32_from_64_S (seed[1]);
  w0[3] = l32_from_64_S (seed[1]);

  w1[0] = h32_from_64_S (seed[2]);
  w1[1] = l32_from_64_S (seed[2]);
  w1[2] = h32_from_64_S (seed[3]);
  w1[3] = l32_from_64_S (seed[3]);

  w2[0] = h32_from_64_S (seed[4]);
  w2[1] = l32_from_64_S (seed[4]);
  w2[2] = h32_from_64_S (seed[5]);
  w2[3] = l32_from_64_S (seed[5]);

  w3[0] = h32_from_64_S (seed[6]);
  w3[1] = l32_from_64_S (seed[6]);
  w3[2] = h32_from_64_S (seed[7]);
  w3[3] = l32_from_64_S (seed[7]);

  sha512_hmac_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);
  sha512_hmac_final (&ctx);

  for (u32 i = 0; i < 8; i++)
    master[i] = ctx.opad.h[i];
}

#endif

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

DECLSPEC void bip39_bytes_to_words_for_hmac (PRIVATE_AS const u8 *src, const u32 len, PRIVATE_AS u32 *dst, const u32 dst_words)
{
  for (u32 i = 0; i < dst_words; i++)
    dst[i] = 0;

  for (u32 i = 0; i < len; i++)
  {
    const u32 word_idx = i >> 2;
    const u32 shift = (i & 3u) << 3;

    dst[word_idx] |= ((u32) src[i]) << shift;
  }
}

// SHA256 helper supporting up to two blocks of input (<= 128 bytes).
// NOTE: This function is no longer called directly - we inline sha256_init/update/final at call sites to bypass NVIDIA bug
DECLSPEC void bip39_sha256_small (PRIVATE_AS const u8 *data, const u32 len, PRIVATE_AS u32 *out_words)
{
#if BIP39_DISABLE_SHA256_SMALL
  if (out_words != 0)
  {
    for (u32 i = 0; i < 8; i++)
      out_words[i] = 0;
  }

  return;
#else
  const u32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  u32 h0 = 0x6a09e667;
  u32 h1 = 0xbb67ae85;
  u32 h2 = 0x3c6ef372;
  u32 h3 = 0xa54ff53a;
  u32 h4 = 0x510e527f;
  u32 h5 = 0x9b05688c;
  u32 h6 = 0x1f83d9ab;
  u32 h7 = 0x5be0cd19;

  PRIVATE_AS u32 w[64];

  u32 offset = 0;

  while ((offset + 64u) <= len)
  {
    for (u32 i = 0; i < 16; i++)
    {
      const u32 base = offset + (i * 4u);

      w[i] = ((u32) data[base + 0] << 24) | ((u32) data[base + 1] << 16) | ((u32) data[base + 2] << 8) | ((u32) data[base + 3] << 0);
    }

    for (u32 i = 16; i < 64; i++)
    {
      const u32 s0 = ((w[i - 15] >> 7) | (w[i - 15] << (32 - 7))) ^ ((w[i - 15] >> 18) | (w[i - 15] << (32 - 18))) ^ (w[i - 15] >> 3);
      const u32 s1 = ((w[i - 2] >> 17) | (w[i - 2] << (32 - 17))) ^ ((w[i - 2] >> 19) | (w[i - 2] << (32 - 19))) ^ (w[i - 2] >> 10);

      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffffu;
    }

    u32 a = h0;
    u32 b = h1;
    u32 c = h2;
    u32 d = h3;
    u32 e = h4;
    u32 f = h5;
    u32 g = h6;
    u32 hh = h7;

    for (u32 i = 0; i < 64; i++)
    {
      const u32 S1 = ((e >> 6) | (e << (32 - 6))) ^ ((e >> 11) | (e << (32 - 11))) ^ ((e >> 25) | (e << (32 - 25)));
      const u32 ch = (e & f) ^ ((~e) & g);
      const u32 temp1 = (hh + S1 + ch + k[i] + w[i]) & 0xffffffffu;
      const u32 S0 = ((a >> 2) | (a << (32 - 2))) ^ ((a >> 13) | (a << (32 - 13))) ^ ((a >> 22) | (a << (32 - 22)));
      const u32 maj = (a & b) ^ (a & c) ^ (b & c);
      const u32 temp2 = (S0 + maj) & 0xffffffffu;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffffu;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffffu;
    }

    h0 = (h0 + a) & 0xffffffffu;
    h1 = (h1 + b) & 0xffffffffu;
    h2 = (h2 + c) & 0xffffffffu;
    h3 = (h3 + d) & 0xffffffffu;
    h4 = (h4 + e) & 0xffffffffu;
    h5 = (h5 + f) & 0xffffffffu;
    h6 = (h6 + g) & 0xffffffffu;
    h7 = (h7 + hh) & 0xffffffffu;

    offset += 64u;
  }

  PRIVATE_AS u8 tail[128];

  const u32 rem = len - offset;

  for (u32 i = 0; i < rem; i++)
    tail[i] = data[offset + i];
  tail[rem] = 0x80;

  const u32 tail_total = (rem + 1u <= 56u) ? 64u : 128u;

  for (u32 i = rem + 1u; i < tail_total; i++)
    tail[i] = 0;

  const u64 bit_len = (u64) len * 8u;

  tail[tail_total - 8u + 0] = (u8) (bit_len >> 56);
  tail[tail_total - 8u + 1] = (u8) (bit_len >> 48);
  tail[tail_total - 8u + 2] = (u8) (bit_len >> 40);
  tail[tail_total - 8u + 3] = (u8) (bit_len >> 32);
  tail[tail_total - 8u + 4] = (u8) (bit_len >> 24);
  tail[tail_total - 8u + 5] = (u8) (bit_len >> 16);
  tail[tail_total - 8u + 6] = (u8) (bit_len >> 8);
  tail[tail_total - 8u + 7] = (u8) (bit_len >> 0);

  u32 tail_offset = 0;

  while (tail_offset < tail_total)
  {
    for (u32 i = 0; i < 16; i++)
    {
      const u32 base = tail_offset + (i * 4u);

      w[i] = ((u32) tail[base + 0] << 24) | ((u32) tail[base + 1] << 16) | ((u32) tail[base + 2] << 8) | ((u32) tail[base + 3] << 0);
    }

    for (u32 i = 16; i < 64; i++)
    {
      const u32 s0 = ((w[i - 15] >> 7) | (w[i - 15] << (32 - 7))) ^ ((w[i - 15] >> 18) | (w[i - 15] << (32 - 18))) ^ (w[i - 15] >> 3);
      const u32 s1 = ((w[i - 2] >> 17) | (w[i - 2] << (32 - 17))) ^ ((w[i - 2] >> 19) | (w[i - 2] << (32 - 19))) ^ (w[i - 2] >> 10);

      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffffu;
    }

    u32 a = h0;
    u32 b = h1;
    u32 c = h2;
    u32 d = h3;
    u32 e = h4;
    u32 f = h5;
    u32 g = h6;
    u32 hh = h7;

    for (u32 i = 0; i < 64; i++)
    {
      const u32 S1 = ((e >> 6) | (e << (32 - 6))) ^ ((e >> 11) | (e << (32 - 11))) ^ ((e >> 25) | (e << (32 - 25)));
      const u32 ch = (e & f) ^ ((~e) & g);
      const u32 temp1 = (hh + S1 + ch + k[i] + w[i]) & 0xffffffffu;
      const u32 S0 = ((a >> 2) | (a << (32 - 2))) ^ ((a >> 13) | (a << (32 - 13))) ^ ((a >> 22) | (a << (32 - 22)));
      const u32 maj = (a & b) ^ (a & c) ^ (b & c);
      const u32 temp2 = (S0 + maj) & 0xffffffffu;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffffu;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffffu;
    }

    h0 = (h0 + a) & 0xffffffffu;
    h1 = (h1 + b) & 0xffffffffu;
    h2 = (h2 + c) & 0xffffffffu;
    h3 = (h3 + d) & 0xffffffffu;
    h4 = (h4 + e) & 0xffffffffu;
    h5 = (h5 + f) & 0xffffffffu;
    h6 = (h6 + g) & 0xffffffffu;
    h7 = (h7 + hh) & 0xffffffffu;

    tail_offset += 64u;
  }

  out_words[0] = h0;
  out_words[1] = h1;
  out_words[2] = h2;
  out_words[3] = h3;
  out_words[4] = h4;
  out_words[5] = h5;
  out_words[6] = h6;
  out_words[7] = h7;
#endif
}

DECLSPEC void bip39_hmac_to_bytes (PRIVATE_AS const sha512_hmac_ctx_t *ctx, PRIVATE_AS u8 *out_bytes)
{
  for (u32 i = 0; i < 8; i++)
  {
    const u64 word = ctx->opad.h[i];

    out_bytes[(i * 8) + 0] = (u8) (word >> 56);
    out_bytes[(i * 8) + 1] = (u8) (word >> 48);
    out_bytes[(i * 8) + 2] = (u8) (word >> 40);
    out_bytes[(i * 8) + 3] = (u8) (word >> 32);
    out_bytes[(i * 8) + 4] = (u8) (word >> 24);
    out_bytes[(i * 8) + 5] = (u8) (word >> 16);
    out_bytes[(i * 8) + 6] = (u8) (word >> 8);
    out_bytes[(i * 8) + 7] = (u8) (word >> 0);
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
    if (il_be[i] > curve_n_be[i])
      return 1;
    if (il_be[i] < curve_n_be[i])
      return 0;
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
    for (int i = 7; i >= 0; i--)
    {
      if (r[i] > curve_n[i])
      {
        reduce = 1;
        break;
      }

      if (r[i] < curve_n[i])
        break;
    }
  }

  if (reduce)
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

  for (u32 i = 0; i < 8; i++)
    acc |= v[i];

  return (acc == 0);
}

DECLSPEC u32 bip39_bip32_child (const u32 index, PRIVATE_AS u32 *key_le, PRIVATE_AS u8 *key_bytes, PRIVATE_AS u8 *chain_bytes, PRIVATE_AS secp256k1_t *preG, PRIVATE_AS u32 *il_debug)
{
  PRIVATE_AS u8 data_bytes[37];

  u32 data_len = 0;

  if (index & 0x80000000)
  {
    data_bytes[0] = 0;

    for (u32 i = 0; i < 32; i++)
      data_bytes[1 + i] = key_bytes[i];

    data_len = 33;
  }
  else
  {
    u32 x[8];
    u32 y[8];

    for (u32 i = 0; i < 8; i++)
    {
      x[i] = 0;
      y[i] = 0;
    }

    point_mul_xy (x, y, key_le, preG);

    PRIVATE_AS u8 pub_bytes[33];

    pub_bytes[0] = (y[0] & 1u) ? 0x03 : 0x02;

    bip39_words_le_to_bytes_be32 (x, pub_bytes + 1);

    for (u32 i = 0; i < 33; i++)
      data_bytes[i] = pub_bytes[i];

    data_len = 33;
  }

  data_bytes[data_len + 0] = (u8) (index >> 24);
  data_bytes[data_len + 1] = (u8) (index >> 16);
  data_bytes[data_len + 2] = (u8) (index >> 8);
  data_bytes[data_len + 3] = (u8) (index >> 0);

  data_len += 4;

  PRIVATE_AS u8 hmac_bytes[64];

#if BIP39_USE_CUSTOM_SHA512

#if BIP39_DEBUG_PRINT
  PRIVATE_AS u32 key_words_dbg[32];

  bip39_bytes_to_words_for_hmac (chain_bytes, 32, key_words_dbg, 32);
  printf ("[m32001] chain words: %08x %08x %08x %08x %08x %08x %08x %08x\n", key_words_dbg[0], key_words_dbg[1], key_words_dbg[2], key_words_dbg[3], key_words_dbg[4], key_words_dbg[5], key_words_dbg[6], key_words_dbg[7]);

  PRIVATE_AS u32 data_words_dbg[32];

  bip39_bytes_to_words_for_hmac (data_bytes, data_len, data_words_dbg, 32);
  printf ("[m32001] data words for index %08x (len %u): %08x %08x %08x %08x %08x %08x %08x %08x %08x\n", index, data_len, data_words_dbg[0], data_words_dbg[1], data_words_dbg[2], data_words_dbg[3], data_words_dbg[4], data_words_dbg[5], data_words_dbg[6], data_words_dbg[7], data_words_dbg[8]);
#endif

  bip39_hmac_sha512 (chain_bytes, 32u, data_bytes, data_len, hmac_bytes);

#else

  PRIVATE_AS u32 key_words[32];

  bip39_bytes_to_words_for_hmac (chain_bytes, 32, key_words, 32);

#if BIP39_DEBUG_PRINT
  printf ("[m32001] chain words: %08x %08x %08x %08x %08x %08x %08x %08x\n", key_words[0], key_words[1], key_words[2], key_words[3], key_words[4], key_words[5], key_words[6], key_words[7]);
#endif

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_swap (&ctx, key_words, 32);

  PRIVATE_AS u32 data_words[32];

  bip39_bytes_to_words_for_hmac (data_bytes, data_len, data_words, 32);

#if BIP39_DEBUG_PRINT
  printf ("[m32001] data words for index %08x (len %u): %08x %08x %08x %08x %08x %08x %08x %08x %08x\n", index, data_len, data_words[0], data_words[1], data_words[2], data_words[3], data_words[4], data_words[5], data_words[6], data_words[7], data_words[8]);
#endif

  sha512_hmac_update_swap (&ctx, data_words, data_len);
  sha512_hmac_final (&ctx);

  bip39_hmac_to_bytes (&ctx, hmac_bytes);

#endif

  PRIVATE_AS const u8 *il_bytes = hmac_bytes;
  PRIVATE_AS const u8 *ir_bytes = hmac_bytes + 32;

#if BIP39_DEBUG_PRINT
  printf ("[m32001] IL bytes: ");
  for (u32 i = 0; i < 32; i++)
    printf ("%02x", il_bytes[i]);
  printf ("\n");
#endif

  if (bip39_il_ge_curve_n (il_bytes))
  {
#if BIP39_DEBUG_PRINT
    printf ("[m32001] IL >= n for index %08x\n", index);
#endif

    return 0;
  }

  PRIVATE_AS u32 il_le[8];

  bip39_bytes_be32_to_words_le (il_bytes, il_le);

#if BIP39_DEBUG_PRINT
  printf ("[m32001] parent key words: %08x %08x %08x %08x %08x %08x %08x %08x\n", key_le[0], key_le[1], key_le[2], key_le[3], key_le[4], key_le[5], key_le[6], key_le[7]);
  printf ("[m32001] IL words for index %08x: %08x %08x %08x %08x %08x %08x %08x %08x\n", index, il_le[0], il_le[1], il_le[2], il_le[3], il_le[4], il_le[5], il_le[6], il_le[7]);
#endif

  if (il_debug != 0)
  {
    for (u32 i = 0; i < 8; i++)
      il_debug[i] = il_le[i];
  }

  PRIVATE_AS u32 child_le[8];

  bip39_add_mod_n (child_le, key_le, il_le);

  if (bip39_scalar_is_zero (child_le))
  {
#if BIP39_DEBUG_PRINT
    printf ("[m32001] child key zero for index %08x\n", index);
#endif

    return 0;
  }

  for (u32 i = 0; i < 8; i++)
    key_le[i] = child_le[i];

  bip39_words_le_to_bytes_be32 (key_le, key_bytes);

#if BIP39_DEBUG_PRINT
  printf ("[m32001] child key words: %08x %08x %08x %08x %08x %08x %08x %08x\n", child_le[0], child_le[1], child_le[2], child_le[3], child_le[4], child_le[5], child_le[6], child_le[7]);
#endif

  for (u32 i = 0; i < 32; i++)
    chain_bytes[i] = ir_bytes[i];

#if BIP39_DEBUG_PRINT
  printf ("[m32001] derived child key for index %08x\n", index);
#endif

  return 1;
}

DECLSPEC void bip39_compute_key_hashes (PRIVATE_AS const u32 *priv_le, PRIVATE_AS secp256k1_t *preG, PRIVATE_AS u32 *out_hash160, PRIVATE_AS u32 *out_script_hash, const bool debug_dump)
{
#if BIP39_DISABLE_KEY_HASHES
  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = 0;
  }

  if (out_script_hash != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_script_hash[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass key hash compute: <disabled>\n");
  }
#endif

  return;
#else
  u32 x[8];
  u32 y[8];

  for (u32 i = 0; i < 8; i++)
  {
    x[i] = 0;
    y[i] = 0;
  }

#if BIP39_DISABLE_POINT_MUL == 0
  point_mul_xy (x, y, priv_le, preG);
#endif

#if BIP39_DISABLE_KEY_HASHES_AFTER_POINT
  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = 0;
  }

  if (out_script_hash != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_script_hash[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] key-hash stage truncated after point multiply\n");
  }
#endif

  return;
#else
  PRIVATE_AS u8 pub_bytes[33];

  pub_bytes[0] = (y[0] & 1u) ? 0x03 : 0x02;

  bip39_words_le_to_bytes_be32 (x, pub_bytes + 1);

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass point x:");
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x", x[i]);
    }
    printf ("\n");

    printf ("[m32001] testpass point y:");
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x", y[i]);
    }
    printf ("\n");

    printf ("[m32001] testpass pubkey:");
    for (u32 i = 0; i < 33; i++)
      printf (" %02x", pub_bytes[i]);
    printf ("\n");
  }
#endif

#if BIP39_DISABLE_KEY_HASHES_AFTER_PUB
  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = 0;
  }

  if (out_script_hash != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_script_hash[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] key-hash stage truncated after pubkey bytes\n");
  }
#endif

  return;
#else
  PRIVATE_AS u32 pub_sha[8];

#if BIP39_DISABLE_PUBKEY_HASH == 0
  // Manual inline SHA-256 for pub_bytes (33 bytes) - bypasses NVIDIA function call bug
  {
    sha256_ctx_t sha_ctx;
    sha256_init (&sha_ctx);

    PRIVATE_AS u32 pub_w[16];
    for (u32 i = 0; i < 16; i++) pub_w[i] = 0;

    for (u32 i = 0; i < 33; i++)
      pub_w[i / 4] |= ((u32) pub_bytes[i]) << ((3 - (i % 4)) * 8);

    sha256_update (&sha_ctx, pub_w, 33);
    sha256_final (&sha_ctx);

    for (u32 i = 0; i < 8; i++)
      pub_sha[i] = sha_ctx.h[i];
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass sha256(pubkey):");
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x", pub_sha[i]);
    }
    printf ("\n");
  }
#endif
#else
  for (u32 i = 0; i < 8; i++)
  {
    pub_sha[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass sha256(pubkey): <disabled>\n");
  }
#endif
#endif

#if BIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA
  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = 0;
  }

  if (out_script_hash != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_script_hash[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] key-hash stage truncated after pubkey sha\n");
  }
#endif

  return;
#else
#if BIP39_DISABLE_SCRIPT_HASH == 0
  u32 tmp[16];

  for (u32 i = 0; i < 8; i++)
    tmp[i] = pub_sha[i];
  for (u32 i = 8; i < 16; i++)
    tmp[i] = 0;

  ripemd160_ctx_t ripemd_ctx;

  ripemd160_init (&ripemd_ctx);
  ripemd160_update_swap (&ripemd_ctx, tmp, 32);
  ripemd160_final (&ripemd_ctx);

  u32 hash160_words[5];

  for (u32 i = 0; i < 5; i++)
  {
    hash160_words[i] = ripemd_ctx.h[i];
  }

  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = hash160_words[i];
  }

  PRIVATE_AS u8 script_bytes[22];

  script_bytes[0] = 0x00;
  script_bytes[1] = 0x14;

  for (u32 i = 0; i < 5; i++)
  {
    const u32 word = hash160_words[i];

    script_bytes[2 + (i * 4) + 0] = (u8) (word & 0xff);
    script_bytes[2 + (i * 4) + 1] = (u8) ((word >> 8) & 0xff);
    script_bytes[2 + (i * 4) + 2] = (u8) ((word >> 16) & 0xff);
    script_bytes[2 + (i * 4) + 3] = (u8) ((word >> 24) & 0xff);
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass script bytes:");
    for (u32 i = 0; i < 22; i++)
      printf (" %02x", script_bytes[i]);
    printf ("\n");
  }
#endif

  PRIVATE_AS u32 script_sha[8];

  // Manual inline SHA-256 for script_bytes (22 bytes) - bypasses NVIDIA function call bug
  {
    sha256_ctx_t sha_ctx;
    sha256_init (&sha_ctx);

    PRIVATE_AS u32 script_w[16];
    for (u32 i = 0; i < 16; i++) script_w[i] = 0;

    for (u32 i = 0; i < 22; i++)
      script_w[i / 4] |= ((u32) script_bytes[i]) << ((3 - (i % 4)) * 8);

    sha256_update (&sha_ctx, script_w, 22);
    sha256_final (&sha_ctx);

    for (u32 i = 0; i < 8; i++)
      script_sha[i] = sha_ctx.h[i];
  }

  for (u32 i = 0; i < 8; i++)
    tmp[i] = script_sha[i];
  for (u32 i = 8; i < 16; i++)
    tmp[i] = 0;

  ripemd160_init (&ripemd_ctx);
  ripemd160_update_swap (&ripemd_ctx, tmp, 32);
  ripemd160_final (&ripemd_ctx);

  if (out_script_hash != 0)
  {
    out_script_hash[0] = ripemd_ctx.h[0];
    out_script_hash[1] = ripemd_ctx.h[1];
    out_script_hash[2] = ripemd_ctx.h[2];
    out_script_hash[3] = ripemd_ctx.h[3];
    out_script_hash[4] = ripemd_ctx.h[4];
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass final script hash:");
    if (out_script_hash != 0)
    {
      for (u32 i = 0; i < 5; i++)
        printf (" %08x", out_script_hash[i]);
    }
    else
    {
      for (u32 i = 0; i < 5; i++)
        printf (" %08x", ripemd_ctx.h[i]);
    }
    printf ("\n");
  }
#endif
#else
  if (out_hash160 != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_hash160[i] = 0;
  }

  if (out_script_hash != 0)
  {
    for (u32 i = 0; i < 5; i++)
      out_script_hash[i] = 0;
  }

#if BIP39_DEBUG_PRINT
  if (debug_dump)
  {
    printf ("[m32001] testpass script bytes: <disabled>\n");
    printf ("[m32001] testpass final script hash: <disabled>\n");
  }
#endif
#endif
#endif // BIP39_DISABLE_KEY_HASHES_AFTER_PUB_SHA
#endif // BIP39_DISABLE_KEY_HASHES_AFTER_PUB
#endif // BIP39_DISABLE_KEY_HASHES_AFTER_POINT
#endif
}

#if BIP39_TEST_ONLY == 0
#if BIP39_DISABLE_INIT_BODY
KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;
  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_total = esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;
  tmps[gid].debug_combo_idx = 0;
}
#elif BIP39_DISABLE_INIT_AFTER_PASSPHRASE
KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;
  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_total = esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;
  tmps[gid].debug_combo_idx = 0;

  return;
}
#elif BIP39_DISABLE_INIT_AFTER_PBKDF2
KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;
  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_total = esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;
  tmps[gid].debug_combo_idx = 0;

  const u32 pw_len = 0;
  const u32 pass_len_raw = 0;

  PRIVATE_AS u8 passphrase_buf[BIP39_MAX_PASSPHRASE_LEN];

  for (u32 i = 0; i < pass_len_raw; i++)
  {
    passphrase_buf[i] = 0;
  }

  PRIVATE_AS u64 seed[8];

  for (u32 i = 0; i < 8; i++)
    seed[i] = 0;

  bip39_pbkdf2_u1 ((GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic, esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len, passphrase_buf, pass_len_raw, seed);

  return;
}
#elif BIP39_DISABLE_INIT_AFTER_BIP32
KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;
  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_total = esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;
  tmps[gid].debug_combo_idx = 0;

  const u32 pw_len = 0;
  const u32 pass_len_raw = 0;

  PRIVATE_AS u8 passphrase_buf[BIP39_MAX_PASSPHRASE_LEN];

  for (u32 i = 0; i < pass_len_raw; i++)
  {
    passphrase_buf[i] = 0;
  }

  PRIVATE_AS u64 seed[8];
  PRIVATE_AS u64 master[8];

  for (u32 i = 0; i < 8; i++)
    seed[i] = 0;

  bip39_pbkdf2_u1 ((GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic, esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len, passphrase_buf, pass_len_raw, seed);

  bip39_derive_bip32_master (seed, master);

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = master[i];

  tmps[gid].master_ready = 1;

  return;
}
#else
KERNEL_FQ void m32001_init (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

#if BIP39_DEBUG_GID != 0xffffffffu
  const bool debug_gid = (gid == (u64) BIP39_DEBUG_GID);
#else
  const bool debug_gid = false;
#endif

#if BIP39_PROFILE
  u32 profile_clk0 = (u32) clock ();
  u32 profile_clk1 = profile_clk0;
  u32 profile_clk2 = profile_clk0;
  u32 profile_clk3 = profile_clk0;
#endif

  for (u32 i = 0; i < 8; i++)
    tmps[gid].master[i] = 0;
  for (u32 i = 0; i < 5; i++)
    tmps[gid].script_hash[i] = 0;

  tmps[gid].derived_ready = 0;
  tmps[gid].debug_combo_total = esalt_bufs[DIGESTS_OFFSET_HOST].path_combo_total;
  tmps[gid].debug_combo_idx = 0;

  const u32 pw_len = pws[gid].pw_len;
  if (pw_len > BIP39_MAX_PASSPHRASE_LEN)
  {
#if BIP39_DEBUG_PRINT
    if (gid == 0)
    {
      printf("[m32001] passphrase too long (%u > %u); skipping candidate\n", pw_len, BIP39_MAX_PASSPHRASE_LEN);
    }
#endif
    return;
  }

  const u32 pass_len_raw = pw_len;

#if BIP39_DISABLE_AFTER_PASSPHRASE == 1
  return;
#else

  PRIVATE_AS u64 seed[8];
  PRIVATE_AS u64 master[8];

  // ASCII-only: use raw UTF-8 bytes directly (no NFKD normalization)
  PRIVATE_AS u8 passphrase_buf[BIP39_MAX_PASSPHRASE_LEN];

  for (u32 i = 0; i < pass_len_raw; i++)
  {
    passphrase_buf[i] = bip39_pw_get_byte (pws, gid, i);
  }

#if BIP39_DEBUG_PRINT
  if (gid == 5)
  {
    printf ("\n[m32001] gid 5 passphrase len %u hex:", pass_len_raw);
    for (u32 i = 0; i < pass_len_raw; i++)
      printf (" %02x", bip39_pw_get_byte (pws, gid, i));
    printf (" ascii=\"");
    for (u32 i = 0; i < pass_len_raw; i++)
    {
      const u8 ch = bip39_pw_get_byte (pws, gid, i);

      printf ((ch >= 32 && ch <= 126) ? "%c" : ".", ch);
    }
    printf ("\"\n");
  }
#endif

  const bool is_testpass = (pass_len_raw == 8) && (passphrase_buf[0] == 't') && (passphrase_buf[1] == 'e') && (passphrase_buf[2] == 's') && (passphrase_buf[3] == 't') && (passphrase_buf[4] == 'p') && (passphrase_buf[5] == 'a') && (passphrase_buf[6] == 's') && (passphrase_buf[7] == 's');

  for (u32 i = 0; i < 8; i++)
  {
    seed[i] = 0;
  }

#if BIP39_DISABLE_PBKDF2 == 0
  bip39_pbkdf2_u1 ((GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic, esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len, passphrase_buf, pass_len_raw, seed);
#endif

#if BIP39_DISABLE_AFTER_PBKDF2 == 0

#if BIP39_DEBUG_PRINT
  if (is_testpass)
  {
#if BIP39_DISABLE_PBKDF2 == 0
    PRIVATE_AS u64 seed_check[8];

    bip39_pbkdf2_u1_from_global ((GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic, esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len, (GLOBAL_AS const u8 *) pws[gid].i, pass_len_raw, seed_check);

    printf ("[m32001] testpass seed_check:");
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x%08x", h32_from_64_S (seed_check[i]), l32_from_64_S (seed_check[i]));
    }
    printf ("\n");
#else
    printf ("[m32001] testpass seed_check: <pbkdf2 disabled>\n");
#endif
  }
#endif

  for (u32 i = 0; i < 8; i++)
  {
    master[i] = 0;
  }

#if BIP39_DISABLE_BIP32_MASTER == 0
  bip39_derive_bip32_master (seed, master);
#endif

#if BIP39_DISABLE_AFTER_BIP32 == 0

#if BIP39_PROFILE
  profile_clk1 = (u32) clock ();
#endif

#if BIP39_DEBUG_PRINT
  if (is_testpass)
  {
    printf ("[m32001] *** located testpass on gid %u (len %u) ***\n", (u32) gid, pass_len_raw);
    printf ("[m32001] testpass hex:");
    for (u32 i = 0; i < pass_len_raw; i++)
      printf (" %02x", passphrase_buf[i]);
    printf (" ascii=\"");
    for (u32 i = 0; i < pass_len_raw; i++)
    {
      const u8 ch = passphrase_buf[i];

      printf ((ch >= 32 && ch <= 126) ? "%c" : ".", ch);
    }
    printf ("\"\n");

    printf ("[m32001] testpass seed:");
#if BIP39_DISABLE_PBKDF2 == 0
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x%08x", h32_from_64_S (seed[i]), l32_from_64_S (seed[i]));
    }
    printf ("\n");
#else
    printf (" <pbkdf2 disabled>\n");
#endif

    printf ("[m32001] testpass master:");
#if BIP39_DISABLE_BIP32_MASTER == 0
    for (u32 i = 0; i < 8; i++)
    {
      printf (" %08x%08x", h32_from_64_S (master[i]), l32_from_64_S (master[i]));
    }
    printf ("\n");
#else
    printf (" <bip32 disabled>\n");
#endif

    const u32 mlen = esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic_len;

    printf ("[m32001] testpass mnemonic len %u bytes:\n", mlen);
    printf ("[m32001] testpass mnemonic bytes:");
    for (u32 i = 0; i < mlen; i++)
    {
      printf (" %02x", esalt_bufs[DIGESTS_OFFSET_HOST].mnemonic[i]);
      if ((i % 32u) == 31u)
        printf ("\n[cont]");
    }
    printf ("\n");
  }
#endif



  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].master[i] = master[i];
  }

  tmps[gid].master_ready = 1;

  const u32 target_type = esalt_bufs[DIGESTS_OFFSET_HOST].target_type;

#if BIP39_DEBUG_PRINT
  if (gid == 0)
  {
    printf ("[m32001] DEVICE TARGET HASH: %08x %08x %08x %08x %08x (type %u)\n", esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[0], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[1], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[2], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[3], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[4], target_type);
  }
#endif

#if BIP39_DISABLE_PATH_DERIVE == 0

#if BIP39_DISABLE_PATH_WALK
  return;
#endif

  if ((target_type == BIP39_TARGET_P2SH) || (target_type == BIP39_TARGET_P2PKH) || (target_type == BIP39_TARGET_P2WPKH))
  {
#if BIP39_DISABLE_PATH_BLOCK
    return;
#else

    const u32 path_depth = esalt_bufs[DIGESTS_OFFSET_HOST].path_depth;
    const u32 dynamic_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].path_dynamic_count;

    if (dynamic_cnt == 0)
    {
#if BIP39_DISABLE_PATH_STATIC
      return;
#else

      PRIVATE_AS u8 master_bytes[64];

      for (u32 i = 0; i < 8; i++)
      {
        const u64 word = master[i];

        master_bytes[(i * 8) + 0] = (u8) (word >> 56);
        master_bytes[(i * 8) + 1] = (u8) (word >> 48);
        master_bytes[(i * 8) + 2] = (u8) (word >> 40);
        master_bytes[(i * 8) + 3] = (u8) (word >> 32);
        master_bytes[(i * 8) + 4] = (u8) (word >> 24);
        master_bytes[(i * 8) + 5] = (u8) (word >> 16);
        master_bytes[(i * 8) + 6] = (u8) (word >> 8);
        master_bytes[(i * 8) + 7] = (u8) (word >> 0);
      }

      PRIVATE_AS u32 path_values[BIP39_MAX_PATH_DEPTH];

      for (u32 i = 0; i < path_depth; i++)
      {
        path_values[i] = esalt_bufs[DIGESTS_OFFSET_HOST].path_indices[i];
      }

      PRIVATE_AS u8 key_bytes[32];
      PRIVATE_AS u8 chain_bytes[32];
      PRIVATE_AS u32 key_le[8];
      PRIVATE_AS u32 hash160_local[5];
      PRIVATE_AS u32 script_local[5];

      for (u32 i = 0; i < 32; i++)
      {
        key_bytes[i] = master_bytes[i];
        chain_bytes[i] = master_bytes[32 + i];
      }

      bip39_bytes_be32_to_words_le (key_bytes, key_le);

      secp256k1_t preG_local;

      set_precomputed_basepoint_g (&preG_local);

      u32 ok = 1;

#if BIP39_DISABLE_PATH_CHILDREN == 0

      for (u32 i = 0; i < path_depth; i++)
      {
        ok = bip39_bip32_child (path_values[i], key_le, key_bytes, chain_bytes, &preG_local, 0);

        if (ok == 0)
          break;
      }
#endif

      if (ok)
      {
#if BIP39_DISABLE_PATH_MATCH == 0

        // Monolithic: compute hashes immediately and compare
        bip39_compute_key_hashes (key_le, &preG_local, hash160_local, script_local, (is_testpass && gid == 0));

        const u32 *candidate_hash = (target_type == BIP39_TARGET_P2SH) ? script_local : hash160_local;

        for (u32 i = 0; i < 5; i++)
          tmps[gid].script_hash[i] = candidate_hash[i];

        tmps[gid].derived_ready = 1;

#endif
      }

      return;
#endif
    }

    if (dynamic_cnt > 0)
    {
#if BIP39_DISABLE_DYNAMIC_SECTION
      return;
#else
      PRIVATE_AS u8 master_bytes[64];

      for (u32 i = 0; i < 8; i++)
      {
        const u64 word = master[i];

        master_bytes[(i * 8) + 0] = (u8) (word >> 56);
        master_bytes[(i * 8) + 1] = (u8) (word >> 48);
        master_bytes[(i * 8) + 2] = (u8) (word >> 40);
        master_bytes[(i * 8) + 3] = (u8) (word >> 32);
        master_bytes[(i * 8) + 4] = (u8) (word >> 24);
        master_bytes[(i * 8) + 5] = (u8) (word >> 16);
        master_bytes[(i * 8) + 6] = (u8) (word >> 8);
        master_bytes[(i * 8) + 7] = (u8) (word >> 0);
      }

      secp256k1_t preG;

      set_precomputed_basepoint_g (&preG);

      PRIVATE_AS u32 path_values[BIP39_MAX_PATH_DEPTH];

      for (u32 i = 0; i < path_depth; i++)
      {
        path_values[i] = esalt_bufs[DIGESTS_OFFSET_HOST].path_indices[i];
      }

      PRIVATE_AS u8 key_bytes[32];
      PRIVATE_AS u8 chain_bytes[32];
      PRIVATE_AS u32 key_le[8];
      PRIVATE_AS u32 hash160_local[5];
      PRIVATE_AS u32 script_local[5];

      bool derived_ok = false;

      GLOBAL_AS const bip39_dynamic_segment_t *dynamic_segments = esalt_bufs[DIGESTS_OFFSET_HOST].dynamic_segments;
      GLOBAL_AS const u32 *dynamic_values = esalt_bufs[DIGESTS_OFFSET_HOST].dynamic_values;

      PRIVATE_AS u32 state[BIP39_MAX_DYNAMIC_SEGMENTS];

      for (u32 i = 0; i < dynamic_cnt; i++)
        state[i] = 0;

      u32 prefix_len = path_depth;

      for (u32 d = 0; d < dynamic_cnt; d++)
      {
        const u32 pos = dynamic_segments[d].position;

        if (pos < prefix_len)
          prefix_len = pos;
      }

      PRIVATE_AS u8 base_key_bytes[32];
      PRIVATE_AS u8 base_chain_bytes[32];
      PRIVATE_AS u32 base_key_le[8];

      for (u32 i = 0; i < 32; i++)
      {
        base_key_bytes[i] = master_bytes[i];
        base_chain_bytes[i] = master_bytes[32 + i];
      }

      bip39_bytes_be32_to_words_le (base_key_bytes, base_key_le);

      u32 prefix_ok = 1;

      for (u32 i = 0; i < prefix_len; i++)
      {
#if BIP39_DISABLE_PATH_CHILDREN == 0
        prefix_ok = bip39_bip32_child (path_values[i], base_key_le, base_key_bytes, base_chain_bytes, &preG, 0);

        if (prefix_ok == 0)
          break;
#endif
      }


#if BIP39_DISABLE_PATH_ITER
      return;
#endif

      bool finished = (prefix_ok == 0);

      while (finished == false)
      {
        for (u32 d = 0; d < dynamic_cnt; d++)
        {
          const bip39_dynamic_segment_t seg = dynamic_segments[d];

          u32 value = seg.start;

          if (seg.kind == BIP39_DYNAMIC_KIND_RANGE)
          {
            value = seg.start + (state[d] * seg.step);
          }
          else
          {
            value = dynamic_values[seg.values_offset + state[d]];
          }

          path_values[seg.position] = value;
        }

        u64 combo_idx = 0;
        u64 multiplier = 1;

        for (u32 idx = 0; idx < dynamic_cnt; idx++)
        {
          combo_idx += ((u64) state[idx]) * multiplier;
          multiplier *= (u64) dynamic_segments[idx].count;
        }

        tmps[gid].debug_combo_idx = combo_idx;

#if BIP39_DEBUG_PRINT
        if (gid == 0)
        {
          printf("[m32001] init: combo_idx=%llu combo_total=%llu dynamic_cnt=%u\n",
                 (ulong) combo_idx, (ulong) tmps[gid].debug_combo_total, dynamic_cnt);
        }
#endif

        for (u32 i = 0; i < 32; i++)
        {
          key_bytes[i] = base_key_bytes[i];
          chain_bytes[i] = base_chain_bytes[i];
        }

        for (u32 i = 0; i < 8; i++)
          key_le[i] = base_key_le[i];

        u32 ok = 1;

        for (u32 i = prefix_len; i < path_depth; i++)
        {
#if BIP39_DISABLE_PATH_CHILDREN == 0
          ok = bip39_bip32_child (path_values[i], key_le, key_bytes, chain_bytes, &preG, 0);

          if (ok == 0)
            break;
#endif
        }

        if (ok)
        {
#if BIP39_PROFILE
          profile_clk2 = (u32) clock ();
#endif

#if BIP39_DISABLE_PATH_MATCH == 0

          // Monolithic: compute hashes immediately and compare
          bip39_compute_key_hashes (key_le, &preG, hash160_local, script_local, (is_testpass && gid == 0));

#if BIP39_PROFILE
          profile_clk3 = (u32) clock ();
#endif

          const u32 *candidate_hash = (target_type == BIP39_TARGET_P2SH) ? script_local : hash160_local;

          bool match = true;

          for (u32 i = 0; i < 5; i++)
          {
            if (candidate_hash[i] != esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[i])
            {
              match = false;
              break;
            }
          }

          if (match)
          {
            derived_ok = true;

            for (u32 i = 0; i < 5; i++)
              tmps[gid].script_hash[i] = candidate_hash[i];

#if BIP39_DEBUG_GID != 0xffffffffu
            if (debug_gid)
            {
              if (target_type == BIP39_TARGET_P2SH)
              {
                printf ("[m32001 dbg] gid %u script hash: %08x %08x %08x %08x %08x target: %08x %08x %08x %08x %08x\n", (u32) gid, script_local[0], script_local[1], script_local[2], script_local[3], script_local[4], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[0], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[1], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[2], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[3], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[4]);
              }
              else
              {
                printf ("[m32001 dbg] gid %u hash160 : %08x %08x %08x %08x %08x target: %08x %08x %08x %08x %08x\n", (u32) gid, hash160_local[0], hash160_local[1], hash160_local[2], hash160_local[3], hash160_local[4], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[0], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[1], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[2], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[3], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[4]);
              }
            }
#endif

            break;
          }

#else
          derived_ok = true;
#endif
        }

        u32 advance = 0;

        while (advance < dynamic_cnt)
        {
          state[advance]++;

          if (state[advance] < dynamic_segments[advance].count)
            break;

          state[advance] = 0;
          advance++;
        }

        if (advance == dynamic_cnt)
        {
          finished = true;
        }

        if (derived_ok)
          break;
      }

      // Monolithic: set ready flag if match found
      if (derived_ok)
      {
        tmps[gid].derived_ready = 1;
      }
#endif // BIP39_DISABLE_DYNAMIC_SECTION
    }
#endif // BIP39_DISABLE_PATH_BLOCK == 0
  }
#endif

#if BIP39_PROFILE
  if (gid == 0)
  {
    GLOBAL_AS u32 *profile_flags = (GLOBAL_AS u32 *) & esalt_bufs[DIGESTS_OFFSET_HOST].reserved;
    const u32 prev_flags = hc_atomic_or (profile_flags, 1u);

    if ((prev_flags & 1u) == 0u)
    {
      const u32 pbkdf_ticks = profile_clk1 - profile_clk0;
      const u32 derive_ticks = profile_clk2 - profile_clk1;
      const u32 script_ticks = profile_clk3 - profile_clk2;

      printf ("[m32001] profile gid=%u pbkdf2_ticks=%u derive_ticks=%u script_ticks=%u\n", (u32) gid, pbkdf_ticks, derive_ticks, script_ticks);
    }
  }
#endif

#if BIP39_DEBUG_PRINT
  if (gid == 0)
  {
    const u32 il0 = h32_from_64_S (master[0]);
    const u32 il1 = l32_from_64_S (master[0]);
    const u32 il2 = h32_from_64_S (master[1]);
    const u32 il3 = l32_from_64_S (master[1]);

    printf ("[m32001] master il: %08x %08x %08x %08x\n", il0, il1, il2, il3);

    if (target_type == BIP39_TARGET_P2SH)
    {
      if (tmps[gid].derived_ready)
      {
        printf ("[m32001] derived script hash: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
      else
      {
        printf ("[m32001] derived script hash: <invalid>\n");
      }
    }
    else if (target_type == BIP39_TARGET_P2PKH)
    {
      if (tmps[gid].derived_ready)
      {
        printf ("[m32001] derived hash160: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
      else
      {
        printf ("[m32001] derived hash160: <invalid>\n");
      }
    }
    else if (target_type == BIP39_TARGET_P2WPKH)
    {
      if (tmps[gid].derived_ready)
      {
        printf ("[m32001] derived witness prog: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
      else
      {
        printf ("[m32001] derived witness prog: <invalid>\n");
      }
    }
  }
#endif

}
#endif // BIP39_DISABLE_AFTER_BIP32 == 0
#endif // BIP39_DISABLE_AFTER_PBKDF2 == 0
#endif // BIP39_DISABLE_AFTER_PASSPHRASE

#endif

KERNEL_FQ void m32001_loop (KERN_ATTR_TMPS_HOOKS_ESALT (bip39_tmp_t, bip39_hook_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

#if BIP39_DISABLE_LOOP_BODY
  hooks[gid].debug_loop_pos  = LOOP_POS;
  hooks[gid].debug_loop_cnt  = LOOP_CNT;
  hooks[gid].debug_combo_idx = tmps[gid].debug_combo_idx;
  hooks[gid].debug_combo_total = tmps[gid].debug_combo_total;
  hooks[gid].reserved        = 0u;
  hooks[gid].reserved_extra0 = 0u;
  hooks[gid].reserved_extra1 = 0u;
  hooks[gid].reserved_extra2 = 0u;

#if BIP39_DEBUG_PRINT
  if (gid == 0)
  {
    printf("[m32001] loop: <disabled> loop_pos=%u loop_cnt=%u\n", LOOP_POS, LOOP_CNT);
  }
#endif

  return;
#else
  const u64 combo_idx = tmps[gid].debug_combo_idx;

  tmps[gid].debug_loop_pos = LOOP_POS;
  tmps[gid].debug_loop_cnt = LOOP_CNT;
  tmps[gid].debug_combo_idx = combo_idx;

  hooks[gid].debug_loop_pos  = tmps[gid].debug_loop_pos;
  hooks[gid].debug_loop_cnt  = tmps[gid].debug_loop_cnt;
  hooks[gid].debug_combo_idx = combo_idx;
  hooks[gid].debug_combo_total = tmps[gid].debug_combo_total;
  hooks[gid].reserved        = 0u;
  hooks[gid].reserved_extra0 = 0u;
  hooks[gid].reserved_extra1 = 0u;
  hooks[gid].reserved_extra2 = 0u;

#if BIP39_DEBUG_PRINT
  if (gid == 0)
  {
    printf("[m32001] loop: loop_pos=%u loop_cnt=%u combo_idx=%llu combo_total=%llu\n",
           LOOP_POS, LOOP_CNT, (ulong) combo_idx, (ulong) tmps[gid].debug_combo_total);
  }
#endif

  // Monolithic path: no-op for skeleton implementation (work done in init)

#endif // BIP39_DISABLE_LOOP_BODY
}

KERNEL_FQ KERNEL_FA void m32001_hook23 (KERN_ATTR_TMPS_HOOKS (bip39_tmp_t, bip39_hook_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  hooks[gid].debug_loop_pos  = tmps[gid].debug_loop_pos;
  hooks[gid].debug_loop_cnt  = tmps[gid].debug_loop_cnt;
  hooks[gid].debug_combo_idx = tmps[gid].debug_combo_idx;
  hooks[gid].debug_combo_total = tmps[gid].debug_combo_total;
  hooks[gid].reserved        = 0u;
  hooks[gid].reserved_extra0 = 0u;
  hooks[gid].reserved_extra1 = 0u;
  hooks[gid].reserved_extra2 = 0u;
}

KERNEL_FQ void m32001_comp (KERN_ATTR_TMPS_ESALT (bip39_tmp_t, bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

#if BIP39_DEBUG_GID != 0xffffffffu
  const bool debug_gid = (gid == (u64) BIP39_DEBUG_GID);
#else
  const bool debug_gid = false;
#endif

#if BIP39_DEBUG_PRINT
  if (gid == 0)
  {
    printf("[m32001] comp: gid=%llu combo_idx=%llu derived_ready=%u\n",
           gid, (ulong) tmps[gid].debug_combo_idx, tmps[gid].derived_ready);
  }
#endif

#define il_pos 0

  const u32 target_type = esalt_bufs[DIGESTS_OFFSET_HOST].target_type;

  if (target_type == BIP39_TARGET_IL_HEX)
  {
    const u32 r0 = h32_from_64_S (tmps[gid].master[0]);
    const u32 r1 = l32_from_64_S (tmps[gid].master[0]);
    const u32 r2 = h32_from_64_S (tmps[gid].master[1]);
    const u32 r3 = l32_from_64_S (tmps[gid].master[1]);

#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
  }
  else if ((target_type == BIP39_TARGET_P2SH) || (target_type == BIP39_TARGET_P2PKH) || (target_type == BIP39_TARGET_P2WPKH))
  {
    if (tmps[gid].derived_ready == 0)
      return;

    u32 match = 1;

    for (u32 i = 0; i < 5; i++)
    {
      if (tmps[gid].script_hash[i] != esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[i])
      {
        match = 0;
        break;
      }
    }

#if BIP39_DEBUG_GID != 0xffffffffu
    if (debug_gid)
    {
      CONSTANT_AS const char *label = (target_type == BIP39_TARGET_P2SH) ? "script" : (target_type == BIP39_TARGET_P2PKH) ? "hash160" : "witness";

      printf ("[m32001 dbg] comp gid %u %s: %08x %08x %08x %08x %08x target: %08x %08x %08x %08x %08x match=%u\n", (u32) gid, label, tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[0], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[1], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[2], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[3], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[4], match);
    }
#endif

#if BIP39_DEBUG_PRINT
    if (gid == 5)
    {
      if (target_type == BIP39_TARGET_P2SH)
      {
        printf ("[m32001] gid 5 script hash: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
      else if (target_type == BIP39_TARGET_P2PKH)
      {
        printf ("[m32001] gid 5 hash160: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
      else
      {
        printf ("[m32001] gid 5 witness prog: %08x %08x %08x %08x %08x\n", tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4]);
      }
    }
#endif

    if (match == 0)
    {
#if BIP39_DEBUG_PRINT
      CONSTANT_AS const char *label = (target_type == BIP39_TARGET_P2SH) ? "script hash" : (target_type == BIP39_TARGET_P2PKH ? "hash160" : "witness prog");

      printf ("[m32001] mismatch %s: %08x %08x %08x %08x %08x vs target %08x %08x %08x %08x %08x\n", label, tmps[gid].script_hash[0], tmps[gid].script_hash[1], tmps[gid].script_hash[2], tmps[gid].script_hash[3], tmps[gid].script_hash[4], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[0], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[1], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[2], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[3], esalt_bufs[DIGESTS_OFFSET_HOST].target_hash[4]);
#endif
      return;
    }

    const u32 r0 = tmps[gid].script_hash[0];
    const u32 r1 = tmps[gid].script_hash[1];
    const u32 r2 = tmps[gid].script_hash[2];
    const u32 r3 = tmps[gid].script_hash[3];

#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
  }
}

KERNEL_FQ void m32001_mxx (KERN_ATTR_ESALT (bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  const u32 r0 = 0;
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

#include COMPARE_M
}

KERNEL_FQ void m32001_sxx (KERN_ATTR_ESALT (bip39_skeleton_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  const u32 search[4] = {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32 r0 = 0;
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

#include COMPARE_S
}
#endif // BIP39_TEST_ONLY

#ifdef BIP39_TEST_KERNEL
KERNEL_FQ void bip39_test_u1 (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS u64 *out_digest)
{
  PRIVATE_AS u64 digest[8];

  bip39_pbkdf2_u1_from_global (mnemonic, mnemonic_len, passphrase, passphrase_len, digest);

  for (u32 i = 0; i < 8; i++)
  {
    out_digest[i] = digest[i];
  }
}

KERNEL_FQ void bip39_test_master (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS u64 *out_seed, GLOBAL_AS u64 *out_master)
{
  PRIVATE_AS u64 seed[8];
  PRIVATE_AS u64 master[8];

  bip39_pbkdf2_u1_from_global (mnemonic, mnemonic_len, passphrase, passphrase_len, seed);
  bip39_derive_bip32_master (seed, master);

  for (u32 i = 0; i < 8; i++)
  {
    out_seed[i] = seed[i];
    out_master[i] = master[i];
  }
}

KERNEL_FQ void bip39_test_script_hash (GLOBAL_AS const u8 *mnemonic, const u32 mnemonic_len, GLOBAL_AS const u8 *passphrase, const u32 passphrase_len, GLOBAL_AS const u32 *path_indices, const u32 path_depth, GLOBAL_AS u32 *out_key_le, GLOBAL_AS u32 *out_hash, GLOBAL_AS u32 *out_status, GLOBAL_AS u32 *out_parent, GLOBAL_AS u32 *out_il)
{
  PRIVATE_AS u64 seed[8];
  PRIVATE_AS u64 master[8];

  bip39_pbkdf2_u1_from_global (mnemonic, mnemonic_len, passphrase, passphrase_len, seed);
  bip39_derive_bip32_master (seed, master);

  PRIVATE_AS u8 master_bytes[64];

  for (u32 i = 0; i < 8; i++)
  {
    const u64 word = master[i];

    master_bytes[(i * 8) + 0] = (u8) (word >> 56);
    master_bytes[(i * 8) + 1] = (u8) (word >> 48);
    master_bytes[(i * 8) + 2] = (u8) (word >> 40);
    master_bytes[(i * 8) + 3] = (u8) (word >> 32);
    master_bytes[(i * 8) + 4] = (u8) (word >> 24);
    master_bytes[(i * 8) + 5] = (u8) (word >> 16);
    master_bytes[(i * 8) + 6] = (u8) (word >> 8);
    master_bytes[(i * 8) + 7] = (u8) (word >> 0);
  }

  PRIVATE_AS u8 key_bytes[32];
  PRIVATE_AS u8 chain_bytes[32];

  for (u32 i = 0; i < 32; i++)
  {
    key_bytes[i] = master_bytes[i];
    chain_bytes[i] = master_bytes[32 + i];
  }

  PRIVATE_AS u32 key_le[8];

  bip39_bytes_be32_to_words_le (key_bytes, key_le);

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  PRIVATE_AS u32 parent_words[8];
  PRIVATE_AS u32 il_words[8];

  for (u32 i = 0; i < 8; i++)
  {
    parent_words[i] = key_le[i];
    il_words[i] = 0;
  }

  u32 ok = 1;

  for (u32 i = 0; i < path_depth; i++)
  {
    for (u32 j = 0; j < 8; j++)
      parent_words[j] = key_le[j];

    ok = bip39_bip32_child (path_indices[i], key_le, key_bytes, chain_bytes, &preG, il_words);

    if (ok == 0)
      break;
  }

  if (out_parent != 0)
  {
    for (u32 i = 0; i < 8; i++)
      out_parent[i] = parent_words[i];
  }

  if (out_il != 0)
  {
    for (u32 i = 0; i < 8; i++)
      out_il[i] = il_words[i];
  }

  if (ok)
  {
    PRIVATE_AS u32 hash160_tmp[5];
    PRIVATE_AS u32 script_tmp[5];

    bip39_compute_key_hashes (key_le, &preG, hash160_tmp, script_tmp, false);

    for (u32 i = 0; i < 8; i++)
      out_key_le[i] = key_le[i];
    for (u32 i = 0; i < 5; i++)
      out_hash[i] = script_tmp[i];

    *out_status = 1;
  }
  else
  {
    for (u32 i = 0; i < 8; i++)
      out_key_le[i] = 0;
    for (u32 i = 0; i < 5; i++)
      out_hash[i] = 0;

    *out_status = 0;
  }
}

KERNEL_FQ void bip39_test_hmac (GLOBAL_AS const u32 *key_words, const u32 key_len, GLOBAL_AS const u32 *data_words, const u32 data_len, GLOBAL_AS u64 *out_digest)
{
  sha512_hmac_ctx_t ctx;

  const u32 key_word_count = (key_len + 3u) / 4u;
  const u32 data_word_count = (data_len + 3u) / 4u;

  PRIVATE_AS u32 key_local[32];
  PRIVATE_AS u32 data_local[64];

  for (u32 i = 0; i < key_word_count; i++)
    key_local[i] = key_words[i];
  for (u32 i = key_word_count; i < 32; i++)
    key_local[i] = 0;

  for (u32 i = 0; i < data_word_count; i++)
    data_local[i] = data_words[i];
  for (u32 i = data_word_count; i < 64; i++)
    data_local[i] = 0;

  sha512_hmac_init_swap (&ctx, key_local, key_len);
  sha512_hmac_update_swap (&ctx, data_local, data_len);
  sha512_hmac_final (&ctx);

for (u32 i = 0; i < 8; i++)
  out_digest[i] = ctx.opad.h[i];
}
#endif

#endif // BIP39_MINIMAL_KERNEL
#ifndef BIP39_DISABLE_PATH_ITER
#define BIP39_DISABLE_PATH_ITER 0
#endif
