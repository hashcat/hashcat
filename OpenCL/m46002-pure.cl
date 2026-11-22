/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Lace / Nami Wallet (SBV1 secret box)
//
//   key = Argon2id(password, salt32, m=19456KiB, t=2, p=1, 32)   [fixed by the format]
//   mac = Poly1305(ChaCha20block0(key, nonce12), header48 || ct) [RFC 8439, AAD = header]
//
// The Argon2 pipeline is the stock hashcat one from inc_hash_argon2.cl; the
// ChaCha20 block follows m37700 (Eternl) and Poly1305 is inc_auth_poly1305.cl.

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_auth_poly1305.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

#define SBV1_HEADER_LEN 48
#define SBV1_CT_MAX     2048

// MUST match module_46002.c field-for-field
typedef struct sbv1
{
  u32 nonce[3];            // 12 bytes
  u32 ct[SBV1_CT_MAX / 4]; // ct without the tag (tag rides in the digest)
  u32 ct_len;

} sbv1_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;
  sbv1_t s;

} merged_options_t;

// ChaCha20 Block Function (Scalar), from m37700 (Eternl)

DECLSPEC void chacha20_block (PRIVATE_AS u32 *state, PRIVATE_AS u32 *out)
{
  u32 x[16];
  for (int i = 0; i < 16; i++) x[i] = state[i];

  for (int i = 0; i < 10; i++)
  {
    // Quarter round 1
    x[0] += x[4]; x[12] = hc_rotl32_S (x[12] ^ x[0], 16);
    x[8] += x[12]; x[4] = hc_rotl32_S (x[4] ^ x[8], 12);
    x[0] += x[4]; x[12] = hc_rotl32_S (x[12] ^ x[0], 8);
    x[8] += x[12]; x[4] = hc_rotl32_S (x[4] ^ x[8], 7);

    // Quarter round 2
    x[1] += x[5]; x[13] = hc_rotl32_S (x[13] ^ x[1], 16);
    x[9] += x[13]; x[5] = hc_rotl32_S (x[5] ^ x[9], 12);
    x[1] += x[5]; x[13] = hc_rotl32_S (x[13] ^ x[1], 8);
    x[9] += x[13]; x[5] = hc_rotl32_S (x[5] ^ x[9], 7);

    // Quarter round 3
    x[2] += x[6]; x[14] = hc_rotl32_S (x[14] ^ x[2], 16);
    x[10] += x[14]; x[6] = hc_rotl32_S (x[6] ^ x[10], 12);
    x[2] += x[6]; x[14] = hc_rotl32_S (x[14] ^ x[2], 8);
    x[10] += x[14]; x[6] = hc_rotl32_S (x[6] ^ x[10], 7);

    // Quarter round 4
    x[3] += x[7]; x[15] = hc_rotl32_S (x[15] ^ x[3], 16);
    x[11] += x[15]; x[7] = hc_rotl32_S (x[7] ^ x[11], 12);
    x[3] += x[7]; x[15] = hc_rotl32_S (x[15] ^ x[3], 8);
    x[11] += x[15]; x[7] = hc_rotl32_S (x[7] ^ x[11], 7);

    // Diagonal round 1
    x[0] += x[5]; x[15] = hc_rotl32_S (x[15] ^ x[0], 16);
    x[10] += x[15]; x[5] = hc_rotl32_S (x[5] ^ x[10], 12);
    x[0] += x[5]; x[15] = hc_rotl32_S (x[15] ^ x[0], 8);
    x[10] += x[15]; x[5] = hc_rotl32_S (x[5] ^ x[10], 7);

    // Diagonal round 2
    x[1] += x[6]; x[12] = hc_rotl32_S (x[12] ^ x[1], 16);
    x[11] += x[12]; x[6] = hc_rotl32_S (x[6] ^ x[11], 12);
    x[1] += x[6]; x[12] = hc_rotl32_S (x[12] ^ x[1], 8);
    x[11] += x[12]; x[6] = hc_rotl32_S (x[6] ^ x[11], 7);

    // Diagonal round 3
    x[2] += x[7]; x[13] = hc_rotl32_S (x[13] ^ x[2], 16);
    x[8] += x[13]; x[7] = hc_rotl32_S (x[7] ^ x[8], 12);
    x[2] += x[7]; x[13] = hc_rotl32_S (x[13] ^ x[2], 8);
    x[8] += x[13]; x[7] = hc_rotl32_S (x[7] ^ x[8], 7);

    // Diagonal round 4
    x[3] += x[4]; x[14] = hc_rotl32_S (x[14] ^ x[3], 16);
    x[9] += x[14]; x[4] = hc_rotl32_S (x[4] ^ x[9], 12);
    x[3] += x[4]; x[14] = hc_rotl32_S (x[14] ^ x[3], 8);
    x[9] += x[14]; x[4] = hc_rotl32_S (x[4] ^ x[9], 7);
  }

  for (int i = 0; i < 16; i++) out[i] = x[i] + state[i];
}

// RFC 8439 2.8: the Poly1305 one-time key is the first 32 bytes of the
// ChaCha20 block at counter 0

DECLSPEC void chacha20_poly1305_key_gen (PRIVATE_AS const u32 *key, PRIVATE_AS const u32 *nonce, PRIVATE_AS u32 *poly_key)
{
  u32 state[16];

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  for (int i = 0; i < 8; i++) state[4 + i] = key[i];

  state[12] = 0; // counter

  state[13] = nonce[0];
  state[14] = nonce[1];
  state[15] = nonce[2];

  u32 out[16];

  chacha20_block (state, out);

  for (int i = 0; i < 8; i++) poly_key[i] = out[i];
}

KERNEL_FQ KERNEL_FA void m46002_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  argon2_init_gg (&pws[gid], &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m46002_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  const u32 lanes = argon2_lane_limit (argon2_options.parallelism, lsz);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < lanes; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m46002_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  GLOBAL_AS const sbv1_t *s = &esalt_bufs[DIGESTS_OFFSET_HOST].s;

  // the 32-byte Argon2id digest: out words are LE-packed, so (u8*)out reads
  // as the raw key on LE

  u32 out[8];

  argon2_final (argon2_block, &argon2_options, out);

  // RFC 8439: poly key = ChaCha20 block 0, tag over AAD || pad || ct || pad ||
  // le64(aad_len) || le64(ct_len); the AAD is the 48-byte envelope header

  u32 nonce[3];

  for (int i = 0; i < 3; i++) nonce[i] = s->nonce[i];

  u32 poly_key[8];

  chacha20_poly1305_key_gen (out, nonce, poly_key);

  poly1305_ctx_t poly1305_ctx;

  poly1305_init (&poly1305_ctx, poly_key);

  // AAD: "SBV1" || salt || nonce, assembled private (salt rides in salt_bufs)

  u32 aad[12];

  aad[0] = 0x31564253; // "SBV1" as LE bytes

  GLOBAL_AS const u32 *salt_w = salt_bufs[SALT_POS_HOST].salt_buf;

  for (int i = 0; i < 8; i++) aad[1 + i] = salt_w[i];

  aad[9]  = nonce[0];
  aad[10] = nonce[1];
  aad[11] = nonce[2];

  poly1305_update_private (&poly1305_ctx, aad, SBV1_HEADER_LEN);

  poly1305_update_pad (&poly1305_ctx, SBV1_HEADER_LEN);

  poly1305_update_global (&poly1305_ctx, s->ct, s->ct_len);

  poly1305_update_pad (&poly1305_ctx, s->ct_len);

  u32 lens[4];

  lens[0] = SBV1_HEADER_LEN; // AAD length low 32 bits
  lens[1] = 0;
  lens[2] = s->ct_len;       // ciphertext length low 32 bits
  lens[3] = 0;

  poly1305_update_private (&poly1305_ctx, lens, 16);

  u32 T[4];

  poly1305_final (&poly1305_ctx, T);

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
