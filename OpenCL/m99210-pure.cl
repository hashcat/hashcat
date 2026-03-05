/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * PuTTY Private Key (PPK) version 3, AES-256-CBC with Argon2id
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define PPK_ALGORITHM_MAX    64
#define PPK_ENCRYPTION_MAX   32
#define PPK_COMMENT_MAX      256
#define PPK_PUBLIC_MAX       4096
#define PPK_PRIVATE_MAX      8192

// Custom argon2_final for 80-byte output (PPK v3)
// The standard hashcat argon2_final only works for outputs <= 64 bytes
// For 80 bytes, we need to implement blake2b_long:
//   V0 = Blake2b(LE32(80) || xor_block, digest_len=64)
//   V1 = Blake2b(V0, digest_len=48)
//   Output = V0[0:32] || V1[all 48 bytes]
DECLSPEC void argon2_final_80 (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS u32 *out)
{
  const u32 lane_length = options->lane_length;
  const u32 lanes = options->parallelism;

  // ============ Phase 1: V0 = Blake2b(LE32(80) || xor_block, digest=64) ============
  blake2b_ctx_t ctx;
  blake2b_init (&ctx);

  // Process the 1028-byte message: LE32(80) || xor_block
  u32 rem = 80;  // LE32(80) = 0x00000050

  for (u32 offset = 0; offset < 128; offset += 16)
  {
    // XOR all lane final blocks for this chunk
    for (u32 l = 0; l < lanes; l++)
    {
      for (u32 idx = 0; idx < 16; idx++)
      {
        ctx.m[idx] ^= blocks[((lane_length - 1) * lanes) + l].values[idx + offset];
      }
    }

    // Shift by 4 bytes to prepend the length prefix
    for (u32 idx = 0; idx < 16; idx++)
    {
      const u64 value = ctx.m[idx];
      ctx.m[idx] = hl32_to_64_S (l32_from_64_S (value), rem);
      rem = h32_from_64_S (value);
    }

    ctx.len += 128;
    blake2b_transform (ctx.h, ctx.m, ctx.len, (u64) BLAKE2B_UPDATE);

    for (u32 idx = 0; idx < 16; idx++) ctx.m[idx] = 0;
  }

  // Final chunk with remaining 4 bytes
  ctx.m[0] = hl32_to_64_S (0, rem);
  blake2b_transform (ctx.h, ctx.m, 1028, (u64) BLAKE2B_FINAL);

  // V0 is now in ctx.h[0..7] (64 bytes)
  // Copy first 32 bytes (4 u64s) to out[0..7]
  for (u32 i = 0; i < 4; i++)
  {
    out[i * 2 + 0] = l32_from_64_S (ctx.h[i]);
    out[i * 2 + 1] = h32_from_64_S (ctx.h[i]);
  }

  // Save full V0 for phase 2
  u64 v0[8];
  for (u32 i = 0; i < 8; i++)
  {
    v0[i] = ctx.h[i];
  }

  // ============ Phase 2: V1 = Blake2b(V0, digest=48) ============
  blake2b_init (&ctx);
  // blake2b_init sets h[0] with 0x01010040 (64-byte output)
  // For 48-byte output we need 0x01010030
  // XOR: (x ^ 0x40) ^ 0x70 = x ^ 0x30, so use 0x70
  ctx.h[0] ^= 0x70;

  // Load V0 (64 bytes = 8 u64s) into message buffer
  for (u32 i = 0; i < 8; i++)
  {
    ctx.m[i] = v0[i];
  }
  for (u32 i = 8; i < 16; i++)
  {
    ctx.m[i] = 0;
  }

  ctx.len = 64;
  blake2b_transform (ctx.h, ctx.m, ctx.len, (u64) BLAKE2B_FINAL);

  // Copy all 48 bytes (6 u64s) to out[8..19]
  for (u32 i = 0; i < 6; i++)
  {
    out[8 + i * 2 + 0] = l32_from_64_S (ctx.h[i]);
    out[8 + i * 2 + 1] = h32_from_64_S (ctx.h[i]);
  }
}

typedef struct ppk3
{
  u32 algorithm_buf[PPK_ALGORITHM_MAX / 4];
  int algorithm_len;

  u32 encryption_buf[PPK_ENCRYPTION_MAX / 4];
  int encryption_len;

  u32 comment_buf[PPK_COMMENT_MAX / 4];
  int comment_len;

  u32 public_buf[PPK_PUBLIC_MAX / 4];
  int public_len;

  u32 private_buf[PPK_PRIVATE_MAX / 4];
  int private_len;

  u32 mac[8];  // SHA-256 = 32 bytes

} ppk3_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;

  ppk3_t ppk3;

} merged_options_t;

typedef struct ppk3_tmp
{
  // Argon2 output will be 80 bytes for PPK v3:
  // bytes 0-31: AES key
  // bytes 32-47: IV
  // bytes 48-79: MAC key

  u32 key[8];      // 32 bytes AES-256 key
  u32 iv[4];       // 16 bytes IV
  u32 mac_key[8];  // 32 bytes MAC key

} ppk3_tmp_t;

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// Helper to update HMAC-SHA256 with SSH string format (4-byte BE length + data)
// Data from global memory needs to be swapped since hex_decode stores bytes sequentially
// CRITICAL: sha256_update_global_swap always reads 16 u32s regardless of len, so we must
// copy data to a local zeroed buffer to avoid reading garbage from adjacent struct members.
DECLSPEC void hmac_sha256_update_ssh_string_global_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *buf, const int len)
{
  // First update with the 4-byte big-endian length
  // Use swap variant: pre-swap the length so that sha256_hmac_update_swap produces BE result
  u32 w[16];
  w[ 0] = hc_swap32_S ((u32) len);
  w[ 1] = 0;
  w[ 2] = 0;
  w[ 3] = 0;
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  sha256_hmac_update_swap (ctx, w, 4);

  // Process data in 64-byte chunks, copying to zeroed local buffer
  // This prevents sha256_update from reading garbage beyond the actual data
  const int len_u32 = (len + 3) / 4;
  int pos = 0;

  // Full 64-byte chunks
  while (pos + 16 <= len_u32)
  {
    w[ 0] = buf[pos +  0];
    w[ 1] = buf[pos +  1];
    w[ 2] = buf[pos +  2];
    w[ 3] = buf[pos +  3];
    w[ 4] = buf[pos +  4];
    w[ 5] = buf[pos +  5];
    w[ 6] = buf[pos +  6];
    w[ 7] = buf[pos +  7];
    w[ 8] = buf[pos +  8];
    w[ 9] = buf[pos +  9];
    w[10] = buf[pos + 10];
    w[11] = buf[pos + 11];
    w[12] = buf[pos + 12];
    w[13] = buf[pos + 13];
    w[14] = buf[pos + 14];
    w[15] = buf[pos + 15];

    sha256_hmac_update_swap (ctx, w, 64);
    pos += 16;
  }

  // Remaining data (less than 64 bytes)
  const int remaining_bytes = len - (pos * 4);

  if (remaining_bytes > 0)
  {
    // Zero entire buffer first
    w[ 0] = 0;
    w[ 1] = 0;
    w[ 2] = 0;
    w[ 3] = 0;
    w[ 4] = 0;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    // Copy only valid u32s from global buffer
    const int remaining_u32 = (remaining_bytes + 3) / 4;
    for (int i = 0; i < remaining_u32; i++)
    {
      w[i] = buf[pos + i];
    }

    sha256_hmac_update_swap (ctx, w, remaining_bytes);
  }
}

// Helper for private buffer (decrypted data) - data is in LE u32 format, needs swap
// CRITICAL: sha256_update_swap always reads 16 u32s regardless of len
DECLSPEC void hmac_sha256_update_ssh_string_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *buf, const int len)
{
  u32 w[16];

  // First update with the 4-byte big-endian length
  w[ 0] = (u32) len;
  w[ 1] = 0;
  w[ 2] = 0;
  w[ 3] = 0;
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  sha256_hmac_update (ctx, w, 4);

  // Process data in 64-byte chunks
  const int len_u32 = (len + 3) / 4;
  int pos = 0;

  // Full 64-byte chunks
  while (pos + 16 <= len_u32)
  {
    w[ 0] = buf[pos +  0];
    w[ 1] = buf[pos +  1];
    w[ 2] = buf[pos +  2];
    w[ 3] = buf[pos +  3];
    w[ 4] = buf[pos +  4];
    w[ 5] = buf[pos +  5];
    w[ 6] = buf[pos +  6];
    w[ 7] = buf[pos +  7];
    w[ 8] = buf[pos +  8];
    w[ 9] = buf[pos +  9];
    w[10] = buf[pos + 10];
    w[11] = buf[pos + 11];
    w[12] = buf[pos + 12];
    w[13] = buf[pos + 13];
    w[14] = buf[pos + 14];
    w[15] = buf[pos + 15];

    sha256_hmac_update_swap (ctx, w, 64);
    pos += 16;
  }

  // Remaining data (less than 64 bytes)
  const int remaining_bytes = len - (pos * 4);

  if (remaining_bytes > 0)
  {
    // Zero entire buffer first
    w[ 0] = 0;
    w[ 1] = 0;
    w[ 2] = 0;
    w[ 3] = 0;
    w[ 4] = 0;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    // Copy only valid u32s
    const int remaining_u32 = (remaining_bytes + 3) / 4;
    for (int i = 0; i < remaining_u32; i++)
    {
      w[i] = buf[pos + i];
    }

    sha256_hmac_update_swap (ctx, w, remaining_bytes);
  }
}

KERNEL_FQ KERNEL_FA void m99210_init (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
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

KERNEL_FQ KERNEL_FA void m99210_loop (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
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

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < argon2_options.parallelism; pos.lane += lsz)
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

KERNEL_FQ KERNEL_FA void m99210_comp (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  // Argon2 output: 80 bytes
  // PPK v3: key (32) + iv (16) + mac_key (32) = 80 bytes
  u32 out[20];

  // Use custom argon2_final_80 for 80-byte output (blake2b_long support)
  argon2_final_80 (argon2_block, &argon2_options, out);

  // Extract key, iv, mac_key from Argon2 output
  u32 aes_key[8];
  aes_key[0] = out[0];
  aes_key[1] = out[1];
  aes_key[2] = out[2];
  aes_key[3] = out[3];
  aes_key[4] = out[4];
  aes_key[5] = out[5];
  aes_key[6] = out[6];
  aes_key[7] = out[7];

  u32 iv[4];
  iv[0] = out[8];
  iv[1] = out[9];
  iv[2] = out[10];
  iv[3] = out[11];

  u32 mac_key[8];
  mac_key[0] = out[12];
  mac_key[1] = out[13];
  mac_key[2] = out[14];
  mac_key[3] = out[15];
  mac_key[4] = out[16];
  mac_key[5] = out[17];
  mac_key[6] = out[18];
  mac_key[7] = out[19];

  // Get PPK data
  const int algorithm_len  = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.algorithm_len;
  const int encryption_len = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.encryption_len;
  const int comment_len    = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.comment_len;
  const int public_len     = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.public_len;
  const int private_len    = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.private_len;

  // Decrypt private key with AES-256-CBC
  u32 ks[60];

  aes256_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 decrypted[PPK_PRIVATE_MAX / 4];
  const int num_blocks = private_len / 16;

  u32 iv_cur[4];
  iv_cur[0] = iv[0];
  iv_cur[1] = iv[1];
  iv_cur[2] = iv[2];
  iv_cur[3] = iv[3];

  for (int b = 0; b < num_blocks && b < PPK_PRIVATE_MAX / 16; b++)
  {
    u32 enc_block[4];
    enc_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.private_buf[b * 4 + 0];
    enc_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.private_buf[b * 4 + 1];
    enc_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.private_buf[b * 4 + 2];
    enc_block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.private_buf[b * 4 + 3];

    u32 dec_block[4];
    aes256_decrypt (ks, enc_block, dec_block, s_td0, s_td1, s_td2, s_td3, s_td4);

    // XOR with IV for CBC mode
    decrypted[b * 4 + 0] = dec_block[0] ^ iv_cur[0];
    decrypted[b * 4 + 1] = dec_block[1] ^ iv_cur[1];
    decrypted[b * 4 + 2] = dec_block[2] ^ iv_cur[2];
    decrypted[b * 4 + 3] = dec_block[3] ^ iv_cur[3];

    iv_cur[0] = enc_block[0];
    iv_cur[1] = enc_block[1];
    iv_cur[2] = enc_block[2];
    iv_cur[3] = enc_block[3];
  }

  // Compute HMAC-SHA256 for MAC verification
  // MAC = HMAC-SHA256(mac_key, ssh_string(algorithm) || ssh_string(encryption) || ssh_string(comment) || ssh_string(public) || ssh_string(decrypted_private))

  sha256_hmac_ctx_t hmac_ctx;

  u32 mac_key_padded[16];
  mac_key_padded[0] = mac_key[0];
  mac_key_padded[1] = mac_key[1];
  mac_key_padded[2] = mac_key[2];
  mac_key_padded[3] = mac_key[3];
  mac_key_padded[4] = mac_key[4];
  mac_key_padded[5] = mac_key[5];
  mac_key_padded[6] = mac_key[6];
  mac_key_padded[7] = mac_key[7];
  mac_key_padded[8] = 0;
  mac_key_padded[9] = 0;
  mac_key_padded[10] = 0;
  mac_key_padded[11] = 0;
  mac_key_padded[12] = 0;
  mac_key_padded[13] = 0;
  mac_key_padded[14] = 0;
  mac_key_padded[15] = 0;

  sha256_hmac_init_swap (&hmac_ctx, mac_key_padded, 32);

  hmac_sha256_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.algorithm_buf, algorithm_len);
  hmac_sha256_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.encryption_buf, encryption_len);
  hmac_sha256_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.comment_buf, comment_len);
  hmac_sha256_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ppk3.public_buf, public_len);
  hmac_sha256_update_ssh_string_swap (&hmac_ctx, decrypted, private_len);

  sha256_hmac_final (&hmac_ctx);

  const u32 r0 = hmac_ctx.opad.h[0];
  const u32 r1 = hmac_ctx.opad.h[1];
  const u32 r2 = hmac_ctx.opad.h[2];
  const u32 r3 = hmac_ctx.opad.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
