/**
 * Author......: Deutsche Telekom Security GmbH
 * License.....: MIT
 *
 * PuTTY Private Key (PPK) version 3, AES-256-CBC
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
  int pos = 0;

  // Full 64-byte chunks
  while ((pos + 16) * 4 <= len)
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
  int pos = 0;

  // Full 64-byte chunks
  while ((pos + 16) * 4 <= len)
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

KERNEL_FQ KERNEL_FA void m37801_init (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
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

KERNEL_FQ KERNEL_FA void m37801_loop (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
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

KERNEL_FQ KERNEL_FA void m37801_comp (KERN_ATTR_TMPS_ESALT (ppk3_tmp_t, merged_options_t))
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

  argon2_final (argon2_block, &argon2_options, out);

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
