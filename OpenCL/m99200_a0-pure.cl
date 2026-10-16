/**
 * Author......: Deutsche Telekom Security GmbH
 * License.....: MIT
 *
 * PuTTY Private Key (PPK) version 2, AES-256-CBC encryption
 *
 * Key derivation:
 *   cipher_key = SHA1(0x00000000 || passphrase) || SHA1(0x00000001 || passphrase) [first 32 bytes]
 *   iv = 0x00 * 16 (all zeros)
 *   mac_key = SHA1("putty-private-key-file-mac-key" || passphrase) [20 bytes]
 *
 * Verification:
 *   HMAC-SHA1(mac_key, ssh_string(algorithm) || ssh_string(encryption) || ssh_string(comment) || ssh_string(public) || ssh_string(decrypted_private))
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct ppk
{
  u32 algorithm_buf[16];
  int algorithm_len;

  u32 encryption_buf[8];
  int encryption_len;

  u32 comment_buf[64];
  int comment_len;

  u32 public_buf[1024];
  int public_len;

  u32 private_buf[2048];
  int private_len;

  u32 mac[5];

} ppk_t;

// Helper for global esalt data - copy from global memory and byte-swap for SHA1
DECLSPEC void hmac_sha1_update_ssh_string_global_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *buf, const int len)
{
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

  sha1_hmac_update_swap (ctx, w, 4);

  const int len_u32 = (len + 3) / 4;
  int pos = 0;

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

    sha1_hmac_update_swap (ctx, w, 64);
    pos += 16;
  }

  const int remaining_bytes = len - (pos * 4);

  if (remaining_bytes > 0)
  {
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

    const int remaining_u32 = (remaining_bytes + 3) / 4;

    for (int i = 0; i < remaining_u32; i++)
    {
      w[i] = buf[pos + i];
    }

    sha1_hmac_update_swap (ctx, w, remaining_bytes);
  }
}

// Helper for private (decrypted) data - byte-swap for SHA1
DECLSPEC void hmac_sha1_update_ssh_string_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *buf, const int len)
{
  u32 w[16];

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

  sha1_hmac_update (ctx, w, 4);

  const int len_u32 = (len + 3) / 4;
  int pos = 0;

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

    sha1_hmac_update_swap (ctx, w, 64);
    pos += 16;
  }

  const int remaining_bytes = len - (pos * 4);

  if (remaining_bytes > 0)
  {
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

    const int remaining_u32 = (remaining_bytes + 3) / 4;

    for (int i = 0; i < remaining_u32; i++)
    {
      w[i] = buf[pos + i];
    }

    sha1_hmac_update_swap (ctx, w, remaining_bytes);
  }
}

KERNEL_FQ KERNEL_FA void m99200_mxx (KERN_ATTR_RULES_ESALT (ppk_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * AES shared memory tables
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

  /**
   * digest (expected MAC)
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base password
   */

  COPY_PW (pws[gid]);

  /**
   * PPK data from esalt
   */

  const int algorithm_len  = esalt_bufs[DIGESTS_OFFSET_HOST].algorithm_len;
  const int encryption_len = esalt_bufs[DIGESTS_OFFSET_HOST].encryption_len;
  const int comment_len    = esalt_bufs[DIGESTS_OFFSET_HOST].comment_len;
  const int public_len     = esalt_bufs[DIGESTS_OFFSET_HOST].public_len;
  const int private_len    = esalt_bufs[DIGESTS_OFFSET_HOST].private_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    /**
     * Derive cipher key: SHA1(0x00000000 || passphrase) || SHA1(0x00000001 || passphrase)
     * Take first 32 bytes for AES-256 key
     */

    sha1_ctx_t sha1_ctx;

    // First hash: SHA1(0x00000000 || passphrase)
    sha1_init (&sha1_ctx);

    u32 prefix[16];
    prefix[0] = 0;  // 0x00000000 in big-endian
    prefix[1] = 0;
    prefix[2] = 0;
    prefix[3] = 0;
    prefix[4] = 0;
    prefix[5] = 0;
    prefix[6] = 0;
    prefix[7] = 0;
    prefix[8] = 0;
    prefix[9] = 0;
    prefix[10] = 0;
    prefix[11] = 0;
    prefix[12] = 0;
    prefix[13] = 0;
    prefix[14] = 0;
    prefix[15] = 0;

    sha1_update_swap (&sha1_ctx, prefix, 4);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 key_part1[5];
    key_part1[0] = sha1_ctx.h[0];
    key_part1[1] = sha1_ctx.h[1];
    key_part1[2] = sha1_ctx.h[2];
    key_part1[3] = sha1_ctx.h[3];
    key_part1[4] = sha1_ctx.h[4];

    // Second hash: SHA1(0x00000001 || passphrase)
    sha1_init (&sha1_ctx);

    prefix[0] = 0x01000000;  // 0x00000001 in little-endian storage (will be big-endian 0x00000001)

    sha1_update_swap (&sha1_ctx, prefix, 4);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 key_part2[5];
    key_part2[0] = sha1_ctx.h[0];
    key_part2[1] = sha1_ctx.h[1];
    key_part2[2] = sha1_ctx.h[2];
    key_part2[3] = sha1_ctx.h[3];
    key_part2[4] = sha1_ctx.h[4];

    // Combine to form 32-byte AES-256 key
    // key = key_part1[0..4] || key_part2[0..2] (first 32 bytes = 8 u32s)
    u32 aes_key[8];
    aes_key[0] = hc_swap32_S (key_part1[0]);
    aes_key[1] = hc_swap32_S (key_part1[1]);
    aes_key[2] = hc_swap32_S (key_part1[2]);
    aes_key[3] = hc_swap32_S (key_part1[3]);
    aes_key[4] = hc_swap32_S (key_part1[4]);
    aes_key[5] = hc_swap32_S (key_part2[0]);
    aes_key[6] = hc_swap32_S (key_part2[1]);
    aes_key[7] = hc_swap32_S (key_part2[2]);

    /**
     * Derive MAC key: SHA1("putty-private-key-file-mac-key" || passphrase)
     */

    sha1_init (&sha1_ctx);

    // "putty-private-key-file-mac-key" = 30 bytes
    u32 mac_prefix[8];
    mac_prefix[0] = 0x74747570;  // "putt"
    mac_prefix[1] = 0x72702d79;  // "y-pr"
    mac_prefix[2] = 0x74617669;  // "ivat"
    mac_prefix[3] = 0x656b2d65;  // "e-ke"
    mac_prefix[4] = 0x69662d79;  // "y-fi"
    mac_prefix[5] = 0x6d2d656c;  // "le-m"
    mac_prefix[6] = 0x6b2d6361;  // "ac-k"
    mac_prefix[7] = 0x00007965;  // "ey\0\0"

    sha1_update_swap (&sha1_ctx, mac_prefix, 30);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 mac_key[5];
    mac_key[0] = sha1_ctx.h[0];
    mac_key[1] = sha1_ctx.h[1];
    mac_key[2] = sha1_ctx.h[2];
    mac_key[3] = sha1_ctx.h[3];
    mac_key[4] = sha1_ctx.h[4];

    /**
     * Decrypt private key using AES-256-CBC with IV = 0
     */

    u32 ks[60];

    aes256_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    // Decrypt private key in CBC mode with zero IV
    u32 iv[4] = { 0, 0, 0, 0 };

    u32 decrypted[512];  // Max 2048 bytes decrypted data
    const int num_blocks = private_len / 16;

    for (int b = 0; b < num_blocks && b < 512/4; b++)
    {
      u32 enc_block[4];
      enc_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 0];
      enc_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 1];
      enc_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 2];
      enc_block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 3];

      u32 dec_block[4];
      aes256_decrypt (ks, enc_block, dec_block, s_td0, s_td1, s_td2, s_td3, s_td4);

      decrypted[b * 4 + 0] = dec_block[0] ^ iv[0];
      decrypted[b * 4 + 1] = dec_block[1] ^ iv[1];
      decrypted[b * 4 + 2] = dec_block[2] ^ iv[2];
      decrypted[b * 4 + 3] = dec_block[3] ^ iv[3];

      // Update IV for CBC mode
      iv[0] = enc_block[0];
      iv[1] = enc_block[1];
      iv[2] = enc_block[2];
      iv[3] = enc_block[3];
    }

    /**
     * Compute HMAC-SHA1 for MAC verification
     * Input: ssh_string(algorithm) || ssh_string(encryption) || ssh_string(comment) || ssh_string(public) || ssh_string(decrypted_private)
     */

    sha1_hmac_ctx_t hmac_ctx;

    // Initialize HMAC with mac_key (20 bytes)
    u32 mac_key_padded[16];
    mac_key_padded[0] = mac_key[0];
    mac_key_padded[1] = mac_key[1];
    mac_key_padded[2] = mac_key[2];
    mac_key_padded[3] = mac_key[3];
    mac_key_padded[4] = mac_key[4];
    mac_key_padded[5] = 0;
    mac_key_padded[6] = 0;
    mac_key_padded[7] = 0;
    mac_key_padded[8] = 0;
    mac_key_padded[9] = 0;
    mac_key_padded[10] = 0;
    mac_key_padded[11] = 0;
    mac_key_padded[12] = 0;
    mac_key_padded[13] = 0;
    mac_key_padded[14] = 0;
    mac_key_padded[15] = 0;

    sha1_hmac_init (&hmac_ctx, mac_key_padded, 20);

    // Add algorithm as SSH string
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].algorithm_buf, algorithm_len);

    // Add encryption as SSH string
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].encryption_buf, encryption_len);

    // Add comment as SSH string
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].comment_buf, comment_len);

    // Add public key as SSH string
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].public_buf, public_len);

    // Add decrypted private key as SSH string
    hmac_sha1_update_ssh_string_swap (&hmac_ctx, decrypted, private_len);

    sha1_hmac_final (&hmac_ctx);

    const u32 r0 = hmac_ctx.opad.h[0];
    const u32 r1 = hmac_ctx.opad.h[1];
    const u32 r2 = hmac_ctx.opad.h[2];
    const u32 r3 = hmac_ctx.opad.h[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m99200_sxx (KERN_ATTR_RULES_ESALT (ppk_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * AES shared memory tables
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

  /**
   * digest (expected MAC)
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base password
   */

  COPY_PW (pws[gid]);

  /**
   * PPK data from esalt
   */

  const int algorithm_len  = esalt_bufs[DIGESTS_OFFSET_HOST].algorithm_len;
  const int encryption_len = esalt_bufs[DIGESTS_OFFSET_HOST].encryption_len;
  const int comment_len    = esalt_bufs[DIGESTS_OFFSET_HOST].comment_len;
  const int public_len     = esalt_bufs[DIGESTS_OFFSET_HOST].public_len;
  const int private_len    = esalt_bufs[DIGESTS_OFFSET_HOST].private_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    /**
     * Derive cipher key: SHA1(0x00000000 || passphrase) || SHA1(0x00000001 || passphrase)
     */

    sha1_ctx_t sha1_ctx;

    sha1_init (&sha1_ctx);

    u32 prefix[16];
    prefix[0] = 0;
    prefix[1] = 0;
    prefix[2] = 0;
    prefix[3] = 0;
    prefix[4] = 0;
    prefix[5] = 0;
    prefix[6] = 0;
    prefix[7] = 0;
    prefix[8] = 0;
    prefix[9] = 0;
    prefix[10] = 0;
    prefix[11] = 0;
    prefix[12] = 0;
    prefix[13] = 0;
    prefix[14] = 0;
    prefix[15] = 0;

    sha1_update_swap (&sha1_ctx, prefix, 4);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 key_part1[5];
    key_part1[0] = sha1_ctx.h[0];
    key_part1[1] = sha1_ctx.h[1];
    key_part1[2] = sha1_ctx.h[2];
    key_part1[3] = sha1_ctx.h[3];
    key_part1[4] = sha1_ctx.h[4];


    sha1_init (&sha1_ctx);

    prefix[0] = 0x01000000;

    sha1_update_swap (&sha1_ctx, prefix, 4);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 key_part2[5];
    key_part2[0] = sha1_ctx.h[0];
    key_part2[1] = sha1_ctx.h[1];
    key_part2[2] = sha1_ctx.h[2];
    key_part2[3] = sha1_ctx.h[3];
    key_part2[4] = sha1_ctx.h[4];


    u32 aes_key[8];
    aes_key[0] = hc_swap32_S (key_part1[0]);
    aes_key[1] = hc_swap32_S (key_part1[1]);
    aes_key[2] = hc_swap32_S (key_part1[2]);
    aes_key[3] = hc_swap32_S (key_part1[3]);
    aes_key[4] = hc_swap32_S (key_part1[4]);
    aes_key[5] = hc_swap32_S (key_part2[0]);
    aes_key[6] = hc_swap32_S (key_part2[1]);
    aes_key[7] = hc_swap32_S (key_part2[2]);


    /**
     * Derive MAC key
     */

    sha1_init (&sha1_ctx);

    u32 mac_prefix[8];
    mac_prefix[0] = 0x74747570;
    mac_prefix[1] = 0x72702d79;
    mac_prefix[2] = 0x74617669;
    mac_prefix[3] = 0x656b2d65;
    mac_prefix[4] = 0x69662d79;
    mac_prefix[5] = 0x6d2d656c;
    mac_prefix[6] = 0x6b2d6361;
    mac_prefix[7] = 0x00007965;

    sha1_update_swap (&sha1_ctx, mac_prefix, 30);
    sha1_update_swap (&sha1_ctx, tmp.i, tmp.pw_len);
    sha1_final (&sha1_ctx);

    u32 mac_key[5];
    mac_key[0] = sha1_ctx.h[0];
    mac_key[1] = sha1_ctx.h[1];
    mac_key[2] = sha1_ctx.h[2];
    mac_key[3] = sha1_ctx.h[3];
    mac_key[4] = sha1_ctx.h[4];


    /**
     * Decrypt private key
     */

    u32 ks[60];

    aes256_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 iv[4] = { 0, 0, 0, 0 };

    u32 decrypted[512];
    const int num_blocks = private_len / 16;

    for (int b = 0; b < num_blocks && b < 512/4; b++)
    {
      u32 enc_block[4];
      enc_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 0];
      enc_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 1];
      enc_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 2];
      enc_block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].private_buf[b * 4 + 3];

      u32 dec_block[4];
      aes256_decrypt (ks, enc_block, dec_block, s_td0, s_td1, s_td2, s_td3, s_td4);

      decrypted[b * 4 + 0] = dec_block[0] ^ iv[0];
      decrypted[b * 4 + 1] = dec_block[1] ^ iv[1];
      decrypted[b * 4 + 2] = dec_block[2] ^ iv[2];
      decrypted[b * 4 + 3] = dec_block[3] ^ iv[3];

      iv[0] = enc_block[0];
      iv[1] = enc_block[1];
      iv[2] = enc_block[2];
      iv[3] = enc_block[3];
    }


    /**
     * Compute HMAC-SHA1
     */

    sha1_hmac_ctx_t hmac_ctx;

    u32 mac_key_padded[16];
    mac_key_padded[0] = mac_key[0];
    mac_key_padded[1] = mac_key[1];
    mac_key_padded[2] = mac_key[2];
    mac_key_padded[3] = mac_key[3];
    mac_key_padded[4] = mac_key[4];
    mac_key_padded[5] = 0;
    mac_key_padded[6] = 0;
    mac_key_padded[7] = 0;
    mac_key_padded[8] = 0;
    mac_key_padded[9] = 0;
    mac_key_padded[10] = 0;
    mac_key_padded[11] = 0;
    mac_key_padded[12] = 0;
    mac_key_padded[13] = 0;
    mac_key_padded[14] = 0;
    mac_key_padded[15] = 0;

    sha1_hmac_init (&hmac_ctx, mac_key_padded, 20);

    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].algorithm_buf, algorithm_len);
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].encryption_buf, encryption_len);
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].comment_buf, comment_len);
    hmac_sha1_update_ssh_string_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].public_buf, public_len);
    hmac_sha1_update_ssh_string_swap (&hmac_ctx, decrypted, private_len);

    sha1_hmac_final (&hmac_ctx);

    const u32 r0 = hmac_ctx.opad.h[0];
    const u32 r1 = hmac_ctx.opad.h[1];
    const u32 r2 = hmac_ctx.opad.h[2];
    const u32 r3 = hmac_ctx.opad.h[3];


    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
