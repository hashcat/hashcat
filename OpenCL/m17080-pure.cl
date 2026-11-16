/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * GPG symmetrically encrypted message: iterated and salted SHA-512 S2K, AES-256 in CFB128,
 * verified by the SHA-1 MDC that RFC 4880 5.13 puts at the end of the plaintext. The MDC is
 * SHA-1 whatever the S2K hash is, which is why this kernel includes both.
 *
 * SHA-512 gives all 32 key bytes, so the S2K runs once and the C module asks for that with
 * salt_repeats = 0.
 *
 * CFB starts on a zero IV. The random prefix of the plaintext is what the IV would otherwise
 * be, and the message carries no IV field of its own.
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

// Mirrors GPG_DATA_MAX in src/modules/module_17080.c. The two have to move together.

#define GPG_DATA_MAX 1536

// The repeated salt||pw stream is fed to the S2K a block buffer at a time. SHA-512 works on
// 128 byte blocks and sha512_update_padded () always loads the whole 128 byte tail window of
// what it is given, so the buffer has to be a whole number of those. 3 of them is the smallest
// that holds the longest salt||pw this mode can see, 8 + 256 bytes, where the SHA-1 and SHA-256
// modes of this family hold 5 of their 64 byte block instead. Mirrors the tmp structure in
// src/modules/module_17080.c.

#define GPG_PW_BLOCK_WORDS 96

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];
  u32 modulus_size;
  u32 encrypted_data[GPG_DATA_MAX / 4];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  // the one S2K pass. SHA-512 returns 64 bytes and AES-256 takes the first 32 of them.

  u64 h[8];

  u32 salted_pw_block[GPG_PW_BLOCK_WORDS];

  u32 salted_pw_block_len;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int len;

} gpg_tmp_t;

DECLSPEC void memcat_le_S (PRIVATE_AS u32 *block, const u32 offset, PRIVATE_AS const u32 *append, u32 len)
{
  const u32 start_index = (offset - 1) >> 2;
  const u32 count = ((offset + len + 3) >> 2) - start_index;
  const int off_mod_4 = offset & 3;
  const int off_minus_4 = 4 - off_mod_4;

  block[start_index] |= hc_bytealign_be_S (append[0], 0, off_minus_4);

  for (u32 idx = 1; idx < count; idx++)
  {
    block[start_index + idx] = hc_bytealign_be_S (append[idx], append[idx - 1], off_minus_4);
  }
}

DECLSPEC void memzero_le_S (PRIVATE_AS u32 *block, const u32 start_offset, const u32 end_offset)
{
  const u32 start_idx = start_offset / 4;

  block[start_idx] &= ~(0xffffffff << ((start_offset & 3) * 8));

  const u32 end_idx = (end_offset + 3) / 4;

  for (u32 i = start_idx + 1; i < end_idx; i++)
  {
    block[i] = 0;
  }
}

DECLSPEC void memzero_be_S (PRIVATE_AS u32 *block, const u32 start_offset, const u32 end_offset)
{
  const u32 start_idx = start_offset / 4;

  block[start_idx] &= ~(0xffffffff >> ((start_offset & 3) * 8));

  const u32 end_idx = (end_offset + 3) / 4;

  for (u32 i = start_idx + 1; i < end_idx; i++)
  {
    block[i] = 0;
  }
}

DECLSPEC void aes256_decrypt_cfb (GLOBAL_AS const u32 *encrypted_data, int data_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *key, PRIVATE_AS u32 *decrypted_data,
                                  SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ks[60];
  u32 essiv[4];

  essiv[0] = iv[0];
  essiv[1] = iv[1];
  essiv[2] = iv[2];
  essiv[3] = iv[3];

  aes256_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);

  for (u32 i = 0; i < (u32) (data_len + 3) / 4; i += 4)
  {
    aes256_encrypt (ks, essiv, decrypted_data + i, s_te0, s_te1, s_te2, s_te3, s_te4);

    decrypted_data[i + 0] ^= encrypted_data[i + 0];
    decrypted_data[i + 1] ^= encrypted_data[i + 1];
    decrypted_data[i + 2] ^= encrypted_data[i + 2];
    decrypted_data[i + 3] ^= encrypted_data[i + 3];

    essiv[0] = encrypted_data[i + 0];
    essiv[1] = encrypted_data[i + 1];
    essiv[2] = encrypted_data[i + 2];
    essiv[3] = encrypted_data[i + 3];
  }
}

DECLSPEC int check_decoded_data (PRIVATE_AS u32 *decoded_data, const u32 decoded_data_size)
{
  const u32 sha1_byte_off = (decoded_data_size - 20);
  const u32 sha1_u32_off  = sha1_byte_off / 4;

  u32 expected_sha1[5];

  expected_sha1[0] = hc_bytealign_be_S (decoded_data[sha1_u32_off + 1], decoded_data[sha1_u32_off + 0], sha1_byte_off);
  expected_sha1[1] = hc_bytealign_be_S (decoded_data[sha1_u32_off + 2], decoded_data[sha1_u32_off + 1], sha1_byte_off);
  expected_sha1[2] = hc_bytealign_be_S (decoded_data[sha1_u32_off + 3], decoded_data[sha1_u32_off + 2], sha1_byte_off);
  expected_sha1[3] = hc_bytealign_be_S (decoded_data[sha1_u32_off + 4], decoded_data[sha1_u32_off + 3], sha1_byte_off);
  expected_sha1[4] = hc_bytealign_be_S (decoded_data[sha1_u32_off + 5], decoded_data[sha1_u32_off + 4], sha1_byte_off);

  memzero_le_S (decoded_data, sha1_byte_off, GPG_DATA_MAX);

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_swap (&ctx, decoded_data, sha1_byte_off);

  sha1_final (&ctx);

  return (expected_sha1[0] == hc_swap32_S (ctx.h[0]))
      && (expected_sha1[1] == hc_swap32_S (ctx.h[1]))
      && (expected_sha1[2] == hc_swap32_S (ctx.h[2]))
      && (expected_sha1[3] == hc_swap32_S (ctx.h[3]))
      && (expected_sha1[4] == hc_swap32_S (ctx.h[4]));
}

KERNEL_FQ KERNEL_FA void m17080_init (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len        = pws[gid].pw_len;
  const u32 salted_pw_len = (salt_bufs[SALT_POS_HOST].salt_len + pw_len);

  u32 salted_pw_block[GPG_PW_BLOCK_WORDS];

  // the salt is always 8 bytes, and the password follows it

  salted_pw_block[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salted_pw_block[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  for (u32 idx = 0; idx < 64; idx++) salted_pw_block[idx + 2] = pws[gid].i[idx];

  for (u32 idx = 66; idx < GPG_PW_BLOCK_WORDS; idx++) salted_pw_block[idx] = 0;

  // a number of copies, for efficiency

  const u32 copies = GPG_PW_BLOCK_WORDS * sizeof (u32) / salted_pw_len;

  for (u32 idx = 1; idx < copies; idx++)
  {
    memcat_le_S (salted_pw_block, idx * salted_pw_len, salted_pw_block, salted_pw_len);
  }

  const u32 salted_pw_block_len = copies * salted_pw_len;

  // memcat_le_S () copies whole u32 words, so the word that straddles the end of the last
  // copy comes out holding the next bytes of the repeated salt||pw stream instead of zero.
  // Everything from salted_pw_block_len on has to read as zero, because
  // sha512_update_padded () loads the whole 128 byte tail window of the buffer and
  // sha512_final () ORs its 0x80 padding byte into whatever is left sitting there.

  if (salted_pw_block_len < sizeof (salted_pw_block))
  {
    memzero_le_S (salted_pw_block, salted_pw_block_len, sizeof (salted_pw_block));
  }

  for (u32 idx = 0; idx < GPG_PW_BLOCK_WORDS; idx++)
  {
    tmps[gid].salted_pw_block[idx] = hc_swap32_S (salted_pw_block[idx]);
  }

  tmps[gid].salted_pw_block_len = salted_pw_block_len;

  tmps[gid].h[0] = SHA512M_A;
  tmps[gid].h[1] = SHA512M_B;
  tmps[gid].h[2] = SHA512M_C;
  tmps[gid].h[3] = SHA512M_D;
  tmps[gid].h[4] = SHA512M_E;
  tmps[gid].h[5] = SHA512M_F;
  tmps[gid].h[6] = SHA512M_G;
  tmps[gid].h[7] = SHA512M_H;

  tmps[gid].len = 0;
}

KERNEL_FQ KERNEL_FA void m17080_loop_prepare (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].w0[0] = 0;
  tmps[gid].w0[1] = 0;
  tmps[gid].w0[2] = 0;
  tmps[gid].w0[3] = 0;
  tmps[gid].w1[0] = 0;
  tmps[gid].w1[1] = 0;
  tmps[gid].w1[2] = 0;
  tmps[gid].w1[3] = 0;
  tmps[gid].w2[0] = 0;
  tmps[gid].w2[1] = 0;
  tmps[gid].w2[2] = 0;
  tmps[gid].w2[3] = 0;
  tmps[gid].w3[0] = 0;
  tmps[gid].w3[1] = 0;
  tmps[gid].w3[2] = 0;
  tmps[gid].w3[3] = 0;
  tmps[gid].w4[0] = 0;
  tmps[gid].w4[1] = 0;
  tmps[gid].w4[2] = 0;
  tmps[gid].w4[3] = 0;
  tmps[gid].w5[0] = 0;
  tmps[gid].w5[1] = 0;
  tmps[gid].w5[2] = 0;
  tmps[gid].w5[3] = 0;
  tmps[gid].w6[0] = 0;
  tmps[gid].w6[1] = 0;
  tmps[gid].w6[2] = 0;
  tmps[gid].w6[3] = 0;
  tmps[gid].w7[0] = 0;
  tmps[gid].w7[1] = 0;
  tmps[gid].w7[2] = 0;
  tmps[gid].w7[3] = 0;

  // one pass, so SALT_REPEAT is always 0 and the accumulator starts empty

  tmps[gid].len = SALT_REPEAT;
}

KERNEL_FQ KERNEL_FA void m17080_loop (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salted_pw_block[GPG_PW_BLOCK_WORDS];

  for (int i = 0; i < GPG_PW_BLOCK_WORDS; i++) salted_pw_block[i] = tmps[gid].salted_pw_block[i];

  const u32 salted_pw_block_len = tmps[gid].salted_pw_block_len;

  if (salted_pw_block_len == 0) return;

  sha512_ctx_t ctx;

  for (int i = 0; i < 8; i++) ctx.h[i] = tmps[gid].h[i];

  for (int i = 0; i < 4; i++) ctx.w0[i] = tmps[gid].w0[i];
  for (int i = 0; i < 4; i++) ctx.w1[i] = tmps[gid].w1[i];
  for (int i = 0; i < 4; i++) ctx.w2[i] = tmps[gid].w2[i];
  for (int i = 0; i < 4; i++) ctx.w3[i] = tmps[gid].w3[i];
  for (int i = 0; i < 4; i++) ctx.w4[i] = tmps[gid].w4[i];
  for (int i = 0; i < 4; i++) ctx.w5[i] = tmps[gid].w5[i];
  for (int i = 0; i < 4; i++) ctx.w6[i] = tmps[gid].w6[i];
  for (int i = 0; i < 4; i++) ctx.w7[i] = tmps[gid].w7[i];

  ctx.len = tmps[gid].len;

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  const u32 salted_pw_block_pos = LOOP_POS % salted_pw_block_len;
  const u32 rounds = (LOOP_CNT + salted_pw_block_pos) / salted_pw_block_len;

  for (u32 i = 0; i < rounds; i++)
  {
    sha512_update_padded (&ctx, salted_pw_block, salted_pw_block_len);
  }

  if ((LOOP_POS + LOOP_CNT) == salt_iter)
  {
    const u32 remaining_bytes = salt_iter % salted_pw_block_len;

    if (remaining_bytes)
    {
      memzero_be_S (salted_pw_block, remaining_bytes, salted_pw_block_len);

      sha512_update_padded (&ctx, salted_pw_block, remaining_bytes);
    }

    sha512_final (&ctx);
  }

  for (int i = 0; i < 8; i++) tmps[gid].h[i] = ctx.h[i];

  for (int i = 0; i < 4; i++) tmps[gid].w0[i] = ctx.w0[i];
  for (int i = 0; i < 4; i++) tmps[gid].w1[i] = ctx.w1[i];
  for (int i = 0; i < 4; i++) tmps[gid].w2[i] = ctx.w2[i];
  for (int i = 0; i < 4; i++) tmps[gid].w3[i] = ctx.w3[i];
  for (int i = 0; i < 4; i++) tmps[gid].w4[i] = ctx.w4[i];
  for (int i = 0; i < 4; i++) tmps[gid].w5[i] = ctx.w5[i];
  for (int i = 0; i < 4; i++) tmps[gid].w6[i] = ctx.w6[i];
  for (int i = 0; i < 4; i++) tmps[gid].w7[i] = ctx.w7[i];

  tmps[gid].len = ctx.len;
}

KERNEL_FQ KERNEL_FA void m17080_comp (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  // not in use, the mode decides a candidate in its deep comp kernel
}

KERNEL_FQ KERNEL_FA void m17080_aux1 (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  // the first 32 bytes of the one SHA-512 pass are the key

  u32 aes_key[8];

  for (int i = 0; i < 4; i++)
  {
    aes_key[(i * 2) + 0] = hc_swap32_S (h32_from_64_S (tmps[gid].h[i]));
    aes_key[(i * 2) + 1] = hc_swap32_S (l32_from_64_S (tmps[gid].h[i]));
  }

  u32 iv[4] = { 0, 0, 0, 0 };

  // one word past the message, because check_decoded_data () reads six words from the start
  // of the last whole word of the payload, and at the maximum message size the sixth is one
  // past what the payload itself occupies. aes256_decrypt_cfb () writes only as far as the
  // message reaches, so that word is zeroed here rather than left for an uninitialized read.

  u32 decoded_data[(GPG_DATA_MAX / 4) + 1];

  decoded_data[GPG_DATA_MAX / 4] = 0;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  const u32 enc_data_size = esalt_bufs[digest_cur].encrypted_data_size;

  aes256_decrypt_cfb (esalt_bufs[digest_cur].encrypted_data, enc_data_size, iv, aes_key, decoded_data, s_te0, s_te1, s_te2, s_te3, s_te4);

  if (check_decoded_data (decoded_data, enc_data_size))
  {
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
    }
  }
}
