/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];
  u32 modulus_size;
  u32 encrypted_data[384];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  // buffer for a maximum of 256 + 8 characters, we extend it to 320 characters so it's always 64 byte aligned
  u32 salted_pw_block[80];
  // actual number of bytes in 'salted_pwd' that are used since salt and password are copied multiple times into the buffer
  u32 salted_pw_block_len;

  u32 h[10];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 len;

} gpg_tmp_t;


DECLSPEC u32 hc_bytealign_le_S (const u32 a, const u32 b, const int c)
{
  const int c_mod_4 = c & 3;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  const u32 r = l32_from_64_S ((v64_from_v32ab_S (b, a) >> (c_mod_4 * 8)));
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> (c_mod_4 * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> (c_mod_4 * 8));
  #endif

  const u32 r = hc_byte_perm (b, a, selector);
  #endif

  return r;
}

DECLSPEC void memcat_le_S (PRIVATE_AS u32 *block, const u32 offset, PRIVATE_AS const u32 *append, u32 len)
{
  const u32 start_index = (offset - 1) >> 2;
  const u32 count = ((offset + len + 3) >> 2) - start_index;
  const int off_mod_4 = offset & 3;
  const int off_minus_4 = 4 - off_mod_4;

  block[start_index] |= hc_bytealign_le_S (append[0], 0, off_minus_4);

  for (u32 idx = 1; idx < count; idx++)
  {
    block[start_index + idx] = hc_bytealign_le_S (append[idx], append[idx - 1], off_minus_4);
  }
}

DECLSPEC void memzero_le_S (PRIVATE_AS u32 *block, const u32 start_offset, const u32 end_offset)
{
  const u32 start_idx = start_offset / 4;

  // zero out bytes in the first u32 starting from 'start_offset'
  // math is a bit complex to avoid shifting by 32 bits, which is not possible on some architectures
  block[start_idx] &= ~(0xffffffff << ((start_offset & 3) * 8));

  const u32 end_idx = (end_offset + 3) / 4;

  // zero out bytes in u32 units -- note that the last u32 is completely zeroed!
  for (u32 i = start_idx + 1; i < end_idx; i++)
  {
    block[i] = 0;
  }
}

DECLSPEC void memzero_be_S (PRIVATE_AS u32 *block, const u32 start_offset, const u32 end_offset)
{
  const u32 start_idx = start_offset / 4;

  // zero out bytes in the first u32 starting from 'start_offset'
  // math is a bit complex to avoid shifting by 32 bits, which is not possible on some architectures
  block[start_idx] &= ~(0xffffffff >> ((start_offset & 3) * 8));

  const u32 end_idx = (end_offset + 3) / 4;

  // zero out bytes in u32 units -- note that the last u32 is completely zeroed!
  for (u32 i = start_idx + 1; i < end_idx; i++)
  {
    block[i] = 0;
  }
}

DECLSPEC void aes128_decrypt_cfb (GLOBAL_AS const u32 *encrypted_data, int data_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *key, PRIVATE_AS u32 *decrypted_data,
                                  SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ks[44];
  u32 essiv[4];

  // Copy the IV, since this will be modified
  essiv[0] = iv[0];
  essiv[1] = iv[1];
  essiv[2] = iv[2];
  essiv[3] = iv[3];

  aes128_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);

  // Decrypt an AES-128 encrypted block
  for (u32 i = 0; i < (data_len + 3) / 4; i += 4)
  {
    aes128_encrypt (ks, essiv, decrypted_data + i, s_te0, s_te1, s_te2, s_te3, s_te4);

    decrypted_data[i + 0] ^= encrypted_data[i + 0];
    decrypted_data[i + 1] ^= encrypted_data[i + 1];
    decrypted_data[i + 2] ^= encrypted_data[i + 2];
    decrypted_data[i + 3] ^= encrypted_data[i + 3];

    // Note: Not necessary if you are only decrypting a single block!
    essiv[0] = encrypted_data[i + 0];
    essiv[1] = encrypted_data[i + 1];
    essiv[2] = encrypted_data[i + 2];
    essiv[3] = encrypted_data[i + 3];
  }
}

DECLSPEC void aes256_decrypt_cfb (GLOBAL_AS const u32 *encrypted_data, int data_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *key, PRIVATE_AS u32 *decrypted_data,
                                  SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ks[60];
  u32 essiv[4];

  // Copy the IV, since this will be modified
  essiv[0] = iv[0];
  essiv[1] = iv[1];
  essiv[2] = iv[2];
  essiv[3] = iv[3];

  aes256_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);

  // Decrypt an AES-256 encrypted block
  for (u32 i = 0; i < (data_len + 3) / 4; i += 4)
  {
    aes256_encrypt (ks, essiv, decrypted_data + i, s_te0, s_te1, s_te2, s_te3, s_te4);

    decrypted_data[i + 0] ^= encrypted_data[i + 0];
    decrypted_data[i + 1] ^= encrypted_data[i + 1];
    decrypted_data[i + 2] ^= encrypted_data[i + 2];
    decrypted_data[i + 3] ^= encrypted_data[i + 3];

    // Note: Not necessary if you are only decrypting a single block!
    essiv[0] = encrypted_data[i + 0];
    essiv[1] = encrypted_data[i + 1];
    essiv[2] = encrypted_data[i + 2];
    essiv[3] = encrypted_data[i + 3];
  }
}

DECLSPEC int check_decoded_data (PRIVATE_AS u32 *decoded_data, const u32 decoded_data_size)
{
  // Check the SHA-1 of the decrypted data which is stored at the end of the decrypted data
  const u32 sha1_byte_off = (decoded_data_size - 20);
  const u32 sha1_u32_off = sha1_byte_off / 4;

  u32 expected_sha1[5];

  expected_sha1[0] = hc_bytealign_le_S (decoded_data[sha1_u32_off + 1], decoded_data[sha1_u32_off + 0], sha1_byte_off);
  expected_sha1[1] = hc_bytealign_le_S (decoded_data[sha1_u32_off + 2], decoded_data[sha1_u32_off + 1], sha1_byte_off);
  expected_sha1[2] = hc_bytealign_le_S (decoded_data[sha1_u32_off + 3], decoded_data[sha1_u32_off + 2], sha1_byte_off);
  expected_sha1[3] = hc_bytealign_le_S (decoded_data[sha1_u32_off + 4], decoded_data[sha1_u32_off + 3], sha1_byte_off);
  expected_sha1[4] = hc_bytealign_le_S (decoded_data[sha1_u32_off + 5], decoded_data[sha1_u32_off + 4], sha1_byte_off);

  memzero_le_S (decoded_data, sha1_byte_off, 384 * sizeof(u32));

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

KERNEL_FQ void m17010_init (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;
  const u32 salted_pw_len = (salt_bufs[SALT_POS_HOST].salt_len + pw_len);

  u32 salted_pw_block[80];

  // concatenate salt and password -- the salt is always 8 bytes
  salted_pw_block[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salted_pw_block[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  for (u32 idx = 0; idx < 64; idx++) salted_pw_block[idx + 2] = pws[gid].i[idx];

  // zero remainder of buffer
  for (u32 idx = 66; idx < 80; idx++) salted_pw_block[idx] = 0;

  // create a number of copies for efficiency
  const u32 copies = 80 * sizeof(u32) / salted_pw_len;

  for (u32 idx = 1; idx < copies; idx++)
  {
    memcat_le_S (salted_pw_block, idx * salted_pw_len, salted_pw_block, salted_pw_len);
  }

  for (u32 idx = 0; idx < 80; idx++)
  {
    tmps[gid].salted_pw_block[idx] = hc_swap32_S (salted_pw_block[idx]);
  }

  tmps[gid].salted_pw_block_len = (copies * salted_pw_len);

  tmps[gid].h[0] = SHA1M_A;
  tmps[gid].h[1] = SHA1M_B;
  tmps[gid].h[2] = SHA1M_C;
  tmps[gid].h[3] = SHA1M_D;
  tmps[gid].h[4] = SHA1M_E;
  tmps[gid].h[5] = SHA1M_A;
  tmps[gid].h[6] = SHA1M_B;
  tmps[gid].h[7] = SHA1M_C;
  tmps[gid].h[8] = SHA1M_D;
  tmps[gid].h[9] = SHA1M_E;

  tmps[gid].len = 0;
}

KERNEL_FQ void m17010_loop_prepare (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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

  tmps[gid].len = SALT_REPEAT;
}

KERNEL_FQ void m17010_loop (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // get the prepared buffer from the gpg_tmp_t struct into a local buffer
  u32 salted_pw_block[80];

  for (int i = 0; i < 80; i++) salted_pw_block[i] = tmps[gid].salted_pw_block[i];

  const u32 salted_pw_block_len = tmps[gid].salted_pw_block_len;

  // do we really need this, since the salt is always length 8?
  if (salted_pw_block_len == 0) return;

  /**
   * context load
   */

  sha1_ctx_t ctx;

  const u32 sha_offset = SALT_REPEAT * 5;

  for (int i = 0; i < 5; i++) ctx.h[i] = tmps[gid].h[sha_offset + i];

  for (int i = 0; i < 4; i++) ctx.w0[i] = tmps[gid].w0[i];
  for (int i = 0; i < 4; i++) ctx.w1[i] = tmps[gid].w1[i];
  for (int i = 0; i < 4; i++) ctx.w2[i] = tmps[gid].w2[i];
  for (int i = 0; i < 4; i++) ctx.w3[i] = tmps[gid].w3[i];

  ctx.len = tmps[gid].len;

  // sha-1 of salt and password, up to 'salt_iter' bytes
  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  const u32 salted_pw_block_pos = LOOP_POS % salted_pw_block_len;
  const u32 rounds = (LOOP_CNT + salted_pw_block_pos) / salted_pw_block_len;

  for (u32 i = 0; i < rounds; i++)
  {
    sha1_update (&ctx, salted_pw_block, salted_pw_block_len);
  }

  if ((LOOP_POS + LOOP_CNT) == salt_iter)
  {
    const u32 remaining_bytes = salt_iter % salted_pw_block_len;

    if (remaining_bytes)
    {
      memzero_be_S (salted_pw_block, remaining_bytes, salted_pw_block_len);

      sha1_update (&ctx, salted_pw_block, remaining_bytes);
    }

    sha1_final (&ctx);
  }

  /**
   * context save
   */

  for (int i = 0; i < 5; i++) tmps[gid].h[sha_offset + i] = ctx.h[i];

  for (int i = 0; i < 4; i++) tmps[gid].w0[i] = ctx.w0[i];
  for (int i = 0; i < 4; i++) tmps[gid].w1[i] = ctx.w1[i];
  for (int i = 0; i < 4; i++) tmps[gid].w2[i] = ctx.w2[i];
  for (int i = 0; i < 4; i++) tmps[gid].w3[i] = ctx.w3[i];

  tmps[gid].len = ctx.len;
}

KERNEL_FQ void m17010_comp (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  // not in use here, special case...
}

KERNEL_FQ void m17010_aux1 (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

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

  // retrieve and use the SHA-1 as the key for AES

  u32 aes_key[4];

  for (int i = 0; i < 4; i++) aes_key[i] = hc_swap32_S (tmps[gid].h[i]);

  u32 iv[4] = {0};

  for (int idx = 0; idx < 4; idx++) iv[idx] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[idx];

  u32 decoded_data[384];

  const u32 enc_data_size = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data_size;

  aes128_decrypt_cfb (esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data, enc_data_size, iv, aes_key, decoded_data, s_te0, s_te1, s_te2, s_te3, s_te4);

  if (check_decoded_data (decoded_data, enc_data_size))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}

KERNEL_FQ void m17010_aux2 (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

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

  // retrieve and use the SHA-1 as the key for AES

  u32 aes_key[8];

  for (int i = 0; i < 8; i++) aes_key[i] = hc_swap32_S (tmps[gid].h[i]);

  u32 iv[4] = {0};

  for (int idx = 0; idx < 4; idx++) iv[idx] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[idx];

  u32 decoded_data[384];

  const u32 enc_data_size = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data_size;

  aes256_decrypt_cfb (esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data, enc_data_size, iv, aes_key, decoded_data, s_te0, s_te1, s_te2, s_te3, s_te4);

  if (check_decoded_data (decoded_data, enc_data_size))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
