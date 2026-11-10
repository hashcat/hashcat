/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * GPG symmetric-mode: SHA1-S2K (Iterated+Salted) + AES-256-CFB128 + SHA1-MDC
 * Mode 17060 — pk_algorithm==0, usage==18, cipher==AES-256
 *
 * Key derivation (RFC 4880 §3.7.1.3):
 *   pass-0: SHA1( (salt||pass) repeated for `count` bytes )         -> key[0..19]
 *   pass-1: SHA1( 0x00 || (salt||pass) repeated for `count` bytes ) -> key[20..31]
 *
 * The two-pass loop is driven by salt_repeats=1 in the C module:
 *   SALT_REPEAT=0 in init/loop_prepare -> ctx.len=0 (no prefix)
 *   SALT_REPEAT=1 in init/loop_prepare -> ctx.len=1 (one 0x00 byte prefix)
 *
 * Decryption: AES-256-CFB128, IV = all-zero 16 bytes
 *
 * Verification (MDC): SHA1(plaintext[0..datalen-21]) == plaintext[datalen-20..]
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
  /* Pre-built repeating (salt || password) block, big-endian for SHA1 */
  u32 salted_pw_block[80];
  u32 salted_pw_block_len;

  /* SHA1 state for two passes (h[0..4] = pass-0, h[5..9] = pass-1) */
  u32 h[10];

  /* Current SHA1 block accumulator */
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 len;

} gpg_tmp_t;

/* ── Byte manipulation helpers (reused from m17010) ── */

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

/* ── AES-256-CFB128 decryption ── */

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

  for (u32 i = 0; i < (u32)(data_len + 3) / 4; i += 4)
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

/* ── MDC verification: SHA1(plaintext[:-20]) == plaintext[-20:] ── */

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

  memzero_le_S (decoded_data, sha1_byte_off, 384 * sizeof (u32));

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

/* ── Init: build the repeating (salt || password) block ── */

KERNEL_FQ KERNEL_FA void m17060_init (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len        = pws[gid].pw_len;
  const u32 salted_pw_len = (salt_bufs[SALT_POS_HOST].salt_len + pw_len);

  u32 salted_pw_block[80];

  /* salt is always 8 bytes; place it first, followed by the password */
  salted_pw_block[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salted_pw_block[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  for (u32 idx = 0; idx < 64; idx++) salted_pw_block[idx + 2] = pws[gid].i[idx];

  for (u32 idx = 66; idx < 80; idx++) salted_pw_block[idx] = 0;

  /* Fill buffer with multiple copies for efficiency */
  const u32 copies = 80 * sizeof (u32) / salted_pw_len;

  for (u32 idx = 1; idx < copies; idx++)
  {
    memcat_le_S (salted_pw_block, idx * salted_pw_len, salted_pw_block, salted_pw_len);
  }

  /* Store in big-endian form (SHA1 processes big-endian words) */
  for (u32 idx = 0; idx < 80; idx++)
  {
    tmps[gid].salted_pw_block[idx] = hc_swap32_S (salted_pw_block[idx]);
  }

  tmps[gid].salted_pw_block_len = (copies * salted_pw_len);

  /* Initialise both SHA1 states (pass-0 and pass-1) */
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

/* ── Loop prepare: reset accumulator for this S2K pass ── */

KERNEL_FQ KERNEL_FA void m17060_loop_prepare (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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

  /*
   * SALT_REPEAT == 0: first pass, fresh SHA1 (no prefix bytes)
   * SALT_REPEAT == 1: second pass, one 0x00 prefix byte already in block
   *
   * The w-buffer is all zeros and len=SALT_REPEAT means SALT_REPEAT zero
   * bytes have been accumulated, which matches the RFC 4880 §3.7.1.3
   * multi-context separator: pass i starts with i leading zero bytes.
   */
  tmps[gid].len = SALT_REPEAT;
}

/* ── Loop: feed (salt || password) pattern to SHA1 ── */

KERNEL_FQ KERNEL_FA void m17060_loop (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salted_pw_block[80];

  for (int i = 0; i < 80; i++) salted_pw_block[i] = tmps[gid].salted_pw_block[i];

  const u32 salted_pw_block_len = tmps[gid].salted_pw_block_len;

  if (salted_pw_block_len == 0) return;

  /* Restore SHA1 context for the current pass */

  sha1_ctx_t ctx;

  const u32 sha_offset = SALT_REPEAT * 5;

  for (int i = 0; i < 5; i++) ctx.h[i] = tmps[gid].h[sha_offset + i];

  for (int i = 0; i < 4; i++) ctx.w0[i] = tmps[gid].w0[i];
  for (int i = 0; i < 4; i++) ctx.w1[i] = tmps[gid].w1[i];
  for (int i = 0; i < 4; i++) ctx.w2[i] = tmps[gid].w2[i];
  for (int i = 0; i < 4; i++) ctx.w3[i] = tmps[gid].w3[i];

  ctx.len = tmps[gid].len;

  /* Feed the pattern bytes */

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

  /* Save SHA1 context */

  for (int i = 0; i < 5; i++) tmps[gid].h[sha_offset + i] = ctx.h[i];

  for (int i = 0; i < 4; i++) tmps[gid].w0[i] = ctx.w0[i];
  for (int i = 0; i < 4; i++) tmps[gid].w1[i] = ctx.w1[i];
  for (int i = 0; i < 4; i++) tmps[gid].w2[i] = ctx.w2[i];
  for (int i = 0; i < 4; i++) tmps[gid].w3[i] = ctx.w3[i];

  tmps[gid].len = ctx.len;
}

/* ── Comp: not used; verification is done in aux1 ── */

KERNEL_FQ KERNEL_FA void m17060_comp (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  // not in use — special case handled by DEEP_COMP_KERNEL / aux1
}

/* ── Aux1: derive AES-256 key and decrypt + MDC-check ── */

KERNEL_FQ KERNEL_FA void m17060_aux1 (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /* ── AES S-boxes (shared memory for speed) ── */

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

  /*
   * AES-256 key = first 32 bytes of the two SHA1 digests:
   *   key[ 0..19] = h[0..4] (pass-0 SHA1)
   *   key[20..31] = h[5..7] (first 12 bytes of pass-1 SHA1)
   */
  u32 aes_key[8];

  for (int i = 0; i < 8; i++) aes_key[i] = hc_swap32_S (tmps[gid].h[i]);

  /*
   * IV = all-zero 16 bytes.
   * Symmetric mode in GPG does not include a stored IV in the hash format;
   * the decryption IV is implicitly zero.
   */
  u32 iv[4] = { 0, 0, 0, 0 };

  u32 decoded_data[384];

  const u32 enc_data_size = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data_size;

  aes256_decrypt_cfb (esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data, enc_data_size, iv, aes_key, decoded_data, s_te0, s_te1, s_te2, s_te3, s_te4);

  /* MDC check: SHA1(plaintext[:-20]) == plaintext[-20:] */

  if (check_decoded_data (decoded_data, enc_data_size))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
