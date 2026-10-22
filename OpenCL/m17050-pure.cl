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

DECLSPEC void pack_be_16_to_u32x4 (const u8 in[16], PRIVATE_AS u32 out[4])
{
  out[0] = ((u32)in[ 0] << 24) | ((u32)in[ 1] << 16) | ((u32)in[ 2] <<  8) | (u32)in[ 3];
  out[1] = ((u32)in[ 4] << 24) | ((u32)in[ 5] << 16) | ((u32)in[ 6] <<  8) | (u32)in[ 7];
  out[2] = ((u32)in[ 8] << 24) | ((u32)in[ 9] << 16) | ((u32)in[10] <<  8) | (u32)in[11];
  out[3] = ((u32)in[12] << 24) | ((u32)in[13] << 16) | ((u32)in[14] <<  8) | (u32)in[15];
}

DECLSPEC void gf_dbl_be (PRIVATE_AS u32 v[4])
{
  const u32 msb = v[0] >> 31;
  v[0] = (v[0] << 1) | (v[1] >> 31);
  v[1] = (v[1] << 1) | (v[2] >> 31);
  v[2] = (v[2] << 1) | (v[3] >> 31);
  v[3] = (v[3] << 1);
  if (msb) v[3] ^= 0x87; // x^128 + x^7 + x^2 + x + 1
}

// https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#ocb-mode
// https://github.com/Legrandin/pycryptodome/blob/2c3a8905a7929335a9b2763e18d6e9ed516b8a38/src/raw_ocb.c#L118
/* OCB3 single full-block decrypt (i = 1)
 * Offset1 = Offset0 XOR L0,  P = Offset1 XOR D_k( C XOR Offset1 )
 * - ks_enc: AES-128 encrypt key schedule  (you already build this)
 * - ks_dec: AES-128 decrypt key schedule  (new: pass this too)
 * - offset_be: 16B Offset0 in BE-packed u32[4] (what you compute via Ktop/Stretch)
 */
DECLSPEC void aes128_decrypt_ocb (
  PRIVATE_AS const u32 *ks_enc,
  PRIVATE_AS const u32 *ks_dec,
  PRIVATE_AS const u32 *offset_be,
  GLOBAL_AS  const u32 *in,
  PRIVATE_AS       u32 *out,
  SHM_TYPE u32a *s_te0,
  SHM_TYPE u32a *s_te1,
  SHM_TYPE u32a *s_te2,
  SHM_TYPE u32a *s_te3,
  SHM_TYPE u32a *s_te4,
  SHM_TYPE u32a *s_td0,
  SHM_TYPE u32a *s_td1,
  SHM_TYPE u32a *s_td2,
  SHM_TYPE u32a *s_td3,
  SHM_TYPE u32a *s_td4)
{
  // L_* = E_k(0^128), L_$ = dbl(L_*), L_0 = dbl(L_$)
  u32 Z[4] = { 0, 0, 0, 0 };

  u32 Lstar[4];
  AES128_encrypt (ks_enc, Z, Lstar, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 Ldollar[4] = { Lstar[0], Lstar[1], Lstar[2], Lstar[3] };
  gf_dbl_be (Ldollar);

  u32 L0[4] = { Ldollar[0], Ldollar[1], Ldollar[2], Ldollar[3] };
  gf_dbl_be (L0);

  // Offset1 = Offset0 XOR L0  (all BE-packed)
  u32 offset1_be[4];
  offset1_be[0] = offset_be[0] ^ L0[0];
  offset1_be[1] = offset_be[1] ^ L0[1];
  offset1_be[2] = offset_be[2] ^ L0[2];
  offset1_be[3] = offset_be[3] ^ L0[3];

  // Load C as BE words (so the XOR is byte-true)
  u32 c_be0 = hc_swap32_S (in[0]);
  u32 c_be1 = hc_swap32_S (in[1]);
  u32 c_be2 = hc_swap32_S (in[2]);
  u32 c_be3 = hc_swap32_S (in[3]);

  u32 x_be[4];
  x_be[0] = c_be0 ^ offset1_be[0];
  x_be[1] = c_be1 ^ offset1_be[1];
  x_be[2] = c_be2 ^ offset1_be[2];
  x_be[3] = c_be3 ^ offset1_be[3];

  // AES-128 decrypt
  u32 d_be[4];
  AES128_decrypt (ks_dec, x_be, d_be, s_td0, s_td1, s_td2, s_td3, s_td4);

  // P (BE) = d_be XOR Offset1; store back in native order
  out[0] = hc_swap32_S (d_be[0] ^ offset1_be[0]);
  out[1] = hc_swap32_S (d_be[1] ^ offset1_be[1]);
  out[2] = hc_swap32_S (d_be[2] ^ offset1_be[2]);
  out[3] = hc_swap32_S (d_be[3] ^ offset1_be[3]);

  // #ifdef KERNEL_DEBUG
  // if (get_global_id (0) == 0)
  // {
  //   printf ("offset_1= %08x%08x%08x%08x\n", offset1_be[0], offset1_be[1], offset1_be[2], offset1_be[3]);
  // }
  // #endif
}

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4]; // we only need 12 bytes, but speedup is negligible
  u32 modulus_size;
  u32 encrypted_data[384]; // we only need 16 bytes, but speedup is negligible
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
  // GPG AES-OCB already has integrity checking, so doesn't save SHA1 at end of decrypted block..
  // we could decrypt everything and verify the tag, but we know the first bytes, so we use that.
  //
  // The decrypted secret is a canonical S-expression (RFC 4880 / libgcrypt): it starts with
  // the first secret MPI, encoded as  "(((1:" <name> <decimal-length> ":" <bytes>. The MPI
  // name is a single byte and depends on the key algorithm, and the length is ASCII decimal,
  // so both vary by key type:
  //   ECC / ed25519  (32-byte  d): "(((1:d32:"
  //   Brainpool/secp (33-byte  d): "(((1:d33:"
  //   ed448          (57-byte  d): "(((1:d57:"
  //   RSA-2048      (256-byte  d): "(((1:d256:"
  //   RSA-4096      (512-byte  d): "(((1:d512:"
  //   DSA / ElGamal  (nn-byte  x): "(((1:x33:"   <- secret is named 'x', not 'd'
  // So we match "(((1:" exactly, require the name byte to be 'd' or 'x', and require the next
  // two bytes to be ASCII decimal digits (a real key's secret is always >= 10 bytes, so the
  // length has >= 2 digits). This keeps the check key-type-agnostic, so RSA, ECC, DSA/ElGamal
  // all pass, while still examining 8 bytes: we can't check for printables on only 8 bytes
  // as that is not enough (false positives), but 5 exact bytes + a 2-way name byte + 2
  // digit-class bytes is ~2^-56, which for this slow hash is ample.
  //
  // full examples of decrypted data for future reference
  // ed25519: 28 28 28 31 3a 64 33 32 3a 49 e4 de 08 ac 5b 0f   (((1:d32:I....[.
  // rsa2048: 28 28 28 31 3a 64 32 35 36 3a 1a 2a a1 ad cf d0   (((1:d256:.*....
  // rsa4096: 28 28 28 31 3a 64 35 31 32 3a 04 ec 42 a9 cb 49   (((1:d512:..B..I
  // dsa2048: 28 28 28 31 3a 78 33 33 3a 00 81 64 ..            (((1:x33:...d

  #define PACK4(a,b,c,d) ((u32)(a) | ((u32)(b)<<8) | ((u32)(c)<<16) | ((u32)(d)<<24))

  const u32 w0 = decoded_data[0]; // plaintext bytes 0..3 : "(((1"
  const u32 w1 = decoded_data[1]; // plaintext bytes 4..7 : ':' <name> <digit> <digit>

  const u32 sep        = (w1 >>  0) & 0xff; // ':'
  const u32 mpi_name   = (w1 >>  8) & 0xff; // 'd' (RSA/ECC) or 'x' (DSA/ElGamal)
  const u32 len_digit0 = (w1 >> 16) & 0xff; // plaintext byte 6
  const u32 len_digit1 = (w1 >> 24) & 0xff; // plaintext byte 7

  return (w0 == PACK4('(', '(', '(', '1'))                    // "(((1"
      && (sep == ':')
      && ((mpi_name == 'd') || (mpi_name == 'x'))             // ":d" or ":x"
      && (len_digit0 >= '0') && (len_digit0 <= '9')
      && (len_digit1 >= '0') && (len_digit1 <= '9');
}

KERNEL_FQ KERNEL_FA void m17050_init (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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

  const u32 salted_pw_block_len = copies * salted_pw_len;

  // memcat_le_S() copies whole u32 words, so the word that straddles the end of the last
  // copy comes out holding the next bytes of the repeated salt||pw stream instead of zero.
  // Everything from salted_pw_block_len on has to read as zero: sha1_update() always pulls
  // a full 64 byte tail window and ORs it into the running context, and sha1_final() ORs
  // its 0x80 padding byte into whatever is left sitting there. Leave the slack dirty and the
  // S2K key comes out wrong whenever the truncated last repetition of salt||pw is shorter
  // than it, which is why some (iteration count, password length) pairs never cracked.
  if (salted_pw_block_len < sizeof (salted_pw_block))
  {
    memzero_le_S (salted_pw_block, salted_pw_block_len, sizeof (salted_pw_block));
  }

  for (u32 idx = 0; idx < 80; idx++)
  {
    tmps[gid].salted_pw_block[idx] = hc_swap32_S (salted_pw_block[idx]);
  }

  tmps[gid].salted_pw_block_len = salted_pw_block_len;

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

KERNEL_FQ KERNEL_FA void m17050_loop_prepare (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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

KERNEL_FQ KERNEL_FA void m17050_loop (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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

KERNEL_FQ KERNEL_FA void m17050_comp (KERN_ATTR_TMPS_ESALT (gpg_tmp_t, gpg_t))
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
  LOCAL_VK u32 s_te0[256], s_te1[256], s_te2[256], s_te3[256], s_te4[256];
  LOCAL_VK u32 s_td0[256], s_td1[256], s_td2[256], s_td3[256], s_td4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i]; s_te1[i] = te1[i]; s_te2[i] = te2[i]; s_te3[i] = te3[i]; s_te4[i] = te4[i];
    s_td0[i] = td0[i]; s_td1[i] = td1[i]; s_td2[i] = td2[i]; s_td3[i] = td3[i]; s_td4[i] = td4[i];
  }

  SYNC_THREADS ();
#else
  SHM_TYPE u32a *s_te0 = te0;  SHM_TYPE u32a *s_te1 = te1;  SHM_TYPE u32a *s_te2 = te2;
  SHM_TYPE u32a *s_te3 = te3;  SHM_TYPE u32a *s_te4 = te4;

  SHM_TYPE u32a *s_td0 = td0;  SHM_TYPE u32a *s_td1 = td1;  SHM_TYPE u32a *s_td2 = td2;
  SHM_TYPE u32a *s_td3 = td3;  SHM_TYPE u32a *s_td4 = td4;
#endif

  if (gid >= GID_CNT) return;

  // retrieve and use the SHA-1 as the key for AES

  u32 aes_key[4];

  for (int i = 0; i < 4; i++) aes_key[i] = hc_swap32_S (tmps[gid].h[i]);
  // if ((gid == 0) && (lid == 0)) printf("aes_key= ");
  // for(int i=0;i<4;i++) {
  //   if ((gid == 0) && (lid == 0)) printf ("%08x", aes_key[i]);
  // }
  // if ((gid == 0) && (lid == 0)) printf ("\n");

  u32 iv[4] = {0};

  for (int idx = 0; idx < 4; idx++) iv[idx] = (esalt_bufs[DIGESTS_OFFSET_HOST].iv[idx]); //  hc_swap32_S ??!! should this be swap?

  // if ((gid == 0) && (lid == 0)) printf("iv= ");
  // for(int i=0;i<4;i++) {
  //   if ((gid == 0) && (lid == 0)) printf ("%08x", iv[i]);
  // }
  // if ((gid == 0) && (lid == 0)) printf ("\n");

  u32 decoded_data[384] = {0};

  const u32 enc_data_size = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data_size;

  PRIVATE_AS u32 ks_enc[44];
  aes128_set_encrypt_key (ks_enc, aes_key, s_te0, s_te1, s_te2, s_te3);

  PRIVATE_AS u32 ks_dec[44];
  aes128_set_decrypt_key (ks_dec, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);


  // --- OCB3 Ktop/Stretch to build Offset_0 into u32 offset[4] ---

  u32 offset[4];

  // 1) Extract the 12 nonce bytes from your iv[3] words (LE -> bytes).
  u8 N[12];
  N[0] = (u8)(iv[0]      ); N[1] = (u8)(iv[0] >>  8);
  N[2] = (u8)(iv[0] >> 16); N[3] = (u8)(iv[0] >> 24);
  N[4] = (u8)(iv[1]      ); N[5] = (u8)(iv[1] >>  8);
  N[6] = (u8)(iv[1] >> 16); N[7] = (u8)(iv[1] >> 24);
  N[8] = (u8)(iv[2]      ); N[9] = (u8)(iv[2] >>  8);
  N[10]= (u8)(iv[2] >> 16); N[11]= (u8)(iv[2] >> 24);

  // 2) bottom and Top per OCB3 (96-bit fast path)
  const int bottom = N[11] & 0x3f;

  u8 Top[16];
  Top[0]=0x00; Top[1]=0x00; Top[2]=0x00; Top[3]=0x01;   // 0x00000001 ||
  Top[4]=N[0]; Top[5]=N[1]; Top[6]=N[2]; Top[7]=N[3];
  Top[8]=N[4]; Top[9]=N[5]; Top[10]=N[6]; Top[11]=N[7];
  Top[12]=N[8]; Top[13]=N[9]; Top[14]=N[10];
  Top[15] = (u8)(N[11] & 0xC0);                         // zero low 6 bits

  // 3) Ktop = AES_k(Top)  (pack Top as BE words for AES tables)
  u32 state[4], Ktop[4];
  pack_be_16_to_u32x4 (Top, state);
  AES128_encrypt (ks_enc, state, Ktop, s_te0, s_te1, s_te2, s_te3, s_te4);

  // 4) Stretch = Ktop || (Ktop[0..7] ^ Ktop[1..8])   // 24 bytes
  u8 S[24];
  S[ 0]=(u8)(Ktop[0]>>24); S[ 1]=(u8)(Ktop[0]>>16); S[ 2]=(u8)(Ktop[0]>>8); S[ 3]=(u8)Ktop[0];
  S[ 4]=(u8)(Ktop[1]>>24); S[ 5]=(u8)(Ktop[1]>>16); S[ 6]=(u8)(Ktop[1]>>8); S[ 7]=(u8)Ktop[1];
  S[ 8]=(u8)(Ktop[2]>>24); S[ 9]=(u8)(Ktop[2]>>16); S[10]=(u8)(Ktop[2]>>8); S[11]=(u8)Ktop[2];
  S[12]=(u8)(Ktop[3]>>24); S[13]=(u8)(Ktop[3]>>16); S[14]=(u8)(Ktop[3]>>8); S[15]=(u8)Ktop[3];
  S[16]= (u8)(S[0] ^ S[1]); S[17]=(u8)(S[1] ^ S[2]); S[18]=(u8)(S[2] ^ S[3]); S[19]=(u8)(S[3] ^ S[4]);
  S[20]= (u8)(S[4] ^ S[5]); S[21]=(u8)(S[5] ^ S[6]); S[22]=(u8)(S[6] ^ S[7]); S[23]=(u8)(S[7] ^ S[8]);

  // 5) Offset_0 = (Stretch << bottom)[0..127]   // ***bit*** shift, not byte slice
  const int b   = bottom >> 3;         // byte offset
  const int rem = bottom & 7;          // bit remainder

  u8 Off[16];
  if (rem == 0)
  {
    // pure byte alignment
    for (int i = 0; i < 16; i++) Off[i] = S[i + b];
  }
  else
  {
    const int r = 8 - rem;
    for (int i = 0; i < 16; i++)
    {
      const u8 lo = S[i + b];
      const u8 hi = S[i + b + 1];
      Off[i] = (u8)((lo << rem) | (hi >> r));
    }
  }

  // 6) Pack back to 4 BE words for AES input
  pack_be_16_to_u32x4 (Off, offset);

  // #define KERNEL_DEBUG 1
  // #ifdef KERNEL_DEBUG
  // if ((gid == 0) && (lid == 0))
  // {
  //   printf ("offset_0 (before encrypt)= %08x%08x%08x%08x\n", offset[0], offset[1], offset[2], offset[3]);
  // }
  // #endif

  aes128_decrypt_ocb (ks_enc, ks_dec, offset,
    esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data,
    decoded_data,
    s_te0, s_te1, s_te2, s_te3, s_te4,
    s_td0, s_td1, s_td2, s_td3, s_td4);

  // if ((gid == 0) && (lid == 0)) printf("aes128_decrypt_ocb decoded_data= ");
  // for(int i=0;i<384;i++) {
  //   if ((gid == 0) && (lid == 0)) printf ("%08x", decoded_data[i]);
  // }
  // if ((gid == 0) && (lid == 0)) printf ("\n");
  // if ((gid == 0) && (lid == 0)) printf ("enc_data_size=%d\n",enc_data_size);

  if (check_decoded_data (decoded_data, enc_data_size))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
