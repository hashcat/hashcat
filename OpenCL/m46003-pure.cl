/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_auth_poly1305.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define EMIP3_CT_MAX 2048

// MUST match module_46003.c field-for-field
typedef struct emip3
{
    u32 salt_buf[8];            // 32 bytes
    u32 nonce[3];               // 12 bytes
    u32 ct[EMIP3_CT_MAX / 4];   // ct only (tag rides in the digest)
    u32 ct_len;

} emip3_t;

typedef struct pbkdf2_sha512_tmp
{
    u64 ipad[8];
    u64 opad[8];
    u64 dgst[16];
    u64 out[16];
} pbkdf2_sha512_tmp_t;

DECLSPEC void hmac_sha512_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, PRIVATE_AS u64x *ipad, PRIVATE_AS u64x *opad, PRIVATE_AS u64x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

// ChaCha20 Block Function (Scalar)
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

DECLSPEC void poly1305_key_gen (PRIVATE_AS u32 *key, PRIVATE_AS u32 *nonce, PRIVATE_AS u32 *poly_key)
{
    u32 state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    state[4] = key[0];
    state[5] = key[1];
    state[6] = key[2];
    state[7] = key[3];
    state[8] = key[4];
    state[9] = key[5];
    state[10] = key[6];
    state[11] = key[7];

    state[12] = 0; // Counter
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    u32 out[16];
    chacha20_block(state, out);

    poly_key[0] = out[0];
    poly_key[1] = out[1];
    poly_key[2] = out[2];
    poly_key[3] = out[3];
    poly_key[4] = out[4];
    poly_key[5] = out[5];
    poly_key[6] = out[6];
    poly_key[7] = out[7];
}

CONSTANT_VK u32 block_idx_be[1] = { 0x01000000 };

KERNEL_FQ KERNEL_FA void m46003_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, emip3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha512_hmac_ctx.opad.h[7];

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // For Eternl we only need block 1 (first 64 bytes of PBKDF2 output)
  // Copy context after salt update, then add block index
  sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

  // Append block index as u32 array like m07100
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = 1;  // Block index 1
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 0;

  sha512_hmac_update_128 (&sha512_hmac_ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&sha512_hmac_ctx2);

  tmps[gid].dgst[0] = sha512_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha512_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha512_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha512_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha512_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha512_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha512_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha512_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ KERNEL_FA void m46003_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, emip3_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad, gid, 0);
  ipad[1] = pack64v (tmps, ipad, gid, 1);
  ipad[2] = pack64v (tmps, ipad, gid, 2);
  ipad[3] = pack64v (tmps, ipad, gid, 3);
  ipad[4] = pack64v (tmps, ipad, gid, 4);
  ipad[5] = pack64v (tmps, ipad, gid, 5);
  ipad[6] = pack64v (tmps, ipad, gid, 6);
  ipad[7] = pack64v (tmps, ipad, gid, 7);

  opad[0] = pack64v (tmps, opad, gid, 0);
  opad[1] = pack64v (tmps, opad, gid, 1);
  opad[2] = pack64v (tmps, opad, gid, 2);
  opad[3] = pack64v (tmps, opad, gid, 3);
  opad[4] = pack64v (tmps, opad, gid, 4);
  opad[5] = pack64v (tmps, opad, gid, 5);
  opad[6] = pack64v (tmps, opad, gid, 6);
  opad[7] = pack64v (tmps, opad, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst, gid, i + 7);

    out[0] = pack64v (tmps, out, gid, i + 0);
    out[1] = pack64v (tmps, out, gid, i + 1);
    out[2] = pack64v (tmps, out, gid, i + 2);
    out[3] = pack64v (tmps, out, gid, i + 3);
    out[4] = pack64v (tmps, out, gid, i + 4);
    out[5] = pack64v (tmps, out, gid, i + 5);
    out[6] = pack64v (tmps, out, gid, i + 6);
    out[7] = pack64v (tmps, out, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];
      u32x w4[4];
      u32x w5[4];
      u32x w6[4];
      u32x w7[4];

      w0[0] = h32_from_64 (dgst[0]);
      w0[1] = l32_from_64 (dgst[0]);
      w0[2] = h32_from_64 (dgst[1]);
      w0[3] = l32_from_64 (dgst[1]);
      w1[0] = h32_from_64 (dgst[2]);
      w1[1] = l32_from_64 (dgst[2]);
      w1[2] = h32_from_64 (dgst[3]);
      w1[3] = l32_from_64 (dgst[3]);
      w2[0] = h32_from_64 (dgst[4]);
      w2[1] = l32_from_64 (dgst[4]);
      w2[2] = h32_from_64 (dgst[5]);
      w2[3] = l32_from_64 (dgst[5]);
      w3[0] = h32_from_64 (dgst[6]);
      w3[1] = l32_from_64 (dgst[6]);
      w3[2] = h32_from_64 (dgst[7]);
      w3[3] = l32_from_64 (dgst[7]);
      w4[0] = 0x80000000;
      w4[1] = 0;
      w4[2] = 0;
      w4[3] = 0;
      w5[0] = 0;
      w5[1] = 0;
      w5[2] = 0;
      w5[3] = 0;
      w6[0] = 0;
      w6[1] = 0;
      w6[2] = 0;
      w6[3] = 0;
      w7[0] = 0;
      w7[1] = 0;
      w7[2] = 0;
      w7[3] = (128 + 64) * 8;

      hmac_sha512_run_V (w0, w1, w2, w3, w4, w5, w6, w7, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpack64v (tmps, dgst, gid, i + 0, dgst[0]);
    unpack64v (tmps, dgst, gid, i + 1, dgst[1]);
    unpack64v (tmps, dgst, gid, i + 2, dgst[2]);
    unpack64v (tmps, dgst, gid, i + 3, dgst[3]);
    unpack64v (tmps, dgst, gid, i + 4, dgst[4]);
    unpack64v (tmps, dgst, gid, i + 5, dgst[5]);
    unpack64v (tmps, dgst, gid, i + 6, dgst[6]);
    unpack64v (tmps, dgst, gid, i + 7, dgst[7]);

    unpack64v (tmps, out, gid, i + 0, out[0]);
    unpack64v (tmps, out, gid, i + 1, out[1]);
    unpack64v (tmps, out, gid, i + 2, out[2]);
    unpack64v (tmps, out, gid, i + 3, out[3]);
    unpack64v (tmps, out, gid, i + 4, out[4]);
    unpack64v (tmps, out, gid, i + 5, out[5]);
    unpack64v (tmps, out, gid, i + 6, out[6]);
    unpack64v (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ KERNEL_FA void m46003_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, emip3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 encrypted_len = esalt_bufs[DIGESTS_OFFSET_HOST].ct_len;

  // Convert PBKDF2 output to ChaCha20 key
  // PBKDF2-SHA512 stores output as big-endian u64 values
  // ChaCha20 expects little-endian u32 values
  // We need to byteswap the extracted u32 values
  u32 key[8];
  key[0] = hc_swap32_S(h32_from_64_S(tmps[gid].out[0]));
  key[1] = hc_swap32_S(l32_from_64_S(tmps[gid].out[0]));
  key[2] = hc_swap32_S(h32_from_64_S(tmps[gid].out[1]));
  key[3] = hc_swap32_S(l32_from_64_S(tmps[gid].out[1]));
  key[4] = hc_swap32_S(h32_from_64_S(tmps[gid].out[2]));
  key[5] = hc_swap32_S(l32_from_64_S(tmps[gid].out[2]));
  key[6] = hc_swap32_S(h32_from_64_S(tmps[gid].out[3]));
  key[7] = hc_swap32_S(l32_from_64_S(tmps[gid].out[3]));

  // ChaCha20Poly1305 decryption
  u32 nonce[3];
  nonce[0] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[0];
  nonce[1] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[1];
  nonce[2] = esalt_bufs[DIGESTS_OFFSET_HOST].nonce[2];

  // Get poly1305 key
  u32 poly1305_key[8];
  poly1305_key_gen(key, nonce, poly1305_key);

  // Decrypt and verify
  u32 mac[4];
  poly1305_ctx_t poly1305_ctx;
  poly1305_init(&poly1305_ctx, poly1305_key);

  // AAD (none)

  // Ciphertext
  poly1305_update_global(&poly1305_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ct, encrypted_len);
  poly1305_update_pad(&poly1305_ctx, encrypted_len);

  // Lengths (as per RFC 8439 Section 2.8)
  // aad_len (64-bit LE) || ciphertext_len (64-bit LE)
  u32 lens[4];
  lens[0] = 0;  // AAD length low 32 bits
  lens[1] = 0;  // AAD length high 32 bits
  lens[2] = encrypted_len;  // Ciphertext length low 32 bits
  lens[3] = 0;  // Ciphertext length high 32 bits
  poly1305_update_private(&poly1305_ctx, lens, 16);

  poly1305_final(&poly1305_ctx, mac);

  const u32 r0 = mac[0];
  const u32 r1 = mac[1];
  const u32 r2 = mac[2];
  const u32 r3 = mac[3];

  // Load expected digest for comparison
  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_S
  #endif
}
