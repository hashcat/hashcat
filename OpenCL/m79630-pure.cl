/**
 * Brave Wallet vault (Preferences: brave.wallet.encrypted_mnemonic):
 *
 *   key = PBKDF2-HMAC-SHA256($pass, salt32, iterations, 32B)
 *   out = AES-256-GCM-SIV(key, nonce12).Seal(mnemonic) = ct || 16B tag
 *
 * iterations: 310000 current, 100000 legacy (pre 18.08.2022) - carried in
 * the hash line. AAD empty. Crack = tag match (RFC 8452 sec. 4):
 *
 *   (auth_k, enc_k) = per-nonce keys: AES256_K(LE32(i) || nonce)[:8], i=0..5
 *   S_s  = POLYVAL(auth_k, pad(ct) || LE64(0) || LE64(ct_bits))  // dot mul
 *   S_s ^= nonce || 0^32; clear msb of last byte
 *   tag  = AES256_enc_k(S_s)
 *
 * Hash format: $brave$*<iterations>*<salt_hex64>*<nonce_hex24>*<ct+tag_hex>
 * License: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct brave
{
  u32 nonce[3];     // 12B, LE-packed bytes
  u32 ct_buf[128];  // 512B max, LE-packed bytes, tag stripped
  u32 ct_len;

} brave_t;

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

// GF(2^128) mul mod x^128 + x^127 + x^126 + x^121 + 1, POLYVAL convention:
// bit i of the LE 128-bit integer is the coefficient of x^i (RFC 8452 sec. 3)

DECLSPEC void polyval_mul_128 (PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b, PRIVATE_AS u32 *r)
{
  u32 v[4];

  v[0] = b[0];
  v[1] = b[1];
  v[2] = b[2];
  v[3] = b[3];

  r[0] = 0;
  r[1] = 0;
  r[2] = 0;
  r[3] = 0;

  for (int i = 0; i < 4; i++)
  {
    u32 w = a[i];

    for (int j = 0; j < 32; j++)
    {
      if (w & 1)
      {
        r[0] ^= v[0];
        r[1] ^= v[1];
        r[2] ^= v[2];
        r[3] ^= v[3];
      }

      w >>= 1;

      const u32 carry = v[3] >> 31;

      v[3] = (v[3] << 1) | (v[2] >> 31);
      v[2] = (v[2] << 1) | (v[1] >> 31);
      v[1] = (v[1] << 1) | (v[0] >> 31);
      v[0] =  v[0] << 1;

      if (carry)
      {
        v[0] ^= 1;
        v[3] ^= 0xc2000000;
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m79630_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, brave_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
    tmps[gid].out[i + 5] = tmps[gid].dgst[i + 5];
    tmps[gid].out[i + 6] = tmps[gid].dgst[i + 6];
    tmps[gid].out[i + 7] = tmps[gid].dgst[i + 7];
  }
}

KERNEL_FQ KERNEL_FA void m79630_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, brave_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ KERNEL_FA void m79630_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, brave_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
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

  CONSTANT_VK u32a *s_te0 = te0;
  CONSTANT_VK u32a *s_te1 = te1;
  CONSTANT_VK u32a *s_te2 = te2;
  CONSTANT_VK u32a *s_te3 = te3;
  CONSTANT_VK u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  // master key from PBKDF2 (BE digest words, raw AES256 API)

  u32 ukey[8];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];
  ukey[4] = tmps[gid].out[4];
  ukey[5] = tmps[gid].out[5];
  ukey[6] = tmps[gid].out[6];
  ukey[7] = tmps[gid].out[7];

  u32 ks[60];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  // per-message keys: AES256(LE32(i) || nonce)[:8], i = 0..5 (RFC 8452 sec. 4)

  GLOBAL_AS const brave_t *brave = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 mk[12]; // [0..3] = auth key, [4..11] = enc key (BE words)

  for (u32 i = 0; i < 6; i++)
  {
    u32 in[4];

    in[0] = hc_swap32_S (i);
    in[1] = hc_swap32_S (brave->nonce[0]);
    in[2] = hc_swap32_S (brave->nonce[1]);
    in[3] = hc_swap32_S (brave->nonce[2]);

    u32 out[4];

    AES256_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    mk[i * 2 + 0] = out[0];
    mk[i * 2 + 1] = out[1];
  }

  u32 enc_ks[60];

  AES256_set_encrypt_key (enc_ks, mk + 4, s_te0, s_te1, s_te2, s_te3);

  // POLYVAL: dot(a, h) = a * h * x^-128; fold x^-128 into the key once

  const u32 xinv[4] = { 1, 0, 0, 0x92040000 }; // x^127+x^124+x^121+x^114+1

  u32 mk_auth_le[4]; // POLYVAL wants the LE integer view of the bytes

  mk_auth_le[0] = hc_swap32_S (mk[0]);
  mk_auth_le[1] = hc_swap32_S (mk[1]);
  mk_auth_le[2] = hc_swap32_S (mk[2]);
  mk_auth_le[3] = hc_swap32_S (mk[3]);

  u32 h[4];

  polyval_mul_128 (mk_auth_le, xinv, h);

  // GCM-SIV authenticates the plaintext, so verify = CTR-decrypt with the
  // given tag as initial counter, then POLYVAL the result (RFC 8452 sec. 5)

  const u32 ct_len = brave->ct_len;

  GLOBAL_AS const u8 *ct = (GLOBAL_AS const u8 *) brave->ct_buf;

  u32 ctr[4]; // LE-packed bytes; msb of the last byte set

  ctr[0] = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0]);
  ctr[1] = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1]);
  ctr[2] = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2]);
  ctr[3] = hc_swap32_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]) | 0x80000000;

  u32 S[4] = { 0, 0, 0, 0 };

  for (u32 off = 0; off < ct_len; off += 16)
  {
    u32 ctr_be[4];

    ctr_be[0] = hc_swap32_S (ctr[0]);
    ctr_be[1] = hc_swap32_S (ctr[1]);
    ctr_be[2] = hc_swap32_S (ctr[2]);
    ctr_be[3] = hc_swap32_S (ctr[3]);

    u32 ks_out[4];

    AES256_encrypt (enc_ks, ctr_be, ks_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctr[0] += 1; // first 32 bits as LE32, wraps at 2^32

    for (u32 w = 0; w < 4; w++)
    {
      const u32 base = off + w * 4;

      u32 v = 0;

      u32 nbytes = (ct_len > base) ? (ct_len - base) : 0;

      if (nbytes > 4) nbytes = 4;

      for (u32 b = 0; b < nbytes; b++)
      {
        v |= ((u32) ct[base + b]) << (b * 8);
      }

      const u32 mask = (nbytes == 4) ? 0xffffffff : ((1u << (nbytes * 8)) - 1);

      S[w] ^= (v ^ hc_swap32_S (ks_out[w])) & mask; // ct ^ keystream = pt
    }

    u32 t[4];

    polyval_mul_128 (S, h, t);

    S[0] = t[0];
    S[1] = t[1];
    S[2] = t[2];
    S[3] = t[3];
  }

  // length block: aad empty, LE64(0) || LE64(ct_len * 8)

  S[2] ^= ct_len * 8;

  {
    u32 t[4];

    polyval_mul_128 (S, h, t);

    S[0] = t[0];
    S[1] = t[1];
    S[2] = t[2];
    S[3] = t[3];
  }

  // xor nonce into first 12 bytes, clear msb of last byte, encrypt

  S[0] ^= brave->nonce[0];
  S[1] ^= brave->nonce[1];
  S[2] ^= brave->nonce[2];

  S[3] &= 0x7fffffff;

  u32 S_be[4];

  S_be[0] = hc_swap32_S (S[0]);
  S_be[1] = hc_swap32_S (S[1]);
  S_be[2] = hc_swap32_S (S[2]);
  S_be[3] = hc_swap32_S (S[3]);

  u32 T[4];

  AES256_encrypt (enc_ks, S_be, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  /* compare tag */

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
