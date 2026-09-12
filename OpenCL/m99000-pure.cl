/**
 * Author......: Ben Carmitchel (Datarecovery.com)
 * License.....: MIT
 *
 * LastPass Vault (Chrome IndexedDB) - kernel
 *
 *   key = PBKDF2-HMAC-SHA256(password, email.lower(), iterations, 32)
 *   pt  = AES-256-CBC-Decrypt(verify_ct, key, iv)   // 2 blocks
 *   match = PKCS7-valid(pt[16:32]) AND ASCII-printable(pt[0:16])
 *
 * On match, write the magic digest {0xdeadbeef, 0xfeedface,
 * 0xcafebabe, 0xbaadf00d} via COMPARE_M_SCALAR.
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

typedef struct lpvault
{
  u32 iv[4];
  u32 ct[8];
} lpvault_t;

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} pbkdf2_sha256_tmp_t;

// hmac_sha256_run_V - defined per-module in hashcat (not in a header).
// Copied verbatim from m15600-pure.cl.
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


// ============================================================
// _init - first HMAC iteration of PBKDF2
// ============================================================
KERNEL_FQ void m99000_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, lpvault_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // HMAC-SHA256 init with password as key
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  // Save ipad / opad for reuse in _loop
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

  // Append salt (the email, stored in standard salt_buf)
  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // Append PBKDF2 counter "1" as 4-byte big-endian, then finalize first HMAC
  sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 1;
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

  // First PBKDF2 round result goes into both dgst (loop input) and out (XOR accumulator)
  tmps[gid].dgst[0] = sha256_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha256_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha256_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha256_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha256_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha256_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha256_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha256_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}


// ============================================================
// _loop - main PBKDF2 iteration loop (called multiple times,
//         total iterations = salt->salt_iter + 1, minus the
//         first one done in _init)
// ============================================================
KERNEL_FQ void m99000_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, lpvault_t))
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

  u32x dgst[8];
  u32x out[8];

  dgst[0] = packv (tmps, dgst, gid, 0);
  dgst[1] = packv (tmps, dgst, gid, 1);
  dgst[2] = packv (tmps, dgst, gid, 2);
  dgst[3] = packv (tmps, dgst, gid, 3);
  dgst[4] = packv (tmps, dgst, gid, 4);
  dgst[5] = packv (tmps, dgst, gid, 5);
  dgst[6] = packv (tmps, dgst, gid, 6);
  dgst[7] = packv (tmps, dgst, gid, 7);

  out[0] = packv (tmps, out, gid, 0);
  out[1] = packv (tmps, out, gid, 1);
  out[2] = packv (tmps, out, gid, 2);
  out[3] = packv (tmps, out, gid, 3);
  out[4] = packv (tmps, out, gid, 4);
  out[5] = packv (tmps, out, gid, 5);
  out[6] = packv (tmps, out, gid, 6);
  out[7] = packv (tmps, out, gid, 7);

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

  unpackv (tmps, dgst, gid, 0, dgst[0]);
  unpackv (tmps, dgst, gid, 1, dgst[1]);
  unpackv (tmps, dgst, gid, 2, dgst[2]);
  unpackv (tmps, dgst, gid, 3, dgst[3]);
  unpackv (tmps, dgst, gid, 4, dgst[4]);
  unpackv (tmps, dgst, gid, 5, dgst[5]);
  unpackv (tmps, dgst, gid, 6, dgst[6]);
  unpackv (tmps, dgst, gid, 7, dgst[7]);

  unpackv (tmps, out, gid, 0, out[0]);
  unpackv (tmps, out, gid, 1, out[1]);
  unpackv (tmps, out, gid, 2, out[2]);
  unpackv (tmps, out, gid, 3, out[3]);
  unpackv (tmps, out, gid, 4, out[4]);
  unpackv (tmps, out, gid, 5, out[5]);
  unpackv (tmps, out, gid, 6, out[6]);
  unpackv (tmps, out, gid, 7, out[7]);
}


// ============================================================
// _comp - take derived key, AES-256-CBC decrypt 2 blocks of esalt
//         ciphertext, verify PKCS7 + ASCII printable, write magic
//         if matched
// ============================================================
KERNEL_FQ void m99000_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, lpvault_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  // Load AES tables into local memory.
  // CRITICAL: This must happen BEFORE the gid >= GID_CNT early-return so that
  // all threads in the workgroup participate. Otherwise with few candidates,
  // most threads exit before loading and the tables end up mostly zeros.
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

  if (gid >= GID_CNT) return;

  // ========================================================================
  // Inline AES-256 implementation - bypasses hashcat AES library functions
  // which fail to populate the middle key schedule in this kernel context.
  // Convention: u32s use BIG-ENDIAN byte order (byte 0 = high bits).
  // ========================================================================

  // -- Load key (8 u32s) directly from PBKDF2 output, no byte_swap.
  // SHA256 already produces BE form which is what AES wants.
  u32 key[8];
  key[0] = tmps[gid].out[0];
  key[1] = tmps[gid].out[1];
  key[2] = tmps[gid].out[2];
  key[3] = tmps[gid].out[3];
  key[4] = tmps[gid].out[4];
  key[5] = tmps[gid].out[5];
  key[6] = tmps[gid].out[6];
  key[7] = tmps[gid].out[7];

  // -- Key expansion: produce 60-u32 encryption schedule
  u32 ks[60];

  ks[0] = key[0]; ks[1] = key[1]; ks[2] = key[2]; ks[3] = key[3];
  ks[4] = key[4]; ks[5] = key[5]; ks[6] = key[6]; ks[7] = key[7];

  const u32 rcon[7] = {0x01000000, 0x02000000, 0x04000000, 0x08000000,
                       0x10000000, 0x20000000, 0x40000000};

  for (u32 i = 8; i < 60; i++)
  {
    u32 t = ks[i - 1];

    if ((i & 7) == 0)
    {
      // RotWord: rotate bytes left by 1 (in BE u32: byte0 moves to byte3)
      t = (t << 8) | (t >> 24);
      // SubWord: extract s[x] from s_te0[x] via (val >> 16) & 0xff.
      // s_te0[x] = (s[x]*2, s[x], s[x], s[x]*3) in BE byte order, so byte 1 = s[x].
      u32 b3 = (s_te0[(t >> 24) & 0xff] >> 16) & 0xff;
      u32 b2 = (s_te0[(t >> 16) & 0xff] >> 16) & 0xff;
      u32 b1 = (s_te0[(t >>  8) & 0xff] >> 16) & 0xff;
      u32 b0 = (s_te0[(t >>  0) & 0xff] >> 16) & 0xff;
      t = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
      t ^= rcon[(i >> 3) - 1];
    }
    else if ((i & 7) == 4)
    {
      // SubWord only
      u32 b3 = (s_te0[(t >> 24) & 0xff] >> 16) & 0xff;
      u32 b2 = (s_te0[(t >> 16) & 0xff] >> 16) & 0xff;
      u32 b1 = (s_te0[(t >>  8) & 0xff] >> 16) & 0xff;
      u32 b0 = (s_te0[(t >>  0) & 0xff] >> 16) & 0xff;
      t = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }

    ks[i] = ks[i - 8] ^ t;
  }

  // Apply InvMixColumns to middle round keys ks[4..55] to convert the
  // encryption schedule into the Equivalent Inverse Cipher schedule. This
  // lets us use td0..td3 T-tables (which combine InvSubBytes+InvShiftRows+
  // InvMixColumns) with simple round-key XOR in the decrypt loop.
  //
  // Trick: td0[s[x]] = (x*0x0e, x*0x09, x*0x0d, x*0x0b) since sinv(s(x))=x.
  // So InvMixColumns(b0,b1,b2,b3) = td0[s[b0]] ^ td1[s[b1]] ^ td2[s[b2]] ^ td3[s[b3]].
  for (u32 i = 4; i < 56; i++)
  {
    u32 v = ks[i];
    u32 b0 = (v >> 24) & 0xff;
    u32 b1 = (v >> 16) & 0xff;
    u32 b2 = (v >>  8) & 0xff;
    u32 b3 =  v        & 0xff;

    // s[x] via s_te0 (byte 1 in BE position = s[x])
    u32 sb0 = (s_te0[b0] >> 16) & 0xff;
    u32 sb1 = (s_te0[b1] >> 16) & 0xff;
    u32 sb2 = (s_te0[b2] >> 16) & 0xff;
    u32 sb3 = (s_te0[b3] >> 16) & 0xff;

    ks[i] = s_td0[sb0] ^ s_td1[sb1] ^ s_td2[sb2] ^ s_td3[sb3];
  }

  // -- Load IV and ciphertext (BE form already, no swap)
  u32 iv[4];
  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[2];
  iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[3];

  u32 ct1[4];
  ct1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0];
  ct1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1];
  ct1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[2];
  ct1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[3];

  u32 ct2[4];
  ct2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[4];
  ct2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[5];
  ct2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[6];
  ct2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[7];

  // ========================================================================
  // AES-256 inverse cipher (decrypt) for block 1
  // ========================================================================
  u32 s0, s1, s2, s3, t0, t1, t2, t3;

  // Initial: state = ct XOR ks[56..59] (last encrypt round key)
  s0 = ct1[0] ^ ks[56];
  s1 = ct1[1] ^ ks[57];
  s2 = ct1[2] ^ ks[58];
  s3 = ct1[3] ^ ks[59];

  // 13 middle rounds (descending key schedule order)
  for (int r = 13; r >= 1; r--)
  {
    t0 = s_td0[(s0 >> 24) & 0xff] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[r*4 + 0];
    t1 = s_td0[(s1 >> 24) & 0xff] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[r*4 + 1];
    t2 = s_td0[(s2 >> 24) & 0xff] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[r*4 + 2];
    t3 = s_td0[(s3 >> 24) & 0xff] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[r*4 + 3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  // Final round: InvShiftRows + InvSubBytes + AddRoundKey (no InvMixColumns)
  // Use s_td4 for inverse S-box. Extract sinv[x] via low byte of entry to be
  // robust to whether td4 is broadcast or single-byte form.
  u32 pt1[4];
  {
    u32 a0 = s_td4[(s0 >> 24) & 0xff] & 0xff;
    u32 a1 = s_td4[(s3 >> 16) & 0xff] & 0xff;
    u32 a2 = s_td4[(s2 >>  8) & 0xff] & 0xff;
    u32 a3 = s_td4[ s1        & 0xff] & 0xff;
    pt1[0] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[0];

    a0 = s_td4[(s1 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s0 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s3 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s2        & 0xff] & 0xff;
    pt1[1] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[1];

    a0 = s_td4[(s2 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s1 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s0 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s3        & 0xff] & 0xff;
    pt1[2] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[2];

    a0 = s_td4[(s3 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s2 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s1 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s0        & 0xff] & 0xff;
    pt1[3] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[3];
  }

  // CBC: XOR with IV for block 1
  pt1[0] ^= iv[0];
  pt1[1] ^= iv[1];
  pt1[2] ^= iv[2];
  pt1[3] ^= iv[3];

  // ========================================================================
  // AES-256 inverse cipher for block 2
  // ========================================================================
  s0 = ct2[0] ^ ks[56];
  s1 = ct2[1] ^ ks[57];
  s2 = ct2[2] ^ ks[58];
  s3 = ct2[3] ^ ks[59];

  for (int r = 13; r >= 1; r--)
  {
    t0 = s_td0[(s0 >> 24) & 0xff] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[r*4 + 0];
    t1 = s_td0[(s1 >> 24) & 0xff] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[r*4 + 1];
    t2 = s_td0[(s2 >> 24) & 0xff] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[r*4 + 2];
    t3 = s_td0[(s3 >> 24) & 0xff] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[r*4 + 3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  u32 pt2[4];
  {
    u32 a0 = s_td4[(s0 >> 24) & 0xff] & 0xff;
    u32 a1 = s_td4[(s3 >> 16) & 0xff] & 0xff;
    u32 a2 = s_td4[(s2 >>  8) & 0xff] & 0xff;
    u32 a3 = s_td4[ s1        & 0xff] & 0xff;
    pt2[0] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[0];

    a0 = s_td4[(s1 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s0 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s3 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s2        & 0xff] & 0xff;
    pt2[1] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[1];

    a0 = s_td4[(s2 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s1 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s0 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s3        & 0xff] & 0xff;
    pt2[2] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[2];

    a0 = s_td4[(s3 >> 24) & 0xff] & 0xff;
    a1 = s_td4[(s2 >> 16) & 0xff] & 0xff;
    a2 = s_td4[(s1 >>  8) & 0xff] & 0xff;
    a3 = s_td4[ s0        & 0xff] & 0xff;
    pt2[3] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) ^ ks[3];
  }

  // CBC: XOR with previous ciphertext block (ct1) for block 2
  pt2[0] ^= ct1[0];
  pt2[1] ^= ct1[1];
  pt2[2] ^= ct1[2];
  pt2[3] ^= ct1[3];

  // ========================================================================
  // Verification (BE byte order: byte n is at (3 - n%4)*8 of u32)
  // ========================================================================
  // Block 2 PKCS7 check: last byte = pad value (1..16), and pad bytes match
  const u32 pad = pt2[3] & 0xff;  // byte 15 (last byte in BE = low bits)

  u32 ok_pkcs7 = (pad >= 1) & (pad <= 16);

  for (u32 n = 0; n < 16; n++)
  {
    const u32 byte_val = (pt2[n / 4] >> ((3 - (n % 4)) * 8)) & 0xff;
    const u32 should_match = (n >= (16 - pad));
    const u32 matches = (byte_val == pad);
    ok_pkcs7 &= (!should_match) | matches;
  }

  // Block 1 ASCII-printable check: every byte in 0x20..0x7E
  u32 ok_ascii = 1;

  for (u32 n = 0; n < 16; n++)
  {
    const u32 byte_val = (pt1[n / 4] >> ((3 - (n % 4)) * 8)) & 0xff;
    ok_ascii &= (byte_val >= 0x20) & (byte_val <= 0x7E);
  }

  const u32 verified = ok_pkcs7 & ok_ascii;

  // Write magic digest only on verification success
  const u32 r0 = verified ? 0xdeadbeef : 0;
  const u32 r1 = verified ? 0xfeedface : 0;
  const u32 r2 = verified ? 0xcafebabe : 0;
  const u32 r3 = verified ? 0xbaadf00d : 0;

  #define il_pos 0

  #include COMPARE_M
}
