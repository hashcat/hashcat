/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct gocryptfs
{
  u32 iv[4];
  u32 data[8];
  u32 tag[4];

  u32 hkdf;

} gocryptfs_t;

KERNEL_FQ KERNEL_FA void m37200_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, gocryptfs_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m37200_loop_prepare (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, gocryptfs_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m37200_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, gocryptfs_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m37200_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, gocryptfs_t))
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

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

  // GCM stuff

  u32 ukey[8];

  ukey[0] = hc_swap32_S (out[0]);
  ukey[1] = hc_swap32_S (out[1]);
  ukey[2] = hc_swap32_S (out[2]);
  ukey[3] = hc_swap32_S (out[3]);
  ukey[4] = hc_swap32_S (out[4]);
  ukey[5] = hc_swap32_S (out[5]);
  ukey[6] = hc_swap32_S (out[6]);
  ukey[7] = hc_swap32_S (out[7]);

  // With the HKDF feature flag set, the key that wraps the master key is HKDF-SHA256 over the
  // scrypt output with an empty salt and gocryptfs's file content info string. Without the flag the
  // scrypt output is that key. HKDF with an empty salt means an all zero HMAC key of one block, and
  // a 32 byte output is one HMAC block, so the whole derivation is two HMAC-SHA256 calls.

  const u32 hkdf = esalt_bufs[DIGESTS_OFFSET_HOST].hkdf;

  if (hkdf == 1)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    sha256_hmac_ctx_t ctx;

    sha256_hmac_init_64 (&ctx, w0, w1, w2, w3);

    u32 ikm[16];

    ikm[ 0] = ukey[0];
    ikm[ 1] = ukey[1];
    ikm[ 2] = ukey[2];
    ikm[ 3] = ukey[3];
    ikm[ 4] = ukey[4];
    ikm[ 5] = ukey[5];
    ikm[ 6] = ukey[6];
    ikm[ 7] = ukey[7];
    ikm[ 8] = 0;
    ikm[ 9] = 0;
    ikm[10] = 0;
    ikm[11] = 0;
    ikm[12] = 0;
    ikm[13] = 0;
    ikm[14] = 0;
    ikm[15] = 0;

    sha256_hmac_update (&ctx, ikm, 32);

    sha256_hmac_final (&ctx);

    w0[0] = ctx.opad.h[0];
    w0[1] = ctx.opad.h[1];
    w0[2] = ctx.opad.h[2];
    w0[3] = ctx.opad.h[3];
    w1[0] = ctx.opad.h[4];
    w1[1] = ctx.opad.h[5];
    w1[2] = ctx.opad.h[6];
    w1[3] = ctx.opad.h[7];

    sha256_hmac_init_64 (&ctx, w0, w1, w2, w3);

    // "AES-GCM file content encryption" and the counter byte 0x01, 32 bytes together

    u32 info[16];

    info[ 0] = 0x4145532d;
    info[ 1] = 0x47434d20;
    info[ 2] = 0x66696c65;
    info[ 3] = 0x20636f6e;
    info[ 4] = 0x74656e74;
    info[ 5] = 0x20656e63;
    info[ 6] = 0x72797074;
    info[ 7] = 0x696f6e01;
    info[ 8] = 0;
    info[ 9] = 0;
    info[10] = 0;
    info[11] = 0;
    info[12] = 0;
    info[13] = 0;
    info[14] = 0;
    info[15] = 0;

    sha256_hmac_update (&ctx, info, 32);

    sha256_hmac_final (&ctx);

    ukey[0] = ctx.opad.h[0];
    ukey[1] = ctx.opad.h[1];
    ukey[2] = ctx.opad.h[2];
    ukey[3] = ctx.opad.h[3];
    ukey[4] = ctx.opad.h[4];
    ukey[5] = ctx.opad.h[5];
    ukey[6] = ctx.opad.h[6];
    ukey[7] = ctx.opad.h[7];
  }

  u32 key[60] = { 0 };
  u32 subKey[4] = { 0 };

  AES_GCM_Init (ukey, 256, key, subKey, s_te0, s_te1, s_te2, s_te3, s_te4);

  // the nonce is 16 bytes with the HKDF flag and 12 without it

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[2];
  iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[3];

  const int iv_len = (hkdf == 1) ? 16 : 12;

  u32 J0[4] = { 0 };

  AES_GCM_Prepare_J0 (iv, iv_len, subKey, J0);

  u32 T[4] = { 0 };
  u32 S[4] = { 0 };

  u32 S_len   = 16;

  // the associated data is the 8 byte big endian block number, which is 0 for the master key. Its
  // content adds nothing to GHASH, since a zero block leaves the accumulator at zero, but its
  // length is folded in at the end, so it has to be passed as 8 rather than 0.

  u32 aad_buf[4] = { 0 };
  u32 aad_len = 8;

  AES_GCM_GHASH_GLOBAL (subKey, aad_buf, aad_len, esalt_bufs[DIGESTS_OFFSET_HOST].data, 32, S);

  AES_GCM_GCTR (key, 256, J0, S, S_len, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
