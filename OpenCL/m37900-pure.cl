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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_bestcrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bestcrypt_sha256_tmp
{
  u32 dgst[8];
  u32 out[8];

} bestcrypt_sha256_tmp_t;

typedef struct bestcrypt
{
  u32 slot_buf[64];

} bestcrypt_t;

// the IV sits behind the key block, which is 128 bytes where the key generator hashes to 32

#define BESTCRYPT_IV_OFF (128 / 4)

KERNEL_FQ KERNEL_FA void m37900_init (KERN_ATTR_TMPS_ESALT (bestcrypt_sha256_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // the first hash of the PKCS#12 derivation of RFC 7292 appendix B, over the diversifier, the
  // salt filled to one block and the password filled to whole blocks

  u32 w[64];

  const int len = bestcrypt_kdf_input (w, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, pws[gid].i, pws[gid].pw_len, bestcrypt_v2 (pws[gid].pw_len));

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, w, len);

  sha256_final (&ctx);

  for (int i = 0; i < 8; i++) tmps[gid].dgst[i] = ctx.h[i];
}

KERNEL_FQ KERNEL_FA void m37900_loop_prepare (KERN_ATTR_TMPS_ESALT (bestcrypt_sha256_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // one pass of the derivation leaves 32 bytes of key material, which is the whole key in CBC. XTS
  // takes 64, so it runs a second pass, and this is what starts it.

  if (SALT_REPEAT == 0) return;

  u32 dgst[8];

  for (int i = 0; i < 8; i++) dgst[i] = tmps[gid].dgst[i];

  for (int i = 0; i < 8; i++) tmps[gid].out[i] = dgst[i];

  // B is the digest repeated over a block, plus one. The salt block and the first block of the
  // password block both move on by it before the second pass hashes them again.

  u32 b[16];

  for (int i = 0; i < 8; i++)
  {
    b[i + 0] = dgst[i];
    b[i + 8] = dgst[i];
  }

  bestcrypt_inc512 (b);

  u32 w[64];

  const int len = bestcrypt_kdf_input (w, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, pws[gid].i, pws[gid].pw_len, bestcrypt_v2 (pws[gid].pw_len));

  bestcrypt_add512 (&w[BESTCRYPT_V / 4], b);
  bestcrypt_add512 (&w[(BESTCRYPT_V * 2) / 4], b);

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, w, len);

  sha256_final (&ctx);

  for (int i = 0; i < 8; i++) tmps[gid].dgst[i] = ctx.h[i];
}

KERNEL_FQ KERNEL_FA void m37900_loop (KERN_ATTR_TMPS_ESALT (bestcrypt_sha256_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 dgst[8];

  for (int i = 0; i < 8; i++) dgst[i] = tmps[gid].dgst[i];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    // the remaining rounds hash the 32 byte digest, which pads into a single block

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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
    w3[3] = 32 * 8;

    dgst[0] = SHA256M_A;
    dgst[1] = SHA256M_B;
    dgst[2] = SHA256M_C;
    dgst[3] = SHA256M_D;
    dgst[4] = SHA256M_E;
    dgst[5] = SHA256M_F;
    dgst[6] = SHA256M_G;
    dgst[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, dgst);
  }

  for (int i = 0; i < 8; i++) tmps[gid].dgst[i] = dgst[i];
}

KERNEL_FQ KERNEL_FA void m37900_comp (KERN_ATTR_TMPS_ESALT (bestcrypt_sha256_tmp_t, bestcrypt_t))
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

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  GLOBAL_AS const bestcrypt_t *bestcrypt = &esalt_bufs[digest_cur];

  const u32 mode_id = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];

  // the derived key, whose bytes are the digest in big endian. The cipher helpers below take host
  // byte order, so each word turns around. XTS takes 64 bytes of it, the first pass of the
  // derivation and then the second, while CBC only ever has the one pass.

  u32 key[16];

  if (mode_id == BESTCRYPT_MODE_XTS)
  {
    for (int i = 0; i < 8; i++) key[i + 0] = hc_swap32_S (tmps[gid].out[i]);
    for (int i = 0; i < 8; i++) key[i + 8] = hc_swap32_S (tmps[gid].dgst[i]);
  }
  else
  {
    for (int i = 0; i < 8; i++) key[i + 0] = hc_swap32_S (tmps[gid].dgst[i]);
  }

  u32 pt[BESTCRYPT_BLOCK_LEN / 4];

  bestcrypt_decrypt_block (pt, bestcrypt->slot_buf, BESTCRYPT_IV_OFF, mode_id, key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  // the digest of the first 90 bytes of the key block. The update below cuts the input off there,
  // so the words past it do not take part.

  u32 w[24];

  for (int i = 0; i < 24; i++) w[i] = hc_swap32_S (pt[i]);

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update (&ctx, w, BESTCRYPT_BODY_LEN);

  sha256_final (&ctx);

  // the slot stores that digest, encrypted along with the key data

  for (int i = 0; i < 8; i++)
  {
    if (ctx.h[i] != hc_swap32_S (pt[(BESTCRYPT_DIGEST_OFF / 4) + i])) return;
  }

  const u32 r0 = bestcrypt->slot_buf[0];
  const u32 r1 = bestcrypt->slot_buf[1];
  const u32 r2 = bestcrypt->slot_buf[2];
  const u32 r3 = bestcrypt->slot_buf[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
