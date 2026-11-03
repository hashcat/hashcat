/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_bestcrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bestcrypt_sha512_tmp
{
  u64 dgst[8];

} bestcrypt_sha512_tmp_t;

typedef struct bestcrypt
{
  u32 slot_buf[64];

} bestcrypt_t;

// the IV sits behind the key block, which is 160 bytes where the key generator hashes to 64

#define BESTCRYPT_IV_OFF (160 / 4)

KERNEL_FQ KERNEL_FA void m37902_init (KERN_ATTR_TMPS_ESALT (bestcrypt_sha512_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // the first hash of the PKCS#12 derivation of RFC 7292 appendix B, over the diversifier, the
  // salt filled to one block and the password filled to one block. SHA-512 reaches 64 bytes of
  // key material in one go, so there is only ever this one block of output.

  u32 w[48];

  const int len = bestcrypt_kdf_input (w, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, pws[gid].i, pws[gid].pw_len, BESTCRYPT_V);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update (&ctx, w, len);

  sha512_final (&ctx);

  for (int i = 0; i < 8; i++) tmps[gid].dgst[i] = ctx.h[i];
}

KERNEL_FQ KERNEL_FA void m37902_loop (KERN_ATTR_TMPS_ESALT (bestcrypt_sha512_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u64 dgst[8];

  for (int i = 0; i < 8; i++) dgst[i] = tmps[gid].dgst[i];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    // the remaining rounds hash the 64 byte digest, which pads into a single block

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    w0[0] = h32_from_64_S (dgst[0]);
    w0[1] = l32_from_64_S (dgst[0]);
    w0[2] = h32_from_64_S (dgst[1]);
    w0[3] = l32_from_64_S (dgst[1]);
    w1[0] = h32_from_64_S (dgst[2]);
    w1[1] = l32_from_64_S (dgst[2]);
    w1[2] = h32_from_64_S (dgst[3]);
    w1[3] = l32_from_64_S (dgst[3]);
    w2[0] = h32_from_64_S (dgst[4]);
    w2[1] = l32_from_64_S (dgst[4]);
    w2[2] = h32_from_64_S (dgst[5]);
    w2[3] = l32_from_64_S (dgst[5]);
    w3[0] = h32_from_64_S (dgst[6]);
    w3[1] = l32_from_64_S (dgst[6]);
    w3[2] = h32_from_64_S (dgst[7]);
    w3[3] = l32_from_64_S (dgst[7]);
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
    w7[3] = 64 * 8;

    dgst[0] = SHA512M_A;
    dgst[1] = SHA512M_B;
    dgst[2] = SHA512M_C;
    dgst[3] = SHA512M_D;
    dgst[4] = SHA512M_E;
    dgst[5] = SHA512M_F;
    dgst[6] = SHA512M_G;
    dgst[7] = SHA512M_H;

    sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, dgst);
  }

  for (int i = 0; i < 8; i++) tmps[gid].dgst[i] = dgst[i];
}

KERNEL_FQ KERNEL_FA void m37902_comp (KERN_ATTR_TMPS_ESALT (bestcrypt_sha512_tmp_t, bestcrypt_t))
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

  // the derived key, whose bytes are the digest in big endian. The cipher helpers below take host
  // byte order, so each word turns around.

  u32 key[16];

  key[ 0] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[0]));
  key[ 1] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[0]));
  key[ 2] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[1]));
  key[ 3] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[1]));
  key[ 4] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[2]));
  key[ 5] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[2]));
  key[ 6] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[3]));
  key[ 7] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[3]));
  key[ 8] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[4]));
  key[ 9] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[4]));
  key[10] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[5]));
  key[11] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[5]));
  key[12] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[6]));
  key[13] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[6]));
  key[14] = hc_swap32_S (h32_from_64_S (tmps[gid].dgst[7]));
  key[15] = hc_swap32_S (l32_from_64_S (tmps[gid].dgst[7]));

  u32 pt[BESTCRYPT_BLOCK_LEN / 4];

  bestcrypt_decrypt_block (pt, bestcrypt->slot_buf, BESTCRYPT_IV_OFF, salt_bufs[SALT_POS_HOST].salt_buf_pc[0], key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  // the digest of the first 90 bytes of the key block. The update below cuts the input off there,
  // so the words past it do not take part.

  u32 w[24];

  for (int i = 0; i < 24; i++) w[i] = hc_swap32_S (pt[i]);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update (&ctx, w, BESTCRYPT_BODY_LEN);

  sha512_final (&ctx);

  // the slot stores the first 32 bytes of it, encrypted along with the key data

  u32 stored[8];

  for (int i = 0; i < 8; i++) stored[i] = hc_swap32_S (pt[(BESTCRYPT_DIGEST_OFF / 4) + i]);

  if (h32_from_64_S (ctx.h[0]) != stored[0]) return;
  if (l32_from_64_S (ctx.h[0]) != stored[1]) return;
  if (h32_from_64_S (ctx.h[1]) != stored[2]) return;
  if (l32_from_64_S (ctx.h[1]) != stored[3]) return;
  if (h32_from_64_S (ctx.h[2]) != stored[4]) return;
  if (l32_from_64_S (ctx.h[2]) != stored[5]) return;
  if (h32_from_64_S (ctx.h[3]) != stored[6]) return;
  if (l32_from_64_S (ctx.h[3]) != stored[7]) return;

  const u32 r0 = bestcrypt->slot_buf[0];
  const u32 r1 = bestcrypt->slot_buf[1];
  const u32 r2 = bestcrypt->slot_buf[2];
  const u32 r3 = bestcrypt->slot_buf[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
