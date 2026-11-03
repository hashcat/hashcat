/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_bestcrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bestcrypt_whirlpool_tmp
{
  u32 dgst[16];

} bestcrypt_whirlpool_tmp_t;

typedef struct bestcrypt
{
  u32 slot_buf[64];

} bestcrypt_t;

// the IV sits behind the key block, which is 160 bytes where the key generator hashes to 64

#define BESTCRYPT_IV_OFF (160 / 4)

KERNEL_FQ KERNEL_FA void m37903_init (KERN_ATTR_TMPS_ESALT (bestcrypt_whirlpool_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  // the first hash of the PKCS#12 derivation of RFC 7292 appendix B, over the diversifier, the
  // salt filled to one block and the password filled to one block. Whirlpool reaches 64 bytes of
  // key material in one go, so there is only ever this one block of output.

  u32 w[48];

  const int len = bestcrypt_kdf_input (w, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, pws[gid].i, pws[gid].pw_len, BESTCRYPT_V);

  whirlpool_ctx_t ctx;

  whirlpool_init (&ctx, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update (&ctx, w, len);

  whirlpool_final (&ctx);

  for (int i = 0; i < 16; i++) tmps[gid].dgst[i] = ctx.h[i];
}

KERNEL_FQ KERNEL_FA void m37903_loop (KERN_ATTR_TMPS_ESALT (bestcrypt_whirlpool_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  u32 dgst[16];

  for (int i = 0; i < 16; i++) dgst[i] = tmps[gid].dgst[i];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    // the remaining rounds hash the 64 byte digest, which fills one block and pads into a second

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = dgst[ 0];
    w0[1] = dgst[ 1];
    w0[2] = dgst[ 2];
    w0[3] = dgst[ 3];
    w1[0] = dgst[ 4];
    w1[1] = dgst[ 5];
    w1[2] = dgst[ 6];
    w1[3] = dgst[ 7];
    w2[0] = dgst[ 8];
    w2[1] = dgst[ 9];
    w2[2] = dgst[10];
    w2[3] = dgst[11];
    w3[0] = dgst[12];
    w3[1] = dgst[13];
    w3[2] = dgst[14];
    w3[3] = dgst[15];

    for (int i = 0; i < 16; i++) dgst[i] = 0;

    whirlpool_transform (w0, w1, w2, w3, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

    w0[0] = 0x80000000;
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
    w3[3] = 64 * 8;

    whirlpool_transform (w0, w1, w2, w3, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
  }

  for (int i = 0; i < 16; i++) tmps[gid].dgst[i] = dgst[i];
}

KERNEL_FQ KERNEL_FA void m37903_comp (KERN_ATTR_TMPS_ESALT (bestcrypt_whirlpool_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool and aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

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
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];

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

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

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

  for (int i = 0; i < 16; i++) key[i] = hc_swap32_S (tmps[gid].dgst[i]);

  u32 pt[BESTCRYPT_BLOCK_LEN / 4];

  bestcrypt_decrypt_block (pt, bestcrypt->slot_buf, BESTCRYPT_IV_OFF, salt_bufs[SALT_POS_HOST].salt_buf_pc[0], key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  // the digest of the first 90 bytes of the key block. The update below cuts the input off there,
  // so the words past it do not take part.

  u32 w[24];

  for (int i = 0; i < 24; i++) w[i] = hc_swap32_S (pt[i]);

  whirlpool_ctx_t ctx;

  whirlpool_init (&ctx, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update (&ctx, w, BESTCRYPT_BODY_LEN);

  whirlpool_final (&ctx);

  // the slot stores the first 32 bytes of it, encrypted along with the key data

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
