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
#include M2S(INCLUDE_PATH/inc_hash_streebog256.cl)
#include M2S(INCLUDE_PATH/inc_hash_yescrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct gost_yescrypt
{
  u32 flags;
  u32 t;

  // "$gy$<params>$<salt>", the message for the inner GOST HMAC

  u32 setting_buf[64];
  u32 setting_len;

} gost_yescrypt_t;

KERNEL_FQ KERNEL_FA void m36200_init (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  yescrypt_kdf_init (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, &tmps[gid], d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid);
}

KERNEL_FQ KERNEL_FA void m36200_loop (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 bid = get_group_id (0);

  if (bid >= GID_CNT) return;

  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  #ifdef COOP_SBOX_LDS
  LOCAL_VK u32 s_sbox[Swords];
  LOCAL_AS u32 *sbox = s_sbox;
  #else
  GLOBAL_AS u32 *sbox = tmps[bid].S;
  #endif

  #ifdef COOP_X_GLOBAL
  GLOBAL_AS u32 *X = tmps[bid].P;
  #else
  LOCAL_VK u32 s_X[YESCRYPT_STATE_CNT4];
  LOCAL_AS u32 *X = s_X;
  #endif

  yescrypt_smix_loop (X, sbox, &tmps[bid], d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bid, lid, lsz, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m36200_comp (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, gost_yescrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;

  #endif

  if (gid >= GID_CNT) return;

  u32 dk[16];

  yescrypt_kdf_final (&tmps[gid], dk);

  // gost-yescrypt keys an outer GOST HMAC with HMAC (Streebog (password), setting)
  // and runs the yescrypt output through it

  u32 pw_buf[64];

  for (u32 i = 0; i < 64; i++) pw_buf[i] = pws[gid].i[i];

  const u32 pw_len = pws[gid].pw_len;

  streebog256_ctx_t hk_ctx;

  streebog256_init (&hk_ctx, s_sbob_sl64);
  streebog256_update_swap (&hk_ctx, pw_buf, pw_len);
  streebog256_final (&hk_ctx);

  u32 hk[16];

  for (u32 i = 8; i < 16; i++) hk[i] = 0;

  hk[0] = h32_from_64_S (hk_ctx.h[3]);
  hk[1] = l32_from_64_S (hk_ctx.h[3]);
  hk[2] = h32_from_64_S (hk_ctx.h[2]);
  hk[3] = l32_from_64_S (hk_ctx.h[2]);
  hk[4] = h32_from_64_S (hk_ctx.h[1]);
  hk[5] = l32_from_64_S (hk_ctx.h[1]);
  hk[6] = h32_from_64_S (hk_ctx.h[0]);
  hk[7] = l32_from_64_S (hk_ctx.h[0]);

  u32 setting[64];

  for (u32 i = 0; i < 64; i++) setting[i] = esalt_bufs[DIGESTS_OFFSET_HOST].setting_buf[i];

  const u32 setting_len = esalt_bufs[DIGESTS_OFFSET_HOST].setting_len;

  streebog256_hmac_ctx_t inner;

  streebog256_hmac_init (&inner, hk, 32, s_sbob_sl64);
  streebog256_hmac_update_swap (&inner, setting, setting_len);
  streebog256_hmac_final (&inner);

  u32 interm[16];

  for (u32 i = 8; i < 16; i++) interm[i] = 0;

  interm[0] = h32_from_64_S (inner.opad.h[3]);
  interm[1] = l32_from_64_S (inner.opad.h[3]);
  interm[2] = h32_from_64_S (inner.opad.h[2]);
  interm[3] = l32_from_64_S (inner.opad.h[2]);
  interm[4] = h32_from_64_S (inner.opad.h[1]);
  interm[5] = l32_from_64_S (inner.opad.h[1]);
  interm[6] = h32_from_64_S (inner.opad.h[0]);
  interm[7] = l32_from_64_S (inner.opad.h[0]);

  streebog256_hmac_ctx_t outer;

  streebog256_hmac_init (&outer, interm, 32, s_sbob_sl64);
  streebog256_hmac_update_swap (&outer, dk, 32);
  streebog256_hmac_final (&outer);

  const u32 r0 = hc_swap32_S (h32_from_64_S (outer.opad.h[3]));
  const u32 r1 = hc_swap32_S (l32_from_64_S (outer.opad.h[3]));
  const u32 r2 = hc_swap32_S (h32_from_64_S (outer.opad.h[2]));
  const u32 r3 = hc_swap32_S (l32_from_64_S (outer.opad.h[2]));

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
