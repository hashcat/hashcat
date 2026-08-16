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
#include M2S(INCLUDE_PATH/inc_hash_yescrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

KERNEL_FQ KERNEL_FA void m36100_init (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  yescrypt_kdf_init (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, &tmps[gid], d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid);
}

KERNEL_FQ KERNEL_FA void m36100_loop (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
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

KERNEL_FQ KERNEL_FA void m36100_comp (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 dk[16];

  yescrypt_kdf_final (&tmps[gid], dk);

  const u32 r0 = dk[0];
  const u32 r1 = dk[1];
  const u32 r2 = dk[2];
  const u32 r3 = dk[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
