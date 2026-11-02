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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_pbkdf2.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_openbsd_softraid.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// The 32 byte mask key takes two SHA-1 blocks of PBKDF2 output.

#define SR_CRYPTO_SALTLEN    128
#define SR_CRYPTO_MASKKEYLEN  32
#define SR_CRYPTO_BLOCKS       2

KERNEL_FQ KERNEL_FA void m38800_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_state_t, openbsd_softraid_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 s[64] = { 0 };

  for (u32 i = 0; i < SR_CRYPTO_SALTLEN / 4; i++)
  {
    s[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];
  }

  pbkdf2_sha1_state_t st;

  pbkdf2_sha1_init (&st, w, pw_len, s, SR_CRYPTO_SALTLEN, 0, SR_CRYPTO_BLOCKS);

  tmps[gid] = st;
}

KERNEL_FQ KERNEL_FA void m38800_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_state_t, openbsd_softraid_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  for (u32 i = 0; i < 5; i++) ipad[i] = packv (tmps, ipad, gid, i);
  for (u32 i = 0; i < 5; i++) opad[i] = packv (tmps, opad, gid, i);

  for (u32 b = 0; b < SR_CRYPTO_BLOCKS; b++)
  {
    u32x dgst[5];
    u32x out[5];

    for (u32 i = 0; i < 5; i++) dgst[i] = packv (tmps, dgst, gid, (b * 5) + i);
    for (u32 i = 0; i < 5; i++) out[i]  = packv (tmps, out,  gid, (b * 5) + i);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      pbkdf2_sha1_run_V (ipad, opad, dgst);

      for (u32 i = 0; i < 5; i++) out[i] ^= dgst[i];
    }

    for (u32 i = 0; i < 5; i++)
    {
      unpackv (tmps, dgst, gid, (b * 5) + i, dgst[i]);
      unpackv (tmps, out,  gid, (b * 5) + i, out[i]);
    }
  }
}

KERNEL_FQ KERNEL_FA void m38800_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_state_t, openbsd_softraid_t))
{
  /**
   * base
   */

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

  #endif

  if (gid >= GID_CNT) return;

  /**
   * the mask key
   */

  const pbkdf2_sha1_state_t st = tmps[gid];

  u32 mask_key[SR_CRYPTO_MASKKEYLEN / 4];

  pbkdf2_sha1_comp (&st, mask_key, SR_CRYPTO_MASKKEYLEN);

  /**
   * the check
   */

  u32 chk[5];

  openbsd_softraid_check (mask_key, esalt_bufs[DIGESTS_OFFSET_HOST].masked_keys, chk, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3, s_td4);

  const u32 r0 = chk[DGST_R0];
  const u32 r1 = chk[DGST_R1];
  const u32 r2 = chk[DGST_R2];
  const u32 r3 = chk[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
