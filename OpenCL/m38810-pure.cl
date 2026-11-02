/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#include M2S(INCLUDE_PATH/inc_bcrypt_pbkdf.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_openbsd_softraid.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// A 32 byte key is a single bcrypt_pbkdf block with a stride of 1, so the block counter is always
// 1 and the output bytes are the key bytes in order.

#define SR_CRYPTO_SALTLEN 128

// must stay identical to the copy in src/modules/module_38810.c
typedef struct openbsd_softraid_bcrypt_tmp
{
  u32 pass_hash[16];
  u32 sha2salt[16];
  u32 out[8];

} openbsd_softraid_bcrypt_tmp_t;

KERNEL_FQ KERNEL_FA void m38810_init (KERN_ATTR_TMPS_ESALT (openbsd_softraid_bcrypt_tmp_t, openbsd_softraid_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);
  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha512_final (&ctx);

  u32 pass_hash[16];

  sha512_digest_to_words (ctx.h, pass_hash);

  for (u32 i = 0; i < 16; i++)
  {
    tmps[gid].pass_hash[i] = pass_hash[i];
  }

  // the salt, then the block counter as a big endian u32. sha512_update () reads 32 words
  // regardless of len.

  u32 w[32] = { 0 };

  w[0] = 1;

  sha512_ctx_t ctx_salt;

  sha512_init (&ctx_salt);
  sha512_update_global_swap (&ctx_salt, salt_bufs[SALT_POS_HOST].salt_buf, SR_CRYPTO_SALTLEN);
  sha512_update (&ctx_salt, w, 4);
  sha512_final (&ctx_salt);

  u32 sha2salt[16];

  sha512_digest_to_words (ctx_salt.h, sha2salt);

  for (u32 i = 0; i < 16; i++)
  {
    tmps[gid].sha2salt[i] = sha2salt[i];
  }

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].out[i] = 0;
  }
}

KERNEL_FQ KERNEL_FA void m38810_loop (KERN_ATTR_TMPS_ESALT (openbsd_softraid_bcrypt_tmp_t, openbsd_softraid_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  // on CUDA the S-boxes exceed the 48 KB static limit, same as m03200
  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  if (gid >= GID_CNT) return;

  u32 sha2pass[16];
  u32 sha2salt[16];

  for (u32 i = 0; i < 16; i++)
  {
    sha2pass[i] = tmps[gid].pass_hash[i];
    sha2salt[i] = tmps[gid].sha2salt[i];
  }

  u32 out[8];

  for (u32 i = 0; i < 8; i++)
  {
    out[i] = tmps[gid].out[i];
  }

  // a bcrypt_hash () cannot be split, so this runs LOOP_CNT whole rounds. Every salt after the
  // first is the SHA-512 of the round before, which is what lets the loop stop at any round.

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    u32 tmp[8];

    bcrypt_hash (sha2pass, sha2salt, tmp, S0, S1, S2, S3);

    for (u32 j = 0; j < 8; j++)
    {
      out[j] ^= tmp[j];
    }

    u32 wt[32] = { 0 };

    for (u32 j = 0; j < 8; j++)
    {
      wt[j] = tmp[j];
    }

    sha512_ctx_t ctx;

    sha512_init   (&ctx);
    sha512_update (&ctx, wt, 32);
    sha512_final  (&ctx);

    sha512_digest_to_words (ctx.h, sha2salt);
  }

  for (u32 i = 0; i < 16; i++)
  {
    tmps[gid].sha2salt[i] = sha2salt[i];
  }

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].out[i] = out[i];
  }
}

KERNEL_FQ KERNEL_FA void m38810_comp (KERN_ATTR_TMPS_ESALT (openbsd_softraid_bcrypt_tmp_t, openbsd_softraid_t))
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

  // bcrypt_hash () leaves its output with the first byte in the top of each word, and the AES key
  // schedule reads the first byte from the bottom

  u32 mask_key[8];

  for (u32 i = 0; i < 8; i++)
  {
    mask_key[i] = hc_swap32_S (tmps[gid].out[i]);
  }

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
