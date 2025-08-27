/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#ifndef ARGON2_PARALLELISM
#define ARGON2_PARALLELISM 0
#endif

#define LUKS_STRIPES    (                                   4000)
#define LUKS_CT_LEN     (                                    512)
#define LUKS_AF_MAX_LEN (HC_LUKS_KEY_SIZE_512 / 8 * LUKS_STRIPES)

typedef enum hc_luks_hash_type
{
  HC_LUKS_HASH_TYPE_SHA1      = 1,
  HC_LUKS_HASH_TYPE_SHA256    = 2,
  HC_LUKS_HASH_TYPE_SHA512    = 3,
  HC_LUKS_HASH_TYPE_RIPEMD160 = 4,
  HC_LUKS_HASH_TYPE_WHIRLPOOL = 5,
  HC_LUKS_HASH_TYPE_ARGON2    = 6,

} hc_luks_hash_type_t;

typedef enum hc_luks_key_size
{
  HC_LUKS_KEY_SIZE_128 = 128,
  HC_LUKS_KEY_SIZE_256 = 256,
  HC_LUKS_KEY_SIZE_512 = 512,

} hc_luks_key_size_t;

typedef enum hc_luks_cipher_type
{
  HC_LUKS_CIPHER_TYPE_AES     = 1,
  HC_LUKS_CIPHER_TYPE_SERPENT = 2,
  HC_LUKS_CIPHER_TYPE_TWOFISH = 3,

} hc_luks_cipher_type_t;

typedef enum hc_luks_cipher_mode
{
  HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256 = 1,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN        = 2,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN64      = 3,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN        = 4,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN64      = 5,

} hc_luks_cipher_mode_t;

typedef struct luks
{
  int hash_type;   // hc_luks_hash_type_t
  int key_size;    // hc_luks_key_size_t
  int cipher_type; // hc_luks_cipher_type_t
  int cipher_mode; // hc_luks_cipher_mode_t

  u32 ct_buf[LUKS_CT_LEN / 4];

  u32 af_buf[LUKS_AF_MAX_LEN / 4];
  u32 af_len;

} luks_t;

typedef struct luks_tmp
{
  u32 ipad32[8];
  u64 ipad64[8];

  u32 opad32[8];
  u64 opad64[8];

  u32 dgst32[32];
  u64 dgst64[16];

  u32 out32[32];
  u64 out64[16];

} luks_tmp_t;

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_luks_af.cl)
#include M2S(INCLUDE_PATH/inc_luks_essiv.cl)
#include M2S(INCLUDE_PATH/inc_luks_xts.cl)
#include M2S(INCLUDE_PATH/inc_luks_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define MAX_ENTROPY 7.0

typedef struct merged_options
{
  argon2_options_t argon2_options;

  luks_t luks;

} merged_options_t;

#define MAX_ENTROPY 7.0

KERNEL_FQ KERNEL_FA void m34100_init (KERN_ATTR_TMPS_ESALT (luks_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  argon2_init_gg (&pws[gid], &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m34100_loop (KERN_ATTR_TMPS_ESALT (luks_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #if ARGON2_PARALLELISM > 0
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #if ARGON2_PARALLELISM > 0
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < argon2_options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m34100_comp (KERN_ATTR_TMPS_ESALT (luks_tmp_t, merged_options_t))
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

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  u32 out[16];

  argon2_final (argon2_block, &argon2_options, out);

  for (u32 i = 0; i < 16; i++) tmps[gid].out32[i] = hc_swap32_S (out[i]);

  // decrypt AF with argon2 result
  // merge AF to masterkey
  // decrypt first payload sector with masterkey

  u32 pt_buf[128];

  luks_af_sha256_then_aes_decrypt (&esalt_bufs[DIGESTS_OFFSET_HOST].luks, &tmps[gid], pt_buf, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  // check entropy

  const float entropy = hc_get_entropy (pt_buf, 128);

  if (entropy < MAX_ENTROPY)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
