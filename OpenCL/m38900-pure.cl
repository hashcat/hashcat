/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

/*
Pseudocode (google/fscrypt protector, crypto/crypto.go):
1. argon2id(password, salt, t, m, p) = wrapping_key (32 bytes)
2. hkdf-sha256(wrapping_key): prk = hmac(zero[32], wrapping_key); enc_key = T(1), auth_key = T(2)
3. hmac_sha256(key=auth_key, data=iv||encrypted_key) = tag
4. compare tag to the stored hmac
*/

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

typedef struct fscrypt
{
  u32 iv[4];
  u32 encrypted_key[8];

} fscrypt_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;

  fscrypt_t fscrypt;

} merged_options_t;

KERNEL_FQ KERNEL_FA void m38900_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
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

KERNEL_FQ KERNEL_FA void m38900_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
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
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  const u32 lanes = argon2_lane_limit (argon2_options.parallelism, lsz);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < lanes; pos.lane += lsz)
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

KERNEL_FQ KERNEL_FA void m38900_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
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

  GLOBAL_AS const fscrypt_t *fscrypt = &esalt_bufs[DIGESTS_OFFSET_HOST].fscrypt;

  u32 out[8];

  argon2_final (argon2_block, &argon2_options, out);

  // wrapping key as a big-endian byte stream

  u32 wk[16] = { 0 };

  wk[0] = hc_swap32_S (out[0]);
  wk[1] = hc_swap32_S (out[1]);
  wk[2] = hc_swap32_S (out[2]);
  wk[3] = hc_swap32_S (out[3]);
  wk[4] = hc_swap32_S (out[4]);
  wk[5] = hc_swap32_S (out[5]);
  wk[6] = hc_swap32_S (out[6]);
  wk[7] = hc_swap32_S (out[7]);

  // HKDF-SHA256 extract: prk = HMAC(zero[32], wrapping_key)

  u32 zero[16] = { 0 };

  sha256_hmac_ctx_t ctx_prk;
  sha256_hmac_init (&ctx_prk, zero, 32);
  sha256_hmac_update (&ctx_prk, wk, 32);
  sha256_hmac_final (&ctx_prk);

  u32 prk[8];
  prk[0] = ctx_prk.opad.h[0];
  prk[1] = ctx_prk.opad.h[1];
  prk[2] = ctx_prk.opad.h[2];
  prk[3] = ctx_prk.opad.h[3];
  prk[4] = ctx_prk.opad.h[4];
  prk[5] = ctx_prk.opad.h[5];
  prk[6] = ctx_prk.opad.h[6];
  prk[7] = ctx_prk.opad.h[7];

  // HKDF-SHA256 expand: T(1) = HMAC(prk, 0x01) is enc_key (unused for cracking)
  //                     T(2) = HMAC(prk, T(1) || 0x02) is auth_key

  u32 msg[16] = { 0 };
  msg[0] = 0x01000000;

  sha256_hmac_ctx_t ctx_t1;
  sha256_hmac_init (&ctx_t1, prk, 32);
  sha256_hmac_update (&ctx_t1, msg, 1);
  sha256_hmac_final (&ctx_t1);

  u32 t2[16] = { 0 };
  t2[0] = ctx_t1.opad.h[0];
  t2[1] = ctx_t1.opad.h[1];
  t2[2] = ctx_t1.opad.h[2];
  t2[3] = ctx_t1.opad.h[3];
  t2[4] = ctx_t1.opad.h[4];
  t2[5] = ctx_t1.opad.h[5];
  t2[6] = ctx_t1.opad.h[6];
  t2[7] = ctx_t1.opad.h[7];
  t2[8] = 0x02000000;

  sha256_hmac_ctx_t ctx_t2;
  sha256_hmac_init (&ctx_t2, prk, 32);
  sha256_hmac_update (&ctx_t2, t2, 33);
  sha256_hmac_final (&ctx_t2);

  u32 auth_key[8];
  auth_key[0] = ctx_t2.opad.h[0];
  auth_key[1] = ctx_t2.opad.h[1];
  auth_key[2] = ctx_t2.opad.h[2];
  auth_key[3] = ctx_t2.opad.h[3];
  auth_key[4] = ctx_t2.opad.h[4];
  auth_key[5] = ctx_t2.opad.h[5];
  auth_key[6] = ctx_t2.opad.h[6];
  auth_key[7] = ctx_t2.opad.h[7];

  // tag = HMAC(auth_key, iv || encrypted_key)

  u32 data[16] = { 0 };
  data[ 0] = hc_swap32_S (fscrypt->iv[0]);
  data[ 1] = hc_swap32_S (fscrypt->iv[1]);
  data[ 2] = hc_swap32_S (fscrypt->iv[2]);
  data[ 3] = hc_swap32_S (fscrypt->iv[3]);
  data[ 4] = hc_swap32_S (fscrypt->encrypted_key[0]);
  data[ 5] = hc_swap32_S (fscrypt->encrypted_key[1]);
  data[ 6] = hc_swap32_S (fscrypt->encrypted_key[2]);
  data[ 7] = hc_swap32_S (fscrypt->encrypted_key[3]);
  data[ 8] = hc_swap32_S (fscrypt->encrypted_key[4]);
  data[ 9] = hc_swap32_S (fscrypt->encrypted_key[5]);
  data[10] = hc_swap32_S (fscrypt->encrypted_key[6]);
  data[11] = hc_swap32_S (fscrypt->encrypted_key[7]);

  sha256_hmac_ctx_t ctx_tag;
  sha256_hmac_init (&ctx_tag, auth_key, 32);
  sha256_hmac_update (&ctx_tag, data, 48);
  sha256_hmac_final (&ctx_tag);

  const u32 r0 = hc_swap32_S (ctx_tag.opad.h[0]);
  const u32 r1 = hc_swap32_S (ctx_tag.opad.h[1]);
  const u32 r2 = hc_swap32_S (ctx_tag.opad.h[2]);
  const u32 r3 = hc_swap32_S (ctx_tag.opad.h[3]);

  #define il_pos 0

  #include COMPARE_M
}
