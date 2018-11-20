/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_sha1.cl"
#include "inc_cipher_aes.cl"

__kernel void m13200_init (KERN_ATTR_TMPS (axcrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * KEK
   */

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha1_final (&ctx);

  u32 KEK[5];

  KEK[0] = ctx.h[0];
  KEK[1] = ctx.h[1];
  KEK[2] = ctx.h[2];
  KEK[3] = ctx.h[3];
  KEK[4] = ctx.h[4];

  /* hash XOR salt is KEK, used as key for AES wrapping routine */
  tmps[gid].KEK[0] = KEK[0] ^ salt_bufs[salt_pos].salt_buf[0];
  tmps[gid].KEK[1] = KEK[1] ^ salt_bufs[salt_pos].salt_buf[1];
  tmps[gid].KEK[2] = KEK[2] ^ salt_bufs[salt_pos].salt_buf[2];
  tmps[gid].KEK[3] = KEK[3] ^ salt_bufs[salt_pos].salt_buf[3];

  /**
   *  salt_buf[0..3] is salt
   *  salt_buf[4..9] is wrapped_key
   */

  /* set lsb */
  tmps[gid].lsb[0] = salt_bufs[salt_pos].salt_buf[6];
  tmps[gid].lsb[1] = salt_bufs[salt_pos].salt_buf[7];
  tmps[gid].lsb[2] = salt_bufs[salt_pos].salt_buf[8];
  tmps[gid].lsb[3] = salt_bufs[salt_pos].salt_buf[9];

  /* set msb */
  tmps[gid].cipher[0] = salt_bufs[salt_pos].salt_buf[4];
  tmps[gid].cipher[1] = salt_bufs[salt_pos].salt_buf[5];
  tmps[gid].cipher[2] = 0;
  tmps[gid].cipher[3] = 0;
}

__kernel void m13200_loop (KERN_ATTR_TMPS (axcrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  u32 ukey[4];

  ukey[0] = tmps[gid].KEK[0];
  ukey[1] = tmps[gid].KEK[1];
  ukey[2] = tmps[gid].KEK[2];
  ukey[3] = tmps[gid].KEK[3];

  u32 lsb[4];

  lsb[0] = tmps[gid].lsb[0];
  lsb[1] = tmps[gid].lsb[1];
  lsb[2] = tmps[gid].lsb[2];
  lsb[3] = tmps[gid].lsb[3];

  u32 cipher[4];

  cipher[0] = tmps[gid].cipher[0];
  cipher[1] = tmps[gid].cipher[1];
  cipher[2] = tmps[gid].cipher[2];
  cipher[3] = tmps[gid].cipher[3];

  /**
   * aes init
   */

  #define KEYLEN 44

  u32 ks[KEYLEN];

  /**
   * aes decrypt key
   */

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  const u32 wrapping_rounds = salt_bufs[salt_pos].salt_iter - 1;

  /* custom AES un-wrapping loop */
  for (u32 i = 0, j = wrapping_rounds - loop_pos; i < loop_cnt; i++, j--)
  {
    const u32 j2 = j * 2;

    cipher[0] ^= swap32_S (j2 + 2);

    /* R[i] */
    cipher[2] = lsb[2];
    cipher[3] = lsb[3];

    /* AES_ECB(KEK, (MSB XOR (NUMBER_AES_BLOCKS * j + i)) | R[i]) */

    AES128_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[2] = cipher[2];
    lsb[3] = cipher[3];

    /* 2nd block treatment */
    cipher[0] ^= swap32_S (j2 + 1);

    cipher[2] = lsb[0];
    cipher[3] = lsb[1];

    AES128_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[0] = cipher[2];
    lsb[1] = cipher[3];
  }

  tmps[gid].lsb[0] = lsb[0];
  tmps[gid].lsb[1] = lsb[1];
  tmps[gid].lsb[2] = lsb[2];
  tmps[gid].lsb[3] = lsb[3];

  tmps[gid].cipher[0] = cipher[0];
  tmps[gid].cipher[1] = cipher[1];
  tmps[gid].cipher[2] = cipher[2];
  tmps[gid].cipher[3] = cipher[3];
}

__kernel void m13200_comp (KERN_ATTR_TMPS (axcrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  #define il_pos 0

  if (tmps[gid].cipher[0] == 0xa6a6a6a6 && tmps[gid].cipher[1] == 0xa6a6a6a6)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
    }
  }
}
