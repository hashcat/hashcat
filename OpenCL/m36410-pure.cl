/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#endif

typedef struct kwallet_legacy_tmp
{
  u32 dgst[4][5];

  u32 nblocks;
  u32 pw_len;

} kwallet_legacy_tmp_t;

typedef struct kwallet
{
  u32 ct[16];
  u32 ct_len;

} kwallet_t;

// see m36400-pure.cl, the plausibility test is identical for both wallet versions

DECLSPEC int kwallet_verify_plain (PRIVATE_AS const u32 *pt, const u32 fsize, const u32 ct_len)
{
  if (fsize > (ct_len - 12)) return 0;

  const u32 lim = (fsize < 52) ? fsize : 52;

  u32 n = 0;

  for (u32 i = 0; i < lim; i++)
  {
    const u32 b = (pt[i >> 2] >> (24 - ((i & 3) << 3))) & 0xff;

    if (b == 0) n++;
  }

  return (n >= 12);
}

/**
 * The pre 4.13 KDF hashes the password in 16 byte chunks, each chunk 2000 times, and
 * then glues the chunk digests together into a 20, 40 or 56 byte Blowfish key. The
 * last chunk is special: it takes everything that is left instead of just 16 byte.
 */

KERNEL_FQ KERNEL_FA void m36410_init (KERN_ATTR_TMPS_ESALT (kwallet_legacy_tmp_t, kwallet_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 nblocks = 1;

  if (pw_len > 16) nblocks = 2;
  if (pw_len > 32) nblocks = 3;
  if (pw_len > 48) nblocks = 4;

  for (u32 k = 0; k < 4; k++)
  {
    u32 h[5];

    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;

    if (k < nblocks)
    {
      const u32 off = k * 16;
      const u32 left = pw_len - off;

      // the last chunk takes the whole rest of the password, the others 16 byte

      const int len = (int) (((k == 3) || (left < 16)) ? left : 16);

      sha1_ctx_t ctx;

      sha1_init (&ctx);

      sha1_update_global_swap (&ctx, pws[gid].i + (k * 4), len);

      sha1_final (&ctx);

      h[0] = ctx.h[0];
      h[1] = ctx.h[1];
      h[2] = ctx.h[2];
      h[3] = ctx.h[3];
      h[4] = ctx.h[4];
    }

    tmps[gid].dgst[k][0] = h[0];
    tmps[gid].dgst[k][1] = h[1];
    tmps[gid].dgst[k][2] = h[2];
    tmps[gid].dgst[k][3] = h[3];
    tmps[gid].dgst[k][4] = h[4];
  }

  tmps[gid].nblocks = nblocks;
  tmps[gid].pw_len  = pw_len;
}

KERNEL_FQ KERNEL_FA void m36410_loop (KERN_ATTR_TMPS_ESALT (kwallet_legacy_tmp_t, kwallet_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 nblocks = tmps[gid].nblocks;

  for (u32 k = 0; k < nblocks; k++)
  {
    u32 h[5];

    h[0] = tmps[gid].dgst[k][0];
    h[1] = tmps[gid].dgst[k][1];
    h[2] = tmps[gid].dgst[k][2];
    h[3] = tmps[gid].dgst[k][3];
    h[4] = tmps[gid].dgst[k][4];

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = h[0];
      w0[1] = h[1];
      w0[2] = h[2];
      w0[3] = h[3];
      w1[0] = h[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 20 * 8;

      h[0] = SHA1M_A;
      h[1] = SHA1M_B;
      h[2] = SHA1M_C;
      h[3] = SHA1M_D;
      h[4] = SHA1M_E;

      sha1_transform (w0, w1, w2, w3, h);
    }

    tmps[gid].dgst[k][0] = h[0];
    tmps[gid].dgst[k][1] = h[1];
    tmps[gid].dgst[k][2] = h[2];
    tmps[gid].dgst[k][3] = h[3];
    tmps[gid].dgst[k][4] = h[4];
  }
}

KERNEL_FQ KERNEL_FA FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE_COMP) void m36410_comp (KERN_ATTR_TMPS_ESALT (kwallet_legacy_tmp_t, kwallet_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = tmps[gid].pw_len;

  u32 b0[5];
  u32 b1[5];
  u32 b2[5];
  u32 b3[5];

  for (u32 i = 0; i < 5; i++)
  {
    b0[i] = tmps[gid].dgst[0][i];
    b1[i] = tmps[gid].dgst[1][i];
    b2[i] = tmps[gid].dgst[2][i];
    b3[i] = tmps[gid].dgst[3][i];
  }

  /**
   * key layout, straight out of KWallet's password2hash()
   */

  u32 E[14];

  for (u32 i = 0; i < 14; i++) E[i] = 0;

  u32 E_dim_size;

  if (pw_len <= 16)
  {
    // 20 byte key

    E[0] = b0[0];
    E[1] = b0[1];
    E[2] = b0[2];
    E[3] = b0[3];
    E[4] = b0[4];

    E_dim_size = 5;
  }
  else if (pw_len <= 32)
  {
    // 40 byte key, 20/20

    E[0] = b0[0];
    E[1] = b0[1];
    E[2] = b0[2];
    E[3] = b0[3];
    E[4] = b0[4];
    E[5] = b1[0];
    E[6] = b1[1];
    E[7] = b1[2];
    E[8] = b1[3];
    E[9] = b1[4];

    E_dim_size = 10;
  }
  else if (pw_len <= 48)
  {
    // 56 byte key, 20/20/16

    E[ 0] = b0[0];
    E[ 1] = b0[1];
    E[ 2] = b0[2];
    E[ 3] = b0[3];
    E[ 4] = b0[4];
    E[ 5] = b1[0];
    E[ 6] = b1[1];
    E[ 7] = b1[2];
    E[ 8] = b1[3];
    E[ 9] = b1[4];
    E[10] = b2[0];
    E[11] = b2[1];
    E[12] = b2[2];
    E[13] = b2[3];

    E_dim_size = 14;
  }
  else
  {
    // 56 byte key, 14/14/14/14 - the only case that is not word aligned

    E[ 0] = b0[0];
    E[ 1] = b0[1];
    E[ 2] = b0[2];
    E[ 3] = (b0[3] & 0xffff0000) | (b1[0] >> 16);
    E[ 4] = (b1[0] <<        16) | (b1[1] >> 16);
    E[ 5] = (b1[1] <<        16) | (b1[2] >> 16);
    E[ 6] = (b1[2] <<        16) | (b1[3] >> 16);
    E[ 7] = b2[0];
    E[ 8] = b2[1];
    E[ 9] = b2[2];
    E[10] = (b2[3] & 0xffff0000) | (b3[0] >> 16);
    E[11] = (b3[0] <<        16) | (b3[1] >> 16);
    E[12] = (b3[1] <<        16) | (b3[2] >> 16);
    E[13] = (b3[2] <<        16) | (b3[3] >> 16);

    E_dim_size = 14;
  }

  /**
   * blowfish setkey
   */

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE_COMP][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  u32 P[18];

  blowfish_set_key (E, E_dim_size, P, S0, S1, S2, S3);

  GLOBAL_AS const kwallet_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  /**
   * ECB over byte 8..63 of the byte swapped header, the first block is skipped
   */

  u32 pt[14];

  for (int j = 2; j < 16; j += 2)
  {
    u32 d0 = hc_swap32_S (es->ct[j + 0]);
    u32 d1 = hc_swap32_S (es->ct[j + 1]);

    BF_DECRYPT (d0, d1);

    pt[j - 2] = d0;
    pt[j - 1] = d1;
  }

  const u32 fsize = hc_swap32_S (pt[0]);

  if (kwallet_verify_plain (pt + 1, fsize, es->ct_len))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
