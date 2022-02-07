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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

KERNEL_FQ void m14552_mxx (KERN_ATTR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * whirlpool shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  /**
   * base
   */

  u32 serpent_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    whirlpool_ctx_t ctx = ctx0;

    whirlpool_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    whirlpool_final (&ctx);

    const u32 k0 = ctx.h[0];
    const u32 k1 = ctx.h[1];
    const u32 k2 = ctx.h[2];
    const u32 k3 = ctx.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (serpent_key_len > 128)
    {
      k4 = ctx.h[4];
      k5 = ctx.h[5];

      if (serpent_key_len > 192)
      {
        k6 = ctx.h[6];
        k7 = ctx.h[7];
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = hc_swap32_S (k0);
    ukey[1] = hc_swap32_S (k1);
    ukey[2] = hc_swap32_S (k2);
    ukey[3] = hc_swap32_S (k3);

    if (serpent_key_len > 128)
    {
      ukey[4] = hc_swap32_S (k4);
      ukey[5] = hc_swap32_S (k5);

      if (serpent_key_len > 192)
      {
        ukey[6] = hc_swap32_S (k6);
        ukey[7] = hc_swap32_S (k7);
      }
    }

    // IV

    const u32 iv[4] = {
      salt_bufs[SALT_POS_HOST].salt_buf[0],
      salt_bufs[SALT_POS_HOST].salt_buf[1],
      salt_bufs[SALT_POS_HOST].salt_buf[2],
      salt_bufs[SALT_POS_HOST].salt_buf[3]
    };

    // CT

    u32 CT[4] = { 0 };

    // serpent

    u32 ks[140] = { 0 };

    if (serpent_key_len == 128)
    {
      serpent128_set_key (ks, ukey);

      serpent128_encrypt (ks, iv, CT);
    }
    else if (serpent_key_len == 192)
    {
      serpent192_set_key (ks, ukey);

      serpent192_encrypt (ks, iv, CT);
    }
    else
    {
      serpent256_set_key (ks, ukey);

      serpent256_encrypt (ks, iv, CT);
    }

    const u32 r0 = hc_swap32_S (CT[0]);
    const u32 r1 = hc_swap32_S (CT[1]);
    const u32 r2 = hc_swap32_S (CT[2]);
    const u32 r3 = hc_swap32_S (CT[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m14552_sxx (KERN_ATTR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * whirlpool shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  u32 serpent_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

  whirlpool_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    whirlpool_ctx_t ctx = ctx0;

    whirlpool_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    whirlpool_final (&ctx);

    const u32 k0 = ctx.h[0];
    const u32 k1 = ctx.h[1];
    const u32 k2 = ctx.h[2];
    const u32 k3 = ctx.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (serpent_key_len > 128)
    {
      k4 = ctx.h[4];
      k5 = ctx.h[5];

      if (serpent_key_len > 192)
      {
        k6 = ctx.h[6];
        k7 = ctx.h[7];
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = hc_swap32_S (k0);
    ukey[1] = hc_swap32_S (k1);
    ukey[2] = hc_swap32_S (k2);
    ukey[3] = hc_swap32_S (k3);

    if (serpent_key_len > 128)
    {
      ukey[4] = hc_swap32_S (k4);
      ukey[5] = hc_swap32_S (k5);

      if (serpent_key_len > 192)
      {
        ukey[6] = hc_swap32_S (k6);
        ukey[7] = hc_swap32_S (k7);
      }
    }

    // IV

    const u32 iv[4] = {
      salt_bufs[SALT_POS_HOST].salt_buf[0],
      salt_bufs[SALT_POS_HOST].salt_buf[1],
      salt_bufs[SALT_POS_HOST].salt_buf[2],
      salt_bufs[SALT_POS_HOST].salt_buf[3]
    };

    // CT

    u32 CT[4] = { 0 };

    // serpent

    u32 ks[140] = { 0 };

    if (serpent_key_len == 128)
    {
      serpent128_set_key (ks, ukey);

      serpent128_encrypt (ks, iv, CT);
    }
    else if (serpent_key_len == 192)
    {
      serpent192_set_key (ks, ukey);

      serpent192_encrypt (ks, iv, CT);
    }
    else
    {
      serpent256_set_key (ks, ukey);

      serpent256_encrypt (ks, iv, CT);
    }

    const u32 r0 = hc_swap32_S (CT[0]);
    const u32 r1 = hc_swap32_S (CT[1]);
    const u32 r2 = hc_swap32_S (CT[2]);
    const u32 r3 = hc_swap32_S (CT[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
