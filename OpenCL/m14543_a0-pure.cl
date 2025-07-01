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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

KERNEL_FQ KERNEL_FA void m14543_mxx (KERN_ATTR_RULES_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 twofish_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 w[64] = { 0 };

    u32 w_len = tmp.pw_len;

    for (u32 i = 0; i < 64; i++) w[i] = tmp.i[i];

    ripemd160_ctx_t ctx0;

    ripemd160_init (&ctx0);

    ripemd160_update (&ctx0, tmp.i, tmp.pw_len);

    ripemd160_final (&ctx0);

    const u32 k0 = ctx0.h[0];
    const u32 k1 = ctx0.h[1];
    const u32 k2 = ctx0.h[2];
    const u32 k3 = ctx0.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (twofish_key_len > 128)
    {
      k4 = ctx0.h[4];

      ripemd160_ctx_t ctx;

      ripemd160_init (&ctx);

      ctx.w0[0] = 0x00000041;

      ctx.len = 1;

      ripemd160_update (&ctx, w, w_len);

      ripemd160_final (&ctx);

      k5 = ctx.h[0];

      if (twofish_key_len > 192)
      {
        k6 = ctx.h[1];
        k7 = ctx.h[2];
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (twofish_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (twofish_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
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

    // twofish

    u32 sk1[4] = { 0 };
    u32 lk1[40] = { 0 };

    if (twofish_key_len == 128)
    {
      twofish128_set_key (sk1, lk1, ukey);

      twofish128_encrypt (sk1, lk1, iv, CT);
    }
    else if (twofish_key_len == 192)
    {
      twofish192_set_key (sk1, lk1, ukey);

      twofish192_encrypt (sk1, lk1, iv, CT);
    }
    else
    {
      twofish256_set_key (sk1, lk1, ukey);

      twofish256_encrypt (sk1, lk1, iv, CT);
    }

    const u32 r0 = hc_swap32_S (CT[0]);
    const u32 r1 = hc_swap32_S (CT[1]);
    const u32 r2 = hc_swap32_S (CT[2]);
    const u32 r3 = hc_swap32_S (CT[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m14543_sxx (KERN_ATTR_RULES_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 twofish_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 w[64] = { 0 };

    u32 w_len = tmp.pw_len;

    for (u32 i = 0; i < 64; i++) w[i] = tmp.i[i];

    ripemd160_ctx_t ctx0;

    ripemd160_init (&ctx0);

    ripemd160_update (&ctx0, tmp.i, tmp.pw_len);

    ripemd160_final (&ctx0);

    const u32 k0 = ctx0.h[0];
    const u32 k1 = ctx0.h[1];
    const u32 k2 = ctx0.h[2];
    const u32 k3 = ctx0.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (twofish_key_len > 128)
    {
      k4 = ctx0.h[4];

      ripemd160_ctx_t ctx;

      ripemd160_init (&ctx);

      ctx.w0[0] = 0x00000041;

      ctx.len = 1;

      ripemd160_update (&ctx, w, w_len);

      ripemd160_final (&ctx);

      k5 = ctx.h[0];

      if (twofish_key_len > 192)
      {
        k6 = ctx.h[1];
        k7 = ctx.h[2];
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (twofish_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (twofish_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
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

    // twofish setkey and encrypt

    u32 sk1[4] = { 0 };
    u32 lk1[40] = { 0 };

    if (twofish_key_len == 128)
    {
      twofish128_set_key (sk1, lk1, ukey);

      twofish128_encrypt (sk1, lk1, iv, CT);
    }
    else if (twofish_key_len == 192)
    {
      twofish192_set_key (sk1, lk1, ukey);

      twofish192_encrypt (sk1, lk1, iv, CT);
    }
    else
    {
      twofish256_set_key (sk1, lk1, ukey);

      twofish256_encrypt (sk1, lk1, iv, CT);
    }

    const u32 r0 = hc_swap32_S (CT[0]);
    const u32 r1 = hc_swap32_S (CT[1]);
    const u32 r2 = hc_swap32_S (CT[2]);
    const u32 r3 = hc_swap32_S (CT[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
