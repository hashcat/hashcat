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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

KERNEL_FQ void m14522_mxx (KERN_ATTR_RULES_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 serpent_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx0;

    sha256_init (&ctx0);

    sha256_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha256_final (&ctx0);

    const u32 k0 = ctx0.h[0];
    const u32 k1 = ctx0.h[1];
    const u32 k2 = ctx0.h[2];
    const u32 k3 = ctx0.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (serpent_key_len > 128)
    {
      k4 = ctx0.h[4];
      k5 = ctx0.h[5];

      if (serpent_key_len > 192)
      {
        k6 = ctx0.h[6];
        k7 = ctx0.h[7];
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

KERNEL_FQ void m14522_sxx (KERN_ATTR_RULES_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 serpent_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

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

    sha256_ctx_t ctx0;

    sha256_init (&ctx0);

    sha256_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha256_final (&ctx0);

    const u32 k0 = ctx0.h[0];
    const u32 k1 = ctx0.h[1];
    const u32 k2 = ctx0.h[2];
    const u32 k3 = ctx0.h[3];

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (serpent_key_len > 128)
    {
      k4 = ctx0.h[4];
      k5 = ctx0.h[5];

      if (serpent_key_len > 192)
      {
        k6 = ctx0.h[6];
        k7 = ctx0.h[7];
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
