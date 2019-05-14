/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_sha512.cl"
#include "inc_hash_ripemd160.cl"
#include "inc_cipher_twofish.cl"
#endif

#define LUKS_STRIPES 4000

typedef enum hc_luks_hash_type
{
  HC_LUKS_HASH_TYPE_SHA1      = 1,
  HC_LUKS_HASH_TYPE_SHA256    = 2,
  HC_LUKS_HASH_TYPE_SHA512    = 3,
  HC_LUKS_HASH_TYPE_RIPEMD160 = 4,
  HC_LUKS_HASH_TYPE_WHIRLPOOL = 5,

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
  HC_LUKS_CIPHER_MODE_CBC_ESSIV = 1,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN = 2,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN = 3,

} hc_luks_cipher_mode_t;

typedef struct luks
{
  int hash_type;    // hc_luks_hash_type_t
  int key_size;     // hc_luks_key_size_t
  int cipher_type;  // hc_luks_cipher_type_t
  int cipher_mode;  // hc_luks_cipher_mode_t

  u32 ct_buf[128];

  u32 af_src_buf[((HC_LUKS_KEY_SIZE_512 / 8) * LUKS_STRIPES) / 4];

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
#include "inc_luks_af.cl"
#include "inc_luks_essiv.cl"
#include "inc_luks_xts.cl"
#include "inc_luks_twofish.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define MAX_ENTROPY 7.0

DECLSPEC void hmac_ripemd160_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  ripemd160_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 20) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  ripemd160_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m14643_init (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  ripemd160_hmac_ctx_t ripemd160_hmac_ctx;

  ripemd160_hmac_init_global (&ripemd160_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad32[0] = ripemd160_hmac_ctx.ipad.h[0];
  tmps[gid].ipad32[1] = ripemd160_hmac_ctx.ipad.h[1];
  tmps[gid].ipad32[2] = ripemd160_hmac_ctx.ipad.h[2];
  tmps[gid].ipad32[3] = ripemd160_hmac_ctx.ipad.h[3];
  tmps[gid].ipad32[4] = ripemd160_hmac_ctx.ipad.h[4];

  tmps[gid].opad32[0] = ripemd160_hmac_ctx.opad.h[0];
  tmps[gid].opad32[1] = ripemd160_hmac_ctx.opad.h[1];
  tmps[gid].opad32[2] = ripemd160_hmac_ctx.opad.h[2];
  tmps[gid].opad32[3] = ripemd160_hmac_ctx.opad.h[3];
  tmps[gid].opad32[4] = ripemd160_hmac_ctx.opad.h[4];

  ripemd160_hmac_update_global (&ripemd160_hmac_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  const u32 key_size = esalt_bufs[digests_offset].key_size;

  for (u32 i = 0, j = 1; i < ((key_size / 8) / 4); i += 5, j += 1)
  {
    ripemd160_hmac_ctx_t ripemd160_hmac_ctx2 = ripemd160_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j << 24;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    ripemd160_hmac_update_64 (&ripemd160_hmac_ctx2, w0, w1, w2, w3, 4);

    ripemd160_hmac_final (&ripemd160_hmac_ctx2);

    tmps[gid].dgst32[i + 0] = ripemd160_hmac_ctx2.opad.h[0];
    tmps[gid].dgst32[i + 1] = ripemd160_hmac_ctx2.opad.h[1];
    tmps[gid].dgst32[i + 2] = ripemd160_hmac_ctx2.opad.h[2];
    tmps[gid].dgst32[i + 3] = ripemd160_hmac_ctx2.opad.h[3];
    tmps[gid].dgst32[i + 4] = ripemd160_hmac_ctx2.opad.h[4];

    tmps[gid].out32[i + 0] = tmps[gid].dgst32[i + 0];
    tmps[gid].out32[i + 1] = tmps[gid].dgst32[i + 1];
    tmps[gid].out32[i + 2] = tmps[gid].dgst32[i + 2];
    tmps[gid].out32[i + 3] = tmps[gid].dgst32[i + 3];
    tmps[gid].out32[i + 4] = tmps[gid].dgst32[i + 4];
  }
}

KERNEL_FQ void m14643_loop (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad32, gid, 0);
  ipad[1] = packv (tmps, ipad32, gid, 1);
  ipad[2] = packv (tmps, ipad32, gid, 2);
  ipad[3] = packv (tmps, ipad32, gid, 3);
  ipad[4] = packv (tmps, ipad32, gid, 4);

  opad[0] = packv (tmps, opad32, gid, 0);
  opad[1] = packv (tmps, opad32, gid, 1);
  opad[2] = packv (tmps, opad32, gid, 2);
  opad[3] = packv (tmps, opad32, gid, 3);
  opad[4] = packv (tmps, opad32, gid, 4);

  u32 key_size = esalt_bufs[digests_offset].key_size;

  for (u32 i = 0; i < ((key_size / 8) / 4); i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst32, gid, i + 0);
    dgst[1] = packv (tmps, dgst32, gid, i + 1);
    dgst[2] = packv (tmps, dgst32, gid, i + 2);
    dgst[3] = packv (tmps, dgst32, gid, i + 3);
    dgst[4] = packv (tmps, dgst32, gid, i + 4);

    out[0] = packv (tmps, out32, gid, i + 0);
    out[1] = packv (tmps, out32, gid, i + 1);
    out[2] = packv (tmps, out32, gid, i + 2);
    out[3] = packv (tmps, out32, gid, i + 3);
    out[4] = packv (tmps, out32, gid, i + 4);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = (64 + 20) * 8;
      w3[3] = 0;

      hmac_ripemd160_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst32, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst32, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst32, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst32, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst32, gid, i + 4, dgst[4]);

    unpackv (tmps, out32, gid, i + 0, out[0]);
    unpackv (tmps, out32, gid, i + 1, out[1]);
    unpackv (tmps, out32, gid, i + 2, out[2]);
    unpackv (tmps, out32, gid, i + 3, out[3]);
    unpackv (tmps, out32, gid, i + 4, out[4]);
  }
}

KERNEL_FQ void m14643_comp (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // decrypt AF with first pbkdf2 result
  // merge AF to masterkey
  // decrypt first payload sector with masterkey

  u32 pt_buf[128];

  luks_af_ripemd160_then_twofish_decrypt (&esalt_bufs[digests_offset], &tmps[gid], pt_buf);

  // check entropy

  const float entropy = hc_get_entropy (pt_buf, 128);

  if (entropy < MAX_ENTROPY)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }
}
