/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct zip2
{
  u32 type;
  u32 mode;
  u32 magic;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 compress_length;
  u32 data_len;
  u32 data_buf[2048];
  u32 auth_len;
  u32 auth_buf[4];

} zip2_t;

DECLSPEC void hmac_sha1_run (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *ipad, u32 *opad, u32 *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
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
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m13600_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc_swap32_S (esalt_bufs[digests_offset].salt_buf[0]);
  w0[1] = hc_swap32_S (esalt_bufs[digests_offset].salt_buf[1]);
  w0[2] = hc_swap32_S (esalt_bufs[digests_offset].salt_buf[2]);
  w0[3] = hc_swap32_S (esalt_bufs[digests_offset].salt_buf[3]);
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

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, esalt_bufs[digests_offset].salt_len);

  const u32 mode = esalt_bufs[digests_offset].mode;

  int iter_start;
  int iter_stop;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            break;
  }

  for (int i = iter_stop - 1, j = iter_stop; i >= iter_start; i--, j--)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    w0[0] = j;
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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    const u32 i5 = i * 5;

    tmps[gid].dgst[i5 + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i5 + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i5 + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i5 + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i5 + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i5 + 0] = tmps[gid].dgst[i5 + 0];
    tmps[gid].out[i5 + 1] = tmps[gid].dgst[i5 + 1];
    tmps[gid].out[i5 + 2] = tmps[gid].dgst[i5 + 2];
    tmps[gid].out[i5 + 3] = tmps[gid].dgst[i5 + 3];
    tmps[gid].out[i5 + 4] = tmps[gid].dgst[i5 + 4];
  }
}

KERNEL_FQ void m13600_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 ipad[5];
  u32 opad[5];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];

  const u32 verify_bytes = esalt_bufs[digests_offset].verify_bytes;

  const u32 mode = esalt_bufs[digests_offset].mode;

  int iter_start;
  int iter_stop;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            break;
  }

  for (int i = iter_stop - 1; i >= iter_start; i--)
  {
    const u32 i5 = i * 5;

    u32 dgst[5];
    u32 out[5];

    dgst[0] = tmps[gid].dgst[i5 + 0];
    dgst[1] = tmps[gid].dgst[i5 + 1];
    dgst[2] = tmps[gid].dgst[i5 + 2];
    dgst[3] = tmps[gid].dgst[i5 + 3];
    dgst[4] = tmps[gid].dgst[i5 + 4];

    out[0] = tmps[gid].out[i5 + 0];
    out[1] = tmps[gid].out[i5 + 1];
    out[2] = tmps[gid].out[i5 + 2];
    out[3] = tmps[gid].out[i5 + 3];
    out[4] = tmps[gid].out[i5 + 4];

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
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
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    if (i == iter_stop - 1) // 2 byte optimization check
    {
      if (mode == 1) if ((out[3] >> 16) != verify_bytes) break;
      if (mode == 2) if ((out[2] >> 16) != verify_bytes) break;
      if (mode == 3) if ((out[1] >> 16) != verify_bytes) break;
    }

    tmps[gid].dgst[i5 + 0] = dgst[0];
    tmps[gid].dgst[i5 + 1] = dgst[1];
    tmps[gid].dgst[i5 + 2] = dgst[2];
    tmps[gid].dgst[i5 + 3] = dgst[3];
    tmps[gid].dgst[i5 + 4] = dgst[4];

    tmps[gid].out[i5 + 0] = out[0];
    tmps[gid].out[i5 + 1] = out[1];
    tmps[gid].out[i5 + 2] = out[2];
    tmps[gid].out[i5 + 3] = out[3];
    tmps[gid].out[i5 + 4] = out[4];
  }
}

KERNEL_FQ void m13600_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 mode = esalt_bufs[digests_offset].mode;

  u32 iter_start;
  u32 iter_stop;

  switch (mode)
  {
    case 1: iter_start = 4;
            iter_stop  = 8;
            break;
    case 2: iter_start = 6;
            iter_stop  = 12;
            break;
    case 3: iter_start = 8;
            iter_stop  = 16;
            break;
  }

  u32 key[8] = { 0 };

  for (u32 i = iter_start, j = 0; i < iter_stop; i++, j++)
  {
    key[j] = tmps[gid].out[i];
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = key[0];
  w0[1] = key[1];
  w0[2] = key[2];
  w0[3] = key[3];
  w1[0] = key[4];
  w1[1] = key[5];
  w1[2] = key[6];
  w1[3] = key[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

  sha1_hmac_update_global_swap (&ctx, esalt_bufs[digests_offset].data_buf, esalt_bufs[digests_offset].data_len);

  sha1_hmac_final (&ctx);

  const u32 r0 = hc_swap32_S (ctx.opad.h[0] & 0xffffffff);
  const u32 r1 = hc_swap32_S (ctx.opad.h[1] & 0xffffffff);
  const u32 r2 = hc_swap32_S (ctx.opad.h[2] & 0xffff0000);
  const u32 r3 = hc_swap32_S (ctx.opad.h[3] & 0x00000000);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
