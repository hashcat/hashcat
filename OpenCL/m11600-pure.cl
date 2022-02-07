/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

typedef struct seven_zip_tmp
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} seven_zip_tmp_t;

typedef struct
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

DECLSPEC void memcat8c_be (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 len, const u32 append, PRIVATE_AS u32 *digest)
{
  const u32 func_len = len & 63;

  //const u32 mod = func_len & 3;
  const u32 div = func_len / 4;

  u32 tmp0;
  u32 tmp1;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  tmp0 = hc_bytealign_be (0, append, func_len);
  tmp1 = hc_bytealign_be (append, 0, func_len);
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((func_len & 3) * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> ((func_len & 3) * 8));
  #endif

  tmp0 = hc_byte_perm (append, 0, selector);
  tmp1 = hc_byte_perm (0, append, selector);
  #endif

  u32 carry = 0;

  switch (div)
  {
    case  0:  w0[0] |= tmp0;
              w0[1]  = tmp1;
              break;
    case  1:  w0[1] |= tmp0;
              w0[2]  = tmp1;
              break;
    case  2:  w0[2] |= tmp0;
              w0[3]  = tmp1;
              break;
    case  3:  w0[3] |= tmp0;
              w1[0]  = tmp1;
              break;
    case  4:  w1[0] |= tmp0;
              w1[1]  = tmp1;
              break;
    case  5:  w1[1] |= tmp0;
              w1[2]  = tmp1;
              break;
    case  6:  w1[2] |= tmp0;
              w1[3]  = tmp1;
              break;
    case  7:  w1[3] |= tmp0;
              w2[0]  = tmp1;
              break;
    case  8:  w2[0] |= tmp0;
              w2[1]  = tmp1;
              break;
    case  9:  w2[1] |= tmp0;
              w2[2]  = tmp1;
              break;
    case 10:  w2[2] |= tmp0;
              w2[3]  = tmp1;
              break;
    case 11:  w2[3] |= tmp0;
              w3[0]  = tmp1;
              break;
    case 12:  w3[0] |= tmp0;
              w3[1]  = tmp1;
              break;
    case 13:  w3[1] |= tmp0;
              w3[2]  = tmp1;
              break;
    case 14:  w3[2] |= tmp0;
              w3[3]  = tmp1;
              break;
    case 15:  w3[3] |= tmp0;
              carry  = tmp1;
              break;
  }

  const u32 new_len = func_len + 8;

  if (new_len >= 64)
  {
    sha256_transform (w0, w1, w2, w3, digest);

    w0[0] = carry;
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
  }
}

KERNEL_FQ void m11600_init (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * context save
   */

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  tmps[gid].h[0] = ctx.h[0];
  tmps[gid].h[1] = ctx.h[1];
  tmps[gid].h[2] = ctx.h[2];
  tmps[gid].h[3] = ctx.h[3];
  tmps[gid].h[4] = ctx.h[4];
  tmps[gid].h[5] = ctx.h[5];
  tmps[gid].h[6] = ctx.h[6];
  tmps[gid].h[7] = ctx.h[7];

  tmps[gid].w0[0] = ctx.w0[0];
  tmps[gid].w0[1] = ctx.w0[1];
  tmps[gid].w0[2] = ctx.w0[2];
  tmps[gid].w0[3] = ctx.w0[3];
  tmps[gid].w1[0] = ctx.w1[0];
  tmps[gid].w1[1] = ctx.w1[1];
  tmps[gid].w1[2] = ctx.w1[2];
  tmps[gid].w1[3] = ctx.w1[3];
  tmps[gid].w2[0] = ctx.w2[0];
  tmps[gid].w2[1] = ctx.w2[1];
  tmps[gid].w2[2] = ctx.w2[2];
  tmps[gid].w2[3] = ctx.w2[3];
  tmps[gid].w3[0] = ctx.w3[0];
  tmps[gid].w3[1] = ctx.w3[1];
  tmps[gid].w3[2] = ctx.w3[2];
  tmps[gid].w3[3] = ctx.w3[3];

  tmps[gid].len = ctx.len;
}

KERNEL_FQ void m11600_loop (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * context load
   */

  sha256_ctx_t ctx;

  ctx.h[0] = tmps[gid].h[0];
  ctx.h[1] = tmps[gid].h[1];
  ctx.h[2] = tmps[gid].h[2];
  ctx.h[3] = tmps[gid].h[3];
  ctx.h[4] = tmps[gid].h[4];
  ctx.h[5] = tmps[gid].h[5];
  ctx.h[6] = tmps[gid].h[6];
  ctx.h[7] = tmps[gid].h[7];

  ctx.w0[0] = tmps[gid].w0[0];
  ctx.w0[1] = tmps[gid].w0[1];
  ctx.w0[2] = tmps[gid].w0[2];
  ctx.w0[3] = tmps[gid].w0[3];
  ctx.w1[0] = tmps[gid].w1[0];
  ctx.w1[1] = tmps[gid].w1[1];
  ctx.w1[2] = tmps[gid].w1[2];
  ctx.w1[3] = tmps[gid].w1[3];
  ctx.w2[0] = tmps[gid].w2[0];
  ctx.w2[1] = tmps[gid].w2[1];
  ctx.w2[2] = tmps[gid].w2[2];
  ctx.w2[3] = tmps[gid].w2[3];
  ctx.w3[0] = tmps[gid].w3[0];
  ctx.w3[1] = tmps[gid].w3[1];
  ctx.w3[2] = tmps[gid].w3[2];
  ctx.w3[3] = tmps[gid].w3[3];

  ctx.len = tmps[gid].len;

  /**
   * base
   */

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    sha256_update_utf16le_swap (&ctx, w, pw_len);

    memcat8c_be (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.len, hc_swap32_S (j), ctx.h);

    ctx.len += 8;
  }

  /**
   * context save
   */

  tmps[gid].h[0] = ctx.h[0];
  tmps[gid].h[1] = ctx.h[1];
  tmps[gid].h[2] = ctx.h[2];
  tmps[gid].h[3] = ctx.h[3];
  tmps[gid].h[4] = ctx.h[4];
  tmps[gid].h[5] = ctx.h[5];
  tmps[gid].h[6] = ctx.h[6];
  tmps[gid].h[7] = ctx.h[7];

  tmps[gid].w0[0] = ctx.w0[0];
  tmps[gid].w0[1] = ctx.w0[1];
  tmps[gid].w0[2] = ctx.w0[2];
  tmps[gid].w0[3] = ctx.w0[3];
  tmps[gid].w1[0] = ctx.w1[0];
  tmps[gid].w1[1] = ctx.w1[1];
  tmps[gid].w1[2] = ctx.w1[2];
  tmps[gid].w1[3] = ctx.w1[3];
  tmps[gid].w2[0] = ctx.w2[0];
  tmps[gid].w2[1] = ctx.w2[1];
  tmps[gid].w2[2] = ctx.w2[2];
  tmps[gid].w2[3] = ctx.w2[3];
  tmps[gid].w3[0] = ctx.w3[0];
  tmps[gid].w3[1] = ctx.w3[1];
  tmps[gid].w3[2] = ctx.w3[2];
  tmps[gid].w3[3] = ctx.w3[3];

  tmps[gid].len = ctx.len;
}

KERNEL_FQ void m11600_hook23 (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * context load
   */

  u32 h[8];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];
  h[5] = tmps[gid].h[5];
  h[6] = tmps[gid].h[6];
  h[7] = tmps[gid].h[7];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 0x80000000;
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
  w3[3] = tmps[gid].len * 8;

  sha256_transform (w0, w1, w2, w3, h);

  hooks[gid].ukey[0] = hc_swap32_S (h[0]);
  hooks[gid].ukey[1] = hc_swap32_S (h[1]);
  hooks[gid].ukey[2] = hc_swap32_S (h[2]);
  hooks[gid].ukey[3] = hc_swap32_S (h[3]);
  hooks[gid].ukey[4] = hc_swap32_S (h[4]);
  hooks[gid].ukey[5] = hc_swap32_S (h[5]);
  hooks[gid].ukey[6] = hc_swap32_S (h[6]);
  hooks[gid].ukey[7] = hc_swap32_S (h[7]);
}

KERNEL_FQ void m11600_comp (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (hooks[gid].hook_success == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
