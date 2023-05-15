/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.h)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.h)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct scrtv2
{
  u32 ct_buf[64];
  int ct_len;

} scrtv2_t;

DECLSPEC void shift_buffer_by_offset (PRIVATE_AS u32 *w0, const u32 offset)
{
  const int offset_switch = offset / 4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  switch (offset_switch)
  {
    case 0:
      w0[3] = hc_bytealign_be_S (w0[2], w0[3], offset);
      w0[2] = hc_bytealign_be_S (w0[1], w0[2], offset);
      w0[1] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[0] = hc_bytealign_be_S (    0, w0[0], offset);
      break;

    case 1:
      w0[3] = hc_bytealign_be_S (w0[1], w0[2], offset);
      w0[2] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[1] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[0] = 0;
      break;

    case 2:
      w0[3] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[2] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w0[3] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    default:
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S(0x0706050403020100UL >> ((offset & 3) * 8));
  #endif

  switch (offset_switch)
  {
    case 0:
      w0[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[0] = hc_byte_perm_S (w0[0],     0, selector);
      break;

    case 1:
      w0[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[1] = hc_byte_perm_S (w0[0],     0, selector);
      w0[0] = 0;
      break;

    case 2:
      w0[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[2] = hc_byte_perm_S (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w0[3] = hc_byte_perm_S (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    default:
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif
}

DECLSPEC void aes256_scrt_format (PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32 *pw, const u32 pw_len, PRIVATE_AS u32 *hash, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  AES256_set_encrypt_key (aes_ks, hash, s_te0, s_te1, s_te2, s_te3);

  shift_buffer_by_offset (hash, pw_len + 4);

  hash[0]  = hc_swap32_S (pw_len);
  hash[1] |= hc_swap32_S (pw[0]);
  hash[2] |= hc_swap32_S (pw[1]);
  hash[3] |= hc_swap32_S (pw[2]);

  AES256_encrypt (aes_ks, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}

KERNEL_FQ void m31400_mxx (KERN_ATTR_ESALT (scrtv2_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 wt[3];

  u32 ks[60];

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    wt[0] = hc_swap32_S (ctx.w0[0]);
    wt[1] = hc_swap32_S (ctx.w0[1]);
    wt[2] = hc_swap32_S (ctx.w0[2]);

    u32 pw_len = ctx.len;

    sha256_final (&ctx);

    u32 out[4] = { 0 };

    aes256_scrt_format (ks, wt, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = out[DGST_R0];
    const u32 r1 = out[DGST_R1];
    const u32 r2 = out[DGST_R2];
    const u32 r3 = out[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31400_sxx (KERN_ATTR_ESALT (scrtv2_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

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

  u32 wt[3];

  u32 ks[60];

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    wt[0] = hc_swap32_S (ctx.w0[0]);
    wt[1] = hc_swap32_S (ctx.w0[1]);
    wt[2] = hc_swap32_S (ctx.w0[2]);

    u32 pw_len = ctx.len;

    sha256_final (&ctx);

    u32 out[4] = { 0 };

    aes256_scrt_format (ks, wt, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = out[DGST_R0];
    const u32 r1 = out[DGST_R1];
    const u32 r2 = out[DGST_R2];
    const u32 r3 = out[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
