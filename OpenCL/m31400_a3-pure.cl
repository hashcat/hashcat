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

DECLSPEC void aes256_scrt_format_VV (PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32x *w, const u32 pw_len, PRIVATE_AS u32x *h, PRIVATE_AS u32x *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  #if VECT_SIZE == 1
  aes256_scrt_format (aes_ks, w, pw_len, h, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  #endif

  #if VECT_SIZE >= 2
  u32 tmp_w[4];
  u32 tmp_h[8];
  u32 tmp_out[4];

  //s0

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s0;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s0;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s0 = tmp_out[i];

  //s1

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s1;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s1;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s1 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 4

  //s2

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s2;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s2;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s2 = tmp_out[i];

  //s3

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s3;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s3;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s3 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 8

  //s4

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s4;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s4;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s4 = tmp_out[i];

  //s5

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s5;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s5;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s5 = tmp_out[i];

  //s6

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s6;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s6;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s6 = tmp_out[i];

  //s7

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s7;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s7;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s7 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 16

  //s8

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s8;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s8;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s8 = tmp_out[i];

  //s9

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s9;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s9;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s9 = tmp_out[i];

  //sa

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sa;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sa;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sa = tmp_out[i];

  //sb

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sb;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sb;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sb = tmp_out[i];

  //sc

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sc;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sc;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sc = tmp_out[i];

  //sd

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sd;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sd;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sd = tmp_out[i];

  //se

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].se;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].se;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].se = tmp_out[i];

  //sf

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sf;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sf;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sf = tmp_out[i];

  #endif
}

KERNEL_FQ void m31400_mxx (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
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

  u32 ks[60];

  u32x w[64] = {0};

  const u32 pw_len = pws[gid].pw_len;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    sha256_update_vector_swap (&ctx, w, pw_len);

    sha256_final_vector (&ctx);

    u32x out[4] = { 0 };

    aes256_scrt_format_VV (ks, w, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32x r0 = out[DGST_R0];
    const u32x r1 = out[DGST_R1];
    const u32x r2 = out[DGST_R2];
    const u32x r3 = out[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31400_sxx (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
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

  u32 ks[60];

  u32x w[64] = { 0 };

  const u32 pw_len = pws[gid].pw_len;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
  * loop
  */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    sha256_update_vector_swap (&ctx, w, pw_len);

    sha256_final_vector (&ctx);

    u32x out[4] = { 0 };

    aes256_scrt_format_VV (ks, w, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32x r0 = out[DGST_R0];
    const u32x r1 = out[DGST_R1];
    const u32x r2 = out[DGST_R2];
    const u32x r3 = out[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
