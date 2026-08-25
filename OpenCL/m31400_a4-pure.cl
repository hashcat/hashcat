/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
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

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (scrtv2_t)

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_te0[256];             \
  LOCAL_VK u32 s_te1[256];             \
  LOCAL_VK u32 s_te2[256];             \
  LOCAL_VK u32 s_te3[256];             \
  LOCAL_VK u32 s_te4[256];             \
  for (u32 i = lid; i < 256; i += lsz) \
  {                                    \
    s_te0[i] = te0[i];                 \
    s_te1[i] = te1[i];                 \
    s_te2[i] = te2[i];                 \
    s_te3[i] = te3[i];                 \
    s_te4[i] = te4[i];                 \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_te0 = s_te0;            \
  (hc)->s_te1 = s_te1;            \
  (hc)->s_te2 = s_te2;            \
  (hc)->s_te3 = s_te3;            \
  (hc)->s_te4 = s_te4;
#endif

typedef struct pcfg_hash_ctx
{
  u32 unused;
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_te0;
  LOCAL_AS u32 *s_te1;
  LOCAL_AS u32 *s_te2;
  LOCAL_AS u32 *s_te3;
  LOCAL_AS u32 *s_te4;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const scrtv2_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_te0 = hc->s_te0;
  LOCAL_AS u32 *s_te1 = hc->s_te1;
  LOCAL_AS u32 *s_te2 = hc->s_te2;
  LOCAL_AS u32 *s_te3 = hc->s_te3;
  LOCAL_AS u32 *s_te4 = hc->s_te4;
  #else
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;
  #endif

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_swap (&ctx, w, len);

  sha256_final (&ctx);

  u32 out[4] = { 0 };

  u32 ks[60];

  aes256_scrt_format (ks, w, len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  dgst[0] = out[DGST_R0];
  dgst[1] = out[DGST_R1];
  dgst[2] = out[DGST_R2];
  dgst[3] = out[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m31400_mxx
#define PCFG_KERNEL_SXX m31400_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
