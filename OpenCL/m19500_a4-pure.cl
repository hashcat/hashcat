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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

typedef struct devise_hash
{
  u32 salt_buf[64];
  int salt_len;

  u32 site_key_buf[64];
  int site_key_len;

} devise_hash_t;

#if   VECT_SIZE == 1
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (devise_hash_t)

#define PCFG_HASH_SHARED_DECL                                   \
  LOCAL_VK u32 l_bin2asc[256];                                  \
  for (u32 i = lid; i < 256; i += lsz)                          \
  {                                                             \
    const u32 i0 = (i >> 0) & 15;                               \
    const u32 i1 = (i >> 4) & 15;                               \
    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0  \
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8; \
  }                                                             \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->l_bin2asc = l_bin2asc;

typedef struct pcfg_hash_ctx
{
  int salt_len;
  int site_key_len;
  u32 s[64];
  u32 k[64];
  u32 glue[16];
  sha1_ctx_t ctx0;
  LOCAL_AS u32 *l_bin2asc;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const devise_hash_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt_len = esalt_bufs[digest_pos].salt_len;

  hc->site_key_len = esalt_bufs[digest_pos].site_key_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0; i < 64; i++) hc->k[i] = 0;

  hc->glue[0] = 0x2d2d0000;
  hc->glue[1] = 0;
  hc->glue[2] = 0;
  hc->glue[3] = 0;
  hc->glue[4] = 0;
  hc->glue[5] = 0;
  hc->glue[6] = 0;
  hc->glue[7] = 0;
  hc->glue[8] = 0;
  hc->glue[9] = 0;
  hc->glue[10] = 0;
  hc->glue[11] = 0;
  hc->glue[12] = 0;
  hc->glue[13] = 0;
  hc->glue[14] = 0;
  hc->glue[15] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = hc_swap32_S (esalt_bufs[salt_pos].salt_buf[idx]);
  }

  for (int i = 0, idx = 0; i < hc->site_key_len; i += 4, idx += 1)
  {
    hc->k[idx] = hc_swap32_S (esalt_bufs[salt_pos].site_key_buf[idx]);
  }

  sha1_init (&hc->ctx0);

  sha1_update (&hc->ctx0, hc->k, hc->site_key_len);

  sha1_update (&hc->ctx0, hc->glue, 2);

  sha1_update (&hc->ctx0, hc->s, hc->salt_len);

  sha1_update (&hc->ctx0, hc->glue, 2);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  sha1_ctx_t ctx = hc->ctx0;

  sha1_update_swap (&ctx, w, len);
  sha1_update      (&ctx, hc->glue, 2);
  sha1_update      (&ctx, hc->k, hc->site_key_len);

  sha1_final (&ctx);

  for (u32 iter = 0; iter < 9; iter++)
  {
    const u32 a = ctx.h[0];
    const u32 b = ctx.h[1];
    const u32 c = ctx.h[2];
    const u32 d = ctx.h[3];
    const u32 e = ctx.h[4];

    sha1_init (&ctx);

    ctx.w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    ctx.w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    ctx.w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    ctx.w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    ctx.w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    ctx.w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    ctx.w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    ctx.w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    ctx.w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    ctx.w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    ctx.w2[2] = hc->glue[0];

    ctx.len = 40 + 2;

    sha1_update      (&ctx, hc->s, hc->salt_len);
    sha1_update      (&ctx, hc->glue, 2);
    sha1_update_swap (&ctx, w, len);
    sha1_update      (&ctx, hc->glue, 2);
    sha1_update      (&ctx, hc->k, hc->site_key_len);

    sha1_final (&ctx);
  }

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  sha1_ctx_t ctx = hc->ctx0;

  sha1_update_global_swap (&ctx, w, len);
  sha1_update      (&ctx, hc->glue, 2);
  sha1_update      (&ctx, hc->k, hc->site_key_len);

  sha1_final (&ctx);

  for (u32 iter = 0; iter < 9; iter++)
  {
    const u32 a = ctx.h[0];
    const u32 b = ctx.h[1];
    const u32 c = ctx.h[2];
    const u32 d = ctx.h[3];
    const u32 e = ctx.h[4];

    sha1_init (&ctx);

    ctx.w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    ctx.w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    ctx.w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    ctx.w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    ctx.w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    ctx.w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    ctx.w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    ctx.w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    ctx.w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
              | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    ctx.w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
              | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    ctx.w2[2] = hc->glue[0];

    ctx.len = 40 + 2;

    sha1_update      (&ctx, hc->s, hc->salt_len);
    sha1_update      (&ctx, hc->glue, 2);
    sha1_update_global_swap (&ctx, w, len);
    sha1_update      (&ctx, hc->glue, 2);
    sha1_update      (&ctx, hc->k, hc->site_key_len);

    sha1_final (&ctx);
  }

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m19500_mxx
#define PCFG_KERNEL_SXX m19500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
