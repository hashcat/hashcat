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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

typedef struct md5_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} md5_double_salt_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (md5_double_salt_t)

#define PCFG_HASH_SHARED_DECL                                   \
  LOCAL_VK u32 l_bin2asc[256];                                  \
  for (u32 i = lid; i < 256; i += lsz)                          \
  {                                                             \
    const u32 i0 = (i >> 0) & 15;                               \
    const u32 i1 = (i >> 4) & 15;                               \
    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8  \
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0; \
  }                                                             \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->l_bin2asc = l_bin2asc;

typedef struct pcfg_hash_ctx
{
  sha1_ctx_t ctx00;
  md5_ctx_t ctx11;
  LOCAL_AS u32 *l_bin2asc;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const md5_double_salt_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_init(&hc->ctx00);

  sha1_update_global (&hc->ctx00, esalt_bufs[digest_pos].salt2_buf, esalt_bufs[digest_pos].salt2_len);

  md5_init (&hc->ctx11);

  md5_update_global (&hc->ctx11, esalt_bufs[digest_pos].salt1_buf, esalt_bufs[digest_pos].salt1_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_ctx_t ctx0 = hc->ctx00;

  sha1_update_swap (&ctx0, w, len);

  sha1_final (&ctx0);

  const u32 a = ctx0.h[0];
  const u32 b = ctx0.h[1];
  const u32 c = ctx0.h[2];
  const u32 d = ctx0.h[3];
  const u32 e = ctx0.h[4];

  md5_ctx_t ctx = hc->ctx11;

  w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
  w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
  w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
  w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
  w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
  w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
  w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
  w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
  w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
  w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((e >>  0) & 255) << 16;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_update_64 (&ctx, w0, w1, w2, w3, 40);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_ctx_t ctx0 = hc->ctx00;

  sha1_update_global_swap (&ctx0, w, len);

  sha1_final (&ctx0);

  const u32 a = ctx0.h[0];
  const u32 b = ctx0.h[1];
  const u32 c = ctx0.h[2];
  const u32 d = ctx0.h[3];
  const u32 e = ctx0.h[4];

  md5_ctx_t ctx = hc->ctx11;

  w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
  w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
  w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
  w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
  w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
  w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
  w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
  w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
  w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
        | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
  w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
        | uint_to_hex_lower8 ((e >>  0) & 255) << 16;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_update_64 (&ctx, w0, w1, w2, w3, 40);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m21310_mxx
#define PCFG_KERNEL_SXX m21310_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
