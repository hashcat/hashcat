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
#define uint_to_hex_lower8_be(i) make_u32x (l_bin2asc_be[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#define uint_to_hex_lower8_be(i) make_u32x (l_bin2asc_be[(i).s0], l_bin2asc_be[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#define uint_to_hex_lower8_be(i) make_u32x (l_bin2asc_be[(i).s0], l_bin2asc_be[(i).s1], l_bin2asc_be[(i).s2], l_bin2asc_be[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#define uint_to_hex_lower8_be(i) make_u32x (l_bin2asc_be[(i).s0], l_bin2asc_be[(i).s1], l_bin2asc_be[(i).s2], l_bin2asc_be[(i).s3], l_bin2asc_be[(i).s4], l_bin2asc_be[(i).s5], l_bin2asc_be[(i).s6], l_bin2asc_be[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#define uint_to_hex_lower8_be(i) make_u32x (l_bin2asc_be[(i).s0], l_bin2asc_be[(i).s1], l_bin2asc_be[(i).s2], l_bin2asc_be[(i).s3], l_bin2asc_be[(i).s4], l_bin2asc_be[(i).s5], l_bin2asc_be[(i).s6], l_bin2asc_be[(i).s7], l_bin2asc_be[(i).s8], l_bin2asc_be[(i).s9], l_bin2asc_be[(i).sa], l_bin2asc_be[(i).sb], l_bin2asc_be[(i).sc], l_bin2asc_be[(i).sd], l_bin2asc_be[(i).se], l_bin2asc_be[(i).sf])
#endif

#define PCFG_HASH_SHARED_DECL                                      \
  LOCAL_VK u32 l_bin2asc[256];                                     \
  LOCAL_VK u32 l_bin2asc_be[256];                                  \
  for (u32 i = lid; i < 256; i += lsz)                             \
  {                                                                \
    const u32 i0 = (i >> 0) & 15;                                  \
    const u32 i1 = (i >> 4) & 15;                                  \
    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8     \
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;    \
    l_bin2asc_be[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0  \
                    | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8; \
  }                                                                \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc)    \
  (hc)->l_bin2asc = l_bin2asc;       \
  (hc)->l_bin2asc_be = l_bin2asc_be;

typedef struct pcfg_hash_ctx
{
  LOCAL_AS u32 *l_bin2asc;
  LOCAL_AS u32 *l_bin2asc_be;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;
  LOCAL_AS u32 *l_bin2asc_be = hc->l_bin2asc_be;

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update (&ctx0, w, len);

  md5_final (&ctx0);

  const u32 a = ctx0.h[0];
  const u32 b = ctx0.h[1];
  const u32 c = ctx0.h[2];
  const u32 d = ctx0.h[3];

  md5_ctx_t ctx1;

  md5_init (&ctx1);

  ctx1.w0[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
  ctx1.w0[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
  ctx1.w0[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
  ctx1.w0[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
  ctx1.w1[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
  ctx1.w1[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
  ctx1.w1[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
  ctx1.w1[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
  ctx1.len = 32;

  md5_final (&ctx1);

  const u32 e = ctx1.h[0];
  const u32 f = ctx1.h[1];
  const u32 g = ctx1.h[2];
  const u32 h = ctx1.h[3];

  sha1_ctx_t ctx2;

  sha1_init (&ctx2);

  ctx2.w0[0] = uint_to_hex_lower8_be ((e >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((e >>  8) & 255) <<  0;
  ctx2.w0[1] = uint_to_hex_lower8_be ((e >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((e >> 24) & 255) <<  0;
  ctx2.w0[2] = uint_to_hex_lower8_be ((f >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((f >>  8) & 255) <<  0;
  ctx2.w0[3] = uint_to_hex_lower8_be ((f >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((f >> 24) & 255) <<  0;
  ctx2.w1[0] = uint_to_hex_lower8_be ((g >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((g >>  8) & 255) <<  0;
  ctx2.w1[1] = uint_to_hex_lower8_be ((g >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((g >> 24) & 255) <<  0;
  ctx2.w1[2] = uint_to_hex_lower8_be ((h >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((h >>  8) & 255) <<  0;
  ctx2.w1[3] = uint_to_hex_lower8_be ((h >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((h >> 24) & 255) <<  0;
  ctx2.len = 32;

  sha1_final (&ctx2);

  dgst[0] = ctx2.h[DGST_R0];
  dgst[1] = ctx2.h[DGST_R1];
  dgst[2] = ctx2.h[DGST_R2];
  dgst[3] = ctx2.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;
  LOCAL_AS u32 *l_bin2asc_be = hc->l_bin2asc_be;

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, w, len);

  md5_final (&ctx0);

  const u32 a = ctx0.h[0];
  const u32 b = ctx0.h[1];
  const u32 c = ctx0.h[2];
  const u32 d = ctx0.h[3];

  md5_ctx_t ctx1;

  md5_init (&ctx1);

  ctx1.w0[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
  ctx1.w0[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
  ctx1.w0[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
  ctx1.w0[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
  ctx1.w1[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
  ctx1.w1[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
  ctx1.w1[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
             | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
  ctx1.w1[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
             | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
  ctx1.len = 32;

  md5_final (&ctx1);

  const u32 e = ctx1.h[0];
  const u32 f = ctx1.h[1];
  const u32 g = ctx1.h[2];
  const u32 h = ctx1.h[3];

  sha1_ctx_t ctx2;

  sha1_init (&ctx2);

  ctx2.w0[0] = uint_to_hex_lower8_be ((e >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((e >>  8) & 255) <<  0;
  ctx2.w0[1] = uint_to_hex_lower8_be ((e >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((e >> 24) & 255) <<  0;
  ctx2.w0[2] = uint_to_hex_lower8_be ((f >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((f >>  8) & 255) <<  0;
  ctx2.w0[3] = uint_to_hex_lower8_be ((f >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((f >> 24) & 255) <<  0;
  ctx2.w1[0] = uint_to_hex_lower8_be ((g >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((g >>  8) & 255) <<  0;
  ctx2.w1[1] = uint_to_hex_lower8_be ((g >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((g >> 24) & 255) <<  0;
  ctx2.w1[2] = uint_to_hex_lower8_be ((h >>  0) & 255) << 16
             | uint_to_hex_lower8_be ((h >>  8) & 255) <<  0;
  ctx2.w1[3] = uint_to_hex_lower8_be ((h >> 16) & 255) << 16
             | uint_to_hex_lower8_be ((h >> 24) & 255) <<  0;
  ctx2.len = 32;

  sha1_final (&ctx2);

  dgst[0] = ctx2.h[DGST_R0];
  dgst[1] = ctx2.h[DGST_R1];
  dgst[2] = ctx2.h[DGST_R2];
  dgst[3] = ctx2.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m18500_mxx
#define PCFG_KERNEL_SXX m18500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
