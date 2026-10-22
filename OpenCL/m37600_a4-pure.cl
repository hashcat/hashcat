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
#endif

typedef struct digest_md5
{
  u32 salt_buf[64];
  u32 salt_len;

  u32 a1_buf[64];
  u32 a1_len;

  u32 esalt_buf[64];
  u32 esalt_len;

} digest_md5_t;

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
  GLOBAL_AS const digest_md5_t *esalt;

  LOCAL_AS u32 *l_bin2asc;

  md5_ctx_t ctx0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->esalt = &((GLOBAL_AS const digest_md5_t *) esalt_bufs)[digest_pos];

  md5_init (&hc->ctx0);

  md5_update_global (&hc->ctx0, hc->esalt->salt_buf, hc->esalt->salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

// The candidate only ever reaches the first of the 3 MD5 runs, so pcfg_hash_init () leaves the
// context holding the salt and this picks it up from there. HA1 and HA2 are properties of the hash.

DECLSPEC bool pcfg_hash_digest (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS md5_ctx_t *ctx1, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  md5_final (ctx1);

  const u32 a = ctx1->h[0];
  const u32 b = ctx1->h[1];
  const u32 c = ctx1->h[2];
  const u32 d = ctx1->h[3];

  md5_ctx_t ctx2;

  md5_init (&ctx2);

  ctx2.w0[0] = a;
  ctx2.w0[1] = b;
  ctx2.w0[2] = c;
  ctx2.w0[3] = d;
  ctx2.len   = 16;

  md5_update_global (&ctx2, hc->esalt->a1_buf, hc->esalt->a1_len);

  md5_final (&ctx2);

  const u32 e = ctx2.h[0];
  const u32 f = ctx2.h[1];
  const u32 g = ctx2.h[2];
  const u32 h = ctx2.h[3];

  md5_ctx_t ctx;

  md5_init (&ctx);

  ctx.w0[0] = uint_to_hex_lower8 ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((e >>  8) & 255) << 16;
  ctx.w0[1] = uint_to_hex_lower8 ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((e >> 24) & 255) << 16;
  ctx.w0[2] = uint_to_hex_lower8 ((f >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((f >>  8) & 255) << 16;
  ctx.w0[3] = uint_to_hex_lower8 ((f >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((f >> 24) & 255) << 16;
  ctx.w1[0] = uint_to_hex_lower8 ((g >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((g >>  8) & 255) << 16;
  ctx.w1[1] = uint_to_hex_lower8 ((g >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((g >> 24) & 255) << 16;
  ctx.w1[2] = uint_to_hex_lower8 ((h >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((h >>  8) & 255) << 16;
  ctx.w1[3] = uint_to_hex_lower8 ((h >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((h >> 24) & 255) << 16;

  ctx.len = 32;

  md5_update_global (&ctx, hc->esalt->esalt_buf, hc->esalt->esalt_len);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx1 = hc->ctx0;

  md5_update (&ctx1, w, len);

  const bool ok = pcfg_hash_digest (hc, &ctx1, dgst);

  return ok;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx1 = hc->ctx0;

  md5_update_global (&ctx1, w, len);

  const bool ok = pcfg_hash_digest (hc, &ctx1, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m37600_mxx
#define PCFG_KERNEL_SXX m37600_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
