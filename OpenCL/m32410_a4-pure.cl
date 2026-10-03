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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
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

#define PCFG_HASH_BLKWORDS  32

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
  u32 salt_len;
  u32 s[64];
  LOCAL_AS u32 *l_bin2asc;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }
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
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  const u64 a = ctx0.h[0];
  const u64 b = ctx0.h[1];
  const u64 c = ctx0.h[2];
  const u64 d = ctx0.h[3];
  const u64 e = ctx0.h[4];
  const u64 f = ctx0.h[5];
  const u64 g = ctx0.h[6];
  const u64 h = ctx0.h[7];

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  w0[0] = uint_to_hex_lower8 ((a >> 56) & 255) << 16
        | uint_to_hex_lower8 ((a >> 48) & 255) <<  0;
  w0[1] = uint_to_hex_lower8 ((a >> 40) & 255) << 16
        | uint_to_hex_lower8 ((a >> 32) & 255) <<  0;
  w0[2] = uint_to_hex_lower8 ((a >> 24) & 255) << 16
        | uint_to_hex_lower8 ((a >> 16) & 255) <<  0;
  w0[3] = uint_to_hex_lower8 ((a >>  8) & 255) << 16
        | uint_to_hex_lower8 ((a >>  0) & 255) <<  0;
  w1[0] = uint_to_hex_lower8 ((b >> 56) & 255) << 16
        | uint_to_hex_lower8 ((b >> 48) & 255) <<  0;
  w1[1] = uint_to_hex_lower8 ((b >> 40) & 255) << 16
        | uint_to_hex_lower8 ((b >> 32) & 255) <<  0;
  w1[2] = uint_to_hex_lower8 ((b >> 24) & 255) << 16
        | uint_to_hex_lower8 ((b >> 16) & 255) <<  0;
  w1[3] = uint_to_hex_lower8 ((b >>  8) & 255) << 16
        | uint_to_hex_lower8 ((b >>  0) & 255) <<  0;
  w2[0] = uint_to_hex_lower8 ((c >> 56) & 255) << 16
        | uint_to_hex_lower8 ((c >> 48) & 255) <<  0;
  w2[1] = uint_to_hex_lower8 ((c >> 40) & 255) << 16
        | uint_to_hex_lower8 ((c >> 32) & 255) <<  0;
  w2[2] = uint_to_hex_lower8 ((c >> 24) & 255) << 16
        | uint_to_hex_lower8 ((c >> 16) & 255) <<  0;
  w2[3] = uint_to_hex_lower8 ((c >>  8) & 255) << 16
        | uint_to_hex_lower8 ((c >>  0) & 255) <<  0;
  w3[0] = uint_to_hex_lower8 ((d >> 56) & 255) << 16
        | uint_to_hex_lower8 ((d >> 48) & 255) <<  0;
  w3[1] = uint_to_hex_lower8 ((d >> 40) & 255) << 16
        | uint_to_hex_lower8 ((d >> 32) & 255) <<  0;
  w3[2] = uint_to_hex_lower8 ((d >> 24) & 255) << 16
        | uint_to_hex_lower8 ((d >> 16) & 255) <<  0;
  w3[3] = uint_to_hex_lower8 ((d >>  8) & 255) << 16
        | uint_to_hex_lower8 ((d >>  0) & 255) <<  0;
  w4[0] = uint_to_hex_lower8 ((e >> 56) & 255) << 16
        | uint_to_hex_lower8 ((e >> 48) & 255) <<  0;
  w4[1] = uint_to_hex_lower8 ((e >> 40) & 255) << 16
        | uint_to_hex_lower8 ((e >> 32) & 255) <<  0;
  w4[2] = uint_to_hex_lower8 ((e >> 24) & 255) << 16
        | uint_to_hex_lower8 ((e >> 16) & 255) <<  0;
  w4[3] = uint_to_hex_lower8 ((e >>  8) & 255) << 16
        | uint_to_hex_lower8 ((e >>  0) & 255) <<  0;
  w5[0] = uint_to_hex_lower8 ((f >> 56) & 255) << 16
        | uint_to_hex_lower8 ((f >> 48) & 255) <<  0;
  w5[1] = uint_to_hex_lower8 ((f >> 40) & 255) << 16
        | uint_to_hex_lower8 ((f >> 32) & 255) <<  0;
  w5[2] = uint_to_hex_lower8 ((f >> 24) & 255) << 16
        | uint_to_hex_lower8 ((f >> 16) & 255) <<  0;
  w5[3] = uint_to_hex_lower8 ((f >>  8) & 255) << 16
        | uint_to_hex_lower8 ((f >>  0) & 255) <<  0;
  w6[0] = uint_to_hex_lower8 ((g >> 56) & 255) << 16
        | uint_to_hex_lower8 ((g >> 48) & 255) <<  0;
  w6[1] = uint_to_hex_lower8 ((g >> 40) & 255) << 16
        | uint_to_hex_lower8 ((g >> 32) & 255) <<  0;
  w6[2] = uint_to_hex_lower8 ((g >> 24) & 255) << 16
        | uint_to_hex_lower8 ((g >> 16) & 255) <<  0;
  w6[3] = uint_to_hex_lower8 ((g >>  8) & 255) << 16
        | uint_to_hex_lower8 ((g >>  0) & 255) <<  0;
  w7[0] = uint_to_hex_lower8 ((h >> 56) & 255) << 16
        | uint_to_hex_lower8 ((h >> 48) & 255) <<  0;
  w7[1] = uint_to_hex_lower8 ((h >> 40) & 255) << 16
        | uint_to_hex_lower8 ((h >> 32) & 255) <<  0;
  w7[2] = uint_to_hex_lower8 ((h >> 24) & 255) << 16
        | uint_to_hex_lower8 ((h >> 16) & 255) <<  0;
  w7[3] = uint_to_hex_lower8 ((h >>  8) & 255) << 16
        | uint_to_hex_lower8 ((h >>  0) & 255) <<  0;

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);

  sha512_update (&ctx, hc->s, hc->salt_len);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_swap (&ctx0, w, len);

  sha512_final (&ctx0);

  const u64 a = ctx0.h[0];
  const u64 b = ctx0.h[1];
  const u64 c = ctx0.h[2];
  const u64 d = ctx0.h[3];
  const u64 e = ctx0.h[4];
  const u64 f = ctx0.h[5];
  const u64 g = ctx0.h[6];
  const u64 h = ctx0.h[7];

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  w0[0] = uint_to_hex_lower8 ((a >> 56) & 255) << 16
        | uint_to_hex_lower8 ((a >> 48) & 255) <<  0;
  w0[1] = uint_to_hex_lower8 ((a >> 40) & 255) << 16
        | uint_to_hex_lower8 ((a >> 32) & 255) <<  0;
  w0[2] = uint_to_hex_lower8 ((a >> 24) & 255) << 16
        | uint_to_hex_lower8 ((a >> 16) & 255) <<  0;
  w0[3] = uint_to_hex_lower8 ((a >>  8) & 255) << 16
        | uint_to_hex_lower8 ((a >>  0) & 255) <<  0;
  w1[0] = uint_to_hex_lower8 ((b >> 56) & 255) << 16
        | uint_to_hex_lower8 ((b >> 48) & 255) <<  0;
  w1[1] = uint_to_hex_lower8 ((b >> 40) & 255) << 16
        | uint_to_hex_lower8 ((b >> 32) & 255) <<  0;
  w1[2] = uint_to_hex_lower8 ((b >> 24) & 255) << 16
        | uint_to_hex_lower8 ((b >> 16) & 255) <<  0;
  w1[3] = uint_to_hex_lower8 ((b >>  8) & 255) << 16
        | uint_to_hex_lower8 ((b >>  0) & 255) <<  0;
  w2[0] = uint_to_hex_lower8 ((c >> 56) & 255) << 16
        | uint_to_hex_lower8 ((c >> 48) & 255) <<  0;
  w2[1] = uint_to_hex_lower8 ((c >> 40) & 255) << 16
        | uint_to_hex_lower8 ((c >> 32) & 255) <<  0;
  w2[2] = uint_to_hex_lower8 ((c >> 24) & 255) << 16
        | uint_to_hex_lower8 ((c >> 16) & 255) <<  0;
  w2[3] = uint_to_hex_lower8 ((c >>  8) & 255) << 16
        | uint_to_hex_lower8 ((c >>  0) & 255) <<  0;
  w3[0] = uint_to_hex_lower8 ((d >> 56) & 255) << 16
        | uint_to_hex_lower8 ((d >> 48) & 255) <<  0;
  w3[1] = uint_to_hex_lower8 ((d >> 40) & 255) << 16
        | uint_to_hex_lower8 ((d >> 32) & 255) <<  0;
  w3[2] = uint_to_hex_lower8 ((d >> 24) & 255) << 16
        | uint_to_hex_lower8 ((d >> 16) & 255) <<  0;
  w3[3] = uint_to_hex_lower8 ((d >>  8) & 255) << 16
        | uint_to_hex_lower8 ((d >>  0) & 255) <<  0;
  w4[0] = uint_to_hex_lower8 ((e >> 56) & 255) << 16
        | uint_to_hex_lower8 ((e >> 48) & 255) <<  0;
  w4[1] = uint_to_hex_lower8 ((e >> 40) & 255) << 16
        | uint_to_hex_lower8 ((e >> 32) & 255) <<  0;
  w4[2] = uint_to_hex_lower8 ((e >> 24) & 255) << 16
        | uint_to_hex_lower8 ((e >> 16) & 255) <<  0;
  w4[3] = uint_to_hex_lower8 ((e >>  8) & 255) << 16
        | uint_to_hex_lower8 ((e >>  0) & 255) <<  0;
  w5[0] = uint_to_hex_lower8 ((f >> 56) & 255) << 16
        | uint_to_hex_lower8 ((f >> 48) & 255) <<  0;
  w5[1] = uint_to_hex_lower8 ((f >> 40) & 255) << 16
        | uint_to_hex_lower8 ((f >> 32) & 255) <<  0;
  w5[2] = uint_to_hex_lower8 ((f >> 24) & 255) << 16
        | uint_to_hex_lower8 ((f >> 16) & 255) <<  0;
  w5[3] = uint_to_hex_lower8 ((f >>  8) & 255) << 16
        | uint_to_hex_lower8 ((f >>  0) & 255) <<  0;
  w6[0] = uint_to_hex_lower8 ((g >> 56) & 255) << 16
        | uint_to_hex_lower8 ((g >> 48) & 255) <<  0;
  w6[1] = uint_to_hex_lower8 ((g >> 40) & 255) << 16
        | uint_to_hex_lower8 ((g >> 32) & 255) <<  0;
  w6[2] = uint_to_hex_lower8 ((g >> 24) & 255) << 16
        | uint_to_hex_lower8 ((g >> 16) & 255) <<  0;
  w6[3] = uint_to_hex_lower8 ((g >>  8) & 255) << 16
        | uint_to_hex_lower8 ((g >>  0) & 255) <<  0;
  w7[0] = uint_to_hex_lower8 ((h >> 56) & 255) << 16
        | uint_to_hex_lower8 ((h >> 48) & 255) <<  0;
  w7[1] = uint_to_hex_lower8 ((h >> 40) & 255) << 16
        | uint_to_hex_lower8 ((h >> 32) & 255) <<  0;
  w7[2] = uint_to_hex_lower8 ((h >> 24) & 255) << 16
        | uint_to_hex_lower8 ((h >> 16) & 255) <<  0;
  w7[3] = uint_to_hex_lower8 ((h >>  8) & 255) << 16
        | uint_to_hex_lower8 ((h >>  0) & 255) <<  0;

  sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);

  sha512_update (&ctx, hc->s, hc->salt_len);

  sha512_final (&ctx);

  dgst[0] = l32_from_64_S (ctx.h[7]);
  dgst[1] = h32_from_64_S (ctx.h[7]);
  dgst[2] = l32_from_64_S (ctx.h[3]);
  dgst[3] = h32_from_64_S (ctx.h[3]);

  return true;
}

#define PCFG_KERNEL_MXX m32410_mxx
#define PCFG_KERNEL_SXX m32410_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
