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

#if   VECT_SIZE == 1
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7], u_bin2asc[(i).s8], u_bin2asc[(i).s9], u_bin2asc[(i).sa], u_bin2asc[(i).sb], u_bin2asc[(i).sc], u_bin2asc[(i).sd], u_bin2asc[(i).se], u_bin2asc[(i).sf])
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
  LOCAL_VK u32 u_bin2asc[256];                                  \
  for (u32 j = lid; j < 256; j += lsz)                          \
  {                                                             \
    const u32 i0 = (j >> 0) & 15;                               \
    const u32 i1 = (j >> 4) & 15;                               \
    u_bin2asc[j] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8  \
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0; \
  }                                                             \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->u_bin2asc = u_bin2asc;

typedef struct pcfg_hash_ctx
{
  u32 salt1_len;
  u32 s1[64];
  md5_ctx_t ctx0;
  LOCAL_AS u32 *u_bin2asc;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const md5_double_salt_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt1_len = esalt_bufs[digest_pos].salt1_len;

  for (u32 i = 0; i < 64; i++) hc->s1[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt1_len; i += 4, idx += 1)
  {
    hc->s1[idx] = esalt_bufs[digest_pos].salt1_buf[idx];
  }

  md5_init (&hc->ctx0);

  md5_update_global (&hc->ctx0, esalt_bufs[digest_pos].salt2_buf, esalt_bufs[digest_pos].salt2_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  LOCAL_AS u32 *u_bin2asc = hc->u_bin2asc;

  md5_ctx_t ctx1 = hc->ctx0;

  md5_update (&ctx1, w, len);

  md5_final (&ctx1);

  const u32 a = ctx1.h[0];
  const u32 b = ctx1.h[1];
  const u32 c = ctx1.h[2];
  const u32 d = ctx1.h[3];

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update (&ctx, hc->s1, hc->salt1_len);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = uint_to_hex_upper8 ((a >>  0) & 255) <<  0
        | uint_to_hex_upper8 ((a >>  8) & 255) << 16;
  w0[1] = uint_to_hex_upper8 ((a >> 16) & 255) <<  0
        | uint_to_hex_upper8 ((a >> 24) & 255) << 16;
  w0[2] = uint_to_hex_upper8 ((b >>  0) & 255) <<  0
        | uint_to_hex_upper8 ((b >>  8) & 255) << 16;
  w0[3] = uint_to_hex_upper8 ((b >> 16) & 255) <<  0
        | uint_to_hex_upper8 ((b >> 24) & 255) << 16;
  w1[0] = uint_to_hex_upper8 ((c >>  0) & 255) <<  0
        | uint_to_hex_upper8 ((c >>  8) & 255) << 16;
  w1[1] = uint_to_hex_upper8 ((c >> 16) & 255) <<  0
        | uint_to_hex_upper8 ((c >> 24) & 255) << 16;
  w1[2] = uint_to_hex_upper8 ((d >>  0) & 255) <<  0
        | uint_to_hex_upper8 ((d >>  8) & 255) << 16;
  w1[3] = uint_to_hex_upper8 ((d >> 16) & 255) <<  0
        | uint_to_hex_upper8 ((d >> 24) & 255) << 16;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_update_64 (&ctx, w0, w1, w2, w3, 32);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m03730_mxx
#define PCFG_KERNEL_SXX m03730_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
