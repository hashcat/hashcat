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

#define uint_to_hex_lower8(i) (l_bin2asc[(i)])

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
  u32 s[8];

  u32 lenbits;

  LOCAL_AS u32 *l_bin2asc;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  for (u32 i = 0; i < 8; i++) hc->s[i] = salt_bufs[salt_pos].salt_buf[i];

  hc->lenbits = (32 + salt_bufs[salt_pos].salt_len) * 8;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_vbulletin (PRIVATE_AS const u32 *wx, const u32 len, PRIVATE_AS u32 *dgst, PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  LOCAL_AS u32 *l_bin2asc = hc->l_bin2asc;

  u32 w0[4] = { wx[0], wx[1], wx[2], wx[3] };
  u32 w1[4] = { wx[4], wx[5], wx[6], wx[7] };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, len * 8, 0 };

  append_0x80_2x4_S (w0, w1, len);

  u32 h[4];

  h[0] = MD5M_A;
  h[1] = MD5M_B;
  h[2] = MD5M_C;
  h[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, h);

  const u32 a = h[0];
  const u32 b = h[1];
  const u32 c = h[2];
  const u32 d = h[3];

  w0[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
  w0[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
  w0[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
  w0[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
  w1[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
  w1[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
  w1[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
  w1[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

  w2[0] = hc->s[0];
  w2[1] = hc->s[1];
  w2[2] = hc->s[2];
  w2[3] = hc->s[3];
  w3[0] = hc->s[4];
  w3[1] = hc->s[5];
  w3[2] = hc->s[6];
  w3[3] = hc->s[7];

  h[0] = MD5M_A;
  h[1] = MD5M_B;
  h[2] = MD5M_C;
  h[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, h);

  w0[0] = 0;
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
  w3[2] = hc->lenbits;
  w3[3] = 0;

  md5_transform (w0, w1, w2, w3, h);

  // m02710_m04 ends on COMPARE_M_SIMD (a, d, c, b), and that order is the contract here

  dgst[0] = h[0];
  dgst[1] = h[3];
  dgst[2] = h[2];
  dgst[3] = h[1];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  return pcfg_vbulletin (w, len, dgst, hc);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_vbulletin (t, len, dgst, hc);
}

#define PCFG_KERNEL_MXX m02710_mxx
#define PCFG_KERNEL_SXX m02710_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
