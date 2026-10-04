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
#endif

#define MYSQL323_ROUND(v)                     \
{                                             \
  a ^= (((a & 0x3f) + add) * (v)) + (a << 8); \
  b += (b << 8) ^ a;                          \
  add += (v);                                 \
}

typedef struct pcfg_hash_ctx
{
  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 a = MYSQL323_A;
  u32 b = MYSQL323_B;

  u32 add = 7;

  for (u32 i = 0; i < len; i++)
  {
    MYSQL323_ROUND (pcfg_get_byte (w, i));
  }

  dgst[0] = a & 0x7fffffff;
  dgst[1] = b & 0x7fffffff;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 a = MYSQL323_A;
  u32 b = MYSQL323_B;

  u32 add = 7;

  for (u32 i = 0; i < len; i++)
  {
    MYSQL323_ROUND ((w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }

  dgst[0] = a & 0x7fffffff;
  dgst[1] = b & 0x7fffffff;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m00200_mxx
#define PCFG_KERNEL_SXX m00200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
