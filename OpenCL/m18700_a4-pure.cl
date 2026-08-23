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

DECLSPEC u32 hashCode (const u32 init, PRIVATE_AS const u32 *w, const u32 pw_len)
{
  u32 hash = init;

  for (u32 i = 0; i < pw_len; i += 4)
  {
    u32 tmp = w[i / 4];

    const u32 left = pw_len - i;

    const u32 c = (left > 4) ? 4 : left;

    switch (c)
    {
      case 1:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        break;
      case 2:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        break;
      case 3:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        hash *= 31; hash += (tmp >> 16) & 0xff;
        break;
      case 4:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        hash *= 31; hash += (tmp >> 16) & 0xff;
        hash *= 31; hash += (tmp >> 24) & 0xff;
        break;
    }
  }

  return hash;
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
  const u32 hash = hashCode (0, w, len);

  dgst[0] = hash;
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  const u32 hash = hashCode (0, w, len);

  dgst[0] = hash;
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m18700_mxx
#define PCFG_KERNEL_SXX m18700_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
