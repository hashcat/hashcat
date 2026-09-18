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

#define PCFG_MURMUR_M 0x7fd652ad
#define PCFG_MURMUR_R 16

#define PCFG_MURMUR_MAX 63

typedef struct pcfg_hash_ctx
{
  u32 seed;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->seed = salt_bufs[salt_pos].salt_buf[0];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

// Everything after the walk over whole words, which does not depend on where the candidate lives.

DECLSPEC u32 pcfg_murmur_tail (const u32 hash_in, const u32 last, const u32 len)
{
  u32 hash = hash_in;

  const u32 tmp = (hash + last) * PCFG_MURMUR_M;

  hash = (len & 3) ? (tmp ^ (tmp >> PCFG_MURMUR_R)) : hash;

  hash *= PCFG_MURMUR_M;
  hash ^= hash >> 10;
  hash *= PCFG_MURMUR_M;
  hash ^= hash >> 17;

  return hash;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_MURMUR_MAX) return false;

  u32 hash = hc->seed + 0xdeadbeef;

  const u32 blocks = len / 4;

  // The rules kernel guards this walk with pw_len >= 4, which a zero block count already covers.

  for (u32 i = 0; i < blocks; i++)
  {
    const u32 tmp = (hash + w[i]) * PCFG_MURMUR_M;

    hash = tmp ^ (tmp >> PCFG_MURMUR_R);
  }

  dgst[0] = pcfg_murmur_tail (hash, w[blocks], len);
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_MURMUR_MAX) return false;

  u32 hash = hc->seed + 0xdeadbeef;

  const u32 blocks = len / 4;

  for (u32 i = 0; i < blocks; i++)
  {
    const u32 tmp = (hash + w[i]) * PCFG_MURMUR_M;

    hash = tmp ^ (tmp >> PCFG_MURMUR_R);
  }

  dgst[0] = pcfg_murmur_tail (hash, w[blocks], len);
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m25700_mxx
#define PCFG_KERNEL_SXX m25700_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
