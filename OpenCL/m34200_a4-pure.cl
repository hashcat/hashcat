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

DECLSPEC u64 MurmurHash64A (const u64 seed, PRIVATE_AS const u32 *data, const u32 len)
{
#define M 0xc6a4a7935bd1e995
#define R 47

  u64 hash = seed ^ (len * M);

  const u32 num_u32_blocks = (len / 8) * 2;

  u32 i = 0;
  while (i < num_u32_blocks)
  {
    u64 k = hl32_to_64 (data[i + 1], data[i]);

    k *= M;
    k ^= k >> R;
    k *= M;

    hash ^= k;
    hash *= M;

    i += 2;
  }

  const u32 overflow = len & 7;

  if (overflow > 4)
  {
    hash ^= hl32_to_64 (data[i + 1], data[i]);
    hash *= M;
  }
  else if (overflow > 0)
  {
    hash ^= hl32_to_64 (0, data[i]);
    hash *= M;
  }

  hash ^= hash >> R;
  hash *= M;
  hash ^= hash >> R;

#undef M
#undef R

  return hash;
}

typedef struct pcfg_hash_ctx
{
  u64 seed;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u32 seed_lo;
  u32 seed_hi;

  seed_lo = salt_bufs[salt_pos].salt_buf[0];

  seed_hi = salt_bufs[salt_pos].salt_buf[1];

  hc->seed = hl32_to_64 (seed_hi, seed_lo);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u64x hash = MurmurHash64A (hc->seed, w, len);

  dgst[0] = l32_from_64 (hash);
  dgst[1] = h32_from_64 (hash);
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64];

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  return pcfg_hash (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m34200_mxx
#define PCFG_KERNEL_SXX m34200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
