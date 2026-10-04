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

// The tail reads the word at len / 4, so the candidate has to stop one word short of the buffer.

#define PCFG_MURMUR3_MAX 63

DECLSPEC u32 Murmur32_Scramble (u32 k)
{
  k = (k * 0x16A88000) | ((k * 0xCC9E2D51) >> 17);

  return (k * 0x1B873593);
}

DECLSPEC u32 MurmurHash3 (const u32 seed, PRIVATE_AS const u32 *data, const u32 size)
{
  u32 checksum = seed;

  const u32 nBlocks = size / 4;

  if (size >= 4)
  {
    for (u32 i = 0; i < nBlocks; i++)
    {
      checksum ^= Murmur32_Scramble (data[i]);

      checksum = (checksum >> 19) | (checksum << 13); // rotateRight (checksum, 19)
      checksum = (checksum * 5) + 0xE6546B64;
    }
  }

  const u32 val = data[nBlocks] & (0x00ffffff >> ((3 - (size & 3)) * 8));

  checksum ^= Murmur32_Scramble (val);

  checksum ^= size;
  checksum ^= checksum >> 16;
  checksum *= 0x85EBCA6B;
  checksum ^= checksum >> 13;
  checksum *= 0xC2B2AE35;

  return checksum ^ (checksum >> 16);
}

DECLSPEC u32 MurmurHash3_global (const u32 seed, GLOBAL_AS const u32 *data, const u32 size)
{
  u32 checksum = seed;

  const u32 nBlocks = size / 4;

  if (size >= 4)
  {
    for (u32 i = 0; i < nBlocks; i++)
    {
      checksum ^= Murmur32_Scramble (data[i]);

      checksum = (checksum >> 19) | (checksum << 13); // rotateRight (checksum, 19)
      checksum = (checksum * 5) + 0xE6546B64;
    }
  }

  const u32 val = data[nBlocks] & (0x00ffffff >> ((3 - (size & 3)) * 8));

  checksum ^= Murmur32_Scramble (val);

  checksum ^= size;
  checksum ^= checksum >> 16;
  checksum *= 0x85EBCA6B;
  checksum ^= checksum >> 13;
  checksum *= 0xC2B2AE35;

  return checksum ^ (checksum >> 16);
}

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
  // Nothing to write into the candidate: the mode asks for no padding byte and no length word.
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_MURMUR3_MAX) return false;

  dgst[0] = MurmurHash3 (hc->seed, w, len);
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_MURMUR3_MAX) return false;

  dgst[0] = MurmurHash3_global (hc->seed, w, len);
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m27800_mxx
#define PCFG_KERNEL_SXX m27800_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
