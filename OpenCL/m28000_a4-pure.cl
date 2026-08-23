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
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#endif

typedef struct crc64
{
  u64 iv;

} crc64_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (crc64_t)

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL              \
  LOCAL_VK u64 s_crc64jonestab[256];       \
  for (u32 i = lid; i < 256; i += lsz)     \
  {                                        \
    s_crc64jonestab[i] = crc64jonestab[i]; \
  }                                        \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) (hc)->s_crc64jonestab = s_crc64jonestab;
#endif

typedef struct pcfg_hash_ctx
{
  u64 iv;
  #ifdef REAL_SHM
  LOCAL_AS u64 *s_crc64jonestab;
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const crc64_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->iv = esalt_bufs[digest_pos].iv;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64 *s_crc64jonestab = hc->s_crc64jonestab;
  #else
  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;
  #endif

  u64 a = crc64j (w, len, hc->iv, s_crc64jonestab);

  dgst[0] = l32_from_64 (a);
  dgst[1] = h32_from_64 (a);
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u64 *s_crc64jonestab = hc->s_crc64jonestab;
  #else
  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;
  #endif

  u64 a = crc64j_global (w, len, hc->iv, s_crc64jonestab);

  dgst[0] = l32_from_64 (a);
  dgst[1] = h32_from_64 (a);
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

#define PCFG_KERNEL_MXX m28000_mxx
#define PCFG_KERNEL_SXX m28000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
