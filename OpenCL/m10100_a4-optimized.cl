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

DECLSPEC u64 siphash_rot32_S (const u64 a)
{
  // swapping the two halves of a 64 bit word is a rotation by 32. Writing it as a union makes
  // Mesa put the value in scratch memory.

  const u64 r = hc_rotr64_S (a, 32);

  return r;
}

#define SIPROUND_S(v0,v1,v2,v3)   \
  (v0) += (v1);                   \
  (v1)  = hc_rotl64_S ((v1), 13); \
  (v1) ^= (v0);                   \
  (v0)  = siphash_rot32_S ((v0)); \
  (v2) += (v3);                   \
  (v3)  = hc_rotl64_S ((v3), 16); \
  (v3) ^= (v2);                   \
  (v0) += (v3);                   \
  (v3)  = hc_rotl64_S ((v3), 21); \
  (v3) ^= (v0);                   \
  (v2) += (v1);                   \
  (v1)  = hc_rotl64_S ((v1), 17); \
  (v1) ^= (v2);                   \
  (v2)  = siphash_rot32_S ((v2))

typedef struct pcfg_hash_ctx
{
  u64 v0;
  u64 v1;
  u64 v2;
  u64 v3;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  u64 v0 = SIPHASHM_0;
  u64 v1 = SIPHASHM_1;
  u64 v2 = SIPHASHM_2;
  u64 v3 = SIPHASHM_3;

  v0 ^= hl32_to_64_S (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v1 ^= hl32_to_64_S (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);
  v2 ^= hl32_to_64_S (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v3 ^= hl32_to_64_S (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);

  hc->v0 = v0;
  hc->v1 = v1;
  hc->v2 = v2;
  hc->v3 = v3;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_siphash24 (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *t, const u32 len, PRIVATE_AS u32 *dgst)
{
  switch (len / 8)
  {
    case 0: t[1] |= len << 24; break;
    case 1: t[3] |= len << 24; break;
    case 2: t[5] |= len << 24; break;
    case 3: t[7] |= len << 24; break;
  }

  u64 v0 = hc->v0;
  u64 v1 = hc->v1;
  u64 v2 = hc->v2;
  u64 v3 = hc->v3;

  for (u32 i = 0, j = 0; i <= len; i += 8, j += 2)
  {
    const u64 m = hl32_to_64_S (t[j + 1], t[j + 0]);

    v3 ^= m;

    SIPROUND_S (v0, v1, v2, v3);
    SIPROUND_S (v0, v1, v2, v3);

    v0 ^= m;
  }

  v2 ^= 0xff;

  SIPROUND_S (v0, v1, v2, v3);
  SIPROUND_S (v0, v1, v2, v3);
  SIPROUND_S (v0, v1, v2, v3);
  SIPROUND_S (v0, v1, v2, v3);

  const u64 v = v0 ^ v1 ^ v2 ^ v3;

  dgst[0] = l32_from_64_S (v);
  dgst[1] = h32_from_64_S (v);
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_siphash24 (hc, t, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 31) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_siphash24 (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m10100_mxx
#define PCFG_KERNEL_SXX m10100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
