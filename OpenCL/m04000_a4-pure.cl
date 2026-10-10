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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha224.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2s.cl)
#include M2S(INCLUDE_PATH/inc_hash_sm3.cl)
#include M2S(INCLUDE_PATH/inc_recipe.cl)
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_len;
  u32 s[64];

  recipe_state_t st;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  // Prepare work independent of the candidate once per salt.

  recipe_prep (&hc->st, hc->s, hc->salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 r[16];

  recipe_eval (&hc->st, w, w, len, hc->s, hc->salt_len, r);

  dgst[0] = r[DGST_R0];
  dgst[1] = r[DGST_R1];
  dgst[2] = r[DGST_R2];
  dgst[3] = r[DGST_R3];

  return true;
}

// The recipe reads passwords from private memory. Copy candidates supplied in global memory before
// evaluating them.

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 pw[64];

  for (u32 i = 0; i < 64; i++) pw[i] = 0;

  const u32 pw_len = (len >= 256) ? 256 : len;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = w[idx];
  }

  u32 r[16];

  recipe_eval (&hc->st, pw, pw, pw_len, hc->s, hc->salt_len, r);

  dgst[0] = r[DGST_R0];
  dgst[1] = r[DGST_R1];
  dgst[2] = r[DGST_R2];
  dgst[3] = r[DGST_R3];

  return true;
}

// GPU hex lookup table. See RECIPE_HEX_TABLE in inc_recipe.cl.

#define PCFG_HASH_SHARED_DECL     RECIPE_HEX_DECL
#define PCFG_HASH_SHARED_BIND(hc) RECIPE_HEX_BIND (&((hc)->st))

#define PCFG_KERNEL_MXX m04000_mxx
#define PCFG_KERNEL_SXX m04000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
