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
#ifdef RECIPE_RMD320
#include M2S(INCLUDE_PATH/inc_hash_ripemd320.cl)
#endif
#ifdef RECIPE_RMD128
#include M2S(INCLUDE_PATH/inc_hash_ripemd128.cl)
#endif
#ifdef RECIPE_RMD256
#include M2S(INCLUDE_PATH/inc_hash_ripemd256.cl)
#endif
#ifdef RECIPE_MD2
#include M2S(INCLUDE_PATH/inc_hash_md2.cl)
#endif
#ifdef RECIPE_SHA0
#include M2S(INCLUDE_PATH/inc_hash_sha0.cl)
#endif
#ifdef RECIPE_SNEFRU
#include M2S(INCLUDE_PATH/inc_hash_snefru.cl)
#endif
#ifdef RECIPE_SKEIN512
#include M2S(INCLUDE_PATH/inc_hash_skein512.cl)
#endif
#ifdef RECIPE_PANAMA
#include M2S(INCLUDE_PATH/inc_hash_panama.cl)
#endif
#ifdef RECIPE_BLAKE
#include M2S(INCLUDE_PATH/inc_hash_blake.cl)
#endif
#ifdef RECIPE_BMW
#include M2S(INCLUDE_PATH/inc_hash_bmw.cl)
#endif
#ifdef RECIPE_CUBEHASH
#include M2S(INCLUDE_PATH/inc_hash_cubehash.cl)
#endif
#ifdef RECIPE_ECHO
#include M2S(INCLUDE_PATH/inc_hash_echo.cl)
#endif
#ifdef RECIPE_FUGUE
#include M2S(INCLUDE_PATH/inc_hash_fugue.cl)
#endif
#ifdef RECIPE_GROESTL
#include M2S(INCLUDE_PATH/inc_hash_groestl.cl)
#endif
#ifdef RECIPE_HAMSI
#include M2S(INCLUDE_PATH/inc_hash_hamsi.cl)
#endif
#ifdef RECIPE_JH
#include M2S(INCLUDE_PATH/inc_hash_jh.cl)
#endif
#ifdef RECIPE_LUFFA
#include M2S(INCLUDE_PATH/inc_hash_luffa.cl)
#endif
#ifdef RECIPE_SHABAL
#include M2S(INCLUDE_PATH/inc_hash_shabal.cl)
#endif
#ifdef RECIPE_SHAVITE
#include M2S(INCLUDE_PATH/inc_hash_shavite.cl)
#endif
#ifdef RECIPE_SIMD
#include M2S(INCLUDE_PATH/inc_hash_simd.cl)
#endif
#ifdef RECIPE_HAS160
#include M2S(INCLUDE_PATH/inc_hash_has160.cl)
#endif
#ifdef RECIPE_EDONR
#include M2S(INCLUDE_PATH/inc_hash_edonr.cl)
#endif
#ifdef RECIPE_MD6
#include M2S(INCLUDE_PATH/inc_hash_md6.cl)
#endif
#ifdef RECIPE_RADIOGATUN
#include M2S(INCLUDE_PATH/inc_hash_radiogatun.cl)
#endif
#ifdef RECIPE_RIPEMD
#include M2S(INCLUDE_PATH/inc_hash_ripemd.cl)
#endif
#ifdef RECIPE_WRL01
#include M2S(INCLUDE_PATH/inc_hash_whirlpool01.cl)
#endif
#ifdef RECIPE_MYSQL323
#include M2S(INCLUDE_PATH/inc_hash_mysql323.cl)
#endif
#ifdef RECIPE_XXHASH
#include M2S(INCLUDE_PATH/inc_hash_xxhash.cl)
#endif
#ifdef RECIPE_DES
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif
#ifdef RECIPE_LM
#include M2S(INCLUDE_PATH/inc_hash_lm.cl)
#endif
#ifdef RECIPE_MDC2
#include M2S(INCLUDE_PATH/inc_hash_mdc2.cl)
#endif
#ifdef RECIPE_HAVAL
#include M2S(INCLUDE_PATH/inc_hash_haval.cl)
#endif
#ifdef RECIPE_TIGER
#include M2S(INCLUDE_PATH/inc_hash_tiger.cl)
#endif
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2s.cl)
#include M2S(INCLUDE_PATH/inc_hash_sm3.cl)
#ifdef RECIPE_WRL
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#endif
#ifdef RECIPE_SHA3
#include M2S(INCLUDE_PATH/inc_hash_sha3.cl)
#endif
#ifdef RECIPE_SBOG256
#undef BOX
#undef BOX_S
#include M2S(INCLUDE_PATH/inc_hash_streebog256.cl)
#endif
#ifdef RECIPE_SBOG512
#undef BOX
#undef BOX_S
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
#endif
#if defined RECIPE_GOST94 || defined RECIPE_GOST94_CP
#undef BOX
#include M2S(INCLUDE_PATH/inc_hash_gost94.cl)
#endif
#if defined RECIPE_AES || defined RECIPE_ECHO || defined RECIPE_SHAVITE
#ifndef RECIPE_AES
#define AES_TE0_TE3_ONLY
#endif
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif
#ifdef RECIPE_AES
#include M2S(INCLUDE_PATH/inc_cipher_aes-modes.cl)
#endif
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

  RECIPE_SALTD_BIND (&hc->st, salt_bufs[salt_pos])
  RECIPE_FIELDS_BIND (&hc->st, salt_bufs[salt_pos])

  // Prepare work independent of the candidate once per salt.

  recipe_prep (&hc->st, hc->s, hc->salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 r[16];

  // This gate assumes the password is read wide, as a full 64 word copy, exactly when
  // RECIPE_PASS_PLAIN is not set. The wide read is RECIPE_XRUN, which a recipe runs only to
  // transform the password, plus the HMAC key path; RECIPE_PASS_PLAIN marks the recipes that do
  // neither, so where it is set the recipe reads only the candidate's own bytes.

#ifdef RECIPE_PASS_PLAIN

  // The recipe hashes the password as is, reading only its own bytes, which the candidate array
  // holds. Evaluate it in place, no copy.

  recipe_eval (&hc->st, w, w, len, hc->s, hc->salt_len, r);

#else

  // The pcfg candidate array holds the candidate zero padded only as far as the generator needs,
  // which can be fewer than 64 words. A recipe that transforms the password reads it as a full 64
  // word copy, past the candidate, so it would read whatever is left in the array beyond it. Copy
  // the candidate into a buffer cleared to the full 256 bytes the recipe may reach, the same way
  // the global path does, so the bytes past the candidate are zero.

  u32 pw[64];

  for (u32 i = 0; i < 64; i++) pw[i] = 0;

  const u32 pw_len = (len >= 256) ? 256 : len;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = w[idx];
  }

  recipe_eval (&hc->st, pw, pw, pw_len, hc->s, hc->salt_len, r);

#endif

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

#define PCFG_HASH_SHARED_DECL     RECIPE_SHM_DECL
#define PCFG_HASH_SHARED_BIND(hc) RECIPE_SHM_BIND (&((hc)->st))

#define PCFG_KERNEL_MXX m04000_mxx
#define PCFG_KERNEL_SXX m04000_sxx

#ifdef RECIPE_SXX_ONLY
#define PCFG_SXX_ONLY
#endif

#ifdef RECIPE_MXX_ONLY
#define PCFG_MXX_ONLY
#endif

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
