/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A recipe with a for loop or pbkdf2 call runs here as a slow hash. See RECIPE_LOOP in
// inc_recipe.cl. The salt stores the iteration count used by the loop kernel. The tmps contain the
// pbkdf2 state and the variables carried from one kernel to the next.

// The loop kernel of a pbkdf2 recipe iterates VECT_SIZE candidates per work item, see
// OPTI_TYPE_SLOW_HASH_SIMD_LOOP. The init and comp kernels take one candidate each.

#ifdef RECIPE_KDF
#define NEW_SIMD_CODE
#endif

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#ifdef RECIPE_KDF
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif
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
#include M2S(INCLUDE_PATH/inc_pbkdf2.cl)
#ifdef RECIPE_AES
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-modes.cl)
#endif
#include M2S(INCLUDE_PATH/inc_recipe.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#ifndef RECIPE_LOOP
#error "mode 4000: the slow kernels need a recipe with a for loop or a pbkdf2 call"
#endif

// A pbkdf2 recipe keeps only its state from one kernel to the next: the init kernel reads its key
// and salt where its steps leave them, and the comp kernel fills the derived key's variable itself.
// See module_tmp_size ().

typedef struct recipe_tmp
{
  #ifdef RECIPE_KDF
  RECIPE_KDF_STATE kdf;
  #else
  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];
  #endif

} recipe_tmp_t;

// The pbkdf2 loop processes VECT_SIZE candidates together. Their states are gathered into vectors,
// iterated with the vector transform and written back. Each family specifies its word type, the
// number of words per block, and the pack and unpack macros from OpenCL/inc_simd.h for that word
// type.

#ifdef RECIPE_KDF

#define RECIPE_KDF_LV(T,N,PACK,UNPACK)                                                  \
{                                                                                       \
  T ipad[N];                                                                            \
  T opad[N];                                                                            \
                                                                                        \
  for (u32 i = 0; i < (N); i++) ipad[i] = PACK (tmps, kdf.ipad, gid, i);                \
  for (u32 i = 0; i < (N); i++) opad[i] = PACK (tmps, kdf.opad, gid, i);                \
                                                                                        \
  for (u32 b = 0; b < RECIPE_KDF_BLOCKS; b++)                                           \
  {                                                                                     \
    T dgst[N];                                                                          \
    T out[N];                                                                           \
                                                                                        \
    for (u32 i = 0; i < (N); i++) dgst[i] = PACK (tmps, kdf.dgst, gid, (b * (N)) + i);  \
    for (u32 i = 0; i < (N); i++) out[i]  = PACK (tmps, kdf.out,  gid, (b * (N)) + i);  \
                                                                                        \
    for (u32 j = 0; j < LOOP_CNT; j++)                                                  \
    {                                                                                   \
      RECIPE_KDF_FN (run_V) (ipad, opad, dgst);                                         \
                                                                                        \
      for (u32 i = 0; i < (N); i++) out[i] ^= dgst[i];                                  \
    }                                                                                   \
                                                                                        \
    for (u32 i = 0; i < (N); i++)                                                       \
    {                                                                                   \
      UNPACK (tmps, kdf.dgst, gid, (b * (N)) + i, dgst[i]);                             \
      UNPACK (tmps, kdf.out,  gid, (b * (N)) + i, out[i]);                              \
    }                                                                                   \
  }                                                                                     \
}

#define RECIPE_KDF_LV_md5    RECIPE_KDF_LV (u32x, 4, packv,   unpackv)
#define RECIPE_KDF_LV_sha1   RECIPE_KDF_LV (u32x, 5, packv,   unpackv)
#define RECIPE_KDF_LV_sha256 RECIPE_KDF_LV (u32x, 8, packv,   unpackv)
#define RECIPE_KDF_LV_sha512 RECIPE_KDF_LV (u64x, 8, pack64v, unpack64v)

#define RECIPE_KDF_LV2(F) RECIPE_KDF_LV_##F
#define RECIPE_KDF_LV1(F) RECIPE_KDF_LV2 (F)

#define RECIPE_KDF_LOOP_V RECIPE_KDF_LV1 (RECIPE_KDF)

#endif

KERNEL_FQ KERNEL_FA void m04000_init (KERN_ATTR_TMPS (recipe_tmp_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_HEX_DECL

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = (pws[gid].pw_len >= 256) ? 256 : pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  /**
   * init
   */

  #ifdef RECIPE_KDF

  RECIPE_KDF_STATE kdf;

  recipe_kdf_init (&st, &kdf, w, pw_len, s, salt_len);

  tmps[gid].kdf = kdf;

  #else

  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = 0;
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = 0;

  recipe_eval_init (&st, w, pw_len, s, salt_len, vb, vl);

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) tmps[gid].vb[i] = vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) tmps[gid].vl[i] = vl[i];

  #endif
}

KERNEL_FQ KERNEL_FA void m04000_loop (KERN_ATTR_TMPS (recipe_tmp_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_HEX_DECL

  // pbkdf2 iterates only its own state and does not use other state. See OpenCL/inc_pbkdf2.cl. Each
  // work item processes VECT_SIZE candidates together.

  #ifdef RECIPE_KDF

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  RECIPE_KDF_LOOP_V

  #else

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = (pws[gid].pw_len >= 256) ? 256 : pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = tmps[gid].vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = tmps[gid].vl[i];

  // The block templates of the loop steps, see recipe_tpl_build ().

  recipe_tpl_t tpl;

  recipe_tpl_build (&st, &tpl, w, pw_len, s, salt_len, vb, vl);

  /**
   * loop
   */

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    recipe_eval_loop (&st, &tpl, w, pw_len, s, salt_len, vb, vl);
  }

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) tmps[gid].vb[i] = vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) tmps[gid].vl[i] = vl[i];

  #endif
}

KERNEL_FQ KERNEL_FA void m04000_comp (KERN_ATTR_TMPS (recipe_tmp_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_HEX_DECL

  // The AES tables of the AES steps, which run here only.

  RECIPE_AES_DECL

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = (pws[gid].pw_len >= 256) ? 256 : pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  RECIPE_AES_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];

  // The derived key, into its carried variable.

  #ifdef RECIPE_KDF

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = 0;
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = 0;

  const RECIPE_KDF_STATE kdf = tmps[gid].kdf;

  recipe_kdf_comp (&st, &kdf, vb, vl);

  #else

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = tmps[gid].vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = tmps[gid].vl[i];

  #endif

  /**
   * digest
   */

  u32 r[16];

  recipe_eval_comp (&st, w, pw_len, s, salt_len, vb, vl, r);

  const u32 r0 = r[DGST_R0];
  const u32 r1 = r[DGST_R1];
  const u32 r2 = r[DGST_R2];
  const u32 r3 = r[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
