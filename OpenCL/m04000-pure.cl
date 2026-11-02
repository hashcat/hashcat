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
#include M2S(INCLUDE_PATH/inc_pbkdf2.cl)
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

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#ifndef RECIPE_LOOP
#error "mode 4000: the slow kernels need a recipe with a for loop or a pbkdf2 call"
#endif

// A pbkdf2 recipe keeps only its state from one kernel to the next: the init kernel reads its key
// and salt where its steps leave them, and the comp kernel fills the derived key's variable itself.
// A loop recipe also carries the chaining values of hoisted HMAC key pads, see RECIPE_S<k>_HK. See
// module_tmp_size ().

typedef struct recipe_tmp
{
  #ifdef RECIPE_KDF
  RECIPE_KDF_STATE kdf;
  #else
  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];
  #if RECIPE_HKW > 0
  u32 hk[RECIPE_HKW];
  #endif
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

  RECIPE_SHM_DECL

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

  RECIPE_SHM_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])
  RECIPE_FIELDS_BIND (&st, salt_bufs[SALT_POS_HOST])

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
  u32 hk[RECIPE_HKN];

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = 0;
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = 0;

  recipe_eval_init (&st, w, pw_len, s, salt_len, vb, vl, hk);

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) tmps[gid].vb[i] = vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) tmps[gid].vl[i] = vl[i];

  #if RECIPE_HKW > 0
  for (u32 i = 0; i < RECIPE_HKW; i++) tmps[gid].hk[i] = hk[i];
  #endif

  #endif
}

KERNEL_FQ KERNEL_FA void m04000_loop (KERN_ATTR_TMPS (recipe_tmp_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_SHM_DECL

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

  RECIPE_SHM_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])
  RECIPE_FIELDS_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  u32 vb[RECIPE_CARRY * 64];
  u32 vl[RECIPE_CARRY];

  for (u32 i = 0; i < (RECIPE_CARRY * 64); i++) vb[i] = tmps[gid].vb[i];
  for (u32 i = 0; i <  RECIPE_CARRY;       i++) vl[i] = tmps[gid].vl[i];

  u32 hk[RECIPE_HKN];

  #if RECIPE_HKW > 0
  for (u32 i = 0; i < RECIPE_HKW; i++) hk[i] = tmps[gid].hk[i];
  #endif

  // The block templates and the hoisted HMAC key pads of the loop steps, see recipe_tpl_build ().

  recipe_tpl_t tpl;

  recipe_tpl_build (&st, &tpl, w, pw_len, s, salt_len, vb, vl, hk);

  /**
   * loop
   */

  // A recipe whose loop steps all hash from templates runs the general evaluation only until the
  // templates apply, see RECIPE_TLOOP.

  u32 j = 0;

  #if RECIPE_TLOOP == 1

  for (; j < LOOP_CNT; j++)
  {
    if (recipe_tpl_ready (&tpl, vl) == true) break;

    recipe_eval_loop (&st, &tpl, w, pw_len, s, salt_len, vb, vl);
  }

  if (j < LOOP_CNT) recipe_eval_tloop (&st, &tpl, w, pw_len, s, salt_len, vb, vl, LOOP_CNT - j);

  #else

  for (; j < LOOP_CNT; j++)
  {
    recipe_eval_loop (&st, &tpl, w, pw_len, s, salt_len, vb, vl);
  }

  #endif

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

  RECIPE_SHM_DECL

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

  RECIPE_SHM_BIND (&st)

  RECIPE_AES_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])
  RECIPE_FIELDS_BIND (&st, salt_bufs[SALT_POS_HOST])

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
