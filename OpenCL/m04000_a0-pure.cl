/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
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

// A session runs one of these 2 kernels: m04000_sxx for a single hash, or m04000_mxx otherwise.
// hashcat selects it with RECIPE_SXX_ONLY or RECIPE_MXX_ONLY, so the unused kernel is not built.

#ifndef RECIPE_SXX_ONLY

KERNEL_FQ KERNEL_FA void m04000_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_SHM_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])
  RECIPE_FIELDS_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 r[16];

    recipe_eval (&st, tmp.i, tmp.i, tmp.pw_len, s, salt_len, r);

    const u32 r0 = r[DGST_R0];
    const u32 r1 = r[DGST_R1];
    const u32 r2 = r[DGST_R2];
    const u32 r3 = r[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

#endif

#ifndef RECIPE_MXX_ONLY

KERNEL_FQ KERNEL_FA void m04000_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_SHM_DECL

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_SHM_BIND (&st)

  RECIPE_SALTD_BIND (&st, salt_bufs[SALT_POS_HOST])
  RECIPE_FIELDS_BIND (&st, salt_bufs[SALT_POS_HOST])

  recipe_prep (&st, s, salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 r[16];

    recipe_eval (&st, tmp.i, tmp.i, tmp.pw_len, s, salt_len, r);

    const u32 r0 = r[DGST_R0];
    const u32 r1 = r[DGST_R1];
    const u32 r2 = r[DGST_R2];
    const u32 r3 = r[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}

#endif
