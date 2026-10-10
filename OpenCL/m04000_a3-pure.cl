/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

// Big endian password copy for big endian hash families. See RECIPE_PASS_COPY in inc_recipe.cl.

#define RECIPE_PASS_COPY

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
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

KERNEL_FQ KERNEL_FA void m04000_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  #if (VECT_SIZE > 1) && defined (RECIPE_WIDE)

  // utf16le decodes pass or salt from UTF-8. Only the generated part of w[0] changes in the loop,
  // so check the rest of the password and the salt for bytes above 0x7f once here.

  u32 base_hi = 0;

  #ifdef RECIPE_WIDE_PASS
  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) base_hi |= pws[gid].i[idx];
  #endif

  #ifdef RECIPE_WIDE_SALT
  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1) base_hi |= salt_bufs[SALT_POS_HOST].salt_buf[idx];
  #endif

  const bool base_ascii = ((base_hi & 0x80808080) == 0);

  #endif

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  recipe_prep (&st, s, salt_len);

  // Only the first word changes per candidate. Swap the remaining words once here.

  #ifdef RECIPE_BE_PASS
  u32x wb[64];

  for (u32 i = 0; i < 64; i++) wb[i] = hc_swap32 (w[i]);
  #endif

  /**
   * loop
   */

  const u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    w[0] = w0l | w0r;

    #ifdef RECIPE_BE_PASS
    wb[0] = hc_swap32 (w[0]);
    #endif

    u32x r[16];

    #if (VECT_SIZE > 1) && defined (RECIPE_WIDE)

    #ifdef RECIPE_WIDE_PASS
    const bool lanes_ascii = ((base_ascii == true) && (hc_vector_is_zero (w0r & 0x80808080) == true));
    #else
    const bool lanes_ascii = base_ascii;
    #endif

    if (lanes_ascii == true)
    {
      recipe_eval (&st, w, RECIPE_WB, pw_len, s, salt_len, r);
    }
    else
    {
      recipe_eval_lanes (&st, w, pw_len, s, salt_len, r);
    }

    #else

    recipe_eval (&st, w, RECIPE_WB, pw_len, s, salt_len, r);

    #endif

    const u32x r0 = r[DGST_R0];
    const u32x r1 = r[DGST_R1];
    const u32x r2 = r[DGST_R2];
    const u32x r3 = r[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m04000_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  RECIPE_HEX_DECL

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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  #if (VECT_SIZE > 1) && defined (RECIPE_WIDE)

  // utf16le decodes pass or salt from UTF-8. Only the generated part of w[0] changes in the loop,
  // so check the rest of the password and the salt for bytes above 0x7f once here.

  u32 base_hi = 0;

  #ifdef RECIPE_WIDE_PASS
  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) base_hi |= pws[gid].i[idx];
  #endif

  #ifdef RECIPE_WIDE_SALT
  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1) base_hi |= salt_bufs[SALT_POS_HOST].salt_buf[idx];
  #endif

  const bool base_ascii = ((base_hi & 0x80808080) == 0);

  #endif

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  recipe_prep (&st, s, salt_len);

  // Only the first word changes per candidate. Swap the remaining words once here.

  #ifdef RECIPE_BE_PASS
  u32x wb[64];

  for (u32 i = 0; i < 64; i++) wb[i] = hc_swap32 (w[i]);
  #endif

  /**
   * loop
   */

  const u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    w[0] = w0l | w0r;

    #ifdef RECIPE_BE_PASS
    wb[0] = hc_swap32 (w[0]);
    #endif

    u32x r[16];

    #if (VECT_SIZE > 1) && defined (RECIPE_WIDE)

    #ifdef RECIPE_WIDE_PASS
    const bool lanes_ascii = ((base_ascii == true) && (hc_vector_is_zero (w0r & 0x80808080) == true));
    #else
    const bool lanes_ascii = base_ascii;
    #endif

    if (lanes_ascii == true)
    {
      recipe_eval (&st, w, RECIPE_WB, pw_len, s, salt_len, r);
    }
    else
    {
      recipe_eval_lanes (&st, w, pw_len, s, salt_len, r);
    }

    #else

    recipe_eval (&st, w, RECIPE_WB, pw_len, s, salt_len, r);

    #endif

    const u32x r0 = r[DGST_R0];
    const u32x r1 = r[DGST_R1];
    const u32x r2 = r[DGST_R2];
    const u32x r3 = r[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
