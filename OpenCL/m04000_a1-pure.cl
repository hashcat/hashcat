/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// the password reaches the recipe as the base word and the right word, see RECIPE_TAIL

#define RECIPE_TAIL_KERNEL

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
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

KERNEL_FQ KERNEL_FA void m04000_mxx (KERN_ATTR_BASIC ())
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

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  recipe_prep (&st, s, salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 r[16];

    #ifdef RECIPE_TAIL
    const bool split = true;
    #else
    const bool split = false;
    #endif

    if ((split == true) && (COMBS_IS_MIDDLE == 0))
    {
      RECIPE_EVAL_TAIL (&st, w, pw_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, s, salt_len, r);
    }
    else
    {
      // Attack mode 12 can put one mask part before the base word and two between the base and right
      // words. All threads use the same il_pos, so these branches are uniform.

      u32 c[64];

      u32 c_len = 0;

      if ((COMBS_IS_MIDDLE) && (COMBS_PRE (il_pos).pw_len > 0))
      {
        for (u32 i = 0; i < 64; i++) c[i] = 0;

        c_len = recipe_append_global (c, c_len, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        c_len = recipe_append_global (c, c_len, pws[gid].i, pw_len);
      }
      else
      {
        for (u32 i = 0; i < 64; i++) c[i] = w[i];

        c_len = pw_len;
      }

      if (COMBS_IS_MIDDLE)
      {
        c_len = recipe_append_global (c, c_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
        c_len = recipe_append_global (c, c_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
      }

      // the last piece is the right word under RECIPE_TAIL, and part of the copy otherwise

      if (split == false) c_len = recipe_append_global (c, c_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

      RECIPE_EVAL_TAIL (&st, c, c_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, s, salt_len, r);
    }

    const u32 r0 = r[DGST_R0];
    const u32 r1 = r[DGST_R1];
    const u32 r2 = r[DGST_R2];
    const u32 r3 = r[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m04000_sxx (KERN_ATTR_BASIC ())
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

  // Prepare work independent of the candidate once per salt.

  recipe_state_t st;

  RECIPE_HEX_BIND (&st)

  recipe_prep (&st, s, salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 r[16];

    #ifdef RECIPE_TAIL
    const bool split = true;
    #else
    const bool split = false;
    #endif

    if ((split == true) && (COMBS_IS_MIDDLE == 0))
    {
      RECIPE_EVAL_TAIL (&st, w, pw_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, s, salt_len, r);
    }
    else
    {
      // Attack mode 12 can put one mask part before the base word and two between the base and right
      // words. All threads use the same il_pos, so these branches are uniform.

      u32 c[64];

      u32 c_len = 0;

      if ((COMBS_IS_MIDDLE) && (COMBS_PRE (il_pos).pw_len > 0))
      {
        for (u32 i = 0; i < 64; i++) c[i] = 0;

        c_len = recipe_append_global (c, c_len, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        c_len = recipe_append_global (c, c_len, pws[gid].i, pw_len);
      }
      else
      {
        for (u32 i = 0; i < 64; i++) c[i] = w[i];

        c_len = pw_len;
      }

      if (COMBS_IS_MIDDLE)
      {
        c_len = recipe_append_global (c, c_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
        c_len = recipe_append_global (c, c_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
      }

      // the last piece is the right word under RECIPE_TAIL, and part of the copy otherwise

      if (split == false) c_len = recipe_append_global (c, c_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

      RECIPE_EVAL_TAIL (&st, c, c_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, s, salt_len, r);
    }

    const u32 r0 = r[DGST_R0];
    const u32 r1 = r[DGST_R1];
    const u32 r2 = r[DGST_R2];
    const u32 r3 = r[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
