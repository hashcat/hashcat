/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  u32 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

KERNEL_FQ void HC_ATTR_SEQ m08900_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out[SCRYPT_CNT4];

  scrypt_pbkdf2_gg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, out, SCRYPT_SZ);

  scrypt_blockmix_in (out, SCRYPT_SZ);

  for (u32 i = 0; i < SCRYPT_CNT4; i++) tmps[gid].P[i] = out[i];
}

KERNEL_FQ void HC_ATTR_SEQ m08900_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].P + (SALT_REPEAT * STATE_CNT4);

  for (u32 z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_init (X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);

  for (u32 z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void HC_ATTR_SEQ m08900_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].P + (SALT_REPEAT * STATE_CNT4);

  for (u32 z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_loop (X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);

  for (u32 z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void HC_ATTR_SEQ m08900_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 x[SCRYPT_CNT4];

  for (u32 i = 0; i < SCRYPT_CNT4; i++) x[i] = tmps[gid].P[i];

  scrypt_blockmix_out (x, SCRYPT_SZ);

  u32 out[4];

  scrypt_pbkdf2_gp (pws[gid].i, pws[gid].pw_len, x, SCRYPT_SZ, out, 16);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
