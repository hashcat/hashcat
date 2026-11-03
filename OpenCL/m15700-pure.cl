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
#include M2S(INCLUDE_PATH/inc_hash_sha3.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define ETHEREUM_CT_MAX 256

typedef struct ethereum_scrypt
{
  u32 salt_buf[16];

  u32 ciphertext[ETHEREUM_CT_MAX / 4];
  u32 ciphertext_len;

} ethereum_scrypt_t;

KERNEL_FQ KERNEL_FA void m15700_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, ethereum_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m15700_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m15700_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m15700_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, ethereum_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

  /**
   * keccak
   */

  u32 key[4];

  key[0] = out[4];
  key[1] = out[5];
  key[2] = out[6];
  key[3] = out[7];

  sha3_ctx_t ctx;

  sha3_init (&ctx, 32, SHA3_PAD_KECCAK);

  sha3_update (&ctx, key, 16);

  sha3_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext, esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext_len);

  sha3_final (&ctx);

  const u32 r0 = l32_from_64_S (ctx.st[0]);
  const u32 r1 = h32_from_64_S (ctx.st[0]);
  const u32 r2 = l32_from_64_S (ctx.st[1]);
  const u32 r3 = h32_from_64_S (ctx.st[1]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
