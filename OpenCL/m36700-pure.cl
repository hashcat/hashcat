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
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// A Byron era Daedalus secret.key stores a spending password check beside each encrypted key, as
// the string log2(N)|r|p|salt|hash. The check is scrypt over the CBOR encoding of BLAKE2b-256 of
// the password, compared with the stored hash. CBOR writes a 32 byte string as 0x58 0x20 and the
// bytes, so the scrypt input is 34 bytes long.
//
// The scrypt helpers byte swap what they are given, so the key material is built in host byte
// order, and BLAKE2b already produces its digest little endian inside each 64 bit word.

DECLSPEC void cardano_key_material (GLOBAL_AS const u32 *pw_buf, const u32 pw_len, PRIVATE_AS u32 *km)
{
  blake2b_ctx_t ctx;

  blake2b_256_init (&ctx);

  blake2b_update_global (&ctx, pw_buf, pw_len);

  blake2b_final (&ctx);

  u32 w[8];

  w[0] = l32_from_64_S (ctx.h[0]);
  w[1] = h32_from_64_S (ctx.h[0]);
  w[2] = l32_from_64_S (ctx.h[1]);
  w[3] = h32_from_64_S (ctx.h[1]);
  w[4] = l32_from_64_S (ctx.h[2]);
  w[5] = h32_from_64_S (ctx.h[2]);
  w[6] = l32_from_64_S (ctx.h[3]);
  w[7] = h32_from_64_S (ctx.h[3]);

  // the two CBOR bytes shift the whole digest along by 16 bits

  km[0] = 0x2058 | (w[0] << 16);

  for (int i = 1; i < 8; i++) km[i] = (w[i - 1] >> 16) | (w[i] << 16);

  km[8] = w[7] >> 16;
}

KERNEL_FQ KERNEL_FA void m36700_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 km[16] = { 0 };

  cardano_key_material (pws[gid].i, pws[gid].pw_len, km);

  scrypt_pbkdf2_pgg (km, 34, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m36700_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m36700_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m36700_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 km[16] = { 0 };

  cardano_key_material (pws[gid].i, pws[gid].pw_len, km);

  u32 out[8];

  scrypt_pbkdf2_pgp (km, 34, tmps[gid].in, SCRYPT_SZ, out, 32);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
