/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define BIP38_FLAG_COMPRESSED 0x20

KERNEL_FQ KERNEL_FA void m44300_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m44300_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m44300_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m44300_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;

  #endif

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[16];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 64);

  // The second half of the scrypt output is the AES-256 key. The first half is xored onto the
  // two decrypted blocks, which then hold the private key.

  u32 key[8];

  key[0] = out[ 8];
  key[1] = out[ 9];
  key[2] = out[10];
  key[3] = out[11];
  key[4] = out[12];
  key[5] = out[13];
  key[6] = out[14];
  key[7] = out[15];

  u32 ks[60];

  aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 enc[4];
  u32 dec[4];

  u32 prv[8];

  enc[0] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  enc[1] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  enc[2] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  enc[3] = salt_bufs[SALT_POS_HOST].salt_buf[4];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  prv[0] = dec[0] ^ out[0];
  prv[1] = dec[1] ^ out[1];
  prv[2] = dec[2] ^ out[2];
  prv[3] = dec[3] ^ out[3];

  enc[0] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  enc[1] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  enc[2] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  enc[3] = salt_bufs[SALT_POS_HOST].salt_buf[8];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  prv[4] = dec[0] ^ out[4];
  prv[5] = dec[1] ^ out[5];
  prv[6] = dec[2] ^ out[6];
  prv[7] = dec[3] ^ out[7];

  // point_mul_xy () takes the scalar as 32 bit words, least significant word first

  u32 k[8];

  k[0] = hc_swap32_S (prv[7]);
  k[1] = hc_swap32_S (prv[6]);
  k[2] = hc_swap32_S (prv[5]);
  k[3] = hc_swap32_S (prv[4]);
  k[4] = hc_swap32_S (prv[3]);
  k[5] = hc_swap32_S (prv[2]);
  k[6] = hc_swap32_S (prv[1]);
  k[7] = hc_swap32_S (prv[0]);

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, k, &preG);

  u32 h160[5];

  const u32 flag = salt_bufs[SALT_POS_HOST].salt_buf[9];

  if ((flag & BIP38_FLAG_COMPRESSED) == BIP38_FLAG_COMPRESSED)
  {
    hash160_pubkey_compressed (h160, x, y);
  }
  else
  {
    hash160_pubkey_uncompressed (h160, x, y);
  }

  // the addresshash is the start of sha256 (sha256 ()) of the P2PKH address as text

  u32 address[16] = { 0 };

  u32 address_len = sizeof (address);

  b58check_enc ((PRIVATE_AS u8 *) address, &address_len, 0, (PRIVATE_AS const u8 *) h160, 20);

  sha256_ctx_t ctx;

  sha256_init        (&ctx);
  sha256_update_swap (&ctx, address, address_len - 1);
  sha256_final       (&ctx);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = ctx.h[0];
  w0[1] = ctx.h[1];
  w0[2] = ctx.h[2];
  w0[3] = ctx.h[3];
  w1[0] = ctx.h[4];
  w1[1] = ctx.h[5];
  w1[2] = ctx.h[6];
  w1[3] = ctx.h[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_init      (&ctx);
  sha256_update_64 (&ctx, w0, w1, w2, w3, 32);
  sha256_final     (&ctx);

  const u32 r0 = ctx.h[0];
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
