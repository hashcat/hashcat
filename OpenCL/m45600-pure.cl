/**
 * SubWallet (polkadot-js keyring) - m45600-pure.cl
 *
 *   key = scrypt(password, salt32, N, r, p, 32)
 *   mac = Poly1305(XSalsa20block0(key, nonce24), ct)   [NaCl secretbox]
 *
 * The scrypt pipeline (PBKDF2 -> BlockMix -> ROMix -> PBKDF2) is the stock
 * hashcat implementation from inc_hash_scrypt.cl; the secretbox verify uses
 * the shared Salsa20/XSalsa20 and Poly1305 primitives from
 * inc_cipher_salsa20.cl and inc_auth_poly1305.cl.
 *
 * License: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_cipher_salsa20.cl)
#include M2S(INCLUDE_PATH/inc_auth_poly1305.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// MUST match module_45600.c field-for-field
typedef struct subwallet_scrypt
{
  u32 nonce[6];         // 24 bytes
  u32 ciphertext[128];  // ct only (tag rides in the digest), up to 512 bytes
  u32 ciphertext_len;

} subwallet_scrypt_t;



KERNEL_FQ KERNEL_FA void m45600_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, subwallet_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m45600_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m45600_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m45600_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, subwallet_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // final scrypt PBKDF2: 32-byte key (out words are LE-packed,
  // i.e. (u8*)out reads as the raw derived key on LE)

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

  // NaCl secretbox verify: poly key = first 32 bytes of XSalsa20 stream

  GLOBAL_AS const subwallet_scrypt_t *esalt = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 nonce[6];

  for (int i = 0; i < 6; i++) nonce[i] = esalt->nonce[i];

  u32 poly_key[8];

  xsalsa20_stream (poly_key, 32, nonce, out);

  // $subwallet$ stores the ct WITHOUT the prepended tag (tag rides in its
  // own line field / the digest), so authenticate from offset 0 - unlike
  // $phantom$'s box, which skips the first 16 bytes.

  poly1305_ctx_t poly1305_ctx;

  poly1305_init (&poly1305_ctx, poly_key);

  poly1305_update_global (&poly1305_ctx, esalt->ciphertext, esalt->ciphertext_len);

  u32 T[4];

  poly1305_final (&poly1305_ctx, T);

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
