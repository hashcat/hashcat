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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_bip39.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

/*******************************************************************************
 * This section is adapted from the optimized scalar_8x32 operations from
 * https://github.com/bitcoin-core/secp256k1/, MIT license
 ******************************************************************************/

// Represents the extended private key and chain code (each 256-bits)
typedef struct extended_key
{
  // private_key is stored in reverse order for secp256k1 algorithms
  u32 private_key[8];
  u32 chain_code[8];
} extended_key_t;

#define SECP256K1_N_C_0 (~SECP256K1_N0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N1)
#define SECP256K1_N_C_2 (~SECP256K1_N2)
#define SECP256K1_N_C_3 (~SECP256K1_N3)
#define SECP256K1_N_C_4 (1)

DECLSPEC int secp256k1_scalar_check_overflow (const u32 * a)
{
  int yes = 0;
  int no = 0;

  no |= (a[7] < SECP256K1_N7);  /* No need for a > check. */
  no |= (a[6] < SECP256K1_N6);  /* No need for a > check. */
  no |= (a[5] < SECP256K1_N5);  /* No need for a > check. */
  no |= (a[4] < SECP256K1_N4);
  yes |= (a[4] > SECP256K1_N4) & ~no;
  no |= (a[3] < SECP256K1_N3) & ~yes;
  yes |= (a[3] > SECP256K1_N3) & ~no;
  no |= (a[2] < SECP256K1_N2) & ~yes;
  yes |= (a[2] > SECP256K1_N2) & ~no;
  no |= (a[1] < SECP256K1_N1) & ~yes;
  yes |= (a[1] > SECP256K1_N1) & ~no;
  yes |= (a[0] >= SECP256K1_N0) & ~no;
  return yes;
}

DECLSPEC void secp256k1_scalar_reduce (u32 * r, u32 overflow)
{
  u64 t;

  t = (u64) r[0] + overflow * SECP256K1_N_C_0;
  r[0] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[1] + overflow * SECP256K1_N_C_1;
  r[1] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[2] + overflow * SECP256K1_N_C_2;
  r[2] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[3] + overflow * SECP256K1_N_C_3;
  r[3] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[4] + overflow * SECP256K1_N_C_4;
  r[4] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[5];
  r[5] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[6];
  r[6] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) r[7];
  r[7] = t & 0xFFFFFFFFUL;
}

DECLSPEC void secp256k1_scalar_add (u32 * r, const u32 * a, const u32 * b)
{
  int overflow;
  u64 t = (u64) a[0] + b[0];

  r[0] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[1] + b[1];
  r[1] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[2] + b[2];
  r[2] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[3] + b[3];
  r[3] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[4] + b[4];
  r[4] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[5] + b[5];
  r[5] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[6] + b[6];
  r[6] = t & 0xFFFFFFFFUL;
  t >>= 32;
  t += (u64) a[7] + b[7];
  r[7] = t & 0xFFFFFFFFUL;
  t >>= 32;
  overflow = t + secp256k1_scalar_check_overflow (r);
  secp256k1_scalar_reduce (r, overflow);
}

/*******************************************************************************
 * This section includes functions for encoding messages into u32 output buffers
 * necessary for generating various hashes.
 ******************************************************************************/

// Encodes the passphrase as specified in BIP-39
DECLSPEC void encode_passphrase (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * password, PRIVATE_AS const u32 password_len, PRIVATE_AS const u32 start_index)
{
  const char salt[] = "mnemonic";

  for (u32 i = 0; i < 8; i++)
  {
    encode_char (encoder, salt[i]);
  }

  encode_array_le (encoder, password, password_len, start_index);
}

// Encodes the derived 33 byte compressed public key for a given private_key
DECLSPEC void encode_compressed_public_key (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const extended_key_t * key)
{
  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  u32 x[8];
  u32 y[8];

  // This next line reduces performance by ~40% compared to the pure 2048 round PBKDF2-HMAC-SHA512 derivation
  // Possibly could be eliminated through precalculation as in https://github.com/XopMC/CudaBrainSecp
  point_mul_xy (x, y, key->private_key, &preG);

  encode_char (encoder, 0x02 | (y[0] & 1));
  for (int i = 0; i < 8; i++)
  {
    encode_array_be (encoder, &x[7 - i], 4, 0);
  }
}

/*******************************************************************************
 * This section runs contains some common cryptographic helper functions.
 ******************************************************************************/

// Run another iteration of PBKDF2-HMAC-SHA512, optimized for loops
DECLSPEC void run_sha512_hmac_iter (PRIVATE_AS u32x * w0, PRIVATE_AS u32x * w1, PRIVATE_AS u32x * w2, PRIVATE_AS u32x * w3, PRIVATE_AS u32x * w4, PRIVATE_AS u32x * w5, PRIVATE_AS u32x * w6, PRIVATE_AS u32x * w7, PRIVATE_AS u64x * ipad, PRIVATE_AS u64x * opad, PRIVATE_AS u64x * digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

// Runs a single iteration of SHA512-HMAC to create an extended key
DECLSPEC extended_key_t run_sha512_hmac (PRIVATE_AS const u32 * key, PRIVATE_AS u32 key_bytes, PRIVATE_AS u32 * msg, PRIVATE_AS u32 msg_bytes)
{
  // SHA512-HMAC requires length 32 arrays initialized to 0
  u32 key_buf[32] = { 0 };
  u32 msg_buf[32] = { 0 };

  for (u32 i = 0; i * 4 < key_bytes; i++)
  {
    key_buf[i] = key[i];
  }

  for (u32 i = 0; i * 4 < msg_bytes; i++)
  {
    msg_buf[i] = msg[i];
  }

  // Run SHA512-HMAC algorithm on key and message
  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init (&sha512_hmac_ctx, key_buf, key_bytes);
  sha512_hmac_update (&sha512_hmac_ctx, msg_buf, msg_bytes);
  sha512_hmac_final (&sha512_hmac_ctx);

  // Split the 512-bit result into 256-bit private_key (reversed) and 256-bit chain_code
  extended_key_t extended;

  for (int i = 0; i < 4; i++)
  {
    int j = i * 2;

    extended.private_key[7 - j] = h32_from_64_S (sha512_hmac_ctx.opad.h[i]);
    extended.private_key[6 - j] = l32_from_64_S (sha512_hmac_ctx.opad.h[i]);
  }

  for (int i = 4; i < 8; i++)
  {
    int j = (i - 4) * 2;

    extended.chain_code[j] = h32_from_64_S (sha512_hmac_ctx.opad.h[i]);
    extended.chain_code[j + 1] = l32_from_64_S (sha512_hmac_ctx.opad.h[i]);
  }

  return extended;
}

// Calculates HASH160 given a message, defined as RIPE160(SHA256(msg))
DECLSPEC ripemd160_ctx_t run_hash160 (PRIVATE_AS const u32 * msg, PRIVATE_AS const u32 msg_bytes)
{
  // SHA256 requires length 16 arrays initialized to 0
  u32 msg_buf[32] = { 0 };
  for (u32 i = 0; i * 4 < msg_bytes; i++)
  {
    msg_buf[i] = msg[i];
  }

  sha256_ctx_t ctx;

  sha256_init (&ctx);
  sha256_update (&ctx, msg_buf, msg_bytes);
  sha256_final (&ctx);

  for (u32 i = 8; i < 16; i++)
    ctx.h[i] = 0;

  ripemd160_ctx_t rctx;

  ripemd160_init (&rctx);
  ripemd160_update_swap (&rctx, ctx.h, 32);
  ripemd160_final (&rctx);
  return rctx;
}

/*******************************************************************************
 * This section specifies how to derive extended private keys from secrets
 * according to the BIP-32 specification.
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 ******************************************************************************/

// Derives the BIP32 master extended key from a 512-bit seed
DECLSPEC extended_key_t extended_key_master (PRIVATE_AS const u64 * seed)
{
  u32 master_seed[16] = { 0 };
  for (int i = 0; i < 8; i++)
  {
    int j = i * 2;

    master_seed[j + 1] = l32_from_64_S (seed[i]);
    master_seed[j] = h32_from_64_S (seed[i]);
  }

  // Encoding of "Bitcoin seed" from BIP32
  u32 bitcoin_seed[3] = { 0x42697463, 0x6f696e20, 0x73656564 };

  return run_sha512_hmac (bitcoin_seed, 12, master_seed, 64);
}

// Helper for tweaking the child key with the parent key
DECLSPEC void extended_key_tweak (extended_key_t * key, const extended_key_t * tweak)
{
  secp256k1_scalar_add (key->private_key, key->private_key, tweak->private_key);
}

// Derives the BIP32 hardened child key
DECLSPEC extended_key_t extended_key_hardened (PRIVATE_AS const extended_key_t * parent_key, PRIVATE_AS const u32 i)
{
  u32 output[32] = { 0 };
  msg_encoder_t encoder = encoder_init (output);

  encode_char (&encoder, 0);
  for (int i = 0; i < 8; i++)
  {
    encode_array_be (&encoder, &parent_key->private_key[7 - i], 4, 0);
  }
  encode_array_be (&encoder, &i, 4, 0);

  extended_key_t child_key = run_sha512_hmac (parent_key->chain_code, 32, output, encoder.len);

  extended_key_tweak (&child_key, parent_key);

  return child_key;
}

// Derives the BIP32 normal child key
DECLSPEC extended_key_t extended_key_normal (PRIVATE_AS const extended_key_t * parent_key, PRIVATE_AS const u32 i)
{
  u32 output[32] = { 0 };
  msg_encoder_t encoder = encoder_init (output);

  encode_compressed_public_key (&encoder, parent_key);
  encode_array_be (&encoder, &i, 4, 0);

  extended_key_t child_key = run_sha512_hmac (parent_key->chain_code, 32, output, encoder.len);

  extended_key_tweak (&child_key, parent_key);

  return child_key;
}

// Derives the BIP32 key using the derivation path
DECLSPEC extended_key_t extended_key_derivation (PRIVATE_AS u64 * seed, PRIVATE_AS const u32 * derivation)
{
  extended_key_t key = extended_key_master (seed);

  for (int i = 0; derivation[i] != DERIVATION_END; i++)
  {
    if (derivation[i] >= DERIVATION_HARDENED)
    {
      key = extended_key_hardened (&key, derivation[i]);
    }
    else
    {
      key = extended_key_normal (&key, derivation[i]);
    }
  }

  return key;
}

DECLSPEC void printf_array (const u32 * bytes, const u32 len)
{
  printf ("\n'");
  for (int i = 0; i <= len / 4; i++)
  {
    printf ("%c", bytes[i] >> 24 & 0xff);
    printf ("%c", bytes[i] >> 16 & 0xff);
    printf ("%c", bytes[i] >> 8 & 0xff);
    printf ("%c", bytes[i] >> 0 & 0xff);
  }
  printf ("'");
}

// Debugging for printing out the private key followed by a ' ' then the chain code
DECLSPEC void extended_key_printf (extended_key_t * key)
{
  for (int i = 0; i < 8; i++)
  {
    printf ("%08x", key->private_key[7 - i]);
  }
  printf (" ");
  for (int i = 0; i < 8; i++)
  {
    printf ("%08x", key->chain_code[i]);
  }
}

/*******************************************************************************
 * This section contains the init, loop, and comp functions required by the pure
 * kernel modules.
 ******************************************************************************/

// Initialize the PBKDF2-SHA512 with the mnemonic and passphrase as described in BIP-32
KERNEL_FQ void m28510_init (KERN_ATTR_TMPS (bip39_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  // Get the BIP39 word list
  u32 pw_index = 0;
  u32 words[25] = { MNEMONIC_END };
  pw_index = bip39_guess_words (pws[gid].i, salt_bufs[SALT_POS_HOST].salt_buf, words);
  tmps[gid].salt_index = SALT_POS_HOST;

  u32 mnemonic[64] = { 0 };
  msg_encoder_t mnemonic_encoder = encoder_init (mnemonic);

  encode_mnemonic_phrase (&mnemonic_encoder, words);

  u32 passphrase[64] = { 0 };
  msg_encoder_t passphrase_encoder = encoder_init (passphrase);

  encode_passphrase (&passphrase_encoder, pws[gid].i, pws[gid].pw_len, pw_index);

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init (&sha512_hmac_ctx, mnemonic, mnemonic_encoder.len);

  for (int i = 0; i < 8; i++)
  {
    tmps[gid].ipad[i] = sha512_hmac_ctx.ipad.h[i];
    tmps[gid].opad[i] = sha512_hmac_ctx.opad.h[i];
  }

  sha512_hmac_update (&sha512_hmac_ctx, passphrase, passphrase_encoder.len);

  u32 w0[4] = { 1, 0, 0, 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };
  u32 w4[4] = { 0 };
  u32 w5[4] = { 0 };
  u32 w6[4] = { 0 };
  u32 w7[4] = { 0 };

  sha512_hmac_update_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&sha512_hmac_ctx);

  for (int i = 0; i < 8; i++)
  {
    tmps[gid].dgst[i] = sha512_hmac_ctx.opad.h[i];
    tmps[gid].out[i] = sha512_hmac_ctx.opad.h[i];
  }
}

// Identical to most modules that run PBKDF2-HMAC-SHA512 iterations
KERNEL_FQ void m28510_loop (KERN_ATTR_TMPS (bip39_tmp_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT)
    return;

  u64x ipad[8];
  u64x opad[8];

  for (u32 i = 0; i < 8; i++)
  {
    ipad[i] = pack64v (tmps, ipad, gid, i);
    opad[i] = pack64v (tmps, opad, gid, i);
  }

  u64x dgst[8];
  u64x out[8];

  for (u32 i = 0; i < 8; i++)
  {
    dgst[i] = pack64v (tmps, dgst, gid, i);
    out[i] = pack64v (tmps, out, gid, i);
  }

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];
    u32x w4[4];
    u32x w5[4];
    u32x w6[4];
    u32x w7[4];

    w0[0] = h32_from_64 (dgst[0]);
    w0[1] = l32_from_64 (dgst[0]);
    w0[2] = h32_from_64 (dgst[1]);
    w0[3] = l32_from_64 (dgst[1]);
    w1[0] = h32_from_64 (dgst[2]);
    w1[1] = l32_from_64 (dgst[2]);
    w1[2] = h32_from_64 (dgst[3]);
    w1[3] = l32_from_64 (dgst[3]);
    w2[0] = h32_from_64 (dgst[4]);
    w2[1] = l32_from_64 (dgst[4]);
    w2[2] = h32_from_64 (dgst[5]);
    w2[3] = l32_from_64 (dgst[5]);
    w3[0] = h32_from_64 (dgst[6]);
    w3[1] = l32_from_64 (dgst[6]);
    w3[2] = h32_from_64 (dgst[7]);
    w3[3] = l32_from_64 (dgst[7]);
    w4[0] = 0x80000000;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = (128 + 64) * 8;

    run_sha512_hmac_iter (w0, w1, w2, w3, w4, w5, w6, w7, ipad, opad, dgst);

    for (u32 i = 0; i < 8; i++)
    {
      out[i] ^= dgst[i];
    }
  }

  for (u32 i = 0; i < 8; i++)
  {
    unpack64v (tmps, dgst, gid, i, dgst[i]);
    unpack64v (tmps, out, gid, i, out[i]);
  }
}

// Final digest comparison depends on the address type
KERNEL_FQ void m28510_comp (KERN_ATTR_TMPS (bip39_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  // Get hardened 512-bit seed and useful salt values
  u64 *seed = tmps[gid].out;
  const u32 address_id = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 *derivation_path = &salt_bufs[SALT_POS_HOST].salt_buf[1];

  // 128-bits that get compared with the digest bits
  u32 r0;
  u32 r1;
  u32 r2;
  u32 r3;

  if (address_id == XPUB_ADDRESS_ID)
  {
    extended_key_t master_key = extended_key_master (seed);

    r0 = hc_swap32_S (master_key.chain_code[0]);
    r1 = hc_swap32_S (master_key.chain_code[1]);
    r2 = hc_swap32_S (master_key.chain_code[2]);
    r3 = hc_swap32_S (master_key.chain_code[3]);
  }
  else if (address_id == P2PKH_ADDRESS_ID || address_id == P2WPKH_ADDRESS_ID)
  {
    const extended_key_t key = extended_key_derivation (seed, derivation_path);

    u32 pubkey[9] = { 0 };
    msg_encoder_t pubkey_encoder = encoder_init (pubkey);

    encode_compressed_public_key (&pubkey_encoder, &key);
    ripemd160_ctx_t hash160 = run_hash160 (pubkey, pubkey_encoder.len);

    r0 = hash160.h[0];
    r1 = hash160.h[1];
    r2 = hash160.h[2];
    r3 = hash160.h[3];
  }
  else if (address_id == P2SHWPKH_ADDRESS_ID)
  {
    const extended_key_t key = extended_key_derivation (seed, derivation_path);

    u32 pubkey[9] = { 0 };
    msg_encoder_t pubkey_encoder = encoder_init (pubkey);

    encode_compressed_public_key (&pubkey_encoder, &key);
    ripemd160_ctx_t hash160 = run_hash160 (pubkey, pubkey_encoder.len);

    u32 script[9] = { 0 };
    msg_encoder_t script_encoder = encoder_init (script);

    encode_char (&script_encoder, 0x0);
    encode_char (&script_encoder, 0x14);
    encode_array_le (&script_encoder, hash160.h, 20, 0);
    ripemd160_ctx_t script_hash160 = run_hash160 (script, script_encoder.len);

    r0 = script_hash160.h[0];
    r1 = script_hash160.h[1];
    r2 = script_hash160.h[2];
    r3 = script_hash160.h[3];
  }

#define il_pos 0

#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
}
