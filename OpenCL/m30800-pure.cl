/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * TronLink Wallet keystore
 *
 * Algorithm:
 *   dk          = PBKDF2-HMAC-SHA512 (password, salt, 1, 32)
 *   private_key = AES-256-CTR (dk) over the stored ciphertext
 *
 * The counter block is 16 bytes big endian and starts at 1, which is the aes-js default the
 * wallet relies on rather than a value it passes. The plaintext is the private key as a 64
 * character hex string, so a candidate can be judged on the plaintext alone and the wallet's own
 * address check needs no elliptic curve work. The case is not fixed: the tronscan wizard that
 * writes these files builds the string with byteArray2hexStr, whose alphabet is upper case, while
 * the extension's own key derivation produces lower case. Both are accepted, and a wrong candidate
 * survives the test with probability 2^-227.
 *
 * Kernel architecture:
 *   init: the single PBKDF2 pass, stored in tmps
 *   loop: no-op, the KDF has one iteration
 *   comp: AES-256-CTR and the hex test
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// 16 words and the 4 blocks below are the module's TRONLINK_CT_LEN of 64 bytes, which a kernel
// cannot share with the host. Both have to move if that changes.

typedef struct tronlink
{
  u32 ciphertext[16];

} tronlink_t;

typedef struct tronlink_tmp
{
  u64 out[4];

} tronlink_tmp_t;

KERNEL_FQ KERNEL_FA void m30800_init (KERN_ATTR_TMPS_ESALT (tronlink_tmp_t, tronlink_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_hmac_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // PBKDF2 block index, big endian. One block covers the 32 bytes the wallet derives.

  u32 w0[4] = { 1, 0, 0, 0 };
  u32 w1[4] = { 0, 0, 0, 0 };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, 0, 0 };
  u32 w4[4] = { 0, 0, 0, 0 };
  u32 w5[4] = { 0, 0, 0, 0 };
  u32 w6[4] = { 0, 0, 0, 0 };
  u32 w7[4] = { 0, 0, 0, 0 };

  sha512_hmac_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&ctx);

  tmps[gid].out[0] = ctx.opad.h[0];
  tmps[gid].out[1] = ctx.opad.h[1];
  tmps[gid].out[2] = ctx.opad.h[2];
  tmps[gid].out[3] = ctx.opad.h[3];
}

KERNEL_FQ KERNEL_FA void m30800_loop (KERN_ATTR_TMPS_ESALT (tronlink_tmp_t, tronlink_t))
{
  // No-op: the KDF runs a single iteration, so init leaves nothing to carry forward
}

KERNEL_FQ KERNEL_FA void m30800_comp (KERN_ATTR_TMPS_ESALT (tronlink_tmp_t, tronlink_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  // The upper case AES entry points take big endian words, which is what the sha512 context holds
  // and what the parser stores the ciphertext as, so nothing is byte swapped here. m09600 reads a
  // sha512 digest into an AES-256 key the same way.

  u32 ukey[8];

  ukey[0] = h32_from_64_S (tmps[gid].out[0]);
  ukey[1] = l32_from_64_S (tmps[gid].out[0]);
  ukey[2] = h32_from_64_S (tmps[gid].out[1]);
  ukey[3] = l32_from_64_S (tmps[gid].out[1]);
  ukey[4] = h32_from_64_S (tmps[gid].out[2]);
  ukey[5] = l32_from_64_S (tmps[gid].out[2]);
  ukey[6] = h32_from_64_S (tmps[gid].out[3]);
  ukey[7] = l32_from_64_S (tmps[gid].out[3]);

  u32 ks[60];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  // All 64 plaintext bytes are tested, but only the first block is computed for all but about one
  // candidate in 2^57, because a wrong one already fails the hex test there.

  for (u32 i = 0; i < 4; i++)
  {
    u32 ctr[4];

    ctr[0] = 0;
    ctr[1] = 0;
    ctr[2] = 0;
    ctr[3] = 1 + i;

    u32 ks_block[4];

    AES256_encrypt (ks, ctr, ks_block, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 o = i * 4;

    u32 pt[4];

    pt[0] = esalt_bufs[digest_cur].ciphertext[o + 0] ^ ks_block[0];
    pt[1] = esalt_bufs[digest_cur].ciphertext[o + 1] ^ ks_block[1];
    pt[2] = esalt_bufs[digest_cur].ciphertext[o + 2] ^ ks_block[2];
    pt[3] = esalt_bufs[digest_cur].ciphertext[o + 3] ^ ks_block[3];

    if (is_valid_hex_32_incl_uppercase (pt[0]) == 0) return;
    if (is_valid_hex_32_incl_uppercase (pt[1]) == 0) return;
    if (is_valid_hex_32_incl_uppercase (pt[2]) == 0) return;
    if (is_valid_hex_32_incl_uppercase (pt[3]) == 0) return;
  }

  const u32 r0 = esalt_bufs[digest_cur].ciphertext[0];
  const u32 r1 = esalt_bufs[digest_cur].ciphertext[1];
  const u32 r2 = esalt_bufs[digest_cur].ciphertext[2];
  const u32 r3 = esalt_bufs[digest_cur].ciphertext[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
