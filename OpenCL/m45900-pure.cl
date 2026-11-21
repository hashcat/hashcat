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
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

typedef struct wallet_sparrow
{
  u32 h2salt[2];  // 8-byte H2 FileEncrypt salt (PBKDF2 stage)
  u32 ct[16];     // first 64 bytes of XTS unit 0 (store-header block)

} wallet_sparrow_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;
  wallet_sparrow_t w;

} merged_options_t;

// MVStore store-header shape gate:
// ^[A-Za-z]{1,12}:[0-9a-fA-F]{1,16}(,|$) over the window, all bytes printable.

DECLSPEC u32 sparrow_structural_ok (PRIVATE_AS const u8 *pt, const int len)
{
  int colon = -1;

  for (int i = 1; i <= 12 && i < len; i++)
  {
    if (pt[i] == ':') { colon = i; break; }

    const u8 c = pt[i];

    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return 0;
  }

  if (colon < 1) return 0;

  const u8 c0 = pt[0];

  if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z'))) return 0;

  int n = 0;
  int i = colon + 1;

  for (; i < len && n < 16; i++)
  {
    const u8 c = pt[i];

    if (c == ',') break;

    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;

    n++;
  }

  if (n == 0) return 0;

  // hex field must be TERMINATED (comma or window end) -- a 17th hex char fails
  if (i < len && pt[i] != ',') return 0;

  for (int j = 0; j < len; j++)
  {
    if (pt[j] < 0x20 || pt[j] > 0x7e) return 0;
  }

  return 1;
}

KERNEL_FQ KERNEL_FA void m45900_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  argon2_init_gg (&pws[gid], &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m45900_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  const u32 lanes = argon2_lane_limit (argon2_options.parallelism, lsz);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < lanes; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m45900_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  /**
   * aes shared (m29400 pattern: fill BEFORE the gid early-out so
   * SYNC_THREADS is reached by every thread of the workgroup)
   */

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
  LOCAL_VK u32 s_te4[256];

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
    s_te4[i] = te4[i];
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
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  GLOBAL_AS const wallet_sparrow_t *w = &esalt_bufs[DIGESTS_OFFSET_HOST].w;

  u32 out[8];

  argon2_final (argon2_block, &argon2_options, out);

  // out[i] = LE-packed u32 of the 32-byte Argon2 digest (byte 4i+j = out[i]>>8j).
  // The digest bytes are the big-endian secp256k1 scalar; secp256k1 wants
  // little-endian limbs (limb[0] = least significant u32).

  u32 prv[8];

  prv[0] = hc_swap32_S (out[7]);
  prv[1] = hc_swap32_S (out[6]);
  prv[2] = hc_swap32_S (out[5]);
  prv[3] = hc_swap32_S (out[4]);
  prv[4] = hc_swap32_S (out[3]);
  prv[5] = hc_swap32_S (out[2]);
  prv[6] = hc_swap32_S (out[1]);
  prv[7] = hc_swap32_S (out[0]);

  // pub = G * priv (curve mul absorbs the mod-N reduction: k*G == (k mod N)*G)

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, prv, &preG);

  // compressed pubkey, BE-packed words (m29400 idiom):
  // byte 0 = 0x02|parity(y), bytes 1..32 = x big-endian

  u32 pub_key[9];

  const u32 type = 0x02 | (y[0] & 1);

  pub_key[8] =               (x[0] << 24);
  pub_key[7] = (x[0] >> 8) | (x[1] << 24);
  pub_key[6] = (x[1] >> 8) | (x[2] << 24);
  pub_key[5] = (x[2] >> 8) | (x[3] << 24);
  pub_key[4] = (x[3] >> 8) | (x[4] << 24);
  pub_key[3] = (x[4] >> 8) | (x[5] << 24);
  pub_key[2] = (x[5] >> 8) | (x[6] << 24);
  pub_key[1] = (x[6] >> 8) | (x[7] << 24);
  pub_key[0] = (x[7] >> 8) | (type << 24);

  // pw16 = utf16be(lowercase hex(pub33)) -- 132 bytes.
  // BE word j = bytes {0x00, hexhi, 0x00, hexlo} of pub byte j.
  // kw[48] fully zeroed: sha256_hmac_init(len=132) reads 3 full 64B blocks
  // (tail-OOB canon: >128B message => >= 48 zeroed words).

  u32 kw[48] = { 0 };

  for (int j = 0; j < 33; j++)
  {
    const u32 b = (pub_key[j / 4] >> (24 - 8 * (j % 4))) & 0xff;

    const u32 hi = b >> 4;
    const u32 lo = b & 15;

    const u32 c_hi = (hi < 10) ? ('0' + hi) : ('a' + hi - 10);
    const u32 c_lo = (lo < 10) ? ('0' + lo) : ('a' + lo - 10);

    kw[j] = (c_hi << 16) | c_lo;
  }

  // PBKDF2-HMAC-SHA256(pw16, h2salt, 10, dkLen 16) -- single block T1.

  sha256_hmac_ctx_t hctx0;

  sha256_hmac_init (&hctx0, kw, 132);

  u32 sm[16] = { 0 };

  sm[0] = hc_swap32_S (w->h2salt[0]);
  sm[1] = hc_swap32_S (w->h2salt[1]);
  sm[2] = 0x00000001; // PBKDF2 block counter INT32_BE(1) -- hashcat idiom

  sha256_hmac_ctx_t hctx = hctx0;

  sha256_hmac_update_64 (&hctx, sm + 0, sm + 4, sm + 8, sm + 12, 12);
  sha256_hmac_final (&hctx);

  u32 T[8];
  u32 U[8];

  for (int i = 0; i < 8; i++) { U[i] = hctx.opad.h[i]; T[i] = U[i]; }

  for (int it = 1; it < 10; it++)
  {
    hctx = hctx0;

    u32 um[16] = { 0 };

    for (int i = 0; i < 8; i++) um[i] = U[i];

    sha256_hmac_update_64 (&hctx, um + 0, um + 4, um + 8, um + 12, 32);
    sha256_hmac_final (&hctx);

    for (int i = 0; i < 8; i++) { U[i] = hctx.opad.h[i]; T[i] ^= U[i]; }
  }

  // hashcat AES words are LE-packed (byte0 = LSB); PBKDF2 output words are
  // BE (sha256 h[] convention) -> swap into LE for the key schedule.

  u32 ukey[4];

  ukey[0] = hc_swap32_S (T[0]);
  ukey[1] = hc_swap32_S (T[1]);
  ukey[2] = hc_swap32_S (T[2]);
  ukey[3] = hc_swap32_S (T[3]);

  u32 ks_e[44];
  u32 ks_d[44];

  aes128_set_encrypt_key (ks_e, ukey, s_te0, s_te1, s_te2, s_te3);
  aes128_set_decrypt_key (ks_d, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  // XTS unit 0, first 2 blocks (32 bytes). tweak0 = AES-128-ECB-enc(key, 0^128)
  // (tweak input = LE128(unit); unit 0 => all zeros). Single-key H2 variant:
  // per block: ct XOR tweak -> AES-dec -> XOR tweak; GF(0x87) tweak update.

  u32 zed[4] = { 0, 0, 0, 0 };
  u32 tweak[4];

  aes128_encrypt (ks_e, zed, tweak, s_te0, s_te1, s_te2, s_te3, s_te4);

  u8 pt[32];

  for (int blk = 0; blk < 2; blk++)
  {
    if (blk > 0)
    {
      u8 tw[16];

      for (int i = 0; i < 4; i++)
      {
        tw[i * 4 + 0] = (tweak[i] >>  0) & 0xff;
        tw[i * 4 + 1] = (tweak[i] >>  8) & 0xff;
        tw[i * 4 + 2] = (tweak[i] >> 16) & 0xff;
        tw[i * 4 + 3] = (tweak[i] >> 24) & 0xff;
      }

      u8 ci = 0;

      for (int i = 0; i < 16; i++)
      {
        const u8 co = tw[i] >> 7;

        tw[i] = (tw[i] << 1) | ci;

        ci = co;
      }

      if (ci) tw[0] ^= 0x87;

      for (int i = 0; i < 4; i++)
      {
        tweak[i] = ((u32) tw[i * 4 + 0] <<  0)
                 | ((u32) tw[i * 4 + 1] <<  8)
                 | ((u32) tw[i * 4 + 2] << 16)
                 | ((u32) tw[i * 4 + 3] << 24);
      }
    }

    // ct from esalt is already LE-packed (parser pack_le) -- feed AES directly.

    u32 ain[4];
    u32 aout[4];

    for (int i = 0; i < 4; i++) ain[i] = w->ct[blk * 4 + i] ^ tweak[i];

    aes128_decrypt (ks_d, ain, aout, s_td0, s_td1, s_td2, s_td3, s_td4);

    for (int i = 0; i < 4; i++)
    {
      const u32 p = aout[i] ^ tweak[i];

      pt[blk * 16 + i * 4 + 0] = (p >>  0) & 0xff;
      pt[blk * 16 + i * 4 + 1] = (p >>  8) & 0xff;
      pt[blk * 16 + i * 4 + 2] = (p >> 16) & 0xff;
      pt[blk * 16 + i * 4 + 3] = (p >> 24) & 0xff;
    }
  }

  const u32 ok = sparrow_structural_ok (pt, 32);

  // boolean oracle: parser pinned digest = 0; emit 0 only on shape match

  const u32 r0 = (ok) ? 0 : 0xffffffff;
  const u32 r1 = (ok) ? 0 : 0xffffffff;
  const u32 r2 = (ok) ? 0 : 0xffffffff;
  const u32 r3 = (ok) ? 0 : 0xffffffff;

  #define il_pos 0

  #include COMPARE_M
}
