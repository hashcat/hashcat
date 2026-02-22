/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * MultiBit HD - bridge-compatible kernel for scrypt-jane bridge
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// fixed MultiBit salt (not a bug)

#define MULTIBIT_S0 0x35510380
#define MULTIBIT_S1 0x75a3b0c5

#define MULTIBIT_IV0 0x1f3944a3
#define MULTIBIT_IV1 0xb3118353
#define MULTIBIT_IV2 0x16865429
#define MULTIBIT_IV3 0x3e7289c4

#define SCRYPT_R_MAX 16
#define SCRYPT_P_MAX 16

#define SCRYPT_TMP_SIZE (128ULL * SCRYPT_R_MAX * SCRYPT_P_MAX)
#define SCRYPT_TMP_SIZE4 (SCRYPT_TMP_SIZE / 4)

typedef struct
{
  u32 P[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

DECLSPEC int is_valid_bitcoinj_8 (const u8 v)
{
  // .abcdefghijklmnopqrstuvwxyz

  if (v > (u8) 'z') return 0;
  if (v < (u8) '.') return 0;

  if ((v > (u8) '.') && (v < (u8) 'a')) return 0;

  return 1;
}

DECLSPEC int is_valid_bitcoinj (PRIVATE_AS const u32 *w)
{
  if ((w[0] & 0x000000ff) != 0x0000000a) return 0;

  if ((w[0] & 0x0000ff00)  > 0x00007f00) return 0;

  // check for "org." substring:

  if ((w[0] & 0xffff0000) != 0x726f0000) return 0;
  if ((w[1] & 0x0000ffff) != 0x00002e67) return 0;

  if (is_valid_bitcoinj_8 (w[1] >> 16) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[1] >> 24) == 0) return 0;

  if (is_valid_bitcoinj_8 (w[2] >>  0) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >>  8) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >> 16) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >> 24) == 0) return 0;

  if (is_valid_bitcoinj_8 (w[3] >>  0) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[3] >>  8) == 0) return 0;

  return 1;
}

KERNEL_FQ KERNEL_FA void m70500_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // UTF8 -> UTF16LE -> UTF16BE password conversion

  u32 w[128] = { 0 };

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  const int w_len = hc_enc_next_global (&hc_enc, pws[gid].i, pws[gid].pw_len, 256, w, sizeof (w));

  if (w_len == -1) return;

  // utf16le to utf16be
  for (int i = 0, j = 0; i < w_len; i += 4, j += 1)
  {
    w[j] = ((w[j] >> 8) & 0x00ff00ff)
         | ((w[j] << 8) & 0xff00ff00);
  }

  // Fixed MultiBit salt, swap32'd
  u32 s[16] = { 0 };

  s[0] = hc_swap32_S (MULTIBIT_S0);
  s[1] = hc_swap32_S (MULTIBIT_S1);

  // 1st PBKDF2-SHA256: HMAC key = UTF16BE password (private), salt = s[] (private)
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, w, w_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, s, 8);

  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0, k = 1; i < x_bytes; i += 32, j += 8, k += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = k;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    u32 digest[8];

    digest[0] = sha256_hmac_ctx2.opad.h[0];
    digest[1] = sha256_hmac_ctx2.opad.h[1];
    digest[2] = sha256_hmac_ctx2.opad.h[2];
    digest[3] = sha256_hmac_ctx2.opad.h[3];
    digest[4] = sha256_hmac_ctx2.opad.h[4];
    digest[5] = sha256_hmac_ctx2.opad.h[5];
    digest[6] = sha256_hmac_ctx2.opad.h[6];
    digest[7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].P[j + 0] = hc_swap32_S (digest[0]);
    tmps[gid].P[j + 1] = hc_swap32_S (digest[1]);
    tmps[gid].P[j + 2] = hc_swap32_S (digest[2]);
    tmps[gid].P[j + 3] = hc_swap32_S (digest[3]);
    tmps[gid].P[j + 4] = hc_swap32_S (digest[4]);
    tmps[gid].P[j + 5] = hc_swap32_S (digest[5]);
    tmps[gid].P[j + 6] = hc_swap32_S (digest[6]);
    tmps[gid].P[j + 7] = hc_swap32_S (digest[7]);
  }
}

KERNEL_FQ KERNEL_FA void m70500_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  // EMPTY - The scrypt-jane bridge replaces this
}

KERNEL_FQ KERNEL_FA void m70500_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
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

  /**
   * 2nd PBKDF2-SHA256
   * Key = UTF16BE password (private), Salt = bridge output tmps[gid].P[] (global)
   */

  u32 w[128] = { 0 };

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  const int w_len = hc_enc_next_global (&hc_enc, pws[gid].i, pws[gid].pw_len, 256, w, sizeof (w));

  if (w_len == -1) return;

  // utf16le to utf16be
  for (int i = 0, j = 0; i < w_len; i += 4, j += 1)
  {
    w[j] = ((w[j] >> 8) & 0x00ff00ff)
         | ((w[j] << 8) & 0xff00ff00);
  }

  // HMAC init with private UTF16BE password
  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_swap (&ctx, w, w_len);

  // Feed bridge output (tmps[gid].P[]) as salt, swap32 back to big-endian for HMAC
  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  for (u32 i = 0, j = 0; i < x_bytes; i += 64, j += 16)
  {
    w0[0] = hc_swap32_S (tmps[gid].P[j +  0]);
    w0[1] = hc_swap32_S (tmps[gid].P[j +  1]);
    w0[2] = hc_swap32_S (tmps[gid].P[j +  2]);
    w0[3] = hc_swap32_S (tmps[gid].P[j +  3]);
    w1[0] = hc_swap32_S (tmps[gid].P[j +  4]);
    w1[1] = hc_swap32_S (tmps[gid].P[j +  5]);
    w1[2] = hc_swap32_S (tmps[gid].P[j +  6]);
    w1[3] = hc_swap32_S (tmps[gid].P[j +  7]);
    w2[0] = hc_swap32_S (tmps[gid].P[j +  8]);
    w2[1] = hc_swap32_S (tmps[gid].P[j +  9]);
    w2[2] = hc_swap32_S (tmps[gid].P[j + 10]);
    w2[3] = hc_swap32_S (tmps[gid].P[j + 11]);
    w3[0] = hc_swap32_S (tmps[gid].P[j + 12]);
    w3[1] = hc_swap32_S (tmps[gid].P[j + 13]);
    w3[2] = hc_swap32_S (tmps[gid].P[j + 14]);
    w3[3] = hc_swap32_S (tmps[gid].P[j + 15]);

    sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&ctx);

  u32 out[8];

  out[0] = hc_swap32_S (ctx.opad.h[0]);
  out[1] = hc_swap32_S (ctx.opad.h[1]);
  out[2] = hc_swap32_S (ctx.opad.h[2]);
  out[3] = hc_swap32_S (ctx.opad.h[3]);
  out[4] = hc_swap32_S (ctx.opad.h[4]);
  out[5] = hc_swap32_S (ctx.opad.h[5]);
  out[6] = hc_swap32_S (ctx.opad.h[6]);
  out[7] = hc_swap32_S (ctx.opad.h[7]);

  // AES256-CBC decrypt with IV from salt buffer (dynamic, alternative 1):

  u32 key[8];

  key[0] = out[0];
  key[1] = out[1];
  key[2] = out[2];
  key[3] = out[3];
  key[4] = out[4];
  key[5] = out[5];
  key[6] = out[6];
  key[7] = out[7];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4];

  iv[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  iv[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  iv[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  iv[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  u32 enc[4];

  enc[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  enc[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  enc[2] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  enc[3] = salt_bufs[SALT_POS_HOST].salt_buf[7];

  u32 dec[4];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= iv[0];
  dec[1] ^= iv[1];
  dec[2] ^= iv[2];
  dec[3] ^= iv[3];

  if (is_valid_bitcoinj (dec) == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }

  // alternative 2 (second block, fixed IV):

  enc[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  enc[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  enc[2] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  enc[3] = salt_bufs[SALT_POS_HOST].salt_buf[11];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= MULTIBIT_IV0;
  dec[1] ^= MULTIBIT_IV1;
  dec[2] ^= MULTIBIT_IV2;
  dec[3] ^= MULTIBIT_IV3;

  if (is_valid_bitcoinj (dec) == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
