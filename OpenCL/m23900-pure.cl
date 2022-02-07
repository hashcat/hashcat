/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

typedef struct bestcrypt_tmp
{
  u32 salt_pw_buf[33];
  u32 out[8];

} bestcrypt_tmp_t;

typedef struct bestcrypt
{
  u32 data[24];

} bestcrypt_t;

KERNEL_FQ void m23900_init (KERN_ATTR_TMPS_ESALT (bestcrypt_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const int salt_pw_len = 8 + MIN (pws[gid].pw_len, 56);

  u32 comb[16];

  comb[ 0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  comb[ 1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  comb[ 2] = hc_swap32_S (pws[gid].i[ 0]); // in theory BE is faster because it
  comb[ 3] = hc_swap32_S (pws[gid].i[ 1]); // avoids several other byte swaps later on
  comb[ 4] = hc_swap32_S (pws[gid].i[ 2]);
  comb[ 5] = hc_swap32_S (pws[gid].i[ 3]);
  comb[ 6] = hc_swap32_S (pws[gid].i[ 4]);
  comb[ 7] = hc_swap32_S (pws[gid].i[ 5]);
  comb[ 8] = hc_swap32_S (pws[gid].i[ 6]);
  comb[ 9] = hc_swap32_S (pws[gid].i[ 7]);
  comb[10] = hc_swap32_S (pws[gid].i[ 8]);
  comb[11] = hc_swap32_S (pws[gid].i[ 9]);
  comb[12] = hc_swap32_S (pws[gid].i[10]);
  comb[13] = hc_swap32_S (pws[gid].i[11]);
  comb[14] = hc_swap32_S (pws[gid].i[12]);
  comb[15] = hc_swap32_S (pws[gid].i[13]);

  u32 salt_pw_buf[32 + 1] = { 0 }; // 8 + 56 + 64 = 128 bytes

  for (int i = 0; i < 128; i += salt_pw_len)
  {
    const int idx = i / 4;
    const int mod = i % 4;

    const int full_len = MIN (salt_pw_len, 128 - i);

    const int copy_len = (full_len + 3) / 4; // ceil () + convert to 4-byte block (u32)

    for (int j = 0, k = idx; j < copy_len; j++, k++)
    {
      // salt_pw_buf[k] |= comb[j] >> (mod * 8);
      // if (mod) salt_pw_buf[k + 1] |= comb[j] << ((4 - mod) * 8);

      switch (mod)
      {
        case 0:
          salt_pw_buf[k + 0] |= comb[j];
          break;
        case 1:
          salt_pw_buf[k + 0] |= comb[j] >>  8;
          salt_pw_buf[k + 1] |= comb[j] << 24;
          break;
        case 2:
          salt_pw_buf[k + 0] |= comb[j] >> 16;
          salt_pw_buf[k + 1] |= comb[j] << 16;
          break;
        case 3:
          salt_pw_buf[k + 0] |= comb[j] >> 24;
          salt_pw_buf[k + 1] |= comb[j] <<  8;
          break;
      }
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 33; i++)
  {
    tmps[gid].salt_pw_buf[i] = salt_pw_buf[i];
  }
}

KERNEL_FQ void m23900_loop (KERN_ATTR_TMPS_ESALT (bestcrypt_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const int salt_pw_len = 8 + MIN (pws[gid].pw_len, 56);

  u32 salt_pw_buf[32 + 1]; // 8 + 56 + 64 = 128 bytes

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 33; i++)
  {
    salt_pw_buf[i] = tmps[gid].salt_pw_buf[i];
  }

  u32 tbl[1024] = { 0 }; // 4 KiB lookup table

  for (int i = 0; i < 64; i++)
  {
    const int idx = i / 4;
    const int mod = i % 4;

    // init:

    int k = i * 16;
    int l = idx;

    // tbl[k] |= salt_pw_buf[l] << (mod * 8);

    switch (mod)
    {
      case 0:
        tbl[k] |= salt_pw_buf[l];
        break;
      case 1:
        tbl[k] |= salt_pw_buf[l] <<  8;
        break;
      case 2:
        tbl[k] |= salt_pw_buf[l] << 16;
        break;
      case 3:
        tbl[k] |= salt_pw_buf[l] << 24;
        break;
    }

    k += 1;
    l += 1;

    // loop:

    for (int j = 1; j < 16; j++, k++, l++)
    {
      // if (mod) tbl[k - 1] |= salt_pw_buf[l] >> ((4 - mod) * 8);
      // tbl[k] |= salt_pw_buf[l] << (mod * 8);

      switch (mod)
      {
        case 0:
          tbl[k - 0] |= salt_pw_buf[l];
          break;
        case 1:
          tbl[k - 0] |= salt_pw_buf[l] <<  8;
          tbl[k - 1] |= salt_pw_buf[l] >> 24;
          break;
        case 2:
          tbl[k - 0] |= salt_pw_buf[l] << 16;
          tbl[k - 1] |= salt_pw_buf[l] >> 16;
          break;
        case 3:
          tbl[k - 0] |= salt_pw_buf[l] << 24;
          tbl[k - 1] |= salt_pw_buf[l] >>  8;
          break;
      }
    }

    // final:

    // if (mod) tbl[k - 1] |= salt_pw_buf[l] >> ((4 - mod) * 8);

    switch (mod)
    {
      case 0:
        break;
      case 1:
        tbl[k - 1] |= salt_pw_buf[l] >> 24;
        break;
      case 2:
        tbl[k - 1] |= salt_pw_buf[l] >> 16;
        break;
      case 3:
        tbl[k - 1] |= salt_pw_buf[l] >>  8;
        break;
    }
  }

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  for (int i = 0; i < 65536; i += 64)
  {
    const int idx = (i % salt_pw_len) * 16;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = tbl[idx +  0];
    w0[1] = tbl[idx +  1];
    w0[2] = tbl[idx +  2];
    w0[3] = tbl[idx +  3];
    w1[0] = tbl[idx +  4];
    w1[1] = tbl[idx +  5];
    w1[2] = tbl[idx +  6];
    w1[3] = tbl[idx +  7];
    w2[0] = tbl[idx +  8];
    w2[1] = tbl[idx +  9];
    w2[2] = tbl[idx + 10];
    w2[3] = tbl[idx + 11];
    w3[0] = tbl[idx + 12];
    w3[1] = tbl[idx + 13];
    w3[2] = tbl[idx + 14];
    w3[3] = tbl[idx + 15];

    sha256_transform (w0, w1, w2, w3, digest);
  }

  tmps[gid].out[0] = digest[0];
  tmps[gid].out[1] = digest[1];
  tmps[gid].out[2] = digest[2];
  tmps[gid].out[3] = digest[3];
  tmps[gid].out[4] = digest[4];
  tmps[gid].out[5] = digest[5];
  tmps[gid].out[6] = digest[6];
  tmps[gid].out[7] = digest[7];
}

KERNEL_FQ void m23900_comp (KERN_ATTR_TMPS_ESALT (bestcrypt_tmp_t, bestcrypt_t))
{
  const u64 gid = get_global_id  (0);
  const u64 lid = get_local_id   (0);
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

  // final transform of sha256:

  u32 digest[8];

  digest[0] = tmps[gid].out[0];
  digest[1] = tmps[gid].out[1];
  digest[2] = tmps[gid].out[2];
  digest[3] = tmps[gid].out[3];
  digest[4] = tmps[gid].out[4];
  digest[5] = tmps[gid].out[5];
  digest[6] = tmps[gid].out[6];
  digest[7] = tmps[gid].out[7];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 0x80000000;
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
  w3[3] = 65536 * 8;

  sha256_transform (w0, w1, w2, w3, digest);

  /**
   * AES part
   */

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_decrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4] = { 0 };

  u32 res[20]; // full would be 24 x u32 (96 bytes)

  for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
  {
    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[i + 0];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[i + 1];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[i + 2];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[i + 3];

    u32 out[4];

    aes256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
    res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
    res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
    res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];
  }

  // checksum:

  // sha256_ctx_t ctx;
  // sha256_init (&ctx);
  // sha256_update_swap (&ctx, res, 64);
  // sha256_final (&ctx);

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  w0[0] = res[ 0];
  w0[1] = res[ 1];
  w0[2] = res[ 2];
  w0[3] = res[ 3];
  w1[0] = res[ 4];
  w1[1] = res[ 5];
  w1[2] = res[ 6];
  w1[3] = res[ 7];
  w2[0] = res[ 8];
  w2[1] = res[ 9];
  w2[2] = res[10];
  w2[3] = res[11];
  w3[0] = res[12];
  w3[1] = res[13];
  w3[2] = res[14];
  w3[3] = res[15];

  sha256_transform (w0, w1, w2, w3, digest);

  w0[0] = 0x80000000;
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
  w3[3] = 64 * 8;

  sha256_transform (w0, w1, w2, w3, digest);

  if ((digest[0] == res[16]) &&
      (digest[1] == res[17]) &&
      (digest[2] == res[18]) &&
      (digest[3] == res[19]))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
