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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct securezip
{
  u32 data[36];
  u32 file[16];
  u32 iv[4];
  u32 iv_len;

} securezip_t;

KERNEL_FQ void m23001_mxx (KERN_ATTR_VECTOR_ESALT (securezip_t))
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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector (&ctx);

    sha1_update_vector (&ctx, w, pw_len);

    sha1_final_vector (&ctx);

    u32 t0[4];

    t0[0] = 0x36363636 ^ ctx.h[0];
    t0[1] = 0x36363636 ^ ctx.h[1];
    t0[2] = 0x36363636 ^ ctx.h[2];
    t0[3] = 0x36363636 ^ ctx.h[3];

    u32 t1[4];

    t1[0] = 0x36363636 ^ ctx.h[4];
    t1[1] = 0x36363636;
    t1[2] = 0x36363636;
    t1[3] = 0x36363636;

    u32 t2[4];

    t2[0] = 0x36363636;
    t2[1] = 0x36363636;
    t2[2] = 0x36363636;
    t2[3] = 0x36363636;

    u32 t3[4];

    t3[0] = 0x36363636;
    t3[1] = 0x36363636;
    t3[2] = 0x36363636;
    t3[3] = 0x36363636;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (t0, t1, t2, t3, digest);

    t0[0] = 0x80000000;
    t0[1] = 0;
    t0[2] = 0;
    t0[3] = 0;

    t1[0] = 0;
    t1[1] = 0;
    t1[2] = 0;
    t1[3] = 0;

    t2[0] = 0;
    t2[1] = 0;
    t2[2] = 0;
    t2[3] = 0;

    t3[0] = 0;
    t3[1] = 0;
    t3[2] = 0;
    t3[3] = 64 * 8;

    sha1_transform (t0, t1, t2, t3, digest);

    u32 key[4];

    key[0] = digest[0];
    key[1] = digest[1];
    key[2] = digest[2];
    key[3] = digest[3];

    u32 iv[4];

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[28];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[29];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[30];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[31];

    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[32];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[33];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[34];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[35];

    #define KEYLEN 44

    u32 ks[KEYLEN];

    AES128_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 out[4];

    aes128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if ((out[0] == 0x10101010) &&
        (out[1] == 0x10101010) &&
        (out[2] == 0x10101010) &&
        (out[3] == 0x10101010))
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ void m23001_sxx (KERN_ATTR_VECTOR_ESALT (securezip_t))
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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector (&ctx);

    sha1_update_vector (&ctx, w, pw_len);

    sha1_final_vector (&ctx);

    u32 t0[4];

    t0[0] = 0x36363636 ^ ctx.h[0];
    t0[1] = 0x36363636 ^ ctx.h[1];
    t0[2] = 0x36363636 ^ ctx.h[2];
    t0[3] = 0x36363636 ^ ctx.h[3];

    u32 t1[4];

    t1[0] = 0x36363636 ^ ctx.h[4];
    t1[1] = 0x36363636;
    t1[2] = 0x36363636;
    t1[3] = 0x36363636;

    u32 t2[4];

    t2[0] = 0x36363636;
    t2[1] = 0x36363636;
    t2[2] = 0x36363636;
    t2[3] = 0x36363636;

    u32 t3[4];

    t3[0] = 0x36363636;
    t3[1] = 0x36363636;
    t3[2] = 0x36363636;
    t3[3] = 0x36363636;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (t0, t1, t2, t3, digest);

    t0[0] = 0x80000000;
    t0[1] = 0;
    t0[2] = 0;
    t0[3] = 0;

    t1[0] = 0;
    t1[1] = 0;
    t1[2] = 0;
    t1[3] = 0;

    t2[0] = 0;
    t2[1] = 0;
    t2[2] = 0;
    t2[3] = 0;

    t3[0] = 0;
    t3[1] = 0;
    t3[2] = 0;
    t3[3] = 64 * 8;

    sha1_transform (t0, t1, t2, t3, digest);

    u32 key[4];

    key[0] = digest[0];
    key[1] = digest[1];
    key[2] = digest[2];
    key[3] = digest[3];

    u32 iv[4];

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[28];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[29];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[30];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[31];

    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[32];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[33];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[34];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[35];

    #define KEYLEN 44

    u32 ks[KEYLEN];

    AES128_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 out[4];

    aes128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if ((out[0] == 0x10101010) &&
        (out[1] == 0x10101010) &&
        (out[2] == 0x10101010) &&
        (out[3] == 0x10101010))
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
