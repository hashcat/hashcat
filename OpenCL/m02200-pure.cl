/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct encfs_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[15];
  u32  out[15];

} encfs_tmp_t;

typedef struct encfs
{
  u32 key_size;
  u32 data_len;
  u32 checksum;
  u32 data[12];

} encfs_t;

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

// the IV of one CFB pass is HMAC-SHA1 (key, iv . le64 (seed)), cut to 16 bytes

DECLSPEC void encfs_ivec (PRIVATE_AS const u32 *ukey, const u32 key_size, PRIVATE_AS const u32 *iv, const u64 seed, PRIVATE_AS u32 *ivec)
{
  sha1_hmac_ctx_t ctx;

  sha1_hmac_init (&ctx, ukey, key_size);

  u32 w[6];

  w[0] = iv[0];
  w[1] = iv[1];
  w[2] = iv[2];
  w[3] = iv[3];
  w[4] = hc_swap32_S (l32_from_64_S (seed));
  w[5] = hc_swap32_S (h32_from_64_S (seed));

  sha1_hmac_update (&ctx, w, 24);

  sha1_hmac_final (&ctx);

  ivec[0] = ctx.opad.h[0];
  ivec[1] = ctx.opad.h[1];
  ivec[2] = ctx.opad.h[2];
  ivec[3] = ctx.opad.h[3];
}

DECLSPEC void encfs_aes_encrypt (PRIVATE_AS const u32 *ks, const u32 key_size, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3, SHM_TYPE const u32 *s_te4)
{
  if (key_size == 32)
  {
    AES256_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else if (key_size == 24)
  {
    AES192_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else
  {
    AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
}

// one AES-CFB128 decryption over the whole buffer, then the byte chain undone: b[i] ^= b[i - 1]

DECLSPEC void encfs_decode_pass (PRIVATE_AS const u32 *ks, const u32 key_size, PRIVATE_AS const u32 *ivec, PRIVATE_AS u32 *buf, const u32 words, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3, SHM_TYPE const u32 *s_te4)
{
  u32 iv[4];

  iv[0] = ivec[0];
  iv[1] = ivec[1];
  iv[2] = ivec[2];
  iv[3] = ivec[3];

  for (u32 i = 0; i < words; i += 4)
  {
    u32 ks_out[4];

    encfs_aes_encrypt (ks, key_size, iv, ks_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    for (u32 j = 0; j < 4; j++)
    {
      if ((i + j) >= words) break;

      iv[j] = buf[i + j];

      buf[i + j] ^= ks_out[j];
    }
  }

  for (u32 i = words - 1; i > 0; i--)
  {
    buf[i] ^= (buf[i] >> 8) | (buf[i - 1] << 24);
  }

  buf[0] ^= buf[0] >> 8;
}

KERNEL_FQ KERNEL_FA void m02200_init (KERN_ATTR_TMPS_ESALT (encfs_tmp_t, encfs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // key and IV together are 32, 40 or 48 bytes, so 2 or 3 PBKDF2 blocks

  const u32 dk_words = (esalt_bufs[DIGESTS_OFFSET_HOST].key_size + 16) / 4;

  for (u32 i = 0, j = 1; i < dk_words; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ KERNEL_FA void m02200_loop (KERN_ATTR_TMPS_ESALT (encfs_tmp_t, encfs_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  const u32 dk_words = (esalt_bufs[DIGESTS_OFFSET_HOST].key_size + 16) / 4;

  for (u32 i = 0; i < dk_words; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

KERNEL_FQ KERNEL_FA void m02200_comp (KERN_ATTR_TMPS_ESALT (encfs_tmp_t, encfs_t))
{
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

  const u32 key_size = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;
  const u32 words    = esalt_bufs[DIGESTS_OFFSET_HOST].data_len / 4;
  const u32 checksum = esalt_bufs[DIGESTS_OFFSET_HOST].checksum;

  // the PBKDF2 output is the AES key followed by a 16 byte IV

  u32 ukey[8];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];
  ukey[4] = tmps[gid].out[4];
  ukey[5] = tmps[gid].out[5];
  ukey[6] = tmps[gid].out[6];
  ukey[7] = tmps[gid].out[7];

  const u32 iv_pos = key_size / 4;

  u32 iv[4];

  iv[0] = tmps[gid].out[iv_pos + 0];
  iv[1] = tmps[gid].out[iv_pos + 1];
  iv[2] = tmps[gid].out[iv_pos + 2];
  iv[3] = tmps[gid].out[iv_pos + 3];

  u32 ks[60];

  if (key_size == 32)
  {
    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
  }
  else if (key_size == 24)
  {
    AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
  }
  else
  {
    AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
  }

  u32 buf[12];

  for (u32 i = 0; i < 12; i++) buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].data[i];

  // the first pass is seeded with checksum + 1, the second with the checksum itself, and the bytes
  // are reversed between them

  u32 ivec[4];

  encfs_ivec (ukey, key_size, iv, (u64) checksum + 1, ivec);

  encfs_decode_pass (ks, key_size, ivec, buf, words, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 rev[12];

  for (u32 i = 0; i < words; i++) rev[i] = hc_swap32_S (buf[words - 1 - i]);

  encfs_ivec (ukey, key_size, iv, (u64) checksum + 0, ivec);

  encfs_decode_pass (ks, key_size, ivec, rev, words, s_te0, s_te1, s_te2, s_te3, s_te4);

  // the checksum is HMAC-SHA1 over the decoded volume key, its first 19 bytes folded into 8 and
  // those into 4

  sha1_hmac_ctx_t ctx;

  sha1_hmac_init (&ctx, ukey, key_size);

  sha1_hmac_update (&ctx, rev, words * 4);

  sha1_hmac_final (&ctx);

  const u32 mac32 = ctx.opad.h[0]
                  ^ ctx.opad.h[1]
                  ^ ctx.opad.h[2]
                  ^ ctx.opad.h[3]
                  ^ (ctx.opad.h[4] & 0xffffff00);

  if (mac32 != checksum) return;

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
  }
}
