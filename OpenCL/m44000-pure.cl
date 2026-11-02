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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

typedef struct androidfde
{
  u32 data[384];

} androidfde_t;

KERNEL_FQ KERNEL_FA void m44000_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, androidfde_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m44000_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44000_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44000_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, androidfde_t))
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
   * scrypt
   */

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 ikey[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, ikey, 32);

  /**
   * aes
   */

  // scrypt_pbkdf2_ggp writes the derived bytes in the order they come off PBKDF2, and the AES
  // helpers want each 4 bytes as one big-endian word, so every word is swapped on the way in.
  // The first 16 bytes are the AES-128 key and the second 16 are the CBC IV, as cryptfs.c's
  // EVP_DecryptInit (ikey, ikey + KEY_LEN_BYTES) reads them.

  u32 ukey[4];

  ukey[0] = hc_swap32_S (ikey[0]);
  ukey[1] = hc_swap32_S (ikey[1]);
  ukey[2] = hc_swap32_S (ikey[2]);
  ukey[3] = hc_swap32_S (ikey[3]);

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 data[4];

  data[0] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0];
  data[1] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1];
  data[2] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2];
  data[3] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 iv[4];

  iv[0] = hc_swap32_S (ikey[4]);
  iv[1] = hc_swap32_S (ikey[5]);
  iv[2] = hc_swap32_S (ikey[6]);
  iv[3] = hc_swap32_S (ikey[7]);

  const u32 a = out[0] ^ iv[0];
  const u32 b = out[1] ^ iv[1];
  const u32 c = out[2] ^ iv[2];
  const u32 d = out[3] ^ iv[3];

  // The footer carries no checksum over the master key, so a and b and c and d are tested by
  // decrypting the start of the filesystem with them. Both checks below are mode 8800's.

  // check for FAT

  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
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

    sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

    sha256_final (&ctx);

    u32 essivhash[8];

    essivhash[0] = ctx.h[0];
    essivhash[1] = ctx.h[1];
    essivhash[2] = ctx.h[2];
    essivhash[3] = ctx.h[3];
    essivhash[4] = ctx.h[4];
    essivhash[5] = ctx.h[5];
    essivhash[6] = ctx.h[6];
    essivhash[7] = ctx.h[7];

    // generate essiv based on startsector, each 512 byte is one sector

    AES256_set_encrypt_key (ks, essivhash, s_te0, s_te1, s_te2, s_te3);

    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    u32 essiv[4];

    AES256_encrypt (ks, data, essiv, s_te0, s_te1, s_te2, s_te3, s_te4);

    // decrypt real data, xor essiv afterwards

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[0];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[1];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[2];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[3];

    iv[0] = essiv[0];
    iv[1] = essiv[1];
    iv[2] = essiv[2];
    iv[3] = essiv[3];

    ukey[0] = a;
    ukey[1] = b;
    ukey[2] = c;
    ukey[3] = d;

    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 r0 = out[0] ^ iv[0];
    u32 r1 = out[1] ^ iv[1];
    u32 r2 = out[2] ^ iv[2];

    // rotate 3 byte (in fat!)

    r0 = r1 << 8 | r0 >> 24;
    r1 = r2 << 8 | r1 >> 24;

    // MSDOS5.0
    if ((r0 == 0x4f44534d) && (r1 == 0x302e3553))
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }
  }

  // check for extfs

  {
    ukey[0] = a;
    ukey[1] = b;
    ukey[2] = c;
    ukey[3] = d;

    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 r[16];

    // not needed because of cbc mode, implementation flaw. first 16 bytes are not interesting

    r[0] = 0;
    r[1] = 0;
    r[2] = 0;
    r[3] = 0;

    for (u32 i = 4; i < 16; i += 4)
    {
      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 3];

      iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 0 - 4];
      iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 1 - 4];
      iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 2 - 4];
      iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[256 + i + 3 - 4];

      AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      r[i + 0] = out[0] ^ iv[0];
      r[i + 1] = out[1] ^ iv[1];
      r[i + 2] = out[2] ^ iv[2];
      r[i + 3] = out[3] ^ iv[3];
    }

    // we need just a few swapped, because we do not access the others

    r[ 5] = hc_swap32_S (r[ 5]);
    r[ 6] = hc_swap32_S (r[ 6]);
    r[14] = hc_swap32_S (r[14]);

    // superblock not on id 0 or 1
    // assumes max block size is 32MiB
    // has EXT2_SUPER_MAGIC

    if ((r[5] < 2) && (r[6] < 16) && ((r[14] & 0xffff) == 0xEF53))
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }
  }
}
