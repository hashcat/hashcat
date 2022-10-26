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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct encdatavault
{
  u32 keychain[32];
  u32 iv[2];

  u32 ct[2];

  u32 algo;
  u32 version;

  u32 nb_keys;
  u32 key_len;

} encdatavault_t;

typedef struct encdatavault_tmp
{
  u32 tmp_buf[4];
  u32 out_buf[4];

} encdatavault_tmp_t;

CONSTANT_VK u32a default_salts[32] =
{
  0x0fc9e7d0, 0x8be424f6, 0x569d4e72, 0xedbc2c5c,
  0xdd7974f3, 0x3d8300c2, 0x9bd293d5, 0x7f9d9b8c,
  0x60850c47, 0x5846e296, 0x2d995d5e, 0xf1d06a28,
  0xe23f3d6b, 0x99614ba9, 0xc4edc5dd, 0xd8253ce1,
  0x2ca45989, 0x1d7852db, 0x3031d09f, 0x9f348835,
  0xdb1bb527, 0xe8214f79, 0xa0b2cb32, 0x42d9f20a,
  0xaea8b68e, 0xd07b62a1, 0x400e17c6, 0xad6420c8,
  0xeae3f44e, 0xaf4a8f84, 0xf1fab308, 0x8569bef8
};

KERNEL_FQ void m29940_init (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update_global (&md5_ctx, pws[gid].i, pws[gid].pw_len);

  md5_final (&md5_ctx);

  tmps[gid].tmp_buf[0] = md5_ctx.h[0];
  tmps[gid].tmp_buf[1] = md5_ctx.h[1];
  tmps[gid].tmp_buf[2] = md5_ctx.h[2];
  tmps[gid].tmp_buf[3] = md5_ctx.h[3];

  tmps[gid].out_buf[0] = 0;
  tmps[gid].out_buf[1] = 0;
  tmps[gid].out_buf[2] = 0;
  tmps[gid].out_buf[3] = 0;
}

KERNEL_FQ void m29940_loop (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x digest[4];

  digest[0] = packv (tmps, tmp_buf, gid, 0);
  digest[1] = packv (tmps, tmp_buf, gid, 1);
  digest[2] = packv (tmps, tmp_buf, gid, 2);
  digest[3] = packv (tmps, tmp_buf, gid, 3);

  u32x out[4];

  out[0] = packv (tmps, out_buf, gid, 0);
  out[1] = packv (tmps, out_buf, gid, 1);
  out[2] = packv (tmps, out_buf, gid, 2);
  out[3] = packv (tmps, out_buf, gid, 3);

  u32x block0[4];
  u32x block1[4];
  u32x block2[4];
  u32x block3[4];

  block0[0] = 0;
  block0[1] = 0;
  block0[2] = 0;
  block0[3] = 0;
  block1[0] = 0x80;
  block1[1] = 0;
  block1[2] = 0;
  block1[3] = 0;
  block2[0] = 0;
  block2[1] = 0;
  block2[2] = 0;
  block2[3] = 0;
  block3[0] = 0;
  block3[1] = 0;
  block3[2] = 16 * 8;
  block3[3] = 0;

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    block0[0] = digest[0];
    block0[1] = digest[1];
    block0[2] = digest[2];
    block0[3] = digest[3];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform_vector (block0, block1, block2, block3, digest);

    out[0] ^= digest[0];
    out[1] ^= digest[1];
    out[2] ^= digest[2];
    out[3] ^= digest[3];
  }

  unpackv (tmps, tmp_buf, gid, 0, digest[0]);
  unpackv (tmps, tmp_buf, gid, 1, digest[1]);
  unpackv (tmps, tmp_buf, gid, 2, digest[2]);
  unpackv (tmps, tmp_buf, gid, 3, digest[3]);

  unpackv (tmps, out_buf, gid, 0, out[0]);
  unpackv (tmps, out_buf, gid, 1, out[1]);
  unpackv (tmps, out_buf, gid, 2, out[2]);
  unpackv (tmps, out_buf, gid, 3, out[3]);
}

KERNEL_FQ void m29940_comp (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
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

  // decrypt keychain using PBKDF2 key

  #define ENC_MAX_KEY_NUM 8

  u32 keysalt[ENC_MAX_KEY_NUM][4];

  for (int i = 0, j = 0; i < ENC_MAX_KEY_NUM; i += 1, j += 4)
  {
    keysalt[i][0] = hc_swap32_S (tmps[gid].out_buf[0]) ^ default_salts[j + 0];
    keysalt[i][1] = hc_swap32_S (tmps[gid].out_buf[1]) ^ default_salts[j + 1];
    keysalt[i][2] = hc_swap32_S (tmps[gid].out_buf[2]) ^ default_salts[j + 2];
    keysalt[i][3] = hc_swap32_S (tmps[gid].out_buf[3]) ^ default_salts[j + 3];
  }

  u32 ukey[4];

  ukey[0] = keysalt[0][0];
  ukey[1] = keysalt[0][1];
  ukey[2] = keysalt[0][2];
  ukey[3] = keysalt[0][3];

  u32 ks[44];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  const u32 key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_len;

  #define ENC_MAX_KEY_NUM 8

  u32 ivs_keychain[ENC_MAX_KEY_NUM][2];

  ivs_keychain[0][0] = 0;
  ivs_keychain[0][1] = 0;

  for (int i = 1, j = 7; i < ENC_MAX_KEY_NUM; i += 1, j -= 1) // +4 is not a bug, 8/16 bytes are just discarded
  {
    ivs_keychain[i][0] = keysalt[j][0];
    ivs_keychain[i][1] = keysalt[j][1];
  }

  u32 ctr_keychain[ENC_MAX_KEY_NUM][4];

  #define ENC_KEYCHAIN_SIZE 128
  #define ENC_BLOCK_SIZE 16

  for (int i = 0, counter = 0; i < (ENC_KEYCHAIN_SIZE / ENC_BLOCK_SIZE); i++, counter++)
  {
    u32 in[4];

    in[0] = ivs_keychain[0][0];
    in[1] = ivs_keychain[0][1];
    in[2] = 0;
    in[3] = counter;

    u32 out[4];

    AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctr_keychain[i][0] = out[0];
    ctr_keychain[i][1] = out[1];
    ctr_keychain[i][2] = out[2];
    ctr_keychain[i][3] = out[3];

    for (int j = 1; j < ENC_MAX_KEY_NUM; j++)
    {
      in[0] = ivs_keychain[j][0];
      in[1] = ivs_keychain[j][1];
      in[2] = 0;
      in[3] = counter;

      AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

      ctr_keychain[i][0] ^= out[0];
      ctr_keychain[i][1] ^= out[1];
      ctr_keychain[i][2] ^= out[2];
      ctr_keychain[i][3] ^= out[3];
    }
  }

  u32 keychain[ENC_MAX_KEY_NUM][4];

  for (int i = 0, j = 0; i < (ENC_KEYCHAIN_SIZE / ENC_BLOCK_SIZE); i += 1, j += 4)
  {
    keychain[i][0] = ctr_keychain[i][0] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 0];
    keychain[i][1] = ctr_keychain[i][1] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 1];
    keychain[i][2] = ctr_keychain[i][2] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 2];
    keychain[i][3] = ctr_keychain[i][3] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 3];
  }

  // decrypt encrypted data using keychain key

  ukey[0] = keychain[0][0];
  ukey[1] = keychain[0][1];
  ukey[2] = keychain[0][2];
  ukey[3] = keychain[0][3];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 ivs[ENC_MAX_KEY_NUM][2];

  ivs[0][0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  ivs[0][1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];

  for (int i = 1; i < esalt_bufs[DIGESTS_OFFSET_HOST].nb_keys; i += 1) // +4 is not a bug, 8/16 bytes are just discarded
  {
    ivs[i][0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0] ^ keychain[i][0];
    ivs[i][1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1] ^ keychain[i][1];
  }

  #define CTR_LEN 16

  u32 ctr[ENC_MAX_KEY_NUM][4];

  for (int i = 0, counter = 1; i < (CTR_LEN / ENC_BLOCK_SIZE); i++, counter++) // is always just 1 iteration here, but concept is needed for later kernels
  {
    u32 in[4];

    in[0] = ivs[0][0];
    in[1] = ivs[0][1];
    in[2] = 0;
    in[3] = counter;

    u32 out[4];

    AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctr[i][0] = out[0];
    ctr[i][1] = out[1];
    ctr[i][2] = out[2];
    ctr[i][3] = out[3];

    for (int j = 1; j < esalt_bufs[DIGESTS_OFFSET_HOST].nb_keys; j++)
    {
      in[0] = ivs[j][0];
      in[1] = ivs[j][1];
      in[2] = 0;
      in[3] = counter;

      AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

      ctr[i][0] ^= out[0];
      ctr[i][1] ^= out[1];
      ctr[i][2] ^= out[2];
      ctr[i][3] ^= out[3];
    }
  }

  u32 ct[2];

  ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0];
  ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1];

  u32 pt[2];

  pt[0] = ct[0] ^ ctr[0][1];
  pt[1] = ct[1] ^ ctr[0][2];

  if ((pt[0] == 0xd2c3b4a1) && ((pt[1] & 0xffffff00) == 0))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
